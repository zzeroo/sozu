use std::io::{self,ErrorKind,Read,Write};
use std::net::{SocketAddr,SocketAddrV4,SocketAddrV6};
use mio::tcp::{TcpListener,TcpStream};
use openssl::ssl::{Error, SslStream, MidHandshakeSslStream, HandshakeError};
use net2::TcpBuilder;
use net2::unix::UnixTcpBuilderExt;

#[derive(Debug,PartialEq,Copy,Clone)]
pub enum SocketResult {
  Continue,
  WouldBlock,
  Error
}

pub trait SocketHandler {
  fn socket_read(&mut self,  buf: &mut[u8]) -> (usize, SocketResult);
  fn socket_write(&mut self, buf: &[u8])    -> (usize, SocketResult);
  fn socket_ref(&self) -> &TcpStream;
}

pub enum BackendSocket {
  TCP(TcpStream),
  TLS(BackendSslStream),
}

impl SocketHandler for BackendSocket {
  fn socket_read(&mut self,  buf: &mut[u8]) -> (usize, SocketResult) {
    match *self {
      BackendSocket::TCP(ref mut stream) => stream.socket_read(buf),
      BackendSocket::TLS(ref mut stream) => stream.socket_read(buf),
    }
  }

  fn socket_write(&mut self,  buf: &[u8]) -> (usize, SocketResult) {
    match *self {
      BackendSocket::TCP(ref mut stream) => stream.socket_write(buf),
      BackendSocket::TLS(ref mut stream) => stream.socket_write(buf),
    }
  }

  fn socket_ref(&self) -> &TcpStream {
    match self {
      &BackendSocket::TCP(ref stream) => stream,
      &BackendSocket::TLS(ref stream) => stream.socket_ref()
    }

  }
}

impl SocketHandler for TcpStream {
  fn socket_read(&mut self,  buf: &mut[u8]) -> (usize, SocketResult) {
    let mut size = 0usize;
    loop {
      if size == buf.len() {
        return (size, SocketResult::Continue);
      }
      match self.read(&mut buf[size..]) {
        Ok(0)  => return (size, SocketResult::Continue),
        Ok(sz) => size +=sz,
        Err(e) => match e.kind() {
          ErrorKind::WouldBlock => return (size, SocketResult::WouldBlock),
          ErrorKind::BrokenPipe => {
            error!("SOCKET\tbroken pipe reading from the socket");
            return (size, SocketResult::Error)
          },
          _ => {
            error!("SOCKET\tsocket_read error={:?}", e);
            return (size, SocketResult::Error)
          },
        }
      }
    }
  }

  fn socket_write(&mut self,  buf: &[u8]) -> (usize, SocketResult) {
    let mut size = 0usize;
    loop {
      if size == buf.len() {
        return (size, SocketResult::Continue);
      }
      match self.write(&buf[size..]) {
        Ok(0)  => return (size, SocketResult::Continue),
        Ok(sz) => size += sz,
        Err(e) => match e.kind() {
          ErrorKind::WouldBlock => return (size, SocketResult::WouldBlock),
          ErrorKind::BrokenPipe => {
            error!("SOCKET\tbroken pipe writing to the socket");
            return (size, SocketResult::Error)
          },
          _ => {
            //FIXME: timeout and other common errors should be sent up
            error!("SOCKET\tsocket_write error={:?}", e);
            return (size, SocketResult::Error)
          },
        }
      }
    }
  }

  fn socket_ref(&self) -> &TcpStream { self }
}

pub struct BackendSslStream {
  ssl: Option<BackendSslState>,
}

impl BackendSslStream {
  pub fn new(res: Result<SslStream<TcpStream>, HandshakeError<TcpStream>> ) -> Option<BackendSslStream> {
    match res {
      Ok(stream) => {
        Some(BackendSslStream {
          ssl: Some(BackendSslState::Ssl(stream)),
        })
      },
      Err(HandshakeError::SetupFailure(e)) => {
        error!("error connecting: {:?}", e);
        None
      },
      Err(HandshakeError::Failure(mid)) => {
        error!("error connecting: {:?}", mid);
        Some(BackendSslStream {
          ssl: Some(BackendSslState::Handshake(mid)),
        })
      },
      Err(HandshakeError::Interrupted(mid)) => {
        info!("first handshake interruped");
        Some(BackendSslStream {
          ssl: Some(BackendSslState::Handshake(mid)),
        })
      }
    }
  }

}

pub enum BackendSslState {
  Handshake(MidHandshakeSslStream<TcpStream>),
  Ssl(SslStream<TcpStream>),
}

impl BackendSslState {
  pub fn handshake(self) -> (Option<BackendSslState>, SocketResult) {
    match self {
      BackendSslState::Handshake(stream) => {
        match stream.handshake() {
          Ok(new_stream) => {
            (Some(BackendSslState::Ssl(new_stream)), SocketResult::Continue)
          },
          Err(HandshakeError::SetupFailure(e)) => {
            error!("error connecting: {:?}", e);
            (None, SocketResult::Error)
          },
          Err(HandshakeError::Failure(mid)) => {
            error!("error connecting: {:?}", mid);
            (Some(BackendSslState::Handshake(mid)), SocketResult::Error)
          },
          Err(HandshakeError::Interrupted(new_mid)) => {
            info!("handshake interrupted");
            (Some(BackendSslState::Handshake(new_mid)), SocketResult::Continue)
          }
        }
      },
      ssl => (Some(ssl), SocketResult::Continue),
    }
  }
}

impl SocketHandler for BackendSslStream {
  fn socket_read(&mut self,  buf: &mut[u8]) -> (usize, SocketResult) {
    let ssl = self.ssl.take().expect("the SSL state should not be None");
    match ssl {
      BackendSslState::Ssl(mut stream) => {
        let res = stream.socket_read(buf);
        self.ssl = Some(BackendSslState::Ssl(stream));
        res
      },
      mid_handshake => {
        let (new_ssl, res) = mid_handshake.handshake();
        self.ssl = new_ssl;
        info!("socket_read mid handshake res: {:?}", (0, res));
        (0, res)
      }
    }
  }

  fn socket_write(&mut self,  buf: &[u8]) -> (usize, SocketResult) {
    let ssl = self.ssl.take().expect("the SSL state should not be None");
    match ssl {
      BackendSslState::Ssl(mut stream) => {
        let res = stream.socket_write(buf);
        self.ssl = Some(BackendSslState::Ssl(stream));
        res
      },
      mid_handshake => {
        let (new_ssl, res) = mid_handshake.handshake();
        self.ssl = new_ssl;
        info!("socket_write mid handshake res: {:?}", (0, res));
        (0, res)
      },
    }
  }

  fn socket_ref(&self) -> &TcpStream {
    match self.ssl {
      Some(BackendSslState::Ssl(ref stream)) => stream.socket_ref(),
      Some(BackendSslState::Handshake(ref stream)) => stream.get_ref(),
      None => panic!("we should not have to ask for socket_ref on an invalid connection"),
    }
  }
}

impl SocketHandler for SslStream<TcpStream> {
  fn socket_read(&mut self,  buf: &mut[u8]) -> (usize, SocketResult) {
    let mut size = 0usize;
    loop {
      if size == buf.len() {
        return (size, SocketResult::Continue);
      }
      match self.ssl_read(&mut buf[size..]) {
        Ok(0)  => return (size, SocketResult::Continue),
        Ok(sz) => size += sz,
        Err(Error::WantRead(_))  => return (size, SocketResult::WouldBlock),
        Err(Error::WantWrite(_)) => return (size, SocketResult::WouldBlock),
        Err(Error::Stream(e))    => {
          error!("SOCKET-TLS\treadable TLS socket err={:?}", e);
          return (size, SocketResult::Error)
        },
        _ => return (size, SocketResult::Error)
      }
    }
  }

  fn socket_write(&mut self,  buf: &[u8]) -> (usize, SocketResult) {
    let mut size = 0usize;
    loop {
      if size == buf.len() {
        return (size, SocketResult::Continue);
      }
      match self.ssl_write(&buf[size..]) {
        Ok(0)  => return (size, SocketResult::Continue),
        Ok(sz) => size +=sz,
        Err(Error::WantRead(_))  => return (size, SocketResult::WouldBlock),
        Err(Error::WantWrite(_)) => return (size, SocketResult::WouldBlock),
        Err(Error::Stream(e))    => {
          error!("SOCKET-TLS\twritable TLS socket err={:?}", e);
          return (size, SocketResult::Error)
        },
        e => {
          error!("SOCKET-TLS\twritable TLS socket err={:?}", e);
          return (size, SocketResult::Error)
        }
      }
    }
  }

  fn socket_ref(&self) -> &TcpStream { self.get_ref() }
}

pub fn server_bind(addr: &SocketAddr) -> io::Result<TcpListener> {
  let sock = try!(match *addr {
    SocketAddr::V4(..) => TcpBuilder::new_v4(),
    SocketAddr::V6(..) => TcpBuilder::new_v6(),
  });

  // set so_reuseaddr, but only on unix (mirrors what libstd does)
  if cfg!(unix) {
    try!(sock.reuse_address(true));
  }

  try!(sock.reuse_port(true));

  // bind the socket
  try!(sock.bind(addr));

  // listen
  let listener = try!(sock.listen(1024));
  TcpListener::from_listener(listener, addr)
}

