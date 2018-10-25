use mio::*;
use mio::net::*;
use mio::unix::UnixReady;
use std::io::ErrorKind;
use nom::{IResult,Err};
use {SessionResult,Readiness};
use socket::{SocketHandler, SocketResult};
use protocol::ProtocolResult;
use sozu_command::buffer::Buffer;
use pool::Checkout;

mod parser;

pub struct PeekSNI {
  pub stream:    TcpStream,
  pub token:     Token,
  pub buffer:    Checkout<Buffer>,
  pub sni_list:  Vec<(u8, Vec<u8>)>,
  pub readiness: Readiness,
}

impl PeekSNI {
  pub fn new(stream: TcpStream, token: Token, buffer: Checkout<Buffer>) -> PeekSNI {
    PeekSNI {
      stream,
      token,
      buffer,
      sni_list: Vec::new(),
      readiness: Readiness {
        interest:  UnixReady::from(Ready::readable())
                           | UnixReady::hup() | UnixReady::error(),
        event: UnixReady::from(Ready::empty()),
      },
    }
  }

  pub fn front_socket(&self) -> &TcpStream {
    &self.stream
  }

  pub fn readiness(&mut self) -> &mut Readiness {
    &mut self.readiness
  }

  pub fn readable(&mut self) -> (ProtocolResult,SessionResult) {
    let (sz, res) = self.stream.socket_read(self.buffer.space());
    if sz > 0 {
      self.buffer.fill(sz);

      if res == SocketResult::Error {
        error!("[{:?}] front socket error, closing the connection", self.token);
        incr!("peek_sni.errors");
        self.readiness.reset();
        return (ProtocolResult::Continue, SessionResult::CloseSession);
      }

      if res == SocketResult::WouldBlock {
        self.readiness.event.remove(Ready::readable());
      }

      match parser::parse_sni_from_client_hello(self.buffer.data()) {
        Ok((_, list)) => {
          if let Some(mut l) = list {
            self.sni_list = l.iter()
              .flatten()
              .flat_map(|l2| l2.list.iter()
                        .map(|(i, v): &(u8, &[u8])| (*i, Vec::from(*v))))
              .collect();
          }

          return (ProtocolResult::Upgrade, SessionResult::Continue);
        },
        Err(Err::Incomplete(_)) => {
          return (ProtocolResult::Continue, SessionResult::CloseSession);
        },
        Err(e) => {
          error!("[{:?}] error parsing the client hello message(error={:?}), closing the connection",
          self.token, e);
          return (ProtocolResult::Continue, SessionResult::CloseSession);
        }
      }
    }

    error!("cannot read from socket, closing");
    return (ProtocolResult::Continue, SessionResult::CloseSession);
  }
}

