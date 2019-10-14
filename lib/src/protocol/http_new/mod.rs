use std::cmp::min;
use std::rc::{Rc,Weak};
use std::cell::RefCell;
use std::net::{SocketAddr,IpAddr};
use std::collections::HashMap;
use mio::*;
use mio::unix::UnixReady;
use mio::tcp::TcpStream;
use uuid::{Uuid, adapter::Hyphenated};
use sozu_command::buffer::Buffer;
use super::super::{SessionResult,Protocol,Readiness,SessionMetrics, LogDuration};
use buffer_queue::BufferQueue;
use socket::{SocketHandler,SocketResult};
use protocol::ProtocolResult;
use pool::{Pool, Checkout};
use util::UnwrapLog;

pub mod parser;
pub mod cookies;
pub mod client;
pub mod server;

use self::parser::request::ParsedRequest;

enum FrontProtocol {
  Http1(server::Server),
  Http2,
}

impl FrontProtocol {
  pub fn parse<'a, 'buffer>(&'a mut self, input: &'buffer [u8]) -> FrontResult<'buffer> {
    match self {
     FrontProtocol::Http1(server) => server.parse(input),
     FrontProtocol::Http2 => unimplemented!()
    }
  }
}

enum BackProtocol {
  Http1(client::Client),
  Http2,
}

struct Frontend<Front> {
  socket: Front,
  token: Token,
  buffer: Option<Checkout<Buffer>>,
  protocol: FrontProtocol,
  readiness: Readiness,
}

struct Backend {
  socket: TcpStream,
  stream_id: StreamId,
  token: Token,
  buffer: Option<Checkout<Buffer>>,
  protocol: BackProtocol,
  readiness: Readiness,
}

impl<Front: SocketHandler> Frontend<Front> {
  pub fn read(&mut self, metrics: &mut SessionMetrics) -> FrontResult {
    if self.buffer.as_ref().unwrap().available_space() == 0 {
      /*FIXME
      if self.backends.is_empty() {
        let answer_413 = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
        self.set_answer(DefaultAnswerStatus::Answer413, Rc::new(Vec::from(answer_413.as_bytes())));
        self.front_readiness.interest.remove(Ready::readable());
        self.front_readiness.interest.insert(Ready::writable());
      } else {
        self.front_readiness.interest.remove(Ready::readable());
        self.back_readiness.interest.insert(Ready::writable());
      }
      return SessionResult::Continue;
      */
    }

    let (sz, res) = self.socket.socket_read(self.buffer.as_mut().unwrap().space());
    debug!("FRONT: read {} bytes", sz);

    if sz > 0 {
      count!("bytes_in", sz as i64);
      metrics.bin += sz;

      if self.buffer.as_ref().unwrap().available_space() == 0 {
        self.readiness.interest.remove(Ready::readable());
      }
    } else {
      self.readiness.event.remove(Ready::readable());
    }

    match res {
      SocketResult::Error => {
        /*
        //we were in keep alive but the peer closed the connection
        if self.request == Some(RequestState::Initial) {
          metrics.service_stop();
          self.front_readiness.reset();
          self.back_readiness.reset();
        } else {
          let front_readiness = self.front_readiness.clone();
          let back_readiness  = self.back_readiness.clone();
          self.log_request_error(metrics,
            &format!("front socket error, closing the session. Readiness: {:?} -> {:?}, read {} bytes",
              front_readiness, back_readiness, sz));
        }
        */
        return FrontResult::Error;
      },
      SocketResult::Closed => {
        /*
        //we were in keep alive but the peer closed the connection
        if self.request == Some(RequestState::Initial) {
          metrics.service_stop();
          self.front_readiness.reset();
          self.back_readiness.reset();
        } else {
          let front_readiness = self.front_readiness.clone();
          let back_readiness  = self.back_readiness.clone();
          self.log_request_error(metrics,
            &format!("front socket was closed, closing the session. Readiness: {:?} -> {:?}, read {} bytes",
              front_readiness, back_readiness, sz));
        }
        */
        return FrontResult::Closed;
      },
      SocketResult::WouldBlock => {
        self.readiness.event.remove(Ready::readable());
      },
      SocketResult::Continue => {}
    };

    return self.parse(metrics)
  }

  pub fn parse(&mut self, metrics: &mut SessionMetrics) -> FrontResult {
    if self.buffer.is_none() {
      FrontResult::Error
    } else {
      self.protocol.parse(self.buffer.as_ref().unwrap().data())
    }
  }

  pub fn wants_read(self) -> bool {
    self.readiness.interest.is_readable() // && self.protocol.can_read()
  }

  pub fn can_read(self) -> bool {
    self.readiness.event.is_readable()
  }
}

pub type StreamId = u16;
#[derive(Debug,Clone,PartialEq)]
pub enum FrontResult<'buffer> {
  Continue,
  Request(StreamId, ParsedRequest<'buffer>),
  Data(StreamId, usize),
  /// stream id, chunk header size, data size
  Chunk(StreamId, usize, usize),
  Error,
  Done,
  Closed,
}

pub struct Session<Front: SocketHandler> {
  frontend: Frontend<Front>,
  backends: HashMap<Token, Backend>,
  connecting_backends: HashMap<StreamId, Vec<WriteEvent>>,
  pool: Weak<RefCell<Pool<Buffer>>>,
}

impl<Front:SocketHandler> Session<Front> {
  pub fn new(socket: Front, token: Token, pool: Weak<RefCell<Pool<Buffer>>>, buffer: Option<Checkout<Buffer>>) -> Self {
    let frontend = Frontend { socket, token, buffer, protocol: FrontProtocol::Http1(server::Server::new()), readiness: Readiness::new() };

    Session { frontend, backends: HashMap::new(), connecting_backends: HashMap::new(), pool }
  }

  pub fn run(&mut self, metrics: &mut SessionMetrics) -> SessionResult {

    if self.frontend.wants_read() {
      if self.frontend.can_read() {
        if self.frontend.buffer.is_none() {
          if let Some(p) = self.pool.upgrade() {
            if let Some(buf) = p.borrow_mut().checkout() {
              self.frontend.buffer = Some(buf);
            } else {
              error!("cannot get front buffer from pool, closing");
              return SessionResult::CloseSession;
            }
          }
        }

        let res = self.frontend.read(metrics);

        //FIXME
        if res != FrontResult::Continue {
          return SessionResult::CloseSession;
        }
      }

      match self.frontend.parse(metrics) {
        Continue => return SessionResult::Continue,
        Error => return SessionResult::CloseSession,
        Closed => return SessionResult::CloseSession,
        Request(StreamId, ParsedRequest<'buffer>) {

        },
        Data(StreamId, usize) => unimplemented!(),
        /// stream id, chunk header size, data size
        Chunk(StreamId, usize, usize) => unimplemented!(),
      }
    }

    SessionResult::CloseSession
  }
}
