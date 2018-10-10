use std::cmp::min;
use std::io::{Write,BufRead};
use std::net::{SocketAddr,IpAddr};
use std::cell::RefCell;
use std::rc::Weak;
use mio::*;
use mio::tcp::TcpStream;
use mio::unix::UnixReady;
use time::{Duration, precise_time_s, precise_time_ns};
use uuid::Uuid;
use {SessionResult,Readiness,SessionMetrics,Protocol};
use buffer_queue::BufferQueue;
use socket::{SocketHandler,SocketResult};
use pool::{Pool,Checkout,Reset};
use nom::{HexDisplay,Offset};

mod parser;
mod serializer;
mod state;

type BackendToken = Token;

#[derive(PartialEq)]
pub enum SessionStatus {
  Normal,
  DefaultAnswer,
}

pub struct Http2<Front:SocketHandler> {
  pub frontend:        Front,
  backend:             Option<TcpStream>,
  frontend_token:      Token,
  backend_token:       Option<Token>,
  pub front_buf:       Option<Checkout<BufferQueue>>,
  back_buf:            Option<Checkout<BufferQueue>>,
  pub app_id:          Option<String>,
  pub request_id:      String,
  pub front_readiness: Readiness,
  pub back_readiness:  Readiness,
  pub log_ctx:         String,
  public_address:      Option<IpAddr>,
  pub state:           Option<state::State>,
  pool:                Weak<RefCell<Pool<BufferQueue>>>,
}

impl<Front:SocketHandler> Http2<Front> {
  pub fn new(frontend: Front, frontend_token: Token, pool: Weak<RefCell<Pool<BufferQueue>>>,
  public_address: Option<IpAddr>, client_address: Option<SocketAddr>, sticky_name: String,
  protocol: Protocol) -> Http2<Front> {
    let request_id = Uuid::new_v4().hyphenated().to_string();
    let log_ctx    = format!("{}\tunknown\t", &request_id);
    let session = Http2 {
      frontend,
      frontend_token,
      backend:            None,
      backend_token:      None,
      front_buf:          None,
      back_buf:           None,
      app_id:             None,
      state:              Some(state::State::new()),
      request_id,
      front_readiness:    Readiness {
                            interest:  UnixReady::from(Ready::readable() | Ready::writable()) | UnixReady::hup() | UnixReady::error(),
                            event: UnixReady::from(Ready::empty()),
      },
      back_readiness:    Readiness {
                            interest:  UnixReady::from(Ready::readable() | Ready::writable()) | UnixReady::hup() | UnixReady::error(),
                            event: UnixReady::from(Ready::empty()),
      },
      log_ctx,
      public_address,
      pool,
    };

    trace!("created http2");
    session
  }

  fn tokens(&self) -> Option<(Token,Token)> {
    if let Some(back) = self.backend_token {
      return Some((self.frontend_token, back))
    }
    None
  }

  pub fn front_socket(&self) -> &TcpStream {
    self.frontend.socket_ref()
  }

  pub fn back_socket(&self)  -> Option<&TcpStream> {
    self.backend.as_ref()
  }

  pub fn set_back_socket(&mut self, socket: TcpStream) {
    self.backend = Some(socket);
  }

  pub fn back_token(&self)   -> Option<Token> {
    self.backend_token
  }

  pub fn close(&mut self) {
  }

  pub fn log_context(&self) -> String {
    if let Some(ref app_id) = self.app_id {
      format!("{}\t{}\t", self.request_id, app_id)
    } else {
      format!("{}\tunknown\t", self.request_id)
    }
  }

  pub fn set_back_token(&mut self, token: Token) {
    self.backend_token = Some(token);
  }

  pub fn front_readiness(&mut self) -> &mut Readiness {
    &mut self.front_readiness
  }

  pub fn back_readiness(&mut self) -> &mut Readiness {
    &mut self.back_readiness
  }

  pub fn front_hup(&mut self) -> SessionResult {
    SessionResult::CloseSession
  }

  pub fn back_hup(&mut self) -> SessionResult {
    error!("todo[{}:{}]: back_hup", file!(), line!());
    SessionResult::CloseSession
    /*
    if self.back_buf.output_data_size() == 0 || self.back_buf.next_output_data().len() == 0 {
      if self.back_readiness.event.is_readable() {
        self.back_readiness().interest.insert(Ready::readable());
        error!("Http2::back_hup: backend connection closed but the kernel still holds some data. readiness: {:?} -> {:?}", self.front_readiness, self.back_readiness);
        SessionResult::Continue
      } else {
        SessionResult::CloseSession
      }
    } else {
      self.front_readiness().interest.insert(Ready::writable());
      if self.back_readiness.event.is_readable() {
        self.back_readiness.interest.insert(Ready::readable());
      }
      SessionResult::Continue
    }
    */
  }

  // Read content from the session
  pub fn readable(&mut self, metrics: &mut SessionMetrics) -> SessionResult {
    trace!("http2 readable");
    error!("todo[{}:{}]: readable", file!(), line!());

    if self.front_buf.is_none() {
      if let Some(p) = self.pool.upgrade() {
        if let Some(buf) = p.borrow_mut().checkout() {
          self.front_buf = Some(buf);
        } else {
          error!("cannot get front buffer from pool, closing");
          return SessionResult::CloseSession;
        }
      }
    }

    if self.front_buf.as_ref().unwrap().buffer.available_space() == 0 {
      if self.backend_token == None {
        //let answer_413 = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
        //self.set_answer(DefaultAnswerStatus::Answer413, Rc::new(Vec::from(answer_413.as_bytes())));
        self.front_readiness.interest.remove(Ready::readable());
        self.front_readiness.interest.insert(Ready::writable());
      } else {
        self.front_readiness.interest.remove(Ready::readable());
        self.back_readiness.interest.insert(Ready::writable());
      }
      return SessionResult::Continue;
    }

    let (sz, res) = self.frontend.socket_read(self.front_buf.as_mut().unwrap().buffer.space());
    info!("{}\tFRONT: read {} bytes", self.log_ctx, sz);

    if sz > 0 {
      count!("bytes_in", sz as i64);
      metrics.bin += sz;

      self.front_buf.as_mut().map(|front_buf| {
        front_buf.buffer.fill(sz);
        front_buf.sliced_input(sz);
        if front_buf.start_parsing_position > front_buf.parsed_position {
          let to_consume = min(front_buf.input_data_size(), front_buf.start_parsing_position - front_buf.parsed_position);
          front_buf.consume_parsed_data(to_consume);
        }
      });

      if self.front_buf.as_ref().unwrap().buffer.available_space() == 0 {
        self.front_readiness.interest.remove(Ready::readable());
      }
    } else {
      self.front_readiness.event.remove(Ready::readable());
    }

    match res {
      SocketResult::Error => {
        let front_readiness = self.front_readiness.clone();
        let back_readiness  = self.back_readiness.clone();
        error!("front socket error, closing the connection. Readiness: {:?} -> {:?}", front_readiness, back_readiness);
        return SessionResult::CloseSession;
      },
      SocketResult::Closed => {
        return SessionResult::CloseSession;
      },
      SocketResult::WouldBlock => {
        self.front_readiness.event.remove(Ready::readable());
      },
      SocketResult::Continue => {}
    };

    self.readable_parse(metrics)
  }

  pub fn readable_parse(&mut self, metrics: &mut SessionMetrics) -> SessionResult {
    let mut state = self.state.take().unwrap();
    let (sz, res) = {
      state.parse_front(self.front_buf.as_ref().unwrap().unparsed_data())
    };
    self.front_buf.as_mut().unwrap().consume_parsed_data(sz);
    info!("parsed: {:?}", res);

    match res {
      Err(e) => {
        error!("error parsing frame: {:?}", e);
        self.state = Some(state);
        SessionResult::CloseSession
      },
      Ok(frame) => {
        if state.handle_front(&frame) {
          self.front_readiness.interest = state.front_interest;
          self.state = Some(state);
          SessionResult::Continue
        } else {
          self.state = Some(state);
          SessionResult::CloseSession
        }
      }
    }


    /*let is_initial = unwrap_msg!(self.state.as_ref()).request == Some(RequestState::Initial);
    // if there's no host, continue parsing until we find it
    let has_host = unwrap_msg!(self.state.as_ref()).has_host();
    if !has_host {
      self.state = Some(parse_request_until_stop(unwrap_msg!(self.state.take()), &self.request_id,
        &mut self.front_buf.as_mut().unwrap(), &self.sticky_name));
      if unwrap_msg!(self.state.as_ref()).is_front_error() {
        self.log_request_error(metrics, "front parsing error, closing the connection");
        incr!("http.front_parse_errors");

        // increment active requests here because it will be decremented right away
        // when closing the connection. It's slightly easier than decrementing it
        // at every place we return SessionResult::CloseSession
        gauge_add!("http.active_requests", 1);

        return SessionResult::CloseSession;
      }
    }
    */
  }


  // Forward content to session
  pub fn writable(&mut self, metrics: &mut SessionMetrics) -> SessionResult {
    trace!("http2 writable");
    error!("todo[{}:{}]: writable", file!(), line!());
    SessionResult::CloseSession
    /*
    if self.back_buf.output_data_size() == 0 || self.back_buf.next_output_data().len() == 0 {
      self.back_readiness.interest.insert(Ready::readable());
      self.front_readiness.interest.remove(Ready::writable());
      return SessionResult::Continue;
    }

    let mut sz = 0usize;
    let mut res = SocketResult::Continue;
    while res == SocketResult::Continue && self.back_buf.output_data_size() > 0 {
      // no more data in buffer, stop here
      if self.back_buf.next_output_data().len() == 0 {
        self.back_readiness.interest.insert(Ready::readable());
        self.front_readiness.interest.remove(Ready::writable());
        return SessionResult::Continue;
      }
      let (current_sz, current_res) = self.frontend.socket_write(self.back_buf.next_output_data());
      res = current_res;
      self.back_buf.consume_output_data(current_sz);
      self.back_buf_position += current_sz;
      sz += current_sz;
    }

    if sz > 0 {
      count!("bytes_out", sz as i64);
      self.back_readiness.interest.insert(Ready::readable());
      metrics.bout += sz;
    }

    if let Some((front,back)) = self.tokens() {
      debug!("{}\tFRONT [{}<-{}]: wrote {} bytes of {}, buffer position {} restart position {}",
        self.log_ctx, front.0, back.0, sz, self.back_buf.output_data_size(),
        self.back_buf.buffer_position, self.back_buf.start_parsing_position);
    }

    match res {
      SocketResult::Error | SocketResult::Closed => {
        error!("{}\t[{:?}] error writing to front socket, closing", self.log_ctx, self.frontend_token);
        incr!("http2.errors");
        metrics.service_stop();
        self.front_readiness.reset();
        self.back_readiness.reset();
        return SessionResult::CloseSession;
      },
      SocketResult::WouldBlock => {
        self.front_readiness.event.remove(Ready::writable());
      },
      SocketResult::Continue => {},
    }

    SessionResult::Continue
    */
  }

  // Forward content to application
  pub fn back_writable(&mut self, metrics: &mut SessionMetrics) -> SessionResult {
    trace!("http2 back_writable");
    error!("todo[{}:{}]: back_writable", file!(), line!());
    SessionResult::CloseSession
    /*
    if self.front_buf.output_data_size() == 0 || self.front_buf.next_output_data().len() == 0 {
      self.front_readiness.interest.insert(Ready::readable());
      self.back_readiness.interest.remove(Ready::writable());
      return SessionResult::Continue;
    }

    let tokens = self.tokens().clone();
    let output_size = self.front_buf.output_data_size();

    let mut sz = 0usize;
    let mut socket_res = SocketResult::Continue;

    if let Some(ref mut backend) = self.backend {
      while socket_res == SocketResult::Continue && self.front_buf.output_data_size() > 0 {
        // no more data in buffer, stop here
        if self.front_buf.next_output_data().len() == 0 {
          self.front_readiness.interest.insert(Ready::readable());
          self.back_readiness.interest.remove(Ready::writable());
          return SessionResult::Continue;
        }

        let (current_sz, current_res) = backend.socket_write(self.front_buf.next_output_data());
        socket_res = current_res;
        self.front_buf.consume_output_data(current_sz);
        self.front_buf_position += current_sz;
        sz += current_sz;
      }
    }

    metrics.backend_bout += sz;

    if let Some((front,back)) = tokens {
      debug!("{}\tBACK [{}->{}]: wrote {} bytes of {}", self.log_ctx, front.0, back.0, sz, output_size);
    }
    match socket_res {
      SocketResult::Error | SocketResult::Closed => {
        error!("{}\tback socket write error, closing connection", self.log_ctx);
        metrics.service_stop();
        incr!("http2.errors");
        self.front_readiness.reset();
        self.back_readiness.reset();
        return SessionResult::CloseSession;
      },
      SocketResult::WouldBlock => {
        self.back_readiness.event.remove(Ready::writable());

      },
      SocketResult::Continue => {}
    }
    SessionResult::Continue
    */
  }

  // Read content from application
  pub fn back_readable(&mut self, metrics: &mut SessionMetrics) -> SessionResult {
    trace!("http2 back_readable");
    error!("todo[{}:{}]: back_readable", file!(), line!());
    SessionResult::CloseSession
    /*
    if self.back_buf.buffer.available_space() == 0 {
      self.back_readiness.interest.remove(Ready::readable());
      return SessionResult::Continue;
    }

    let tokens     = self.tokens().clone();

    if let Some(ref mut backend) = self.backend {
      let (sz, r) = backend.socket_read(&mut self.back_buf.buffer.space());
      self.back_buf.buffer.fill(sz);
      self.back_buf.sliced_input(sz);
      self.back_buf.consume_parsed_data(sz);
      self.back_buf.slice_output(sz);

      if let Some((front,back)) = tokens {
        debug!("{}\tBACK  [{}<-{}]: read {} bytes", self.log_ctx, front.0, back.0, sz);
      }

      if r != SocketResult::Continue || sz == 0 {
        self.back_readiness.event.remove(Ready::readable());
      }
      if sz > 0 {
        self.front_readiness.interest.insert(Ready::writable());
        metrics.backend_bin += sz;
      }

      match r {
        SocketResult::Error => {
          error!("{}\tback socket read error, closing connection", self.log_ctx);
          metrics.service_stop();
          incr!("http2.errors");
          self.front_readiness.reset();
          self.back_readiness.reset();
          return SessionResult::CloseSession;
        },
        SocketResult::Closed => {
          metrics.service_stop();
          self.front_readiness.reset();
          self.back_readiness.reset();
          return SessionResult::CloseSession;
        },
        SocketResult::WouldBlock => {
          self.back_readiness.event.remove(Ready::readable());
        },
        SocketResult::Continue => {}
      }
    }

    SessionResult::Continue
    */
  }
}

