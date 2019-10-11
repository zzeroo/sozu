use std::cmp::min;
use std::rc::{Rc,Weak};
use std::cell::RefCell;
use std::net::{SocketAddr,IpAddr};
use mio::*;
use mio::unix::UnixReady;
use mio::tcp::TcpStream;
use uuid::{Uuid, adapter::Hyphenated};
use sozu_command::buffer::Buffer;
use super::super::{SessionResult,Protocol,Readiness,SessionMetrics, LogDuration};
use buffer_queue::BufferQueue;
use socket::{SocketHandler,SocketResult};
use protocol::ProtocolResult;
use pool::Pool;
use util::UnwrapLog;

pub mod parser;
pub mod cookies;
pub mod answers;
pub mod client;
pub mod server;

/*
use self::parser::{parse_request_until_stop, parse_response_until_stop,
  RequestState, ResponseState, Chunk, Continue, RRequestLine, RStatusLine,
  compare_no_case};
*/

#[derive(Clone)]
pub struct StickySession {
  pub sticky_id: String
}

impl StickySession {
  pub fn new(backend_id: String) -> StickySession {
    StickySession {
      sticky_id: backend_id
    }
  }
}

#[derive(Debug,Clone,PartialEq)]
pub enum SessionStatus {
  Normal,
  /// status, HTTP answer, index in HTTP answer
  DefaultAnswer(DefaultAnswerStatus, Rc<Vec<u8>>, usize),
}

#[derive(Debug,Clone,Copy,PartialEq)]
pub enum DefaultAnswerStatus {
  Answer301,
  Answer400,
  Answer404,
  Answer408,
  Answer413,
  Answer503,
  Answer504,
}

#[derive(Debug,Clone,Copy,PartialEq)]
pub enum TimeoutStatus {
  Request,
  Response,
  WaitingForNewRequest,
}

/*
pub struct Http<Front:SocketHandler> {
  pub frontend:       Front,
  pub backend:        Option<TcpStream>,
  frontend_token:     Token,
  backend_token:      Option<Token>,
  pub status:         SessionStatus,
  pub front_buf:      Option<BufferQueue>,
  pub back_buf:       Option<BufferQueue>,
  pub app_id:         Option<String>,
  pub request_id:     Hyphenated,
  pub front_readiness:Readiness,
  pub back_readiness: Readiness,
  pub log_ctx:        String,
  pub public_address: Option<SocketAddr>,
  pub session_address: Option<SocketAddr>,
  pub sticky_name:    String,
  pub sticky_session: Option<StickySession>,
  pub protocol:       Protocol,
  pub request:        Option<RequestState>,
  pub response:       Option<ResponseState>,
  pub req_header_end: Option<usize>,
  pub res_header_end: Option<usize>,
  pub added_req_header: String,
  pub added_res_header: String,
  pub keepalive_count: usize,
  pool:                Weak<RefCell<Pool<Buffer>>>,
}

*/
