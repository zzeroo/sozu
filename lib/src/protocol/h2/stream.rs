use std::collections::VecDeque;
use hpack::Decoder;
use std::str::from_utf8;

use super::state::OutputFrame;
use super::parser;

#[derive(Clone,Debug,PartialEq)]
pub enum St {
  Init,
  ClientPrefaceReceived,
  ServerPrefaceSent,
}

#[derive(Clone,Debug,PartialEq)]
pub struct Stream {
  pub id: u32,
  pub state: StreamState,
  pub output: VecDeque<OutputFrame>,
  pub inbound_headers: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum StreamState {
  Idle,
  ReservedLocal,
  ReservedRemote,
  Open,
  HalfClosedLocal,
  HalfClosedRemote,
  Closed,
}

impl Stream {
  pub fn new(id: u32) -> Stream {
    info!("new stream with id {}", id);

    Stream {
      id,
      state: StreamState::Idle,
      output: VecDeque::new(),
      inbound_headers: None,
    }
  }

  pub fn handle(&mut self, frame: &parser::Frame) -> bool {
    match self.state {
      StreamState::Idle => {
        match frame {
          parser::Frame::Headers(h) => {
            let mut decoder = Decoder::new();
            match decoder.decode(h.header_block_fragment) {
              Err(e) => {
                error!("error decoding headers: {:?}", e);
              },
              Ok(h) => {
                for header in &h {
                  info!("{}: {}",
                    from_utf8(&header.0).unwrap(), from_utf8(&header.1).unwrap());
                }

                self.inbound_headers = Some(h);
                self.state = StreamState::Open;
                info!("stream[{}] state is now {:?}", self.id, self.state);
              }
            };

            false
          },
          frame => {
            panic!("unknown frame for now: {:?}", frame);
          }
        }
      },
      s => {
        unimplemented!("stream[{}] state {:?} not implemented", self.id, self.state);
      }
    }
  }
}
