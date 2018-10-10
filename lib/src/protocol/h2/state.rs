use super::parser;
use nom::{HexDisplay,Offset};

#[derive(Clone,Debug,PartialEq)]
pub struct State {
  pub started: bool,
}

impl State {
  pub fn new() -> State {
    State {
      started: false,
    }
  }

  pub fn parse_front(&mut self, mut input: &[u8]) -> (usize, Result<parser::FrameHeader, ()>) {
    let mut consumed = 0usize;

    if ! self.started {
      match parser::preface(input) {
        Err(e) => {
          error!("parser::preface error: {:?}", e);
          return (0, Err(()));
        },
        Ok((i, _)) => {
          consumed += input.offset(i);
          self.started = true;
          input = i;
        }
      }
    }


    match parser::frame(input) {
      Err(e) => {
        error!("parser::frame error: {:?}", e);
        (consumed, Err(()))
      },
      Ok((i, frame)) => {
        consumed += input.offset(i);
        (consumed, Ok(frame))
      }
    }
  }
}
