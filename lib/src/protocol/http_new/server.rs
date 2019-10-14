use super::parser::request::*;
use super::FrontResult;

pub struct Server {
  parser: Option<RequestParser>,
}

impl Server {
  pub fn new() -> Self {
    Server { parser: Some(RequestParser::Initial) }
  }

  pub fn parse<'a, 'buffer>(&'a mut self, input: &'buffer [u8]) -> FrontResult<'buffer> {
    let mut state = self.parser.take().unwrap();

    loop {
      let previous_position = state.position();

      state = state.parse(&input[..]);

      println!("state is now: {:?}", state);
      if state.is_error() {
        println!("got an error");
        return FrontResult::Error;
      }

      if state.position() == previous_position {
        println!("position did not change, failed advancing");
        return FrontResult::Continue;
      }

      if state.is_finished() {
        println!("done");
        break;
      }
    }

    if let Some(req) = state.validate(&input[..]) {
      println!("validated request: {:?}", req);
      for (name, value) in req.headers.iter() {
        println!("{} -> {}", name, value);
      }

      self.parser = Some(state);

      FrontResult::Request(0, req)
    } else {
      FrontResult::Error
    }


  }
}
