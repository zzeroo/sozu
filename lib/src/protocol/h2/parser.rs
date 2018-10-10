use nom::{HexDisplay, IResult, Offset, be_u8, be_u24, be_u32};

#[derive(Clone,Debug,PartialEq)]
pub struct FrameHeader {
  pub payload_len: u32,
  pub frame_type:  FrameType,
  pub flags:       u8,
  pub stream_id:   u32,
}

#[derive(Clone,Debug,PartialEq)]
pub enum FrameType {
  Data,
  Headers,
  Priority,
  RstStream,
  Settings,
  PushPromise,
  Ping,
  GoAway,
  WindowUpdate,
  Continuation,
}

named!(pub preface,
  tag!(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
);

// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1
named!(pub frame<FrameHeader>,
  do_parse!(
    payload_len: dbg_dmp!(be_u24) >>
    frame_type: map_opt!(be_u8, convert_frame_type) >>
    flags: dbg_dmp!(be_u8) >>
    stream_id: dbg_dmp!(be_u32) >>
    (FrameHeader { payload_len, frame_type, flags, stream_id })
  )
);

fn convert_frame_type(t: u8) -> Option<FrameType> {
  info!("got frame type: {}", t);
  match t {
    0 => Some(FrameType::Data),
    1 => Some(FrameType::Headers),
    2 => Some(FrameType::Priority),
    3 => Some(FrameType::RstStream),
    4 => Some(FrameType::Settings),
    5 => Some(FrameType::PushPromise),
    6 => Some(FrameType::Ping),
    7 => Some(FrameType::GoAway),
    8 => Some(FrameType::WindowUpdate),
    9 => Some(FrameType::Continuation),
    _ => None,
  }
}
