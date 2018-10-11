use nom::{Err, ErrorKind, HexDisplay, IResult, Offset, be_u8, be_u24, be_u32};

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
/*named!(pub frame_header<FrameHeader>,
  do_parse!(
    payload_len: dbg_dmp!(be_u24) >>
    frame_type: map_opt!(be_u8, convert_frame_type) >>
    flags: dbg_dmp!(be_u8) >>
    stream_id: dbg_dmp!(verify!(be_u32, |id| {
      match frame_type {
        
      }
    }) >>
    (FrameHeader { payload_len, frame_type, flags, stream_id })
  )
);
  */

pub fn frame_header(input: &[u8]) -> IResult<&[u8], FrameHeader> {
  let (i1, payload_len) = be_u24(input)?;
  let (i2, frame_type)  = map_opt!(i1, be_u8, convert_frame_type)?;
  let (i3, flags)       = be_u8(i2)?;
  let (i4, stream_id)   = be_u32(i3)?;

  Ok((i4, FrameHeader { payload_len, frame_type, flags, stream_id }))
}

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

#[derive(Clone,Debug,PartialEq)]
pub enum Frame {
  Data(Data),
  Headers,
  Priority,
  RstStream(RstStream),
  Settings,
  PushPromise,
  Ping(Ping),
  GoAway,
  WindowUpdate(WindowUpdate),
  Continuation,
}

pub fn frame(input: &[u8], max_frame_size: u32) -> IResult<&[u8], FrameHeader> {
  let (i,header) = frame_header(input)?;

  if header.payload_len > max_frame_size {
    return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
  }

  let valid_stream_id = match header.frame_type {
    FrameType::Data | FrameType::Headers | FrameType::Priority
      | FrameType::RstStream | FrameType::PushPromise
      | FrameType::Continuation => header.stream_id != 0,
    FrameType::Settings | FrameType::Ping | FrameType::GoAway => header.stream_id == 0,
    FrameType::WindowUpdate => true,
  };

  if !valid_stream_id {
    return Err(Err::Failure(error_position!(input, ErrorKind::Custom(PROTOCOL_ERROR))));
  }

  let f = match header.frame_type {
    FrameType::Data => {
      data_frame(i, &header)
    },
    FrameType::Headers => {
      unimplemented!();
    },
    FrameType::Priority => {
      if header.payload_len != 5 {
        return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
      }
      unimplemented!();
    },
    FrameType::RstStream => {
      if header.payload_len != 4 {
        return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
      }
      rst_stream_frame(i, &header)
    },
    FrameType::PushPromise => {
      unimplemented!();
    },
    FrameType::Continuation => {
      unimplemented!();
    },
    FrameType::Settings => {
      if header.payload_len % 6 != 0 {
        return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
      }
      unimplemented!();
    },
    FrameType::Ping => {
      if header.payload_len != 8 {
        return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
      }
      ping_frame(i, &header)
    },
    FrameType::GoAway => {
      unimplemented!();
    },
    FrameType::WindowUpdate => {
      if header.payload_len != 4 {
        return Err(Err::Failure(error_position!(input, ErrorKind::Custom(FRAME_SIZE_ERROR))));
      }
      window_update_frame(i, &header)
    }
  };

  Ok((i, header))
}

#[derive(Clone,Debug,PartialEq)]
pub struct Data {
  pub stream_id: u32,
  pub payload_len: u32,
  pub padding_len: u8,
  pub end: bool,
}

pub fn data_frame<'a,'b>(input: &'a[u8], header: &'b FrameHeader) -> IResult<&'a [u8], Frame> {
  do_parse!(input,
    pad_length: cond!(header.flags & 0x8 != 0, be_u8) >>
    (Frame::Data(Data {
      stream_id: header.stream_id,
      payload_len: header.payload_len,
      padding_len: pad_length.unwrap_or(0),
      end: header.flags & 0x1 != 0,
    }))
  )
}

#[derive(Clone,Debug,PartialEq)]
pub struct RstStream {
  pub error_code: u32,
}

pub fn rst_stream_frame<'a,'b>(input: &'a[u8], header: &'b FrameHeader) -> IResult<&'a [u8], Frame> {
  map!(input,
    be_u32,
    |error_code| {
      Frame::RstStream(RstStream { error_code })
  })
}

#[derive(Clone,Debug,PartialEq)]
pub struct Ping {
  pub payload: [u8; 8],
}

pub fn ping_frame<'a,'b>(input: &'a[u8], header: &'b FrameHeader) -> IResult<&'a [u8], Frame> {
  map!(input,
    take!(8),
    |data| {
      let mut p = Ping {
        payload: [0; 8]
      };

      for i in 0..8 {
        p.payload[i] = data[i];
      }

      Frame::Ping(p)
    }
  )
}

#[derive(Clone,Debug,PartialEq)]
pub struct WindowUpdate {
  pub increment: u32,
}

pub fn window_update_frame<'a,'b>(input: &'a[u8], header: &'b FrameHeader) -> IResult<&'a [u8], Frame> {
  let (i, increment) = be_u32(input)?;
  let increment = increment & 0x7FFF;

  //FIXME: if stream id is 0, trat it as connection error?
  if increment == 0 {
    return Err(Err::Failure(error_position!(input, ErrorKind::Custom(PROTOCOL_ERROR))));
  }

  Ok((i, Frame::WindowUpdate(WindowUpdate { increment })))
}

#[macro_export]
macro_rules! map_err(
  (__impl $i:expr, $submac:ident!( $($args:tt)* ), $g:expr) => (
    ($submac!($i, $($args)*)).map_err(|e| {
      $g(e)
    })
  );
);

const NO_ERROR: u32 = 0x0;
const PROTOCOL_ERROR: u32 = 0x1;
const INTERNAL_ERROR: u32 = 0x2;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const SETTINGS_TIMEOUT: u32 = 0x4;
const STREAM_CLOSED: u32 = 0x5;
const FRAME_SIZE_ERROR: u32 = 0x6;
const REFUSED_STREAM: u32 = 0x7;
const CANCEL: u32 = 0x8;
const COMPRESSION_ERROR: u32 = 0x9;
const CONNECT_ERROR: u32 = 0xa;
const ENHANCE_YOUR_CALM: u32 = 0xb;
const INADEQUATE_SECURITY: u32 = 0xc;
const HTTP_1_1_REQUIRED: u32 = 0xd;
