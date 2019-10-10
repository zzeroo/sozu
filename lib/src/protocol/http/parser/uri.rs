// reference: https://tools.ietf.org/html/rfc3986
use nom::{
  IResult, Slice, Offset, Err,
  error::ErrorKind,
  combinator::{opt, recognize},
  sequence::{tuple, terminated, delimited, preceded},
  branch::alt,
  bytes::complete::{tag, take_while},
  character::complete::{char, alpha1, digit1}
};

use std::str::from_utf8;

#[derive(Debug,Clone,PartialEq)]
pub struct Uri<'a> {
  pub scheme: &'a [u8],
  pub authority: Authority<'a>,
  pub path: &'a[u8],
  pub query: Option<&'a[u8]>,
  pub fragment: Option<&'a[u8]>,
}

pub fn uri(i:&[u8]) -> IResult<&[u8], Uri> {
  let (i, (scheme, _)) = tuple((scheme, tag("://")))(i)?;
  let (i, authority) = authority(i)?;
  let (i, path) = path_abempty(i)?;
  let (i, query) = opt(preceded(char('?'), query_or_fragment))(i)?;
  let (i, fragment) = opt(preceded(char('#'), query_or_fragment))(i)?;

  if i.len() > 0 {
    Err(Err::Error(error_position!(i, ErrorKind::Eof)))
  } else {
    Ok((i, Uri { scheme, authority, path, query, fragment }))
  }
}

pub fn absolute_path(i: &[u8]) -> IResult<&[u8], &[u8]> {
  let (i, o) = recognize(tuple((path_abempty, opt(preceded(char('?'), query_or_fragment)))))(i)?;
  if o.len() > 0 {
    Ok((i, o))
  } else {
    Err(Err::Error(error_position!(i, ErrorKind::Eof)))
  }
}

pub fn scheme(i: &[u8]) -> IResult<&[u8], &[u8]> {
  recognize(tuple((
        alpha1,
        take_while(|c| {
          (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') || c == b'+' || c == b'-' || c == b'.'
        })
  )))(i)
}

#[derive(Debug,Clone,PartialEq)]
pub struct Authority<'a> {
  pub user_info: Option<&'a[u8]>,
  pub host: &'a[u8],
  pub host_and_port: &'a[u8],
}

pub fn authority(i:&[u8]) -> IResult<&[u8], Authority> {
  //println!("URI parser: {}", from_utf8(i).unwrap());
  let (i, u) = opt(terminated(user_info, char('@')))(i)?;
  //println!("URI parser: {}", from_utf8(i).unwrap());
  let i1 = i.clone();
  let (i, h) = host(i)?;
  //println!("URI parser: {} | host: {}", from_utf8(i).unwrap(), from_utf8(h).unwrap());
  let (i, _) = opt(preceded(char(':'), digit1))(i)?;
  //println!("URI parser: {}", from_utf8(i).unwrap());
  let index = i1.offset(i);
  let hp = i1.slice(..index);
  //println!("URI parser: {}", from_utf8(i).unwrap());

  Ok((i, Authority { user_info: u, host: h, host_and_port: hp }))
}

// slightly incorrect user info parser (not parsing percent encoded data correctly, but we do not care about it
pub fn user_info(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    //unreserved
    (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') ||
      c == b'_' || c == b'.' || c == b'-' || c == b'~' ||
      // percent encoding
      c == b'%' ||
      //sub-delims
      c== b'!' || c == b'$' || c ==  b'&' || c == b'\'' || c ==  b'(' || c ==  b')' ||
      c == b'*' || c == b'+' || c == b',' || c == b';' || c == b'=' ||
      // :
      c == b':'
  })(i)
}

pub fn host(i: &[u8]) -> IResult<&[u8], &[u8]> {
  alt((
    delimited(char('['), ipv6_or_future, char(']')),
    ipv4,
    reg_name
  ))(i)
}

// not really spec comliant
// does not handle ipvfuture
pub fn ipv6_or_future(i: &[u8]) -> IResult<&[u8], &[u8]> {
  // ipv6
  take_while(|c| {
    (b'A' <= c && c <= b'F') || (b'a' <= c && c <= b'f') || (b'0' <= c && c <= b'9') ||
      c == b':' || c == b'.'
  })(i)
}

// not really spec compliant either
pub fn ipv4(i: &[u8]) -> IResult<&[u8], &[u8]> {
  recognize(tuple((
    dec_digit, char('.'), dec_digit, char('.'), dec_digit, char('.'), dec_digit
  )))(i)
}

// not spec compliant, will only recognize host names (the URI spec also handles files)
pub fn reg_name(i: &[u8]) -> IResult<&[u8], &[u8]> {
  let i1 = i.clone();
  //println!("reg_name1: {}", from_utf8(i).unwrap());
  let (mut i, n) = name_element(i)?;
  //println!("reg_name2: {} name = {}", from_utf8(i).unwrap(), from_utf8(n).unwrap());

  loop {
    match preceded(char('.'), name_element)(i) {
      Ok((i2, _)) => i = i2,
      _ => break,
    }
  //println!("reg_name3: {}", from_utf8(i).unwrap());
  }

  let index = i1.offset(i);
  //println!("reg_name3: {} | index = {}", from_utf8(i).unwrap(), index);

  Ok((i, i1.slice(..index)))
}

pub fn hex_digit(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    (b'A' <= c && c <= b'F') || (b'a' <= c && c <= b'f') || (b'0' <= c && c <= b'9')
  })(i)
}

pub fn dec_digit(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    (b'0' <= c && c <= b'9')
  })(i)
}

pub fn name_element(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') || c == b'-'
  })(i)
}

// HTTP URIs only support that kind of path
pub fn path_abempty(mut i: &[u8]) -> IResult<&[u8], &[u8]> {
  let i1 = i.clone();

  loop {
    match preceded(char('/'), segment)(i) {
      Ok((i2, _)) => i = i2,
      _ => break,
    }
  }

  let index = i1.offset(i);

  Ok((i, i1.slice(..index)))
}

pub fn segment(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    //unreserved
    (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') ||
      c == b'_' || c == b'.' || c == b'-' || c == b'~' ||
      // percent encoding
      c == b'%' ||
      //sub-delims
      c== b'!' || c == b'$' || c ==  b'&' || c == b'\'' || c ==  b'(' || c ==  b')' ||
      c == b'*' || c == b'+' || c == b',' || c == b';' || c == b'=' ||
      // : @
      c == b':' || c == b'@'
  })(i)
}

pub fn query_or_fragment(i: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c| {
    //unreserved
    (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') ||
      c == b'_' || c == b'.' || c == b'-' || c == b'~' ||
      // percent encoding
      c == b'%' ||
      //sub-delims
      c== b'!' || c == b'$' || c ==  b'&' || c == b'\'' || c ==  b'(' || c ==  b')' ||
      c == b'*' || c == b'+' || c == b',' || c == b';' || c == b'=' ||
      // : @
      c == b':' || c == b'@' ||
      // / ?
      c == b'/' || c == b'?'
  })(i)
}
