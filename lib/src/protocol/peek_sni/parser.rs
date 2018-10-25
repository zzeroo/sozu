/// source: https://github.com/rusticata/tls-parser
use nom::{IResult, ErrorKind, be_u8, be_u16, be_u24, be_u32};

#[macro_export]
macro_rules! error_if (
  ($i:expr, $cond:expr, $err:expr) => (
    {
      if $cond {
        Err(::nom::Err::Error(error_position!($i, $err)))
      } else {
        Ok(($i, ()))
      }
    }
  );
);

pub fn parse_sni_from_client_hello(i:&[u8]) -> IResult<&[u8],Option<Vec<Option<SNIList>>>> {
    do_parse!(i,
        hdr: parse_tls_record_header >>
        msg: flat_map!(
              take!(hdr.len),
              parse_client_hello
            ) >>
        ( msg )
    )
}

#[derive(Clone,PartialEq)]
pub struct TlsRecordHeader {
    pub record_type: TlsRecordType,
    pub version: u16,
    pub len: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordType(pub u8);

#[allow(non_upper_case_globals)]
impl TlsRecordType {
    pub const ChangeCipherSpec : TlsRecordType = TlsRecordType(0x14);
    pub const Alert            : TlsRecordType = TlsRecordType(0x15);
    pub const Handshake        : TlsRecordType = TlsRecordType(0x16);
    pub const ApplicationData  : TlsRecordType = TlsRecordType(0x17);
    pub const Heartbeat        : TlsRecordType = TlsRecordType(0x18);
}

named!(parse_tls_record_header<TlsRecordHeader>,
    do_parse!(
        t: verify!(be_u8, |r| r == 0x16) >> // force the Handshake type
        v: be_u16 >>
        l: be_u16 >>
        (
            TlsRecordHeader {
                record_type: TlsRecordType(t),
                version: v,
                len: l,
            }
        )
    )
);


named!(parse_client_hello<Option<Vec<Option<SNIList>>>>,
  do_parse!(
    ht: tag!([0x01]) >> // ClientHello
    hl: be_u24 >>
    m: flat_map!(
      take!(hl),
      parse_tls_handshake_msg_client_hello
    ) >> (m)
  )
);

named!(parse_tls_handshake_msg_client_hello<Option<Vec<Option<SNIList>>>>,
  do_parse!(
      v:         be_u16  >>
      rand_time: be_u32 >>
      rand_data: take!(28) >> // 28 as 32 (aligned) - 4 (time)
      sidlen:    be_u8 >> // check <= 32, can be 0
                 error_if!(sidlen > 32, ErrorKind::Custom(128)) >>
      sid:       cond!(sidlen > 0, take!(sidlen as usize)) >>
      ciphers_len: be_u16 >>
      ciphers:   take!(ciphers_len) >> // skip ciphers call!(parse_cipher_suites, ciphers_len as usize) >>
      comp_len:  be_u8 >>
      comp:      take!(comp_len) >> // skip compression algorithms call!(parse_compressions_algs, comp_len as usize) >>
      ext:       opt!(flat_map!(
                   complete!(length_bytes!(be_u16)),
                   parse_tls_extensions
                 )) >>
      (ext)
  )
);

named!(pub parse_tls_extensions<Vec<Option<SNIList>>>,
    many0!(complete!(parse_tls_extension))
);

named!(pub parse_tls_extension<Option<SNIList>>,
   do_parse!(
       ext_type: be_u16 >>
       ext_len:  be_u16 >>
       ext: flat_map!(take!(ext_len),call!(parse_tls_extension_with_type,ext_type,ext_len)) >>
       ( ext )
   )
);

fn parse_tls_extension_with_type(i: &[u8], ext_type:u16, ext_len:u16) -> IResult<&[u8],Option<SNIList>> {
    match ext_type {
        0x0000 => map!(i, parse_tls_extension_sni_content, Some),
        /*0x0001 => parse_tls_extension_max_fragment_length_content(i),
        0x0005 => parse_tls_extension_status_request_content(i,ext_len),
        0x000a => parse_tls_extension_elliptic_curves_content(i),
        0x000b => parse_tls_extension_ec_point_formats_content(i),
        0x000d => parse_tls_extension_signature_algorithms_content(i),
        0x000f => parse_tls_extension_heartbeat_content(i),
        0x0010 => parse_tls_extension_alpn_content(i),
        0x0012 => parse_tls_extension_signed_certificate_timestamp_content(i),
        0x0015 => parse_tls_extension_padding_content(i,ext_len),
        0x0016 => parse_tls_extension_encrypt_then_mac_content(i,ext_len),
        0x0017 => parse_tls_extension_extended_master_secret_content(i,ext_len),
        0x0023 => parse_tls_extension_session_ticket_content(i,ext_len),
        0x0028 => parse_tls_extension_key_share_old_content(i,ext_len),
        0x0029 => parse_tls_extension_pre_shared_key_content(i,ext_len),
        0x002a => parse_tls_extension_early_data_content(i,ext_len),
        0x002b => parse_tls_extension_supported_versions_content(i,ext_len),
        0x002c => parse_tls_extension_cookie_content(i,ext_len),
        0x002d => parse_tls_extension_psk_key_exchange_modes_content(i),
        0x0030 => parse_tls_extension_oid_filters(i),
        0x0031 => parse_tls_extension_post_handshake_auth_content(i,ext_len),
        0x0033 => parse_tls_extension_key_share_content(i,ext_len),
        0x3374 => parse_tls_extension_npn_content(i,ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(i),
        */
        _      => { map!(i, take!(ext_len), |_| {
          println!("extension with type {}", ext_type);
          None
        }) },
    }
}

named!(pub parse_tls_extension_sni<SNIList>,
    do_parse!(
        tag!([0x00,0x00]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_sni_content) >>
        ( ext )
    )
);

pub struct SNIList<'a>{
  pub list: Vec<(u8,&'a[u8])>,
}

named!(pub parse_tls_extension_sni_content<SNIList>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),
            many0!(complete!(parse_tls_extension_sni_hostname))
        ) >>
        (SNIList {
          list: v
        })
    )
);

named!(pub parse_tls_extension_sni_hostname<(u8,&[u8])>,
    pair!(be_u8,length_bytes!(be_u16))
);

