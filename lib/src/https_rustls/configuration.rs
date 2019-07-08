use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;
use mio::*;
use mio::net::*;
use mio_uds::UnixStream;
use mio::unix::UnixReady;
use std::os::unix::io::{AsRawFd};
use std::io::ErrorKind;
use std::collections::{HashMap, BTreeMap};
use slab::Slab;
use std::net::SocketAddr;
use std::str::from_utf8_unchecked;
use rustls::{ServerConfig, ServerSession, NoClientAuth, ProtocolVersion,
  ALL_CIPHERSUITES};
use mio_extras::timer::Timeout;

use sozu_command::scm_socket::ScmSocket;
use sozu_command::proxy::{Application,
  ProxyRequestData,HttpFront,HttpsListener,ProxyRequest,ProxyResponse,
  ProxyResponseStatus,AddCertificate,RemoveCertificate,ReplaceCertificate,
  TlsVersion,ListenerType,ApplicationRule};
use sozu_command::logging;
use sozu_command::buffer::Buffer;

use protocol::http::{parser::{RRequestLine,hostname_and_port}, answers::{CustomAnswers, HttpAnswers}};
use pool::Pool;
use {AppId,ConnectionError,Protocol,ProxySession,ProxyConfiguration,AcceptError,};
use backends::BackendMap;
use server::{Server,ProxyChannel,SessionToken,ListenSession,CONN_RETRIES};
use socket::{server_bind, server_unbind};
use protocol::StickySession;
use protocol::http::DefaultAnswerStatus;
use util::UnwrapLog;
use router::Router;
use super::resolver::CertificateResolverWrapper;
use super::session::Session;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct TlsApp {
  pub app_id:           String,
  pub hostname:         String,
  pub path_begin:       String,
}

pub type HostName  = String;
pub type PathBegin = String;

pub struct Listener {
  listener:   Option<TcpListener>,
  address:    SocketAddr,
  fronts:     Router,
  answers:    Rc<RefCell<HttpAnswers>>,
  config:     HttpsListener,
  ssl_config: Arc<ServerConfig>,
  resolver:   Arc<CertificateResolverWrapper>,
  pub token:  Token,
  active:     bool,
  pub proxy:  Rc<RefCell<Proxy>>,
  pub poll:   Rc<RefCell<Poll>>,
}

impl Listener {
  pub fn new(config: HttpsListener, token: Token, proxy: Rc<RefCell<Proxy>>, poll: Rc<RefCell<Poll>>) -> Listener {

    let mut server_config = ServerConfig::new(NoClientAuth::new());
    server_config.versions = config.versions.iter().map(|version| {
      match version {
        TlsVersion::SSLv2   => ProtocolVersion::SSLv2,
        TlsVersion::SSLv3   => ProtocolVersion::SSLv3,
        TlsVersion::TLSv1_0 => ProtocolVersion::TLSv1_0,
        TlsVersion::TLSv1_1 => ProtocolVersion::TLSv1_1,
        TlsVersion::TLSv1_2 => ProtocolVersion::TLSv1_2,
        TlsVersion::TLSv1_3 => ProtocolVersion::TLSv1_3,
      }
    }).collect();

    let resolver = Arc::new(CertificateResolverWrapper::new());
    server_config.cert_resolver = resolver.clone();

    //FIXME: we should have another way than indexes in ALL_CIPHERSUITES,
    //but rustls does not export the static SupportedCipherSuite instances yet
    if !config.rustls_cipher_list.is_empty() {
      let mut ciphers = Vec::new();
      for cipher in config.rustls_cipher_list.iter() {
        match cipher.as_str() {
          "TLS13_CHACHA20_POLY1305_SHA256" => ciphers.push(ALL_CIPHERSUITES[0]),
          "TLS13_AES_256_GCM_SHA384" => ciphers.push(ALL_CIPHERSUITES[1]),
          "TLS13_AES_128_GCM_SHA256" => ciphers.push(ALL_CIPHERSUITES[2]),
          "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => ciphers.push(ALL_CIPHERSUITES[3]),
          "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => ciphers.push(ALL_CIPHERSUITES[4]),
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => ciphers.push(ALL_CIPHERSUITES[5]),
          "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => ciphers.push(ALL_CIPHERSUITES[6]),
          "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => ciphers.push(ALL_CIPHERSUITES[7]),
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => ciphers.push(ALL_CIPHERSUITES[8]),
          s => error!("unknown cipher: {:?}", s),
        }
      }
      server_config.ciphersuites = ciphers;
    }

    Listener {
      address:    config.front.clone(),
      fronts:     Router::new(),
      answers:    Rc::new(RefCell::new(HttpAnswers::new(&config.answer_404, &config.answer_503))),
      ssl_config: Arc::new(server_config),
      listener: None,
      config,
      resolver,
      token,
      active: false,
      proxy,
      poll,
    }
  }

  pub fn activate(&mut self, tcp_listener: Option<TcpListener>) -> Option<Token> {
    if self.active {
      return None;
    }

    let listener = tcp_listener.or_else(|| server_bind(&self.config.front).map_err(|e| {
      error!("could not create listener {:?}: {:?}", self.config.front, e);
    }).ok());


    if let Some(ref sock) = listener {
      if let Err(e) = self.poll.borrow_mut().register(sock, self.token, Ready::readable(), PollOpt::edge()) {
        error!("error registering listen socket: {:?}", e);
      }
    } else {
      return None;
    }

    self.listener = listener;
    self.active = true;
    Some(self.token)
  }

  pub fn deactivate(&mut self) -> Option<TcpListener> {
    if !self.active {
      return None;
    }

    if let Some(listener) = self.listener.take() {
      if let Err(e) = self.poll.borrow_mut().deregister(&listener) {
        error!("error deregistering socket({:?}: {:?})", listener, e);
        self.listener = Some(listener);
        return None;
      } else {
        if let Err(e) = server_unbind(&listener) {
          error!("Failed to unbind socket {:?} with error {:?}", listener, e);
        }
        self.active = false;
        return Some(listener);
      }
    }
    return None;
  }

  pub fn add_https_front(&mut self, tls_front: HttpFront) -> bool {
    self.fronts.add_http_front(tls_front)
  }

  pub fn remove_https_front(&mut self, tls_front: HttpFront) -> bool {
    debug!("removing tls_front {:?}", tls_front);
    self.fronts.remove_http_front(tls_front)
  }

  pub fn add_certificate(&mut self, add_certificate: AddCertificate) -> bool {
    (*self.resolver).add_certificate(add_certificate).is_some()
  }

  // FIXME: return an error if the cert is still in use
  pub fn remove_certificate(&mut self, remove_certificate: RemoveCertificate) {
    debug!("removing certificate {:?}", remove_certificate);
    (*self.resolver).remove_certificate(remove_certificate)
  }

  pub fn replace_certificate(&mut self, replace_certificate: ReplaceCertificate) {
    debug!("replacing certificate {:?}", replace_certificate);
    let ReplaceCertificate { front, new_certificate, old_fingerprint, old_names, new_names } = replace_certificate;
    let remove = RemoveCertificate {
      front,
      fingerprint: old_fingerprint,
      names: old_names,
    };
    let add = AddCertificate {
      front,
      certificate: new_certificate,
      names: new_names,
    };

    //FIXME: handle results
    (*self.resolver).remove_certificate(remove);
    (*self.resolver).add_certificate(add);
  }

  fn accept(&self) -> Result<TcpStream, AcceptError> {

    if let Some(ref listener) = self.listener.as_ref() {
      listener.accept().map_err(|e| {
        match e.kind() {
          ErrorKind::WouldBlock => AcceptError::WouldBlock,
          _ => {
            error!("accept() IO error: {:?}", e);
            AcceptError::IoError
          }
        }
      }).map(|(frontend_sock, _)| frontend_sock)
    } else {
      Err(AcceptError::IoError)
    }
  }

  // ToDo factor out with http.rs
  pub fn frontend_from_request(&self, host: &str, uri: &str) -> Option<ApplicationRule> {
    let host: &str = if let Ok((i, (hostname, _))) = hostname_and_port(host.as_bytes()) {
      if i != &b""[..] {
        error!("invalid remaining chars after hostname");
        return None;
      }

      // it is alright to call from_utf8_unchecked,
      // we already verified that there are only ascii
      // chars in there
      unsafe { from_utf8_unchecked(hostname) }
    } else {
      error!("hostname parsing failed for: '{}'", host);
      return None;
    };

    self.fronts.lookup(host.as_bytes(), uri.as_bytes())
  }

  pub fn backend_from_request(&mut self, session: &mut Session, app_id: &str,
    front_should_stick: bool, sticky_session: Option<String>) -> Result<TcpStream,ConnectionError> {

    session.http().map(|h| h.set_app_id(String::from(app_id)));

    let res = match (front_should_stick, sticky_session) {
      (true, Some(sticky_session)) => {
        self.proxy.borrow().backends.borrow_mut().backend_from_sticky_session(app_id, &sticky_session)
          .map_err(|e| {
            debug!("Couldn't find a backend corresponding to sticky_session {} for app {}", sticky_session, app_id);
            e
          })
      },
      _ => self.proxy.borrow().backends.borrow_mut().backend_from_app_id(app_id),
    };

    match res {
      Err(e) => {
        let answer = self.get_service_unavailable_answer(Some(app_id));
        session.set_answer(DefaultAnswerStatus::Answer503, answer);
        Err(e)
      },
      Ok((backend, conn))  => {
        if front_should_stick {
          let sticky_name = self.config.sticky_name.clone();
          session.http().map(|http| {
            http.sticky_session =
              Some(StickySession::new(backend.borrow().sticky_id.clone().unwrap_or(backend.borrow().backend_id.clone())));
            http.sticky_name = sticky_name;
          });
        }
        session.metrics.backend_id = Some(backend.borrow().backend_id.clone());
        session.metrics.backend_start();
        session.backend = Some(backend);

        Ok(conn)
      }
    }
  }

  pub fn app_id_from_request(&mut self, session: &mut Session) -> Result<String, ConnectionError> {
    let h = session.http().and_then(|h| h.request.as_ref()).and_then(|r| r.get_host()).ok_or(ConnectionError::NoHostGiven)?;

    let host: &str = if let Ok((i, (hostname, port))) = hostname_and_port(h.as_bytes()) {
      if i != &b""[..] {
        error!("invalid remaining chars after hostname");
        let answer = self.answers.borrow().get(DefaultAnswerStatus::Answer400, None);
        session.set_answer(DefaultAnswerStatus::Answer400, answer);
        return Err(ConnectionError::InvalidHost);
      }

      // it is alright to call from_utf8_unchecked,
      // we already verified that there are only ascii
      // chars in there
      let hostname_str =  unsafe { from_utf8_unchecked(hostname) };

      //FIXME: what if we don't use SNI?
      let servername: Option<String> = session.http()
        .and_then(|h| h.frontend.session.get_sni_hostname()).map(|s| s.to_string());
      if servername.as_ref().map(|s| s.as_str()) != Some(hostname_str) {
        error!("TLS SNI hostname '{:?}' and Host header '{}' don't match", servername, hostname_str);
        let answer = self.answers.borrow().get(DefaultAnswerStatus::Answer404, None);
        unwrap_msg!(session.http()).set_answer(DefaultAnswerStatus::Answer404, answer);
        return Err(ConnectionError::HostNotFound);
      }

      //FIXME: we should check that the port is right too

      if port == Some(&b"443"[..]) {
        hostname_str
      } else {
        &h
      }
    } else {
      error!("hostname parsing failed");
      let answer = self.answers.borrow().get(DefaultAnswerStatus::Answer400, None);
      session.set_answer(DefaultAnswerStatus::Answer400, answer);
      return Err(ConnectionError::InvalidHost);
    };

    let rl:RRequestLine = session.http()
      .and_then(|h| h.request.as_ref()).and_then(|r| r.get_request_line())
      .ok_or(ConnectionError::NoRequestLineGiven)?;
    match self.frontend_from_request(&host, &rl.uri) {
      Some(ApplicationRule::Id(app_id)) => Ok(app_id),
      Some(ApplicationRule::Reject) => {
        let answer = self.answers.borrow().get(DefaultAnswerStatus::Answer404, None);
        session.set_answer(DefaultAnswerStatus::Answer403, answer);
        Err(ConnectionError::Forbidden)
      }
      None => {
        let answer = self.answers.borrow().get(DefaultAnswerStatus::Answer404, None);
        session.set_answer(DefaultAnswerStatus::Answer404, answer);
        Err(ConnectionError::HostNotFound)
      }
    }
  }

  pub fn check_circuit_breaker(&mut self, session: &mut Session) -> Result<(), ConnectionError> {
    if session.connection_attempt == CONN_RETRIES {
      error!("{} max connection attempt reached", session.log_context());
      let answer = self.get_service_unavailable_answer(session.app_id.as_ref().map(|app_id| app_id.as_str()));
      session.set_answer(DefaultAnswerStatus::Answer503, answer);
      Err(ConnectionError::NoBackendAvailable)
    } else {
      Ok(())
    }
  }

  fn get_service_unavailable_answer(&self, app_id: Option<&str>) -> Rc<Vec<u8>> {
    self.answers.borrow().get(DefaultAnswerStatus::Answer503, app_id)
  }

  fn create_session(&self, frontend_sock: TcpStream, session_token: Token, timeout: Timeout,
    wrapper: ListenerWrapper)
    -> Result<(Rc<RefCell<dyn ProxySession>>, bool), AcceptError> {

      if let Err(e) = frontend_sock.set_nodelay(true) {
        error!("error setting nodelay on front socket({:?}): {:?}", frontend_sock, e);
      }

      if let Err(e) = self.poll.borrow_mut().register(
        &frontend_sock,
        session_token,
        Ready::readable() | Ready::writable() | Ready::from(UnixReady::hup() | UnixReady::error()),
        PollOpt::edge()
      ) {
        error!("error registering fron socket({:?}): {:?}", frontend_sock, e);
      }

      let pool = Rc::downgrade(&self.proxy.borrow().pool);
      let session = ServerSession::new(&self.ssl_config);
      let c = Session::new(session, frontend_sock, session_token, wrapper, pool,
        self.config.public_address, self.config.expect_proxy,
        self.config.sticky_name.clone(), timeout, self.answers.clone(), self.token);

      Ok((Rc::new(RefCell::new(c)) as Rc<RefCell<dyn ProxySession>>, false))
    }
}

#[derive(Clone)]
pub struct ListenerWrapper {
  pub inner: Rc<RefCell<Listener>>,
}

impl ListenerWrapper {
  fn new(l: Listener) -> Self {
    ListenerWrapper {
      inner: Rc::new(RefCell::new(l)),
    }
  }
}

impl super::super::Listener for ListenerWrapper {
  fn address(&self) -> SocketAddr {
    self.inner.borrow().address
  }

  fn active(&self) -> bool {
    self.inner.borrow().active
  }

  fn notify(&self, message: ProxyRequest) -> ProxyResponse {
    // ToDo temporary
    //trace!("{} notified", message);
    match message.order {
      ProxyRequestData::AddApplication(application) => {
        if let Some(answer_503) = application.answer_503.as_ref() {
          self.inner.borrow_mut().answers.borrow_mut().add_custom_answer(&application.app_id, &answer_503);
        }
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::RemoveApplication(application) => {
        self.inner.borrow().answers.borrow_mut().remove_custom_answer(&application);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::AddHttpsFront(front) => {
        debug!("{} add front {:?}", message.id, front);
        match self.inner.borrow_mut().add_https_front(front) {
          true => ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None },
          false => ProxyResponse{ id: message.id, status: ProxyResponseStatus::Error(String::from("error adding HTTPS front")), data: None }
        }
      },
      ProxyRequestData::RemoveHttpsFront(front) => {
        debug!("{} front {:?}", message.id, front);
          match self.inner.borrow_mut().remove_https_front(front) {
            true => ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None },
            false => ProxyResponse{ id: message.id, status: ProxyResponseStatus::Error(String::from("error removing HTTPS front")), data: None }
          }
      },
      ProxyRequestData::AddCertificate(add_certificate) => {
        self.inner.borrow_mut().add_certificate(add_certificate);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::RemoveCertificate(remove_certificate) => {
        //FIXME: should return an error if certificate still has fronts referencing it
        self.inner.borrow_mut().remove_certificate(remove_certificate);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::ReplaceCertificate(replace_certificate) => {
        //FIXME: should return an error if certificate still has fronts referencing it
        self.inner.borrow_mut().replace_certificate(replace_certificate);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      command => {
        debug!("{} unsupported message for HTTP listener, ignoring: {:?}", message.id, command);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Error(String::from("unsupported message")), data: None }
      }
    }
  }

  fn activate(&self, tcp_listener: Option<mio::net::TcpListener>) -> Option<Token> {
    self.inner.borrow_mut().activate(tcp_listener)
  }

  fn deactivate(&self) -> Option<TcpListener> {
    self.inner.borrow_mut().deactivate()
  }

  fn accept(&self) -> Result<TcpStream, AcceptError> {
    self.inner.borrow().accept()
  }

  fn create_session(&self, socket: TcpStream, session_token: Token, timeout: Timeout)
    -> Result<(Rc<RefCell<dyn ProxySession>>, bool), AcceptError> {
      let wrapper = self.clone();

    self.inner.borrow().create_session(socket, session_token, timeout, wrapper)
  }

  fn give_back_listener(&self) -> Option<(SocketAddr, TcpListener)> {
    let mut listener = self.inner.borrow_mut();
    if let Some(l) = listener.listener.take() {
      Some((listener.address, l))
    } else {
      None
    }
  }

  fn listener_type(&self) -> ListenerType {
    ListenerType::HTTPS
  }

  fn query_all_certificates(&self) -> Option<BTreeMap<String, Vec<u8>>> {
    let mut domains = (&unwrap_msg!(self.inner.borrow().resolver.0.lock()).domains).to_hashmap();
    Some(domains.drain().map(|(k, v)| {
      (String::from_utf8(k).unwrap(), v.0)
    }).collect())
  }

  fn query_certificates_domain(&self, d: &str) -> Option<(String, Vec<u8>)> {
    self.inner.borrow().resolver.0.lock().ok()
      .and_then(|r| r.domains.domain_lookup(d.as_bytes()).map(|(k, v)| {
      (String::from_utf8(k.to_vec()).unwrap(), v.0.clone())
    }))
  }
}

pub struct Proxy {
  pub applications: HashMap<AppId, Application>,
  pub backends:     Rc<RefCell<BackendMap>>,
  pool:             Rc<RefCell<Pool<Buffer>>>,
  pub poll:         Rc<RefCell<Poll>>,
}

impl Proxy {
  pub fn new(pool: Rc<RefCell<Pool<Buffer>>>, backends: Rc<RefCell<BackendMap>>, poll: Rc<RefCell<Poll>>) -> Proxy {
    Proxy {
      applications: HashMap::new(),
      backends,
      pool,
      poll,
    }
  }

  pub fn add_listener(&mut self, config: HttpsListener, token: Token, proxy: Rc<RefCell<Proxy>>) -> Option<ListenerWrapper> {
    let listener = ListenerWrapper::new(Listener::new(config, token, proxy, self.poll.clone()));
    Some(listener)
  }

  pub fn add_application(&mut self, mut application: Application) {
    self.applications.insert(application.app_id.clone(), application);
  }

  pub fn remove_application(&mut self, app_id: &str) {
    self.applications.remove(app_id);
  }
}

impl ProxyConfiguration for Proxy {
  fn notify(&mut self, message: ProxyRequest) -> ProxyResponse {
    //info!("{} notified", message);
    match message.order {
      ProxyRequestData::AddApplication(application) => {
        debug!("{} add application {:?}", message.id, application);
        self.add_application(application);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::RemoveApplication(application) => {
        debug!("{} remove application {:?}", message.id, application);
        self.remove_application(&application);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::Status => {
        debug!("{} status", message.id);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      ProxyRequestData::Logging(logging_filter) => {
        debug!("{} changing logging filter to {}", message.id, logging_filter);
        logging::LOGGER.with(|l| {
          let directives = logging::parse_logging_spec(&logging_filter);
          l.borrow_mut().set_directives(directives);
        });
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Ok, data: None }
      },
      command => {
        error!("{} unsupported message for rustls proxy, ignoring {:?}", message.id, command);
        ProxyResponse{ id: message.id, status: ProxyResponseStatus::Error(String::from("unsupported message")), data: None }
      }
    }
  }
}

use server::HttpsProvider;
pub fn start(channel: ProxyChannel, max_buffers: usize, buffer_size: usize) {
  use server;

  let poll = Rc::new(RefCell::new(Poll::new().expect("could not create event loop")));

  let pool = Rc::new(RefCell::new(
    Pool::with_capacity(2*max_buffers, 0, || Buffer::with_capacity(buffer_size))
  ));
  let backends = Rc::new(RefCell::new(BackendMap::new()));

  let mut sessions: Slab<Rc<RefCell<dyn ProxySession>>,SessionToken> = Slab::with_capacity(max_buffers);
  {
    let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
    info!("taking token {:?} for channel", entry.index());
    entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::HTTPListen })));
  }
  {
    let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
    info!("taking token {:?} for timer", entry.index());
    entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::HTTPListen })));
  }
  {
    let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
    info!("taking token {:?} for metrics", entry.index());
    entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::HTTPListen })));
  }

  let configuration = Proxy::new(pool.clone(), backends.clone(), poll.clone());
  let (scm_server, _scm_client) = UnixStream::pair().unwrap();
  let mut server_config: server::ServerConfig = Default::default();
  server_config.max_connections = max_buffers;
  let mut server  = Server::new(poll, channel, ScmSocket::new(scm_server.as_raw_fd()),
  sessions, pool, backends, None, Some(HttpsProvider::Rustls(Rc::new(RefCell::new(configuration)))), None, server_config, None);

  info!("starting event loop");
  server.run();
  info!("ending event loop");
}

