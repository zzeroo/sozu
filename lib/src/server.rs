use std::net::SocketAddr;
use std::rc::Rc;
use std::cell::RefCell;
use mio::net::*;
use mio::*;
use mio::unix::UnixReady;
use std::collections::{HashSet,VecDeque};
use std::os::unix::io::{FromRawFd,IntoRawFd};
use slab::Slab;
use time::{self, SteadyTime};
use std::time::Duration;
use mio_extras::timer::{Timer, Timeout};
use hashbrown::HashMap;

use sozu_command::config::Config;
use sozu_command::channel::Channel;
use sozu_command::scm_socket::{Listeners,ScmSocket};
use sozu_command::state::{ConfigState,get_application_ids_by_domain, get_certificate};
use sozu_command::proxy::{ProxyRequestData,MessageId,ProxyResponse, ProxyEvent,
  ProxyResponseData,ProxyResponseStatus,ProxyRequest,Topic,Query,QueryAnswer,
  QueryApplicationType,TlsProvider,ListenerType,HttpsListener,QueryAnswerCertificate,
  QueryCertificateType,ApplicationRule};
use sozu_command::buffer::Buffer;

use {SessionResult,ConnectionError,Protocol,ProxySession, Listener,
  CloseResult,AcceptError,BackendConnectAction,ProxyConfiguration,Backend};
use {http,tcp};
use pool::Pool;
use metrics::METRICS;
use backends::BackendMap;

// Number of retries to perform on a server after a connection failure
pub const CONN_RETRIES: u8 = 3;

pub type ProxyChannel = Channel<ProxyResponse,ProxyRequest>;

thread_local! {
  pub static QUEUE: RefCell<VecDeque<ProxyResponse>> = RefCell::new(VecDeque::new());
}

pub fn push_queue(message: ProxyResponse) {
  QUEUE.with(|queue| {
    (*queue.borrow_mut()).push_back(message);
  });
}

pub fn push_event(event: ProxyEvent) {
  QUEUE.with(|queue| {
    (*queue.borrow_mut()).push_back(ProxyResponse {
      id:     "EVENT".to_string(),
      status: ProxyResponseStatus::Processing,
      data:   Some(ProxyResponseData::Event(event))
    });
  });
}

#[derive(PartialEq)]
pub enum ListenPortState {
  Available,
  InUse
}

#[derive(Copy,Clone,Debug,PartialEq,Eq,PartialOrd,Ord,Hash)]
pub struct ListenToken(pub usize);
#[derive(Copy,Clone,Debug,PartialEq,Eq,PartialOrd,Ord,Hash)]
pub struct SessionToken(pub usize);

impl From<usize> for ListenToken {
    fn from(val: usize) -> ListenToken {
        ListenToken(val)
    }
}

impl From<ListenToken> for usize {
    fn from(val: ListenToken) -> usize {
        val.0
    }
}

impl From<usize> for SessionToken {
    fn from(val: usize) -> SessionToken {
        SessionToken(val)
    }
}

impl From<SessionToken> for usize {
    fn from(val: SessionToken) -> usize {
        val.0
    }
}

pub struct ServerConfig {
  pub max_connections:          usize,
  pub front_timeout:            u32,
  pub zombie_check_interval:    u32,
  pub accept_queue_timeout:     u32,
}

impl ServerConfig {
  pub fn from_config(config: &Config) -> ServerConfig {
    ServerConfig {
      max_connections: config.max_connections,
      front_timeout: config.front_timeout,
      zombie_check_interval: config.zombie_check_interval,
      accept_queue_timeout: config.accept_queue_timeout,
    }
  }
}

impl Default for ServerConfig {
  fn default() -> ServerConfig {
    ServerConfig {
      max_connections: 10000,
      front_timeout: 60,
      zombie_check_interval: 30*60,
      accept_queue_timeout: 60,
    }
  }
}

pub struct Server {
  pub poll:        Rc<RefCell<Poll>>,
  shutting_down:   Option<MessageId>,
  accept_ready:    HashSet<ListenToken>,
  can_accept:      bool,
  channel:         ProxyChannel,
  http:            Rc<RefCell<http::Proxy>>,
  https:           HttpsProvider,
  tcp:             Rc<RefCell<tcp::Proxy>>,
  config_state:    ConfigState,
  scm:             ScmSocket,
  sessions:        Slab<Rc<RefCell<dyn ProxySession>>,SessionToken>,
  max_connections: usize,
  nb_connections:  usize,
  front_timeout:   time::Duration,
  timer:           Timer<Token>,
  pool:            Rc<RefCell<Pool<Buffer>>>,
  backends:        Rc<RefCell<BackendMap>>,
  scm_listeners:   Option<Listeners>,
  zombie_check_interval: time::Duration,
  accept_queue:    VecDeque<(TcpStream, ListenToken, SteadyTime)>,
  accept_queue_timeout: time::Duration,
  base_sessions_count: usize,
  listeners:       HashMap<ListenToken, Box<dyn Listener>>,
}

impl Server {
  pub fn new_from_config(channel: ProxyChannel, scm: ScmSocket, config: Config, config_state: ConfigState) -> Self {
    let poll = Rc::new(RefCell::new(Poll::new().expect("could not create event loop")));
    let pool = Rc::new(RefCell::new(
      Pool::with_capacity(2*config.max_buffers, 0, || Buffer::with_capacity(config.buffer_size))
    ));
    let backends = Rc::new(RefCell::new(BackendMap::new()));

    //FIXME: we will use a few entries for the channel, metrics socket and the listeners
    //FIXME: for HTTP/2, we will have more than 2 entries per session
    let mut sessions: Slab<Rc<RefCell<dyn ProxySession>>,SessionToken> = Slab::with_capacity(10+2*config.max_connections);
    {
      let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
      trace!("taking token {:?} for channel", entry.index());
      entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::Channel })));
    }
    {
      let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
      trace!("taking token {:?} for metrics", entry.index());
      entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::Timer })));
    }
    {
      let entry = sessions.vacant_entry().expect("session list should have enough room at startup");
      trace!("taking token {:?} for metrics", entry.index());
      entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::Metrics })));
    }

    let use_openssl = config.tls_provider == TlsProvider::Openssl;
    let https = HttpsProvider::new(use_openssl, pool.clone(), backends.clone(), poll.clone());

    let server_config = ServerConfig::from_config(&config);
    Server::new(poll, channel, scm, sessions, pool, backends, None, Some(https), None, server_config, Some(config_state))
  }

  pub fn new(poll: Rc<RefCell<Poll>>, channel: ProxyChannel, scm: ScmSocket,
    sessions: Slab<Rc<RefCell<dyn ProxySession>>,SessionToken>,
    pool: Rc<RefCell<Pool<Buffer>>>,
    backends: Rc<RefCell<BackendMap>>,
    http: Option<Rc<RefCell<http::Proxy>>>,
    https: Option<HttpsProvider>,
    tcp:  Option<tcp::Proxy>,
    server_config: ServerConfig,
    config_state: Option<ConfigState>) -> Self {

    poll.borrow_mut().register(
      &channel,
      Token(0),
      Ready::readable() | Ready::writable() | Ready::from(UnixReady::hup() | UnixReady::error()),
      PollOpt::edge()
    ).expect("should register the channel");

    let timer = Timer::default();
    poll.borrow_mut().register(
      &timer,
      Token(1),
      Ready::readable() | Ready::writable() | Ready::from(UnixReady::hup() | UnixReady::error()),
      PollOpt::edge()
    ).expect("should register the timer");

    METRICS.with(|metrics| {
      if let Some(sock) = (*metrics.borrow()).socket() {
        poll.borrow_mut().register(sock, Token(2), Ready::writable(), PollOpt::edge()).expect("should register the metrics socket");
      }
    });

    let base_sessions_count = sessions.len();

    let mut server = Server {
      poll:            poll.clone(),
      shutting_down:   None,
      accept_ready:    HashSet::new(),
      can_accept:      true,
      channel,
      http:            http.unwrap_or_else(|| Rc::new(RefCell::new(http::Proxy::new(pool.clone(), backends.clone(), poll.clone())))),
      https:           https.unwrap_or_else(|| HttpsProvider::new(false, pool.clone(), backends.clone(), poll.clone())),
      tcp:             Rc::new(RefCell::new(tcp.unwrap_or_else(|| tcp::Proxy::new(backends.clone(), poll.clone())))),
      config_state:    ConfigState::new(),
      scm,
      sessions,
      max_connections: server_config.max_connections,
      nb_connections:  0,
      scm_listeners:   None,
      timer,
      pool,
      backends,
      front_timeout: time::Duration::seconds(i64::from(server_config.front_timeout)),
      zombie_check_interval: time::Duration::seconds(i64::from(server_config.zombie_check_interval)),
      accept_queue:    VecDeque::new(),
      accept_queue_timeout: time::Duration::seconds(i64::from(server_config.accept_queue_timeout)),
      base_sessions_count,
      listeners:       HashMap::new(),
    };

    // initialize the worker with the state we got from a file
    if let Some(state) = config_state {
      let mut counter = 0usize;

      for order in state.generate_orders() {
        let id = format!("INIT-{}", counter);
        let message = ProxyRequest { id, order };

        trace!("generating initial config order: {:#?}", message);
        server.notify_proxys(message);

        counter += 1;
      }
      // do not send back answers to the initialization messages
      QUEUE.with(|queue| {
        (*queue.borrow_mut()).clear();
      });
    }

    info!("will try to receive listeners");
    server.scm.set_blocking(true);
    let listeners = server.scm.receive_listeners();
    server.scm.set_blocking(false);
    info!("received listeners: {:?}", listeners);
    server.scm_listeners = listeners;

    server
  }
}

impl Server {
  pub fn run(&mut self) {
    //FIXME: make those parameters configurable?
    let mut events = Events::with_capacity(1024);
    let poll_timeout = Some(Duration::from_millis(1000));
    let max_poll_errors = 10000;
    let mut current_poll_errors = 0;
    let mut last_zombie_check = SteadyTime::now();
    let mut last_sessions_len = self.sessions.len();

    loop {
      if current_poll_errors == max_poll_errors {
        error!("Something is going very wrong. Last {} poll() calls failed, crashing..", current_poll_errors);
        panic!("poll() calls failed {} times in a row", current_poll_errors);
      }

      if let Err(error) = self.poll.borrow_mut().poll(&mut events, poll_timeout) {
        error!("Error while polling events: {:?}", error);
        current_poll_errors += 1;
        continue;
      } else {
        current_poll_errors = 0;
      }

      self.send_queue();

      for event in events.iter() {
        if event.token() == Token(0) {
          let kind = event.readiness();
          if UnixReady::from(kind).is_error() {
            error!("error reading from command channel");
            continue;
          }
          if UnixReady::from(kind).is_hup() {
            error!("command channel was closed");
            continue;
          }
          self.channel.handle_events(kind);

          // loop here because iterations has borrow issues
          loop {
            QUEUE.with(|queue| {
              if !(*queue.borrow()).is_empty() {
                self.channel.interest.insert(Ready::writable());
              }
            });

            //trace!("WORKER[{}] channel readiness={:?}, interest={:?}, queue={} elements",
            //  line!(), self.channel.readiness, self.channel.interest, self.queue.len());
            if self.channel.readiness() == Ready::empty() {
              break;
            }

            if self.channel.readiness().is_readable() {
              if let Err(e) = self.channel.readable() {
                error!("error reading from channel: {:?}", e);
              }

              loop {
                let msg = self.channel.read_message();

                // if the message was too large, we grow the buffer and retry to read if possible
                if msg.is_none() {
                  if (self.channel.interest & self.channel.readiness).is_readable() {
                    if let Err(e) = self.channel.readable() {
                      error!("error reading from channel: {:?}", e);
                    }
                    continue;
                  } else {
                    break;
                  }
                }

                let msg = msg.expect("the message should be valid");
                if let ProxyRequestData::HardStop = msg.order {
                  let mut v = self.listeners.drain().collect::<HashMap<_,_>>();
                  for (_, l) in v.iter_mut() {
                    l.give_back_listener().map(|(_addr,  sock)| {
                      if let Err(e) = self.poll.borrow_mut().deregister(&sock) {
                        error!("error deregistering listen socket({:?}): {:?}", sock, e);
                      }
                    });
                  }

                  self.channel.write_message(&ProxyResponse{ id: msg.id.clone(), status: ProxyResponseStatus::Ok, data: None});
                  self.channel.run();
                  return;
                } else if let ProxyRequestData::SoftStop = msg.order {
                  self.shutting_down = Some(msg.id.clone());
                  last_sessions_len = self.sessions.len();

                  let mut v = self.listeners.drain().collect::<HashMap<_,_>>();
                  for (_, l) in v.iter_mut() {
                    l.give_back_listener().map(|(_addr, sock)| {
                      if let Err(e) = self.poll.borrow_mut().deregister(&sock) {
                        error!("error deregistering listen socket({:?}): {:?}", sock, e);
                      }
                    });
                  }

                  self.channel.write_message(&ProxyResponse{ id: msg.id.clone(), status: ProxyResponseStatus::Processing, data: None});
                  self.channel.run();
                } else if let ProxyRequestData::ReturnListenSockets = msg.order {
                  info!("received ReturnListenSockets order");
                  self.return_listen_sockets();
                } else {
                  self.notify(msg);
                }

              }
            }

            QUEUE.with(|queue| {
              if !(*queue.borrow()).is_empty() {
                self.channel.interest.insert(Ready::writable());
              }
            });

            self.send_queue();
          }

        } else if event.token() == Token(1) {
          while let Some(t) = self.timer.poll() {
            self.timeout(t);
          }
        } else if event.token() == Token(2) {
          METRICS.with(|metrics| {
            (*metrics.borrow_mut()).writable();
          });
        } else {
          self.ready(event.token(), event.readiness());
        }
      }

      self.handle_remaining_readiness();
      self.create_sessions();

      let now = SteadyTime::now();
      if now - last_zombie_check > self.zombie_check_interval {
        info!("zombie check");
        last_zombie_check = now;

        let mut tokens = HashSet::new();
        let mut frontend_tokens = HashSet::new();

        let mut count = 0;
        let duration = self.zombie_check_interval;
        for session in self.sessions.iter_mut().filter(|c| {
          now - c.borrow().last_event() > duration
        }) {
          let t = session.borrow().tokens();
          if !frontend_tokens.contains(&t[0]) {
            session.borrow().print_state();

            frontend_tokens.insert(t[0]);
            for tk in t.into_iter() {
              tokens.insert(tk);
            }

            count += 1;
          }
        }

        for tk in frontend_tokens.iter() {
          let cl = self.to_session(*tk);
          self.close_session(cl);
        }

        if count > 0 {
          count!("zombies", count);

          let mut remaining = 0;
          for tk in tokens.into_iter() {
            let cl = self.to_session(tk);
            if self.sessions.remove(cl).is_some() {
              remaining += 1;
            }
          }
          info!("removing {} zombies ({} remaining tokens after close)", count, remaining);
        }
      }

      gauge!("client.connections", self.nb_connections);
      gauge!("slab.count", self.sessions.len());
      METRICS.with(|metrics| {
        (*metrics.borrow_mut()).send_data();
      });

      if self.shutting_down.is_some() {
        let count = self.sessions.len();
        if count <= self.base_sessions_count {
          info!("last session stopped, shutting down!");
          self.channel.run();
          self.channel.set_blocking(true);
          self.channel.write_message(&ProxyResponse{ id: self.shutting_down.take().expect("should have shut down correctly"), status: ProxyResponseStatus::Ok, data: None});
          return;
        } else if count < last_sessions_len {
          info!("shutting down, {} slab elements remaining (base: {})",
            count - self.base_sessions_count, self.base_sessions_count);
          last_sessions_len = count;
        }
      }
    }
  }

  fn send_queue(&mut self) {
    if self.channel.readiness.is_writable() {
      QUEUE.with(|q| {
        let mut queue = q.borrow_mut();
        loop {
          if let Some(msg) = queue.pop_front() {
            if !self.channel.write_message(&msg) {
              queue.push_front(msg);
            }
          }

          if self.channel.back_buf.available_data() > 0 {
            if let Err(e) = self.channel.writable() {
              error!("error writing to channel: {:?}", e);
            }
          }

          if !self.channel.readiness.is_writable() {
            break;
          }

          if self.channel.back_buf.available_data() == 0 && queue.len() == 0 {
            break;
          }
        }
      });
    }
  }

  fn notify(&mut self, message: ProxyRequest) {
    if let ProxyRequestData::Metrics = message.order {
      METRICS.with(|metrics| {
        push_queue(ProxyResponse {
          id:     message.id.clone(),
          status: ProxyResponseStatus::Ok,
          data:   Some(ProxyResponseData::Metrics(
            (*metrics.borrow_mut()).dump_metrics_data()
          ))
        });
      });
      return;
    }

    if let ProxyRequestData::Query(ref query) = message.order {
      match query {
        &Query::ApplicationsHashes => {
          push_queue(ProxyResponse {
            id:     message.id.clone(),
            status: ProxyResponseStatus::Ok,
            data:   Some(ProxyResponseData::Query(
              QueryAnswer::ApplicationsHashes(self.config_state.hash_state())
            ))
          });
          return;
        },
        &Query::Applications(ref query_type) => {
          let answer = match query_type {
            &QueryApplicationType::AppId(ref app_id) => {
              QueryAnswer::Applications(vec!(self.config_state.application_state(app_id)))
            },
            &QueryApplicationType::Domain(ref domain) => {
              let app_ids = get_application_ids_by_domain(&self.config_state, domain.hostname.clone(), domain.path.clone());
              let answer = app_ids.iter().filter_map(|ref app_rule| if let ApplicationRule::Id(app_id) = app_rule {
                  Some(self.config_state.application_state(app_id))
                } else {
                  None
                }
              ).collect();

              QueryAnswer::Applications(answer)
            }
          };

          push_queue(ProxyResponse {
            id:     message.id.clone(),
            status: ProxyResponseStatus::Ok,
            data:   Some(ProxyResponseData::Query(answer))
          });
          return;
        },
        &Query::Certificates(ref q) => {
          match q {
            QueryCertificateType::Domain(d) => {
              let res = self.listeners.values().filter(|l| l.listener_type() == ListenerType::HTTPS)
                .map(|l| (l.address(), l.query_certificates_domain(&d))).collect();
              push_queue(ProxyResponse {
                id:     message.id.clone(),
                status: ProxyResponseStatus::Ok,
                data:   Some(ProxyResponseData::Query(QueryAnswer::Certificates(QueryAnswerCertificate::Domain(res))))
              });
              return
            },
            QueryCertificateType::All => {
              let res = self.listeners.values().filter_map(|l| l.query_all_certificates().map(|res| (l.address(), res))).collect();
              push_queue(ProxyResponse {
                id:     message.id.clone(),
                status: ProxyResponseStatus::Ok,
                data:   Some(ProxyResponseData::Query(QueryAnswer::Certificates(QueryAnswerCertificate::All(res))))
              });
              return
            },
            QueryCertificateType::Fingerprint(f) => {
              push_queue(ProxyResponse {
                id:     message.id.clone(),
                status: ProxyResponseStatus::Ok,
                data:   Some(ProxyResponseData::Query(QueryAnswer::Certificates(QueryAnswerCertificate::Fingerprint(
                  get_certificate(&self.config_state, &f)
                ))))
              });
              return
            },
          }
        }
      }
    }

    self.notify_proxys(message);
  }

  pub fn notify_proxys(&mut self, message: ProxyRequest) {
    self.config_state.handle_order(&message.order);

    match message.order.listener() {
      Some(address) => {
         if let Some(listener) = self.listeners.values_mut().find(|l| l.address() == address) {
          push_queue(listener.notify(message))
        } else {
          push_queue(ProxyResponse{ id: message.id, status: ProxyResponseStatus::Error(format!("no listener at address: {}", address)), data: None })
        }
        return;
      },
      None => {},
    }

    match message {
      ProxyRequest { order: ProxyRequestData::AddApplication(ref application), .. } => {
        self.backends.borrow_mut().set_load_balancing_policy_for_app(&application.app_id,
          application.load_balancing_policy);
        //not returning because the message must still be handled by each proxy
      },
      ProxyRequest { ref id, order: ProxyRequestData::AddBackend(ref backend) } => {
        let new_backend = Backend::new(&backend.backend_id, backend.address,
          backend.sticky_id.clone(), backend.load_balancing_parameters.clone(), backend.backup);
        self.backends.borrow_mut().add_backend(&backend.app_id, new_backend);

        let answer = ProxyResponse { id: id.to_string(), status: ProxyResponseStatus::Ok, data: None };
        push_queue(answer);
        return;
      },
      ProxyRequest { ref id, order: ProxyRequestData::RemoveBackend(ref backend) } => {
        self.backends.borrow_mut().remove_backend(&backend.app_id, &backend.address);

        let answer = ProxyResponse { id: id.to_string(), status: ProxyResponseStatus::Ok, data: None };
        push_queue(answer);
        return;
      },
      // special case for AddHttpListener because we need to register a listener
      ProxyRequest { ref id, order: ProxyRequestData::AddHttpListener(ref listener) } => {
        debug!("{} add http listener {:?}", id, listener);
        if self.listen_address_state(listener.front) == ListenPortState::InUse {
          error!("Couldn't add HTTP front {}: address already in use", listener.front);
          push_queue(ProxyResponse {
            id: id.to_string(),
            status: ProxyResponseStatus::Error(format!("Couldn't add HTTP front {}: port already in use", listener.front)),
            data: None
          });
          return;
        }

        let entry = self.sessions.vacant_entry();

        if entry.is_none() {
          push_queue(ProxyResponse {
            id: id.to_string(),
            status: ProxyResponseStatus::Error(String::from("session list is full, cannot add a listener")),
            data: None
          });
          return;
        }

        let entry = entry.unwrap();
        let token = Token(entry.index().0);
        let proxy = self.http.clone();

        let status = if let Some(listener) = self.http.borrow_mut().add_listener(listener.clone(), token, proxy) {
          entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::HTTPListen })));
          self.base_sessions_count += 1;
          self.listeners.insert(ListenToken(token.0), Box::new(listener));
          ProxyResponseStatus::Ok
        } else {
          error!("Couldn't add HTTP listener");
          ProxyResponseStatus::Error(String::from("cannot add HTTP listener"))
        };

        let answer = ProxyResponse { id: id.to_string(), status, data: None };
        push_queue(answer);
        return;
      },
      // special case for AddHttpListener because we need to register a listener
      ProxyRequest { ref id, order: ProxyRequestData::AddHttpsListener(ref listener) } => {
        debug!("{} add https listener {:?}", id, listener);
        if self.listen_address_state(listener.front) == ListenPortState::InUse {
          error!("Couldn't add HTTPS front {}: address already in use", listener.front);
          push_queue(ProxyResponse {
            id: id.to_string(),
            status: ProxyResponseStatus::Error(format!("Couldn't add HTTPS front {}: port already in use", listener.front)),
            data: None
          });
          return;
        }

        let entry = self.sessions.vacant_entry();

        if entry.is_none() {
          push_queue(ProxyResponse {
            id: id.to_string(),
            status: ProxyResponseStatus::Error(String::from("session list is full, cannot add a listener")),
            data: None
          });
          return;
        }

        let entry = entry.unwrap();
        let token = Token(entry.index().0);

        let status = if let Some(listener) = self.https.add_listener(listener.clone(), token) {
          entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::HTTPSListen })));
          self.base_sessions_count += 1;
          self.listeners.insert(ListenToken(token.0), listener);

          ProxyResponseStatus::Ok
        } else {
          error!("Couldn't add HTTPS listener");
          ProxyResponseStatus::Error(String::from("cannot add HTTPS listener"))
        };

        let answer = ProxyResponse { id: id.to_string(), status, data: None };
        push_queue(answer);
        return;
      },
      // special case for AddTcpListener because we need to register a listener
      ProxyRequest { id, order: ProxyRequestData::AddTcpListener(listener) } => {
        debug!("{} add tcp listener {:?}", id, listener);
        if self.listen_address_state(listener.front) == ListenPortState::InUse {
          error!("Couldn't add TCP front {}: address already in use", listener.front);
          push_queue(ProxyResponse {
            id: id.to_string(),
            status: ProxyResponseStatus::Error(format!("Couldn't add TCP front {}: port already in use", listener.front)),
            data: None
          });
          return;
        }

        let entry = self.sessions.vacant_entry();

        if entry.is_none() {
          push_queue(ProxyResponse {
            id,
            status: ProxyResponseStatus::Error(String::from("session list is full, cannot add a listener")),
            data: None
          });
          return;
        }

        let entry = entry.unwrap();
        let token = Token(entry.index().0);
        let tcp = self.tcp.clone();

        let status = if let Some(listener) = self.tcp.borrow_mut().add_listener(listener.clone(), self.pool.clone(), token, tcp) {
          entry.insert(Rc::new(RefCell::new(ListenSession { protocol: Protocol::TCPListen })));
          self.base_sessions_count += 1;
          self.listeners.insert(ListenToken(token.0), Box::new(listener));

          ProxyResponseStatus::Ok
        } else {
          error!("Couldn't add TCP listener");
          ProxyResponseStatus::Error(String::from("cannot add TCP listener"))
        };
        let answer = ProxyResponse { id, status, data: None };
        push_queue(answer);
        return;
      },
      ProxyRequest { ref id, order: ProxyRequestData::RemoveListener(ref remove) } => {
        debug!("{} remove http listener {:?}", id, remove);
        self.base_sessions_count -= 1;

        let token = self.listeners.iter()
          .find(|(_, listener)| listener.address() == remove.front)
          .and_then(|(token, listener)| {
            match listener.active() {
              false => Some(token.clone()),
              true => {
                error!("Listener {:?} is still active, not removing", listener.address());
                None
              }
            }
          });

        if let Some(t) = token {
          self.listeners.remove_entry(&t);
          push_queue(ProxyResponse{ id: id.to_string(), status: ProxyResponseStatus::Ok, data: None })
        } else {
          push_queue(ProxyResponse{ id: id.to_string(), status: ProxyResponseStatus::Error(String::from("failed to remove listener")), data: None })
        }
        return;
      },
      ProxyRequest { ref id, order: ProxyRequestData::ActivateListener(ref activate) } => {
        debug!("{} activate listener {:?}", id, activate);
        let tcp_listener = self.scm_listeners.as_mut().and_then(|s| s.get(&activate.front))
          .map(|fd| unsafe { TcpListener::from_raw_fd(fd) });
        let opt_token = self.listeners.values().find(|listener| listener.address() == activate.front).and_then(|listener| {
          listener.activate(tcp_listener)
        });
        let status = match opt_token {
          Some(token) => {
            self.accept(ListenToken(token.0));
            ProxyResponseStatus::Ok
          },
          None => {
            error!("Couldn't activate listener");
            ProxyResponseStatus::Error(String::from("cannot activate listener"))
          }
        };

        let answer = ProxyResponse { id: id.to_string(), status, data: None };
        push_queue(answer);
        return;
      },
      ProxyRequest { ref id, order: ProxyRequestData::DeactivateListener(ref deactivate) } => {
        debug!("{} deactivate listener {:?}", id, deactivate);
        let opt_listener = self.listeners.values().find(|listener| listener.address() == deactivate.front).and_then(|listener| {
          listener.deactivate()
        });
        let status = match opt_listener {
          Some(_listener) => ProxyResponseStatus::Ok,
          None => {
            error!("Couldn't deactivate listener");
            ProxyResponseStatus::Error(String::from("cannot deactivate listener"))
          }
        };

        let answer = ProxyResponse { id: id.to_string(), status, data: None };
        push_queue(answer);
        return;
      },
      _ => {},
    };

    let topics = message.order.get_topics();

    if topics.contains(&Topic::HttpProxyConfig) {
      push_queue(self.http.borrow_mut().notify(message.clone()));
    }
    if topics.contains(&Topic::HttpsProxyConfig) {
      push_queue(self.https.notify(message.clone()));
    }
    if topics.contains(&Topic::TcpProxyConfig) {
      push_queue(self.tcp.borrow_mut().notify(message));
    }
  }

  pub fn return_listen_sockets(&mut self) {
    self.scm.set_blocking(false);

    let mut http_listeners = Vec::new();
    let mut https_listeners = Vec::new();
    let mut tcp_listeners = Vec::new();

    for (_, listener) in self.listeners.drain() {
      if let Some((addr, sock)) = listener.give_back_listener() {
        if let Err(e) = self.poll.borrow_mut().deregister(&sock) {
          error!("error deregistering HTTP listen socket({:?}): {:?}", sock, e);
        }

        match listener.listener_type() {
          ListenerType::HTTP => http_listeners.push((addr, sock)),
          ListenerType::HTTPS => https_listeners.push((addr, sock)),
          ListenerType::TCP => tcp_listeners.push((addr, sock)),
        };
      }
    }

    let listeners = Listeners {
      http: http_listeners.into_iter().map(|(addr, listener)|  (addr, listener.into_raw_fd())).collect(),
      tls:  https_listeners.into_iter().map(|(addr, listener)| (addr, listener.into_raw_fd())).collect(),
      tcp:  tcp_listeners.into_iter().map(|(addr, listener)|   (addr, listener.into_raw_fd())).collect(),
    };
    info!("sending default listeners: {:?}", listeners);
    let res = self.scm.send_listeners(listeners);

    self.scm.set_blocking(true);

    info!("sent default listeners: {:?}", res);
  }

  pub fn to_session(&self, token: Token) -> SessionToken {
    SessionToken(token.0)
  }

  pub fn from_session(&self, token: SessionToken) -> Token {
    Token(token.0)
  }

  pub fn close_session(&mut self, token: SessionToken) {
    if self.sessions.contains(token) {
      let session = self.sessions.remove(token).expect("session shoud be there");
      session.borrow().cancel_timeouts(&mut self.timer);
      let CloseResult { tokens } = session.borrow_mut().close(&mut self.poll.borrow_mut());

      for tk in tokens.into_iter() {
        let cl = self.to_session(tk);
        self.sessions.remove(cl);
      }

      assert!(self.nb_connections != 0);
      self.nb_connections -= 1;
      gauge!("client.connections", self.nb_connections);
    }

    // do not be ready to accept right away, wait until we get back to 10% capacity
    if !self.can_accept && self.nb_connections < self.max_connections * 90 / 100 {
      debug!("nb_connections = {}, max_connections = {}, starting to accept again", self.nb_connections, self.max_connections);
      self.can_accept = true;
    }
  }

  pub fn create_session_wrapper(&mut self, token: ListenToken, socket: TcpStream) -> bool {
    if self.nb_connections == self.max_connections {
      error!("max number of session connection reached, flushing the accept queue");
      self.can_accept = false;
      return false;
    }

    //FIXME: we must handle separately the session limit since the sessions slab also has entries for listeners and backends
    let index = match self.sessions.vacant_entry() {
      None => {
        error!("not enough memory to accept another session, flushing the accept queue");
        error!("nb_connections: {}, max_connections: {}", self.nb_connections, self.max_connections);
        self.can_accept = false;

        return false;
      },
      Some(entry) => {
        let session_token = Token(entry.index().0);
        let index = entry.index();
        let timeout = self.timer.set_timeout(self.front_timeout.to_std().unwrap(), session_token);

        let res = if let Some(listener) = self.listeners.get(&token) {
          listener.create_session(socket, session_token, timeout)
        } else {
          return false;
        };

        match res {
          Ok((session, should_connect)) => {
            entry.insert(session);
            self.nb_connections += 1;
            assert!(self.nb_connections <= self.max_connections);
            gauge!("client.connections", self.nb_connections);

            // specific to TCP, otherwise just return true
            if should_connect {
              index
            } else {
              return true;
            }
          },
          Err(AcceptError::IoError) => {
            //FIXME: do we stop accepting?
            return false;
          },
          Err(AcceptError::WouldBlock) => {
            self.accept_ready.remove(&token);
            return false;
          },
          Err(AcceptError::TooManySessions) => {
            error!("max number of session connection reached, flushing the accept queue");
            self.can_accept = false;
            return false;
          }
        }
      }
    };

    self.connect_to_backend(index);
    true
  }


  pub fn accept(&mut self, token: ListenToken) {
    if let Some(listener) = self.listeners.get(&token) {
      loop {
        match listener.accept() {
          Ok(sock) => self.accept_queue.push_back((sock, token, SteadyTime::now())),
          Err(AcceptError::WouldBlock) => {
            self.accept_ready.remove(&token);
            break
          },
          Err(other) => {
            error!("error accepting TCP sockets: {:?}", other);
            self.accept_ready.remove(&token);
            break;
          }
        }
      }
    }

    gauge!("accept_queue.count", self.accept_queue.len());
  }

  pub fn create_sessions(&mut self) {
    loop {
      if let Some((sock, token, timestamp)) = self.accept_queue.pop_back() {
        let delay = SteadyTime::now() - timestamp;
        time!("accept_queue.wait_time", delay.num_milliseconds());
        if delay > self.accept_queue_timeout {
          incr!("accept_queue.timeout");
          continue;
        }

        if !self.create_session_wrapper(token, sock) {
          break;
        }
      } else {
        break;
      }
    }

    gauge!("accept_queue.count", self.accept_queue.len());
  }

  pub fn connect_to_backend(&mut self, token: SessionToken) {
    if ! self.sessions.contains(token) {
      error!("invalid token in connect_to_backend");
      return;
    }

    let (protocol, res) = {
      let client = self.sessions[token].clone();
      let cl2: Rc<RefCell<dyn ProxySession>> = self.sessions[token].clone();
      let protocol = { client.borrow().protocol() };
      let entry = self.sessions.vacant_entry();
      if entry.is_none() {
        error!("not enough memory, cannot connect to backend");
        return;
      }
      let entry = entry.unwrap();
      let entry = entry.insert(cl2);
      let back_token = Token(entry.index().0);

      if protocol != Protocol::TCP && protocol != Protocol::HTTP && protocol != Protocol::HTTPS {
        panic!("should not call connect_to_backend on listeners");
      }

      let res = client.borrow_mut().connect_backend(back_token);

      if res != Ok(BackendConnectAction::New) {
        entry.remove();
      }
      (protocol, res)
    };

    match res {
      Ok(BackendConnectAction::Reuse) => {
        debug!("keepalive, reusing backend connection");
      }
      Ok(BackendConnectAction::Replace) => {
      },
      Ok(BackendConnectAction::New) => {
      },
      Err(ConnectionError::HostNotFound) | Err(ConnectionError::NoBackendAvailable) |
        Err(ConnectionError::HttpsRedirect) | Err(ConnectionError::InvalidHost) |
        Err(ConnectionError::Forbidden) => {
        if protocol == Protocol::TCP {
          self.close_session(token);
        }
      },
      _ => self.close_session(token),
    }
  }

  pub fn interpret_session_order(&mut self, token: SessionToken, order: SessionResult) {
    //trace!("INTERPRET ORDER: {:?}", order);
    match order {
      SessionResult::CloseSession     => self.close_session(token),
      SessionResult::CloseBackend(opt) => {
        if let Some(token) = opt {
          let cl = self.to_session(token);
          if let Some(session) = self.sessions.remove(cl) {
            session.borrow_mut().close_backend(token, &mut self.poll.borrow_mut());
          }
        }
      },
      SessionResult::ReconnectBackend(main_token, backend_token)  => {
        if let Some(t) = backend_token {
          let cl = self.to_session(t);
          if let Some(session) = self.sessions.remove(cl) {
            session.borrow_mut().close_backend(t, &mut self.poll.borrow_mut());
          }
        }

        if let Some(t) = main_token {
          let tok = self.to_session(t);
          self.connect_to_backend(tok)
        }
      },
      SessionResult::ConnectBackend  => self.connect_to_backend(token),
      SessionResult::Continue        => {}
    }
  }

  pub fn ready(&mut self, token: Token, events: Ready) {
    trace!("PROXY\t{:?} got events: {:?}", token, events);

    let mut session_token = SessionToken(token.0);
    if self.sessions.contains(session_token) {
      //info!("sessions contains {:?}", session_token);
      let protocol = self.sessions[session_token].borrow().protocol();
      //info!("protocol: {:?}", protocol);
      match protocol {
        Protocol::HTTPListen | Protocol::HTTPSListen | Protocol::TCPListen => {
          if events.is_readable() {
            self.accept_ready.insert(ListenToken(token.0));
            if self.can_accept {
              self.accept(ListenToken(token.0));
            }
            return;
          }

          if events.is_writable() {
            error!("received writable for listener {:?}, this should not happen", token);
            return;
          }

          if UnixReady::from(events).is_hup() {
            error!("should not happen: server {:?} closed", token);
            return;
          }

          unreachable!();

        },
        _ => {}
      }

      self.sessions[session_token].borrow_mut().process_events(token, events);

      loop {
        if !self.sessions.contains(session_token) {
          break;
        }

        let order = self.sessions[session_token].borrow_mut().ready();
        trace!("session[{:?} -> {:?}] got events {:?} and returned order {:?}", session_token, self.from_session(session_token), events, order);
        //FIXME: the CloseBackend message might not mean we have nothing else to do
        //with that session
        let is_connect = match order {
          SessionResult::ConnectBackend | SessionResult::ReconnectBackend(_,_) => true,
          _ => false,
        };

        // if we got ReconnectBackend, that means the current session_token
        // corresponds to an entry that will be removed in interpret_session_order
        // so we ask for the "main" token, ie the one for the front socket
        if let SessionResult::ReconnectBackend(Some(t), _) = order {
          session_token = self.to_session(t);
        }

        self.interpret_session_order(session_token, order);

        // if we had to connect to a backend server, go back to the loop
        // I'm not sure we would have anything to do right away, though,
        // so maybe we can just stop there for that session?
        // also the events would change?
        if !is_connect {
          break;
        }
      }
    }
  }

  pub fn timeout(&mut self, token: Token) {
    trace!("PROXY\t{:?} got timeout", token);

    let session_token = SessionToken(token.0);
    if self.sessions.contains(session_token) {
      let order = self.sessions[session_token].borrow_mut().timeout(token, &mut self.timer, &self.front_timeout);
      self.interpret_session_order(session_token, order);
    }
  }

  pub fn handle_remaining_readiness(&mut self) {
    // try to accept again after handling all session events,
    // since we might have released a few session slots
    if self.can_accept && !self.accept_ready.is_empty() {
      loop {
        if let Some(token) = self.accept_ready.iter().next().map(|token| ListenToken(token.0)) {
          self.accept(token);
          if !self.can_accept || self.accept_ready.is_empty() {
            break;
          }
        } else {
          // we don't have any more elements to loop over
          break;
        }
      }
    }
  }

  fn listen_address_state(&self, addr: SocketAddr) -> ListenPortState {
    match self.listeners.values().find(|l| l.address() == addr) {
      Some(_) => ListenPortState::InUse,
      None    => ListenPortState::Available,
    }
  }
}

pub struct ListenSession {
  pub protocol: Protocol,
}

impl ProxySession for ListenSession {
  fn last_event(&self) -> SteadyTime {
    SteadyTime::now()
  }

  fn print_state(&self) {}

  fn tokens(&self) -> Vec<Token> {
    Vec::new()
  }

  fn protocol(&self) -> Protocol {
    self.protocol
  }

  fn ready(&mut self) -> SessionResult {
    SessionResult::Continue
  }

  fn process_events(&mut self, _token: Token, _events: Ready) {}

  fn close(&mut self, _poll: &mut Poll) -> CloseResult {
    CloseResult::default()
  }

  fn close_backend(&mut self, _token: Token, _poll: &mut Poll) {
  }

  fn timeout(&mut self, _token: Token, _timer: &mut Timer<Token>, _front_timeout: &time::Duration) -> SessionResult {
    unimplemented!();
  }

  fn cancel_timeouts(&self, _timer: &mut Timer<Token>) {
    unimplemented!();
  }

  fn connect_backend(&mut self, _back_token: Token) -> Result<BackendConnectAction,ConnectionError> {
    unimplemented!()
  }
}

#[cfg(feature = "use-openssl")]
use https_openssl;

use https_rustls;

#[cfg(feature = "use-openssl")]
pub enum HttpsProvider {
  Openssl(Rc<RefCell<https_openssl::Proxy>>),
  Rustls(Rc<RefCell<https_rustls::configuration::Proxy>>),
}

#[cfg(not(feature = "use-openssl"))]
pub enum HttpsProvider {
  Rustls(Rc<RefCell<https_rustls::configuration::Proxy>>),
}

#[cfg(feature = "use-openssl")]
impl HttpsProvider {
  pub fn new(use_openssl: bool, pool: Rc<RefCell<Pool<Buffer>>>, backends: Rc<RefCell<BackendMap>>, poll: Rc<RefCell<Poll>>) -> HttpsProvider {
    if use_openssl {
      HttpsProvider::Openssl(Rc::new(RefCell::new(https_openssl::Proxy::new(pool, backends, poll))))
    } else {
      HttpsProvider::Rustls(Rc::new(RefCell::new(https_rustls::configuration::Proxy::new(pool, backends, poll))))
    }
  }

  pub fn notify(&mut self, message: ProxyRequest) -> ProxyResponse {
    match self {
      &mut HttpsProvider::Rustls(ref mut rustls)   => rustls.borrow_mut().notify(message),
      &mut HttpsProvider::Openssl(ref mut openssl) => openssl.borrow_mut().notify(message),
    }
  }

  pub fn add_listener(&mut self, config: HttpsListener, token: Token) -> Option<Box<dyn Listener>> {

    match self {
      &mut HttpsProvider::Rustls(ref mut rustls)   => {
        let proxy = rustls.clone();
        rustls.borrow_mut().add_listener(config, token, proxy).map(|l| Box::new(l) as Box<dyn Listener>)
      },
      &mut HttpsProvider::Openssl(ref mut openssl) => {
        let proxy = openssl.clone();
        openssl.borrow_mut().add_listener(config, token, proxy).map(|l| Box::new(l) as Box<dyn Listener>)
      },
    }
  }
}

#[cfg(not(feature = "use-openssl"))]
impl HttpsProvider {
  pub fn new(use_openssl: bool, pool: Rc<RefCell<Pool<Buffer>>>, backends: Rc<RefCell<BackendMap>>, poll: Rc<RefCell<Poll>>) -> HttpsProvider {
    if use_openssl {
      error!("the openssl provider is not compiled, continuing with the rustls provider");
    }

    let configuration = https_rustls::configuration::Proxy::new(pool, backends, poll);
    HttpsProvider::Rustls(Rc::new(RefCell::new(configuration)))
  }

  pub fn notify(&mut self, message: ProxyRequest) -> ProxyResponse {
    let &mut HttpsProvider::Rustls(ref mut rustls) = self;
    rustls.borrow_mut().notify(message)
  }

  pub fn add_listener(&mut self, config: HttpsListener, token: Token) -> Option<Box<dyn Listener>> {
    let &mut HttpsProvider::Rustls(ref mut rustls) = self;
    let proxy = rustls.clone();
    rustls.borrow_mut().add_listener(config, token, proxy).map(|l| Box::new(l) as Box<dyn Listener>)
  }
}
