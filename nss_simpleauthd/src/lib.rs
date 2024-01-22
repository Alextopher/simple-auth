mod config;
mod ffi;
mod group;
mod passwd;
mod shadow;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::{self, Runtime};
use tokio::time::sleep_until;
use trust_dns_resolver::TokioAsyncResolver;

use crate::config::CFG;

lazy_static::lazy_static! {
    static ref RPC: Mutex<ClientAccessControl> = Mutex::new(ClientAccessControl::default());
    static ref RT: Runtime = runtime::Builder::new_multi_thread().worker_threads(2).enable_io().enable_time().build().expect("could not initialize tokio runtime");
}

struct AuthdPasswd;
struct AuthdShadow;
struct AuthdGroup;

#[derive(Default)]
struct ClientAccessControl {
    client: Arc<Mutex<Option<authd::rpc::AuthdClient>>>,
    latest_ts: Arc<Mutex<Option<Instant>>>,
}

impl ClientAccessControl {
    fn with_client<O>(&mut self, f: impl FnOnce(&mut authd::rpc::AuthdClient) -> O) -> O {
        let _guard = RT.enter();
        let mut lts = self.latest_ts.lock().unwrap();
        *lts = Some(std::time::Instant::now() + Duration::from_secs(30));

        let client = self.client.clone();
        let latest_ts = self.latest_ts.clone();
        tokio::spawn(async move {
            loop {
                let dur = latest_ts.lock().unwrap().unwrap_or(Instant::now()).into();
                sleep_until(dur).await;
                // make sure it wasn't moved forward while we were sleeping
                if latest_ts.lock().unwrap().unwrap_or(Instant::now()) < Instant::now() {
                    *client.lock().unwrap() = None;
                    break;
                }
            }
        });

        let resolver = TokioAsyncResolver::tokio_from_system_conf().expect("need dns resolver");

        let final_sockaddr = match &CFG.host {
            authd::SocketName::Dns(name, port) => {
                let ip = RT
                    .block_on(resolver.lookup_ip(name))
                    .expect("lookup failure");
                Some(std::net::SocketAddr::new(
                    ip.iter().next().expect("need at least one ip"),
                    *port,
                ))
            }
            authd::SocketName::Addr(sa) => Some(*sa),
        };

        eprintln!(
            "nss_simpleauthd: ClientAccessControl: connecting to {:?}",
            final_sockaddr
        );

        let mut client = self.client.lock().unwrap();
        if client.is_none() {
            *client = Some(
                RT.block_on(authd::client_connect(
                    final_sockaddr.expect("no host found"),
                    &rustls::Certificate(std::fs::read(&CFG.cert).expect("reading cert")),
                    "localhost",
                ))
                .unwrap(),
            );
        }
        f(client.as_mut().unwrap())
    }
}
