//! The running service. One TCP port carries two things, told apart by TLS
//! ALPN before any certificate is chosen:
//! - `rdpgate/1`: the desktop client. TLS 1.3 with a throwaway self-signed
//!   certificate; trust comes from the server's pinned identity key, proven
//!   over the TLS channel binding, so no DNS name or CA is involved.
//! - HTTP/1.1: the passkey web portal, only when a DNS name is configured.

use crate::config::Config;
use crate::firewall::Firewall;
use crate::grants::Grants;
use crate::identity::Identity;
use crate::limiter::Limiter;
use crate::state::{State, Store, now};
use rdpgate_core::rdp::RdpCert;
use rustls::ServerConfig;
use rustls_pki_types::PrivateKeyDer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::LazyConfigAcceptor;
use webauthn_rs::prelude::*;

/// Concurrent connections, including ones still in the TLS handshake.
const MAX_CONNECTIONS: usize = 256;
/// Per source address (IPv4 /32, IPv6 /64), so one host can't take them all.
const MAX_PER_SOURCE: u32 = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Wait between attempts to turn pending protection on.
const PROTECT_RETRY_SECS: i64 = 15 * 60;
/// How long a probed RDP certificate fingerprint is reused.
const RDP_CERT_TTL: Duration = Duration::from_secs(600);

pub struct App {
    pub cfg: Config,
    pub store: Store,
    pub identity: Identity,
    /// Present only when browser sign-in is enabled.
    pub webauthn: Option<Webauthn>,
    pub limiter: Limiter,
    pub grants: Arc<Grants>,
    pub logins: Pending<PasskeyAuthentication>,
    pub enrolls: Pending<(String, PasskeyRegistration)>,
    rdp_cert: tokio::sync::Mutex<Option<(RdpCert, Instant)>>,
    conns: Mutex<HashMap<String, u32>>,
    restart: tokio::sync::Notify,
    restart_requested: std::sync::atomic::AtomicBool,
    /// Protection waits for the first connected sign-in (see `protect`).
    protection_pending: AtomicBool,
    /// A lock-down is running right now.
    protecting: AtomicBool,
    /// Unix time before which a failed lock-down isn't tried again.
    protect_retry_at: std::sync::atomic::AtomicI64,
}

/// Why the server stopped.
#[derive(Debug, PartialEq)]
pub enum Exit {
    Stopped,
    /// A new version was installed; the service manager should start it.
    Restart,
}

/// Short-lived WebAuthn ceremony state, keyed by a random id. Each source
/// may hold only a couple at once, and the oldest is evicted when full, so
/// nobody can fill the table to lock the owner out.
pub struct Pending<T> {
    map: Mutex<HashMap<String, (T, i64, String)>>,
    cap: usize,
}

const PENDING_PER_SOURCE: usize = 2;

impl<T> Pending<T> {
    pub fn new(cap: usize) -> Self {
        Pending { map: Mutex::new(HashMap::new()), cap }
    }
    pub fn put(&self, key: String, v: T, ttl_secs: i64, src: &str) -> bool {
        let mut m = self.map.lock().unwrap();
        let t = now();
        m.retain(|_, (_, exp, _)| *exp > t);
        let mine: Vec<(String, i64)> =
            m.iter().filter(|(_, (_, _, s))| s == src).map(|(k, (_, exp, _))| (k.clone(), *exp)).collect();
        if mine.len() >= PENDING_PER_SOURCE
            && let Some((oldest, _)) = mine.iter().min_by_key(|(_, exp)| *exp)
        {
            m.remove(oldest);
        }
        if m.len() >= self.cap
            && let Some(oldest) = m.iter().min_by_key(|(_, (_, exp, _))| *exp).map(|(k, _)| k.clone())
        {
            m.remove(&oldest);
        }
        m.insert(key, (v, t + ttl_secs, src.to_string()));
        true
    }
    /// Removes and returns the entry: each challenge is answerable once.
    pub fn take(&self, key: &str) -> Option<T> {
        let (v, exp, _) = self.map.lock().unwrap().remove(key)?;
        (exp > now()).then_some(v)
    }
}

/// Counts a connection against its source until dropped.
struct ConnSlot<'a> {
    app: &'a App,
    src: String,
}

impl Drop for ConnSlot<'_> {
    fn drop(&mut self) {
        let mut m = self.app.conns.lock().unwrap();
        if let Some(n) = m.get_mut(&self.src) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.src);
            }
        }
    }
}

impl App {
    pub fn new(cfg: Config, fw: Arc<dyn Firewall>) -> Result<Arc<Self>, String> {
        let identity = Identity::load_or_create(&cfg.data_dir)?;
        let webauthn = match (&cfg.public_host, cfg.public_url(), cfg.web_login) {
            (Some(host), Some(url), true) => {
                let origin = Url::parse(&url).map_err(|e| e.to_string())?;
                Some(
                    WebauthnBuilder::new(host, &origin)
                        .and_then(|b| b.rp_name("RDP Gate").timeout(Duration::from_secs(300)).build())
                        .map_err(|e| format!("webauthn: {e:?}"))?,
                )
            }
            _ => None,
        };
        let grants = Arc::new(
            Grants::new(
                fw,
                cfg.grant_duration(),
                cfg.max_duration(),
                cfg.allow_private_sources,
                Some(cfg.data_dir.join("grants.json")),
            )
            .with_power(crate::power::for_config(&cfg)),
        );
        let store = Store::new(&cfg.data_dir);
        let protection_pending = store.load().map(|s| s.protection_pending).unwrap_or(false);
        Ok(Arc::new(App {
            store,
            identity,
            webauthn,
            limiter: Limiter::default(),
            grants,
            logins: Pending::new(16),
            enrolls: Pending::new(4),
            rdp_cert: tokio::sync::Mutex::new(None),
            conns: Mutex::new(HashMap::new()),
            restart: tokio::sync::Notify::new(),
            restart_requested: std::sync::atomic::AtomicBool::new(false),
            protection_pending: AtomicBool::new(protection_pending),
            protecting: AtomicBool::new(false),
            protect_retry_at: std::sync::atomic::AtomicI64::new(0),
            cfg,
        }))
    }

    /// Keeps the firewall warnings for `rdpgate-server status`.
    fn write_warnings(&self, warnings: &[String]) {
        if let Ok(json) = serde_json::to_vec_pretty(warnings) {
            let _ = rdpgate_core::keystore::write_private(&self.cfg.data_dir.join("warnings.json"), &json);
        }
    }

    /// Asks the server to stop so the freshly installed version can start.
    pub fn request_restart(&self) {
        self.restart_requested.store(true, std::sync::atomic::Ordering::SeqCst);
        self.restart.notify_one();
    }

    fn take_slot(&self, src: &str) -> Option<ConnSlot<'_>> {
        let mut m = self.conns.lock().unwrap();
        let n = m.entry(src.to_string()).or_insert(0);
        if *n >= MAX_PER_SOURCE {
            return None;
        }
        *n += 1;
        Some(ConnSlot { app: self, src: src.to_string() })
    }

    /// Reads state.json off the async threads (it takes a file lock).
    pub async fn state(&self) -> Result<State, String> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.load()).await.map_err(|e| e.to_string())?
    }

    /// Read-modify-writes state.json off the async threads.
    pub async fn update_state<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut State) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.update(f)).await.map_err(|e| e.to_string())?
    }

    /// Fingerprint of the certificate the local RDP service presents, read by
    /// connecting to it on 127.0.0.1 the way an RDP client would.
    pub async fn rdp_cert(&self) -> Option<RdpCert> {
        let mut cached = self.rdp_cert.lock().await;
        if let Some((c, at)) = cached.as_ref()
            && at.elapsed() < RDP_CERT_TTL
        {
            return Some(c.clone());
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], self.cfg.rdp_port));
        match rdpgate_core::rdp::probe(addr, Duration::from_secs(4)).await {
            Ok(c) => {
                *cached = Some((c.clone(), Instant::now()));
                Some(c)
            }
            Err(e) => {
                crate::logln!("WARNING cannot read the local Remote Desktop certificate: {e}");
                None
            }
        }
    }
}

struct Tls {
    gate: Arc<ServerConfig>,
    web: Option<Arc<ServerConfig>>,
}

/// TLS for the desktop protocol: 1.3 only, fresh self-signed certificate on
/// every start. Clients ignore the certificate and check the identity key.
fn gate_tls() -> Result<Arc<ServerConfig>, String> {
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = rcgen::CertificateParams::new(vec!["rdpgate.invalid".to_string()])
        .and_then(|p| p.self_signed(&key))
        .map_err(|e| e.to_string())?;
    let mut c = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .map_err(|e| e.to_string())?;
    c.alpn_protocols = vec![rdpgate_core::wire::ALPN.to_vec()];
    Ok(Arc::new(c))
}

fn tls_setup(cfg: &Config, shutdown: watch::Receiver<bool>) -> Result<Tls, String> {
    let gate = gate_tls()?;
    let (Some(_), Some((cert, key)), true) = (&cfg.public_host, cfg.tls.files(), cfg.web_login) else {
        return Ok(Tls { gate, web: None });
    };
    let files = crate::cert::FileCert::load(cert, key)?;
    files.clone().watch(shutdown);
    let mut c = ServerConfig::builder().with_no_client_auth().with_cert_resolver(files);
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls { gate, web: Some(Arc::new(c)) })
}

/// Binds the configured addresses and serves until `shutdown` flips to true.
pub async fn run(app: Arc<App>, mut shutdown: watch::Receiver<bool>) -> Result<Exit, String> {
    let mut listeners = Vec::new();
    for (addr, required) in app.cfg.listen_addrs() {
        match bind(addr) {
            Ok(l) => listeners.push(l),
            Err(e) if required => return Err(format!("listen {addr}: {e}")),
            Err(e) => crate::logln!("WARN no IPv6 sign-in: could not listen on {addr}: {e}"),
        }
    }
    serve(app, listeners, &mut shutdown).await
}

/// Binds the listener. On Windows, with SO_EXCLUSIVEADDRUSE so no other
/// local program can bind the same port and intercept connections.
fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{SO_EXCLUSIVEADDRUSE, SOL_SOCKET, setsockopt};
        let on: i32 = 1;
        let rc = unsafe {
            setsockopt(sock.as_raw_socket() as _, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (&on as *const i32).cast(), 4)
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    TcpListener::from_std(sock.into())
}

pub async fn serve(app: Arc<App>, listeners: Vec<TcpListener>, shutdown: &mut watch::Receiver<bool>) -> Result<Exit, String> {
    let tls = Arc::new(tls_setup(&app.cfg, shutdown.clone())?);

    // Nothing from a previous run may stay open, then check for anything
    // else that would expose RDP. Warnings are also kept for `status`.
    let fw = app.grants.firewall();
    let portal_ports: Vec<u16> = listeners.iter().filter_map(|l| l.local_addr().ok()).map(|a| a.port()).collect();
    let warnings = tokio::task::spawn_blocking(move || {
        let mut w = Vec::new();
        if let Err(e) = fw.revoke_all() {
            w.push(format!("could not remove old RDPGate rules: {e}"));
        }
        // The sign-in port must be reachable: (re)create our own allow rule.
        if let Err(e) = fw.ensure_portal(&portal_ports) {
            w.push(format!("could not open the sign-in port in Windows Firewall: {e}"));
        }
        w.extend(fw.audit());
        w
    })
    .await
    .unwrap_or_default();
    for w in &warnings {
        crate::logln!("WARNING {w}");
    }
    if app.protection_pending.load(Ordering::SeqCst) {
        crate::logln!(
            "PROTECT pending: Remote Desktop is reachable as before Setup until someone signs in through RDP Gate and connects"
        );
    }
    app.write_warnings(&warnings);

    let addrs: Vec<String> = listeners.iter().filter_map(|l| l.local_addr().ok()).map(|a| a.to_string()).collect();
    crate::logln!(
        "START listen={} server_key={} rdp=:{} (clients use :{}) udp={} browser_login={} desktop_login={} beacon={} firewall={}",
        addrs.join(","),
        app.identity.fingerprint(),
        app.cfg.rdp_port,
        app.cfg.rdp_public_port,
        app.cfg.allow_udp,
        tls.web.is_some(),
        app.cfg.desktop_login,
        app.cfg.beacon.is_some(),
        app.cfg.firewall
    );

    // The sign-in listeners and the grant upkeep must never stop on their
    // own. If one does (a panic), the whole process exits as failed and the
    // service manager starts it again, rather than running half-alive.
    let mut critical = tokio::task::JoinSet::new();
    critical.spawn(maintain(app.clone(), shutdown.clone()));
    let beacon = tokio::spawn(crate::beacon::run(app.clone(), shutdown.clone()));
    let updater = tokio::spawn(crate::updater::run(app.clone(), shutdown.clone()));
    let router = tokio::spawn(crate::router::run(app.cfg.clone(), shutdown.clone()));

    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    for ln in listeners {
        let (app, tls, limit, mut stop) = (app.clone(), tls.clone(), limit.clone(), shutdown.clone());
        critical.spawn(async move {
            loop {
                tokio::select! {
                    r = ln.accept() => {
                        let Ok((tcp, peer)) = r else {
                            // e.g. out of sockets: don't spin, try again shortly.
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        };
                        let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
                        let (app, tls) = (app.clone(), tls.clone());
                        tokio::spawn(async move {
                            connection(app, tls, tcp, peer).await;
                            drop(permit);
                        });
                    }
                    _ = stop.changed() => break,
                }
            }
        });
    }

    let mut failed = None;
    loop {
        if *shutdown.borrow() || app.restart_requested.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            r = shutdown.changed() => if r.is_err() { break },
            _ = app.restart.notified() => {}
            Some(r) = critical.join_next() => {
                if !*shutdown.borrow() {
                    failed = Some(if r.as_ref().is_err_and(|e| e.is_panic()) { "a server task panicked" } else { "a server task stopped" });
                    break;
                }
            }
        }
    }
    crate::logln!("STOP closing all firewall grants");
    critical.abort_all();
    beacon.abort();
    updater.abort();
    router.abort();
    app.grants.shutdown().await;
    if let Some(why) = failed {
        return Err(format!("{why} unexpectedly; exiting so the service restarts"));
    }
    if app.restart_requested.load(std::sync::atomic::Ordering::SeqCst) { Ok(Exit::Restart) } else { Ok(Exit::Stopped) }
}

async fn connection(app: Arc<App>, tls: Arc<Tls>, tcp: TcpStream, peer: SocketAddr) {
    let _ = tcp.set_nodelay(true);
    let src = crate::limiter::source_key(peer.ip());
    if !app.limiter.allowed(&src) {
        return; // banned sources get silence
    }
    let Some(_slot) = app.take_slot(&src) else { return };
    let start = match tokio::time::timeout(HANDSHAKE_TIMEOUT, LazyConfigAcceptor::new(Default::default(), tcp)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let hello = start.client_hello();
    let wants_gate = hello.alpn().is_some_and(|mut protos| protos.any(|p| p == rdpgate_core::wire::ALPN));
    let sni_ok = match (hello.server_name(), &app.cfg.public_host) {
        (Some(n), Some(h)) => n.eq_ignore_ascii_case(h),
        _ => false,
    };
    let config = if wants_gate {
        tls.gate.clone()
    } else if let (Some(web), true) = (&tls.web, sni_ok) {
        web.clone()
    } else {
        // Scanners get a dropped handshake, not a certificate that names us.
        return;
    };
    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, start.into_stream(config)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    if stream.get_ref().1.alpn_protocol() == Some(rdpgate_core::wire::ALPN) {
        crate::gate::handle(app.clone(), stream, peer).await;
    } else {
        crate::web::serve(app.clone(), stream, peer).await;
    }
}

async fn maintain(app: Arc<App>, mut shutdown: watch::Receiver<bool>) {
    let mut t = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = t.tick() => {
                // Time limits apply without a restart, which would end sessions.
                if let Ok(c) = Config::load(&app.cfg.data_dir) {
                    app.grants.set_limits(c.grant_duration(), c.max_duration()).await;
                }
                app.grants.tick().await;
                app.limiter.prune();
                protect_when_ready(&app).await;
            }
            _ = shutdown.changed() => return,
        }
    }
}

/// Turns pending protection on once a signed-in address has Remote Desktop
/// connected. Runs in the background: inspecting every firewall rule can
/// take a minute, and grants must keep ticking meanwhile.
async fn protect_when_ready(app: &Arc<App>) {
    if !app.protection_pending.load(Ordering::SeqCst)
        || app.protecting.load(Ordering::SeqCst)
        || now() < app.protect_retry_at.load(Ordering::SeqCst)
        || !crate::protect::ready(&app.grants.list().await)
    {
        return;
    }
    // `rdpgate-server protect` may have done it already.
    if !app.state().await.is_ok_and(|s| s.protection_pending) {
        app.protection_pending.store(false, Ordering::SeqCst);
        return;
    }
    app.protecting.store(true, Ordering::SeqCst);
    let app = app.clone();
    tokio::spawn(async move {
        crate::logln!("PROTECT signed in and connected through RDP Gate: locking Remote Desktop down");
        let (fw, store) = (app.grants.firewall(), app.store.clone());
        match tokio::task::spawn_blocking(move || crate::protect::apply(&*fw, &store)).await {
            Ok(Ok(disabled)) => {
                for r in &disabled {
                    crate::logln!("PROTECT disabled firewall rule {r:?}");
                }
                crate::logln!("PROTECT on: Remote Desktop now opens only for signed-in addresses");
                app.protection_pending.store(false, Ordering::SeqCst);
                let fw = app.grants.firewall();
                let warnings = tokio::task::spawn_blocking(move || fw.audit()).await.unwrap_or_default();
                app.write_warnings(&warnings);
            }
            Ok(Err(e)) => {
                crate::logln!("ERROR turning protection on (trying again in 15 minutes): {e}");
                app.protect_retry_at.store(now() + PROTECT_RETRY_SECS, Ordering::SeqCst);
            }
            Err(e) => {
                crate::logln!("ERROR turning protection on: {e}");
                app.protect_retry_at.store(now() + PROTECT_RETRY_SECS, Ordering::SeqCst);
            }
        }
        app.protecting.store(false, Ordering::SeqCst);
    });
}
