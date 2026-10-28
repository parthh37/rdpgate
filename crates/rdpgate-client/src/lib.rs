//! RDP Gate client: the device key, finding and authenticating the server,
//! signing in, and launching the system's Remote Desktop app. Used by both the
//! `rdpgate` command-line tool and the desktop app.
//!
//! Nothing here trusts DNS, IP addresses or certificate authorities. The
//! server card pins the server's identity key; wherever an address comes from
//! (the encrypted beacon, a host name, the last address that worked), the
//! server must prove that key over the TLS channel binding before the client
//! sends a single byte about itself.

use ed25519_dalek::SigningKey;
use rdpgate_core::beacon::{self, Card};
use rdpgate_core::keystore::{KeyFile, write_private};
use rdpgate_core::rdp;
use rdpgate_core::wire::{self, Payload, Response, ServerHello};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub mod settings;
pub mod trust;
pub mod winpass;

pub use settings::RdpSettings;

pub type Result<T> = std::result::Result<T, String>;

pub const MIN_PASSPHRASE: usize = 10;
const NET_TIMEOUT: Duration = Duration::from_secs(12);
/// Connecting on the home network is near-instant when it works at all.
const LAN_TIMEOUT: Duration = Duration::from_secs(3);
/// IPv6 is tried before IPv4 when the server has both. Where it works the
/// handshake is quick; where a router silently drops it, don't wait long.
const IPV6_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// This computer's name as enrolled on the server.
    pub device: String,
    /// Windows account to pre-fill in the Remote Desktop app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_username: Option<String>,
    /// The server card (`rdpgate-card:…`) printed by `rdpgate-server device-add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<String>,
    /// Last sign-in address where the server proved its identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known: Option<SocketAddr>,
    /// Remote Desktop port to use with `last_known` when it was the server's
    /// address on its own network (the router may forward a different one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_rdp_port: Option<u16>,
    /// Newest beacon time seen. Older beacons are refused, so a replayed
    /// beacon can't send the client back to an old address.
    #[serde(default)]
    pub beacon_ts: i64,
    /// Install signed updates automatically.
    #[serde(default = "yes")]
    pub auto_update: bool,
    /// Unix time of the last update check.
    #[serde(default)]
    pub last_update_check: i64,
    /// "Keep me signed in": signing in with passphrase and code asks the
    /// server to remember this computer, so it connects without them next
    /// time ([`trust`]).
    #[serde(default)]
    pub keep_signed_in: bool,
    /// Remote Desktop settings, written into the connection file at every launch.
    #[serde(default, deserialize_with = "settings::lenient")]
    pub rdp: RdpSettings,
    /// Connect here first (tests, or `--address`).
    #[serde(skip)]
    pub connect_override: Option<SocketAddr>,
    /// Tests: send this hardware digest and keep nothing sealed.
    #[serde(skip)]
    pub hw_override: Option<String>,
}

fn yes() -> bool {
    true
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// True when automatic updates are on and the last check was over a day ago.
pub fn update_due(cfg: &ClientConfig) -> bool {
    cfg.auto_update && unix_now() - cfg.last_update_check > 24 * 3600
}

/// Records that an update check happened (best effort).
pub fn mark_update_checked(dir: &Path) {
    if let Ok(mut cfg) = load_config(dir) {
        cfg.last_update_check = unix_now();
        let _ = save_config(dir, &cfg);
    }
}

pub fn set_auto_update(dir: &Path, on: bool) -> Result<()> {
    let mut cfg = load_config(dir)?;
    cfg.auto_update = on;
    save_config(dir, &cfg)
}

/// Remembers the "Keep me signed in" choice for the next sign-in. Turning it
/// off also forgets this computer here.
pub fn set_keep_signed_in(dir: &Path, on: bool) -> Result<()> {
    let mut cfg = load_config(dir)?;
    if !on {
        trust::forget(dir);
    }
    if cfg.keep_signed_in != on {
        cfg.keep_signed_in = on;
        save_config(dir, &cfg)?;
    }
    Ok(())
}

pub fn set_rdp_settings(dir: &Path, rdp: &RdpSettings) -> Result<()> {
    let mut cfg = load_config(dir)?;
    cfg.rdp = rdp.clone();
    save_config(dir, &cfg)
}

/// The Windows account Remote Desktop signs in with. A saved password for
/// another account is forgotten.
pub fn set_rdp_username(dir: &Path, user: &str) -> Result<()> {
    let user = Some(user.trim().to_string()).filter(|u| !u.is_empty());
    let mut cfg = load_config(dir)?;
    if winpass::is_saved(dir) && winpass::saved_user(dir) != user {
        winpass::forget(dir);
    }
    if cfg.rdp_username != user {
        cfg.rdp_username = user;
        save_config(dir, &cfg)?;
    }
    Ok(())
}

/// Asks GitHub for a newer signed release (blocking). 0.x releases are
/// pre-releases, so those are included.
pub fn check_update() -> Result<Option<rdpgate_core::update::Available>> {
    rdpgate_core::update::check(VERSION, true)
}

/// Downloads, verifies and installs the update for this program (blocking).
/// Returns what to relaunch: the new executable, or the app bundle on macOS.
pub fn install_update(av: &rdpgate_core::update::Available, c: rdpgate_core::update::Component) -> Result<PathBuf> {
    use rdpgate_core::update::{Component, asset_for, download, replace_current_exe};
    let asset = asset_for(c).ok_or("no updates are published for this system; download the new version manually")?;
    let bytes = download(av, asset)?;
    #[cfg(target_os = "macos")]
    if c == Component::App {
        return rdpgate_core::update::replace_mac_app(&bytes);
    }
    let _ = Component::App;
    replace_current_exe(&bytes)
}

/// Per-user settings folder: `~/Library/Application Support/rdpgate` on
/// macOS, `%APPDATA%\rdpgate` on Windows.
pub fn default_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("rdpgate")
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("device.key")
}

pub fn is_set_up(dir: &Path) -> bool {
    config_path(dir).exists() && key_path(dir).exists()
}

pub fn load_config(dir: &Path) -> Result<ClientConfig> {
    let raw = std::fs::read(config_path(dir)).map_err(|e| format!("not set up yet ({e}); run setup first"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("config.json: {e}"))
}

pub fn save_config(dir: &Path, cfg: &ClientConfig) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec_pretty(cfg).map_err(|e| e.to_string())?;
    write_private(&config_path(dir), &json).map_err(|e| e.to_string())
}

/// What the owner copies to the server to enroll this computer.
#[derive(Debug, Clone)]
pub struct Identity {
    pub device: String,
    pub public_key: String,
    pub fingerprint: String,
}

impl Identity {
    /// The exact command to run on the server.
    pub fn enroll_command(&self) -> String {
        format!("rdpgate-server device-add {} {}", self.device, self.public_key)
    }
}

pub fn valid_device_name(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Creates the device key (encrypted with `passphrase`) and the config.
pub fn create_device(dir: &Path, device: &str, rdp_username: Option<String>, passphrase: &str, overwrite: bool) -> Result<Identity> {
    if !valid_device_name(device) {
        return Err("Computer name: 1-32 letters, digits, dots, dashes or underscores.".into());
    }
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(format!("Use a passphrase of at least {MIN_PASSPHRASE} characters."));
    }
    if key_path(dir).exists() && !overwrite {
        return Err("This computer already has a device key. Remove it first to make a new one.".into());
    }
    let key = SigningKey::from_bytes(&rdpgate_core::random_bytes::<32>());
    let file = KeyFile::seal(&key, passphrase.as_bytes()).map_err(|e| e.to_string())?;
    let cfg = ClientConfig {
        device: device.into(),
        rdp_username: rdp_username.filter(|u| !u.trim().is_empty()),
        card: None,
        last_known: None,
        last_known_rdp_port: None,
        beacon_ts: 0,
        auto_update: true,
        last_update_check: 0,
        keep_signed_in: false,
        rdp: RdpSettings::default(),
        connect_override: None,
        hw_override: None,
    };
    save_config(dir, &cfg)?;
    file.save(&key_path(dir)).map_err(|e| e.to_string())?;
    identity(dir)
}

pub fn identity(dir: &Path) -> Result<Identity> {
    let cfg = load_config(dir)?;
    let file = KeyFile::load(&key_path(dir)).map_err(|e| e.to_string())?;
    let vk = file.verifying_key().ok_or("device.key is corrupted")?;
    Ok(Identity { device: cfg.device, public_key: wire::encode_public_key(&vk), fingerprint: wire::fingerprint(&vk) })
}

/// Saves the server card. Returns the server key fingerprint to show the user.
pub fn set_card(dir: &Path, text: &str) -> Result<String> {
    let card = Card::decode(text)?;
    let mut cfg = load_config(dir)?;
    let changed = cfg.card.as_deref().and_then(|c| Card::decode(c).ok()).is_none_or(|old| old.key != card.key);
    if changed {
        cfg.last_known = None;
        cfg.last_known_rdp_port = None;
        cfg.beacon_ts = 0;
    }
    cfg.card = Some(card.encode());
    save_config(dir, &cfg)?;
    Ok(wire::fingerprint(&card.server_key()))
}

pub fn card(cfg: &ClientConfig) -> Result<Card> {
    let text = cfg.card.as_deref().ok_or("Paste the server card first (rdpgate-server card prints it).")?;
    Card::decode(text)
}

/// Decrypts the device key. Takes about a second on purpose (Argon2id).
pub fn unlock(dir: &Path, passphrase: &str) -> Result<SigningKey> {
    let file = KeyFile::load(&key_path(dir)).map_err(|e| e.to_string())?;
    file.open(passphrase.as_bytes()).map_err(|e| e.to_string())
}

/// The result of a successful sign-in.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Public IP the server opened (as the server saw it).
    pub ip: String,
    /// Unix seconds by which the RDP session must start.
    pub expires: i64,
    /// Unix seconds when access ends even while connected (older servers don't say).
    pub hard_expires: Option<i64>,
    /// The address the server proved its identity at. RDP goes to the same IP.
    pub server_addr: SocketAddr,
    pub rdp_port: u16,
    /// SHA-256 of the real RDP certificate, as read by the server itself.
    pub rdp_cert_sha256: Option<String>,
    /// This computer's address as the server saw it.
    pub source: Option<IpAddr>,
    /// The server remembers this computer (auto mode, which the server turns
    /// on, or "Keep me signed in", which the server allows or not): the
    /// token that opens access without a passphrase or code
    /// ([`open`]) and moves it when this computer's address changes
    /// ([`keep_following`]).
    pub auto: Option<String>,
    /// The token and key are now sealed on this computer, so next time it
    /// connects without a passphrase or code ([`trust::recall`]).
    pub remembered: bool,
}

impl Grant {
    pub fn rdp_target(&self) -> SocketAddr {
        SocketAddr::new(self.server_addr.ip(), self.rdp_port)
    }

    /// "Access stays open while you're connected, for up to 12 h."
    pub fn while_connected(&self) -> String {
        match self.hard_expires {
            Some(t) => format!("Access stays open while you're connected, for up to {}.", minutes_left(t)),
            None => "Access stays open while you're connected.".into(),
        }
    }
}

#[derive(Clone, Copy)]
enum Source {
    Given,
    Beacon,
    Host,
    LastKnown,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Source::Given => "the address you gave",
            Source::Beacon => "the beacon",
            Source::Host => "the host name",
            Source::LastKnown => "the last address that worked",
        }
    }
}

/// A place to ask for the server, and the Remote Desktop port that goes with
/// it when that isn't the one the server reports (its own-network address).
#[derive(Clone, Copy)]
struct Target {
    addr: SocketAddr,
    rdp_port: Option<u16>,
}

impl Target {
    fn at(addr: SocketAddr) -> Self {
        Target { addr, rdp_port: None }
    }
}

/// A home-network address: it only answers when this computer is on that
/// network, and elsewhere the same address can belong to anything.
fn is_local_network(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        std::net::IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The order to try a server's public addresses in: the one that worked
/// last time, then IPv6 (it reaches networks whose IPv4 is shared, behind
/// carrier-grade NAT), then IPv4. No address twice.
fn public_order(ips: Vec<IpAddr>, last_known: Option<SocketAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out.sort_by_key(|ip| (Some(*ip) != last_known.map(|a| a.ip()), ip.is_ipv4()));
    out
}

/// Where to look next. None of these is trusted: an address is only a place
/// to ask the server to prove its identity.
async fn resolve(src: Source, cfg: &ClientConfig, card: &Card, notes: &mut Vec<String>, newest: &mut Option<i64>) -> Vec<Target> {
    match src {
        Source::Given => cfg.connect_override.map(Target::at).into_iter().collect(),
        Source::LastKnown => cfg.last_known.map(|addr| Target { addr, rdp_port: cfg.last_known_rdp_port }).into_iter().collect(),
        Source::Beacon => {
            let Some(gist) = card.gist.clone() else { return vec![] };
            let text = match tokio::task::spawn_blocking(move || beacon::fetch_gist(&gist)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    notes.push(e);
                    return vec![];
                }
                Err(_) => return vec![],
            };
            match beacon::open(&text, &card.server_key(), &card.beacon_key) {
                Ok(loc) if loc.ts < cfg.beacon_ts => {
                    notes.push("ignored a beacon older than one already seen (possible replay)".into());
                    vec![]
                }
                Ok(loc) => {
                    *newest = Some(loc.ts);
                    // At home, straight to the server; elsewhere that fails fast.
                    let lan = loc.lan.map(|l| Target { addr: SocketAddr::new(l.ip, l.port), rdp_port: Some(l.rdp_port) });
                    let ip6 = loc.ip6.map(IpAddr::V6);
                    let public = public_order(ip6.into_iter().chain([loc.ip]).collect(), cfg.last_known);
                    let target = |ip| {
                        if Some(ip) == ip6 {
                            // No router port mapping over IPv6: the server's own ports.
                            Target { addr: SocketAddr::new(ip, loc.ip6_port.unwrap_or(loc.port)), rdp_port: loc.ip6_rdp_port }
                        } else {
                            Target::at(SocketAddr::new(ip, loc.port))
                        }
                    };
                    lan.into_iter().chain(public.into_iter().map(target)).collect()
                }
                Err(e) => {
                    notes.push(e);
                    vec![]
                }
            }
        }
        Source::Host => {
            let Some(host) = card.host.as_deref() else { return vec![] };
            match tokio::time::timeout(NET_TIMEOUT, tokio::net::lookup_host((host, card.port))).await {
                Ok(Ok(addrs)) => {
                    // The firewall grant is for whichever address signs in, and
                    // Remote Desktop then connects to the same server address.
                    let ips = addrs.map(|a| a.ip()).collect();
                    public_order(ips, cfg.last_known).into_iter().map(|ip| Target::at(SocketAddr::new(ip, card.port))).collect()
                }
                _ => {
                    notes.push(format!("could not look up {host}"));
                    vec![]
                }
            }
        }
    }
}

/// TCP + TLS 1.3 to `addr`, then the server must prove the pinned key.
async fn open_verified(addr: SocketAddr, card: &Card) -> std::result::Result<(TlsStream<TcpStream>, [u8; 32]), (bool, String)> {
    let connect_timeout = if is_local_network(addr.ip()) {
        LAN_TIMEOUT
    } else if addr.is_ipv6() {
        IPV6_TIMEOUT
    } else {
        NET_TIMEOUT
    };
    let tcp = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| (false, format!("{addr}: timed out")))?
        .map_err(|e| (false, format!("{addr}: {e}")))?;
    let cfg = rdp::unverified_client_config(true, &[wire::ALPN]);
    let name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut tls = tokio::time::timeout(NET_TIMEOUT, tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp))
        .await
        .map_err(|_| (false, format!("{addr}: TLS timed out")))?
        .map_err(|e| (false, format!("{addr}: TLS failed: {e}")))?;
    let conn = tls.get_ref().1;
    if conn.alpn_protocol() != Some(wire::ALPN) {
        return Err((true, format!("{addr} is not an RDP Gate server")));
    }
    let binding = conn
        .export_keying_material([0u8; wire::EKM_LEN], wire::EKM_LABEL, None)
        .map_err(|e| (false, format!("{addr}: {e}")))?;
    let hello: ServerHello = tokio::time::timeout(NET_TIMEOUT, wire::read_frame(&mut tls))
        .await
        .map_err(|_| (true, format!("{addr} did not prove its identity")))?
        .map_err(|_| (true, format!("{addr} did not prove its identity")))?;
    wire::verify_server_hello(&card.server_key(), &binding, &hello)
        .map_err(|_| (true, format!("{addr} answered but is NOT your server")))?;
    Ok((tls, binding))
}

/// Sends one signed request on a verified connection and reads the reply.
async fn request(tls: &mut TlsStream<TcpStream>, binding: &[u8], key: &SigningKey, p: Payload) -> Result<Response> {
    let req = wire::sign(key, binding, &p);
    tokio::time::timeout(NET_TIMEOUT, async {
        wire::write_frame(tls, &req).await?;
        wire::read_frame(tls).await
    })
    .await
    .map_err(|_| "the server did not answer in time".to_string())?
    .map_err(|e| format!("server connection: {e}"))
}

/// Finds the server, verifies it, sends one signed request (`p`, stamped
/// with this device and the time). Also returns the server's other
/// addresses from the same source, not tried yet.
async fn exchange(dir: &Path, cfg: &ClientConfig, key: &SigningKey, p: Payload) -> Result<(Response, Target, Vec<Target>)> {
    let card = card(cfg)?;
    let mut notes = Vec::new();
    let mut newest_beacon = None;
    let mut tried: Vec<SocketAddr> = Vec::new();
    let mut impostor = None;
    for src in [Source::Given, Source::Beacon, Source::Host, Source::LastKnown] {
        let targets = resolve(src, cfg, &card, &mut notes, &mut newest_beacon).await;
        for (i, &target) in targets.iter().enumerate() {
            let addr = target.addr;
            if tried.contains(&addr) {
                continue;
            }
            tried.push(addr);
            let (mut tls, binding) = match open_verified(addr, &card).await {
                Ok(v) => v,
                Err((spoof, msg)) => {
                    // Away from home, the server's home address can be some
                    // other machine: expected, not a sign of spoofing.
                    if spoof && !is_local_network(addr.ip()) {
                        impostor = Some(msg.clone());
                    }
                    notes.push(format!("{msg} (from {})", src.label()));
                    continue;
                }
            };
            let p = Payload { device: cfg.device.clone(), ts: unix_now(), ..p.clone() };
            let resp = request(&mut tls, &binding, key, p).await?;

            // Remember where the server proved itself, and the newest beacon.
            let mut updated = cfg.clone();
            updated.last_known = Some(addr);
            updated.last_known_rdp_port = target.rdp_port;
            updated.beacon_ts = updated.beacon_ts.max(newest_beacon.unwrap_or(0));
            updated.connect_override = None;
            // Auto mode asks every few seconds: only write what changed.
            let same = (cfg.last_known, cfg.last_known_rdp_port, cfg.beacon_ts)
                == (updated.last_known, updated.last_known_rdp_port, updated.beacon_ts);
            if !same {
                let _ = save_config(dir, &updated);
            }
            let rest = targets[i + 1..].iter().filter(|t| !tried.contains(&t.addr)).copied().collect();
            return Ok((resp, target, rest));
        }
    }
    if tried.is_empty() {
        notes.insert(0, "No address to try for the server.".into());
        return Err(notes.join("\n"));
    }
    let mut msg = match impostor {
        Some(m) => format!(
            "Could not reach your server safely: {m}.\nThe server's identity check failed, so nothing was sent. \
             This can mean someone is impersonating it, or its IP changed and another machine has the old one."
        ),
        None => "Could not reach your server.".into(),
    };
    msg.push_str("\nTried: ");
    msg.push_str(&notes.join("; "));
    Err(msg)
}

/// Server text is shown to people; strip anything that could drive a terminal.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(300).collect()
}

fn explain(resp: &Response) -> String {
    match resp.error.as_deref().map(clean).as_deref() {
        Some("denied") | None => "The server refused this computer. Is it enrolled (rdpgate-server device-list)? Repeated failures also block your IP for a while.".into(),
        Some(e) => {
            let mut s = e.to_string();
            if let Some(f) = s.get_mut(0..1) {
                f.make_ascii_uppercase();
            }
            s
        }
    }
}

/// Device key + 6-digit code: asks the server to open RDP for this network.
/// With [`ClientConfig::keep_signed_in`], also asks it to remember this
/// computer; without, whatever it was remembered with is forgotten.
pub async fn sign_in(dir: &Path, cfg: &ClientConfig, key: &SigningKey, code: &str) -> Result<Grant> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Enter the 6-digit code from your authenticator app.".into());
    }
    // Saying what hardware this is lets the server remember it, in auto mode
    // or when asked to keep it signed in. Not asking, it says nothing.
    let keep = cfg.keep_signed_in;
    let hw = hardware(cfg, key).filter(|_| keep);
    let p = Payload { op: wire::OP_TOTP.into(), totp: code.into(), hw: hw.clone().unwrap_or_default(), keep, ..Default::default() };
    let (resp, target, rest) = exchange(dir, cfg, key, p).await?;
    if !resp.ok {
        return Err(explain(&resp));
    }
    let mut grant = opened(cfg, key, resp, target, &rest).await;
    match (&grant.auto, &hw, &cfg.hw_override) {
        (Some(token), Some(hw), None) => grant.remembered = trust::remember(dir, key, token, hw).is_ok(),
        // The server forgot it too.
        (None, _, None) => trust::forget(dir),
        _ => {}
    }
    Ok(grant)
}

/// Why asking to stay signed in didn't work, after a sign-in that asked.
pub fn not_kept(grant: &Grant) -> Option<&'static str> {
    if grant.remembered {
        None
    } else if !trust::supported() {
        Some("Staying signed in isn't supported on this system yet.")
    } else if grant.auto.is_none() {
        Some("The server doesn't let computers stay signed in (RDP Gate Server > Computers).")
    } else {
        Some("This computer couldn't keep its sign-in safely (system keychain).")
    }
}

/// This computer's hardware digest, where it can be remembered.
fn hardware(cfg: &ClientConfig, key: &SigningKey) -> Option<String> {
    cfg.hw_override.clone().or_else(|| trust::supported().then(|| trust::hardware_digest(&key.verifying_key())).flatten())
}

/// The server no longer remembers this computer: forget it here too.
fn not_remembered(dir: &Path, resp: &Response) -> Option<String> {
    let why = resp.error.as_deref()?.strip_prefix(wire::NOT_REMEMBERED)?;
    trust::forget(dir);
    let mut why = clean(why);
    if let Some(f) = why.get_mut(0..1) {
        f.make_ascii_uppercase();
    }
    Some(format!("{why}. Sign in with your passphrase and code."))
}

/// The grant a successful sign-in (or auto-mode move) answered with.
async fn opened(cfg: &ClientConfig, key: &SigningKey, resp: Response, target: Target, rest: &[Target]) -> Grant {
    let source = resp.ip.as_deref().and_then(|i| i.parse::<IpAddr>().ok());
    let mut ip = source.map(|i| i.to_string()).unwrap_or_default();
    // Don't hold up signing in for long if the other address doesn't answer.
    if let Some(token) = resp.link.as_deref()
        && let Ok(Some(also)) = tokio::time::timeout(IPV6_TIMEOUT, link_other_family(cfg, key, target, rest, token)).await
    {
        ip = format!("{ip} and {also}");
    }
    Grant {
        ip,
        expires: resp.expires.unwrap_or_default(),
        hard_expires: resp.hard_expires,
        server_addr: target.addr,
        rdp_port: target.rdp_port.or(resp.rdp_port).unwrap_or(3389),
        rdp_cert_sha256: resp.rdp_cert_sha256.filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
        source,
        auto: resp.auto.filter(|t| !t.is_empty()),
        remembered: false,
    }
}

/// What one auto-mode check found.
#[derive(Debug, Clone)]
pub enum Followed {
    /// This computer's address hasn't changed.
    Same,
    /// It changed: the server opened the new address and closed the old one.
    Moved(Grant),
    /// Access has closed (time ran out, the longest session ended, or the
    /// service restarted). A remembered computer opens it again with [`open`].
    Closed,
    /// Following has stopped: the server no longer remembers this computer
    /// (it was forgotten here too) or refused for another reason.
    Ended(String),
}

/// Auto mode: asks the server, from wherever this computer is now, to move
/// `grant` here if this computer's address changed. Goes to the address the
/// server proved itself at, and only searches again (beacon, host name) if
/// that fails. An `Err` means the server couldn't be reached; try again later.
pub async fn follow(dir: &Path, cfg: &ClientConfig, key: &SigningKey, grant: &Grant) -> Result<Followed> {
    let Some(token) = grant.auto.clone() else { return Ok(Followed::Ended("auto mode is off for this computer".into())) };
    let cfg = ClientConfig { connect_override: Some(grant.server_addr), ..cfg.clone() };
    let hw = hardware(&cfg, key).unwrap_or_default();
    let p = Payload { op: wire::OP_FOLLOW.into(), auto: token, hw, ..Default::default() };
    let (resp, mut target, rest) = exchange(dir, &cfg, key, p).await?;
    if !resp.ok {
        if resp.error.as_deref() == Some(wire::CLOSED) {
            return Ok(Followed::Closed);
        }
        return Ok(Followed::Ended(not_remembered(dir, &resp).unwrap_or_else(|| explain(&resp))));
    }
    let source = resp.ip.as_deref().and_then(|i| i.parse::<IpAddr>().ok());
    if target.addr == grant.server_addr {
        if source == grant.source {
            return Ok(Followed::Same);
        }
        // Same place as before (perhaps the server's own-network address).
        target.rdp_port = Some(grant.rdp_port);
    }
    let cert = grant.rdp_cert_sha256.clone();
    let mut moved = opened(&cfg, key, resp, target, &rest).await;
    moved.rdp_cert_sha256 = moved.rdp_cert_sha256.or(cert);
    (moved.auto, moved.remembered) = (grant.auto.clone(), grant.remembered);
    Ok(Followed::Moved(moved))
}

/// Auto mode: opens access for a remembered computer with no passphrase or
/// code: its device `key` and the server's `token` (from [`trust::recall`]).
/// If the server no longer remembers it, it's forgotten here too.
pub async fn open(dir: &Path, cfg: &ClientConfig, key: &SigningKey, token: &str) -> Result<Grant> {
    let hw = hardware(cfg, key).ok_or("this computer's hardware can't be read, so it can't be remembered")?;
    let p = Payload { op: wire::OP_OPEN.into(), auto: token.into(), hw, ..Default::default() };
    let (resp, target, rest) = exchange(dir, cfg, key, p).await?;
    if !resp.ok {
        return Err(not_remembered(dir, &resp).unwrap_or_else(|| explain(&resp)));
    }
    let mut grant = opened(cfg, key, resp, target, &rest).await;
    (grant.auto, grant.remembered) = (Some(token.into()), true);
    Ok(grant)
}

/// [`open`] with what this computer remembers. The key is returned too, for
/// following and closing access later.
pub async fn open_remembered(dir: &Path, cfg: &ClientConfig) -> Result<(Grant, SigningKey)> {
    let r = trust::recall(dir).ok_or("This computer isn't remembered (or its hardware changed). Sign in with your passphrase and code.")?;
    Ok((open(dir, cfg, &r.key, &r.token).await?, r.key))
}

/// How often auto mode checks this computer's address. Remote Desktop keeps
/// trying to reconnect for a minute or so after the address changes.
pub const FOLLOW_EVERY: Duration = Duration::from_secs(15);
/// Longest wait between checks while the server can't be reached (offline,
/// asleep), so the beacon isn't fetched every few seconds.
const FOLLOW_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// How often auto mode looks at this computer's own network. That costs
/// nothing (no packet is sent), so a change of network (Wi-Fi to hotspot,
/// a new address from the router) reaches the server within a second or two
/// instead of at the next [`FOLLOW_EVERY`].
const NETWORK_EVERY: Duration = Duration::from_secs(1);
/// After this computer's network changes: quick retries while the new one
/// comes up, before backing off as usual.
const NETWORK_RETRY: Duration = Duration::from_secs(2);
const NETWORK_RETRIES: u32 = 8;

/// The addresses this computer would send from to reach the internet, over
/// IPv4 and IPv6. Connecting a UDP socket only picks a route: nothing is
/// sent. When they change, so has this computer's network, and most likely
/// the address the server sees.
pub fn local_route() -> Vec<IpAddr> {
    let probe = |bind: &str, to: &str| {
        let s = std::net::UdpSocket::bind(bind).ok()?;
        s.connect(to).ok()?;
        s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified())
    };
    [probe("0.0.0.0:0", "192.0.2.1:9"), probe("[::]:0", "[2001:db8::1]:9")].into_iter().flatten().collect()
}

/// What [`keep_following`] reports.
#[derive(Debug, Clone)]
pub enum FollowEvent {
    /// Access moved to this computer's new address. The connection file was
    /// rewritten for it, and the Remote Desktop certificate checked again.
    Moved { grant: Grant, check: RdpCheck, rdp_file: PathBuf },
    /// Access has closed; a remembered computer opens it again with [`open`].
    /// Following has stopped.
    Closed,
    /// Auto mode is over, or the server at the new address failed the
    /// certificate check. Following has stopped.
    Ended(String),
}

/// Auto mode: checks every [`FOLLOW_EVERY`], and straight away when this
/// computer's network changes, whether its address changed and moves the
/// access with it, until access closes, auto mode ends or `stop` is set.
/// Only for a grant that has an auto token.
pub async fn keep_following(
    dir: &Path,
    cfg: &ClientConfig,
    key: &SigningKey,
    mut grant: Grant,
    stop: &std::sync::atomic::AtomicBool,
    mut on: impl FnMut(FollowEvent),
) {
    use std::sync::atomic::Ordering;
    use tokio::time::Instant;
    let mut wait = FOLLOW_EVERY;
    let mut route = local_route();
    let mut looked = Instant::now();
    let mut retries = 0;
    loop {
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            if looked.elapsed() >= NETWORK_EVERY {
                looked = Instant::now();
                let now = local_route();
                if now != route {
                    route = now;
                    retries = NETWORK_RETRIES;
                    break;
                }
            }
        }
        // The newest beacon time, if signing in elsewhere saw one.
        let cfg = load_config(dir).map(|c| ClientConfig { connect_override: None, ..c }).unwrap_or_else(|_| cfg.clone());
        let result = follow(dir, &cfg, key, &grant).await;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        if result.is_ok() {
            retries = 0;
        }
        match result {
            Ok(Followed::Same) => wait = FOLLOW_EVERY,
            Ok(Followed::Moved(g)) => {
                wait = FOLLOW_EVERY;
                // Never send Remote Desktop into an interception.
                let check = match verify_rdp(&g).await {
                    Ok(c) => c,
                    Err(e) => return on(FollowEvent::Ended(e)),
                };
                match write_rdp_file(dir, &cfg, &g) {
                    Ok(rdp_file) => on(FollowEvent::Moved { grant: g.clone(), check, rdp_file }),
                    Err(e) => return on(FollowEvent::Ended(format!("could not write the connection file: {e}"))),
                }
                grant = g;
            }
            Ok(Followed::Closed) => return on(FollowEvent::Closed),
            Ok(Followed::Ended(e)) => return on(FollowEvent::Ended(e)),
            // The new network may still be coming up: try again soon.
            Err(_) if retries > 0 => {
                retries -= 1;
                wait = NETWORK_RETRY;
            }
            Err(_) => wait = (wait * 2).min(FOLLOW_BACKOFF_MAX),
        }
    }
}

/// A computer with both IPv6 and IPv4 signed in over one of them: open the
/// other as well, so Remote Desktop gets through whichever it ends up using.
/// Best effort; returns the address the server opened.
async fn link_other_family(cfg: &ClientConfig, key: &SigningKey, signed_in: Target, rest: &[Target], token: &str) -> Option<String> {
    // At home the server sees this computer's home address; going out
    // through the router for the other family would only look like the router.
    if is_local_network(signed_in.addr.ip()) {
        return None;
    }
    let card = card(cfg).ok()?;
    let other = rest.iter().find(|t| t.addr.is_ipv4() != signed_in.addr.is_ipv4() && !is_local_network(t.addr.ip()))?;
    let (mut tls, binding) = open_verified(other.addr, &card).await.ok()?;
    let p = Payload { op: wire::OP_LINK.into(), device: cfg.device.clone(), ts: unix_now(), link: token.into(), ..Default::default() };
    let resp = request(&mut tls, &binding, key, p).await.ok().filter(|r| r.ok)?;
    resp.ip.as_deref().and_then(|i| i.parse::<IpAddr>().ok()).map(|i| i.to_string())
}

/// Closes the firewall for this network again.
pub async fn lock(dir: &Path, cfg: &ClientConfig, key: &SigningKey) -> Result<String> {
    let (resp, ..) = exchange(dir, cfg, key, Payload { op: wire::OP_REVOKE.into(), ..Default::default() }).await?;
    if !resp.ok {
        return Err(explain(&resp));
    }
    Ok(resp.ip.as_deref().map(clean).unwrap_or_default())
}

/// Outcome of checking the RDP endpoint before launching Remote Desktop.
#[derive(Debug, Clone, PartialEq)]
pub enum RdpCheck {
    /// The RDP port presents the certificate the server vouched for.
    Verified,
    /// Couldn't check (reason). Remote Desktop will show its own warning.
    Unchecked(String),
}

/// Probes the RDP port and compares its certificate with the one the server
/// reported over the authenticated channel. A mismatch is an error: someone
/// is intercepting the RDP connection.
pub async fn verify_rdp(grant: &Grant) -> Result<RdpCheck> {
    let Some(expected) = &grant.rdp_cert_sha256 else {
        return Ok(RdpCheck::Unchecked("the server could not read its own Remote Desktop certificate".into()));
    };
    match rdp::probe(grant.rdp_target(), Duration::from_secs(8)).await {
        Ok(c) if c.sha256.eq_ignore_ascii_case(expected) => Ok(RdpCheck::Verified),
        Ok(c) => Err(format!(
            "STOP: the Remote Desktop certificate at {} is not your computer's.\nExpected {}\nGot      {}\n\
             Someone may be intercepting the connection, so Remote Desktop was not opened.",
            grant.rdp_target(),
            rdp::pretty(expected),
            rdp::pretty(&c.sha256)
        )),
        Err(e) => Ok(RdpCheck::Unchecked(e)),
    }
}

/// Writes a .rdp file pointing at the exact address the server proved
/// itself at, with this computer's Remote Desktop settings. A saved Windows
/// password is handed to Remote Desktop where it can take one ([`winpass`]).
pub fn write_rdp_file(dir: &Path, cfg: &ClientConfig, grant: &Grant) -> Result<PathBuf> {
    let user = cfg.rdp_username.as_deref().filter(|u| !u.is_empty());
    let signs_in = user.is_some_and(|u| winpass::prepare(dir, u, grant.server_addr.ip()));
    let mut lines = vec![
        format!("full address:s:{}", grant.rdp_target()),
        format!("prompt for credentials:i:{}", u8::from(!signs_in)),
        "authentication level:i:2".into(),
        "enablecredsspsupport:i:1".into(),
    ];
    lines.extend(cfg.rdp.rdp_lines());
    if let Some(u) = user {
        lines.push(format!("username:s:{u}"));
    }
    let path = dir.join("RDP Gate.rdp");
    std::fs::write(&path, lines.join("\r\n") + "\r\n").map_err(|e| e.to_string())?;
    Ok(path)
}

/// Opens the .rdp file in the system's Remote Desktop app.
pub fn launch_rdp(path: &Path) -> Result<()> {
    use std::process::Command;
    if cfg!(windows) {
        // mstsc keeps running for the whole session, so don't wait for it.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        return Command::new(format!(r"{root}\System32\mstsc.exe"))
            .arg(path)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Could not start Remote Desktop (mstsc): {e}"));
    }
    // Microsoft's Windows App first (same bundle ID as the old Microsoft
    // Remote Desktop): other apps claim .rdp files too, such as the
    // "Remote Desktop Connection" stub Parallels Desktop leaves behind, which
    // only says Parallels is missing. Without it, the default for .rdp files.
    #[cfg(target_os = "macos")]
    {
        let ms = Command::new("/usr/bin/open").args(["-b", "com.microsoft.rdc.macos"]).arg(path).status();
        if ms.is_ok_and(|s| s.success()) {
            return Ok(());
        }
    }
    let opener = if cfg!(target_os = "macos") { "/usr/bin/open" } else { "xdg-open" };
    match Command::new(opener).arg(path).status() {
        Ok(s) if s.success() => Ok(()),
        _ if cfg!(target_os = "macos") => {
            Err("Could not open Remote Desktop. Install \"Windows App\" from the Mac App Store, then try again.".into())
        }
        _ => Err(format!("Could not open {}. Open it with your Remote Desktop app.", path.display())),
    }
}

/// "12 min", for showing how long a grant has left.
pub fn minutes_left(unix: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mins = ((unix - now) as f64 / 60.0).round() as i64;
    match (mins / 60, mins % 60) {
        _ if mins <= 0 => "now".into(),
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_what_worked_then_ipv6_then_ipv4() {
        let (v4, v6): (IpAddr, IpAddr) = ("198.72.98.36".parse().unwrap(), "2607:f748:203:b9::11".parse().unwrap());
        assert_eq!(public_order(vec![v4, v6, v4], None), [v6, v4]);
        assert_eq!(public_order(vec![v6, v4], Some(SocketAddr::new(v4, 47443))), [v4, v6]);
        assert_eq!(public_order(vec![v4], Some(SocketAddr::new(v6, 47443))), [v4]);
    }

    #[test]
    fn local_route_is_stable_and_sends_nothing() {
        let route = local_route();
        assert!(route.iter().all(|ip| !ip.is_unspecified()));
        assert_eq!(local_route(), route, "the same network gives the same answer");
    }

    #[test]
    fn device_setup_and_card_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rdpgate-client-{}", rdpgate_core::random_token::<6>()));
        assert!(create_device(&dir, "mac", None, "short", false).is_err());
        let id = create_device(&dir, "mac", None, "long enough passphrase", false).unwrap();
        assert!(id.enroll_command().starts_with("rdpgate-server device-add mac rdpgate-ed25519:"));
        assert!(create_device(&dir, "mac", None, "long enough passphrase", false).is_err(), "must not overwrite");
        let key = unlock(&dir, "long enough passphrase").unwrap();
        assert_eq!(wire::encode_public_key(&key.verifying_key()), id.public_key);
        assert!(unlock(&dir, "wrong passphrase!").is_err());

        assert!(set_card(&dir, "rdpgate-card:nonsense").is_err());
        let server = SigningKey::from_bytes(&rdpgate_core::random_bytes::<32>());
        let c = Card {
            v: 1,
            key: wire::encode_server_key(&server.verifying_key()),
            beacon_key: rdpgate_core::random_bytes::<32>().to_vec(),
            gist: None,
            host: Some("rdp.example.org".into()),
            port: 47443,
        };
        assert_eq!(set_card(&dir, &c.encode()).unwrap(), wire::fingerprint(&server.verifying_key()));
        assert_eq!(card(&load_config(&dir).unwrap()).unwrap().server_key(), server.verifying_key());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn connection_file_follows_the_saved_settings() {
        let dir = std::env::temp_dir().join(format!("rdpgate-rdpfile-{}", rdpgate_core::random_token::<6>()));
        create_device(&dir, "mac", Some("alice".into()), "long enough passphrase", false).unwrap();
        let rdp = RdpSettings { display: settings::Display::AllMonitors, clipboard: false, ..Default::default() };
        set_rdp_settings(&dir, &rdp).unwrap();
        let cfg = load_config(&dir).unwrap();
        assert_eq!(cfg.rdp, rdp, "kept in config.json");
        let grant = Grant {
            ip: "198.51.100.4".into(),
            expires: 0,
            hard_expires: None,
            server_addr: "192.0.2.10:47443".parse().unwrap(),
            rdp_port: 3390,
            rdp_cert_sha256: None,
            source: None,
            auto: None,
            remembered: false,
        };
        let text = std::fs::read_to_string(write_rdp_file(&dir, &cfg, &grant).unwrap()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for line in ["full address:s:192.0.2.10:3390", "use multimon:i:1", "redirectclipboard:i:0", "username:s:alice", "prompt for credentials:i:1"] {
            assert!(lines.contains(&line), "{line} in\n{text}");
        }
        assert!(text.ends_with("\r\n") && !text.contains("password"), "no password in the file");

        set_rdp_username(&dir, "  ").unwrap();
        assert_eq!(load_config(&dir).unwrap().rdp_username, None);
        std::fs::remove_dir_all(dir).ok();
    }
}
