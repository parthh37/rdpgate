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
    /// Connect here first (tests, or `--address`).
    #[serde(skip)]
    pub connect_override: Option<SocketAddr>,
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
        connect_override: None,
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
    /// The address the server proved its identity at. RDP goes to the same IP.
    pub server_addr: SocketAddr,
    pub rdp_port: u16,
    /// SHA-256 of the real RDP certificate, as read by the server itself.
    pub rdp_cert_sha256: Option<String>,
}

impl Grant {
    pub fn rdp_target(&self) -> SocketAddr {
        SocketAddr::new(self.server_addr.ip(), self.rdp_port)
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

/// Finds the server, verifies it, sends one signed request.
async fn exchange(dir: &Path, cfg: &ClientConfig, key: &SigningKey, op: &str, code: &str) -> Result<(Response, Target)> {
    let card = card(cfg)?;
    let mut notes = Vec::new();
    let mut newest_beacon = None;
    let mut tried: Vec<SocketAddr> = Vec::new();
    let mut impostor = None;
    for src in [Source::Given, Source::Beacon, Source::Host, Source::LastKnown] {
        for target in resolve(src, cfg, &card, &mut notes, &mut newest_beacon).await {
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
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let req = wire::sign(key, &binding, &Payload { op: op.into(), device: cfg.device.clone(), ts, totp: code.into() });
            let resp: Response = tokio::time::timeout(NET_TIMEOUT, async {
                wire::write_frame(&mut tls, &req).await?;
                wire::read_frame(&mut tls).await
            })
            .await
            .map_err(|_| "the server did not answer in time".to_string())?
            .map_err(|e| format!("server connection: {e}"))?;

            // Remember where the server proved itself, and the newest beacon.
            let mut updated = cfg.clone();
            updated.last_known = Some(addr);
            updated.last_known_rdp_port = target.rdp_port;
            updated.beacon_ts = updated.beacon_ts.max(newest_beacon.unwrap_or(0));
            updated.connect_override = None;
            let _ = save_config(dir, &updated);
            return Ok((resp, target));
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
pub async fn sign_in(dir: &Path, cfg: &ClientConfig, key: &SigningKey, code: &str) -> Result<Grant> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Enter the 6-digit code from your authenticator app.".into());
    }
    let (resp, target) = exchange(dir, cfg, key, wire::OP_TOTP, code).await?;
    if !resp.ok {
        return Err(explain(&resp));
    }
    Ok(Grant {
        ip: resp.ip.as_deref().and_then(|i| i.parse::<std::net::IpAddr>().ok()).map(|i| i.to_string()).unwrap_or_default(),
        expires: resp.expires.unwrap_or_default(),
        server_addr: target.addr,
        rdp_port: target.rdp_port.or(resp.rdp_port).unwrap_or(3389),
        rdp_cert_sha256: resp.rdp_cert_sha256.filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
    })
}

/// Closes the firewall for this network again.
pub async fn lock(dir: &Path, cfg: &ClientConfig, key: &SigningKey) -> Result<String> {
    let (resp, _) = exchange(dir, cfg, key, wire::OP_REVOKE, "").await?;
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

/// Writes a .rdp file pointing at the exact address the server proved itself at.
pub fn write_rdp_file(dir: &Path, cfg: &ClientConfig, grant: &Grant) -> Result<PathBuf> {
    let mut lines = vec![
        format!("full address:s:{}", grant.rdp_target()),
        "prompt for credentials:i:1".into(),
        "authentication level:i:2".into(),
        "enablecredsspsupport:i:1".into(),
        "redirectclipboard:i:1".into(),
        "redirectprinters:i:0".into(),
        "drivestoredirect:s:".into(),
        "screen mode id:i:2".into(),
    ];
    if let Some(u) = cfg.rdp_username.as_deref().filter(|u| !u.is_empty()) {
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
    if mins <= 0 { "now".into() } else { format!("{mins} min") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_what_worked_then_ipv6_then_ipv4() {
        let (v4, v6): (IpAddr, IpAddr) = ("198.72.98.36".parse().unwrap(), "2607:f748:203:b9::11".parse().unwrap());
        assert_eq!(public_order(vec![v4, v6, v4], None), [v6, v4]);
        assert_eq!(public_order(vec![v6, v4], Some(SocketAddr::new(v4, 443))), [v4, v6]);
        assert_eq!(public_order(vec![v4], Some(SocketAddr::new(v6, 443))), [v4]);
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
            port: 443,
        };
        assert_eq!(set_card(&dir, &c.encode()).unwrap(), wire::fingerprint(&server.verifying_key()));
        assert_eq!(card(&load_config(&dir).unwrap()).unwrap().server_key(), server.verifying_key());
        std::fs::remove_dir_all(dir).ok();
    }
}
