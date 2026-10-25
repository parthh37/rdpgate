//! `<data dir>/config.json`, written by `rdpgate-server init`.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The default sign-in port, here and on the router. Anything but 80 and
/// 443, which web servers, VPNs and other software on the same PC or router
/// expect to have.
pub const DEFAULT_PORT: u16 = 47443;

/// Ports RDP Gate never listens on or forwards.
pub const RESERVED_PORTS: [u16; 2] = [80, 443];

pub fn reserved_port(p: u16) -> bool {
    RESERVED_PORTS.contains(&p)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Optional DNS name, e.g. "rdp.example.com". Only needed for browser
    /// (passkey) sign-in: browsers bind passkeys to a name, never to an IP.
    /// Desktop clients find the server through the encrypted beacon instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// Port the router forwards to `listen` (never 80 or 443).
    #[serde(default = "d_port")]
    pub public_port: u16,
    /// Local addresses to bind, e.g. ["0.0.0.0:47443"]. With `ipv6`, each
    /// "0.0.0.0:port" is also bound as "[::]:port".
    #[serde(default = "d_listen")]
    pub listen: Vec<String>,
    /// Also accept sign-in over IPv6 and publish this network's public IPv6
    /// address in the beacon. Many networks without a reachable IPv4 address
    /// (carrier-grade NAT) can still be reached this way.
    #[serde(default = "d_true")]
    pub ipv6: bool,
    /// Certificate for the browser portal (needed for `web_login`).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Local RDP port the firewall rules open (Windows default 3389).
    #[serde(default = "d_3389")]
    pub rdp_port: u16,
    /// Port clients connect to for RDP: the router's external forwarded port.
    #[serde(default = "d_3389")]
    pub rdp_public_port: u16,
    /// Also open UDP for the signed-in address. UDP has no handshake, so its
    /// source address can be forged; leave this off unless you need the speed.
    #[serde(default)]
    pub allow_udp: bool,
    /// Grant private, loopback and carrier-NAT source addresses. Off by
    /// default: behind a port forward that rewrites source addresses, every
    /// internet host would share one private IP, and a grant for it would
    /// open RDP to all of them. Turn on only for sign-in from your own LAN.
    #[serde(default)]
    pub allow_private_sources: bool,
    /// Random URL prefix for the web portal.
    pub portal_path: String,
    /// Minutes an approval leaves the firewall open for you to start RDP.
    /// While an RDP connection from your IP stays up, the grant stays too.
    #[serde(default = "d_grant")]
    pub grant_minutes: u32,
    /// Hard cap on one grant, connected or not.
    #[serde(default = "d_max")]
    pub max_hours: f64,
    /// Keep the PC from sleeping while any grant is open.
    #[serde(default = "d_true")]
    pub keep_awake: bool,
    /// Allow signing in from a browser with a passkey (needs `public_host`).
    #[serde(default)]
    pub web_login: bool,
    /// Allow signing in from the desktop app (device key + 6-digit code).
    #[serde(default = "d_true")]
    pub desktop_login: bool,
    /// "windows" changes Windows Firewall; "dry-run" only logs (for testing).
    #[serde(default = "d_firewall")]
    pub firewall: String,
    /// Forward the needed ports on the home router automatically (UPnP).
    #[serde(default = "d_true")]
    pub upnp: bool,
    /// Install signed updates automatically (once a day, only while nobody
    /// has access open).
    #[serde(default = "d_true")]
    pub auto_update: bool,
    /// Also take pre-releases (all 0.x releases are pre-releases).
    #[serde(default = "d_true")]
    pub update_prereleases: bool,
    /// Where the encrypted, signed IP beacon is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<BeaconConfig>,

    #[serde(skip)]
    pub data_dir: PathBuf,
}

/// The browser portal's certificate: PEM files you renew yourself (the
/// service picks up renewed files without a restart). There is no automatic
/// Let's Encrypt: its checks need port 80 or 443.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate chain covering `public_host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
}

impl TlsConfig {
    pub fn files(&self) -> Option<(&Path, &Path)> {
        Some((self.cert_file.as_deref()?, self.key_file.as_deref()?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    /// Secret GitHub gist that holds the beacon.
    pub gist_id: String,
    /// GitHub token limited to "Gists: read and write".
    pub token: String,
}

fn d_port() -> u16 {
    DEFAULT_PORT
}
fn d_3389() -> u16 {
    3389
}
fn d_listen() -> Vec<String> {
    vec![format!("0.0.0.0:{DEFAULT_PORT}")]
}
fn d_grant() -> u32 {
    10
}
fn d_max() -> f64 {
    12.0
}
fn d_true() -> bool {
    true
}
fn d_firewall() -> String {
    if cfg!(windows) { "windows".into() } else { "dry-run".into() }
}

pub fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(base).join("RDPGate")
    } else {
        PathBuf::from("/var/lib/rdpgate")
    }
}

/// Device and passkey names: safe to log, display and use in file names.
pub fn valid_name(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.parse::<IpAddr>().is_err()
        && h.contains('.')
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

impl Config {
    pub fn new(host: Option<&str>) -> Self {
        let host = host.map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase());
        Config {
            web_login: false,
            public_host: host,
            public_port: DEFAULT_PORT,
            listen: d_listen(),
            ipv6: true,
            tls: TlsConfig::default(),
            rdp_port: 3389,
            rdp_public_port: 3389,
            allow_udp: false,
            allow_private_sources: false,
            portal_path: format!("/{}/", rdpgate_core::random_token::<18>()),
            grant_minutes: d_grant(),
            max_hours: d_max(),
            keep_awake: true,
            desktop_login: true,
            firewall: d_firewall(),
            upnp: true,
            auto_update: true,
            update_prereleases: true,
            beacon: None,
            data_dir: PathBuf::new(),
        }
    }

    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("config.json")
    }

    pub fn load(data_dir: &Path) -> Result<Self, String> {
        Self::load_noting(data_dir).map(|(c, _)| c)
    }

    /// Like `load`, also returning what was changed to bring a config from
    /// an older version up to date (saved when this process may write it).
    pub fn load_noting(data_dir: &Path) -> Result<(Self, Vec<String>), String> {
        let raw = std::fs::read(Self::path(data_dir))
            .map_err(|e| format!("{}: {e} (did you run \"rdpgate-server init\"?)", Self::path(data_dir).display()))?;
        let mut c: Config = serde_json::from_slice(&raw).map_err(|e| format!("config.json: {e}"))?;
        c.data_dir = data_dir.to_path_buf();
        let notes = c.migrate();
        c.validate().map_err(|e| format!("config.json: {e}"))?;
        if !notes.is_empty() {
            let _ = c.save(data_dir);
        }
        Ok((c, notes))
    }

    /// Moves a config from an older version off ports 80 and 443, and turns
    /// browser sign-in off where it relied on Let's Encrypt. Returns a line
    /// per change.
    pub fn migrate(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        for l in &mut self.listen {
            if let Ok(mut a) = l.parse::<SocketAddr>()
                && reserved_port(a.port())
            {
                a.set_port(DEFAULT_PORT);
                notes.push(format!("sign-in moved from {l} to {a}: RDP Gate no longer uses ports 80 and 443"));
                *l = a.to_string();
            }
        }
        if reserved_port(self.public_port) {
            notes.push(format!(
                "the router now forwards TCP {DEFAULT_PORT} for sign-in instead of {}; if you forwarded it by hand, change it on the router",
                self.public_port
            ));
            self.public_port = DEFAULT_PORT;
        }
        if reserved_port(self.rdp_public_port) {
            let to = if reserved_port(self.rdp_port) { 3389 } else { self.rdp_port };
            notes.push(format!(
                "the router now forwards TCP {to} for Remote Desktop instead of {}; if you forwarded it by hand, change it on the router",
                self.rdp_public_port
            ));
            self.rdp_public_port = to;
        }
        if self.web_login && self.tls.files().is_none() {
            notes.push(
                "browser sign-in is off: its Let's Encrypt certificate needed port 443. Turn it on again with your own \
                 certificate files (rdpgate-server domain-setup)"
                    .into(),
            );
            self.web_login = false;
            self.desktop_login = true;
        }
        notes
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        self.validate()?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        rdpgate_core::keystore::write_private(&Self::path(data_dir), &json).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(h) = &self.public_host
            && !valid_host(h)
        {
            return Err("public_host must be a DNS name like rdp.example.com (passkeys cannot use an IP address)".into());
        }
        if self.web_login && self.public_host.is_none() {
            return Err("web_login needs public_host: browsers only use passkeys with a DNS name".into());
        }
        if self.listen.is_empty() {
            return Err("listen must contain at least one address".into());
        }
        for l in &self.listen {
            let a = l.parse::<SocketAddr>().map_err(|e| format!("listen {l:?}: {e}"))?;
            if reserved_port(a.port()) {
                return Err(format!("listen {l:?}: RDP Gate never uses ports 80 or 443; pick another, e.g. {DEFAULT_PORT}"));
            }
        }
        for (name, p) in [("public_port", self.public_port), ("rdp_public_port", self.rdp_public_port)] {
            if reserved_port(p) {
                return Err(format!("{name} {p}: RDP Gate never uses ports 80 or 443; pick another"));
            }
        }
        if self.web_login && self.tls.files().is_none() {
            return Err("web_login needs tls.cert_file and tls.key_file (a certificate for public_host)".into());
        }
        let p = &self.portal_path;
        if !p.starts_with('/') || !p.ends_with('/') || p.len() < 20 || p[1..p.len() - 1].contains('/') {
            return Err("portal_path must look like /<random 18+ characters>/".into());
        }
        if !(1..=240).contains(&self.grant_minutes) {
            return Err("grant_minutes must be 1-240".into());
        }
        if !(self.max_hours > 0.0 && self.max_hours <= 168.0) {
            return Err("max_hours must be between 0 and 168".into());
        }
        if !self.web_login && !self.desktop_login {
            return Err("enable at least one of web_login, desktop_login".into());
        }
        if self.firewall != "windows" && self.firewall != "dry-run" {
            return Err("firewall must be \"windows\" or \"dry-run\"".into());
        }
        if let Some(b) = &self.beacon
            && (!rdpgate_core::beacon::valid_gist_id(&b.gist_id) || b.token.trim().is_empty())
        {
            return Err("beacon needs a valid gist_id and token (run: rdpgate-server beacon-setup)".into());
        }
        Ok(())
    }

    /// The addresses to listen on, each with whether failing to bind it is
    /// fatal. The IPv6 twins added for `ipv6` aren't: a PC with IPv6 turned
    /// off still serves IPv4.
    pub fn listen_addrs(&self) -> Vec<(SocketAddr, bool)> {
        let configured: Vec<SocketAddr> = self.listen.iter().filter_map(|l| l.parse().ok()).collect();
        let mut out: Vec<(SocketAddr, bool)> = configured.iter().map(|a| (*a, true)).collect();
        if self.ipv6 {
            for a in &configured {
                let twin = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), a.port());
                if a.ip() == IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) && !out.iter().any(|(o, _)| *o == twin) {
                    out.push((twin, false));
                }
            }
        }
        out
    }

    /// The Remote Desktop port a computer signed in from `src` connects to:
    /// the router's forwarded one over IPv4, this PC's own over IPv6 (no
    /// port mapping in between).
    pub fn rdp_port_for(&self, src: IpAddr) -> u16 {
        if src.to_canonical().is_ipv6() { self.rdp_port } else { self.rdp_public_port }
    }

    /// Browser origin, e.g. https://rdp.example.com (only with a host name).
    pub fn public_url(&self) -> Option<String> {
        let h = self.public_host.as_ref()?;
        Some(format!("https://{h}:{}", self.public_port))
    }

    pub fn portal_url(&self, page: &str) -> Option<String> {
        Some(format!("{}{}{}", self.public_url()?, self.portal_path, page))
    }

    pub fn grant_duration(&self) -> Duration {
        Duration::from_secs(self.grant_minutes as u64 * 60)
    }

    pub fn max_duration(&self) -> Duration {
        Duration::from_secs_f64(self.max_hours * 3600.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_reject_bad_hosts() {
        let mut c = Config::new(Some("Home.Example.org."));
        assert_eq!(c.public_host.as_deref(), Some("home.example.org"));
        c.validate().unwrap();
        c.web_login = true;
        assert!(c.validate().is_err(), "web login without a certificate");
        c.tls.cert_file = Some("cert.pem".into());
        c.tls.key_file = Some("key.pem".into());
        c.validate().unwrap();
        assert_eq!(c.public_url().as_deref(), Some("https://home.example.org:47443"));

        let no_host = Config::new(None);
        assert!(!no_host.web_login);
        no_host.validate().unwrap();
        assert!(no_host.public_url().is_none());

        for bad in ["", "1.2.3.4", "localhost", "a/b.com", "x.com:443", "a..b"] {
            let mut c = Config::new(Some("ok.example"));
            c.public_host = Some(bad.into());
            assert!(c.validate().is_err(), "{bad:?} accepted");
        }
        let mut c = Config::new(None);
        c.web_login = true;
        assert!(c.validate().is_err(), "web login without a host name");
        assert!(valid_name("mac-book_1.2") && !valid_name("bad name") && !valid_name(""));
    }

    #[test]
    fn listens_on_ipv6_too_unless_turned_off() {
        let mut c = Config::new(None);
        let addrs = |c: &Config| c.listen_addrs().into_iter().map(|(a, required)| (a.to_string(), required)).collect::<Vec<_>>();
        assert_eq!(addrs(&c), [("0.0.0.0:47443".into(), true), ("[::]:47443".into(), false)]);
        // A config from before IPv6 support turns it on.
        let old: serde_json::Value = serde_json::json!({ "portal_path": c.portal_path });
        assert!(serde_json::from_value::<Config>(old).unwrap().ipv6);
        // Listed by hand: not added twice, and its failure counts.
        c.listen.push("[::]:47443".into());
        assert_eq!(addrs(&c), [("0.0.0.0:47443".into(), true), ("[::]:47443".into(), true)]);
        c.listen = vec!["192.168.1.5:8443".into()];
        assert_eq!(addrs(&c), [("192.168.1.5:8443".into(), true)]);
        c.listen = vec!["0.0.0.0:8443".into()];
        c.ipv6 = false;
        assert_eq!(addrs(&c), [("0.0.0.0:8443".into(), true)]);
    }

    #[test]
    fn never_uses_80_or_443() {
        for port in RESERVED_PORTS {
            let mut c = Config::new(None);
            c.listen = vec![format!("0.0.0.0:{port}")];
            assert!(c.validate().is_err(), "listen on {port} accepted");
            let mut c = Config::new(None);
            c.public_port = port;
            assert!(c.validate().is_err(), "public_port {port} accepted");
            let mut c = Config::new(None);
            c.rdp_public_port = port;
            assert!(c.validate().is_err(), "rdp_public_port {port} accepted");
        }
    }

    #[test]
    fn migrates_old_configs_off_443_and_lets_encrypt() {
        // Written by 1.2: sign-in on 443, browser sign-in with Let's Encrypt.
        let old = serde_json::json!({
            "public_host": "rdp.example.com",
            "public_port": 443,
            "listen": ["0.0.0.0:443", "[::]:443", "192.168.1.5:8443"],
            "tls": { "mode": "acme", "email": "me@example.com" },
            "rdp_public_port": 443,
            "web_login": true,
            "portal_path": format!("/{}/", "a".repeat(24)),
        });
        let mut c: Config = serde_json::from_value(old.clone()).unwrap();
        assert!(c.validate().is_err());
        let notes = c.migrate();
        assert_eq!(notes.len(), 5, "{notes:?}");
        assert_eq!(c.listen, ["0.0.0.0:47443", "[::]:47443", "192.168.1.5:8443"]);
        assert_eq!((c.public_port, c.rdp_public_port), (47443, 3389));
        assert!(!c.web_login && c.desktop_login);
        c.validate().unwrap();
        assert!(c.migrate().is_empty(), "migrating twice changes nothing");

        // Loading it saves the migrated config, once.
        let dir = std::env::temp_dir().join(format!("rdpgate-migrate-{}", rdpgate_core::random_token::<6>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Config::path(&dir), serde_json::to_vec(&old).unwrap()).unwrap();
        let (loaded, notes) = Config::load_noting(&dir).unwrap();
        assert_eq!((notes.len(), loaded.public_port), (5, 47443));
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(Config::path(&dir)).unwrap()).unwrap();
        assert_eq!(saved["listen"][0], "0.0.0.0:47443");
        assert!(saved["tls"].get("mode").is_none(), "{saved}");
        assert!(Config::load_noting(&dir).unwrap().1.is_empty());
        let _ = std::fs::remove_dir_all(&dir);

        // Own certificate files keep browser sign-in on.
        let mut c = Config::new(Some("rdp.example.com"));
        c.web_login = true;
        c.tls.cert_file = Some("cert.pem".into());
        c.tls.key_file = Some("key.pem".into());
        assert!(c.migrate().is_empty());
        assert!(c.web_login);
    }
}
