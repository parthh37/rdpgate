//! `<data dir>/config.json`, written by `rdpgate-server init`.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Optional DNS name, e.g. "rdp.example.com". Only needed for browser
    /// (passkey) sign-in: browsers bind passkeys to a name, never to an IP.
    /// Desktop clients find the server through the encrypted beacon instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// Port the router forwards to `listen` (normally 443).
    #[serde(default = "d_443")]
    pub public_port: u16,
    /// Local addresses to bind, e.g. ["0.0.0.0:443"] or add "[::]:443" for IPv6.
    #[serde(default = "d_listen")]
    pub listen: Vec<String>,
    /// Certificate for the browser portal (only used with `public_host`).
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// "acme" (automatic Let's Encrypt) or "files".
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Use the Let's Encrypt staging CA (for testing; browsers won't trust it).
    #[serde(default)]
    pub staging: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig { mode: "acme".into(), email: None, staging: false, cert_file: None, key_file: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    /// Secret GitHub gist that holds the beacon.
    pub gist_id: String,
    /// GitHub token limited to "Gists: read and write".
    pub token: String,
}

fn d_443() -> u16 {
    443
}
fn d_3389() -> u16 {
    3389
}
fn d_listen() -> Vec<String> {
    vec!["0.0.0.0:443".into()]
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
            web_login: host.is_some(),
            public_host: host,
            public_port: 443,
            listen: d_listen(),
            tls: TlsConfig::default(),
            rdp_port: 3389,
            rdp_public_port: 3389,
            allow_udp: false,
            allow_private_sources: false,
            portal_path: format!("/{}/", rdpgate_core::random_token::<18>()),
            grant_minutes: d_grant(),
            max_hours: d_max(),
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
        let raw = std::fs::read(Self::path(data_dir))
            .map_err(|e| format!("{}: {e} (did you run \"rdpgate-server init\"?)", Self::path(data_dir).display()))?;
        let mut c: Config = serde_json::from_slice(&raw).map_err(|e| format!("config.json: {e}"))?;
        c.data_dir = data_dir.to_path_buf();
        c.validate().map_err(|e| format!("config.json: {e}"))?;
        Ok(c)
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
            l.parse::<SocketAddr>().map_err(|e| format!("listen {l:?}: {e}"))?;
        }
        match self.tls.mode.as_str() {
            "acme" => {}
            "files" if self.tls.cert_file.is_some() && self.tls.key_file.is_some() => {}
            "files" => return Err("tls mode \"files\" needs cert_file and key_file".into()),
            m => return Err(format!("tls.mode {m:?} must be \"acme\" or \"files\"")),
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

    /// Browser origin, e.g. https://rdp.example.com (only with a host name).
    pub fn public_url(&self) -> Option<String> {
        let h = self.public_host.as_ref()?;
        Some(if self.public_port == 443 { format!("https://{h}") } else { format!("https://{h}:{}", self.public_port) })
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
        let c = Config::new(Some("Home.Example.org."));
        assert_eq!(c.public_host.as_deref(), Some("home.example.org"));
        assert!(c.web_login);
        c.validate().unwrap();

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
}
