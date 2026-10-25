//! What an administrator can do on the server, as functions that return data
//! instead of printing. The `rdpgate-server` command line and the RDP Gate
//! Server window both go through these, so they always behave the same.

use crate::config::{BeaconConfig, Config, valid_name};
use crate::identity::Identity;
use crate::log::local;
use crate::state::{Device, EnrollToken, MAX_FAILED_CODES, Store, TotpState, now, token_hash};
use rdpgate_core::{totp, wire};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub fingerprint: String,
    pub added: i64,
    pub last_auth: Option<i64>,
    pub locked: bool,
    pub auto: bool,
    /// Remembered (auto mode) since then.
    pub remembered: Option<i64>,
}

pub fn devices(data: &Path) -> Result<Vec<DeviceInfo>, String> {
    let st = Store::new(data).load()?;
    Ok(st
        .devices
        .iter()
        .map(|d| DeviceInfo {
            name: d.name.clone(),
            fingerprint: wire::parse_public_key(&d.public_key).map(|k| wire::fingerprint(&k)).unwrap_or_default(),
            added: d.added,
            last_auth: d.last_auth,
            locked: d.failed_codes >= MAX_FAILED_CODES,
            auto: d.auto,
            remembered: d.trust.as_ref().map(|t| t.since),
        })
        .collect())
}

/// Enrolls a computer. `key_text` may be the bare key or the whole
/// `rdpgate-server device-add …` line its app shows. Returns its fingerprint.
pub fn add_device(data: &Path, name: &str, key_text: &str) -> Result<String, String> {
    let name = name.trim();
    if !valid_name(name) {
        return Err("Computer name: 1-32 letters, digits, dots, dashes or underscores.".into());
    }
    let Some(token) = key_text.split_whitespace().find(|t| t.starts_with("rdpgate-ed25519:")) else {
        return Err("That isn't a computer's key. On the computer you'll connect FROM (not this server), open the RDP Gate app \
                    and click Copy command (or This computer and server > Copy enrollment command), then paste the whole line. \
                    The key is one long word starting with rdpgate-ed25519:"
            .into());
    };
    let key = wire::parse_public_key(token)?;
    let encoded = wire::encode_public_key(&key);
    Store::new(data).update(|st| {
        if st.devices.iter().any(|d| d.name == name) {
            return Err(format!("a computer named {name:?} is already enrolled"));
        }
        if let Some(d) = st.devices.iter().find(|d| d.public_key == encoded) {
            return Err(format!("that key is already enrolled as {:?}", d.name));
        }
        st.devices.push(Device {
            name: name.into(),
            public_key: encoded.clone(),
            added: now(),
            last_auth: None,
            failed_codes: 0,
            auto: false,
            trust: None,
        });
        Ok(())
    })?;
    Ok(wire::fingerprint(&key))
}

pub fn remove_device(data: &Path, name: &str) -> Result<(), String> {
    Store::new(data).update(|st| {
        let before = st.devices.len();
        st.devices.retain(|d| d.name != name);
        if st.devices.len() == before {
            return Err(format!("no computer named {name:?}"));
        }
        Ok(())
    })
}

pub fn unlock_device(data: &Path, name: &str) -> Result<(), String> {
    Store::new(data).update(|st| {
        let d = st.devices.iter_mut().find(|d| d.name == name).ok_or(format!("no computer named {name:?}"))?;
        d.failed_codes = 0;
        Ok(())
    })
}

/// Turns auto mode on or off for a computer. Takes effect on the running
/// service immediately: turning it off forgets the computer, so it stops
/// following its address and signs in with passphrase and code again.
pub fn set_device_auto(data: &Path, name: &str, on: bool) -> Result<(), String> {
    Store::new(data).update(|st| {
        let d = st.devices.iter_mut().find(|d| d.name == name).ok_or(format!("no computer named {name:?}"))?;
        d.auto = on;
        if !on {
            d.trust = None;
        }
        Ok(())
    })
}

/// The server card (`rdpgate-card:…`) to paste into the app on each computer.
pub fn card(data: &Path) -> Result<String, String> {
    let cfg = Config::load(data)?;
    Ok(Identity::load_or_create(data)?.card(&cfg).encode())
}

/// A new authenticator secret, not saved until a code from it is confirmed.
pub struct TotpEnrollment {
    secret: Vec<u8>,
    /// `otpauth://…`, for the QR code.
    pub uri: String,
    /// The secret in base32, in groups of four, for typing in by hand.
    pub key: String,
}

pub fn totp_begin(data: &Path, replace: bool) -> Result<TotpEnrollment, String> {
    let st = Store::new(data).load()?;
    if st.totp.is_some() && !replace {
        return Err("6-digit codes are already set up (replace them to use a new phone; old codes stop working)".into());
    }
    let secret = totp::new_secret();
    let account = format!("{}@{}", st.user_name, Identity::load_or_create(data)?.fingerprint().get(..9).unwrap_or("server"));
    let uri = totp::uri("RDP Gate", &account, &secret);
    let b32 = totp::base32(&secret);
    let key = b32.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ");
    Ok(TotpEnrollment { secret, uri, key })
}

/// Saves the secret if `code` is the one the authenticator app shows now.
/// Returns false for a wrong code (nothing is saved).
pub fn totp_confirm(data: &Path, e: &TotpEnrollment, code: &str) -> Result<bool, String> {
    let Some(step) = totp::validate(&e.secret, code.trim(), now() as u64, 0) else { return Ok(false) };
    let secret = e.secret.clone();
    Store::new(data).update(|st| {
        st.totp = Some(TotpState { secret, last_step: step });
        Ok(())
    })?;
    Ok(true)
}

/// Saves a GitHub token (and a new or given gist) and publishes the first
/// beacon. Returns the gist id. Blocking: it talks to GitHub.
pub fn beacon_setup(data: &Path, token: &str, gist: Option<&str>) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("no token entered".into());
    }
    let mut cfg = Config::load(data)?;
    let gist_id = match gist.map(str::trim).filter(|g| !g.is_empty()) {
        Some(g) if rdpgate_core::beacon::valid_gist_id(g) => g.to_string(),
        Some(_) => return Err("that doesn't look like a gist id".into()),
        None => rdpgate_core::beacon::create_gist(token)?,
    };
    cfg.beacon = Some(BeaconConfig { gist_id: gist_id.clone(), token: token.into() });
    let id = Identity::load_or_create(data)?;
    let ips = crate::beacon::discover_public_ips(cfg.ipv6)?;
    crate::beacon::publish(&cfg, &id, ips, crate::beacon::lan_location(&cfg))?;
    cfg.save(data)?;
    Ok(gist_id)
}

/// Turns sign-in from this PC's own network on or off. Takes effect when
/// the service restarts. Returns this PC's address on that network.
pub fn set_lan(data: &Path, on: bool) -> Result<Option<std::net::IpAddr>, String> {
    let mut cfg = Config::load(data)?;
    cfg.allow_private_sources = on;
    cfg.save(data)?;
    Ok(crate::router::lan_ip())
}

pub fn set_auto_update(data: &Path, on: bool) -> Result<(), String> {
    let mut cfg = Config::load(data)?;
    cfg.auto_update = on;
    cfg.save(data)
}

/// Turns sign-in over IPv6 on or off. Takes effect when the service restarts.
pub fn set_ipv6(data: &Path, on: bool) -> Result<(), String> {
    let mut cfg = Config::load(data)?;
    cfg.ipv6 = on;
    cfg.save(data)
}

/// How long a sign-in stays open for Remote Desktop to connect, and the most
/// one sign-in can last even while connected. Takes effect when the service
/// restarts.
pub fn set_time_limits(data: &Path, grant_minutes: u32, max_hours: f64) -> Result<(), String> {
    let mut cfg = Config::load(data)?;
    if max_hours * 60.0 < grant_minutes as f64 {
        return Err("The longest session can't be shorter than the time to connect.".into());
    }
    cfg.grant_minutes = grant_minutes;
    cfg.max_hours = max_hours;
    cfg.save(data)
}

// ---- browser sign-in (domain setup) -------------------------------------

/// The domain name typed in, cleaned up and checked.
pub fn clean_host(host: &str) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if !crate::config::valid_host(&host) {
        return Err(format!("{host:?} isn't a domain name like rdp.example.com"));
    }
    Ok(host)
}

/// One DNS record to create for browser sign-in.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    /// "A" (IPv4) or "AAAA" (IPv6).
    pub kind: &'static str,
    /// What most providers want in Name: the part before the domain.
    pub name: String,
    pub value: String,
}

/// The records `host` needs so browsers reach this PC over every address it
/// has. Blocking: it asks the internet for this network's addresses.
pub fn dns_records(data: &Path, host: &str) -> Result<(Vec<DnsRecord>, crate::beacon::PublicIps), String> {
    let cfg = Config::load(data)?;
    let ips = crate::beacon::discover_public_ips(cfg.ipv6)?;
    let name = host.split('.').next().unwrap_or(host).to_string();
    let mut records = Vec::new();
    if let Some(v4) = ips.v4 {
        records.push(DnsRecord { kind: "A", name: name.clone(), value: v4.to_string() });
    }
    if let Some(v6) = ips.v6 {
        records.push(DnsRecord { kind: "AAAA", name, value: v6.to_string() });
    }
    Ok((records, ips))
}

/// What `host` resolves to now (blocking).
pub fn resolve_host(host: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let mut addrs: Vec<std::net::IpAddr> = (host, 0).to_socket_addrs().map(|i| i.map(|a| a.ip()).collect()).unwrap_or_default();
    addrs.sort();
    addrs.dedup();
    addrs
}

/// One thing a DNS check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// The record points at this PC.
    Good,
    /// Works without it, but worth doing.
    Hint,
    /// Browsers would fail.
    Wrong,
}

/// Compares what `host` resolves to with this network's addresses. Returns
/// whether browsers will reach this PC, and a line per finding (good first).
pub fn dns_verdict(host: &str, public: &crate::beacon::PublicIps, resolved: &[std::net::IpAddr]) -> (bool, Vec<(Finding, String)>) {
    use std::net::IpAddr;
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = resolved.iter().partition(|a| a.is_ipv4());
    let list = |a: &[IpAddr]| a.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ");
    let mut lines = Vec::new();
    if resolved.is_empty() {
        lines.push((Finding::Wrong, format!("{host} doesn't resolve yet. New records can take a few minutes to appear.")));
        return (false, lines);
    }
    // A browser may use any address the name has, so each one must be this PC.
    let mut every_ok = true;
    let mut check = |kind: &str, family: &str, ours: Option<IpAddr>, seen: &[IpAddr]| match (ours, seen.is_empty()) {
        (Some(ip), false) if seen == [ip] => lines.push((Finding::Good, format!("{kind} record: {host} points at {ip}."))),
        (Some(ip), false) => {
            every_ok = false;
            lines.push((Finding::Wrong, format!("{kind} record: {host} points at {}, not {ip}. If that's a Cloudflare address, switch the record to \"DNS only\".", list(seen))));
        }
        (Some(ip), true) => lines.push((Finding::Hint, format!("No {kind} record yet: add one for {ip} so {family} visitors reach this PC too."))),
        (None, false) => {
            every_ok = false;
            lines.push((Finding::Wrong, format!("{host} has a {kind} record ({}), but this PC has no public {family} address: delete it, or browsers may try it and fail.", list(seen))));
        }
        (None, true) => {}
    };
    check("A", "IPv4", public.v4.map(IpAddr::V4), &v4);
    check("AAAA", "IPv6", public.v6.map(IpAddr::V6), &v6);
    lines.sort_by_key(|(f, _)| *f);
    (every_ok, lines)
}

/// Turns browser sign-in on for `host`, with the certificate in `cert` and
/// its private key in `key` (PEM files). Takes effect when the service
/// restarts. Returns the sign-in page's address.
pub fn domain_on(data: &Path, host: &str, cert: &str, key: &str) -> Result<String, String> {
    let host = clean_host(host)?;
    let (cert, key) = (cert.trim().trim_matches('"'), key.trim().trim_matches('"'));
    if cert.is_empty() || key.is_empty() {
        return Err("choose the certificate file and its private key file".into());
    }
    let (cert, key) = (std::path::absolute(cert).map_err(|e| e.to_string())?, std::path::absolute(key).map_err(|e| e.to_string())?);
    crate::cert::read(&cert, &key, Some(&host))?;
    let mut cfg = Config::load(data)?;
    cfg.public_host = Some(host);
    cfg.web_login = true;
    cfg.tls.cert_file = Some(cert);
    cfg.tls.key_file = Some(key);
    cfg.save(data)?;
    cfg.portal_url("").ok_or_else(|| "no sign-in address".into())
}

/// Turns browser sign-in off. Passkeys are kept for if it's turned on again.
pub fn domain_off(data: &Path) -> Result<(), String> {
    let mut cfg = Config::load(data)?;
    cfg.web_login = false;
    cfg.public_host = None;
    cfg.save(data)
}

/// A one-time link that adds a passkey, valid for `minutes`. Returns the
/// link and when it expires.
pub fn passkey_link(data: &Path, minutes: u32) -> Result<(String, i64), String> {
    if !(1..=60).contains(&minutes) {
        return Err("--minutes must be 1-60".into());
    }
    let cfg = Config::load(data)?;
    let Some(url) = cfg.portal_url("enroll").filter(|_| cfg.web_login) else {
        return Err("browser sign-in needs a domain name: run the guided domain setup first".into());
    };
    let token = rdpgate_core::random_token::<24>();
    let expires = now() + minutes as i64 * 60;
    Store::new(data).update(|st| {
        st.enroll_tokens.retain(|t| t.expires > now());
        st.enroll_tokens.push(EnrollToken { hash: token_hash(&token), expires });
        Ok(())
    })?;
    Ok((format!("{url}#{token}"), expires))
}

pub fn remove_passkey(data: &Path, name: &str) -> Result<(), String> {
    Store::new(data).update(|st| {
        let before = st.passkeys.len();
        st.passkeys.retain(|p| p.name != name);
        if st.passkeys.len() == before {
            return Err(format!("no passkey named {name:?}"));
        }
        Ok(())
    })
}

#[derive(Debug, Clone, Default)]
pub struct GrantInfo {
    pub ip: String,
    pub who: String,
    /// The time to start Remote Desktop runs out here.
    pub expires: i64,
    /// The grant ends here even while connected.
    pub hard_expires: i64,
    /// Last time an RDP connection from this address was seen.
    pub last_connected: Option<i64>,
}

impl GrantInfo {
    /// When the grant closes if nothing changes: a live connection keeps it
    /// open (checked every few seconds) until `hard_expires`.
    pub fn closes(&self, t: i64) -> i64 {
        let held = self.last_connected.map_or(0, |c| c + crate::grants::GRACE.as_secs() as i64);
        self.expires.max(held).min(self.hard_expires).max(t)
    }

    /// Remote Desktop is connected through this grant right now.
    pub fn connected(&self, t: i64) -> bool {
        self.last_connected.is_some_and(|c| t - c < 30)
    }
}

#[derive(Debug, Clone, Default)]
pub struct BeaconInfo {
    pub gist: String,
    pub ip: Option<String>,
    pub ip6: Option<String>,
    pub published: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PasskeyInfo {
    pub name: String,
    pub added: i64,
    pub last_used: Option<i64>,
}

/// Everything `status` shows, read from the files the service keeps.
#[derive(Debug, Clone, Default)]
pub struct Overview {
    pub version: &'static str,
    pub auto_update: bool,
    pub server_fingerprint: String,
    pub protection_pending: bool,
    pub lan: bool,
    pub lan_ip: Option<String>,
    pub beacon: Option<BeaconInfo>,
    /// One line about port forwarding on the router.
    pub router: String,
    pub behind_nat: bool,
    pub browser_url: Option<String>,
    /// The domain for browser sign-in, and its certificate files, as set up.
    pub public_host: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ipv6: bool,
    pub totp: bool,
    pub passkeys: Vec<PasskeyInfo>,
    pub devices: usize,
    pub warnings: Vec<String>,
    pub grants: Vec<GrantInfo>,
    pub grant_minutes: u32,
    pub max_hours: f64,
    pub rdp_port: u16,
    pub rdp_public_port: u16,
    pub public_port: u16,
    /// The port this PC listens on for sign-in (what IPv6 reaches).
    pub listen_port: u16,
}

fn read_json(data: &Path, file: &str) -> serde_json::Value {
    std::fs::read(data.join(file)).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or_default()
}

pub fn overview(data: &Path) -> Result<Overview, String> {
    let cfg = Config::load(data)?;
    let st = Store::new(data).load()?;
    let id = Identity::load_or_create(data)?;
    let beacon = cfg.beacon.as_ref().map(|b| {
        let s = read_json(data, "beacon.json");
        BeaconInfo {
            gist: b.gist_id.clone(),
            ip: s["ip"].as_str().map(str::to_string),
            ip6: s["ip6"].as_str().map(str::to_string),
            published: s["published"].as_i64(),
            error: s["error"].as_str().map(str::to_string),
        }
    });
    let r = read_json(data, "router.json");
    let router = match (cfg.upnp, r["found"].as_bool()) {
        (false, _) => "automatic forwarding off: forward the ports by hand".to_string(),
        (true, None) => "not checked yet".to_string(),
        (true, Some(false)) => "no UPnP router answered: forward the ports by hand".to_string(),
        (true, Some(true)) => {
            let n = r["mapped"].as_array().map_or(0, |a| a.len());
            let refused = r["failed"].as_array().is_some_and(|a| !a.is_empty());
            format!("{n} port forward(s) in place{}", if refused { ", some refused: forward those by hand" } else { "" })
        }
    };
    let grants = match read_json(data, "grants.json") {
        serde_json::Value::Array(a) => a
            .iter()
            .map(|g| GrantInfo {
                ip: g["ip"].as_str().unwrap_or("?").into(),
                who: g["who"].as_str().unwrap_or("?").into(),
                expires: g["expires"].as_i64().unwrap_or(0),
                hard_expires: g["hard_expires"].as_i64().unwrap_or(0),
                last_connected: g["last_connected"].as_i64(),
            })
            .collect(),
        _ => vec![],
    };
    let warnings = match read_json(data, "warnings.json") {
        serde_json::Value::Array(a) => a.iter().filter_map(|w| w.as_str().map(str::to_string)).collect(),
        _ => vec![],
    };
    Ok(Overview {
        version: crate::updater::VERSION,
        auto_update: cfg.auto_update,
        server_fingerprint: id.fingerprint(),
        protection_pending: st.protection_pending,
        lan: cfg.allow_private_sources,
        lan_ip: crate::router::lan_ip().map(|i| i.to_string()),
        beacon,
        router,
        behind_nat: r["behind_nat"].as_bool() == Some(true),
        browser_url: cfg.portal_url("").filter(|_| cfg.web_login),
        public_host: cfg.public_host.clone(),
        cert_file: cfg.tls.cert_file.as_ref().map(|p| p.display().to_string()),
        key_file: cfg.tls.key_file.as_ref().map(|p| p.display().to_string()),
        ipv6: cfg.ipv6,
        totp: st.totp.is_some(),
        passkeys: st.passkeys.iter().map(|p| PasskeyInfo { name: p.name.clone(), added: p.added, last_used: p.last_used }).collect(),
        devices: st.devices.len(),
        warnings,
        grants,
        grant_minutes: cfg.grant_minutes,
        max_hours: cfg.max_hours,
        rdp_port: cfg.rdp_port,
        rdp_public_port: cfg.rdp_public_port,
        public_port: cfg.public_port,
        listen_port: crate::router::listen_port(&cfg),
    })
}

/// Closes Remote Desktop to everyone who hasn't signed in, now. Returns the
/// firewall rules it disabled.
pub fn protect_now(data: &Path) -> Result<Vec<String>, String> {
    let cfg = Config::load(data)?;
    let fw = crate::firewall::for_config(&cfg);
    crate::protect::apply(&*fw, &Store::new(data))
}

/// The last `lines` lines of the service log, oldest first.
pub fn log_tail(data: &Path, lines: usize) -> String {
    let text = std::fs::read(data.join("logs").join("rdpgate.log")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// "2026-10-23 21:07", or "never".
pub fn when(t: Option<i64>) -> String {
    t.map(local).unwrap_or_else(|| "never".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::PublicIps;

    fn ips(v4: Option<&str>, v6: Option<&str>) -> PublicIps {
        PublicIps { v4: v4.map(|a| a.parse().unwrap()), v6: v6.map(|a| a.parse().unwrap()) }
    }

    fn resolved(list: &[&str]) -> Vec<std::net::IpAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn dns_is_right_when_every_address_is_this_pc() {
        let both = ips(Some("198.72.98.36"), Some("2607:f748:203:b9::11"));
        let (ok, lines) = dns_verdict("rdp.example.com", &both, &resolved(&["198.72.98.36", "2607:f748:203:b9::11"]));
        assert!(ok);
        assert!(lines.iter().all(|(f, _)| *f == Finding::Good) && lines.len() == 2);
        // An AAAA record can come later: IPv4 alone already works.
        let (ok, lines) = dns_verdict("rdp.example.com", &both, &resolved(&["198.72.98.36"]));
        assert!(ok && lines.iter().any(|(f, l)| *f == Finding::Hint && l.contains("No AAAA record yet")));
        // IPv6 only (carrier-grade NAT for IPv4, say).
        let (ok, _) = dns_verdict("rdp.example.com", &ips(None, Some("2607:f748::11")), &resolved(&["2607:f748::11"]));
        assert!(ok);
    }

    #[test]
    fn dns_is_wrong_when_any_address_is_elsewhere() {
        let both = ips(Some("198.72.98.36"), Some("2607:f748:203:b9::11"));
        // The case from the field: the name points at someone else's IPv6.
        let (ok, lines) = dns_verdict("rdp.example.com", &both, &resolved(&["198.72.98.36", "2607:f748:203:b9:b::11"]));
        assert!(!ok);
        assert_eq!(lines[0].0, Finding::Good, "good findings come first");
        assert!(lines.iter().any(|(f, l)| *f == Finding::Wrong && l.contains("AAAA") && l.contains("2607:f748:203:b9:b::11")));
        // A stray AAAA record when this PC has no IPv6.
        let (ok, _) = dns_verdict("rdp.example.com", &ips(Some("198.72.98.36"), None), &resolved(&["198.72.98.36", "2001:4860::1"]));
        assert!(!ok);
        // Not created yet.
        assert!(!dns_verdict("rdp.example.com", &both, &[]).0);
        assert!(clean_host(" RDP.Example.com. ").unwrap() == "rdp.example.com" && clean_host("1.2.3.4").is_err());
    }
}
