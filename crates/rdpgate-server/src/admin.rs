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
    let token = key_text.split_whitespace().find(|t| t.starts_with("rdpgate-ed25519:")).unwrap_or(key_text.trim());
    let key = wire::parse_public_key(token)?;
    let encoded = wire::encode_public_key(&key);
    Store::new(data).update(|st| {
        if st.devices.iter().any(|d| d.name == name) {
            return Err(format!("a computer named {name:?} is already enrolled"));
        }
        if let Some(d) = st.devices.iter().find(|d| d.public_key == encoded) {
            return Err(format!("that key is already enrolled as {:?}", d.name));
        }
        st.devices.push(Device { name: name.into(), public_key: encoded.clone(), added: now(), last_auth: None, failed_codes: 0 });
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
    let ip = crate::beacon::discover_public_ip()?;
    crate::beacon::publish(&cfg, &id, ip, crate::beacon::lan_location(&cfg))?;
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
    pub expires: i64,
}

#[derive(Debug, Clone, Default)]
pub struct BeaconInfo {
    pub gist: String,
    pub ip: Option<String>,
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
    pub totp: bool,
    pub passkeys: Vec<PasskeyInfo>,
    pub devices: usize,
    pub warnings: Vec<String>,
    pub grants: Vec<GrantInfo>,
    pub rdp_port: u16,
    pub rdp_public_port: u16,
    pub public_port: u16,
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
        totp: st.totp.is_some(),
        passkeys: st.passkeys.iter().map(|p| PasskeyInfo { name: p.name.clone(), added: p.added, last_used: p.last_used }).collect(),
        devices: st.devices.len(),
        warnings,
        grants,
        rdp_port: cfg.rdp_port,
        rdp_public_port: cfg.rdp_public_port,
        public_port: cfg.public_port,
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
