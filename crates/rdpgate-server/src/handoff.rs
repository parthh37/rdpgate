//! Carries open access across a planned restart (an update, or a setting
//! that needs one), so Remote Desktop sessions that came through RDP Gate
//! stay connected and signed-in computers don't have to sign in again.
//!
//! The stopping service leaves its firewall rules in place and writes the
//! grants it tracked to `handoff.json` in the data folder (SYSTEM and
//! Administrators only). The next start reads the file and deletes it at
//! once, so it is used at most once, and adopts the grants only if:
//! - the file is fresh (written moments ago, see [`MAX_AGE`]), so a stop
//!   that turns into a long outage, a crash or a reboot still closes
//!   everything, as before;
//! - the firewall settings a rule depends on (RDP port, UDP, firewall mode)
//!   are unchanged, otherwise the old rules no longer fit and are removed;
//! - the grant's own firewall rule still exists. Adopting never creates a
//!   rule, so the file can only keep open what was open already.
//!
//! Anything else (a plain stop, a shutdown, a failure) closes every grant,
//! and every start removes the rules nobody handed over.

use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE: &str = "handoff.json";
/// Longest gap, in seconds, between the old run stopping and the new one
/// starting. The service manager restarts the service within 5 to 30 s.
pub const MAX_AGE: i64 = 90;
const VERSION: u32 = 1;

/// One open grant, as the next run needs it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeptGrant {
    pub ip: IpAddr,
    pub who: String,
    pub created: i64,
    pub expires: i64,
    pub hard_expires: i64,
    pub last_connected: Option<i64>,
    pub revoke_token: String,
}

/// One auto session (a computer whose access follows its address).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeptAuto {
    pub who: String,
    pub created: i64,
    pub hard_expires: i64,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Handoff {
    pub v: u32,
    /// System clock (not the corrected one: the next run may not have
    /// corrected its clock yet) when this was written.
    pub written: i64,
    /// Version of RDP Gate that wrote it.
    pub from: String,
    pub firewall: String,
    pub rdp_port: u16,
    pub allow_udp: bool,
    pub grants: Vec<KeptGrant>,
    pub autos: Vec<KeptAuto>,
}

fn system_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

impl Handoff {
    pub fn new(cfg: &Config, grants: Vec<KeptGrant>, autos: Vec<KeptAuto>) -> Self {
        Handoff {
            v: VERSION,
            written: system_now(),
            from: crate::updater::VERSION.to_string(),
            firewall: cfg.firewall.clone(),
            rdp_port: cfg.rdp_port,
            allow_udp: cfg.allow_udp,
            grants,
            autos,
        }
    }

    /// The addresses whose firewall rules the next run should leave alone.
    pub fn ips(&self) -> HashSet<IpAddr> {
        self.grants.iter().map(|g| g.ip).collect()
    }

    /// Why the rules of this hand-over don't fit `cfg`, if they don't.
    pub fn misfit(&self, cfg: &Config) -> Option<&'static str> {
        if self.firewall != cfg.firewall {
            Some("the firewall mode changed")
        } else if self.rdp_port != cfg.rdp_port {
            Some("the Remote Desktop port changed")
        } else if self.allow_udp != cfg.allow_udp {
            Some("the UDP setting changed")
        } else {
            None
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        rdpgate_core::keystore::write_private(&path(dir), &json).map_err(|e| format!("write {FILE}: {e}"))
    }
}

/// Reads and deletes the hand-over left by the previous run. `Ok(None)`:
/// there was none. `Err`: there was one, but it can't be used (too old,
/// unreadable); the message says why, for the log.
pub fn take(dir: &Path) -> Result<Option<Handoff>, String> {
    let p = path(dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            let _ = std::fs::remove_file(&p);
            return Err(format!("could not read {FILE}: {e}"));
        }
    };
    // Used once, whatever happens next.
    if let Err(e) = std::fs::remove_file(&p) {
        return Err(format!("could not remove {FILE}, so it isn't used: {e}"));
    }
    let h: Handoff = serde_json::from_slice(&bytes).map_err(|_| format!("{FILE} is damaged"))?;
    if h.v != VERSION {
        return Err(format!("{FILE} is from an unknown version"));
    }
    let age = system_now() - h.written;
    if !(-5..=MAX_AGE).contains(&age) {
        return Err(format!("the previous run stopped {age} s ago, too long to keep its access"));
    }
    Ok(Some(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("rdpgate-handoff-{}", rdpgate_core::random_token::<6>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample(cfg: &Config) -> Handoff {
        let g = KeptGrant {
            ip: "81.2.69.160".parse().unwrap(),
            who: "device mac".into(),
            created: 1,
            expires: 2,
            hard_expires: 3,
            last_connected: Some(2),
            revoke_token: "t".into(),
        };
        Handoff::new(cfg, vec![g], vec![])
    }

    #[test]
    fn a_fresh_handoff_is_used_once() {
        let (d, cfg) = (dir(), Config::new(None));
        assert_eq!(take(&d).unwrap(), None);
        let h = sample(&cfg);
        h.save(&d).unwrap();
        assert_eq!(take(&d).unwrap(), Some(h));
        assert_eq!(take(&d).unwrap(), None, "deleted once read");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_stale_or_damaged_handoff_is_refused_and_removed() {
        let (d, cfg) = (dir(), Config::new(None));
        let mut h = sample(&cfg);
        h.written -= MAX_AGE + 1;
        h.save(&d).unwrap();
        assert!(take(&d).is_err());
        assert!(!path(&d).exists());

        std::fs::write(path(&d), b"{ nope").unwrap();
        assert!(take(&d).is_err());
        assert!(!path(&d).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn changed_firewall_settings_make_it_misfit() {
        let mut cfg = Config::new(None);
        let h = sample(&cfg);
        assert_eq!(h.misfit(&cfg), None);
        cfg.rdp_port += 1;
        assert!(h.misfit(&cfg).is_some());
        cfg.rdp_port -= 1;
        cfg.allow_udp = !cfg.allow_udp;
        assert!(h.misfit(&cfg).is_some());
    }
}
