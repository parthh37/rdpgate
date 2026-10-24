//! Time-limited firewall openings, one per signed-in source address.
//!
//! A grant opens the RDP port for `grant_minutes` so you can start a session.
//! While an RDP connection from that address is established the grant is kept
//! alive (plus a short grace period, so a quick reconnect works), but never
//! beyond `max_hours`. Grants live in memory only: restarting the service
//! closes everything (fail closed), and rules that exist without a grant are
//! found and removed every few minutes. While any grant is open the PC is
//! kept awake, so it can't fall asleep under a session.

use crate::firewall::Firewall;
use crate::power::Power;
use crate::state::now;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

/// More simultaneous grants than this almost certainly means something is wrong.
const MAX_GRANTS: usize = 32;
/// How long a grant survives after its last RDP connection drops.
pub const GRACE: Duration = Duration::from_secs(120);
/// Ticks (10 s each) between full reconciliations against the firewall.
const RECONCILE_EVERY: u32 = 30;
/// How long after signing in the same computer can open its address in the
/// other IP family (a dual-stack computer has one of each).
const LINK_WINDOW: i64 = 60;

struct Inner {
    grants: HashMap<IpAddr, Grant>,
    /// Revokes that failed; retried on every tick until they succeed.
    closing: HashSet<IpAddr>,
}

pub struct Grants {
    fw: Arc<dyn Firewall>,
    inner: Mutex<Inner>,
    /// Seconds to start Remote Desktop after signing in, and the most one
    /// grant can last. Can change while running, see [`Grants::set_limits`].
    grant: AtomicU64,
    max: AtomicU64,
    allow_private: bool,
    status_file: Option<PathBuf>,
    power: Option<Arc<dyn Power>>,
    /// Whether the power request is currently held.
    awake: AtomicBool,
    shutting_down: AtomicBool,
    ticks: AtomicU32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Grant {
    pub ip: IpAddr,
    /// "device <name>" or "passkey <name>"
    pub who: String,
    pub created: i64,
    /// Unix seconds; the grant lapses here unless RDP is connected.
    pub expires: i64,
    /// Unix seconds; the grant ends here no matter what.
    pub hard_expires: i64,
    pub last_connected: Option<i64>,
    /// Closes the grant from the web page. Grants opened together (IPv6 and
    /// IPv4 of one computer) share it, and close together.
    #[serde(skip)]
    pub revoke_token: String,
    /// One-time token (and its expiry) that opens the signed-in computer's
    /// address in the other IP family, see [`Grants::link`].
    #[serde(skip)]
    pub link: Option<(String, i64)>,
}

/// True for addresses that identify one internet host. Private, loopback,
/// link-local, carrier-NAT and similar ranges can stand for many machines
/// (or, behind a source-rewriting port forward, for the whole internet).
pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 carrier NAT
                || o[0] == 0
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("firewall task: {e}"))?
}

impl Grants {
    pub fn new(fw: Arc<dyn Firewall>, grant: Duration, max: Duration, allow_private: bool, status_file: Option<PathBuf>) -> Self {
        Grants {
            fw,
            inner: Mutex::new(Inner { grants: HashMap::new(), closing: HashSet::new() }),
            grant: AtomicU64::new(grant.as_secs()),
            max: AtomicU64::new(max.as_secs()),
            allow_private,
            status_file,
            power: None,
            awake: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            ticks: AtomicU32::new(0),
        }
    }

    /// Keeps the PC awake through `power` while any grant is open.
    pub fn with_power(mut self, power: Option<Arc<dyn Power>>) -> Self {
        self.power = power;
        self
    }

    /// New time limits from the settings. Open grants keep their time to
    /// connect, but the longest-session cap moves with the setting, so a
    /// session already running can be given longer (or less).
    pub async fn set_limits(&self, grant: Duration, max: Duration) {
        let (grant, max) = (grant.as_secs(), max.as_secs());
        if self.grant.swap(grant, Ordering::SeqCst) == grant && self.max.swap(max, Ordering::SeqCst) == max {
            return;
        }
        self.max.store(max, Ordering::SeqCst);
        let mut inner = self.inner.lock().await;
        for g in inner.grants.values_mut() {
            g.hard_expires = g.created + max as i64;
        }
        self.changed(&inner.grants);
        crate::logln!("LIMITS time to connect {} min, longest session {:.1} h", grant / 60, max as f64 / 3600.0);
    }

    pub fn firewall(&self) -> Arc<dyn Firewall> {
        self.fw.clone()
    }

    /// Opens (or refreshes) the firewall for `ip`. Runs to completion even if
    /// the caller goes away, so a rule is never added without being tracked.
    pub async fn allow(self: &Arc<Self>, ip: IpAddr, who: String) -> Result<Grant, String> {
        let me = self.clone();
        tokio::spawn(async move { me.allow_inner(ip, who, None).await }).await.map_err(|e| format!("grant task: {e}"))?
    }

    /// Opens `ip` too, for the computer that just signed in over the other IP
    /// family and was handed `token` (once, within a minute). `who` must
    /// match that sign-in. The two grants then close together.
    pub async fn link(self: &Arc<Self>, token: &str, ip: IpAddr, who: &str) -> Result<Grant, String> {
        let (ip, t) = (ip.to_canonical(), now());
        let (group, first) = {
            let mut inner = self.inner.lock().await;
            let g = inner
                .grants
                .values_mut()
                .find(|g| g.link.as_ref().is_some_and(|(l, _)| !token.is_empty() && bool::from(l.as_bytes().ct_eq(token.as_bytes()))))
                .ok_or("unknown or used link token")?;
            let (_, until) = g.link.take().unwrap_or_default();
            if t > until {
                return Err("link token expired".into());
            }
            if g.who != who {
                return Err(format!("link token belongs to {}", g.who));
            }
            if g.ip.is_ipv4() == ip.is_ipv4() {
                return Err(format!("{ip} is the same IP family as {}", g.ip));
            }
            (g.revoke_token.clone(), g.ip)
        };
        let me = self.clone();
        let who = format!("{who} with {first}");
        tokio::spawn(async move { me.allow_inner(ip, who, Some(group)).await }).await.map_err(|e| format!("grant task: {e}"))?
    }

    /// `group` is the revoke token to share; a new sign-in gets its own,
    /// and a link token for its other address.
    async fn allow_inner(&self, ip: IpAddr, who: String, group: Option<String>) -> Result<Grant, String> {
        let ip = ip.to_canonical();
        if !self.allow_private && !is_public(ip) {
            return Err(format!(
                "{ip} is not a public address. If your router rewrites source addresses, a grant for it would open \
                 Remote Desktop to everyone. For sign-in from your own network run: rdpgate-server lan on"
            ));
        }
        // Routers that rewrite source addresses make *every* connection,
        // including ones from the internet, look like the router itself.
        if !is_public(ip) && Some(ip) == crate::router::default_gateway() {
            return Err(format!(
                "{ip} is your router's own address, and a grant for it could open Remote Desktop to the internet. \
                 At home, the RDP Gate app connects to this PC directly; update it if it went through the router"
            ));
        }
        let mut inner = self.inner.lock().await;
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err("the service is stopping".into());
        }
        if !inner.grants.contains_key(&ip) {
            if inner.grants.len() >= MAX_GRANTS {
                return Err("too many active grants".into());
            }
            let fw = self.fw.clone();
            blocking(move || fw.allow(ip)).await?;
            inner.closing.remove(&ip);
        }
        let t = now();
        let g = Grant {
            ip,
            who,
            created: t,
            expires: t + self.grant.load(Ordering::SeqCst) as i64,
            hard_expires: t + self.max.load(Ordering::SeqCst) as i64,
            last_connected: inner.grants.get(&ip).and_then(|g| g.last_connected),
            link: group.is_none().then(|| (rdpgate_core::random_token::<24>(), t + LINK_WINDOW)),
            revoke_token: group.unwrap_or_else(rdpgate_core::random_token::<24>),
        };
        inner.grants.insert(ip, g.clone());
        self.changed(&inner.grants);
        crate::logln!("GRANT open ip={ip} who={:?} until={}", g.who, crate::log::local(g.expires));
        Ok(g)
    }

    async fn close(&self, inner: &mut Inner, ip: IpAddr, why: &str) -> bool {
        let existed = inner.grants.remove(&ip).is_some();
        let fw = self.fw.clone();
        match blocking(move || fw.revoke(ip)).await {
            Ok(()) => {
                inner.closing.remove(&ip);
            }
            Err(e) => {
                crate::logln!("ERROR firewall revoke {ip} (will retry): {e}");
                inner.closing.insert(ip);
            }
        }
        if existed {
            crate::logln!("GRANT closed ip={ip} reason={why}");
            self.changed(&inner.grants);
        }
        existed
    }

    /// Closes `ip` and any grant opened together with it.
    pub async fn revoke(&self, ip: IpAddr, why: &str) -> bool {
        let ip = ip.to_canonical();
        let mut inner = self.inner.lock().await;
        let group = inner.grants.get(&ip).map(|g| g.revoke_token.clone());
        let mut ips = vec![ip];
        if let Some(group) = group {
            ips.extend(inner.grants.values().filter(|g| g.ip != ip && g.revoke_token == group).map(|g| g.ip));
        }
        let mut closed = false;
        for ip in ips {
            closed |= self.close(&mut inner, ip, why).await;
        }
        closed
    }

    pub async fn revoke_by_token(&self, token: &str) -> Option<IpAddr> {
        if token.is_empty() {
            return None;
        }
        let ip = {
            let inner = self.inner.lock().await;
            inner.grants.values().find(|g| bool::from(g.revoke_token.as_bytes().ct_eq(token.as_bytes()))).map(|g| g.ip)?
        };
        self.revoke(ip, "closed from the web page").await;
        Some(ip)
    }

    /// Closes everything and refuses new grants. Uses one quick delete per
    /// known address first (shutdown may give us only a few seconds), then a
    /// full sweep for anything else.
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let mut inner = self.inner.lock().await;
        let ips: Vec<IpAddr> = inner.grants.keys().chain(inner.closing.iter()).copied().collect();
        for ip in ips {
            self.close(&mut inner, ip, "service stopping").await;
        }
        let fw = self.fw.clone();
        if let Err(e) = blocking(move || fw.revoke_all()).await {
            crate::logln!("ERROR firewall sweep: {e}");
        }
        inner.grants.clear();
        self.changed(&inner.grants);
    }

    /// Refreshes grants with live RDP connections, closes expired ones,
    /// retries failed revokes and removes rules nobody is tracking.
    pub async fn tick(&self) {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.inner.lock().await;

        for ip in inner.closing.clone() {
            let fw = self.fw.clone();
            if blocking(move || fw.revoke(ip)).await.is_ok() {
                inner.closing.remove(&ip);
                crate::logln!("GRANT closed ip={ip} reason=retry succeeded");
            }
        }

        if n.is_multiple_of(RECONCILE_EVERY) {
            let fw = self.fw.clone();
            match blocking(move || fw.list_allowed()).await {
                Ok(rules) => {
                    let stray: Vec<IpAddr> = rules.into_iter().filter(|ip| !inner.grants.contains_key(ip)).collect();
                    for ip in stray {
                        crate::logln!("WARNING removing firewall rule with no grant: {ip}");
                        self.close(&mut inner, ip, "untracked rule").await;
                    }
                }
                Err(e) => crate::logln!("ERROR listing firewall rules: {e}"),
            }
        }

        if inner.grants.is_empty() {
            return;
        }
        let fw = self.fw.clone();
        let peers = match blocking(move || fw.connected_peers()).await {
            Ok(p) => p,
            Err(e) => {
                // Fail closed: if connections cannot be seen, treat them as absent.
                crate::logln!("ERROR reading connection table: {e}");
                Default::default()
            }
        };
        let t = now();
        let mut expired = Vec::new();
        for g in inner.grants.values_mut() {
            if peers.contains(&g.ip) {
                if g.last_connected.is_none() {
                    crate::logln!("RDP connected ip={}", g.ip);
                }
                g.last_connected = Some(t);
            }
            let keep_until = g.expires.max(g.last_connected.map_or(0, |c| c + GRACE.as_secs() as i64));
            if t >= keep_until || t >= g.hard_expires {
                expired.push((g.ip, if t >= g.hard_expires { "max_hours reached" } else { "expired" }));
            }
        }
        for (ip, why) in expired {
            self.close(&mut inner, ip, why).await;
        }
        self.changed(&inner.grants);
    }

    pub async fn list(&self) -> Vec<Grant> {
        self.inner.lock().await.grants.values().cloned().collect()
    }

    /// Runs after every change to the grant table, with `inner` locked.
    fn changed(&self, map: &HashMap<IpAddr, Grant>) {
        self.write_status(map);
        self.sync_power(!map.is_empty());
    }

    /// Holds the power request from sign-in until the last grant closes, so
    /// the PC can't sleep between signing in and connecting, or mid-session.
    /// A failure is retried on the next change (every tick while grants exist).
    fn sync_power(&self, want: bool) {
        let Some(power) = &self.power else { return };
        if self.awake.load(Ordering::SeqCst) == want {
            return;
        }
        match power.keep_awake(want) {
            Ok(()) => {
                self.awake.store(want, Ordering::SeqCst);
                crate::logln!("{}", if want { "POWER keeping this PC awake while signed in" } else { "POWER sleep allowed again" });
            }
            Err(e) => crate::logln!("ERROR {e}"),
        }
    }

    /// grants.json lets `rdpgate-server status` show live grants without IPC.
    fn write_status(&self, map: &HashMap<IpAddr, Grant>) {
        if let Some(path) = &self.status_file {
            let list: Vec<&Grant> = map.values().collect();
            if let Ok(json) = serde_json::to_vec_pretty(&list) {
                let _ = rdpgate_core::keystore::write_private(path, &json);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::DryRun;

    fn grants(fw: Arc<DryRun>, private: bool) -> Arc<Grants> {
        Arc::new(Grants::new(fw, Duration::ZERO, Duration::from_secs(3600), private, None))
    }

    #[tokio::test]
    async fn grant_lifecycle() {
        let fw = Arc::new(DryRun::default());
        let grants = grants(fw.clone(), false);
        let ip: IpAddr = "81.2.69.160".parse().unwrap();

        let g = grants.allow(ip, "device mac".into()).await.unwrap();
        assert!(fw.allowed.lock().unwrap().contains(&ip));

        // Connected: kept open even though grant_minutes (0 here) has passed.
        fw.peers.lock().unwrap().insert(ip);
        grants.tick().await;
        assert!(fw.allowed.lock().unwrap().contains(&ip));

        // Revoking by the web page's token closes it.
        assert_eq!(grants.revoke_by_token(&g.revoke_token).await, Some(ip));
        assert!(!fw.allowed.lock().unwrap().contains(&ip));
        assert_eq!(grants.revoke_by_token("nope").await, None);

        // Not connected and expired: closed on the next tick.
        grants.allow(ip, "device mac".into()).await.unwrap();
        fw.peers.lock().unwrap().clear();
        grants.tick().await;
        assert!(fw.allowed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_sign_in_opens_the_other_ip_family_once_and_both_close_together() {
        let fw = Arc::new(DryRun::default());
        let grants = grants(fw.clone(), false);
        let (v6, v4): (IpAddr, IpAddr) = ("2a00:1450::1".parse().unwrap(), "81.2.69.160".parse().unwrap());
        let g = grants.allow(v6, "device mac".into()).await.unwrap();
        let token = g.link.clone().unwrap().0;

        let err = grants.link(&token, "2a00:1450::2".parse().unwrap(), "device mac").await.unwrap_err();
        assert!(err.contains("same IP family"), "{err}");
        assert!(grants.link(&token, v4, "device mac").await.is_err(), "a token works once, even after a refusal");

        let token = grants.allow(v6, "device mac".into()).await.unwrap().link.unwrap().0;
        assert!(grants.link(&token, v4, "device other").await.unwrap_err().contains("belongs to"));
        let token = grants.allow(v6, "device mac".into()).await.unwrap().link.unwrap().0;
        let linked = grants.link(&token, v4, "device mac").await.unwrap();
        assert_eq!(linked.who, format!("device mac with {v6}"));
        assert!(linked.link.is_none(), "a linked grant can't link further");
        assert_eq!(fw.allowed.lock().unwrap().len(), 2);

        // Locking from either address closes both.
        assert!(grants.revoke(v4, "test").await);
        assert!(fw.allowed.lock().unwrap().is_empty());
        assert!(grants.list().await.is_empty());
    }

    #[tokio::test]
    async fn changed_limits_apply_to_open_sessions_without_closing_them() {
        let fw = Arc::new(DryRun::default());
        let grants = grants(fw.clone(), false);
        let ip: IpAddr = "81.2.69.160".parse().unwrap();
        let g = grants.allow(ip, "device mac".into()).await.unwrap();
        assert_eq!(g.hard_expires - g.created, 3600);

        grants.set_limits(Duration::from_secs(600), Duration::from_secs(24 * 3600)).await;
        let open = grants.list().await;
        assert_eq!(open[0].hard_expires - open[0].created, 24 * 3600, "a running session gets the new cap");
        assert!(fw.allowed.lock().unwrap().contains(&ip), "and stays open");
        let g2 = grants.allow("81.2.69.161".parse().unwrap(), "x".into()).await.unwrap();
        assert_eq!((g2.expires - g2.created, g2.hard_expires - g2.created), (600, 24 * 3600));

        // Shortening below what has already passed closes it on the next tick.
        grants.set_limits(Duration::from_secs(600), Duration::ZERO).await;
        fw.peers.lock().unwrap().insert(ip);
        grants.tick().await;
        assert!(grants.list().await.is_empty());
    }

    #[tokio::test]
    async fn private_sources_are_refused_unless_enabled() {
        let fw = Arc::new(DryRun::default());
        for ip in ["10.0.0.1", "192.168.1.9", "100.64.0.7", "127.0.0.1", "::1", "fd00::5", "::ffff:10.1.1.1"] {
            let err = grants(fw.clone(), false).allow(ip.parse().unwrap(), "x".into()).await.unwrap_err();
            assert!(err.contains("not a public address"), "{ip}: {err}");
        }
        assert!(fw.allowed.lock().unwrap().is_empty());
        grants(fw.clone(), true).allow("10.123.45.67".parse().unwrap(), "x".into()).await.unwrap();
        // Even then, never this PC's own router (where there is one).
        if let Some(gw) = crate::router::default_gateway().filter(|g| !is_public(*g)) {
            let err = grants(fw.clone(), true).allow(gw, "x".into()).await.unwrap_err();
            assert!(err.contains("router's own address"), "{gw}: {err}");
        }
    }

    #[tokio::test]
    async fn pc_stays_awake_while_any_grant_is_open() {
        let fw = Arc::new(DryRun::default());
        let power = Arc::new(crate::power::DryRun::default());
        let g = Arc::new(
            Grants::new(fw.clone(), Duration::ZERO, Duration::from_secs(3600), false, None).with_power(Some(power.clone())),
        );
        let awake = || power.awake.load(Ordering::SeqCst);
        let (a, b): (IpAddr, IpAddr) = ("81.2.69.160".parse().unwrap(), "81.2.69.161".parse().unwrap());
        assert!(!awake());

        g.allow(a, "device mac".into()).await.unwrap();
        g.allow(b, "passkey phone".into()).await.unwrap();
        assert!(awake());
        g.revoke(a, "test").await;
        assert!(awake(), "another grant is still open");

        // A live RDP connection keeps the grant, and the PC, past grant_minutes (0 here).
        fw.peers.lock().unwrap().insert(b);
        g.tick().await;
        assert!(awake());
        fw.peers.lock().unwrap().clear();
        g.revoke(b, "test").await;
        assert!(!awake(), "sleep is allowed once the last grant closes");

        g.allow(a, "device mac".into()).await.unwrap();
        g.shutdown().await;
        assert!(!awake(), "stopping the service releases it");
    }

    #[tokio::test]
    async fn stray_rules_are_reconciled_and_shutdown_closes_everything() {
        let fw = Arc::new(DryRun::default());
        let g = grants(fw.clone(), true);
        // A rule that exists without a grant (e.g. left over from a crash).
        fw.allowed.lock().unwrap().insert("81.2.69.161".parse().unwrap());
        g.tick().await; // first tick reconciles
        assert!(fw.allowed.lock().unwrap().is_empty());

        g.allow("81.2.69.160".parse().unwrap(), "x".into()).await.unwrap();
        g.shutdown().await;
        assert!(fw.allowed.lock().unwrap().is_empty());
        assert!(g.allow("81.2.69.160".parse().unwrap(), "x".into()).await.is_err(), "no grants after shutdown");
    }
}
