//! Publishes where this server can be reached, signed and encrypted, to a
//! secret GitHub gist, so desktop clients can find it without any DNS.

use crate::app::App;
use crate::config::Config;
use crate::identity::Identity;
use crate::state::now;
use rdpgate_core::beacon::{self, LanLocation, Location};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Independent "what is my IP" services, all queried over HTTPS. Two must
/// agree before an address is published, so one lying or compromised source
/// cannot redirect clients (and even then, clients verify the server's key).
const IPV4_SOURCES: &[&str] = &[
    "https://1.1.1.1/cdn-cgi/trace",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ipv4.icanhazip.com",
];
/// The same over IPv6: each of these names has only an IPv6 address.
const IPV6_SOURCES: &[&str] = &["https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me", "https://ipv6.seeip.org"];
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// Re-publish even when nothing changed, so clients can tell the beacon is live.
const REFRESH_EVERY: Duration = Duration::from_secs(6 * 3600);

/// This network's public addresses, as the internet sees them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PublicIps {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl PublicIps {
    /// The address older clients read: IPv4 when there is one.
    pub fn primary(&self) -> Option<IpAddr> {
        self.v4.map(IpAddr::V4).or(self.v6.map(IpAddr::V6))
    }

    /// "81.2.69.160 and 2a00:1450::1", for messages.
    pub fn describe(&self) -> String {
        match (self.v4, self.v6) {
            (Some(a), Some(b)) => format!("{a} and {b}"),
            (Some(a), None) => a.to_string(),
            (None, Some(b)) => b.to_string(),
            (None, None) => "none".into(),
        }
    }
}

fn reply_text<'a>(url: &str, body: &'a str) -> Option<&'a str> {
    if url.ends_with("/cdn-cgi/trace") { body.lines().find_map(|l| l.strip_prefix("ip=")) } else { Some(body) }.map(str::trim)
}

fn parse_ipv4(url: &str, body: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = reply_text(url, body)?.parse().ok()?;
    crate::grants::is_public(IpAddr::V4(ip)).then_some(ip)
}

/// Only global unicast (2000::/3), and not Teredo (2001::/32), whose
/// addresses come and go with a relay.
fn parse_ipv6(url: &str, body: &str) -> Option<Ipv6Addr> {
    let ip: Ipv6Addr = reply_text(url, body)?.parse().ok()?;
    let s = ip.segments();
    let global = (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0);
    (global && crate::grants::is_public(IpAddr::V6(ip))).then_some(ip)
}

/// Asks `sources` in turn until two agree (blocking).
fn confirm<T: PartialEq + std::fmt::Debug>(
    sources: &[&str],
    family: &str,
    parse: impl Fn(&str, &str) -> Option<T>,
) -> Result<T, String> {
    let mut seen: Vec<T> = Vec::new();
    let mut errors = Vec::new();
    for url in sources {
        match beacon::http_get_text(url) {
            Ok(body) => match parse(url, &body) {
                Some(ip) if seen.contains(&ip) => return Ok(ip),
                Some(ip) => seen.push(ip),
                None => errors.push(format!("{url}: no public {family} address in reply")),
            },
            Err(e) => errors.push(e),
        }
    }
    if seen.len() > 1 {
        return Err(format!("{family} sources disagree ({seen:?}); not publishing"));
    }
    Err(format!("could not confirm the public {family} address: {}", errors.join("; ")))
}

/// Finds this network's public IPv4 address and, with `ipv6`, its IPv6 one
/// (blocking). Either may be missing; an error only when neither is found.
pub fn discover_public_ips(ipv6: bool) -> Result<PublicIps, String> {
    let (v4, v6) = std::thread::scope(|s| {
        let v6 = ipv6.then(|| s.spawn(|| confirm(IPV6_SOURCES, "IPv6", parse_ipv6)));
        let v4 = confirm(IPV4_SOURCES, "IPv4", parse_ipv4);
        (v4, v6.map(|h| h.join().unwrap_or_else(|_| Err("IPv6 check failed".into()))))
    });
    let ips = PublicIps { v4: v4.as_ref().ok().copied(), v6: v6.as_ref().and_then(|r| r.as_ref().ok()).copied() };
    if ips.primary().is_some() {
        return Ok(ips);
    }
    let mut errors = vec![v4.unwrap_err()];
    if let Some(Err(e)) = v6 {
        errors.push(e);
    }
    Err(errors.join("; "))
}

#[derive(Serialize)]
struct Status {
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip6: Option<String>,
    published: Option<i64>,
    error: Option<String>,
}

impl Status {
    fn new(ips: Option<PublicIps>, published: Option<i64>, error: Option<String>) -> Self {
        Status {
            ip: ips.and_then(|i| i.v4).map(|i| i.to_string()),
            ip6: ips.and_then(|i| i.v6).map(|i| i.to_string()),
            published,
            error,
        }
    }
}

fn write_status(app: &App, s: &Status) {
    if let Ok(json) = serde_json::to_vec_pretty(s) {
        let _ = rdpgate_core::keystore::write_private(&app.cfg.data_dir.join("beacon.json"), &json);
    }
}

/// This PC's address on its own network, published only when sign-in from
/// there is allowed: computers at home then connect to it directly, instead
/// of through the router (which many routers can't loop back, and which would
/// make every one of them look like the router).
pub fn lan_location(cfg: &Config) -> Option<LanLocation> {
    if !cfg.allow_private_sources {
        return None;
    }
    Some(LanLocation { ip: crate::router::lan_ip()?, port: crate::router::listen_port(cfg), rdp_port: cfg.rdp_port })
}

/// What the beacon says. The router's forwarded ports apply to IPv4 only:
/// over IPv6 computers reach this PC's own ports.
fn location(cfg: &Config, ips: PublicIps, lan: Option<LanLocation>) -> Option<Location> {
    let (port6, rdp_port6) = (crate::router::listen_port(cfg), cfg.rdp_port);
    let differs = |own: u16, forwarded: u16| (own != forwarded).then_some(own);
    let loc = match (ips.v4, ips.v6) {
        (Some(v4), v6) => Location {
            ip: IpAddr::V4(v4),
            ip6: v6,
            ip6_port: v6.and(differs(port6, cfg.public_port)),
            ip6_rdp_port: v6.and(differs(rdp_port6, cfg.rdp_public_port)),
            port: cfg.public_port,
            rdp_port: cfg.rdp_public_port,
            ts: now(),
            lan,
        },
        // Older clients only read `ip`, `port` and `rdp_port`.
        (None, Some(v6)) => {
            Location { ip: IpAddr::V6(v6), ip6: None, ip6_port: None, ip6_rdp_port: None, port: port6, rdp_port: rdp_port6, ts: now(), lan }
        }
        (None, None) => return None,
    };
    Some(loc)
}

/// Seals the current location and pushes it to the gist (blocking).
pub fn publish(cfg: &Config, identity: &Identity, ips: PublicIps, lan: Option<LanLocation>) -> Result<(), String> {
    let b = cfg.beacon.as_ref().ok_or("no beacon configured")?;
    let loc = location(cfg, ips, lan).ok_or("no public address to publish")?;
    let text = beacon::seal(&loc, &identity.server, identity.beacon_key.as_ref())?;
    beacon::publish_gist(&b.gist_id, &b.token, &text)
}

pub async fn run(app: Arc<App>, mut shutdown: watch::Receiver<bool>) {
    if app.cfg.beacon.is_none() {
        return;
    }
    let mut last: Option<(PublicIps, Instant)> = None;
    let mut last_lan: Option<LanLocation> = None;
    let mut last_error: Option<String> = None;
    let mut tick = tokio::time::interval(CHECK_EVERY);
    let ipv6 = app.cfg.ipv6;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let found = match tokio::task::spawn_blocking(move || discover_public_ips(ipv6)).await {
            Ok(Ok(ips)) => ips,
            Ok(Err(e)) => {
                if last_error.as_deref() != Some(e.as_str()) {
                    crate::logln!("BEACON {e}");
                    write_status(&app, &Status::new(last.map(|l| l.0), None, Some(e.clone())));
                }
                last_error = Some(e);
                continue;
            }
            Err(_) => return,
        };
        // One family's sources not answering this time doesn't mean its
        // address went away: keep publishing the one last confirmed.
        let recent = last.filter(|(_, at)| at.elapsed() < REFRESH_EVERY).map(|l| l.0).unwrap_or_default();
        let ips = PublicIps { v4: found.v4.or(recent.v4), v6: found.v6.or(recent.v6) };
        let lan = lan_location(&app.cfg);
        let stale = lan != last_lan || last.is_none_or(|(old, at)| old != ips || at.elapsed() > REFRESH_EVERY);
        if !stale {
            continue;
        }
        let app2 = app.clone();
        let lan2 = lan.clone();
        match tokio::task::spawn_blocking(move || publish(&app2.cfg, &app2.identity, ips, lan2)).await {
            Ok(Ok(())) => {
                if lan != last_lan || last.is_none_or(|(old, _)| old != ips) {
                    let v6 = ips.v6.map(|v| format!(" ip6={v}")).unwrap_or_default();
                    let ip = ips.primary().map(|i| i.to_string()).unwrap_or_default();
                    match &lan {
                        Some(l) => crate::logln!("BEACON published ip={ip}{v6} lan={}", l.ip),
                        None => crate::logln!("BEACON published ip={ip}{v6}"),
                    }
                }
                last = Some((ips, Instant::now()));
                last_lan = lan;
                last_error = None;
                write_status(&app, &Status::new(Some(ips), Some(now()), None));
            }
            Ok(Err(e)) => {
                crate::logln!("BEACON {e}");
                last_error = Some(e.clone());
                write_status(&app, &Status::new(Some(ips), None, Some(e)));
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_sources_and_rejects_private_addresses() {
        assert_eq!(parse_ipv4("https://api.ipify.org", "203.0.113.7\n"), None, "documentation range is not public");
        assert_eq!(parse_ipv4("https://api.ipify.org", "81.2.69.160\n"), Some("81.2.69.160".parse().unwrap()));
        let trace = "fl=1\nh=1.1.1.1\nip=81.2.69.160\nts=1\n";
        assert_eq!(parse_ipv4("https://1.1.1.1/cdn-cgi/trace", trace), Some("81.2.69.160".parse().unwrap()));
        for private in ["10.0.0.1", "192.168.1.5", "100.64.3.2", "127.0.0.1", "nonsense", "2a00:1450:4001::1"] {
            assert_eq!(parse_ipv4("https://api.ipify.org", private), None, "{private}");
        }
    }

    #[test]
    fn parses_ipv6_sources_and_rejects_non_global_addresses() {
        let v6 = "2607:f748:203:b9:b::11";
        assert_eq!(parse_ipv6("https://api6.ipify.org", &format!("{v6}\n")), Some(v6.parse().unwrap()));
        assert_eq!(parse_ipv6("https://v6.ident.me", v6), Some(v6.parse().unwrap()));
        for not_global in ["fe80::1", "fd00::5", "::1", "2001:db8::1", "2001:0:4136:e378::1", "81.2.69.160", "nonsense"] {
            assert_eq!(parse_ipv6("https://api6.ipify.org", not_global), None, "{not_global}");
        }
    }

    #[test]
    #[ignore = "asks the internet"]
    fn finds_this_networks_addresses() {
        let ips = discover_public_ips(true).unwrap();
        println!("public addresses: {}", ips.describe());
        assert!(ips.primary().is_some());
    }

    #[test]
    fn ipv6_uses_this_pcs_own_ports() {
        let mut cfg = Config::new(None);
        let ips = PublicIps { v4: Some("81.2.69.160".parse().unwrap()), v6: Some("2607:f748::11".parse().unwrap()) };
        let loc = location(&cfg, ips, None).unwrap();
        assert_eq!((loc.ip6_port, loc.ip6_rdp_port), (None, None), "same ports: nothing extra");
        // The router forwards 50443 -> 443 and 53389 -> 3389.
        cfg.public_port = 50443;
        cfg.rdp_public_port = 53389;
        let loc = location(&cfg, ips, None).unwrap();
        assert_eq!((loc.port, loc.rdp_port, loc.ip6_port, loc.ip6_rdp_port), (50443, 53389, Some(443), Some(3389)));
        let v6_only = location(&cfg, PublicIps { v4: None, ..ips }, None).unwrap();
        assert_eq!((v6_only.ip, v6_only.port, v6_only.rdp_port, v6_only.ip6), (ips.v6.unwrap().into(), 443, 3389, None));
        assert!(location(&cfg, PublicIps::default(), None).is_none());
    }

    #[test]
    fn older_clients_read_ipv4_first() {
        let both = PublicIps { v4: Some("81.2.69.160".parse().unwrap()), v6: Some("2607:f748::11".parse().unwrap()) };
        assert_eq!(both.primary(), Some("81.2.69.160".parse().unwrap()));
        let v6_only = PublicIps { v4: None, ..both };
        assert_eq!(v6_only.primary(), Some("2607:f748::11".parse().unwrap()));
        assert_eq!(PublicIps::default().primary(), None);
    }
}
