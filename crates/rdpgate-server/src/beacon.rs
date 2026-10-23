//! Publishes where this server can be reached, signed and encrypted, to a
//! secret GitHub gist, so desktop clients can find it without any DNS.

use crate::app::App;
use crate::config::Config;
use crate::identity::Identity;
use crate::state::now;
use rdpgate_core::beacon::{self, LanLocation, Location};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Independent "what is my IP" services, all queried over HTTPS. Two must
/// agree before an address is published, so one lying or compromised source
/// cannot redirect clients (and even then, clients verify the server's key).
const IP_SOURCES: &[&str] = &[
    "https://1.1.1.1/cdn-cgi/trace",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ipv4.icanhazip.com",
];
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// Re-publish even when nothing changed, so clients can tell the beacon is live.
const REFRESH_EVERY: Duration = Duration::from_secs(6 * 3600);

fn parse_ip(url: &str, body: &str) -> Option<Ipv4Addr> {
    let text = if url.ends_with("/cdn-cgi/trace") {
        body.lines().find_map(|l| l.strip_prefix("ip="))?
    } else {
        body
    };
    let ip: Ipv4Addr = text.trim().parse().ok()?;
    let public = !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
        || ip.is_broadcast() || ip.is_documentation() || ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64);
    public.then_some(ip)
}

/// Asks the sources in turn until two agree (blocking).
pub fn discover_public_ip() -> Result<IpAddr, String> {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    let mut errors = Vec::new();
    for url in IP_SOURCES {
        match beacon::http_get_text(url) {
            Ok(body) => match parse_ip(url, &body) {
                Some(ip) if seen.contains(&ip) => return Ok(IpAddr::V4(ip)),
                Some(ip) => seen.push(ip),
                None => errors.push(format!("{url}: no public IPv4 address in reply")),
            },
            Err(e) => errors.push(e),
        }
    }
    if seen.len() > 1 {
        return Err(format!("IP sources disagree ({seen:?}); not publishing"));
    }
    Err(format!("could not confirm the public IP: {}", errors.join("; ")))
}

#[derive(Serialize)]
struct Status {
    ip: Option<String>,
    published: Option<i64>,
    error: Option<String>,
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

/// Seals the current location and pushes it to the gist (blocking).
pub fn publish(cfg: &Config, identity: &Identity, ip: IpAddr, lan: Option<LanLocation>) -> Result<(), String> {
    let b = cfg.beacon.as_ref().ok_or("no beacon configured")?;
    let loc = Location { ip, port: cfg.public_port, rdp_port: cfg.rdp_public_port, ts: now(), lan };
    let text = beacon::seal(&loc, &identity.server, identity.beacon_key.as_ref())?;
    beacon::publish_gist(&b.gist_id, &b.token, &text)
}

pub async fn run(app: Arc<App>, mut shutdown: watch::Receiver<bool>) {
    if app.cfg.beacon.is_none() {
        return;
    }
    let mut last: Option<(IpAddr, Instant)> = None;
    let mut last_lan: Option<LanLocation> = None;
    let mut last_error: Option<String> = None;
    let mut tick = tokio::time::interval(CHECK_EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let ip = match tokio::task::spawn_blocking(discover_public_ip).await {
            Ok(Ok(ip)) => ip,
            Ok(Err(e)) => {
                if last_error.as_deref() != Some(e.as_str()) {
                    crate::logln!("BEACON {e}");
                    write_status(&app, &Status { ip: last.map(|l| l.0.to_string()), published: None, error: Some(e.clone()) });
                }
                last_error = Some(e);
                continue;
            }
            Err(_) => return,
        };
        let lan = lan_location(&app.cfg);
        let stale = lan != last_lan || last.is_none_or(|(old, at)| old != ip || at.elapsed() > REFRESH_EVERY);
        if !stale {
            continue;
        }
        let app2 = app.clone();
        let lan2 = lan.clone();
        match tokio::task::spawn_blocking(move || publish(&app2.cfg, &app2.identity, ip, lan2)).await {
            Ok(Ok(())) => {
                if lan != last_lan || last.is_none_or(|(old, _)| old != ip) {
                    match &lan {
                        Some(l) => crate::logln!("BEACON published ip={ip} lan={}", l.ip),
                        None => crate::logln!("BEACON published ip={ip}"),
                    }
                }
                last = Some((ip, Instant::now()));
                last_lan = lan;
                last_error = None;
                write_status(&app, &Status { ip: Some(ip.to_string()), published: Some(now()), error: None });
            }
            Ok(Err(e)) => {
                crate::logln!("BEACON {e}");
                last_error = Some(e.clone());
                write_status(&app, &Status { ip: Some(ip.to_string()), published: None, error: Some(e) });
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
        assert_eq!(parse_ip("https://api.ipify.org", "203.0.113.7\n"), None, "documentation range is not public");
        assert_eq!(parse_ip("https://api.ipify.org", "81.2.69.160\n"), Some("81.2.69.160".parse().unwrap()));
        let trace = "fl=1\nh=1.1.1.1\nip=81.2.69.160\nts=1\n";
        assert_eq!(parse_ip("https://1.1.1.1/cdn-cgi/trace", trace), Some("81.2.69.160".parse().unwrap()));
        for private in ["10.0.0.1", "192.168.1.5", "100.64.3.2", "127.0.0.1", "nonsense"] {
            assert_eq!(parse_ip("https://api.ipify.org", private), None, "{private}");
        }
    }
}
