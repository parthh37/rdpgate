//! Automatic port forwarding on the home router (UPnP IGD), so setup needs
//! no router configuration when the router allows it. Only the sign-in port
//! and the RDP port are mapped; Windows Firewall still keeps RDP closed until
//! someone signs in. Mappings are leased and renewed every 30 minutes.
//!
//! Asking the router for its own internet address also reveals carrier-grade
//! NAT (or a second router in front), where no port forwarding can work.

use crate::config::Config;
use crate::grants::is_public;
use crate::state::now;
use igd_next::{AddPortError, PortMappingProtocol, SearchOptions, search_gateway};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::sync::watch;

const LEASE_SECS: u32 = 2 * 3600;
const RENEW_EVERY: Duration = Duration::from_secs(30 * 60);
const DESCRIPTION: &str = "RDP Gate";

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct RouterStatus {
    /// A UPnP router answered.
    pub found: bool,
    /// e.g. "TCP 443 -> 192.168.1.20:443"
    pub mapped: Vec<String>,
    pub failed: Vec<String>,
    pub lan_ip: Option<String>,
    /// The router's own internet-side address.
    pub router_external_ip: Option<String>,
    /// The router's internet address isn't public: carrier-grade NAT or a
    /// second router in front. Inbound connections can't reach this PC.
    pub behind_nat: bool,
    pub checked: i64,
}

impl RouterStatus {
    pub fn all_mapped(&self) -> bool {
        self.found && self.failed.is_empty() && !self.mapped.is_empty() && !self.behind_nat
    }

    /// One plain-language line per finding, for the CLI, installer and log.
    pub fn summary(&self, cfg: &Config) -> Vec<String> {
        let mut out = Vec::new();
        if !self.found {
            out.push("No router answered UPnP (it may be turned off on the router). Forward the ports by hand:".into());
            out.extend(manual_lines(cfg, self.lan_ip.as_deref()));
            return out;
        }
        for m in &self.mapped {
            out.push(format!("Router: forwarded {m}"));
        }
        for f in &self.failed {
            out.push(format!("Router refused: {f}"));
        }
        if !self.failed.is_empty() {
            out.push("Forward the refused ports by hand in your router's settings:".into());
            out.extend(manual_lines(cfg, self.lan_ip.as_deref()));
        }
        if self.behind_nat {
            out.push(format!(
                "Your router's own internet address is {}, which is not public: your ISP uses carrier-grade NAT, or there is \
                 another router in front of this one. Nothing on the internet can reach this PC until that changes. Ask your \
                 ISP for a public IPv4 address (often free), or forward the ports on the outer router too.",
                self.router_external_ip.as_deref().unwrap_or("?")
            ));
        }
        out
    }
}

/// The port forwards this configuration needs: (protocol, external, internal).
pub fn needed(cfg: &Config) -> Vec<(PortMappingProtocol, u16, u16)> {
    let listen_port = cfg
        .listen
        .iter()
        .filter_map(|l| l.parse::<SocketAddr>().ok())
        .find(|a| a.is_ipv4())
        .map(|a| a.port())
        .unwrap_or(443);
    let mut v = vec![(PortMappingProtocol::TCP, cfg.public_port, listen_port), (PortMappingProtocol::TCP, cfg.rdp_public_port, cfg.rdp_port)];
    if cfg.allow_udp {
        v.push((PortMappingProtocol::UDP, cfg.rdp_public_port, cfg.rdp_port));
    }
    v
}

fn proto_name(p: PortMappingProtocol) -> &'static str {
    match p {
        PortMappingProtocol::TCP => "TCP",
        PortMappingProtocol::UDP => "UDP",
    }
}

pub fn manual_lines(cfg: &Config, lan_ip: Option<&str>) -> Vec<String> {
    let lan = lan_ip.unwrap_or("this PC");
    needed(cfg)
        .into_iter()
        .map(|(p, ext, int)| format!("  {} {ext}  ->  {lan}:{int}", proto_name(p)))
        .collect()
}

/// The address this PC uses to reach `gateway` (no packets are sent).
fn lan_ip_towards(gateway: IpAddr) -> Option<IpAddr> {
    let sock = UdpSocket::bind(if gateway.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.connect(SocketAddr::new(gateway, 9)).ok()?;
    Some(sock.local_addr().ok()?.ip())
}

/// Finds the router and adds or renews every needed mapping (blocking).
pub fn apply(cfg: &Config) -> RouterStatus {
    let mut st = RouterStatus { checked: now(), ..Default::default() };
    let mut opts = SearchOptions::default();
    opts.timeout = Some(Duration::from_secs(4));
    let gw = match search_gateway(opts) {
        Ok(g) => g,
        Err(_) => {
            st.lan_ip = lan_ip_towards("192.0.2.1".parse().unwrap()).map(|i| i.to_string());
            return st;
        }
    };
    st.found = true;
    let Some(lan) = lan_ip_towards(gw.addr.ip()) else {
        st.failed.push("could not work out this PC's local address".into());
        return st;
    };
    st.lan_ip = Some(lan.to_string());
    if let Ok(ext) = gw.get_external_ip() {
        st.router_external_ip = Some(ext.to_string());
        st.behind_nat = !is_public(ext);
    }
    for (proto, ext, int) in needed(cfg) {
        let local = SocketAddr::new(lan, int);
        let label = format!("{} {ext} -> {local}", proto_name(proto));
        let result = match gw.add_port(proto, ext, local, LEASE_SECS, DESCRIPTION) {
            // Some routers only accept permanent mappings.
            Err(AddPortError::OnlyPermanentLeasesSupported) => gw.add_port(proto, ext, local, 0, DESCRIPTION),
            r => r,
        };
        match result {
            Ok(()) => st.mapped.push(label),
            Err(AddPortError::PortInUse) => st.failed.push(format!("{label} (already forwarded to another device)")),
            Err(e) => st.failed.push(format!("{label} ({e})")),
        }
    }
    st
}

fn write_status(cfg: &Config, st: &RouterStatus) {
    if let Ok(json) = serde_json::to_vec_pretty(st) {
        let _ = rdpgate_core::keystore::write_private(&cfg.data_dir.join("router.json"), &json);
    }
}

/// Keeps the router's port forwards in place while the service runs.
pub async fn run(cfg: Config, mut shutdown: watch::Receiver<bool>) {
    if !cfg.upnp {
        return;
    }
    let mut last: Option<RouterStatus> = None;
    loop {
        let c = cfg.clone();
        let Ok(st) = tokio::task::spawn_blocking(move || apply(&c)).await else { return };
        write_status(&cfg, &st);
        // Log only when something changed, not every renewal.
        let changed = last.as_ref().is_none_or(|l| l.mapped != st.mapped || l.failed != st.failed || l.found != st.found);
        if changed {
            for line in st.summary(&cfg) {
                crate::logln!("ROUTER {line}");
            }
        }
        last = Some(st);
        tokio::select! {
            _ = tokio::time::sleep(RENEW_EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needed_forwards_follow_the_config() {
        let mut cfg = Config::new(None);
        cfg.listen = vec!["0.0.0.0:8443".into()];
        cfg.public_port = 443;
        cfg.rdp_public_port = 53389;
        let n: Vec<_> = needed(&cfg).into_iter().map(|(p, e, i)| (proto_name(p), e, i)).collect();
        assert_eq!(n, vec![("TCP", 443, 8443), ("TCP", 53389, 3389)]);
        cfg.allow_udp = true;
        assert_eq!(needed(&cfg).len(), 3);
    }

    #[test]
    fn summary_explains_nat_and_manual_steps() {
        let cfg = Config::new(None);
        let none = RouterStatus { lan_ip: Some("192.168.1.20".into()), ..Default::default() };
        let text = none.summary(&cfg).join("\n");
        assert!(text.contains("TCP 443  ->  192.168.1.20:443") && text.contains("TCP 3389"), "{text}");
        let nat = RouterStatus {
            found: true,
            mapped: vec!["TCP 443 -> 192.168.1.20:443".into()],
            behind_nat: true,
            router_external_ip: Some("100.64.1.2".into()),
            ..Default::default()
        };
        assert!(nat.summary(&cfg).join("\n").contains("carrier-grade NAT"));
        assert!(!nat.all_mapped());
    }
}
