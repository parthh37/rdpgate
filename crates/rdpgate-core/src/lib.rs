//! Shared building blocks for the RDP Gate server and clients: the signed
//! wire protocol, RFC 6238 one-time codes and the encrypted device key file.

pub mod beacon;
pub mod keystore;
pub mod nettime;
pub mod rdp;
pub mod totp;
pub mod update;
pub mod wire;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use std::net::{IpAddr, Ipv6Addr};

/// How much of an IPv6 address a firewall opening covers.
pub const IPV6_GRANT_PREFIX: u8 = 64;

/// What a firewall opening for `ip` covers: the address itself for IPv4, its
/// /64 network for IPv6. An IPv6 computer uses several addresses from its
/// network at once and rotates them every few hours (privacy addresses), so
/// signing in and Remote Desktop often come from different ones. A /64 is
/// one home, office or phone network, like one shared IPv4 address. Only
/// global addresses (2000::/3) are widened; loopback, link-local and
/// unique-local ones stay as they are.
pub fn grant_scope(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v) if is_global_v6(v) => {
            let s = v.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        other => other,
    }
}

fn is_global_v6(v: Ipv6Addr) -> bool {
    v.segments()[0] & 0xe000 == 0x2000
}

/// [`grant_scope`] of `ip`, written for people: `2001:db8:1:2::/64`.
pub fn describe_scope(ip: IpAddr) -> String {
    match grant_scope(ip) {
        IpAddr::V6(v) if is_global_v6(v) => format!("{v}/{IPV6_GRANT_PREFIX}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn ipv6_grants_cover_the_network_and_ipv4_the_address() {
        let a: IpAddr = "2405:201:2022:ca6f:8963:b2a5:373c:317d".parse().unwrap();
        let b: IpAddr = "2405:201:2022:ca6f:34c8:931b:a619:fcdd".parse().unwrap();
        let other: IpAddr = "2405:201:2022:ca70::1".parse().unwrap();
        assert_eq!(grant_scope(a), grant_scope(b));
        assert_ne!(grant_scope(a), grant_scope(other));
        assert_eq!(describe_scope(a), "2405:201:2022:ca6f::/64");
        let v4: IpAddr = "81.2.69.160".parse().unwrap();
        assert_eq!(grant_scope(v4), v4);
        assert_eq!(grant_scope("::ffff:81.2.69.160".parse().unwrap()), v4);
        assert_eq!(describe_scope(v4), "81.2.69.160");
        for local in ["::1", "fe80::1:2:3:4", "fd00::5:6:7:8"] {
            let ip: IpAddr = local.parse().unwrap();
            assert_eq!(grant_scope(ip), ip, "{local} isn't widened");
            assert_eq!(describe_scope(ip), local);
        }
    }
}

/// Fills an array from the operating system's CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("operating system random number generator failed");
    b
}

/// A random URL-safe token with `N` bytes of entropy.
pub fn random_token<const N: usize>() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<N>())
}

/// Serde helper: `Vec<u8>` as standard base64.
pub mod b64 {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
