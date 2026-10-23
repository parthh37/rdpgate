//! Shared building blocks for the RDP Gate server and clients: the signed
//! wire protocol, RFC 6238 one-time codes and the encrypted device key file.

pub mod beacon;
pub mod keystore;
pub mod rdp;
pub mod totp;
pub mod wire;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

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
