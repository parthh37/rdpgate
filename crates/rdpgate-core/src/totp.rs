//! RFC 6238 time-based one-time passwords (HMAC-SHA1, 30-second steps, six
//! digits): the format Google Authenticator, Microsoft Authenticator,
//! 1Password, Authy and others all use.

use hmac::{KeyInit, Mac};
use subtle::ConstantTimeEq;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: usize = 6;
/// Steps accepted either side of "now", to absorb clock drift.
pub const SKEW: i64 = 1;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// A fresh 160-bit secret (the RFC 4226 recommended size).
pub fn new_secret() -> Vec<u8> {
    crate::random_bytes::<20>().to_vec()
}

/// The form people type into an authenticator app.
pub fn base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

/// The `otpauth://` link encoded in the enrollment QR code.
pub fn uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let label = url_escape(&format!("{issuer}:{account}"));
    format!(
        "otpauth://totp/{label}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        base32(secret),
        url_escape(issuer)
    )
}

fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The RFC 6238 time step for a Unix timestamp.
pub fn step(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// The RFC 4226 HOTP value for one counter.
pub fn code(secret: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let off = (sum[sum.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([sum[off], sum[off + 1], sum[off + 2], sum[off + 3]]) & 0x7fff_ffff;
    format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

/// Checks `input` against the steps around `now`. Any step at or before
/// `last_used` is refused, so each code works exactly once even inside its
/// window. On success returns the matched step, which the caller must persist
/// as the new `last_used`.
pub fn validate(secret: &[u8], input: &str, now_unix: u64, last_used: u64) -> Option<u64> {
    if input.len() != DIGITS || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let cur = step(now_unix) as i64;
    for d in -SKEW..=SKEW {
        let c = cur + d;
        if c < 0 || c as u64 <= last_used {
            continue;
        }
        let expected = code(secret, c as u64, DIGITS as u32);
        if bool::from(expected.as_bytes().ct_eq(input.as_bytes())) {
            return Some(c as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1 column (8 digits).
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, want) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code(secret, step(t), 8), want, "T={t}");
        }
    }

    #[test]
    fn window_and_replay() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000;
        let cur = step(now);
        let c = code(secret, cur, 6);
        let used = validate(secret, &c, now, 0).expect("current code accepted");
        assert_eq!(used, cur);
        assert!(validate(secret, &c, now, used).is_none(), "replay must fail");
        assert!(validate(secret, &code(secret, cur - 1, 6), now, 0).is_some(), "one step of skew allowed");
        assert!(validate(secret, &code(secret, cur - 2, 6), now, 0).is_none(), "two steps old rejected");
        assert!(validate(secret, "12345", now, 0).is_none());
        assert!(validate(secret, "12345a", now, 0).is_none());
    }

    #[test]
    fn uri_format() {
        let u = uri("RDP Gate", "owner@home.example", &[0u8; 20]);
        assert!(u.starts_with("otpauth://totp/RDP%20Gate%3Aowner%40home.example?secret=AAAA"));
    }
}
