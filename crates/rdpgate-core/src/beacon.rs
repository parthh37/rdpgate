//! Finding the server without DNS.
//!
//! The server publishes its current public address as a *beacon*: signed with
//! the server's identity key (so nobody can forge one) and encrypted with a
//! beacon key that only enrolled computers hold (so the storage, a secret
//! GitHub gist, never sees your home IP). Clients learn the server's public
//! key and the beacon key once, from the *server card* printed at enrollment.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// File name inside the gist.
pub const GIST_FILE: &str = "rdpgate-beacon";
const BEACON_PREFIX: &str = "v1.";
const SIG_CONTEXT: &[u8] = b"rdpgate beacon v1\0";
const AAD: &[u8] = b"rdpgate-beacon-v1";
const CARD_PREFIX: &str = "rdpgate-card:";

/// Where the server can be reached, as of `ts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub ip: IpAddr,
    /// Port forwarded to the agent (sign-in).
    pub port: u16,
    /// Port forwarded to Remote Desktop.
    pub rdp_port: u16,
    /// Unix seconds when the server published this.
    pub ts: i64,
}

#[derive(Serialize, Deserialize)]
struct Signed {
    #[serde(with = "crate::b64")]
    payload: Vec<u8>,
    #[serde(with = "crate::b64")]
    sig: Vec<u8>,
}

fn cipher(beacon_key: &[u8]) -> Result<XChaCha20Poly1305, String> {
    XChaCha20Poly1305::new_from_slice(beacon_key).map_err(|_| "beacon key must be 32 bytes".to_string())
}

/// Signs and encrypts a location for publishing.
pub fn seal(loc: &Location, server: &SigningKey, beacon_key: &[u8]) -> Result<String, String> {
    let payload = serde_json::to_vec(loc).map_err(|e| e.to_string())?;
    let sig = server.sign(&[SIG_CONTEXT, &payload].concat()).to_bytes().to_vec();
    let inner = serde_json::to_vec(&Signed { payload, sig }).map_err(|e| e.to_string())?;
    let nonce = crate::random_bytes::<24>();
    let ct = cipher(beacon_key)?
        .encrypt(&XNonce::from(nonce), Payload { msg: &inner, aad: AAD })
        .map_err(|_| "encryption failed".to_string())?;
    Ok(format!("{BEACON_PREFIX}{}", URL_SAFE_NO_PAD.encode([nonce.as_slice(), &ct].concat())))
}

/// Decrypts a beacon and checks the server's signature on it.
pub fn open(text: &str, server: &VerifyingKey, beacon_key: &[u8]) -> Result<Location, String> {
    let raw = text
        .trim()
        .strip_prefix(BEACON_PREFIX)
        .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok())
        .filter(|r| r.len() > 24)
        .ok_or("the server's beacon is missing or malformed")?;
    let (nonce, ct) = raw.split_at(24);
    let nonce = XNonce::try_from(nonce).map_err(|_| "malformed beacon")?;
    let inner = cipher(beacon_key)?
        .decrypt(&nonce, Payload { msg: ct, aad: AAD })
        .map_err(|_| "the beacon could not be decrypted: wrong server card, or it was tampered with")?;
    let signed: Signed = serde_json::from_slice(&inner).map_err(|_| "malformed beacon")?;
    let sig = Signature::from_slice(&signed.sig).map_err(|_| "malformed beacon signature")?;
    server
        .verify_strict(&[SIG_CONTEXT, &signed.payload].concat(), &sig)
        .map_err(|_| "the beacon is not signed by your server (possible spoofing)")?;
    serde_json::from_slice(&signed.payload).map_err(|_| "malformed beacon contents".into())
}

/// Everything a client needs to find and trust one server. It contains the
/// beacon key, so treat it like a password (it reveals where you live online).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub v: u32,
    /// `rdpgate-server-ed25519:...`
    pub key: String,
    #[serde(with = "crate::b64")]
    pub beacon_key: Vec<u8>,
    /// Secret GitHub gist holding the beacon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gist: Option<String>,
    /// Optional DNS name (only needed for browser sign-in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Sign-in port, used with `host`.
    pub port: u16,
}

pub fn valid_gist_id(id: &str) -> bool {
    (20..=40).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Card {
    pub fn encode(&self) -> String {
        format!("{CARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("card serializes")))
    }

    pub fn decode(s: &str) -> Result<Card, String> {
        let raw = s
            .trim()
            .strip_prefix(CARD_PREFIX)
            .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok())
            .ok_or("that is not a server card (it starts with \"rdpgate-card:\")")?;
        let c: Card = serde_json::from_slice(&raw).map_err(|_| "the server card is damaged; copy it again")?;
        if c.v != 1 {
            return Err("this server card needs a newer version of RDP Gate".into());
        }
        crate::wire::parse_server_key(&c.key)?;
        if c.beacon_key.len() != 32 {
            return Err("the server card is damaged; copy it again".into());
        }
        if c.gist.as_deref().is_some_and(|g| !valid_gist_id(g)) {
            return Err("the server card has an invalid gist id".into());
        }
        if c.gist.is_none() && c.host.is_none() {
            return Err("the server has neither a beacon nor a host name configured".into());
        }
        Ok(c)
    }

    pub fn server_key(&self) -> VerifyingKey {
        crate::wire::parse_server_key(&self.key).expect("validated in decode")
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .user_agent("rdpgate")
        .build()
        .into()
}

/// GETs a small text resource over HTTPS (blocking).
pub fn http_get_text(url: &str) -> Result<String, String> {
    let mut resp = agent().get(url).call().map_err(|e| format!("{url}: {e}"))?;
    resp.body_mut().with_config().limit(16 * 1024).read_to_string().map_err(|e| format!("{url}: {e}"))
}

/// Reads the beacon text from a secret gist (blocking; run off async threads).
pub fn fetch_gist(gist_id: &str) -> Result<String, String> {
    if !valid_gist_id(gist_id) {
        return Err("invalid gist id".into());
    }
    let mut resp = agent()
        .get(&format!("https://api.github.com/gists/{gist_id}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|e| format!("could not read the beacon from GitHub: {e}"))?;
    let body = resp
        .body_mut()
        .with_config()
        .limit(256 * 1024)
        .read_to_string()
        .map_err(|e| format!("could not read the beacon from GitHub: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| "unexpected reply from GitHub")?;
    v["files"][GIST_FILE]["content"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "the gist has no beacon yet: is the RDP Gate service running?".into())
}

/// Replaces the beacon in the gist (server side; blocking).
pub fn publish_gist(gist_id: &str, token: &str, content: &str) -> Result<(), String> {
    let body = serde_json::json!({ "files": { GIST_FILE: { "content": content } } }).to_string();
    agent()
        .patch(&format!("https://api.github.com/gists/{gist_id}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(body.as_str())
        .map(|_| ())
        .map_err(|e| format!("GitHub rejected the beacon update: {e}"))
}

/// Creates a new secret gist for the beacon and returns its id (server side).
pub fn create_gist(token: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "description": "RDP Gate beacon (encrypted)",
        "public": false,
        "files": { GIST_FILE: { "content": "pending" } }
    })
    .to_string();
    let mut resp = agent()
        .post("https://api.github.com/gists")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(body.as_str())
        .map_err(|e| format!("GitHub refused to create the gist (does the token have Gists: read and write?): {e}"))?;
    let text = resp.body_mut().with_config().limit(256 * 1024).read_to_string().map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| "unexpected reply from GitHub")?;
    let id = v["id"].as_str().ok_or("unexpected reply from GitHub")?.to_string();
    if !valid_gist_id(&id) {
        return Err("unexpected gist id from GitHub".into());
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&crate::random_bytes::<32>())
    }

    #[test]
    fn beacon_roundtrip_and_tamper() {
        let server = key();
        let bk = crate::random_bytes::<32>();
        let loc = Location { ip: "203.0.113.7".parse().unwrap(), port: 443, rdp_port: 3389, ts: 1_700_000_000 };
        let text = seal(&loc, &server, &bk).unwrap();
        assert_eq!(open(&text, &server.verifying_key(), &bk).unwrap(), loc);

        // Wrong beacon key: can't read it.
        assert!(open(&text, &server.verifying_key(), &crate::random_bytes::<32>()).is_err());
        // Someone with the beacon key but not the server key can't forge one.
        let forged = seal(&loc, &key(), &bk).unwrap();
        assert!(open(&forged, &server.verifying_key(), &bk).unwrap_err().contains("not signed"));
        // Flipped ciphertext byte.
        let mut raw = URL_SAFE_NO_PAD.decode(text.strip_prefix("v1.").unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(open(&format!("v1.{}", URL_SAFE_NO_PAD.encode(raw)), &server.verifying_key(), &bk).is_err());
    }

    #[test]
    fn card_roundtrip_and_validation() {
        let server = key();
        let card = Card {
            v: 1,
            key: crate::wire::encode_server_key(&server.verifying_key()),
            beacon_key: crate::random_bytes::<32>().to_vec(),
            gist: Some("0123456789abcdef0123456789abcdef".into()),
            host: None,
            port: 443,
        };
        let back = Card::decode(&card.encode()).unwrap();
        assert_eq!(back.server_key(), server.verifying_key());
        assert!(Card::decode("rdpgate-card:AAAA").is_err());
        assert!(Card::decode("hello").is_err());
        let mut bad = card.clone();
        bad.gist = Some("../../evil".into());
        assert!(Card::decode(&bad.encode()).is_err());
    }
}
