//! The `rdpgate/1` protocol between the desktop client and the server, spoken
//! inside TLS 1.3 on the same port as the passkey web portal.
//!
//! Every request is signed with the device's Ed25519 key over the TLS
//! connection's exported keying material (RFC 8446 §7.5). Those 32 bytes are
//! unique to one connection and known only to its two endpoints, so a captured
//! request can never be replayed on another connection or relayed through a
//! man-in-the-middle.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// TLS ALPN identifier. Browsers never offer it, which is how the server tells
/// the desktop client apart from the web portal on port 443.
pub const ALPN: &[u8] = b"rdpgate/1";
/// RFC 5705 / RFC 8446 exporter label for the channel binding.
pub const EKM_LABEL: &[u8] = b"EXPORTER-rdpgate-client-auth";
pub const EKM_LEN: usize = 32;
const SIG_CONTEXT: &[u8] = b"rdpgate/1 client-auth\0";
const HELLO_CONTEXT: &[u8] = b"rdpgate/1 server-hello\0";
/// Upper bound on every frame, so pre-authentication reads stay tiny.
pub const MAX_FRAME: usize = 16 * 1024;

/// Open the firewall for this connection's source IP (device key + TOTP code).
pub const OP_TOTP: &str = "totp";
/// Close the firewall for this connection's source IP again.
pub const OP_REVOKE: &str = "revoke";
/// Open the firewall for this connection's source IP as well, with the
/// one-time `link` from a sign-in made moments ago over the other IP family.
pub const OP_LINK: &str = "link";

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("malformed signature")]
    MalformedSignature,
    #[error("bad signature")]
    BadSignature,
    #[error("device name mismatch")]
    DeviceMismatch,
    #[error("bad payload: {0}")]
    Payload(#[from] serde_json::Error),
    #[error("frame too large or empty")]
    FrameSize,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// First frame on every connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub device: String,
    /// JSON-encoded [`Payload`]: these exact bytes are what gets signed.
    #[serde(with = "crate::b64")]
    pub payload: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Payload {
    pub op: String,
    pub device: String,
    /// Unix seconds; the server rejects large clock skew.
    pub ts: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp: String,
    /// For [`OP_LINK`]: the token from [`Response::link`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub link: String,
}

/// Every server reply. Before the device is authenticated, errors are a bare
/// "denied"; the server log holds the specific reason.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The public IP address that was allowed through the firewall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Unix seconds after which the grant lapses unless an RDP connection is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    /// Unix seconds when the grant ends even while connected (longest session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_expires: Option<i64>,
    /// The port the RDP client should connect to (the router's forwarded port).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_port: Option<u16>,
    /// SHA-256 of the certificate the real RDP service presents. The client
    /// compares it with what it sees on the RDP port before launching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_cert_sha256: Option<String>,
    /// After a sign-in: a short-lived, one-time token that opens this
    /// computer's address in the other IP family too (see [`OP_LINK`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// First frame the server sends: proof that it holds the pinned server key,
/// bound to this TLS connection. The client verifies it before sending
/// anything, so a look-alike server (DNS hijack, mis-issued certificate,
/// someone else at your old IP) learns nothing, not even the device name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    #[serde(with = "crate::b64")]
    pub sig: Vec<u8>,
}

pub fn server_hello(key: &SigningKey, binding: &[u8]) -> ServerHello {
    let msg = [HELLO_CONTEXT, binding].concat();
    ServerHello { sig: key.sign(&msg).to_bytes().to_vec() }
}

pub fn verify_server_hello(key: &VerifyingKey, binding: &[u8], hello: &ServerHello) -> Result<(), WireError> {
    let sig = Signature::from_slice(&hello.sig).map_err(|_| WireError::MalformedSignature)?;
    key.verify_strict(&[HELLO_CONTEXT, binding].concat(), &sig).map_err(|_| WireError::BadSignature)
}

impl Response {
    pub fn error(msg: impl Into<String>) -> Self {
        Self { ok: false, error: Some(msg.into()), ..Default::default() }
    }
}

fn signed_bytes(binding: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_CONTEXT.len() + binding.len() + payload.len());
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(binding);
    m.extend_from_slice(payload);
    m
}

/// Builds a request bound to one TLS connection.
pub fn sign(key: &SigningKey, binding: &[u8], p: &Payload) -> Request {
    let payload = serde_json::to_vec(p).expect("payload serializes");
    let sig = key.sign(&signed_bytes(binding, &payload));
    Request { device: p.device.clone(), payload, sig: sig.to_bytes().to_vec() }
}

/// Checks the signature first and parses the payload only afterwards, so no
/// attacker-controlled JSON is interpreted before authentication.
pub fn verify(key: &VerifyingKey, binding: &[u8], req: &Request) -> Result<Payload, WireError> {
    let sig = Signature::from_slice(&req.sig).map_err(|_| WireError::MalformedSignature)?;
    key.verify_strict(&signed_bytes(binding, &req.payload), &sig)
        .map_err(|_| WireError::BadSignature)?;
    let p: Payload = serde_json::from_slice(&req.payload)?;
    if p.device != req.device {
        return Err(WireError::DeviceMismatch);
    }
    Ok(p)
}

/// Writes `v` as a 4-byte big-endian length followed by JSON.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> Result<(), WireError> {
    let body = serde_json::to_vec(v)?;
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(WireError::FrameSize);
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one frame written by [`write_frame`].
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, WireError> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(WireError::FrameSize);
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

const PUBKEY_PREFIX: &str = "rdpgate-ed25519:";
const SERVER_KEY_PREFIX: &str = "rdpgate-server-ed25519:";

fn encode_key(prefix: &str, k: &VerifyingKey) -> String {
    format!("{prefix}{}", STANDARD.encode(k.as_bytes()))
}

fn parse_key(prefix: &str, s: &str) -> Result<VerifyingKey, String> {
    let b64 = s.trim().strip_prefix(prefix).ok_or_else(|| format!("key must start with \"{prefix}\""))?;
    let raw = STANDARD.decode(b64).map_err(|_| "invalid key".to_string())?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "invalid key length".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "invalid key".to_string())
}

/// Renders a device public key for copy/paste enrollment.
pub fn encode_public_key(k: &VerifyingKey) -> String {
    encode_key(PUBKEY_PREFIX, k)
}

/// Parses the output of [`encode_public_key`].
pub fn parse_public_key(s: &str) -> Result<VerifyingKey, String> {
    parse_key(PUBKEY_PREFIX, s)
}

/// Server identity keys use a different prefix, so the two can never be mixed up.
pub fn encode_server_key(k: &VerifyingKey) -> String {
    encode_key(SERVER_KEY_PREFIX, k)
}

pub fn parse_server_key(s: &str) -> Result<VerifyingKey, String> {
    parse_key(SERVER_KEY_PREFIX, s)
}

/// A short digest people can compare by eye, e.g. `3F2A-91C0-…`.
pub fn fingerprint(k: &VerifyingKey) -> String {
    let h = hex::encode_upper(&Sha256::digest(k.as_bytes())[..10]);
    h.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&crate::random_bytes::<32>())
    }

    #[test]
    fn sign_verify_and_tamper() {
        let k = key();
        let binding = [7u8; 32];
        let p = Payload { op: OP_TOTP.into(), device: "mac".into(), ts: 1, totp: "123456".into(), ..Default::default() };
        let req = sign(&k, &binding, &p);
        assert_eq!(verify(&k.verifying_key(), &binding, &req).unwrap().totp, "123456");

        // A request captured on one TLS connection is useless on another.
        assert!(verify(&k.verifying_key(), &[8u8; 32], &req).is_err());

        let mut tampered = req.clone();
        let s = String::from_utf8(tampered.payload).unwrap().replace("123456", "654321");
        tampered.payload = s.into_bytes();
        assert!(verify(&k.verifying_key(), &binding, &tampered).is_err());

        let mut renamed = req.clone();
        renamed.device = "other".into();
        assert!(matches!(verify(&k.verifying_key(), &binding, &renamed), Err(WireError::DeviceMismatch)));

        assert!(verify(&key().verifying_key(), &binding, &req).is_err());
    }

    #[test]
    fn server_hello_binds_key_and_connection() {
        let server = key();
        let hello = server_hello(&server, &[1u8; 32]);
        verify_server_hello(&server.verifying_key(), &[1u8; 32], &hello).unwrap();
        // A relayed hello (different TLS connection) or a different server fails.
        assert!(verify_server_hello(&server.verifying_key(), &[2u8; 32], &hello).is_err());
        assert!(verify_server_hello(&key().verifying_key(), &[1u8; 32], &hello).is_err());
        // Device and server keys are not interchangeable.
        assert!(parse_public_key(&encode_server_key(&server.verifying_key())).is_err());
    }

    #[tokio::test]
    async fn frames_roundtrip_and_reject_oversize() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Response { ok: true, ..Default::default() }).await.unwrap();
        let r: Response = read_frame(&mut buf.as_slice()).await.unwrap();
        assert!(r.ok);

        let mut huge = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        huge.extend(vec![b' '; 8]);
        assert!(read_frame::<_, Response>(&mut huge.as_slice()).await.is_err());
    }

    #[test]
    fn public_key_encoding() {
        let k = key().verifying_key();
        let parsed = parse_public_key(&format!("  {}\n", encode_public_key(&k))).unwrap();
        assert_eq!(parsed, k);
        assert!(parse_public_key("rdpgate-ed25519:AAAA").is_err());
        assert_eq!(fingerprint(&k).len(), 24);
    }
}
