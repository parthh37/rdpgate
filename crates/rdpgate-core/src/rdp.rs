//! Reads the TLS certificate a Remote Desktop server presents, without
//! logging in. The server agent probes its own RDP service on 127.0.0.1 and
//! tells clients the fingerprint over the authenticated channel; the client
//! probes the RDP port it is about to use and refuses to launch Remote Desktop
//! if the two differ (someone is intercepting the RDP connection).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq)]
pub struct RdpCert {
    /// Lowercase hex SHA-256 of the DER certificate.
    pub sha256: String,
    /// Lowercase hex SHA-1, the "thumbprint" Windows dialogs show.
    pub sha1: String,
}

/// `ab12cd…` → `AB:12:CD:…`, the way certificate dialogs show it.
pub fn pretty(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("").to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":")
}

/// Accepts any certificate (we only want to read it) but still checks the
/// handshake signature, which proves the peer holds that certificate's key.
#[derive(Debug)]
struct ReadOnly(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for ReadOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// A TLS client config that does NOT check the certificate chain. Only for
/// connections whose peer is authenticated some other way: the RDP probe
/// (we only read the certificate) and the rdpgate protocol (the server proves
/// its pinned identity key over the channel binding).
pub fn unverified_client_config(tls13_only: bool, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls13_only { &[&rustls::version::TLS13] } else { &[&rustls::version::TLS13, &rustls::version::TLS12] };
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("ring supports TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReadOnly(algs)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

/// X.224 Connection Request asking for TLS or CredSSP (MS-RDPBCGR 2.2.1.1).
const CONNECTION_REQUEST: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, // TPKT, length 19
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ: PROTOCOL_SSL | PROTOCOL_HYBRID
];

async fn probe_inner(addr: SocketAddr) -> Result<RdpCert, String> {
    let mut tcp = TcpStream::connect(addr).await.map_err(|e| format!("cannot reach Remote Desktop at {addr}: {e}"))?;
    tcp.write_all(&CONNECTION_REQUEST).await.map_err(|e| e.to_string())?;
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await.map_err(|_| format!("{addr} closed the connection: not a Remote Desktop server?"))?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if hdr[0] != 3 || !(11..=512).contains(&len) {
        return Err(format!("{addr} is not a Remote Desktop server"));
    }
    let mut body = vec![0u8; len - 4];
    tcp.read_exact(&mut body).await.map_err(|e| e.to_string())?;
    if body.len() < 7 || body[1] & 0xf0 != 0xd0 {
        return Err(format!("{addr} is not a Remote Desktop server"));
    }
    let neg = body.get(7..15).ok_or("Remote Desktop is using legacy (non-TLS) security; enable NLA")?;
    let value = u32::from_le_bytes([neg[4], neg[5], neg[6], neg[7]]);
    match neg[0] {
        0x02 if value & 0x3 != 0 => {}
        0x02 => return Err("Remote Desktop is using legacy (non-TLS) security; enable NLA".into()),
        0x03 => return Err(format!("Remote Desktop refused TLS (failure code {value})")),
        _ => return Err(format!("{addr} sent an unexpected Remote Desktop reply")),
    }

    let cfg = unverified_client_config(false, &[]);
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::IpAddress(addr.ip().into()), tcp)
        .await
        .map_err(|e| format!("Remote Desktop TLS handshake failed: {e}"))?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("Remote Desktop presented no certificate")?;
    Ok(RdpCert { sha256: hex::encode(Sha256::digest(cert)), sha1: hex::encode(Sha1::digest(cert)) })
}

/// Connects to `addr`, negotiates TLS the way an RDP client does, records the
/// certificate and disconnects before any login.
pub async fn probe(addr: SocketAddr, timeout: Duration) -> Result<RdpCert, String> {
    tokio::time::timeout(timeout, probe_inner(addr))
        .await
        .map_err(|_| format!("Remote Desktop at {addr} did not answer in time"))?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A minimal RDP-like listener: answers the X.224 request selecting TLS,
    /// then completes a TLS handshake with a fresh self-signed certificate.
    pub async fn fake_rdp() -> (SocketAddr, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["rdp.test".to_string()]).unwrap().self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = ln.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 19];
                    if tcp.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let confirm = [
                        0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, //
                        0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, // RDP_NEG_RSP: PROTOCOL_SSL
                    ];
                    let _ = tcp.write_all(&confirm).await;
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        (addr, der)
    }

    #[tokio::test]
    async fn reads_the_certificate_of_an_rdp_listener() {
        let (addr, der) = fake_rdp().await;
        let got = probe(addr, Duration::from_secs(5)).await.unwrap();
        assert_eq!(got.sha256, hex::encode(Sha256::digest(&der)));
        assert_eq!(pretty("ab01").as_str(), "AB:01");
    }

    #[tokio::test]
    async fn rejects_something_that_is_not_rdp() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        });
        assert!(probe(addr, Duration::from_secs(5)).await.is_err());
    }
}
