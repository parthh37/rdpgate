//! End-to-end: real servers on 127.0.0.1 with dry-run firewalls, fake RDP
//! listeners, and the real client library signing in over TLS 1.3.

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use rdpgate_client::{self as client, ClientConfig, RdpCheck};
use rdpgate_core::totp;
use rdpgate_server::app::{self, App};
use rdpgate_server::config::Config;
use rdpgate_server::firewall::DryRun;
use rdpgate_server::identity::Identity;
use rdpgate_server::state::{Device, Store, TotpState, now};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "gate.test";

struct Harness {
    dir: PathBuf,
    addr: SocketAddr,
    fw: Arc<DryRun>,
    secret: Vec<u8>,
    ca: PathBuf,
    card: String,
    rdp_sha256: String,
    app: Arc<App>,
    _stop: tokio::sync::watch::Sender<bool>,
}

fn write_web_certs(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "rdpgate test CA");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_string()]).unwrap().signed_by(&leaf_key, &ca).unwrap();
    let (ca_p, cert_p, key_p) = (dir.join("ca.pem"), dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&ca_p, ca.pem()).unwrap();
    std::fs::write(&cert_p, leaf.pem()).unwrap();
    std::fs::write(&key_p, leaf_key.serialize_pem()).unwrap();
    (ca_p, cert_p, key_p)
}

/// A minimal stand-in for Windows' RDP listener: answers the X.224 request
/// selecting TLS, then completes a TLS handshake with its own certificate.
/// Like Windows', it also answers on 127.0.0.1, where the server reads it.
async fn fake_rdp(ip: &str) -> (SocketAddr, String) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["rdp.test".to_string()]).unwrap().self_signed(&key).unwrap();
    let sha = hex::encode(Sha256::digest(cert.der()));
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let ln = tokio::net::TcpListener::bind(format!("{ip}:0")).await.unwrap();
    let addr = ln.local_addr().unwrap();
    let mut listeners = vec![ln];
    if addr.is_ipv6() {
        listeners.push(tokio::net::TcpListener::bind(("127.0.0.1", addr.port())).await.unwrap());
    }
    for ln in listeners {
        let acceptor = acceptor.clone();
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
                        0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
                    ];
                    let _ = tcp.write_all(&confirm).await;
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
    }
    (addr, sha)
}

async fn start() -> Harness {
    start_at("127.0.0.1").await.expect("127.0.0.1 is always there")
}

/// A server listening on `ip` only, or None when this machine can't (no IPv6).
async fn start_at(ip: &str) -> Option<Harness> {
    let ln = tokio::net::TcpListener::bind(format!("{ip}:0")).await.ok()?;
    start_with(ip, vec![ln]).await
}

/// A server on both [::1] and 127.0.0.1 (same port), like a dual-stack PC.
async fn start_dual_stack() -> Option<Harness> {
    let v6 = tokio::net::TcpListener::bind("[::1]:0").await.ok()?;
    let v4 = tokio::net::TcpListener::bind(("127.0.0.1", v6.local_addr().unwrap().port())).await.ok()?;
    start_with("[::1]", vec![v6, v4]).await
}

async fn start_with(ip: &str, listeners: Vec<tokio::net::TcpListener>) -> Option<Harness> {
    let ln = &listeners[0];
    rdpgate_server::install_crypto();
    let dir = std::env::temp_dir().join(format!("rdpgate-e2e-{}", rdpgate_core::random_token::<6>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (ca, cert, key) = write_web_certs(&dir);
    let (rdp_addr, rdp_sha256) = fake_rdp(ip).await;

    let mut cfg = Config::new(Some(HOST));
    cfg.tls.mode = "files".into();
    cfg.tls.cert_file = Some(cert);
    cfg.tls.key_file = Some(key);
    cfg.firewall = "dry-run".into();
    cfg.rdp_port = rdp_addr.port();
    cfg.rdp_public_port = rdp_addr.port();
    cfg.allow_private_sources = true; // everything here comes from 127.0.0.1
    cfg.data_dir = dir.clone();
    cfg.save(&dir).unwrap();

    let store = Store::new(&dir);
    store.init("owner").unwrap();
    let secret = totp::new_secret();
    let s2 = secret.clone();
    store
        .update(|st| {
            st.totp = Some(TotpState { secret: s2, last_step: 0 });
            Ok(())
        })
        .unwrap();

    let fw = Arc::new(DryRun::default());
    let card = Identity::load_or_create(&dir).unwrap().card(&cfg).encode();
    let app = App::new(cfg, fw.clone()).unwrap();
    let addr = ln.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let served = app.clone();
    tokio::spawn(async move { app::serve(served, listeners, &mut rx).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Some(Harness { dir, addr, fw, secret, ca, card, rdp_sha256, app, _stop: tx })
}

struct TestDevice {
    dir: PathBuf,
    cfg: ClientConfig,
    key: ed25519_dalek::SigningKey,
}

fn enroll(server_dir: &std::path::Path, name: &str, public_key: String) {
    Store::new(server_dir)
        .update(|st| {
            st.devices.retain(|d| d.name != name);
            st.devices.push(Device { name: name.into(), public_key, added: now(), last_auth: None, failed_codes: 0, auto: false, trust: None });
            Ok(())
        })
        .unwrap();
}

impl Harness {
    /// A client folder with its own device key and this server's card.
    /// Enrolls the device on the server if asked.
    fn device(&self, name: &str, enrolled: bool) -> TestDevice {
        let cdir = self.dir.join(format!("client-{name}-{}", rdpgate_core::random_token::<4>()));
        let id = client::create_device(&cdir, name, None, "test passphrase 123", false).unwrap();
        client::set_card(&cdir, &self.card).unwrap();
        if enrolled {
            enroll(&self.dir, name, id.public_key);
        }
        let mut cfg = client::load_config(&cdir).unwrap();
        cfg.connect_override = Some(self.addr);
        TestDevice { key: client::unlock(&cdir, "test passphrase 123").unwrap(), dir: cdir, cfg }
    }

    fn code(&self) -> String {
        totp::code(&self.secret, totp::step(now() as u64), 6)
    }

    fn allowed(&self) -> Vec<IpAddr> {
        self.fw.allowed.lock().unwrap().iter().copied().collect()
    }

    /// One raw HTTP/1.1 request to the portal; returns (status, body).
    async fn http(&self, method: &str, path: &str, host: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
        let mut roots = rustls::RootCertStore::empty();
        use rustls_pki_types::pem::PemObject;
        for c in rustls_pki_types::CertificateDer::pem_file_iter(&self.ca).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        let mut cc = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cc))
            .connect(rustls_pki_types::ServerName::try_from(HOST).unwrap(), tcp)
            .await
            .unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        let text = String::from_utf8_lossy(&out).to_string();
        let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        (status, body)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn desktop_sign_in_verifies_rdp_and_lock_closes_the_firewall() {
    let h = start().await;
    let d = h.device("mac", true);

    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    assert_eq!(grant.ip, "127.0.0.1");
    assert_eq!(h.allowed(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(grant.rdp_cert_sha256.as_deref(), Some(h.rdp_sha256.as_str()), "server vouches for its RDP cert");
    assert_eq!(client::verify_rdp(&grant).await.unwrap(), RdpCheck::Verified);
    assert_eq!(client::load_config(&d.dir).unwrap().last_known, Some(h.addr), "remembers where the server proved itself");

    let rdp = client::write_rdp_file(&d.dir, &d.cfg, &grant).unwrap();
    assert!(std::fs::read_to_string(rdp).unwrap().contains(&format!("full address:s:{}", grant.rdp_target())));

    // The same code cannot be used twice.
    let err = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.unwrap_err();
    assert!(err.contains("already-used"), "{err}");

    client::lock(&d.dir, &d.cfg, &d.key).await.expect("lock succeeds");
    assert!(h.allowed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn impostor_server_is_refused_before_anything_is_sent() {
    let real = start().await;
    let impostor = start().await; // a different server identity
    let d = real.device("mac", true);
    // Worst case: the same device key is enrolled on the impostor too.
    enroll(&impostor.dir, "mac", client::identity(&d.dir).unwrap().public_key);

    let mut cfg = d.cfg.clone();
    cfg.connect_override = Some(impostor.addr); // e.g. a DNS hijack or a stale IP
    cfg.last_known = None;
    let err = client::sign_in(&d.dir, &cfg, &d.key, &impostor.code()).await.unwrap_err();
    assert!(err.contains("NOT your server"), "{err}");
    assert!(impostor.allowed().is_empty());
    let st = Store::new(&impostor.dir).load().unwrap();
    assert_eq!(st.totp.unwrap().last_step, 0, "the impostor never received a code");
}

#[tokio::test(flavor = "multi_thread")]
async fn intercepted_rdp_endpoint_is_refused() {
    let h = start().await;
    let d = h.device("mac", true);
    let mut grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.unwrap();
    // Someone else's RDP listener answers on the RDP port.
    let (mitm, _) = fake_rdp("127.0.0.1").await;
    grant.rdp_port = mitm.port();
    let err = client::verify_rdp(&grant).await.unwrap_err();
    assert!(err.contains("STOP"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_and_impostor_devices_are_denied() {
    let h = start().await;

    let stranger = h.device("stranger", false);
    let err = client::sign_in(&stranger.dir, &stranger.cfg, &stranger.key, &h.code()).await.unwrap_err();
    assert!(err.contains("refused"), "{err}");

    // Enroll "mac", then try to sign in as "mac" with a different key.
    let mac = h.device("mac", true);
    let other = h.device("other", false);
    let err = client::sign_in(&mac.dir, &mac.cfg, &other.key, &h.code()).await.unwrap_err();
    assert!(err.contains("refused"), "{err}");

    let err = client::sign_in(&mac.dir, &mac.cfg, &mac.key, "000000").await.unwrap_err();
    assert!(err.to_lowercase().contains("wrong"), "{err}");

    assert!(h.allowed().is_empty(), "nothing may be opened by failed attempts");
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_wrong_codes_lock_the_device() {
    let h = start().await;
    let mac = h.device("mac", true);
    let mut locked = false;
    for _ in 0..12 {
        // Pretend each guess comes from a different address, as a botnet's
        // would: the per-IP limiter can't help, the per-device lock must.
        h.app.limiter.reset("127.0.0.1");
        let err = client::sign_in(&mac.dir, &mac.cfg, &mac.key, "000000").await.unwrap_err();
        if err.contains("locked") {
            locked = true;
            break;
        }
    }
    assert!(locked, "device never locked");
    // Even the right code is refused until an administrator unlocks it.
    h.app.limiter.reset("127.0.0.1");
    let err = client::sign_in(&mac.dir, &mac.cfg, &mac.key, &h.code()).await.unwrap_err();
    assert!(err.contains("locked"), "{err}");
    assert!(h.allowed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_failures_silence_the_source() {
    let h = start().await;
    let stranger = h.device("stranger", false);
    let mut silenced = false;
    for _ in 0..30 {
        match client::sign_in(&stranger.dir, &stranger.cfg, &stranger.key, &h.code()).await {
            Err(e) if e.contains("refused") => continue,
            Err(_) => {
                silenced = true; // dropped before TLS: no reply at all
                break;
            }
            Ok(_) => panic!("stranger signed in"),
        }
    }
    assert!(silenced, "the limiter never kicked in");
}

#[tokio::test(flavor = "multi_thread")]
async fn web_portal_guards() {
    let h = start().await;
    let portal = Config::load(&h.dir).unwrap().portal_path;
    let origin = format!("https://{HOST}");
    let json = [("Content-Type", "application/json"), ("Origin", origin.as_str())];

    let (s, body) = h.http("GET", &portal, HOST, &[], "").await;
    assert_eq!(s, 200);
    assert!(body.contains("Sign in with passkey"));

    // Anything outside the secret portal path, or for another Host, is a 404.
    assert_eq!(h.http("GET", "/", HOST, &[], "").await.0, 404);
    assert_eq!(h.http("GET", &portal, "evil.example", &[], "").await.0, 404);

    // POSTs need our Origin and a JSON content type (CSRF protection).
    assert_eq!(h.http("POST", &format!("{portal}api/login/begin"), HOST, &[], "{}").await.0, 403);

    // No passkeys yet: sign-in explains how to add one.
    let (s, body) = h.http("POST", &format!("{portal}api/login/begin"), HOST, &json, "{}").await;
    assert_eq!(s, 400, "{body}");
    assert!(body.contains("passkey-enroll"));

    // Enrollment needs a valid one-time token.
    let mut with_token = json.to_vec();
    with_token.push(("X-Enroll-Token", "not-a-real-token"));
    let (s, _) = h.http("POST", &format!("{portal}api/enroll/begin"), HOST, &with_token, r#"{"name":"mac"}"#).await;
    assert_eq!(s, 403);
    assert!(h.allowed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn passkey_enroll_then_browser_sign_in_and_close() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    let h = start().await;
    let portal = Config::load(&h.dir).unwrap().portal_path;
    let origin = format!("https://{HOST}");
    let origin_url = url::Url::parse(&origin).unwrap();
    let json = [("Content-Type", "application/json"), ("Origin", origin.as_str())];
    let mut authenticator = SoftPasskey::new(true);

    // 1. One-time enrollment link, as printed by `rdpgate-server passkey-enroll`.
    let token = rdpgate_core::random_token::<24>();
    Store::new(&h.dir)
        .update(|st| {
            st.enroll_tokens.push(rdpgate_server::state::EnrollToken {
                hash: rdpgate_server::state::token_hash(&token),
                expires: now() + 600,
            });
            Ok(())
        })
        .unwrap();
    let mut hdr = json.to_vec();
    hdr.push(("X-Enroll-Token", token.as_str()));
    let (s, body) = h.http("POST", &format!("{portal}api/enroll/begin"), HOST, &hdr, r#"{"name":"touchid"}"#).await;
    assert_eq!(s, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["publicKey"]["rp"]["id"], HOST);
    let ccr: CreationChallengeResponse = serde_json::from_value(v).unwrap();
    let reg = authenticator.do_registration(origin_url.clone(), ccr).expect("authenticator registers");
    let (s, body) = h.http("POST", &format!("{portal}api/enroll/finish"), HOST, &hdr, &serde_json::to_string(&reg).unwrap()).await;
    assert_eq!(s, 200, "{body}");
    let st = Store::new(&h.dir).load().unwrap();
    assert_eq!(st.passkeys.len(), 1);
    assert!(st.enroll_tokens.is_empty(), "the link must be single use");
    let (s, _) = h.http("POST", &format!("{portal}api/enroll/begin"), HOST, &hdr, r#"{"name":"again"}"#).await;
    assert_eq!(s, 403, "a used enrollment link must not work twice");

    // 2. Browser sign-in opens the firewall for the browser's address.
    let (s, body) = h.http("POST", &format!("{portal}api/login/begin"), HOST, &json, "{}").await;
    assert_eq!(s, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let login_id = v["login_id"].as_str().unwrap().to_string();
    let rcr: RequestChallengeResponse = serde_json::from_value(v["options"].clone()).unwrap();
    let assertion = authenticator.do_authentication(origin_url, rcr).expect("authenticator signs");
    let assertion = serde_json::to_string(&assertion).unwrap();
    let mut hdr = json.to_vec();
    hdr.push(("X-Login-ID", login_id.as_str()));
    let (s, body) = h.http("POST", &format!("{portal}api/login/finish"), HOST, &hdr, &assertion).await;
    assert_eq!(s, 200, "{body}");
    let g: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(g["ip"], "127.0.0.1");
    assert_eq!(g["rdp_sha256"], rdpgate_core::rdp::pretty(&h.rdp_sha256), "page shows the RDP certificate to compare");
    assert_eq!(h.allowed(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);

    // 3. The same signed challenge cannot be replayed.
    let (s, _) = h.http("POST", &format!("{portal}api/login/finish"), HOST, &hdr, &assertion).await;
    assert_eq!(s, 403);

    // 4. "Close access now" on the page revokes the grant.
    let revoke = g["revoke_token"].as_str().unwrap();
    let mut hdr = json.to_vec();
    hdr.push(("X-Revoke-Token", revoke));
    let (s, body) = h.http("POST", &format!("{portal}api/revoke"), HOST, &hdr, "{}").await;
    assert_eq!(s, 200, "{body}");
    assert!(h.allowed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn desktop_sign_in_over_ipv6() {
    let Some(h) = start_at("[::1]").await else {
        eprintln!("skipped: no IPv6 on this machine");
        return;
    };
    let d = h.device("mac6", true);

    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in over IPv6 succeeds");
    assert_eq!(grant.ip, "::1");
    assert_eq!(h.allowed(), vec!["::1".parse::<IpAddr>().unwrap()], "the grant is for the IPv6 address");
    assert_eq!(client::verify_rdp(&grant).await.unwrap(), RdpCheck::Verified, "Remote Desktop checked over IPv6 too");
    let rdp = client::write_rdp_file(&d.dir, &d.cfg, &grant).unwrap();
    let text = std::fs::read_to_string(rdp).unwrap();
    assert!(text.contains(&format!("full address:s:[::1]:{}", grant.rdp_port)), "{text}");

    client::lock(&d.dir, &d.cfg, &d.key).await.expect("lock succeeds");
    assert!(h.allowed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_in_over_ipv6_opens_ipv4_too_and_lock_closes_both() {
    let Some(h) = start_dual_stack().await else {
        eprintln!("skipped: no IPv6 on this machine");
        return;
    };
    let d = h.device("dual", true);
    // Found by name, like a dual-stack PC with A and AAAA records.
    let mut card = rdpgate_core::beacon::Card::decode(&h.card).unwrap();
    (card.host, card.port) = (Some("localhost".into()), h.addr.port());
    client::set_card(&d.dir, &card.encode()).unwrap();
    let mut cfg = client::load_config(&d.dir).unwrap();
    cfg.connect_override = None;
    if !tokio::net::lookup_host(("localhost", 1)).await.unwrap().any(|a| a.is_ipv4()) {
        eprintln!("skipped: localhost has no IPv4 address here");
        return;
    }

    let grant = client::sign_in(&d.dir, &cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    assert_eq!(grant.ip, "::1 and 127.0.0.1", "IPv6 first, then IPv4 with the link token");
    let mut allowed = h.allowed();
    allowed.sort();
    assert_eq!(allowed, vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);
    let who: Vec<String> = h.app.grants.list().await.into_iter().map(|g| g.who).collect();
    assert!(who.contains(&"device dual with ::1".to_string()), "{who:?}");
    assert!(grant.hard_expires.is_some_and(|t| t > grant.expires), "the app learns the longest session");

    let cfg = client::load_config(&d.dir).unwrap();
    client::lock(&d.dir, &cfg, &d.key).await.expect("lock succeeds");
    assert!(h.allowed().is_empty(), "locking closes both addresses");
}


/// Turns auto mode on for `name` and gives the client a fixed hardware digest.
fn auto_mode(h: &Harness, d: &mut TestDevice, name: &str, hw: &str) {
    rdpgate_server::admin::set_device_auto(&h.dir, name, true).unwrap();
    d.cfg.hw_override = Some(hw.into());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_auto_mode_nothing_is_remembered() {
    let h = start().await;
    let mut d = h.device("mac", true);
    d.cfg.hw_override = Some("hw-1".into());
    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    assert!(grant.auto.is_none(), "auto mode is off unless the server turns it on");
    assert!(matches!(client::follow(&d.dir, &d.cfg, &d.key, &grant).await, Ok(client::Followed::Ended(_))));
    // A made-up token is refused: the server decides, not the app.
    let err = client::open(&d.dir, &d.cfg, &d.key, "made-up").await.unwrap_err();
    assert!(err.contains("Auto mode is off"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_remembered_computer_connects_without_a_code_until_its_hardware_changes() {
    let h = start().await;
    let mut d = h.device("mac", true);
    auto_mode(&h, &mut d, "mac", "hw-1");
    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    let token = grant.auto.clone().expect("the server remembers this computer");
    assert!(rdpgate_server::admin::devices(&h.dir).unwrap()[0].remembered.is_some());

    // Same address: nothing to follow.
    assert!(matches!(client::follow(&d.dir, &d.cfg, &d.key, &grant).await, Ok(client::Followed::Same)));

    // Closing access doesn't forget the computer: it connects again, no code.
    client::lock(&d.dir, &d.cfg, &d.key).await.expect("lock succeeds");
    assert!(h.allowed().is_empty());
    assert!(matches!(client::follow(&d.dir, &d.cfg, &d.key, &grant).await, Ok(client::Followed::Closed)), "following never opens");
    let again = client::open(&d.dir, &d.cfg, &d.key, &token).await.expect("opens without a code");
    assert_eq!(h.allowed(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(again.rdp_cert_sha256.as_deref(), Some(h.rdp_sha256.as_str()));
    assert_eq!(client::verify_rdp(&again).await.unwrap(), RdpCheck::Verified);

    // Also after the service restarts (grants are in memory, being remembered isn't).
    h.app.grants.shutdown().await;
    let restarted = App::new(Config::load(&h.dir).unwrap(), h.fw.clone()).unwrap();
    assert!(restarted.state().await.unwrap().device("mac").unwrap().trust.is_some());

    // The wrong token, or another computer with the right key, gets nothing.
    let err = client::open(&d.dir, &d.cfg, &d.key, "made-up").await.unwrap_err();
    assert!(err.contains("signed in with a code again"), "{err}");
    let mut moved_disk = d.cfg.clone();
    moved_disk.hw_override = Some("hw-2".into());
    let err = client::open(&d.dir, &moved_disk, &d.key, &token).await.unwrap_err();
    assert!(err.contains("hardware changed") && err.contains("passphrase and code"), "{err}");
    // That forgets it on the server: even the original hardware needs a code now.
    assert!(client::open(&d.dir, &d.cfg, &d.key, &token).await.unwrap_err().contains("isn't remembered"));
}

#[tokio::test(flavor = "multi_thread")]
async fn turning_auto_mode_off_forgets_the_computer() {
    let h = start().await;
    let mut d = h.device("mac", true);
    auto_mode(&h, &mut d, "mac", "hw-1");
    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    rdpgate_server::admin::set_device_auto(&h.dir, "mac", false).unwrap();
    let Ok(client::Followed::Ended(e)) = client::follow(&d.dir, &d.cfg, &d.key, &grant).await else { panic!() };
    assert!(e.contains("Auto mode is off"), "{e}");
    rdpgate_server::admin::set_device_auto(&h.dir, "mac", true).unwrap();
    let err = client::open(&d.dir, &d.cfg, &d.key, grant.auto.as_deref().unwrap()).await.unwrap_err();
    assert!(err.contains("isn't remembered"), "turned back on, it still needs a code once: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_mode_moves_access_when_this_computers_address_changes() {
    let Some(h) = start_dual_stack().await else {
        eprintln!("skipped: no IPv6 on this machine");
        return;
    };
    let mut d = h.device("mac", true);
    auto_mode(&h, &mut d, "mac", "hw-1");
    // Sign in from 127.0.0.1…
    d.cfg.connect_override = Some(SocketAddr::new("127.0.0.1".parse().unwrap(), h.addr.port()));
    let grant = client::sign_in(&d.dir, &d.cfg, &d.key, &h.code()).await.expect("sign-in succeeds");
    assert_eq!(h.allowed(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);

    // …then this computer turns up at ::1 instead (as the server sees it).
    let at_v6 = client::Grant { server_addr: h.addr, ..grant.clone() };
    let Ok(client::Followed::Moved(moved)) = client::follow(&d.dir, &d.cfg, &d.key, &at_v6).await else { panic!("should move") };
    assert_eq!(moved.source, Some("::1".parse().unwrap()));
    assert_eq!(h.allowed(), vec!["::1".parse::<IpAddr>().unwrap()], "the old address is closed");
    assert_eq!(moved.hard_expires, grant.hard_expires, "moving doesn't extend the session");
    assert_eq!(moved.auto, grant.auto);
    assert_eq!(client::verify_rdp(&moved).await.unwrap(), RdpCheck::Verified);

    // And from there on it's the same place again.
    assert!(matches!(client::follow(&d.dir, &d.cfg, &d.key, &moved).await, Ok(client::Followed::Same)));
}
