//! Desktop sign-in over `rdpgate/1`: the server proves its identity first,
//! then the device signs a request with a 6-digit code, and the result is a
//! firewall opening for the connection's source address.

use crate::app::App;
use crate::grants::{Grant, Renewed};
use crate::state::{MAX_FAILED_CODES, now};
use rdpgate_core::wire::{self, OP_FOLLOW, OP_LINK, OP_REOPEN, OP_REVOKE, OP_TOTP, Request, Response};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

const PREAUTH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CLOCK_SKEW: u64 = 120;

pub async fn handle(app: Arc<App>, mut tls: TlsStream<TcpStream>, peer: SocketAddr) {
    let ip = peer.ip().to_canonical();
    let src = crate::limiter::source_key(ip);
    let resp = match tokio::time::timeout(PREAUTH_TIMEOUT, process(&app, &mut tls, ip, &src)).await {
        Ok(r) => r,
        Err(_) => deny(&app, &src, "", "timed out"),
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), wire::write_frame(&mut tls, &resp)).await;
    let _ = tls.shutdown().await;
}

/// Counts a failure against the source and returns a generic refusal.
fn deny(app: &App, src: &str, device: &str, reason: &str) -> Response {
    let ban = app.limiter.fail(src);
    let device: String = device.chars().take(40).collect();
    crate::logln!("DENY src={src} device={device:?} reason={reason:?} ban={}s", ban.as_secs());
    Response::error("denied")
}

/// Refuses a proven device without counting a failure, with a useful message.
fn reject(src: &str, device: &str, reason: &str) -> Response {
    crate::logln!("REJECT src={src} device={device:?} reason={reason:?}");
    Response::error(reason)
}

async fn process(app: &App, tls: &mut TlsStream<TcpStream>, ip: IpAddr, src: &str) -> Response {
    let conn = tls.get_ref().1;
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return deny(app, src, "", "TLS 1.3 required");
    }
    let binding = match conn.export_keying_material([0u8; wire::EKM_LEN], wire::EKM_LABEL, None) {
        Ok(b) => b,
        Err(e) => return deny(app, src, "", &format!("keying material: {e}")),
    };
    // Prove who we are before the client says anything. The signature covers
    // this connection's keying material, so it can't be replayed or relayed.
    if wire::write_frame(tls, &wire::server_hello(&app.identity.server, &binding)).await.is_err() {
        return Response::error("denied");
    }
    let req: Request = match wire::read_frame(tls).await {
        Ok(r) => r,
        Err(_) => return deny(app, src, "", "bad frame"),
    };
    let st = match app.state().await {
        Ok(s) => s,
        Err(e) => {
            crate::logln!("ERROR state: {e}");
            return Response::error("denied");
        }
    };
    let Some(dev) = st.device(&req.device) else {
        return deny(app, src, &req.device, "unknown device");
    };
    let Ok(key) = wire::parse_public_key(&dev.public_key) else {
        return deny(app, src, &dev.name, "stored public key is invalid");
    };
    let p = match wire::verify(&key, &binding, &req) {
        Ok(p) => p,
        Err(e) => return deny(app, src, &dev.name, &e.to_string()),
    };
    if (now() as u64).abs_diff(p.ts as u64) > MAX_CLOCK_SKEW {
        return deny(app, src, &dev.name, "clock skew: fix the time on the client or server");
    }

    // The request provably comes from an enrolled device from here on.
    let name = dev.name.clone();
    match p.op.as_str() {
        OP_TOTP => sign_in(app, ip, src, name, p.totp).await,
        OP_REVOKE => {
            app.grants.revoke(ip, &format!("locked by device {name}")).await;
            Response { ok: true, ip: Some(ip.to_string()), ..Default::default() }
        }
        OP_LINK => link(app, ip, src, name, p.link).await,
        OP_FOLLOW | OP_REOPEN => {
            if !dev.auto {
                return reject(src, &name, "auto mode is off for this computer on the server; sign in with a code");
            }
            if dev.failed_codes >= MAX_FAILED_CODES {
                return reject(src, &name, "this computer is locked after too many wrong codes");
            }
            renew(app, ip, src, name, p.auto, p.op == OP_REOPEN).await
        }
        _ => deny(app, src, &name, "unknown op"),
    }
}

enum Check {
    Ok { auto: bool },
    BadCode,
    Locked,
    Gone,
    NoTotp,
}

async fn sign_in(app: &App, ip: IpAddr, src: &str, device: String, code: String) -> Response {
    if !app.cfg.desktop_login {
        return reject(src, &device, "desktop sign-in is disabled on this server");
    }
    let t = now();
    let dev = device.clone();
    // One locked read-modify-write: the device must still exist, must not be
    // locked, and the code must be new. Wrong codes are counted per device.
    let checked = app
        .update_state(move |st| {
            let Some(totp) = st.totp.clone() else { return Ok(Check::NoTotp) };
            let Some(d) = st.devices.iter_mut().find(|d| d.name == dev) else { return Ok(Check::Gone) };
            if d.failed_codes >= MAX_FAILED_CODES {
                return Ok(Check::Locked);
            }
            match rdpgate_core::totp::validate(&totp.secret, &code, t as u64, totp.last_step) {
                Some(step) => {
                    d.failed_codes = 0;
                    d.last_auth = Some(t);
                    let auto = d.auto;
                    if let Some(s) = st.totp.as_mut() {
                        s.last_step = step;
                    }
                    Ok(Check::Ok { auto })
                }
                None => {
                    d.failed_codes += 1;
                    Ok(if d.failed_codes >= MAX_FAILED_CODES { Check::Locked } else { Check::BadCode })
                }
            }
        })
        .await;
    let auto = match checked {
        Ok(Check::Ok { auto }) => auto,
        Ok(Check::BadCode) => {
            let r = deny(app, src, &device, "wrong or already-used code");
            return Response { error: Some("wrong or already-used code".into()), ..r };
        }
        Ok(Check::Locked) => {
            crate::logln!("LOCKED device={device:?} after {MAX_FAILED_CODES} wrong codes");
            return reject(
                src,
                &device,
                &format!("this computer is locked after too many wrong codes; on the server run: rdpgate-server device-unlock {device}"),
            );
        }
        Ok(Check::Gone) => return deny(app, src, &device, "device was removed"),
        Ok(Check::NoTotp) => {
            return reject(src, &device, "6-digit codes are not set up on the server yet (run: rdpgate-server totp-setup)");
        }
        Err(e) => {
            crate::logln!("ERROR state: {e}");
            return Response::error("server error");
        }
    };
    match app.grants.allow(ip, format!("device {device}")).await {
        Ok(g) => {
            app.limiter.reset(src);
            let auto = if auto { Some(app.grants.start_auto(&g).await) } else { None };
            Response { auto, ..opened(app, ip, g).await }
        }
        Err(e) => {
            crate::logln!("ERROR grant {ip}: {e}");
            reject(src, &device, &format!("could not open the firewall: {e}"))
        }
    }
}

/// The answer to a sign-in that opened `g` for `ip`.
async fn opened(app: &App, ip: IpAddr, g: Grant) -> Response {
    Response {
        ok: true,
        ip: Some(ip.to_string()),
        expires: Some(g.expires),
        hard_expires: Some(g.hard_expires),
        rdp_port: Some(app.cfg.rdp_port_for(ip)),
        rdp_cert_sha256: app.rdp_cert().await.map(|c| c.sha256),
        link: g.link.map(|(token, _)| token),
        ..Default::default()
    }
}

/// Auto mode: a computer that signed in with a code earlier presents its
/// auto token from wherever it is now. The device signature proves who it
/// is; the token proves that sign-in, so no new code is needed.
async fn renew(app: &App, ip: IpAddr, src: &str, device: String, token: String, reopen: bool) -> Response {
    if !app.cfg.desktop_login {
        return reject(src, &device, "desktop sign-in is disabled on this server");
    }
    match app.grants.renew(&token, ip, &format!("device {device}"), reopen).await {
        // Asked every few seconds: keep it cheap and quiet.
        Ok((g, Renewed::Same)) => Response {
            ok: true,
            ip: Some(ip.to_string()),
            expires: Some(g.expires),
            hard_expires: Some(g.hard_expires),
            rdp_port: Some(app.cfg.rdp_port_for(ip)),
            auto: Some(token),
            ..Default::default()
        },
        Ok((g, _)) => Response { auto: Some(token), ..opened(app, ip, g).await },
        Err(e) if e == wire::CLOSED => Response::error(e),
        Err(e) => reject(src, &device, &e),
    }
}

/// A device that just signed in over IPv6 opens its IPv4 address too (or the
/// other way round). The device signature proves who it is; the one-time
/// token from that sign-in stands in for the code it already gave.
async fn link(app: &App, ip: IpAddr, src: &str, device: String, token: String) -> Response {
    if !app.cfg.desktop_login {
        return reject(src, &device, "desktop sign-in is disabled on this server");
    }
    match app.grants.link(&token, ip, &format!("device {device}")).await {
        Ok(g) => Response {
            ok: true,
            ip: Some(ip.to_string()),
            expires: Some(g.expires),
            rdp_port: Some(app.cfg.rdp_port_for(ip)),
            ..Default::default()
        },
        Err(e) => {
            crate::logln!("REJECT src={src} device={device:?} reason={:?}", format!("link: {e}"));
            Response::error("could not open this address too")
        }
    }
}
