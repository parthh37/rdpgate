//! The passkey web portal: sign in from any browser (the firewall then opens
//! for that browser's IP) and enroll new passkeys with a one-time link.

use crate::app::App;
use crate::config::valid_name;
use crate::state::{PasskeyEntry, now, token_hash};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HOST, HeaderValue, ORIGIN};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use webauthn_rs::prelude::*;

const LOGIN_HTML: &str = include_str!("../web/login.html");
const ENROLL_HTML: &str = include_str!("../web/enroll.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE_CSS: &str = include_str!("../web/style.css");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const MAX_BODY: usize = 64 * 1024;

type Resp = Response<Full<Bytes>>;

pub async fn serve(app: Arc<App>, tls: TlsStream<TcpStream>, peer: SocketAddr) {
    let svc = hyper::service::service_fn(move |req| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(route(&app, peer.ip().to_canonical(), req).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(64 * 1024)
        .serve_connection(TokioIo::new(tls), svc);
    // The portal only needs a few short requests; don't let idle connections linger.
    let _ = tokio::time::timeout(Duration::from_secs(60), conn).await;
}

fn reply(status: StatusCode, ctype: &'static str, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(ctype));
    r
}

fn json_reply(status: StatusCode, v: Value) -> Resp {
    reply(status, "application/json", serde_json::to_vec(&v).unwrap_or_default())
}

fn api_error(status: StatusCode, msg: &str) -> Resp {
    json_reply(status, json!({ "error": msg }))
}

fn not_found() -> Resp {
    reply(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", "not found")
}

fn harden(mut r: Resp) -> Resp {
    let h = r.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert("strict-transport-security", HeaderValue::from_static("max-age=31536000"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn route(app: &App, ip: IpAddr, req: Request<Incoming>) -> Resp {
    let (Some(public_host), Some(public_url)) = (&app.cfg.public_host, app.cfg.public_url()) else {
        return harden(not_found());
    };
    let host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    if !host.eq_ignore_ascii_case(public_host) {
        return harden(not_found());
    }
    let src = crate::limiter::source_key(ip);
    if !app.limiter.allowed(&src) {
        return harden(reply(StatusCode::TOO_MANY_REQUESTS, "text/plain; charset=utf-8", "too many attempts, try again later"));
    }
    let path = req.uri().path().to_string();
    let Some(rest) = path.strip_prefix(&app.cfg.portal_path) else {
        return harden(not_found());
    };
    let resp = match (req.method(), rest) {
        (&Method::GET, "") => reply(StatusCode::OK, "text/html; charset=utf-8", LOGIN_HTML),
        (&Method::GET, "enroll") => reply(StatusCode::OK, "text/html; charset=utf-8", ENROLL_HTML),
        (&Method::GET, "static/app.js") => reply(StatusCode::OK, "text/javascript; charset=utf-8", APP_JS),
        (&Method::GET, "static/style.css") => reply(StatusCode::OK, "text/css; charset=utf-8", STYLE_CSS),
        (&Method::POST, api) if api.starts_with("api/") => {
            // A cross-site page cannot forge both of these.
            let origin_ok = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) == Some(public_url.as_str());
            let json_ok = req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) == Some("application/json");
            if !origin_ok || !json_ok {
                return harden(api_error(StatusCode::FORBIDDEN, "forbidden"));
            }
            let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let (login_id, enroll_token, revoke_token) = (header("x-login-id"), header("x-enroll-token"), header("x-revoke-token"));
            let api = api.to_string();
            let body = match tokio::time::timeout(Duration::from_secs(10), Limited::new(req.into_body(), MAX_BODY).collect()).await {
                Ok(Ok(b)) => b.to_bytes(),
                Ok(Err(_)) => return harden(api_error(StatusCode::PAYLOAD_TOO_LARGE, "request too large")),
                Err(_) => return harden(api_error(StatusCode::REQUEST_TIMEOUT, "request timed out")),
            };
            match api.as_str() {
                "api/login/begin" => login_begin(app, &src).await,
                "api/login/finish" => login_finish(app, ip, &src, &login_id, &body).await,
                "api/revoke" => revoke(app, &src, &revoke_token).await,
                "api/enroll/begin" => enroll_begin(app, &src, &enroll_token, &body).await,
                "api/enroll/finish" => enroll_finish(app, &src, &enroll_token, &body).await,
                _ => not_found(),
            }
        }
        _ => not_found(),
    };
    harden(resp)
}

/// Counts a failure against the browser's address. The reason goes to the
/// log; the browser only learns that it failed.
fn web_fail(app: &App, src: &str, reason: &str) -> Resp {
    let ban = app.limiter.fail(src);
    crate::logln!("WEB-DENY src={src} reason={reason:?} ban={}s", ban.as_secs());
    api_error(StatusCode::FORBIDDEN, "Sign-in failed or the link has expired. Try again.")
}

// ---- sign in -------------------------------------------------------------

fn disabled() -> Resp {
    api_error(StatusCode::FORBIDDEN, "Browser sign-in is disabled on this server.")
}

async fn login_begin(app: &App, src: &str) -> Resp {
    let Some(webauthn) = &app.webauthn else { return disabled() };
    let st = match app.state().await {
        Ok(s) => s,
        Err(e) => {
            crate::logln!("ERROR state: {e}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error.");
        }
    };
    let passkeys = st.passkey_list();
    if passkeys.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "No passkeys are enrolled yet. On the server run: rdpgate-server passkey-enroll");
    }
    match webauthn.start_passkey_authentication(&passkeys) {
        Ok((options, state)) => {
            let id = rdpgate_core::random_token::<24>();
            app.logins.put(id.clone(), state, 120, src);
            json_reply(StatusCode::OK, json!({ "login_id": id, "options": options }))
        }
        Err(e) => {
            crate::logln!("ERROR start authentication: {e:?}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error.")
        }
    }
}

async fn login_finish(app: &App, ip: IpAddr, src: &str, login_id: &str, body: &[u8]) -> Resp {
    let Some(webauthn) = &app.webauthn else { return disabled() };
    let Some(state) = app.logins.take(login_id) else {
        return web_fail(app, src, "login: unknown or expired challenge");
    };
    let cred: PublicKeyCredential = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => return web_fail(app, src, &format!("login: parse: {e}")),
    };
    let result = match webauthn.finish_passkey_authentication(&cred, &state) {
        Ok(r) => r,
        Err(e) => return web_fail(app, src, &format!("login: verify: {e:?}")),
    };
    let t = now();
    // The passkey must still be enrolled now, not just when sign-in began.
    let name = app
        .update_state(move |st| {
            let p = st.passkeys.iter_mut().find(|p| p.passkey.cred_id() == result.cred_id()).ok_or("passkey was removed")?;
            p.passkey.update_credential(&result);
            p.last_used = Some(t);
            Ok(p.name.clone())
        })
        .await;
    let name = match name {
        Ok(n) => n,
        Err(e) => return web_fail(app, src, &format!("login: {e}")),
    };
    match app.grants.allow(ip, format!("passkey {name}")).await {
        Ok(g) => {
            app.limiter.reset(src);
            let cert = app.rdp_cert().await;
            json_reply(
                StatusCode::OK,
                json!({
                    "ip": ip.to_string(),
                    "expires": g.expires,
                    "hard_expires": g.hard_expires,
                    "rdp_host": app.cfg.public_host,
                    "rdp_port": app.cfg.rdp_port_for(ip),
                    "revoke_token": g.revoke_token,
                    "rdp_sha256": cert.as_ref().map(|c| rdpgate_core::rdp::pretty(&c.sha256)),
                    "rdp_sha1": cert.as_ref().map(|c| rdpgate_core::rdp::pretty(&c.sha1)),
                }),
            )
        }
        Err(e) => {
            crate::logln!("ERROR grant {ip}: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not open the firewall. See the server log.")
        }
    }
}

async fn revoke(app: &App, src: &str, token: &str) -> Resp {
    match app.grants.revoke_by_token(token).await {
        Some(ip) => json_reply(StatusCode::OK, json!({ "ok": true, "ip": ip.to_string() })),
        None => web_fail(app, src, "revoke: unknown token"),
    }
}

// ---- passkey enrollment -----------------------------------------------------

async fn enroll_begin(app: &App, src: &str, token: &str, body: &[u8]) -> Resp {
    let Some(webauthn) = &app.webauthn else { return disabled() };
    let name = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["name"].as_str().map(str::to_string)).unwrap_or_default();
    if !valid_name(&name) {
        return api_error(StatusCode::BAD_REQUEST, "Name the passkey with 1-32 letters, digits, dots, dashes or underscores.");
    }
    let st = match app.state().await {
        Ok(s) => s,
        Err(e) => {
            crate::logln!("ERROR state: {e}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error.");
        }
    };
    if !st.valid_enroll_token(token, now()) {
        return web_fail(app, src, "enroll: bad or expired token");
    }
    if st.passkeys.iter().any(|p| p.name == name) {
        return api_error(StatusCode::CONFLICT, "A passkey with that name already exists.");
    }
    let exclude: Vec<CredentialID> = st.passkeys.iter().map(|p| p.passkey.cred_id().clone()).collect();
    match webauthn.start_passkey_registration(st.user_id, &st.user_name, &st.user_name, Some(exclude)) {
        Ok((options, reg)) => {
            app.enrolls.put(token_hash(token), (name, reg), 300, src);
            json_reply(StatusCode::OK, serde_json::to_value(options).unwrap_or_default())
        }
        Err(e) => {
            crate::logln!("ERROR start registration: {e:?}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Server error.")
        }
    }
}

async fn enroll_finish(app: &App, src: &str, token: &str, body: &[u8]) -> Resp {
    let Some(webauthn) = &app.webauthn else { return disabled() };
    let Some((name, reg)) = app.enrolls.take(&token_hash(token)) else {
        return web_fail(app, src, "enroll: no registration in progress for this token");
    };
    let cred: RegisterPublicKeyCredential = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => return web_fail(app, src, &format!("enroll: parse: {e}")),
    };
    let passkey = match webauthn.finish_passkey_registration(&cred, &reg) {
        Ok(p) => p,
        Err(e) => return web_fail(app, src, &format!("enroll: verify: {e:?}")),
    };
    let (token_owned, name2) = (token.to_string(), name.clone());
    let saved = app
        .update_state(move |st| {
            let t = now();
            if !st.valid_enroll_token(&token_owned, t) {
                return Err("token expired".into());
            }
            if st.passkeys.iter().any(|p| p.name == name2) {
                return Err("name already exists".into());
            }
            if st.passkeys.iter().any(|p| p.passkey.cred_id() == passkey.cred_id()) {
                return Err("that authenticator is already enrolled".into());
            }
            st.consume_enroll_token(&token_owned, t);
            st.passkeys.push(PasskeyEntry { name: name2, added: t, last_used: None, passkey });
            Ok(())
        })
        .await;
    match saved {
        Ok(()) => {
            crate::logln!("PASSKEY added name={name:?} src={src}");
            json_reply(StatusCode::OK, json!({ "ok": true }))
        }
        Err(e) => web_fail(app, src, &format!("enroll: save: {e}")),
    }
}
