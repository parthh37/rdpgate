//! `<data dir>/state.json`: enrolled devices, passkeys and the TOTP secret.
//!
//! The admin CLI and the running service share this file through [`Store`],
//! which takes an exclusive OS file lock around every read-modify-write. That
//! is what makes `rdpgate-server device-remove` effective on the live service
//! immediately, without any IPC.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{Passkey, Uuid};

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// WebAuthn user handle for the one owner of this server.
    pub user_id: Uuid,
    pub user_name: String,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enroll_tokens: Vec<EnrollToken>,
    /// Setup left Remote Desktop reachable as it was, so installing over RDP
    /// doesn't cut the installer off. The service locks it down once someone
    /// has signed in and connected through RDP Gate (see `protect`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub protection_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    /// `rdpgate-ed25519:<base64>`
    pub public_key: String,
    pub added: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_auth: Option<i64>,
    /// Wrong 6-digit codes in a row. At MAX_FAILED_CODES the device is locked
    /// until `rdpgate-server device-unlock`, whatever the source address.
    #[serde(default)]
    pub failed_codes: u32,
}

pub const MAX_FAILED_CODES: u32 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyEntry {
    pub name: String,
    pub added: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<i64>,
    pub passkey: Passkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpState {
    #[serde(with = "rdpgate_core::b64")]
    pub secret: Vec<u8>,
    pub last_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollToken {
    /// SHA-256 of the token, hex. The token itself is never stored.
    pub hash: String,
    pub expires: i64,
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl State {
    pub fn device(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    pub fn passkey_list(&self) -> Vec<Passkey> {
        self.passkeys.iter().map(|p| p.passkey.clone()).collect()
    }

    pub fn valid_enroll_token(&self, token: &str, now: i64) -> bool {
        if token.is_empty() {
            return false;
        }
        let h = token_hash(token);
        self.enroll_tokens.iter().any(|t| now < t.expires && bool::from(t.hash.as_bytes().ct_eq(h.as_bytes())))
    }

    /// Removes `token` and anything expired.
    pub fn consume_enroll_token(&mut self, token: &str, now: i64) {
        let h = token_hash(token);
        self.enroll_tokens.retain(|t| now < t.expires && !bool::from(t.hash.as_bytes().ct_eq(h.as_bytes())));
    }
}

#[derive(Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(data_dir: &Path) -> Self {
        Store { path: data_dir.join("state.json") }
    }

    /// Exclusive lock, released when the File is dropped. Gives up after a
    /// few seconds rather than hanging forever if something holds it.
    fn lock(&self) -> std::io::Result<File> {
        let f = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(self.path.with_extension("json.lock"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match f.try_lock() {
                Ok(()) => return Ok(f),
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "state.json is locked by another process"));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
        }
    }

    /// Creates a fresh state file; refuses to overwrite one.
    pub fn init(&self, user_name: &str) -> Result<bool, String> {
        let _l = self.lock().map_err(|e| e.to_string())?;
        if self.path.exists() {
            return Ok(false);
        }
        let s = State {
            user_id: Uuid::new_v4(),
            user_name: user_name.into(),
            devices: vec![],
            passkeys: vec![],
            totp: None,
            enroll_tokens: vec![],
            protection_pending: false,
        };
        self.write(&s)?;
        Ok(true)
    }

    pub fn load(&self) -> Result<State, String> {
        let _l = self.lock().map_err(|e| format!("lock state: {e}"))?;
        self.read()
    }

    /// Applies `f` atomically; if it returns an error nothing is written.
    pub fn update<T>(&self, f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
        let _l = self.lock().map_err(|e| format!("lock state: {e}"))?;
        let mut s = self.read()?;
        let out = f(&mut s)?;
        self.write(&s)?;
        Ok(out)
    }

    fn read(&self) -> Result<State, String> {
        let raw = std::fs::read(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        serde_json::from_slice(&raw).map_err(|e| format!("state.json: {e}"))
    }

    /// Temp file + rename, so a crash never leaves a half-written state file.
    fn write(&self, s: &State) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension(format!("tmp-{}", rdpgate_core::random_token::<6>()));
        rdpgate_core::keystore::write_private(&tmp, &json).map_err(|e| e.to_string())?;
        // Windows may briefly refuse the rename while antivirus scans the file.
        let mut tries = 0;
        loop {
            match std::fs::rename(&tmp, &self.path) {
                Ok(()) => return Ok(()),
                Err(e) if tries >= 20 => {
                    std::fs::remove_file(&tmp).ok();
                    return Err(format!("save state: {e}"));
                }
                Err(_) => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }
}
