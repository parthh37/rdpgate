//! Keeps a device's Ed25519 private key encrypted at rest.
//!
//! The 32-byte seed is sealed with XChaCha20-Poly1305 under a key derived from
//! the user's passphrase with Argon2id. A stolen key file is useless without
//! the passphrase, and every offline guess costs 64 MiB of memory.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

const AAD_PREFIX: &[u8] = b"rdpgate-device-key-v1";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("wrong passphrase or corrupted key file")]
    WrongPassphrase,
    #[error("unsupported key file parameters")]
    Unsupported,
    #[error("key file: {0}")]
    Io(#[from] std::io::Error),
    #[error("key file: {0}")]
    Json(#[from] serde_json::Error),
}

/// On-disk JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u32,
    pub kdf: String,
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
    /// In clear so the fingerprint can be shown without the passphrase.
    #[serde(with = "crate::b64")]
    pub public_key: Vec<u8>,
}

fn derive(pass: &[u8], salt: &[u8], t: u32, m: u32, p: u32) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let params = Params::new(m, t, p, Some(32)).map_err(|_| KeyError::Unsupported)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass, salt, out.as_mut())
        .map_err(|_| KeyError::Unsupported)?;
    Ok(out)
}

impl KeyFile {
    /// Encrypts `key` under `passphrase`.
    pub fn seal(key: &SigningKey, passphrase: &[u8]) -> Result<Self, KeyError> {
        let mut f = KeyFile {
            version: 1,
            kdf: "argon2id".into(),
            salt: crate::random_bytes::<16>().to_vec(),
            time_cost: 3,
            memory_kib: 64 * 1024,
            parallelism: 4,
            nonce: crate::random_bytes::<24>().to_vec(),
            ciphertext: Vec::new(),
            public_key: key.verifying_key().as_bytes().to_vec(),
        };
        let k = derive(passphrase, &f.salt, f.time_cost, f.memory_kib, f.parallelism)?;
        let aead = XChaCha20Poly1305::new_from_slice(k.as_ref()).map_err(|_| KeyError::Unsupported)?;
        let nonce = XNonce::try_from(f.nonce.as_slice()).map_err(|_| KeyError::Unsupported)?;
        let seed = Zeroizing::new(key.to_bytes());
        f.ciphertext = aead
            .encrypt(&nonce, Payload { msg: seed.as_ref(), aad: &f.aad() })
            .map_err(|_| KeyError::Unsupported)?;
        Ok(f)
    }

    /// The AAD binds the ciphertext to its public key, so editing the public
    /// key field is detected. Changing the KDF parameters changes the derived
    /// key, so decryption fails anyway.
    fn aad(&self) -> Vec<u8> {
        [AAD_PREFIX, self.public_key.as_slice()].concat()
    }

    /// Decrypts the key and checks it matches the stored public key.
    pub fn open(&self, passphrase: &[u8]) -> Result<SigningKey, KeyError> {
        // Bounds on both sides: too weak is unsafe, too strong is a cheap way
        // to make the app hang (a tampered key file).
        if self.version != 1
            || self.kdf != "argon2id"
            || !(19 * 1024..=1024 * 1024).contains(&self.memory_kib)
            || !(1..=20).contains(&self.time_cost)
            || !(1..=16).contains(&self.parallelism)
        {
            return Err(KeyError::Unsupported);
        }
        let k = derive(passphrase, &self.salt, self.time_cost, self.memory_kib, self.parallelism)?;
        let aead = XChaCha20Poly1305::new_from_slice(k.as_ref()).map_err(|_| KeyError::Unsupported)?;
        let nonce = XNonce::try_from(self.nonce.as_slice()).map_err(|_| KeyError::WrongPassphrase)?;
        let seed = Zeroizing::new(
            aead.decrypt(&nonce, Payload { msg: &self.ciphertext, aad: &self.aad() })
                .map_err(|_| KeyError::WrongPassphrase)?,
        );
        let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| KeyError::WrongPassphrase)?;
        let key = SigningKey::from_bytes(seed);
        if key.verifying_key().as_bytes() != self.public_key.as_slice() {
            return Err(KeyError::WrongPassphrase);
        }
        Ok(key)
    }

    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        let b: [u8; 32] = self.public_key.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&b).ok()
    }

    /// Writes the file readable by the owner only.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        let json = serde_json::to_vec_pretty(self)?;
        write_private(path, &json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, KeyError> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

/// Creates or replaces a file with owner-only permissions on Unix. On Windows
/// the file inherits its folder's ACL: the client's folder is in the user
/// profile, and the server hardens its data folder at startup.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        // `mode` only applies to new files; tighten one that already existed.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SigningKey::from_bytes(&crate::random_bytes::<32>());
        let f = KeyFile::seal(&key, b"correct horse battery staple").unwrap();
        let dir = std::env::temp_dir().join(format!("rdpgate-test-{}", crate::random_token::<6>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.key");
        f.save(&path).unwrap();
        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(loaded.open(b"correct horse battery staple").unwrap().to_bytes(), key.to_bytes());
        assert!(matches!(loaded.open(b"wrong"), Err(KeyError::WrongPassphrase)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn swapped_public_key_detected() {
        let key = SigningKey::from_bytes(&crate::random_bytes::<32>());
        let other = SigningKey::from_bytes(&crate::random_bytes::<32>());
        let mut f = KeyFile::seal(&key, b"pw").unwrap();
        f.public_key = other.verifying_key().as_bytes().to_vec();
        assert!(f.open(b"pw").is_err());
    }
}
