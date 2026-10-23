//! The server's own identity: an Ed25519 key that clients pin (so nothing can
//! impersonate the server) and the symmetric key that encrypts the beacon.
//! Stored in `<data dir>/identity.json`, readable by SYSTEM/Administrators only.

use crate::config::Config;
use ed25519_dalek::SigningKey;
use rdpgate_core::beacon::Card;
use rdpgate_core::wire;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

pub struct Identity {
    pub server: SigningKey,
    pub beacon_key: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct File {
    #[serde(with = "rdpgate_core::b64")]
    server_seed: Vec<u8>,
    #[serde(with = "rdpgate_core::b64")]
    beacon_key: Vec<u8>,
}

impl Identity {
    /// Loads the identity, creating it on first use.
    pub fn load_or_create(data_dir: &Path) -> Result<Identity, String> {
        let path = data_dir.join("identity.json");
        if let Ok(raw) = std::fs::read(&path) {
            let f: File = serde_json::from_slice(&raw).map_err(|e| format!("identity.json: {e}"))?;
            let seed: [u8; 32] = f.server_seed.as_slice().try_into().map_err(|_| "identity.json is damaged")?;
            let bk: [u8; 32] = f.beacon_key.as_slice().try_into().map_err(|_| "identity.json is damaged")?;
            return Ok(Identity { server: SigningKey::from_bytes(&seed), beacon_key: Zeroizing::new(bk) });
        }
        let id = Identity {
            server: SigningKey::from_bytes(&rdpgate_core::random_bytes::<32>()),
            beacon_key: Zeroizing::new(rdpgate_core::random_bytes::<32>()),
        };
        let f = File { server_seed: id.server.to_bytes().to_vec(), beacon_key: id.beacon_key.to_vec() };
        let json = Zeroizing::new(serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?);
        rdpgate_core::keystore::write_private(&path, &json).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(id)
    }

    pub fn public_key(&self) -> String {
        wire::encode_server_key(&self.server.verifying_key())
    }

    pub fn fingerprint(&self) -> String {
        wire::fingerprint(&self.server.verifying_key())
    }

    /// The one line a client needs: how to find this server and how to trust it.
    pub fn card(&self, cfg: &Config) -> Card {
        Card {
            v: 1,
            key: self.public_key(),
            beacon_key: self.beacon_key.to_vec(),
            gist: cfg.beacon.as_ref().map(|b| b.gist_id.clone()),
            host: cfg.public_host.clone(),
            port: cfg.public_port,
        }
    }
}
