//! Release tooling: makes the release signing key and the signed update
//! manifest that every RDP Gate program checks before updating itself.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rdpgate_core::update::{self, AssetInfo, Manifest};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rdpgate-release", about = "RDP Gate release signing")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new release signing key (once). Prints the public key to embed.
    Keygen {
        /// Where to write the private key (keep it secret, back it up)
        #[arg(long)]
        out: PathBuf,
    },
    /// Hash every file in DIR and write DIR/rdpgate-update.json, signed with
    /// the key in the RDPGATE_UPDATE_KEY environment variable.
    Manifest {
        #[arg(long)]
        version: String,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Check a manifest against the release key built into this tool.
    Verify { file: PathBuf },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Keygen { out } => {
            if out.exists() {
                return Err(format!("{} already exists; refusing to overwrite a signing key", out.display()));
            }
            let key = SigningKey::from_bytes(&rdpgate_core::random_bytes::<32>());
            rdpgate_core::keystore::write_private(&out, STANDARD.encode(key.to_bytes()).as_bytes()).map_err(|e| e.to_string())?;
            println!("{}", update::encode_release_key(&key.verifying_key()));
            Ok(())
        }
        Cmd::Manifest { version, dir } => {
            semver::Version::parse(&version).map_err(|e| format!("version: {e}"))?;
            let seed = std::env::var("RDPGATE_UPDATE_KEY").map_err(|_| "RDPGATE_UPDATE_KEY is not set; refusing to publish an unsigned release")?;
            let seed: [u8; 32] = STANDARD
                .decode(seed.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or("RDPGATE_UPDATE_KEY is not a valid key")?;
            let key = SigningKey::from_bytes(&seed);
            if update::release_key() != Some(key.verifying_key()) {
                return Err("RDPGATE_UPDATE_KEY doesn't match the public key built into the programs".into());
            }
            let mut assets = BTreeMap::new();
            for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
                let path = entry.map_err(|e| e.to_string())?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
                if !path.is_file() || name == update::MANIFEST_ASSET || name == "SHA256SUMS.txt" {
                    continue;
                }
                let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
                assets.insert(name, AssetInfo { sha256: hex::encode(Sha256::digest(&bytes)), size: bytes.len() as u64 });
            }
            for c in ["rdpgate-server-windows-x64.exe", "rdpgate-windows-x64.exe", "rdpgate-app-windows-x64.exe", "rdpgate-server-app-windows-x64.exe", "rdpgate-macos-universal", "rdpgate-app-macos-universal.zip"] {
                if !assets.contains_key(c) {
                    return Err(format!("{c} is missing from {}", dir.display()));
                }
            }
            let published = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let text = update::sign_manifest(&Manifest { version, published, assets }, &key);
            std::fs::write(dir.join(update::MANIFEST_ASSET), text).map_err(|e| e.to_string())?;
            println!("signed {}", dir.join(update::MANIFEST_ASSET).display());
            Ok(())
        }
        Cmd::Verify { file } => {
            let key = update::release_key().ok_or("no release key built in")?;
            let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
            let m = update::verify_manifest(&text, &key)?;
            println!("OK: version {} with {} files", m.version, m.assets.len());
            Ok(())
        }
    }
}
