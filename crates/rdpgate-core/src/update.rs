//! Signed self-updates for every RDP Gate program.
//!
//! Each GitHub release carries `rdpgate-update.json`: a manifest listing the
//! version and the SHA-256 and size of every file, signed with the project's
//! release key. Programs embed the matching public key and install an update
//! only if the signature verifies, the version is newer than their own (no
//! downgrades), and the downloaded file matches the signed hash and size.
//! GitHub, a network attacker or anyone with write access to the releases
//! page cannot push code to your machines without the release key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

pub const REPO: &str = "parthh37/rdpgate";
pub const MANIFEST_ASSET: &str = "rdpgate-update.json";
const SIG_CONTEXT: &[u8] = b"rdpgate update manifest v1\0";
const KEY_PREFIX: &str = "rdpgate-release-ed25519:";
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;

/// The project's release public key. Only manifests signed by the matching
/// private key (held in the repository's Actions secrets) are accepted.
pub const RELEASE_PUBLIC_KEY: &str = "rdpgate-release-ed25519:EPivIz+uAeVY/mIfxabwfx6QxHMB4VTaRp8KPGgfI5Q=";

/// The programs that can update themselves.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Component {
    Server,
    Cli,
    App,
    /// The RDP Gate Server window, next to the server (updated by the service).
    ServerApp,
    /// The server's notification-area icon, next to the server (updated by the service).
    Tray,
}

/// Release file that updates `c` on this OS, if one is published.
pub fn asset_for(c: Component) -> Option<&'static str> {
    match (c, std::env::consts::OS) {
        (Component::Server, "windows") => Some("rdpgate-server-windows-x64.exe"),
        (Component::Cli, "windows") => Some("rdpgate-windows-x64.exe"),
        (Component::App, "windows") => Some("rdpgate-app-windows-x64.exe"),
        (Component::ServerApp, "windows") => Some("rdpgate-server-app-windows-x64.exe"),
        (Component::Tray, "windows") => Some("rdpgate-tray-windows-x64.exe"),
        (Component::Cli, "macos") => Some("rdpgate-macos-universal"),
        (Component::App, "macos") => Some("rdpgate-app-macos-universal.zip"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub published: i64,
    pub assets: BTreeMap<String, AssetInfo>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    #[serde(with = "crate::b64")]
    manifest: Vec<u8>,
    #[serde(with = "crate::b64")]
    sig: Vec<u8>,
}

pub fn encode_release_key(k: &VerifyingKey) -> String {
    format!("{KEY_PREFIX}{}", STANDARD.encode(k.as_bytes()))
}

pub fn parse_release_key(s: &str) -> Result<VerifyingKey, String> {
    let raw = s
        .trim()
        .strip_prefix(KEY_PREFIX)
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or("invalid release key")?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "invalid release key")?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "invalid release key".into())
}

/// The embedded release key (None in a build made before the key existed).
pub fn release_key() -> Option<VerifyingKey> {
    parse_release_key(RELEASE_PUBLIC_KEY).ok()
}

/// Signs a manifest (release tooling only).
pub fn sign_manifest(m: &Manifest, key: &SigningKey) -> String {
    let manifest = serde_json::to_vec(m).expect("manifest serializes");
    let sig = key.sign(&[SIG_CONTEXT, &manifest].concat()).to_bytes().to_vec();
    serde_json::to_string_pretty(&Envelope { v: 1, manifest, sig }).expect("envelope serializes")
}

/// Checks the signature, then parses. Nothing unsigned is ever interpreted.
pub fn verify_manifest(text: &str, key: &VerifyingKey) -> Result<Manifest, String> {
    let env: Envelope = serde_json::from_str(text).map_err(|_| "malformed update manifest")?;
    if env.v != 1 {
        return Err("this update needs a newer updater; download it manually".into());
    }
    let sig = Signature::from_slice(&env.sig).map_err(|_| "malformed update signature")?;
    key.verify_strict(&[SIG_CONTEXT, &env.manifest].concat(), &sig)
        .map_err(|_| "the update is NOT signed with the RDP Gate release key; refusing it")?;
    serde_json::from_slice(&env.manifest).map_err(|_| "malformed update manifest".into())
}

/// A newer, verified release.
#[derive(Debug, Clone)]
pub struct Available {
    pub version: Version,
    pub tag: String,
    pub url: String,
    pub manifest: Manifest,
    downloads: HashMap<String, String>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .user_agent(concat!("rdpgate/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut resp = agent()
        .get(url)
        .header("Accept", "application/octet-stream")
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    resp.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| format!("download failed: {e}"))
}

/// Picks the release to offer from GitHub's release list: the highest version
/// that has a manifest (pre-releases only if asked for).
fn pick(releases: &serde_json::Value, prereleases: bool) -> Option<(Version, &serde_json::Value)> {
    releases
        .as_array()?
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(true))
        .filter(|r| prereleases || !r["prerelease"].as_bool().unwrap_or(true))
        .filter(|r| r["assets"].as_array().is_some_and(|a| a.iter().any(|x| x["name"] == MANIFEST_ASSET)))
        .filter_map(|r| Some((Version::parse(r["tag_name"].as_str()?.trim_start_matches('v')).ok()?, r)))
        .max_by(|a, b| a.0.cmp(&b.0))
}

/// Asks GitHub for the newest release and verifies its manifest. Returns
/// `None` when this program (version `current`) is already up to date.
/// Blocking: run it off async threads.
pub fn check(current: &str, prereleases: bool) -> Result<Option<Available>, String> {
    let key = release_key().ok_or("this build has no release key; update manually")?;
    let current = Version::parse(current).map_err(|e| e.to_string())?;
    let mut resp = agent()
        .get(&format!("https://api.github.com/repos/{REPO}/releases?per_page=30"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|e| format!("could not check for updates: {e}"))?;
    let body = resp.body_mut().with_config().limit(4 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
    let releases: serde_json::Value = serde_json::from_str(&body).map_err(|_| "unexpected reply from GitHub")?;
    let Some((version, rel)) = pick(&releases, prereleases) else { return Ok(None) };
    if version <= current {
        return Ok(None);
    }
    let mut downloads = HashMap::new();
    for a in rel["assets"].as_array().into_iter().flatten() {
        if let (Some(n), Some(u)) = (a["name"].as_str(), a["browser_download_url"].as_str()) {
            downloads.insert(n.to_string(), u.to_string());
        }
    }
    let text = get_bytes(&downloads[MANIFEST_ASSET], 256 * 1024)?;
    let manifest = verify_manifest(&String::from_utf8_lossy(&text), &key)?;
    if manifest.version != version.to_string() {
        return Err("the signed manifest doesn't match the release version; refusing it".into());
    }
    Ok(Some(Available {
        version,
        tag: rel["tag_name"].as_str().unwrap_or_default().to_string(),
        url: rel["html_url"].as_str().unwrap_or_default().to_string(),
        manifest,
        downloads,
    }))
}

/// Downloads one release file and checks it against the signed manifest.
pub fn download(av: &Available, asset: &str) -> Result<Vec<u8>, String> {
    let info = av.manifest.assets.get(asset).ok_or("this release has no update for your system")?;
    let url = av.downloads.get(asset).ok_or("this release has no update for your system")?;
    if info.size > MAX_DOWNLOAD {
        return Err("update is unexpectedly large".into());
    }
    let bytes = get_bytes(url, info.size + 1)?;
    if bytes.len() as u64 != info.size || hex::encode(Sha256::digest(&bytes)) != info.sha256 {
        return Err("the downloaded update doesn't match its signed checksum; refusing it".into());
    }
    Ok(bytes)
}

/// Puts `bytes` in place of the running program. The running process keeps
/// working; the new version starts next time. On Windows the running file
/// is renamed out of the way (allowed while it runs) and removed later.
pub fn replace_current_exe(bytes: &[u8]) -> Result<PathBuf, String> {
    replace_exe(std::env::current_exe().map_err(|e| e.to_string())?, bytes)
}

/// Puts `bytes` in place of the program at `exe`, which may be running.
pub fn replace_exe(exe: PathBuf, bytes: &[u8]) -> Result<PathBuf, String> {
    let new = exe.with_extension(if cfg!(windows) { "new.exe" } else { "new" });
    let denied = |e: std::io::Error| format!("can't write next to {}: {e}", exe.display());
    std::fs::write(&new, bytes).map_err(denied)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        std::fs::rename(&new, &exe).map_err(denied)?;
    }
    #[cfg(windows)]
    {
        let old = exe.with_extension("old.exe");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&exe, &old).map_err(denied)?;
        if let Err(e) = std::fs::rename(&new, &exe) {
            let _ = std::fs::rename(&old, &exe);
            return Err(denied(e));
        }
    }
    Ok(exe)
}

/// Removes the previous version left behind by an update (Windows).
pub fn cleanup_previous() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("old.exe"));
    }
}

/// Replaces the running `.app` bundle with the one in `zip` (macOS).
#[cfg(target_os = "macos")]
pub fn replace_mac_app(zip: &[u8]) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let bundle = exe
        .ancestors()
        .nth(3)
        .filter(|b| b.extension().is_some_and(|e| e == "app"))
        .ok_or("RDP Gate isn't running from an app bundle; update it manually")?
        .to_path_buf();
    let parent = bundle.parent().ok_or("no parent folder")?;
    let work = parent.join(format!(".rdpgate-update-{}", crate::random_token::<6>()));
    std::fs::create_dir(&work).map_err(|e| format!("can't write to {}: {e}. Move RDP Gate to a folder you own, or update manually.", parent.display()))?;
    let result = (|| {
        let zip_path = work.join("update.zip");
        std::fs::write(&zip_path, zip).map_err(|e| e.to_string())?;
        let ok = std::process::Command::new("/usr/bin/ditto")
            .arg("-x")
            .arg("-k")
            .arg(&zip_path)
            .arg(work.join("x"))
            .status()
            .map_err(|e| e.to_string())?
            .success();
        if !ok {
            return Err("could not unpack the update".to_string());
        }
        let new = std::fs::read_dir(work.join("x"))
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "app"))
            .ok_or("the update has no app inside")?;
        let old = work.join("old.app");
        std::fs::rename(&bundle, &old).map_err(|e| e.to_string())?;
        if let Err(e) = std::fs::rename(&new, &bundle) {
            let _ = std::fs::rename(&old, &bundle);
            return Err(e.to_string());
        }
        Ok(bundle.clone())
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(v: &str) -> Manifest {
        let mut assets = BTreeMap::new();
        assets.insert("rdpgate-windows-x64.exe".into(), AssetInfo { sha256: "ab".repeat(32), size: 10 });
        Manifest { version: v.into(), published: 1, assets }
    }

    #[test]
    fn signed_manifest_roundtrip_and_tamper() {
        let key = SigningKey::from_bytes(&crate::random_bytes::<32>());
        let text = sign_manifest(&manifest("0.2.0"), &key);
        assert_eq!(verify_manifest(&text, &key.verifying_key()).unwrap(), manifest("0.2.0"));

        // Signed by someone else: refused.
        let other = SigningKey::from_bytes(&crate::random_bytes::<32>());
        assert!(verify_manifest(&sign_manifest(&manifest("0.2.0"), &other), &key.verifying_key()).is_err());

        // A changed hash or version: refused.
        let mut env: serde_json::Value = serde_json::from_str(&text).unwrap();
        let m = String::from_utf8(STANDARD.decode(env["manifest"].as_str().unwrap()).unwrap()).unwrap();
        env["manifest"] = STANDARD.encode(m.replace("0.2.0", "9.9.9")).into();
        assert!(verify_manifest(&env.to_string(), &key.verifying_key()).is_err());

        let k = key.verifying_key();
        assert_eq!(parse_release_key(&encode_release_key(&k)).unwrap(), k);
    }

    #[test]
    fn picks_highest_suitable_release() {
        let rel = |tag: &str, pre: bool, manifest: bool| {
            let mut assets = vec![serde_json::json!({ "name": "x.zip" })];
            if manifest {
                assets.push(serde_json::json!({ "name": MANIFEST_ASSET }));
            }
            serde_json::json!({ "tag_name": tag, "draft": false, "prerelease": pre, "assets": assets })
        };
        let list = serde_json::json!([
            rel("v0.3.0", true, true),
            rel("v0.4.0", false, false), // no manifest: can't be verified, ignored
            rel("v0.2.1", false, true),
            rel("v0.10.0", true, true), // semver, not string, ordering
        ]);
        assert_eq!(pick(&list, true).unwrap().0, Version::parse("0.10.0").unwrap());
        assert_eq!(pick(&list, false).unwrap().0, Version::parse("0.2.1").unwrap());
        assert!(pick(&serde_json::json!([]), true).is_none());
    }

    #[test]
    fn every_platform_component_has_a_distinct_asset() {
        // On this OS, whichever components are supported map to distinct files.
        let names: Vec<_> =
            [Component::Server, Component::Cli, Component::App, Component::ServerApp, Component::Tray].into_iter().filter_map(asset_for).collect();
        let mut dedup = names.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len());
    }
}
