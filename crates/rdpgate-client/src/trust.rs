//! Remembering this computer (auto mode, which the server turns on for it).
//!
//! After one sign-in with passphrase and code, the server remembers this
//! computer, and this module keeps what it takes to connect again with no
//! passphrase or code: the unlocked device key and the server's token. They
//! are sealed so that only this user on this machine can read them (Windows:
//! DPAPI; macOS: the login Keychain); copying the settings folder to another
//! computer gets nothing. Both ends also tie them to a digest of this
//! computer's hardware IDs: when those change, the computer is forgotten and
//! signs in with passphrase and code again.

use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// What [`recall`] gives back: enough to open access without a passphrase.
pub struct Remembered {
    pub key: SigningKey,
    pub token: String,
    pub hw: String,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    #[serde(with = "rdpgate_core::b64")]
    key: Vec<u8>,
    token: String,
    hw: String,
}

/// Whether this system can keep a remembered computer's key safely.
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// A digest of this computer's hardware IDs, mixed with this device's key so
/// it means nothing to anyone else. The IDs themselves never leave it.
pub fn hardware_digest(device: &VerifyingKey) -> Option<String> {
    let ids = platform::hardware_ids()?;
    let mut h = Sha256::new();
    h.update(b"rdpgate-hw\0");
    h.update(device.as_bytes());
    h.update(ids.as_bytes());
    Some(hex::encode(h.finalize()))
}

/// Seals `key` and the server's `token` for this user on this machine.
pub fn remember(dir: &Path, key: &SigningKey, token: &str, hw: &str) -> Result<()> {
    let sealed = Sealed { key: key.to_bytes().to_vec(), token: token.into(), hw: hw.into() };
    let json = Zeroizing::new(serde_json::to_vec(&sealed).map_err(|e| e.to_string())?);
    let mut key_bytes = sealed.key;
    zeroize::Zeroize::zeroize(&mut key_bytes);
    platform::store(dir, &json)
}

/// What [`remember`] kept, while the hardware and the device key are still
/// the same. Otherwise it is forgotten and this returns None.
pub fn recall(dir: &Path) -> Option<Remembered> {
    let raw = Zeroizing::new(platform::load(dir)?);
    let Ok(Sealed { key, token, hw }) = serde_json::from_slice::<Sealed>(&raw) else {
        forget(dir);
        return None;
    };
    let key = Zeroizing::new(key);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(key.as_slice().try_into().ok()?);
    let key = SigningKey::from_bytes(&bytes);
    let same_key = crate::identity(dir).is_ok_and(|id| id.public_key == rdpgate_core::wire::encode_public_key(&key.verifying_key()));
    if !same_key || hardware_digest(&key.verifying_key()).as_deref() != Some(hw.as_str()) {
        forget(dir);
        return None;
    }
    Some(Remembered { key, token, hw })
}

/// True when something is remembered (cheap; doesn't check the hardware).
pub fn is_remembered(dir: &Path) -> bool {
    platform::exists(dir)
}

pub fn forget(dir: &Path) {
    platform::remove(dir);
}

#[cfg(windows)]
mod platform {
    use crate::Result;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData};
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW};
    use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

    const ENTROPY: &[u8] = b"rdpgate remembered computer";

    fn path(dir: &Path) -> PathBuf {
        dir.join("remembered.bin")
    }

    /// DPAPI for the current user: only this account on this machine can open it.
    fn dpapi(data: &[u8], open: bool) -> Option<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let ok = unsafe {
            if open {
                CryptUnprotectData(&input, null_mut(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptProtectData(&input, null(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        if ok == 0 || out.pbData.is_null() {
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
        let v = bytes.to_vec();
        bytes.fill(0);
        unsafe { LocalFree(out.pbData.cast()) };
        Some(v)
    }

    pub fn store(dir: &Path, data: &[u8]) -> Result<()> {
        let sealed = dpapi(data, false).ok_or("Windows could not protect the remembered key (DPAPI)")?;
        rdpgate_core::keystore::write_private(&path(dir), &sealed).map_err(|e| e.to_string())
    }

    pub fn load(dir: &Path) -> Option<Vec<u8>> {
        dpapi(&std::fs::read(path(dir)).ok()?, true)
    }

    pub fn exists(dir: &Path) -> bool {
        path(dir).exists()
    }

    pub fn remove(dir: &Path) {
        let _ = std::fs::remove_file(path(dir));
    }

    /// The motherboard's SMBIOS UUID and this Windows installation's ID.
    pub fn hardware_ids() -> Option<String> {
        let (board, install) = (smbios_uuid(), machine_guid());
        if board.is_none() && install.is_none() {
            return None;
        }
        Some(format!("board={};install={}", board.unwrap_or_default(), install.unwrap_or_default()))
    }

    fn smbios_uuid() -> Option<String> {
        let n = unsafe { GetSystemFirmwareTable(RSMB, 0, null_mut(), 0) };
        if n == 0 {
            return None;
        }
        let mut buf = vec![0u8; n as usize];
        if unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), n) } != n {
            return None;
        }
        // RawSMBIOSData: four version bytes and the table length, then the table.
        let len = u32::from_le_bytes(buf.get(4..8)?.try_into().ok()?) as usize;
        let table = buf.get(8..8 + len)?;
        let mut i = 0;
        while i + 4 <= table.len() {
            let (kind, formatted) = (table[i], table[i + 1] as usize);
            if formatted < 4 {
                return None;
            }
            // Type 1, System Information: the UUID is at offset 8.
            if kind == 1 && formatted >= 0x19 {
                let uuid = table.get(i + 8..i + 24)?;
                return (!uuid.iter().all(|&b| b == 0) && !uuid.iter().all(|&b| b == 0xff)).then(|| hex::encode(uuid));
            }
            if kind == 127 {
                return None;
            }
            // Past the formatted part, then its strings up to a double NUL.
            let mut j = i + formatted;
            while j + 1 < table.len() && !(table[j] == 0 && table[j + 1] == 0) {
                j += 1;
            }
            i = j + 2;
        }
        None
    }

    fn machine_guid() -> Option<String> {
        let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
        let (key, value) = (wide(r"SOFTWARE\Microsoft\Cryptography"), wide("MachineGuid"));
        let mut buf = [0u16; 128];
        let mut size = (buf.len() * 2) as u32;
        let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
        let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), flags, null_mut(), buf.as_mut_ptr().cast(), &mut size) };
        if r != 0 {
            return None;
        }
        let s = String::from_utf16_lossy(&buf[..size as usize / 2]);
        let s = s.trim_end_matches('\0').trim();
        (!s.is_empty()).then(|| s.to_string())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::Result;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    const SERVICE: &str = "rdpgate-remembered-computer";
    const SECURITY: &str = "/usr/bin/security";

    /// One Keychain item per settings folder.
    fn account(dir: &Path) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(&Sha256::digest(dir.to_string_lossy().as_bytes())[..12])
    }

    pub fn store(dir: &Path, data: &[u8]) -> Result<()> {
        // Through stdin, so the secret never shows up in the process list.
        let mut child = Command::new(SECURITY)
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Keychain: {e}"))?;
        let line = zeroize::Zeroizing::new(format!(
            "add-generic-password -U -a {} -s {SERVICE} -w {}\n",
            account(dir),
            hex::encode(data)
        ));
        child.stdin.take().ok_or("Keychain: no input")?.write_all(line.as_bytes()).map_err(|e| format!("Keychain: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("Keychain: {e}"))?;
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() || !err.trim().is_empty() {
            return Err(format!("Keychain refused to keep the remembered key: {}", err.trim()));
        }
        Ok(())
    }

    pub fn load(dir: &Path) -> Option<Vec<u8>> {
        let out = Command::new(SECURITY)
            .args(["find-generic-password", "-a", &account(dir), "-s", SERVICE, "-w"])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let text = zeroize::Zeroizing::new(out.stdout);
        if !out.status.success() {
            return None;
        }
        hex::decode(String::from_utf8_lossy(&text).trim()).ok()
    }

    pub fn exists(dir: &Path) -> bool {
        Command::new(SECURITY)
            .args(["find-generic-password", "-a", &account(dir), "-s", SERVICE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    pub fn remove(dir: &Path) {
        let _ = Command::new(SECURITY)
            .args(["delete-generic-password", "-a", &account(dir), "-s", SERVICE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// The logic board's hardware UUID.
    pub fn hardware_ids() -> Option<String> {
        let out = Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
        let uuid = line.rsplit('"').nth(1)?.trim();
        (!uuid.is_empty()).then(|| format!("board={uuid}"))
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use crate::Result;
    use std::path::Path;

    pub fn store(_: &Path, _: &[u8]) -> Result<()> {
        Err("remembering this computer isn't supported on this system yet".into())
    }

    pub fn load(_: &Path) -> Option<Vec<u8>> {
        None
    }

    pub fn exists(_: &Path) -> bool {
        false
    }

    pub fn remove(_: &Path) {}

    pub fn hardware_ids() -> Option<String> {
        let id = std::fs::read_to_string("/etc/machine-id").ok()?;
        let id = id.trim();
        (!id.is_empty()).then(|| format!("install={id}"))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn remembers_for_this_hardware_only() {
        let dir = std::env::temp_dir().join(format!("rdpgate-trust-{}", rdpgate_core::random_token::<6>()));
        crate::create_device(&dir, "mac", None, "long enough passphrase", false).unwrap();
        let key = crate::unlock(&dir, "long enough passphrase").unwrap();
        let hw = hardware_digest(&key.verifying_key()).expect("Windows has hardware IDs");
        assert_eq!(hardware_digest(&key.verifying_key()).as_deref(), Some(hw.as_str()), "stable");

        remember(&dir, &key, "tok", &hw).unwrap();
        assert!(is_remembered(&dir));
        assert!(!std::fs::read(dir.join("remembered.bin")).unwrap().windows(3).any(|w| w == b"tok"), "sealed, not plain");
        let r = recall(&dir).unwrap();
        assert_eq!((r.token.as_str(), r.key.to_bytes()), ("tok", key.to_bytes()));

        // Other hardware: forgotten.
        remember(&dir, &key, "tok", "another computer").unwrap();
        assert!(recall(&dir).is_none());
        assert!(!is_remembered(&dir));
        std::fs::remove_dir_all(dir).ok();
    }
}
