//! "Remember my Windows password": the Windows account password for Remote
//! Desktop, kept in the system's credential store and never in a file of
//! ours (Windows: Credential Manager; macOS: the login Keychain).
//!
//! On Windows, each launch also saves it as `TERMSRV/<address>`, the
//! credential Remote Desktop Connection (mstsc) itself saves with "Remember
//! me", so it signs in without asking. Those are tagged as RDP Gate's: only
//! the current address keeps one, and forgetting removes them all.
//!
//! Microsoft's Windows App on the Mac can't take a password from a
//! connection file or from another app, so there it can only be copied for
//! pasting ([`copy_for_paste`]).

use crate::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use zeroize::Zeroizing;

/// What is kept: the account and its password.
#[derive(Serialize, Deserialize)]
struct Saved {
    user: String,
    password: String,
}

impl Drop for Saved {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}

/// Whether this system has a credential store to keep it in.
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Whether Remote Desktop signs in with the saved password by itself.
pub fn fills_in() -> bool {
    cfg!(windows)
}

/// Where it is kept, for showing people.
pub fn store_name() -> &'static str {
    if cfg!(windows) { "Windows Credential Manager" } else { "the macOS Keychain" }
}

/// One store item per settings folder, like [`crate::trust`].
fn account(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(dir.to_string_lossy().as_bytes())[..12])
}

/// Saves `password` for Windows account `user` and makes `user` the account
/// Remote Desktop signs in with.
pub fn save(dir: &Path, user: &str, password: &str) -> Result<()> {
    let user = user.trim();
    if user.is_empty() {
        return Err("Enter your Windows user name first.".into());
    }
    if password.is_empty() {
        return Err("Enter your Windows password.".into());
    }
    let mut cfg = crate::load_config(dir)?;
    let saved = Saved { user: user.into(), password: password.into() };
    let json = Zeroizing::new(serde_json::to_vec(&saved).map_err(|e| e.to_string())?);
    platform::store(&account(dir), user, &json)?;
    if cfg.rdp_username.as_deref() != Some(user) {
        cfg.rdp_username = Some(user.into());
        crate::save_config(dir, &cfg)?;
    }
    Ok(())
}

fn load(dir: &Path) -> Option<Saved> {
    let raw = Zeroizing::new(platform::load(&account(dir))?);
    serde_json::from_slice(&raw).ok()
}

/// True when a password is saved (cheap; doesn't read it).
pub fn is_saved(dir: &Path) -> bool {
    platform::exists(&account(dir))
}

/// The account the saved password belongs to.
pub fn saved_user(dir: &Path) -> Option<String> {
    load(dir).map(|s| s.user.clone())
}

/// Forgets the saved password, and the copies Remote Desktop was given.
pub fn forget(dir: &Path) {
    let account = account(dir);
    platform::remove(&account);
    platform::remove_rdp_copies(&account, &[]);
}

/// Before launching Remote Desktop for `user` at `host`: hands it the saved
/// password where it can take one. True when it will sign in by itself.
pub(crate) fn prepare(dir: &Path, user: &str, host: IpAddr) -> bool {
    let Some(saved) = load(dir) else { return false };
    if !fills_in() || !saved.user.eq_ignore_ascii_case(user) {
        return false;
    }
    let account = account(dir);
    // mstsc looks for the address without the port. For IPv6 it's unclear
    // whether brackets are used, so both are written.
    let mut targets = vec![format!("TERMSRV/{host}")];
    if host.is_ipv6() {
        targets.push(format!("TERMSRV/[{host}]"));
    }
    platform::remove_rdp_copies(&account, &targets);
    let mut ok = false;
    for t in &targets {
        ok |= platform::give_rdp(&account, t, &saved.user, &saved.password).is_ok();
    }
    ok
}

/// For Remote Desktop apps that can't take it (Windows App on the Mac): puts
/// the saved password on the clipboard and clears it after 45 seconds, if it
/// is still there.
pub fn copy_for_paste(dir: &Path) -> Result<()> {
    let saved = load(dir).ok_or("No Windows password is saved.")?;
    platform::copy(&saved.password)
}

#[cfg(windows)]
mod platform {
    use crate::Result;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE, CRED_TYPE_DOMAIN_PASSWORD, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredEnumerateW,
        CredFree, CredReadW, CredWriteW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn target(account: &str) -> Vec<u16> {
        wide(&format!("RDP Gate/Windows password/{account}"))
    }

    /// Marks the `TERMSRV/…` credentials RDP Gate wrote for this account.
    fn tag(account: &str) -> String {
        format!("Saved by RDP Gate ({account})")
    }

    fn write(kind: CRED_TYPE, target: &[u16], user: &str, blob: &[u8], comment: Option<&str>) -> Result<()> {
        let (mut target, mut user) = (target.to_vec(), wide(user));
        let mut comment = comment.map(wide);
        let cred = CREDENTIALW {
            Type: kind,
            TargetName: target.as_mut_ptr(),
            Comment: comment.as_mut().map_or(null_mut(), |c| c.as_mut_ptr()),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: user.as_mut_ptr(),
            ..Default::default()
        };
        if unsafe { CredWriteW(&cred, 0) } == 0 {
            return Err(format!("Windows Credential Manager refused it ({})", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn store(account: &str, user: &str, data: &[u8]) -> Result<()> {
        write(CRED_TYPE_GENERIC, &target(account), user, data, None)
    }

    pub fn load(account: &str) -> Option<Vec<u8>> {
        let mut cred: *mut CREDENTIALW = null_mut();
        if unsafe { CredReadW(target(account).as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 || cred.is_null() {
            return None;
        }
        let c = unsafe { &*cred };
        let bytes = unsafe { std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize) };
        let v = bytes.to_vec();
        bytes.fill(0);
        unsafe { CredFree(cred.cast()) };
        Some(v)
    }

    pub fn exists(account: &str) -> bool {
        load(account).map(|mut v| v.fill(0)).is_some()
    }

    pub fn remove(account: &str) {
        unsafe { CredDeleteW(target(account).as_ptr(), CRED_TYPE_GENERIC, 0) };
    }

    /// Saves it the way mstsc's "Remember me" does. A domain password can't
    /// be read back by programs, only used to sign in; where a policy forbids
    /// those, a generic credential (what `cmdkey /generic` makes) still works.
    pub fn give_rdp(account: &str, target: &str, user: &str, password: &str) -> Result<()> {
        let blob = zeroize::Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());
        let (target, tag) = (wide(target), tag(account));
        write(CRED_TYPE_DOMAIN_PASSWORD, &target, user, &blob, Some(&tag))
            .or_else(|_| write(CRED_TYPE_GENERIC, &target, user, &blob, Some(&tag)))
    }

    /// Deletes this account's `TERMSRV/…` credentials, except `keep`.
    pub fn remove_rdp_copies(account: &str, keep: &[String]) {
        let tag = tag(account);
        let filter = wide("TERMSRV/*");
        let (mut count, mut list): (u32, *mut *mut CREDENTIALW) = (0, null_mut());
        if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut list) } == 0 || list.is_null() {
            return;
        }
        let read = |p: *const u16| {
            if p.is_null() {
                return String::new();
            }
            let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
        };
        let mut doomed = Vec::new();
        for i in 0..count as usize {
            let c = unsafe { &**list.add(i) };
            let name = read(c.TargetName);
            if read(c.Comment) == tag && !keep.iter().any(|k| k.eq_ignore_ascii_case(&name)) {
                doomed.push((wide(&name), c.Type));
            }
        }
        unsafe { CredFree(list.cast()) };
        for (name, kind) in doomed {
            unsafe { CredDeleteW(name.as_ptr(), kind, 0) };
        }
    }

    pub fn copy(_: &str) -> Result<()> {
        Err("Remote Desktop on Windows signs in with the saved password by itself.".into())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::Result;
    use std::io::Write;
    use std::process::{Command, Stdio};

    const SERVICE: &str = "rdpgate-windows-password";
    const SECURITY: &str = "/usr/bin/security";

    pub fn store(account: &str, _user: &str, data: &[u8]) -> Result<()> {
        // Through stdin, so the password never shows up in the process list.
        let mut child = Command::new(SECURITY)
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Keychain: {e}"))?;
        let line = zeroize::Zeroizing::new(format!("add-generic-password -U -a {account} -s {SERVICE} -w {}\n", hex::encode(data)));
        child.stdin.take().ok_or("Keychain: no input")?.write_all(line.as_bytes()).map_err(|e| format!("Keychain: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("Keychain: {e}"))?;
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() || !err.trim().is_empty() {
            return Err(format!("Keychain refused to keep the password: {}", err.trim()));
        }
        Ok(())
    }

    pub fn load(account: &str) -> Option<Vec<u8>> {
        let out = Command::new(SECURITY)
            .args(["find-generic-password", "-a", account, "-s", SERVICE, "-w"])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let text = zeroize::Zeroizing::new(out.stdout);
        if !out.status.success() {
            return None;
        }
        hex::decode(String::from_utf8_lossy(&text).trim()).ok()
    }

    pub fn exists(account: &str) -> bool {
        Command::new(SECURITY)
            .args(["find-generic-password", "-a", account, "-s", SERVICE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    pub fn remove(account: &str) {
        let _ = Command::new(SECURITY)
            .args(["delete-generic-password", "-a", account, "-s", SERVICE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    pub fn give_rdp(_: &str, _: &str, _: &str, _: &str) -> Result<()> {
        Err("Windows App can't take a saved password".into())
    }

    pub fn remove_rdp_copies(_: &str, _: &[String]) {}

    /// pbcopy, then a detached shell that empties the clipboard after 45
    /// seconds if it still holds the password. It only gets a digest of the
    /// password to compare with, never the password.
    pub fn copy(password: &str) -> Result<()> {
        use sha2::{Digest, Sha256};
        let mut child = Command::new("/usr/bin/pbcopy").stdin(Stdio::piped()).spawn().map_err(|e| format!("Clipboard: {e}"))?;
        child.stdin.take().ok_or("Clipboard: no input")?.write_all(password.as_bytes()).map_err(|e| format!("Clipboard: {e}"))?;
        child.wait().map_err(|e| format!("Clipboard: {e}"))?;
        let digest = hex::encode(Sha256::digest(password.as_bytes()));
        let _ = Command::new("/bin/sh")
            .args([
                "-c",
                r#"sleep 45; [ "$(/usr/bin/pbpaste | /usr/bin/shasum -a 256 | /usr/bin/cut -d' ' -f1)" = "$RDPGATE_DIGEST" ] && /usr/bin/pbcopy </dev/null"#,
            ])
            .env("RDPGATE_DIGEST", digest)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use crate::Result;

    pub fn store(_: &str, _: &str, _: &[u8]) -> Result<()> {
        Err("saving the Windows password isn't supported on this system yet".into())
    }

    pub fn load(_: &str) -> Option<Vec<u8>> {
        None
    }

    pub fn exists(_: &str) -> bool {
        false
    }

    pub fn remove(_: &str) {}

    pub fn give_rdp(_: &str, _: &str, _: &str, _: &str) -> Result<()> {
        Err("not supported".into())
    }

    pub fn remove_rdp_copies(_: &str, _: &[String]) {}

    pub fn copy(_: &str) -> Result<()> {
        Err("saving the Windows password isn't supported on this system yet".into())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_DOMAIN_PASSWORD, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW};

    /// The user name of a `TERMSRV/…` credential, if there is one.
    fn rdp_user(target: &str) -> Option<String> {
        let name: Vec<u16> = target.encode_utf16().chain([0]).collect();
        for kind in [CRED_TYPE_DOMAIN_PASSWORD, CRED_TYPE_GENERIC] {
            let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
            if unsafe { CredReadW(name.as_ptr(), kind, 0, &mut cred) } != 0 {
                let p = unsafe { (*cred).UserName };
                let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
                let user = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
                unsafe { CredFree(cred.cast()) };
                return Some(user);
            }
        }
        None
    }

    #[test]
    fn saved_in_credential_manager_given_to_remote_desktop_and_forgotten() {
        let dir = std::env::temp_dir().join(format!("rdpgate-winpass-{}", rdpgate_core::random_token::<6>()));
        crate::create_device(&dir, "pc", None, "long enough passphrase", false).unwrap();
        assert!(!is_saved(&dir));
        assert!(save(&dir, "", "pw").is_err());
        save(&dir, "rdpgate-test", "s3cret pässword").unwrap();
        assert!(is_saved(&dir));
        assert_eq!(saved_user(&dir).as_deref(), Some("rdpgate-test"));
        assert_eq!(crate::load_config(&dir).unwrap().rdp_username.as_deref(), Some("rdpgate-test"));
        assert!(!std::fs::read(dir.join("config.json")).unwrap().windows(6).any(|w| w == b"s3cret"), "not in the config");

        // Documentation addresses (RFC 5737 / 3849), so nothing real is touched.
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.77".parse().unwrap(), "2001:db8::77".parse().unwrap());
        assert!(!prepare(&dir, "someone-else", a), "only for the account it was saved for");
        assert!(prepare(&dir, "rdpgate-test", a));
        assert_eq!(rdp_user("TERMSRV/192.0.2.77").as_deref(), Some("rdpgate-test"));
        assert!(prepare(&dir, "RDPGATE-TEST", b));
        assert_eq!(rdp_user("TERMSRV/2001:db8::77").as_deref(), Some("rdpgate-test"));
        assert!(rdp_user("TERMSRV/192.0.2.77").is_none(), "only the current address keeps a copy");

        forget(&dir);
        assert!(!is_saved(&dir));
        assert!(rdp_user("TERMSRV/2001:db8::77").is_none() && rdp_user("TERMSRV/[2001:db8::77]").is_none());
        assert!(!prepare(&dir, "rdpgate-test", a));
        std::fs::remove_dir_all(dir).ok();
    }
}
