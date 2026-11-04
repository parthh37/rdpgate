//! A small public summary of the running service, for the tray icon.
//!
//! The tray runs as whoever signed in to Windows, without Administrator
//! rights, so it can't read the data folder. The service puts what the icon
//! shows in `HKLM\SOFTWARE\RDPGate\Status`, which everyone signed in to this
//! PC can read and only Administrators and SYSTEM can change: which computers
//! have access open and whether Remote Desktop is connected, and what's
//! wrong (Windows Firewall off, the clock off). Never addresses, keys or
//! tokens. The key is volatile, so it's gone after a reboot, and the value is
//! removed when the service stops.

use crate::grants::Grant;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Public {
    pub version: String,
    /// The service's process, to tell its runs apart.
    pub pid: u32,
    pub signed_in: Vec<SignedIn>,
    pub warnings: Vec<String>,
}

/// One computer (or passkey) with access open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedIn {
    /// "macbook", "passkey phone".
    pub name: String,
    /// Remote Desktop is connected from it right now.
    pub connected: bool,
    /// Unix time when its access ends unless it stays connected.
    pub expires: i64,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static CURRENT: Mutex<Option<Public>> = Mutex::new(None);

/// Publishes from now on. Only the service does: a test or a second copy
/// run by hand must not overwrite what the service says.
pub fn enable() {
    ENABLED.store(true, Ordering::SeqCst);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

fn update(f: impl FnOnce(&mut Public)) {
    if !enabled() {
        return;
    }
    let mut cur = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let first = cur.is_none();
    let p = cur.get_or_insert_with(|| Public {
        version: crate::updater::VERSION.into(),
        pid: std::process::id(),
        ..Default::default()
    });
    let before = p.clone();
    f(p);
    if (first || *p != before)
        && let Ok(json) = serde_json::to_string(p)
    {
        imp::write(&json);
    }
}

/// Publishes the summary as it is now: the service has started.
pub fn started() {
    update(|_| {});
}

/// "device macbook with 2001:db8::1" → "macbook".
fn display_name(who: &str) -> String {
    let who = who.split(" with ").next().unwrap_or(who);
    who.strip_prefix("device ").unwrap_or(who).chars().take(64).collect()
}

/// The open grants, one entry per computer (IPv4 and IPv6 together).
pub fn set_grants<'a>(grants: impl Iterator<Item = &'a Grant>) {
    let mut list: Vec<SignedIn> = Vec::new();
    for g in grants {
        let name = display_name(&g.who);
        let connected = g.last_connected.is_some_and(|c| crate::state::now() - c < 30);
        match list.iter_mut().find(|s| s.name == name) {
            Some(s) => {
                s.connected |= connected;
                s.expires = s.expires.max(g.expires);
            }
            None => list.push(SignedIn { name, connected, expires: g.expires }),
        }
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    update(|p| p.signed_in = list);
}

pub fn set_warnings(w: Vec<String>) {
    update(|p| p.warnings = w);
}

/// Removes the summary: the service is stopping.
pub fn clear() {
    if enabled() {
        *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        imp::remove();
    }
}

/// What the service published, if it is running and publishing.
pub fn read() -> Option<Public> {
    serde_json::from_str(&imp::read()?).ok()
}

#[cfg(windows)]
mod imp {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_OPTION_VOLATILE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
        RegDeleteKeyValueW, RegGetValueW, RegSetValueExW,
    };

    const KEY: &str = r"SOFTWARE\RDPGate";
    const VALUE: &str = "Status";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    pub fn write(json: &str) {
        let (key, value, data) = (wide(KEY), wide(VALUE), wide(json));
        unsafe {
            let mut h: HKEY = null_mut();
            let rc = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                0,
                null(),
                REG_OPTION_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut h,
                null_mut(),
            );
            if rc != ERROR_SUCCESS {
                return;
            }
            RegSetValueExW(h, value.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32);
            RegCloseKey(h);
        }
    }

    pub fn remove() {
        let (key, value) = (wide(KEY), wide(VALUE));
        unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr()) };
    }

    pub fn read() -> Option<String> {
        let (key, value) = (wide(KEY), wide(VALUE));
        let mut size: u32 = 0;
        unsafe {
            if RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, null_mut(), null_mut(), &mut size)
                != ERROR_SUCCESS
                || size == 0
                || size > 256 * 1024
            {
                return None;
            }
            let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
            size = (buf.len() * 2) as u32;
            if RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr().cast(), &mut size)
                != ERROR_SUCCESS
            {
                return None;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Some(String::from_utf16_lossy(&buf[..end]))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn write(_: &str) {}
    pub fn remove() {}
    pub fn read() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_never_carry_addresses() {
        assert_eq!(display_name("device macbook with 2405:201::1"), "macbook");
        assert_eq!(display_name("passkey phone"), "passkey phone");
    }
}
