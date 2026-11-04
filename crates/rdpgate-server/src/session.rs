//! Starts the notification-area icon in every signed-in Windows session.
//!
//! The Startup folder starts it too, but Startup apps can be turned off (in
//! Task Manager or by cleanup tools), and an icon that quit to update itself
//! may not come back. The service sees every session, so it starts the icon
//! wherever someone has signed in and it isn't running, once per sign-in:
//! someone who chose "Hide this icon until next sign-in" keeps it hidden.
//! The service only; a copy run by hand does nothing here.

use std::time::Duration;
use tokio::sync::watch;

/// How often sessions are looked at.
const EVERY: Duration = Duration::from_secs(15);
/// How long after a sign-in to leave the Startup folder to start the icon.
#[cfg_attr(not(windows), allow(dead_code))]
const GRACE_SECS: u64 = 30;

pub async fn run(mut shutdown: watch::Receiver<bool>) {
    if !crate::status::enabled() {
        return;
    }
    #[cfg(windows)]
    let mut seen = imp::Seen::default();
    loop {
        #[cfg(windows)]
        {
            seen = match tokio::task::spawn_blocking(move || {
                imp::ensure(&mut seen);
                seen
            })
            .await
            {
                Ok(s) => s,
                Err(_) => return,
            };
        }
        tokio::select! {
            _ = tokio::time::sleep(EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::GRACE_SECS;
    use std::collections::{HashMap, HashSet};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSINFOW, WTSQuerySessionInformationW, WTSQueryUserToken, WTSSessionInfo,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW,
    };

    /// Sign-ins already taken care of, by (session, logon time), and when
    /// each was first seen without the icon.
    #[derive(Default)]
    pub struct Seen {
        done: HashSet<(u32, i64)>,
        waiting: HashMap<(u32, i64), Instant>,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Active sessions with someone signed in, with their logon time.
    fn active_sessions() -> Vec<(u32, i64)> {
        let mut out = Vec::new();
        unsafe {
            let mut list: *mut WTS_SESSION_INFOW = null_mut();
            let mut n = 0;
            if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut n) == 0 {
                return out;
            }
            for s in std::slice::from_raw_parts(list, n as usize) {
                if s.State != WTSActive || s.SessionId == 0 {
                    continue;
                }
                let mut info: *mut u16 = null_mut();
                let mut len = 0;
                if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, s.SessionId, WTSSessionInfo, &mut info, &mut len) != 0 {
                    if len as usize >= size_of::<WTSINFOW>() {
                        let i = &*(info as *const WTSINFOW);
                        // A user name means someone has signed in (not the sign-in screen).
                        if i.UserName[0] != 0 {
                            out.push((s.SessionId, i.LogonTime));
                        }
                    }
                    WTSFreeMemory(info.cast());
                }
            }
            WTSFreeMemory(list.cast());
        }
        out
    }

    /// Sessions where `exe` (a file name) is running.
    fn running_in(exe: &str) -> HashSet<u32> {
        let mut out = HashSet::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut e) != 0;
            while ok {
                let end = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                if String::from_utf16_lossy(&e.szExeFile[..end]).eq_ignore_ascii_case(exe) {
                    let mut s = 0;
                    if ProcessIdToSessionId(e.th32ProcessID, &mut s) != 0 {
                        out.insert(s);
                    }
                }
                ok = Process32NextW(snap, &mut e) != 0;
            }
            CloseHandle(snap);
        }
        out
    }

    /// Starts `exe` as the person signed in to `session`, on their desktop.
    fn start_in(session: u32, exe: &std::path::Path) -> Result<(), String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if WTSQueryUserToken(session, &mut token) == 0 {
                return Err(format!("no user token: {}", std::io::Error::last_os_error()));
            }
            let mut env = null_mut();
            let have_env = CreateEnvironmentBlock(&mut env, token, 0) != 0;
            let app: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
            let mut cmd: Vec<u16> = format!("\"{}\"", exe.display()).encode_utf16().chain([0]).collect();
            let dir: Vec<u16> = exe.parent().unwrap_or(exe).as_os_str().encode_wide().chain([0]).collect();
            let mut desktop = wide("winsta0\\default");
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            si.lpDesktop = desktop.as_mut_ptr();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessAsUserW(
                token,
                app.as_ptr(),
                cmd.as_mut_ptr(),
                null(),
                null(),
                0,
                if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 },
                if have_env { env } else { null() },
                dir.as_ptr(),
                &si,
                &mut pi,
            ) != 0;
            let err = std::io::Error::last_os_error();
            if have_env {
                DestroyEnvironmentBlock(env);
            }
            CloseHandle(token);
            if !ok {
                return Err(err.to_string());
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Ok(())
        }
    }

    pub fn ensure(seen: &mut Seen) {
        let Ok(me) = std::env::current_exe() else { return };
        let tray = me.with_file_name(crate::updater::TRAY_EXE);
        if !tray.exists() {
            return;
        }
        let sessions = active_sessions();
        seen.done.retain(|k| sessions.contains(k));
        seen.waiting.retain(|k, _| sessions.contains(k));
        let with_icon = running_in(crate::updater::TRAY_EXE);
        for key in sessions {
            if seen.done.contains(&key) {
                continue;
            }
            if with_icon.contains(&key.0) {
                seen.done.insert(key);
                continue;
            }
            let first = *seen.waiting.entry(key).or_insert_with(Instant::now);
            if first.elapsed().as_secs() < GRACE_SECS {
                continue;
            }
            seen.done.insert(key);
            seen.waiting.remove(&key);
            match start_in(key.0, &tray) {
                Ok(()) => crate::logln!("TRAY started the RDP Gate icon in session {}", key.0),
                Err(e) => crate::logln!("WARNING could not start the RDP Gate icon in session {}: {e}", key.0),
            }
        }
    }
}
