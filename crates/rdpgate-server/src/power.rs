//! Keeping the PC awake while someone is signed in. A PC that falls asleep
//! drops the Remote Desktop session and stops answering sign-ins, and nothing
//! on the internet can wake it up again.
//!
//! Uses a Windows power request (what media players and downloads use) rather
//! than changing the power plan: it only applies while held, ends with the
//! process, and `powercfg /requests` shows it with a reason. It doesn't stop
//! someone choosing Sleep, closing a laptop lid or a critically low battery.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub trait Power: Send + Sync + 'static {
    /// Holds (`true`) or releases (`false`) the request. Calling it again with
    /// the same value does nothing.
    fn keep_awake(&self, on: bool) -> Result<(), String>;
}

/// The real power request on Windows when `keep_awake` is on; otherwise one
/// that only records what it would do. The firewall's "dry-run" mode touches
/// nothing on the machine, so it gets the recording one too.
pub fn for_config(cfg: &crate::config::Config) -> Option<Arc<dyn Power>> {
    if !cfg.keep_awake {
        return None;
    }
    #[cfg(windows)]
    if cfg.firewall == "windows" {
        return match windows_power::PowerRequest::new() {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                crate::logln!("ERROR {e}: the PC may sleep during sessions");
                None
            }
        };
    }
    Some(Arc::new(DryRun::default()))
}

/// Logs instead of changing anything. Used off Windows and in tests.
#[derive(Default)]
pub struct DryRun {
    pub awake: AtomicBool,
}

impl Power for DryRun {
    fn keep_awake(&self, on: bool) -> Result<(), String> {
        if self.awake.swap(on, Ordering::SeqCst) != on {
            crate::logln!("POWER (dry-run) keep awake {on}");
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows_power {
    use super::Power;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Power::{PowerClearRequest, PowerCreateRequest, PowerRequestSystemRequired, PowerSetRequest};
    use windows_sys::Win32::System::SystemServices::POWER_REQUEST_CONTEXT_VERSION;
    use windows_sys::Win32::System::Threading::{POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0};

    /// Shown by `powercfg /requests`.
    const REASON: &str = "RDP Gate: someone is signed in to Remote Desktop";

    pub struct PowerRequest {
        handle: HANDLE,
        held: Mutex<bool>,
        /// Windows copies the reason when the request is created; kept anyway
        /// so the pointer it was given stays valid for the handle's lifetime.
        _reason: Vec<u16>,
    }

    // SAFETY: a power request is a kernel handle, usable from any thread, and
    // every set/clear goes through the `held` mutex.
    unsafe impl Send for PowerRequest {}
    unsafe impl Sync for PowerRequest {}

    impl PowerRequest {
        pub fn new() -> Result<Self, String> {
            let mut reason: Vec<u16> = REASON.encode_utf16().chain(Some(0)).collect();
            let ctx = REASON_CONTEXT {
                Version: POWER_REQUEST_CONTEXT_VERSION,
                Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
                Reason: REASON_CONTEXT_0 { SimpleReasonString: reason.as_mut_ptr() },
            };
            let handle = unsafe { PowerCreateRequest(&ctx) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(format!("PowerCreateRequest failed: {}", std::io::Error::last_os_error()));
            }
            Ok(PowerRequest { handle, held: Mutex::new(false), _reason: reason })
        }
    }

    impl Power for PowerRequest {
        fn keep_awake(&self, on: bool) -> Result<(), String> {
            let mut held = self.held.lock().unwrap();
            if *held == on {
                return Ok(());
            }
            let ok = unsafe {
                if on {
                    PowerSetRequest(self.handle, PowerRequestSystemRequired)
                } else {
                    PowerClearRequest(self.handle, PowerRequestSystemRequired)
                }
            };
            if ok == 0 {
                return Err(format!("power request: {}", std::io::Error::last_os_error()));
            }
            *held = on;
            Ok(())
        }
    }

    impl Drop for PowerRequest {
        fn drop(&mut self) {
            unsafe {
                if *self.held.get_mut().unwrap() {
                    PowerClearRequest(self.handle, PowerRequestSystemRequired);
                }
                CloseHandle(self.handle);
            }
        }
    }
}
