//! This PC's clock, corrected from internet time when it's wrong.
//!
//! Every sign-in is checked against the time: the request's timestamp, the
//! 6-digit code, the beacon's freshness. A clock that is hours off (a virtual
//! machine whose hardware clock is read in the wrong time zone at boot, a
//! dead CMOS battery, Windows Time stopped) would make the server refuse
//! everyone after a reboot, with nobody at the PC to fix it.
//!
//! So the service reads the real time from the internet (see
//! [`rdpgate_core::nettime`]). If the system clock is off, RDP Gate keeps the
//! real time on the monotonic clock, which a later correction or jump of the
//! system clock can't disturb, and asks Windows to set its own clock right.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

/// Below this the system clock is used as it is.
pub const TOLERANCE: i64 = 30;
/// How often the time is checked while the system clock is right.
const CHECK_EVERY: Duration = Duration::from_secs(3600);
/// How often while it's wrong (to notice when Windows has set it right).
const CHECK_WRONG_EVERY: Duration = Duration::from_secs(300);
/// Before the first answer: at boot the network may still be coming up.
const RETRY_EVERY: Duration = Duration::from_secs(20);
/// How often the system clock is watched for jumps (sleep, a correction).
const LOOK_EVERY: Duration = Duration::from_secs(15);

/// The real Unix time at an instant, when the system clock is wrong.
static REAL: Mutex<Option<(i64, Instant)>> = Mutex::new(None);

fn system_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The current Unix time: the system clock, or internet time when the system
/// clock was found to be wrong.
pub fn now() -> i64 {
    match *REAL.lock().unwrap_or_else(|e| e.into_inner()) {
        Some((unix, at)) => unix + at.elapsed().as_secs() as i64,
        None => system_now(),
    }
}

/// Seconds the system clock is behind (negative: ahead) the time in use.
pub fn system_error() -> i64 {
    now() - system_now()
}

/// Uses `m` from now on. Returns the system clock's error if it is off by
/// more than [`TOLERANCE`].
pub fn apply(m: &rdpgate_core::nettime::Measured) -> Option<i64> {
    let mut real = REAL.lock().unwrap_or_else(|e| e.into_inner());
    if m.offset.abs() > TOLERANCE {
        *real = Some((m.unix, m.at));
        Some(m.offset)
    } else {
        *real = None;
        None
    }
}

/// Reads the time from the internet and uses it from now on. Blocking.
pub fn sync() -> Result<Option<i64>, String> {
    rdpgate_core::nettime::measure().map(|m| apply(&m))
}

/// Starts [`sync`] in the background, for the window and the command line.
pub fn sync_in_background() {
    std::thread::spawn(|| {
        let _ = sync();
    });
}

/// "5 h 30 min behind", "2 min ahead".
pub fn describe(error: i64) -> String {
    format!("{} {}", span(error.abs()), if error > 0 { "behind" } else { "ahead" })
}

/// `secs` for people: "2 min", "5 h 30 min", "3 days 2 h".
pub fn span(secs: i64) -> String {
    let n = secs.max(0);
    match (n / 86400, n % 86400 / 3600) {
        (0, 0) => format!("{} min", (n + 59) / 60),
        (0, h) => format!("{h} h {} min", n % 3600 / 60),
        (d, h) => format!("{d} days {h} h"),
    }
}

/// The warning shown in RDP Gate Server and `status` while the clock is off.
pub fn warning(error: i64) -> String {
    format!(
        "this PC's clock is {} the real time. RDP Gate uses internet time, so sign-in still works; \
         Windows was asked to set its clock (Settings > Time & language > Date & time > Sync now)",
        describe(error)
    )
}

/// Asks Windows to set its clock right: Windows Time starts automatically
/// and syncs now. Windows normally leaves it to start on demand and syncs
/// about once a week, so a wrong clock after a reboot can stay wrong.
#[cfg(windows)]
pub fn fix_windows_time() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let run = |exe: &str, args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new(format!(r"{root}\System32\{exe}"))
            .args(args)
            .stdin(std::process::Stdio::null())
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("{exe}: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        if out.status.success() { Ok(text) } else { Err(format!("{exe} {}: {}", args.join(" "), text.trim())) }
    };
    run("sc.exe", &["config", "W32Time", "start=", "auto"])?;
    // Already running is fine.
    let _ = run("sc.exe", &["start", "W32Time"]);
    std::thread::sleep(Duration::from_secs(2));
    // Large corrections are allowed (standalone PCs accept up to 48 h).
    run("w32tm.exe", &["/resync", "/force"]).map(|_| ())
}

#[cfg(not(windows))]
pub fn fix_windows_time() -> Result<(), String> {
    Ok(())
}

/// The service's clock watch: checks at start (retrying while the network
/// comes up), then regularly, and again whenever the system clock jumps.
/// `warn` is told the current clock warning (`None` once the clock is right).
pub async fn run(mut warn: impl FnMut(Option<String>) + Send, mut shutdown: watch::Receiver<bool>) {
    let mut next = Instant::now();
    let mut measured = false;
    let mut last_error: Option<String> = None;
    let mut asked_windows = false;
    // The system clock against the monotonic one, to see jumps.
    let mut mark = (system_now(), Instant::now());
    loop {
        let (sys, at) = mark;
        let jumped = (system_now() - sys - at.elapsed().as_secs() as i64).abs() > TOLERANCE;
        mark = (system_now(), Instant::now());
        if jumped || Instant::now() >= next {
            match tokio::task::spawn_blocking(sync).await {
                Ok(Ok(err)) => {
                    measured = true;
                    last_error = None;
                    match err {
                        Some(e) => {
                            if !asked_windows {
                                crate::logln!("CLOCK this PC's clock is {}: using internet time", describe(e));
                                asked_windows = true;
                                match tokio::task::spawn_blocking(fix_windows_time).await {
                                    Ok(Ok(())) => crate::logln!("CLOCK asked Windows Time to set the clock"),
                                    Ok(Err(e)) => crate::logln!("WARNING could not ask Windows Time to set the clock: {e}"),
                                    Err(_) => {}
                                }
                            }
                            warn(Some(warning(e)));
                            next = Instant::now() + CHECK_WRONG_EVERY;
                        }
                        None => {
                            if asked_windows {
                                crate::logln!("CLOCK this PC's clock is right again");
                                asked_windows = false;
                            }
                            warn(None);
                            next = Instant::now() + CHECK_EVERY;
                        }
                    }
                }
                Ok(Err(e)) => {
                    if last_error.as_deref() != Some(e.as_str()) && !measured {
                        crate::logln!("CLOCK {e} (using this PC's clock meanwhile)");
                    }
                    last_error = Some(e);
                    next = Instant::now() + if measured { CHECK_WRONG_EVERY } else { RETRY_EVERY };
                }
                Err(_) => return,
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(LOOK_EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdpgate_core::nettime::Measured;

    #[test]
    fn a_wrong_clock_is_replaced_and_a_right_one_kept() {
        let real = system_now() + 19_800;
        assert_eq!(apply(&Measured { unix: real, at: Instant::now(), offset: 19_800 }), Some(19_800));
        assert!((now() - real).abs() <= 1);
        assert!((system_error() - 19_800).abs() <= 1);
        assert_eq!(apply(&Measured { unix: system_now() + 3, at: Instant::now(), offset: 3 }), None);
        assert!((now() - system_now()).abs() <= 1);
    }

    #[test]
    fn describes_errors() {
        assert_eq!(describe(19_800), "5 h 30 min behind");
        assert_eq!(describe(-90), "2 min ahead");
        assert_eq!(describe(3 * 86400 + 7200), "3 days 2 h behind");
    }
}
