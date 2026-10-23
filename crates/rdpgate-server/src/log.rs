//! A tiny append-only log: `<data dir>/logs/rdpgate.log`, rotated at 10 MB,
//! mirrored to stderr when running in a console.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_BYTES: u64 = 10 * 1024 * 1024;

struct Logger {
    path: Option<PathBuf>,
    file: Mutex<Option<File>>,
    stderr: bool,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Call once at startup. Without it, lines go to stderr only.
pub fn init(dir: Option<PathBuf>, stderr: bool) -> std::io::Result<()> {
    let path = match dir {
        Some(d) => {
            std::fs::create_dir_all(&d)?;
            Some(d.join("rdpgate.log"))
        }
        None => None,
    };
    let file = match &path {
        Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
        None => None,
    };
    let _ = LOGGER.set(Logger { path, file: Mutex::new(file), stderr });
    Ok(())
}

pub fn write(msg: &str) {
    let line = format!("{} {msg}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    let Some(l) = LOGGER.get() else {
        eprint!("{line}");
        return;
    };
    if l.stderr {
        eprint!("{line}");
    }
    let mut guard = l.file.lock().unwrap();
    if let (Some(f), Some(path)) = (guard.as_mut(), &l.path) {
        let _ = f.write_all(line.as_bytes());
        if f.metadata().map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
            *guard = OpenOptions::new().create(true).append(true).open(path).ok();
        }
    }
}

/// Formats a Unix timestamp in local time for logs and CLI output.
pub fn local(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| unix.to_string())
}

#[macro_export]
macro_rules! logln {
    ($($t:tt)*) => { $crate::log::write(&format!($($t)*)) };
}
