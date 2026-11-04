//! Keeps the server up to date. Once a day it asks GitHub for a newer signed
//! release; if there is one, it waits until nobody has access open (so no
//! session is cut), swaps in the new rdpgate-server.exe and asks the service
//! manager to restart it.

use crate::app::App;
use rdpgate_core::update::{self, Component};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const FIRST_CHECK: Duration = Duration::from_secs(10 * 60);
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
const IDLE_POLL: Duration = Duration::from_secs(5 * 60);
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Downloads, verifies and installs `av` (blocking). Run by the service, by
/// `rdpgate-server update` and by the RDP Gate Server window: each program
/// is replaced by its file name in the install folder, never "whatever is
/// running", so the window can't put the server in its own place.
pub fn install(av: &update::Available) -> Result<(), String> {
    let dir = install_dir()?;
    let asset = update::asset_for(Component::Server).ok_or("updates are published for Windows servers only")?;
    let bytes = update::download(av, asset)?;
    update::replace_exe(dir.join(SERVER_EXE), &bytes)?;
    // The RDP Gate Server window and tray icon live next to the server: keep
    // them in step. The tray icon notices and restarts itself on the new one.
    for (name, component) in [(WINDOW_EXE, Component::ServerApp), (TRAY_EXE, Component::Tray)] {
        let path = dir.join(name);
        if path.exists()
            && let Some(asset) = update::asset_for(component)
            && let Err(e) = update::download(av, asset).and_then(|b| update::replace_exe(path, &b))
        {
            crate::logln!("UPDATE could not update {name}: {e}");
        }
    }
    Ok(())
}

/// The folder RDP Gate is installed in: where this program is.
fn install_dir() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent().map(std::path::Path::to_path_buf).ok_or_else(|| "can't tell where RDP Gate is installed".into())
}

/// File name of the server (and service), in the install folder.
pub const SERVER_EXE: &str = "rdpgate-server.exe";
/// File name of the server's desktop window, installed next to rdpgate-server.exe.
pub const WINDOW_EXE: &str = "RDP Gate Server.exe";
/// File name of the server's notification-area icon, installed next to rdpgate-server.exe.
pub const TRAY_EXE: &str = "rdpgate-tray.exe";

/// Repairs the RDP Gate Server window if an update from the window itself
/// (in 1.5.1 and earlier) put a copy of the server in its place, leaving the
/// real window behind as "RDP Gate Server.new.exe". Run by the service.
pub fn repair_window(dir: &std::path::Path) {
    let (window, server) = (dir.join(WINDOW_EXE), dir.join(SERVER_EXE));
    let same = |a: &std::path::Path, b: &std::path::Path| -> bool {
        match (std::fs::read(a), std::fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    };
    let (Ok(w), Ok(s)) = (std::fs::metadata(&window), std::fs::metadata(&server)) else { return };
    if w.len() != s.len() || !same(&window, &server) {
        return;
    }
    let left = window.with_extension("new.exe");
    if std::fs::metadata(&left).is_ok_and(|m| m.len() > 0) && !same(&left, &server) {
        let broken = window.with_extension("broken.exe");
        let _ = std::fs::remove_file(&broken);
        match std::fs::rename(&window, &broken).and_then(|()| std::fs::rename(&left, &window)) {
            Ok(()) => {
                let _ = std::fs::remove_file(&broken);
                crate::logln!("REPAIR {WINDOW_EXE} had been replaced by a copy of the server; put the window back");
            }
            Err(e) => {
                let _ = std::fs::rename(&broken, &window);
                crate::logln!("WARNING {WINDOW_EXE} is a copy of the server and could not be repaired ({e}): run RDP Gate Server Setup again");
            }
        }
    } else {
        crate::logln!("WARNING {WINDOW_EXE} is a copy of the server: run RDP Gate Server Setup again (the next update also repairs it)");
    }
}

async fn sleep_or_stop(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = shutdown.changed() => false,
    }
}

pub async fn run(app: Arc<App>, mut shutdown: watch::Receiver<bool>) {
    if !app.cfg.auto_update || update::asset_for(Component::Server).is_none() {
        return;
    }
    if !sleep_or_stop(FIRST_CHECK, &mut shutdown).await {
        return;
    }
    let mut last_error = String::new();
    loop {
        let pre = app.cfg.update_prereleases;
        match tokio::task::spawn_blocking(move || update::check(VERSION, pre)).await {
            Ok(Ok(Some(av))) => {
                crate::logln!("UPDATE available: {} (running {VERSION})", av.version);
                // Never cut an open session: wait until no grants remain.
                while !app.grants.list().await.is_empty() {
                    if !sleep_or_stop(IDLE_POLL, &mut shutdown).await {
                        return;
                    }
                }
                let v = av.version.clone();
                match tokio::task::spawn_blocking(move || install(&av)).await {
                    Ok(Ok(())) => {
                        crate::logln!("UPDATE installed {v}; restarting");
                        app.request_restart();
                        return;
                    }
                    Ok(Err(e)) => crate::logln!("UPDATE failed: {e}"),
                    Err(_) => return,
                }
            }
            Ok(Ok(None)) => last_error.clear(),
            Ok(Err(e)) => {
                if e != last_error {
                    crate::logln!("UPDATE check failed: {e}");
                    last_error = e;
                }
            }
            Err(_) => return,
        }
        if !sleep_or_stop(CHECK_EVERY, &mut shutdown).await {
            return;
        }
    }
}
