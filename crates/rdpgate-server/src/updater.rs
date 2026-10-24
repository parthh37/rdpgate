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

/// Downloads, verifies and installs `av` over the running executable (blocking).
pub fn install(av: &update::Available) -> Result<(), String> {
    let asset = update::asset_for(Component::Server).ok_or("updates are published for Windows servers only")?;
    let bytes = update::download(av, asset)?;
    let exe = update::replace_current_exe(&bytes)?;
    // The RDP Gate Server window and tray icon live next to the server: keep
    // them in step. The tray icon notices and restarts itself on the new one.
    for (name, component) in [(WINDOW_EXE, Component::ServerApp), (TRAY_EXE, Component::Tray)] {
        let path = exe.with_file_name(name);
        if path.exists()
            && let Some(asset) = update::asset_for(component)
            && let Err(e) = update::download(av, asset).and_then(|b| update::replace_exe(path, &b))
        {
            crate::logln!("UPDATE could not update {name}: {e}");
        }
    }
    Ok(())
}

/// File name of the server's desktop window, installed next to rdpgate-server.exe.
pub const WINDOW_EXE: &str = "RDP Gate Server.exe";
/// File name of the server's notification-area icon, installed next to rdpgate-server.exe.
pub const TRAY_EXE: &str = "rdpgate-tray.exe";

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
