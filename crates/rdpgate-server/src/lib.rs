//! RDP Gate server agent: the one thing installed on the Windows machine.

pub mod admin;
pub mod app;
pub mod beacon;
pub mod cert;
pub mod clock;
pub mod config;
pub mod firewall;
pub mod fix;
pub mod gate;
pub mod grants;
pub mod handoff;
pub mod identity;
pub mod limiter;
pub mod router;
pub mod log;
pub mod power;
pub mod protect;
pub mod secure_dir;
pub mod service;
pub mod session;
pub mod state;
pub mod status;
pub mod updater;
pub mod web;

use std::path::Path;
use tokio::sync::watch;

/// Installs the process-wide TLS crypto provider (ring). Safe to call twice.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Loads the config in `data_dir` and serves until `shutdown` flips to true.
pub fn run_server(data_dir: &Path, interactive: bool, shutdown: watch::Receiver<bool>) -> Result<app::Exit, String> {
    install_crypto();
    rdpgate_core::update::cleanup_previous();
    // First, before anything that could fail: no rule may outlive the run
    // that created it, even after a crash or power cut. Only a planned
    // restart moments ago hands its open access over (and only once).
    let taken = handoff::take(data_dir);
    let keep = taken.as_ref().ok().and_then(Option::as_ref).map(handoff::Handoff::ips).unwrap_or_default();
    let swept = firewall::early_sweep(&keep);
    secure_dir::harden(data_dir)?;
    log::init(Some(data_dir.join("logs")), interactive).map_err(|e| format!("open log: {e}"))?;
    if let Err(e) = swept {
        logln!("ERROR removing leftover firewall rules: {e}");
    }
    let taken = match taken {
        Ok(h) => h,
        Err(e) => {
            logln!("RESTART {e}: access open before it was closed");
            None
        }
    };
    if let Some(h) = &taken {
        logln!("RESTART from {} with {} address(es) signed in", h.from, h.grants.len());
    }
    if status::enabled()
        && let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf))
    {
        updater::repair_window(&dir);
        // What updates of the window and the icon left behind (in use then).
        for name in [updater::WINDOW_EXE, updater::TRAY_EXE] {
            let _ = std::fs::remove_file(dir.join(name).with_extension("old.exe"));
        }
    }
    let (cfg, changed) = config::Config::load_noting(data_dir)?;
    logln!("RDP Gate server {}", updater::VERSION);
    for c in changed {
        logln!("CONFIG {c}");
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let fw = firewall::for_config(&cfg);
        let app = app::App::new(cfg, fw)?;
        if let Some(h) = taken {
            app.carry_over(h);
        }
        app::run(app, shutdown).await
    })
}
