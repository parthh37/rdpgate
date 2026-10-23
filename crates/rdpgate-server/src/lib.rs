//! RDP Gate server agent: the one thing installed on the Windows machine.

pub mod app;
pub mod beacon;
pub mod config;
pub mod firewall;
pub mod gate;
pub mod grants;
pub mod identity;
pub mod limiter;
pub mod log;
pub mod power;
pub mod secure_dir;
pub mod service;
pub mod state;
pub mod web;

use std::path::Path;
use tokio::sync::watch;

/// Installs the process-wide TLS crypto provider (ring). Safe to call twice.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Loads the config in `data_dir` and serves until `shutdown` flips to true.
pub fn run_server(data_dir: &Path, interactive: bool, shutdown: watch::Receiver<bool>) -> Result<(), String> {
    install_crypto();
    // First, before anything that could fail: no rule may outlive the run
    // that created it, even after a crash or power cut.
    let swept = firewall::early_sweep();
    secure_dir::harden(data_dir)?;
    log::init(Some(data_dir.join("logs")), interactive).map_err(|e| format!("open log: {e}"))?;
    if let Err(e) = swept {
        logln!("ERROR removing leftover firewall rules: {e}");
    }
    let cfg = config::Config::load(data_dir)?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let fw = firewall::for_config(&cfg);
        let app = app::App::new(cfg, fw)?;
        app::run(app, shutdown).await
    })
}
