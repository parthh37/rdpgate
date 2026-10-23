//! Windows service integration. The installer registers
//! `rdpgate-server.exe run --service --data <dir>` to start automatically as
//! LocalSystem (changing firewall rules needs administrator rights).

#[cfg(windows)]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const NAME: &str = "RDPGate";
    static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service(data_dir: PathBuf) -> Result<(), String> {
        let _ = DATA_DIR.set(data_dir);
        service_dispatcher::start(NAME, ffi_service_main).map_err(|e| format!("service dispatcher: {e}"))
    }

    fn service_main(_args: Vec<OsString>) {
        let data_dir = DATA_DIR.get().cloned().unwrap_or_else(crate::config::default_data_dir);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handler = move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status) = service_control_handler::register(NAME, handler) else { return };
        let set = |state, code| {
            let _ = status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                // PRESHUTDOWN gives us time to close firewall rules before
                // Windows starts killing services.
                controls_accepted: if state == ServiceState::Running {
                    ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN
                } else {
                    ServiceControlAccept::empty()
                },
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            });
        };
        set(ServiceState::Running, 0);
        let result = crate::run_server(&data_dir, false, rx);
        if let Err(e) = &result {
            crate::logln!("FATAL {e}");
        }
        // A non-zero exit code makes the service manager apply the restart
        // policy: after a failure, and to start a freshly installed version.
        let code = match result {
            Ok(crate::app::Exit::Stopped) => 0,
            Ok(crate::app::Exit::Restart) | Err(_) => 1,
        };
        set(ServiceState::Stopped, code);
    }

    pub fn install(data_dir: &std::path::Path) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|e| format!("open service manager (run as Administrator): {e}"))?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "RDP Gate".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec!["run".into(), "--service".into(), "--data".into(), data_dir.as_os_str().to_owned()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = m
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .map_err(|e| format!("create service: {e}"))?;
        let _ = svc.set_description("Opens Remote Desktop only for signed-in devices and passkeys.");
        // Always restart after a failure. Windows repeats the last action for
        // every later failure, so it never gives up; the scheduled watchdog
        // task (see install-server.ps1) covers a service stopped any other way.
        let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(10), restart(30)]),
        })
        .map_err(|e| format!("set restart-on-failure: {e}"))?;
        svc.set_failure_actions_on_non_crash_failures(true).map_err(|e| format!("set restart-on-failure: {e}"))?;
        svc.start(&[] as &[&OsStr]).map_err(|e| format!("start service: {e}"))?;
        Ok(())
    }

    pub fn status() -> super::Status {
        use super::Status;
        let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return Status::Unknown };
        let Ok(svc) = m.open_service(NAME, ServiceAccess::QUERY_STATUS) else { return Status::NotInstalled };
        match svc.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => Status::Running,
            Ok(ServiceState::Stopped) => Status::Stopped,
            Ok(ServiceState::StartPending | ServiceState::ContinuePending) => Status::Starting,
            Ok(ServiceState::StopPending | ServiceState::PausePending | ServiceState::Paused) => Status::Stopping,
            Err(_) => Status::Unknown,
        }
    }

    /// Starts the service if it is stopped. Returns whether it had to.
    pub fn ensure_running() -> Result<bool, String> {
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("open service manager (run as Administrator): {e}"))?;
        let svc = m
            .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)
            .map_err(|e| format!("open service: {e}"))?;
        if svc.query_status().map_err(|e| format!("query service: {e}"))?.current_state != ServiceState::Stopped {
            return Ok(false);
        }
        svc.start(&[] as &[&OsStr]).map_err(|e| format!("start service: {e}"))?;
        Ok(true)
    }

    /// Stops the service (if running) and starts it again.
    pub fn restart() -> Result<(), String> {
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("open service manager (run as Administrator): {e}"))?;
        let svc = m
            .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START)
            .map_err(|e| format!("open service: {e}"))?;
        if svc.query_status().map(|s| s.current_state != ServiceState::Stopped).unwrap_or(false) {
            let _ = svc.stop();
            for _ in 0..60 {
                std::thread::sleep(Duration::from_millis(500));
                if svc.query_status().map(|s| s.current_state == ServiceState::Stopped).unwrap_or(true) {
                    break;
                }
            }
        }
        svc.start(&[] as &[&OsStr]).map_err(|e| format!("start service: {e}"))
    }

    pub fn uninstall() -> Result<(), String> {
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("open service manager (run as Administrator): {e}"))?;
        let svc = m
            .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
            .map_err(|e| format!("open service: {e}"))?;
        if let Ok(s) = svc.query_status()
            && s.current_state != ServiceState::Stopped
        {
            let _ = svc.stop();
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(500));
                if svc.query_status().map(|s| s.current_state == ServiceState::Stopped).unwrap_or(true) {
                    break;
                }
            }
        }
        svc.delete().map_err(|e| format!("delete service: {e}"))
    }
}

/// What the RDPGate service is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
    Unknown,
}

#[cfg(windows)]
pub use imp::{ensure_running, install, restart, run_as_service, status, uninstall};

#[cfg(not(windows))]
pub fn status() -> Status {
    Status::NotInstalled
}

#[cfg(not(windows))]
pub fn install(_: &std::path::Path) -> Result<(), String> {
    Err("service-install is only available on Windows".into())
}
#[cfg(not(windows))]
pub fn restart() -> Result<(), String> {
    Err("the service only exists on Windows".into())
}
#[cfg(not(windows))]
pub fn ensure_running() -> Result<bool, String> {
    Err("the service only exists on Windows".into())
}
#[cfg(not(windows))]
pub fn uninstall() -> Result<(), String> {
    Err("service-uninstall is only available on Windows".into())
}
#[cfg(not(windows))]
pub fn run_as_service(_: std::path::PathBuf) -> Result<(), String> {
    Err("--service is only available on Windows".into())
}
