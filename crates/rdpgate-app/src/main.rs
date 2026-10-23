//! RDP Gate desktop app for macOS and Windows: set up this computer's device
//! key once, then sign in with passphrase + 6-digit code and Remote Desktop
//! opens. Shares its settings folder with the `rdpgate` command-line tool.

#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText, TextEdit};
use ed25519_dalek::SigningKey;
use rdpgate_client::{self as client, Grant, Identity, RdpCheck};
use rdpgate_core::update::{Available, Component};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use zeroize::Zeroizing;

fn main() -> eframe::Result {
    rdpgate_core::update::cleanup_previous();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RDP Gate")
            .with_inner_size([460.0, 500.0])
            .with_min_inner_size([400.0, 440.0]),
        ..Default::default()
    };
    eframe::run_native("RDP Gate", options, Box::new(|_cc| Ok(Box::new(GateApp::new()))))
}

/// The one prominent action on each screen.
fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
        .fill(Color32::from_rgb(36, 87, 214))
        .min_size(egui::vec2(220.0, 32.0))
}

const GOOD: Color32 = Color32::from_rgb(40, 150, 80);
const BAD: Color32 = Color32::from_rgb(210, 70, 60);

enum Screen {
    Setup,
    Enroll(Identity),
    Main,
}

struct Session {
    grant: Grant,
    key: SigningKey,
    rdp_file: PathBuf,
    check: RdpCheck,
}

/// Self-update progress, shown as a banner.
enum Upd {
    Idle,
    Checking,
    UpToDate,
    Available(Box<Available>),
    Installing,
    Installed { version: String, relaunch: PathBuf },
    Failed(String),
}

enum UpdMsg {
    Checked(Result<Option<Available>, String>),
    Installed(Result<(String, PathBuf), String>),
}

/// Starts the freshly installed version and quits this one.
fn relaunch(target: &std::path::Path) {
    let started = if cfg!(target_os = "macos") {
        std::process::Command::new("/usr/bin/open").arg("-n").arg(target).spawn()
    } else {
        std::process::Command::new(target).spawn()
    };
    if started.is_ok() {
        std::process::exit(0);
    }
}

/// Results of work done off the UI thread (Argon2 and the network are slow).
enum Done {
    Created(Result<Identity, String>),
    SignedIn(Result<Box<Session>, String>),
    Locked(Result<String, String>),
}

struct GateApp {
    dir: PathBuf,
    screen: Screen,
    // setup form
    device: String,
    username: String,
    pass1: Zeroizing<String>,
    pass2: Zeroizing<String>,
    // server card
    card_text: String,
    // sign-in form
    passphrase: Zeroizing<String>,
    code: String,
    session: Option<Session>,
    busy: Option<&'static str>,
    status: Option<(bool, String)>,
    rx: Option<Receiver<Done>>,
    upd: Upd,
    upd_rx: Option<Receiver<UpdMsg>>,
    upd_started: bool,
}

fn default_device_name() -> String {
    // GUI apps on macOS get no HOSTNAME variable; ask the system instead.
    let mac_name = || {
        std::process::Command::new("/usr/sbin/scutil")
            .args(["--get", "LocalHostName"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(())
    };
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| if cfg!(target_os = "macos") { mac_name() } else { Err(()) })
        .unwrap_or_else(|_| "my-computer".into());
    let s: String = raw
        .trim_end_matches(".local")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .take(32)
        .collect();
    if s.trim_matches('-').is_empty() { "my-computer".into() } else { s }
}

fn rt() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())
}

impl GateApp {
    fn new() -> Self {
        let dir = client::default_dir();
        let screen = if client::is_set_up(&dir) { Screen::Main } else { Screen::Setup };
        GateApp {
            dir,
            screen,
            device: default_device_name(),
            username: String::new(),
            pass1: Default::default(),
            pass2: Default::default(),
            card_text: String::new(),
            passphrase: Default::default(),
            code: String::new(),
            session: None,
            busy: None,
            status: None,
            rx: None,
            upd: Upd::Idle,
            upd_rx: None,
            upd_started: false,
        }
    }

    fn start_update_check(&mut self, ctx: &egui::Context) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        client::mark_update_checked(&self.dir);
        std::thread::spawn(move || {
            let _ = tx.send(UpdMsg::Checked(client::check_update()));
            ctx.request_repaint();
        });
        self.upd = Upd::Checking;
        self.upd_rx = Some(rx);
    }

    fn start_update_install(&mut self, ctx: &egui::Context, av: Available) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = client::install_update(&av, Component::App).map(|p| (av.version.to_string(), p));
            let _ = tx.send(UpdMsg::Installed(r));
            ctx.request_repaint();
        });
        self.upd = Upd::Installing;
        self.upd_rx = Some(rx);
    }

    /// Checks once a day at launch (if enabled) and installs automatically
    /// when the user allowed it.
    fn poll_update(&mut self, ctx: &egui::Context) {
        if !self.upd_started {
            self.upd_started = true;
            if client::load_config(&self.dir).map(|c| client::update_due(&c)).unwrap_or(false) {
                self.start_update_check(ctx);
            }
        }
        let Some(rx) = &self.upd_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.upd_rx = None;
        match msg {
            UpdMsg::Checked(Ok(None)) => self.upd = Upd::UpToDate,
            UpdMsg::Checked(Ok(Some(av))) => {
                let auto = client::load_config(&self.dir).map(|c| c.auto_update).unwrap_or(false);
                if auto {
                    self.start_update_install(ctx, av);
                } else {
                    self.upd = Upd::Available(Box::new(av));
                }
            }
            UpdMsg::Installed(Ok((version, relaunch))) => self.upd = Upd::Installed { version, relaunch },
            UpdMsg::Checked(Err(e)) | UpdMsg::Installed(Err(e)) => self.upd = Upd::Failed(e),
        }
    }

    fn update_banner(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        match &self.upd {
            Upd::Installed { version, relaunch: target } => {
                let target = target.clone();
                ui.horizontal(|ui| {
                    ui.colored_label(GOOD, format!("Updated to {version}."));
                    if ui.button("Restart now").clicked() {
                        relaunch(&target);
                    }
                });
            }
            Upd::Available(av) => {
                let av = (**av).clone();
                ui.horizontal(|ui| {
                    ui.label(format!("Version {} is available.", av.version));
                    if ui.button("Install update").clicked() {
                        self.start_update_install(&ctx, av);
                    }
                });
            }
            Upd::Installing => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Installing update…");
                });
            }
            _ => return,
        }
        ui.add_space(8.0);
    }

    fn run(&mut self, ctx: &egui::Context, label: &'static str, job: impl FnOnce() -> Done + Send + 'static) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(job());
            ctx.request_repaint();
        });
        self.rx = Some(rx);
        self.busy = Some(label);
        self.status = None;
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        let Ok(done) = rx.try_recv() else { return };
        self.rx = None;
        self.busy = None;
        match done {
            Done::Created(Ok(id)) => {
                self.pass1 = Default::default();
                self.pass2 = Default::default();
                self.screen = Screen::Enroll(id);
            }
            Done::SignedIn(Ok(s)) => {
                let msg = match &s.check {
                    RdpCheck::Verified => format!("Access open for {}. Remote Desktop verified and opening…", s.grant.ip),
                    RdpCheck::Unchecked(why) => {
                        format!("Access open for {}. Couldn't verify the Remote Desktop certificate ({why}).", s.grant.ip)
                    }
                };
                self.status = Some((true, msg));
                self.passphrase = Default::default();
                self.code.clear();
                self.session = Some(*s);
            }
            Done::Locked(Ok(ip)) => {
                self.status = Some((true, format!("Access closed for {ip}.")));
                self.session = None;
            }
            Done::Created(Err(e)) | Done::SignedIn(Err(e)) | Done::Locked(Err(e)) => self.status = Some((false, e)),
        }
    }

    fn setup_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Set up this computer");
        ui.label("RDP Gate creates a private key for this computer. You enroll it on the server once; after that this computer can sign in.");
        ui.add_space(12.0);
        egui::Grid::new("setup").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("This computer");
            ui.add(TextEdit::singleline(&mut self.device).hint_text("macbook"));
            ui.end_row();
            ui.label("Windows user");
            ui.add(TextEdit::singleline(&mut self.username).hint_text("optional"));
            ui.end_row();
            ui.label("Passphrase");
            ui.add(TextEdit::singleline(&mut *self.pass1).password(true).hint_text(format!("at least {} characters", client::MIN_PASSPHRASE)));
            ui.end_row();
            ui.label("Repeat");
            ui.add(TextEdit::singleline(&mut *self.pass2).password(true));
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.small("The passphrase encrypts the key on this computer. It is never sent anywhere and cannot be recovered.");
        ui.add_space(12.0);
        if ui.add_enabled(self.busy.is_none(), primary("Create device key")).clicked() {
            if *self.pass1 != *self.pass2 {
                self.status = Some((false, "The passphrases don't match.".into()));
            } else {
                let (dir, pass, device) = (self.dir.clone(), self.pass1.clone(), self.device.trim().to_string());
                let user = Some(self.username.trim().to_string());
                let ctx = ui.ctx().clone();
                self.run(&ctx, "Creating key…", move || Done::Created(client::create_device(&dir, &device, user, &pass, false)));
            }
        }
    }

    /// Paste box for the server card. Returns true once a valid card is saved.
    fn card_ui(&mut self, ui: &mut egui::Ui) -> bool {
        ui.add(
            TextEdit::multiline(&mut self.card_text)
                .hint_text("rdpgate-card:…")
                .font(egui::TextStyle::Monospace)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        if ui.add_enabled(!self.card_text.trim().is_empty(), primary("Save server card")).clicked() {
            match client::set_card(&self.dir, &self.card_text) {
                Ok(fp) => {
                    self.status = Some((true, format!("Server card saved. Server key fingerprint {fp}.")));
                    self.card_text.clear();
                    return true;
                }
                Err(e) => self.status = Some((false, e)),
            }
        }
        false
    }

    fn enroll_ui(&mut self, ui: &mut egui::Ui, id: &Identity) {
        ui.heading("Enroll this computer");
        ui.label("1. On the Windows server, in PowerShell as Administrator, run:");
        let mut cmd = id.enroll_command();
        ui.add(TextEdit::multiline(&mut cmd).font(egui::TextStyle::Monospace).desired_rows(3).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            if ui.button("Copy command").clicked() {
                ui.ctx().copy_text(id.enroll_command());
            }
            ui.label(RichText::new(&id.fingerprint).monospace().small());
        });
        ui.small("The server prints this fingerprint too; check they match.");
        ui.add_space(14.0);
        ui.label("2. Paste the server card it prints back here:");
        if self.card_ui(ui) {
            self.screen = Screen::Main;
        }
    }

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        let cfg = match client::load_config(&self.dir) {
            Ok(c) => c,
            Err(e) => {
                ui.colored_label(BAD, e);
                return;
            }
        };
        self.update_banner(ui);
        ui.heading("Remote Desktop");
        match client::card(&cfg) {
            Ok(c) => {
                let fp = rdpgate_core::wire::fingerprint(&c.server_key());
                ui.label(format!("{} → server {}", cfg.device, &fp[..9]));
            }
            Err(_) => {
                ui.label("Paste the server card (run rdpgate-server card on the server):");
                self.card_ui(ui);
                return;
            }
        }
        ui.add_space(14.0);

        if let Some(s) = &self.session {
            ui.label(RichText::new(format!("Open for {}", s.grant.ip)).strong());
            ui.label(format!(
                "Start Remote Desktop within {}. Access stays open while you're connected.",
                client::minutes_left(s.grant.expires)
            ));
            if s.check == RdpCheck::Verified {
                ui.colored_label(GOOD, "Remote Desktop certificate verified");
            }
            ui.add_space(10.0);
            let (file, key) = (s.rdp_file.clone(), s.key.clone());
            ui.horizontal(|ui| {
                if ui.button("Open Remote Desktop").clicked()
                    && let Err(e) = client::launch_rdp(&file)
                {
                    self.status = Some((false, e));
                }
                if ui.add_enabled(self.busy.is_none(), egui::Button::new("Close access now")).clicked() {
                    let (dir, cfg) = (self.dir.clone(), cfg.clone());
                    let ctx = ui.ctx().clone();
                    self.run(&ctx, "Closing…", move || {
                        Done::Locked(rt().and_then(|rt| rt.block_on(client::lock(&dir, &cfg, &key))))
                    });
                }
            });
            ui.add_space(10.0);
            ui.small("Anyone who shares your public IP (same Wi-Fi or mobile carrier) can reach the Windows login screen until access closes. They still need your Windows password.");
            return;
        }

        egui::Grid::new("signin").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("Passphrase");
            ui.add(TextEdit::singleline(&mut *self.passphrase).password(true));
            ui.end_row();
            ui.label("6-digit code");
            ui.add(TextEdit::singleline(&mut self.code).char_limit(6).hint_text("from your authenticator app"));
            ui.end_row();
        });
        ui.add_space(12.0);
        let submit = ui.input(|i| i.key_pressed(egui::Key::Enter)) && self.code.len() == 6;
        if (ui.add_enabled(self.busy.is_none(), primary("Sign in and open Remote Desktop")).clicked() || submit)
            && self.busy.is_none()
        {
            let (dir, pass, code) = (self.dir.clone(), self.passphrase.clone(), self.code.trim().to_string());
            let (ctx, cfg) = (ui.ctx().clone(), cfg.clone());
            self.run(&ctx, "Finding your server and signing in…", move || {
                let result = (|| {
                    let key = client::unlock(&dir, &pass)?;
                    let rt = rt()?;
                    let grant = rt.block_on(client::sign_in(&dir, &cfg, &key, &code))?;
                    // A certificate mismatch is an error: never launch into an interception.
                    let check = rt.block_on(client::verify_rdp(&grant))?;
                    let rdp_file = client::write_rdp_file(&dir, &cfg, &grant)?;
                    client::launch_rdp(&rdp_file)?;
                    Ok(Box::new(Session { grant, key, rdp_file, check }))
                })();
                Done::SignedIn(result)
            });
        }

        ui.add_space(24.0);
        egui::CollapsingHeader::new("This computer and server").show(ui, |ui| {
            if let Ok(id) = client::identity(&self.dir) {
                ui.label(format!("Device key {}", id.fingerprint));
                if ui.button("Copy enrollment command").clicked() {
                    ui.ctx().copy_text(id.enroll_command());
                }
            }
            if let Some(a) = cfg.last_known {
                ui.label(format!("Server last seen at {a}"));
            }
            ui.separator();
            let mut auto = cfg.auto_update;
            if ui.checkbox(&mut auto, "Update automatically (signed updates only)").changed() {
                let _ = client::set_auto_update(&self.dir, auto);
            }
            ui.horizontal(|ui| {
                ui.label(format!("Version {}", client::VERSION));
                let checking = matches!(self.upd, Upd::Checking | Upd::Installing);
                if ui.add_enabled(!checking, egui::Button::new("Check for updates")).clicked() {
                    let ctx = ui.ctx().clone();
                    self.start_update_check(&ctx);
                }
            });
            match &self.upd {
                Upd::Checking => {
                    ui.small("Checking…");
                }
                Upd::UpToDate => {
                    ui.small("You have the latest version.");
                }
                Upd::Failed(e) => {
                    ui.colored_label(BAD, format!("Update: {e}"));
                }
                _ => {}
            }
            ui.separator();
            ui.label("Replace the server card:");
            self.card_ui(ui);
        });
    }
}

impl eframe::App for GateApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if matches!(self.screen, Screen::Main) {
            let ctx = ui.ctx().clone();
            self.poll_update(&ctx);
        }
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(6.0);
                match &self.screen {
                    Screen::Setup => self.setup_ui(ui),
                    Screen::Enroll(id) => {
                        let id = id.clone();
                        self.enroll_ui(ui, &id);
                    }
                    Screen::Main => self.main_ui(ui),
                }
                ui.add_space(16.0);
                if let Some(label) = self.busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(label);
                    });
                }
                if let Some((ok, msg)) = &self.status {
                    ui.colored_label(if *ok { GOOD } else { BAD }, msg);
                }
            });
        });
    }
}
