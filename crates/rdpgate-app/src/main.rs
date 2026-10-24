//! RDP Gate desktop app for macOS and Windows: set up this computer's device
//! key once, then sign in with passphrase + 6-digit code and Remote Desktop
//! opens. Shares its settings folder with the `rdpgate` command-line tool.

#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui::{self, RichText, TextEdit};
use ed25519_dalek::SigningKey;
use rdpgate_client::{self as client, Grant, Identity, RdpCheck};
use rdpgate_core::update::{Available, Component};
use rdpgate_ui::{self as theme, MUTED, Tone, muted, primary, primary_wide};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use zeroize::Zeroizing;

/// Passed to the relaunched app when Direct3D couldn't start (Windows).
const OPENGL_ARG: &str = "--opengl";

fn main() -> eframe::Result {
    rdpgate_core::update::cleanup_previous();
    let opengl = !cfg!(windows) || std::env::args().any(|a| a == OPENGL_ARG);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RDP Gate")
            .with_inner_size([500.0, 640.0])
            .with_min_inner_size([420.0, 520.0]),
        #[cfg(windows)]
        renderer: if opengl { eframe::Renderer::Glow } else { eframe::Renderer::Wgpu },
        ..Default::default()
    };
    let result = eframe::run_native("RDP Gate", options, Box::new(|cc| {
        theme::apply(&cc.egui_ctx);
        Ok(Box::new(GateApp::new()))
    }));
    // A window can only be opened once per process, so try OpenGL in a new one.
    if result.is_err()
        && !opengl
        && let Ok(exe) = std::env::current_exe()
        && std::process::Command::new(exe).arg(OPENGL_ARG).spawn().is_ok()
    {
        return Ok(());
    }
    result
}

/// The steps of getting a computer ready, shown at the top of each.
const STEPS: [&str; 3] = ["Create key", "Enroll", "Connect"];

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

    /// Checks once a day at launch (if enabled, and only once set up, so
    /// first-time setup is never interrupted) and installs automatically
    /// when the user allowed it.
    fn poll_update(&mut self, ctx: &egui::Context, auto_check: bool) {
        if auto_check && !self.upd_started {
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
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        theme::pill(ui, Tone::Good, &format!("Updated to {version}"));
                        if ui.button("Restart now").clicked() {
                            relaunch(&target);
                        }
                    });
                });
            }
            Upd::Available(av) => {
                let av = (**av).clone();
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        theme::pill(ui, Tone::Info, &format!("Version {} is available", av.version));
                        if ui.button("Install update").clicked() {
                            self.start_update_install(&ctx, av);
                        }
                    });
                });
            }
            Upd::Installing => {
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Installing update…");
                    });
                });
            }
            _ => return,
        }
        ui.add_space(10.0);
    }

    /// Version and "Check for updates", at the bottom of every screen.
    fn update_footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(muted(format!("RDP Gate {}", client::VERSION)).small());
            match &self.upd {
                Upd::Checking => {
                    ui.spinner();
                }
                Upd::UpToDate => {
                    ui.label(muted("You have the latest version.").small());
                }
                Upd::Failed(e) => {
                    ui.label(RichText::new(format!("Update: {e}")).small().color(theme::BAD));
                }
                _ => {}
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let busy = matches!(self.upd, Upd::Checking | Upd::Installing);
                if ui.add_enabled(!busy, egui::Button::new("Check for updates").small()).clicked() {
                    let ctx = ui.ctx().clone();
                    self.start_update_check(&ctx);
                }
            });
        });
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
        theme::steps(ui, &STEPS, 0);
        ui.add_space(12.0);
        theme::titled_card(
            ui,
            "Set up this computer",
            Some("RDP Gate creates a private key for this computer. You enroll it on the server once; after that this computer can sign in."),
            |ui| {
                ui.add_space(4.0);
                theme::field_label(ui, "This computer");
                ui.add(TextEdit::singleline(&mut self.device).hint_text("macbook").desired_width(f32::INFINITY));
                theme::field_label(ui, "Windows user (optional)");
                ui.add(TextEdit::singleline(&mut self.username).hint_text("the account you sign in to Windows with").desired_width(f32::INFINITY));
                theme::field_label(ui, "Passphrase");
                ui.add(
                    TextEdit::singleline(&mut *self.pass1)
                        .password(true)
                        .hint_text(format!("at least {} characters", client::MIN_PASSPHRASE))
                        .desired_width(f32::INFINITY),
                );
                theme::field_label(ui, "Repeat passphrase");
                ui.add(TextEdit::singleline(&mut *self.pass2).password(true).desired_width(f32::INFINITY));
                ui.add_space(2.0);
                ui.label(muted("The passphrase encrypts the key on this computer. It is never sent anywhere and cannot be recovered.").small());
                ui.add_space(8.0);
                if primary_wide(ui, self.busy.is_none(), "Create device key").clicked() {
                    if *self.pass1 != *self.pass2 {
                        self.status = Some((false, "The passphrases don't match.".into()));
                    } else {
                        let (dir, pass, device) = (self.dir.clone(), self.pass1.clone(), self.device.trim().to_string());
                        let user = Some(self.username.trim().to_string());
                        let ctx = ui.ctx().clone();
                        self.run(&ctx, "Creating key…", move || Done::Created(client::create_device(&dir, &device, user, &pass, false)));
                    }
                }
            },
        );
    }

    /// Paste box for the server card. Returns true once a valid card is saved.
    fn card_ui(&mut self, ui: &mut egui::Ui) -> bool {
        ui.add(
            TextEdit::multiline(&mut self.card_text)
                .hint_text("rdpgate-card:…")
                .font(egui::TextStyle::Monospace)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .margin(egui::Margin::symmetric(10, 8)),
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
        theme::steps(ui, &STEPS, 1);
        ui.add_space(12.0);
        theme::titled_card(
            ui,
            "1  Add this computer on the server",
            Some("On the server, open RDP Gate Server > Computers and paste this into Add a computer (or run it in PowerShell as Administrator)."),
            |ui| {
                // One line that never wraps: a wrapped copy pastes into PowerShell
                // as two commands, and the key alone is "not recognized".
                theme::code_line(ui, &id.enroll_command());
                ui.horizontal(|ui| {
                    if ui.button("Copy command").clicked() {
                        ui.ctx().copy_text(id.enroll_command());
                        self.status = Some((true, "Copied. Paste it into RDP Gate Server > Computers on the server.".into()));
                    }
                    ui.label(RichText::new(&id.fingerprint).monospace().small().color(MUTED));
                });
                ui.label(muted("The server shows this fingerprint too; check they match.").small());
            },
        );
        ui.add_space(10.0);
        let saved = theme::titled_card(ui, "2  Paste the server card", Some("The server shows it once the computer is added."), |ui| self.card_ui(ui));
        if saved {
            self.screen = Screen::Main;
        }
    }

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        let cfg = match client::load_config(&self.dir) {
            Ok(c) => c,
            Err(e) => {
                theme::notice(ui, Tone::Bad, &e, false);
                return;
            }
        };
        let server = match client::card(&cfg) {
            Ok(c) => rdpgate_core::wire::fingerprint(&c.server_key())[..9].to_string(),
            Err(_) => {
                theme::steps(ui, &STEPS, 1);
                ui.add_space(12.0);
                theme::titled_card(
                    ui,
                    "Paste the server card",
                    Some("RDP Gate Server > Computers on the server shows it."),
                    |ui| self.card_ui(ui),
                );
                return;
            }
        };

        if let Some(s) = &self.session {
            let (file, key) = (s.rdp_file.clone(), s.key.clone());
            let verified = s.check == RdpCheck::Verified;
            let (ip, left, held) = (s.grant.ip.to_string(), client::minutes_left(s.grant.expires), s.grant.while_connected());
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    theme::pill(ui, Tone::Good, "Access open");
                    if verified {
                        theme::pill(ui, Tone::Info, "Certificate verified");
                    }
                });
                ui.add_space(6.0);
                ui.label(muted("Remote Desktop is open for"));
                ui.label(RichText::new(&ip).monospace().size(26.0).strong().color(theme::TEXT));
                ui.label(muted(format!("Start Remote Desktop within {left}. {held}")));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary("Open Remote Desktop")).clicked()
                        && let Err(e) = client::launch_rdp(&file)
                    {
                        self.status = Some((false, e));
                    }
                    if ui.add_enabled(self.busy.is_none(), egui::Button::new("Close access now").min_size(egui::vec2(0.0, 36.0))).clicked() {
                        let (dir, cfg) = (self.dir.clone(), cfg.clone());
                        let ctx = ui.ctx().clone();
                        self.run(&ctx, "Closing…", move || {
                            Done::Locked(rt().and_then(|rt| rt.block_on(client::lock(&dir, &cfg, &key))))
                        });
                    }
                });
            });
            ui.add_space(10.0);
            theme::notice(
                ui,
                Tone::Warn,
                "Anyone who shares your public IP (same Wi-Fi or mobile carrier) can reach the Windows login screen until access closes. They still need your Windows password.",
                false,
            );
            return;
        }

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new("Sign in to Remote Desktop").strong().size(16.0).color(theme::TEXT));
                    ui.label(muted(format!("{}  →  server {server}", cfg.device)).small());
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    theme::pill(ui, Tone::Neutral, "Closed");
                });
            });
            ui.add_space(10.0);
            theme::field_label(ui, "Passphrase");
            ui.add(TextEdit::singleline(&mut *self.passphrase).password(true).desired_width(f32::INFINITY));
            theme::field_label(ui, "6-digit code");
            ui.add(
                TextEdit::singleline(&mut self.code)
                    .char_limit(6)
                    .hint_text("from your authenticator app")
                    .font(egui::FontId::monospace(18.0))
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
            let submit = ui.input(|i| i.key_pressed(egui::Key::Enter)) && self.code.len() == 6;
            if (primary_wide(ui, self.busy.is_none(), "Sign in and open Remote Desktop").clicked() || submit) && self.busy.is_none() {
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
        });

        ui.add_space(10.0);
        theme::card(ui, |ui| {
            egui::CollapsingHeader::new(RichText::new("This computer and server").strong()).show(ui, |ui| {
                if let Ok(id) = client::identity(&self.dir) {
                    ui.label(muted("Device key"));
                    ui.label(RichText::new(&id.fingerprint).monospace().small());
                    if ui.button("Copy enrollment command").clicked() {
                        ui.ctx().copy_text(id.enroll_command());
                        self.status = Some((true, "Copied. Paste it into RDP Gate Server > Computers on the server.".into()));
                    }
                }
                if let Some(a) = cfg.last_known {
                    ui.label(muted(format!("Server last seen at {a}")));
                }
                ui.separator();
                let mut auto = cfg.auto_update;
                if ui.checkbox(&mut auto, "Update automatically (signed updates only)").changed() {
                    let _ = client::set_auto_update(&self.dir, auto);
                }
                ui.separator();
                ui.label(muted("Replace the server card:"));
                self.card_ui(ui);
            });
        });
    }

    /// What the top bar says about this computer.
    fn state_pill(&self) -> (Tone, &'static str) {
        match self.screen {
            Screen::Setup => (Tone::Neutral, "Not set up"),
            Screen::Enroll(_) => (Tone::Warn, "Enrolling"),
            Screen::Main if self.session.is_some() => (Tone::Good, "Access open"),
            Screen::Main => (Tone::Info, "Ready"),
        }
    }
}

impl eframe::App for GateApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        self.poll_update(&ctx, matches!(self.screen, Screen::Main));
        let bar = egui::Frame::new().fill(theme::BAR).inner_margin(egui::Margin::symmetric(16, 10));
        egui::Panel::top("brand").frame(bar).show(ui, |ui| {
            ui.horizontal(|ui| {
                theme::brand(ui, "RDP Gate", "Remote Desktop, closed until it's you");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (tone, text) = self.state_pill();
                    theme::pill(ui, tone, text);
                });
            });
        });
        egui::Panel::bottom("updates").frame(bar.inner_margin(egui::Margin::symmetric(16, 6))).show(ui, |ui| {
            self.update_footer(ui);
        });
        let body = egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::same(16));
        egui::CentralPanel::default().frame(body).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.update_banner(ui);
                match &self.screen {
                    Screen::Setup => self.setup_ui(ui),
                    Screen::Enroll(id) => {
                        let id = id.clone();
                        self.enroll_ui(ui, &id);
                    }
                    Screen::Main => self.main_ui(ui),
                }
                ui.add_space(12.0);
                if let Some(label) = self.busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(label);
                    });
                }
                if let Some((ok, msg)) = &self.status
                    && theme::notice(ui, Tone::from_ok(*ok), msg, true)
                {
                    self.status = None;
                }
            });
        });
    }
}

