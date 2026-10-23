use eframe::egui::{self, Color32, RichText, TextEdit};
use rdpgate_core::update::Available;
use rdpgate_server::admin::{self, DeviceInfo, Overview, TotpEnrollment, when};
use rdpgate_server::service::{self, Status};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const GOOD: Color32 = Color32::from_rgb(40, 150, 80);
const BAD: Color32 = Color32::from_rgb(210, 70, 60);
const WARN: Color32 = Color32::from_rgb(200, 130, 20);
const REFRESH: Duration = Duration::from_secs(3);
/// Passed to the relaunched window when Direct3D couldn't start.
const OPENGL_ARG: &str = "--opengl";

pub fn main() {
    rdpgate_core::update::cleanup_previous();
    rdpgate_server::install_crypto();
    let opengl = std::env::args().any(|a| a == OPENGL_ARG);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RDP Gate Server")
            .with_inner_size([820.0, 600.0])
            .with_min_inner_size([640.0, 460.0]),
        renderer: if opengl { eframe::Renderer::Glow } else { eframe::Renderer::Wgpu },
        ..Default::default()
    };
    let Err(e) = eframe::run_native("RDP Gate Server", options, Box::new(|_cc| Ok(Box::new(ServerApp::new())))) else {
        return;
    };
    // A window can only be opened once per process, so try OpenGL in a new one.
    if !opengl
        && let Ok(exe) = std::env::current_exe()
        && std::process::Command::new(exe).arg(OPENGL_ARG).spawn().is_ok()
    {
        return;
    }
    message_box(&format!(
        "RDP Gate Server could not open its window on this PC ({e}).\n\n\
         The RDP Gate service keeps running. You can still manage it from PowerShell as \
         Administrator with rdpgate-server (for example: rdpgate-server status)."
    ));
}

fn message_box(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (text, title) = (wide(text), wide("RDP Gate Server"));
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR) };
}

/// The one prominent action on each page.
fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
        .fill(Color32::from_rgb(36, 87, 214))
        .min_size(egui::vec2(180.0, 30.0))
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(14.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add_space(4.0);
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Computers,
    Codes,
    Network,
    Browser,
    Log,
}

impl Page {
    const ALL: [Page; 6] = [Page::Overview, Page::Computers, Page::Codes, Page::Network, Page::Browser, Page::Log];

    fn title(self) -> &'static str {
        match self {
            Page::Overview => "Overview",
            Page::Computers => "Computers",
            Page::Codes => "6-digit codes",
            Page::Network => "Network",
            Page::Browser => "Browser sign-in",
            Page::Log => "Activity log",
        }
    }
}

/// A question to answer before something disruptive happens.
enum Confirm {
    RemoveComputer(String),
    RemovePasskey(String),
    ReplaceCodes,
    /// Restarting closes every open grant; `why` says what it applies.
    Restart(&'static str),
    Protect,
    InstallUpdate(Box<Available>),
}

/// Results of work done off the UI thread (the network and the service
/// manager can take a while).
enum Done {
    Message(Result<String, String>),
    Router(Vec<String>),
    UpdateChecked(Result<Option<Available>, String>),
}

/// The QR code for the authenticator app, as rows of dark/light modules.
struct Qr {
    width: usize,
    dark: Vec<bool>,
}

struct ServerApp {
    data: PathBuf,
    page: Page,
    overview: Result<Overview, String>,
    service: Status,
    devices: Vec<DeviceInfo>,
    refreshed: Instant,
    // Computers
    add_name: String,
    add_key: String,
    added: Option<(String, String)>,
    // 6-digit codes
    enrolling: Option<(TotpEnrollment, Qr)>,
    code: String,
    // Network
    token: Zeroizing<String>,
    gist: String,
    router_lines: Vec<String>,
    // Browser sign-in
    passkey_link: Option<(String, i64)>,
    // Activity log
    log: String,
    update: Option<Available>,
    confirm: Option<Confirm>,
    status: Option<(bool, String)>,
    busy: Option<&'static str>,
    rx: Option<Receiver<Done>>,
}

impl ServerApp {
    fn new() -> Self {
        // --data DIR, like rdpgate-server's, to manage a data folder elsewhere.
        let args: Vec<String> = std::env::args().collect();
        let data = args.iter().position(|a| a == "--data").and_then(|i| args.get(i + 1)).map(PathBuf::from);
        let mut app = ServerApp {
            data: data.unwrap_or_else(rdpgate_server::config::default_data_dir),
            page: Page::Overview,
            overview: Err(String::new()),
            service: Status::Unknown,
            devices: vec![],
            refreshed: Instant::now(),
            add_name: String::new(),
            add_key: String::new(),
            added: None,
            enrolling: None,
            code: String::new(),
            token: Zeroizing::new(String::new()),
            gist: String::new(),
            router_lines: vec![],
            passkey_link: None,
            log: String::new(),
            update: None,
            confirm: None,
            status: None,
            busy: None,
            rx: None,
        };
        app.refresh();
        app
    }

    /// Re-reads what the service keeps on disk. Cheap: a few small files.
    fn refresh(&mut self) {
        self.overview = admin::overview(&self.data);
        self.devices = admin::devices(&self.data).unwrap_or_default();
        self.service = service::status();
        if self.page == Page::Log {
            self.log = admin::log_tail(&self.data, 400);
        }
        self.refreshed = Instant::now();
    }

    fn say(&mut self, r: Result<String, String>) {
        self.status = Some(match r {
            Ok(m) => (true, m),
            Err(e) => (false, e),
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
            Done::Message(r) => self.say(r),
            Done::Router(lines) => self.router_lines = lines,
            Done::UpdateChecked(Ok(None)) => self.say(Ok("You have the latest version.".into())),
            Done::UpdateChecked(Ok(Some(av))) => self.update = Some(av),
            Done::UpdateChecked(Err(e)) => self.say(Err(format!("Update check: {e}"))),
        }
        self.refresh();
    }

    fn open_grants(&self) -> usize {
        self.overview.as_ref().map_or(0, |o| o.grants.len())
    }

    /// Restarts the service so a changed setting applies, asking first when
    /// that would close someone's access.
    fn restart(&mut self, ctx: &egui::Context, why: &'static str) {
        if self.open_grants() > 0 {
            self.confirm = Some(Confirm::Restart(why));
        } else {
            self.restart_now(ctx, why);
        }
    }

    fn restart_now(&mut self, ctx: &egui::Context, why: &'static str) {
        self.run(ctx, "Restarting the RDP Gate service…", move || {
            Done::Message(service::restart().map(|()| format!("{why} The service restarted with it.")))
        });
    }

    // ---- pages ---------------------------------------------------------

    fn overview_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        ui.heading("Overview");
        let ctx = ui.ctx().clone();
        egui::Grid::new("overview").num_columns(3).spacing([16.0, 10.0]).show(ui, |ui| {
            ui.label("Service");
            let (text, color) = match self.service {
                Status::Running => ("Running", GOOD),
                Status::Starting => ("Starting…", WARN),
                Status::Stopping => ("Stopping…", WARN),
                Status::Stopped => ("Stopped: nobody can sign in", BAD),
                Status::NotInstalled => ("Not installed: run RDP Gate Server Setup again", BAD),
                Status::Unknown => ("Unknown", WARN),
            };
            ui.colored_label(color, text);
            ui.horizontal(|ui| {
                let idle = self.busy.is_none();
                if self.service == Status::Stopped && ui.add_enabled(idle, egui::Button::new("Start")).clicked() {
                    self.run(&ctx, "Starting the service…", || {
                        Done::Message(service::ensure_running().map(|_| "The RDP Gate service is starting.".into()))
                    });
                }
                if self.service == Status::Running && ui.add_enabled(idle, egui::Button::new("Restart")).clicked() {
                    self.restart(&ctx, "Restarted.");
                }
            });
            ui.end_row();

            ui.label("Remote Desktop");
            if o.protection_pending {
                ui.colored_label(WARN, "Still reachable without RDP Gate until a computer signs in through it");
                if ui.add_enabled(self.busy.is_none(), egui::Button::new("Close it now")).clicked() {
                    self.confirm = Some(Confirm::Protect);
                }
            } else {
                ui.colored_label(GOOD, "Closed to everyone who hasn't signed in");
                ui.label("");
            }
            ui.end_row();

            ui.label("Finding this PC");
            match &o.beacon {
                Some(b) if b.error.is_some() => {
                    ui.colored_label(BAD, format!("Beacon problem: {}", b.error.as_deref().unwrap_or_default()));
                }
                Some(b) => {
                    ui.colored_label(GOOD, format!("Beacon published {} (updated {})", b.ip.as_deref().unwrap_or("?"), when(b.published)));
                }
                None => {
                    ui.colored_label(BAD, "No beacon: your computers can't find this PC");
                }
            }
            if ui.button("Network…").clicked() {
                self.page = Page::Network;
            }
            ui.end_row();

            ui.label("Router");
            ui.colored_label(if o.behind_nat { BAD } else { ui.visuals().text_color() }, &o.router);
            ui.label("");
            ui.end_row();

            ui.label("6-digit codes");
            if o.totp {
                ui.colored_label(GOOD, "Set up");
            } else {
                ui.colored_label(BAD, "Not set up: nobody can sign in yet");
            }
            if ui.button("6-digit codes…").clicked() {
                self.page = Page::Codes;
            }
            ui.end_row();

            ui.label("Computers");
            ui.label(match o.devices {
                0 => "None enrolled yet".to_string(),
                1 => "1 enrolled".to_string(),
                n => format!("{n} enrolled"),
            });
            if ui.button("Computers…").clicked() {
                self.page = Page::Computers;
            }
            ui.end_row();

            ui.label("Home network");
            ui.label(if o.lan {
                format!("Sign-in allowed (this PC is {})", o.lan_ip.as_deref().unwrap_or("not on a home network right now"))
            } else {
                "Sign-in only from outside".into()
            });
            ui.label("");
            ui.end_row();
        });

        if o.behind_nat {
            ui.add_space(6.0);
            ui.colored_label(
                BAD,
                "Your router's own internet address isn't public (carrier-grade NAT, or a second router in front). \
                 Nothing on the internet can reach this PC: ask your internet provider for a public IPv4 address.",
            );
        }
        for w in &o.warnings {
            ui.colored_label(WARN, format!("Warning: {w}"));
        }

        section(ui, "Open access");
        if o.grants.is_empty() {
            ui.label("Nobody has access open right now.");
        } else {
            egui::Grid::new("grants").striped(true).num_columns(3).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.strong("Address");
                ui.strong("Who");
                ui.strong("Until");
                ui.end_row();
                for g in &o.grants {
                    ui.monospace(&g.ip);
                    ui.label(&g.who);
                    ui.label(when(Some(g.expires)));
                    ui.end_row();
                }
            });
        }

        section(ui, "Updates");
        ui.horizontal(|ui| {
            ui.label(format!("Version {}", o.version));
            let mut auto = o.auto_update;
            if ui.checkbox(&mut auto, "Install signed updates automatically (when nobody is signed in)").changed() {
                let r = admin::set_auto_update(&self.data, auto);
                if r.is_ok() {
                    self.restart(&ctx, "Automatic updates changed.");
                } else {
                    self.say(r.map(|()| String::new()));
                }
            }
        });
        match self.update.clone() {
            Some(av) => {
                ui.horizontal(|ui| {
                    ui.label(format!("Version {} is available.", av.version));
                    if ui.add_enabled(self.busy.is_none(), primary("Install update")).clicked() {
                        self.confirm = Some(Confirm::InstallUpdate(Box::new(av)));
                    }
                });
            }
            None => {
                if ui.add_enabled(self.busy.is_none(), egui::Button::new("Check for updates")).clicked() {
                    let pre = rdpgate_server::config::Config::load(&self.data).map(|c| c.update_prereleases).unwrap_or(true);
                    self.run(&ctx, "Checking for updates…", move || {
                        Done::UpdateChecked(rdpgate_core::update::check(rdpgate_server::updater::VERSION, pre))
                    });
                }
            }
        }
        ui.add_space(4.0);
        ui.small(format!("Server key fingerprint {}", o.server_fingerprint));
    }

    fn computers_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Computers");
        ui.label("Each computer you connect from has its own key. Only enrolled computers can sign in.");

        section(ui, "Add a computer");
        ui.label("1. On that computer, install the RDP Gate app and set it up. It shows a key that starts with rdpgate-ed25519: (and a Copy button).");
        ui.label("2. Paste it below. Pasting the whole \"rdpgate-server device-add …\" line works too.");
        egui::Grid::new("add").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            let label = ui.label("Key");
            let pasted = ui
                .add(TextEdit::multiline(&mut self.add_key).hint_text("rdpgate-ed25519:…").desired_rows(2).desired_width(480.0))
                .labelled_by(label.id)
                .changed();
            // "rdpgate-server device-add NAME KEY": take the name from it too.
            if pasted && self.add_name.is_empty() {
                let words: Vec<&str> = self.add_key.split_whitespace().collect();
                if let Some(i) = words.iter().position(|w| *w == "device-add")
                    && let Some(name) = words.get(i + 1).filter(|n| !n.starts_with("rdpgate-"))
                {
                    self.add_name = name.to_string();
                }
            }
            ui.end_row();
            let label = ui.label("Name");
            ui.add(TextEdit::singleline(&mut self.add_name).hint_text("e.g. laptop").desired_width(220.0)).labelled_by(label.id);
            ui.end_row();
        });
        ui.add_space(6.0);
        let ready = !self.add_key.trim().is_empty() && !self.add_name.trim().is_empty();
        if ui.add_enabled(ready, primary("Add computer")).clicked() {
            match admin::add_device(&self.data, &self.add_name, &self.add_key) {
                Ok(fp) => {
                    self.added = Some((self.add_name.trim().to_string(), fp));
                    self.add_key.clear();
                    self.add_name.clear();
                    self.status = None;
                    self.refresh();
                }
                Err(e) => self.say(Err(e)),
            }
        }
        if let Some((name, fp)) = self.added.clone() {
            ui.add_space(8.0);
            ui.colored_label(GOOD, format!("Enrolled {name}."));
            ui.label(format!("Its fingerprint is {fp}. Check it matches the one shown on that computer."));
            ui.label("3. Paste this server card into the app on that computer:");
            self.card_ui(ui);
        }

        section(ui, "Enrolled");
        if self.devices.is_empty() {
            ui.label("No computers yet.");
        }
        let devices = self.devices.clone();
        egui::Grid::new("devices").striped(true).num_columns(5).spacing([16.0, 6.0]).show(ui, |ui| {
            if !devices.is_empty() {
                ui.strong("Name");
                ui.strong("Fingerprint");
                ui.strong("Last sign-in");
                ui.strong("");
                ui.strong("");
                ui.end_row();
            }
            for d in &devices {
                ui.label(&d.name);
                ui.monospace(d.fingerprint.get(..14).unwrap_or(&d.fingerprint));
                ui.label(when(d.last_auth));
                if d.locked {
                    ui.horizontal(|ui| {
                        ui.colored_label(BAD, "Locked (10 wrong codes)");
                        if ui.button("Unlock").clicked() {
                            let r = admin::unlock_device(&self.data, &d.name).map(|()| format!("Unlocked {}.", d.name));
                            self.say(r);
                            self.refresh();
                        }
                    });
                } else {
                    ui.label("");
                }
                if ui.button("Remove…").clicked() {
                    self.confirm = Some(Confirm::RemoveComputer(d.name.clone()));
                }
                ui.end_row();
            }
        });

        if self.added.is_none() {
            section(ui, "Server card");
            ui.label("Every computer needs this once (the app asks for it). It lets the app find and check this PC.");
            self.card_ui(ui);
        }
    }

    fn card_ui(&mut self, ui: &mut egui::Ui) {
        match admin::card(&self.data) {
            Ok(card) => {
                let mut shown = card.clone();
                ui.add(TextEdit::multiline(&mut shown).font(egui::TextStyle::Monospace).desired_rows(3).desired_width(f32::INFINITY));
                if ui.button("Copy server card").clicked() {
                    ui.ctx().copy_text(card);
                    self.say(Ok("Server card copied. Keep it private: it reveals where to find this PC.".into()));
                }
            }
            Err(e) => {
                ui.colored_label(BAD, e);
            }
        }
    }

    fn codes_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        ui.heading("6-digit codes");
        ui.label("Signing in takes the computer's key plus a code from an authenticator app on your phone (Google or Microsoft Authenticator, 1Password, …).");
        ui.add_space(8.0);
        if let Some((e, qr)) = &self.enrolling {
            ui.label("1. In the authenticator app, add an account and scan this code:");
            ui.add_space(6.0);
            draw_qr(ui, qr);
            ui.add_space(6.0);
            ui.label("Or type this key into the app instead:");
            ui.monospace(&e.key);
            ui.small("Don't photograph or screenshot it: anyone with this key can make your codes.");
            ui.add_space(10.0);
            let label = ui.label("2. Type the 6-digit code the app shows now:");
            let mut confirm = false;
            ui.horizontal(|ui| {
                let r = ui
                    .add(TextEdit::singleline(&mut self.code).char_limit(6).desired_width(90.0).font(egui::TextStyle::Monospace))
                    .labelled_by(label.id);
                confirm = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                confirm |= ui.add_enabled(self.code.trim().len() == 6, primary("Turn codes on")).clicked();
                if ui.button("Cancel").clicked() {
                    self.enrolling = None;
                    self.code.clear();
                }
            });
            if confirm && let Some((e, _)) = &self.enrolling {
                match admin::totp_confirm(&self.data, e, &self.code) {
                    Ok(true) => {
                        self.enrolling = None;
                        self.code.clear();
                        self.say(Ok("6-digit codes are on.".into()));
                        self.refresh();
                    }
                    Ok(false) => self.say(Err("That code doesn't match. Check the phone sets its clock automatically, then try the next code.".into())),
                    Err(e) => self.say(Err(e)),
                }
            }
            return;
        }
        if o.totp {
            ui.colored_label(GOOD, "6-digit codes are set up.");
            ui.add_space(6.0);
            if ui.button("Use a new phone…").clicked() {
                self.confirm = Some(Confirm::ReplaceCodes);
            }
        } else {
            ui.colored_label(BAD, "Not set up yet. Nobody can sign in until they are.");
            ui.add_space(6.0);
            if ui.add(primary("Set up 6-digit codes")).clicked() {
                self.begin_codes(false);
            }
        }
    }

    fn begin_codes(&mut self, replace: bool) {
        let r = admin::totp_begin(&self.data, replace).and_then(|e| {
            let code = qrcode::QrCode::new(e.uri.as_bytes()).map_err(|err| err.to_string())?;
            let dark = code.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect();
            Ok((e, Qr { width: code.width(), dark }))
        });
        match r {
            Ok(v) => {
                self.enrolling = Some(v);
                self.code.clear();
                self.status = None;
            }
            Err(e) => self.say(Err(e)),
        }
    }

    fn network_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        let ctx = ui.ctx().clone();
        ui.heading("Network");

        section(ui, "Beacon (how your computers find this PC)");
        ui.label("This PC publishes its address, encrypted and signed, in a secret GitHub gist. It needs a GitHub token that can only use Gists, ideally from a GitHub account used just for this.");
        match &o.beacon {
            Some(b) => {
                ui.label(format!("Gist {}  ·  last address {}  ·  published {}", b.gist, b.ip.as_deref().unwrap_or("?"), when(b.published)));
                if let Some(e) = &b.error {
                    ui.colored_label(BAD, format!("Last error: {e}"));
                }
            }
            None => {
                ui.colored_label(BAD, "Not set up.");
            }
        }
        ui.horizontal(|ui| {
            ui.hyperlink_to("Create a token on GitHub", "https://github.com/settings/personal-access-tokens/new");
            ui.label("with Account permissions > Gists: Read and write, and nothing else.");
        });
        egui::Grid::new("beacon").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            let label = ui.label("GitHub token");
            ui.add(TextEdit::singleline(&mut *self.token).password(true).desired_width(360.0)).labelled_by(label.id);
            ui.end_row();
            let label = ui.label("Gist (optional)");
            ui.add(TextEdit::singleline(&mut self.gist).hint_text("leave empty to create a new one").desired_width(360.0))
                .labelled_by(label.id);
            ui.end_row();
        });
        let label = if o.beacon.is_some() { "Replace token and publish" } else { "Save and publish" };
        if ui.add_enabled(self.busy.is_none() && !self.token.trim().is_empty(), primary(label)).clicked() {
            let (data, token, gist) = (self.data.clone(), self.token.clone(), self.gist.clone());
            self.token = Zeroizing::new(String::new());
            let restart = self.service == Status::Running;
            self.run(&ctx, "Publishing the beacon…", move || {
                let r = admin::beacon_setup(&data, &token, Some(&gist)).and_then(|id| {
                    // The service publishes updates only with the new settings loaded.
                    if restart {
                        service::restart()?;
                    }
                    Ok(format!("Beacon published to gist {id}. If computers were enrolled before, give them the server card again."))
                });
                Done::Message(r)
            });
        }

        section(ui, "Sign-in from this network");
        let mut lan = o.lan;
        let label = match &o.lan_ip {
            Some(ip) => format!("Allow computers on this PC's own network to sign in (this PC is {ip} here)"),
            None => "Allow computers on this PC's own network to sign in".to_string(),
        };
        if ui.checkbox(&mut lan, label).changed() {
            match admin::set_lan(&self.data, lan) {
                Ok(_) => self.restart(&ctx, if lan { "Sign-in from this network is on." } else { "Sign-in from this network is off." }),
                Err(e) => self.say(Err(e)),
            }
        }
        ui.small("For a laptop on the same Wi-Fi. Give this PC a reserved address in your router so it keeps the same one.");

        section(ui, "Router");
        ui.label(format!(
            "Your router must send TCP {} (sign-in) and TCP {} (Remote Desktop) to this PC. Remote Desktop stays closed in Windows Firewall until someone signs in.",
            o.public_port, o.rdp_public_port
        ));
        ui.label(format!("Now: {}", o.router));
        if ui.add_enabled(self.busy.is_none(), egui::Button::new("Forward the ports now (UPnP)")).clicked() {
            let data = self.data.clone();
            self.run(&ctx, "Asking the router…", move || {
                let lines = match rdpgate_server::config::Config::load(&data) {
                    Ok(cfg) => rdpgate_server::router::apply(&cfg).summary(&cfg),
                    Err(e) => vec![e],
                };
                Done::Router(lines)
            });
        }
        for l in &self.router_lines {
            ui.monospace(l);
        }
    }

    fn browser_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        ui.heading("Browser sign-in");
        ui.label("Optional: sign in from a web browser with a passkey. It needs a domain name you control pointing at this PC. The RDP Gate app doesn't need any of this.");
        ui.add_space(8.0);
        match &o.browser_url {
            Some(url) => {
                ui.colored_label(GOOD, "On. Your sign-in page (bookmark the full address):");
                let mut shown = url.clone();
                ui.add(TextEdit::singleline(&mut shown).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
            }
            None => {
                ui.label("Off.");
            }
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button(if o.browser_url.is_some() { "Change the domain…" } else { "Set up with my domain…" }).clicked() {
                self.console(&["domain-setup"]);
            }
            if o.browser_url.is_some() && ui.button("Turn off…").clicked() {
                self.console(&["domain-setup", "--remove"]);
            }
        });
        ui.small("The guided setup opens in its own window: it shows the DNS record to create and checks it for you.");

        if o.browser_url.is_none() {
            return;
        }
        section(ui, "Passkeys");
        if o.passkeys.is_empty() {
            ui.label("No passkeys yet.");
        }
        egui::Grid::new("passkeys").striped(true).num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
            for p in &o.passkeys {
                ui.label(&p.name);
                ui.label(format!("added {}", when(Some(p.added))));
                ui.label(format!("last used {}", when(p.last_used)));
                if ui.button("Remove…").clicked() {
                    self.confirm = Some(Confirm::RemovePasskey(p.name.clone()));
                }
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        if ui.button("Create a link to add a passkey").clicked() {
            match admin::passkey_link(&self.data, 15) {
                Ok(l) => self.passkey_link = Some(l),
                Err(e) => self.say(Err(e)),
            }
        }
        if let Some((link, expires)) = self.passkey_link.clone() {
            ui.label(format!("Open it on the phone or computer whose passkey you want to add. It works once, until {}:", when(Some(expires))));
            let mut shown = link.clone();
            ui.add(TextEdit::singleline(&mut shown).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
            if ui.button("Copy link").clicked() {
                ui.ctx().copy_text(link);
                self.say(Ok("Link copied. Treat it like a password.".into()));
            }
        }
    }

    fn log_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Activity log");
            if ui.button("Refresh").clicked() {
                self.log = admin::log_tail(&self.data, 400);
            }
            if ui.button("Open log folder").clicked() {
                let _ = std::process::Command::new("explorer.exe").arg(self.data.join("logs")).spawn();
            }
        });
        ui.small("Sign-ins, firewall openings and closings, beacon and update activity. Newest at the bottom.");
        ui.add_space(6.0);
        egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(&self.log).monospace().size(12.0)).wrap_mode(egui::TextWrapMode::Extend));
        });
    }

    /// Runs `rdpgate-server <args>` in its own console window, for the
    /// guided steps that ask questions as they go.
    fn console(&mut self, args: &[&str]) {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        let exe = std::env::current_exe().map(|p| p.with_file_name("rdpgate-server.exe")).unwrap_or_default();
        let line = format!("\"\"{}\" {} & pause\"", exe.display(), args.join(" "));
        let r = std::process::Command::new("cmd.exe").arg("/c").raw_arg(line).creation_flags(CREATE_NEW_CONSOLE).spawn();
        if let Err(e) = r {
            self.say(Err(format!("Could not open the guided setup: {e}")));
        }
    }

    fn confirm_ui(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let grants = self.open_grants();
        let (title, body, action) = match c {
            Confirm::RemoveComputer(n) => (format!("Remove {n}?"), "It can no longer sign in. Access it has open now closes on its normal schedule.".to_string(), "Remove"),
            Confirm::RemovePasskey(n) => (format!("Remove the passkey {n}?"), "It can no longer sign in from a browser.".to_string(), "Remove"),
            Confirm::ReplaceCodes => (
                "Use a new phone?".to_string(),
                "Codes from the current authenticator app stop working once the new one is confirmed.".to_string(),
                "Continue",
            ),
            Confirm::Restart(_) => (
                "Restart the RDP Gate service?".to_string(),
                format!("{grants} address(es) have access open right now, maybe including yours. Restarting closes it and disconnects Remote Desktop sessions that came through RDP Gate. They can sign in again afterwards."),
                "Restart now",
            ),
            Confirm::Protect => (
                "Close Remote Desktop to everyone else now?".to_string(),
                if std::env::var("SESSIONNAME").is_ok_and(|s| s.to_ascii_uppercase().starts_with("RDP-TCP")) {
                    "You are connected over Remote Desktop. This disconnects every session that didn't come through RDP Gate, including this one unless you signed in through RDP Gate."
                } else {
                    "Remote Desktop sessions that didn't come through RDP Gate are disconnected."
                }
                .to_string(),
                "Close it now",
            ),
            Confirm::InstallUpdate(av) => (
                format!("Install version {}?", av.version),
                if grants > 0 {
                    format!("The service restarts on the new version, which closes access for the {grants} address(es) signed in right now.")
                } else {
                    "The service restarts on the new version. This window updates too: reopen it afterwards.".to_string()
                },
                "Install",
            ),
        };
        let mut answer = None;
        egui::Modal::new(egui::Id::unique("confirm")).show(ctx, |ui| {
            ui.set_max_width(420.0);
            ui.heading(title);
            ui.add_space(6.0);
            ui.label(body);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(primary(action)).clicked() {
                    answer = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    answer = Some(false);
                }
            });
        });
        let Some(yes) = answer else { return };
        let Some(c) = self.confirm.take() else { return };
        if !yes {
            return;
        }
        match c {
            Confirm::RemoveComputer(n) => {
                let r = admin::remove_device(&self.data, &n).map(|()| format!("Removed {n}. It can no longer sign in."));
                self.say(r);
                self.refresh();
            }
            Confirm::RemovePasskey(n) => {
                let r = admin::remove_passkey(&self.data, &n).map(|()| format!("Removed the passkey {n}."));
                self.say(r);
                self.refresh();
            }
            Confirm::ReplaceCodes => self.begin_codes(true),
            Confirm::Restart(why) => self.restart_now(ctx, why),
            Confirm::Protect => {
                let data = self.data.clone();
                self.run(ctx, "Closing Remote Desktop to everyone else (this can take a minute)…", move || {
                    Done::Message(admin::protect_now(&data).map(|rules| {
                        format!("Remote Desktop now opens only for addresses that sign in through RDP Gate ({} firewall rule(s) disabled).", rules.len())
                    }))
                });
            }
            Confirm::InstallUpdate(av) => {
                self.update = None;
                self.run(ctx, "Installing the update…", move || {
                    let r = rdpgate_server::updater::install(&av).and_then(|()| service::restart()).map(|()| {
                        format!("Installed {}. The service restarted on it; reopen this window to use its new version.", av.version)
                    });
                    Done::Message(r)
                });
            }
        }
    }
}

/// Draws the QR code black on white, whatever the theme, with a quiet zone.
fn draw_qr(ui: &mut egui::Ui, qr: &Qr) {
    let module = 5.0;
    let quiet = 4.0;
    let side = (qr.width as f32 + 2.0 * quiet) * module;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 0.0, Color32::WHITE);
    for (i, dark) in qr.dark.iter().enumerate() {
        if *dark {
            let (x, y) = ((i % qr.width) as f32 + quiet, (i / qr.width) as f32 + quiet);
            let min = rect.min + egui::vec2(x * module, y * module);
            p.rect_filled(egui::Rect::from_min_size(min, egui::vec2(module, module)), 0.0, Color32::BLACK);
        }
    }
}

impl eframe::App for ServerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        // Keep the service state and open access current while idle.
        if self.busy.is_none() && self.enrolling.is_none() && self.refreshed.elapsed() >= REFRESH {
            self.refresh();
        }
        ctx.request_repaint_after(REFRESH);

        egui::Panel::left("nav").resizable(false).exact_size(170.0).show(ui, |ui| {
            ui.add_space(10.0);
            ui.label(RichText::new("RDP Gate Server").strong().size(16.0));
            ui.add_space(10.0);
            for p in Page::ALL {
                if ui.add_sized([150.0, 28.0], egui::Button::selectable(self.page == p, p.title())).clicked() && self.page != p {
                    self.page = p;
                    self.status = None;
                    if p == Page::Log {
                        self.log = admin::log_tail(&self.data, 400);
                    }
                }
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(label) = self.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(label);
                });
                ui.add_space(4.0);
            }
            if let Some((ok, msg)) = self.status.clone() {
                ui.horizontal(|ui| {
                    ui.colored_label(if ok { GOOD } else { BAD }, msg);
                    if ui.small_button("Dismiss").clicked() {
                        self.status = None;
                    }
                });
                ui.add_space(6.0);
            }
            if self.page == Page::Log {
                self.log_ui(ui);
                return;
            }
            let o = match &self.overview {
                Ok(o) => o.clone(),
                Err(e) => {
                    ui.heading("RDP Gate isn't set up on this PC");
                    ui.add_space(6.0);
                    ui.label("Run RDP Gate Server Setup (RDP-Gate-Server-Setup-….exe) to install the service, then open this window again.");
                    ui.add_space(6.0);
                    ui.colored_label(BAD, e);
                    return;
                }
            };
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.page {
                Page::Overview => self.overview_ui(ui, &o),
                Page::Computers => self.computers_ui(ui),
                Page::Codes => self.codes_ui(ui, &o),
                Page::Network => self.network_ui(ui, &o),
                Page::Browser => self.browser_ui(ui, &o),
                Page::Log => {}
            });
        });
        self.confirm_ui(&ctx);
    }
}
