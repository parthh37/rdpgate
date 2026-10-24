use eframe::egui::{self, Color32, RichText, TextEdit};
use rdpgate_core::update::Available;
use rdpgate_ui::{self as theme, MUTED, TEXT, Tone, card, muted, primary, titled_card};
use rdpgate_server::admin::{self, DeviceInfo, DnsRecord, Finding, Overview, TotpEnrollment, when};
use rdpgate_server::beacon::PublicIps;
use rdpgate_server::service::{self, Status};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

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
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([720.0, 500.0]),
        renderer: if opengl { eframe::Renderer::Glow } else { eframe::Renderer::Wgpu },
        ..Default::default()
    };
    let Err(e) = eframe::run_native("RDP Gate Server", options, Box::new(|cc| {
        theme::apply(&cc.egui_ctx);
        Ok(Box::new(ServerApp::new()))
    })) else {
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

/// Space between the cards on a page.
fn gap(ui: &mut egui::Ui) {
    ui.add_space(12.0);
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

    /// A small line drawing for the side bar, centred on `c`. Drawn rather
    /// than taken from a font: the built-in fonts have no such symbols.
    fn paint_icon(self, p: &egui::Painter, c: egui::Pos2, color: Color32) {
        use egui::{Rect, Stroke, StrokeKind, vec2};
        let s = Stroke::new(1.5, color);
        let line = |a: egui::Vec2, b: egui::Vec2| {
            p.line_segment([c + a, c + b], s);
        };
        match self {
            Page::Overview => {
                for (x, y) in [(-4.0, -4.0), (4.0, -4.0), (-4.0, 4.0), (4.0, 4.0)] {
                    p.rect_stroke(Rect::from_center_size(c + vec2(x, y), vec2(6.0, 6.0)), 1.5, s, StrokeKind::Middle);
                }
            }
            Page::Computers => {
                p.rect_stroke(Rect::from_center_size(c + vec2(0.0, -1.5), vec2(15.0, 10.0)), 2.0, s, StrokeKind::Middle);
                line(vec2(0.0, 3.5), vec2(0.0, 6.5));
                line(vec2(-4.0, 6.5), vec2(4.0, 6.5));
            }
            Page::Codes => {
                p.rect_stroke(Rect::from_center_size(c, vec2(16.0, 10.0)), 3.0, s, StrokeKind::Middle);
                for x in [-4.0, 0.0, 4.0] {
                    p.circle_filled(c + vec2(x, 0.0), 1.4, color);
                }
            }
            Page::Network => {
                p.circle_stroke(c, 7.0, s);
                line(vec2(-7.0, 0.0), vec2(7.0, 0.0));
                p.add(egui::Shape::ellipse_stroke(c, vec2(3.2, 7.0), s));
            }
            Page::Browser => {
                p.circle_stroke(c + vec2(-3.5, 0.0), 3.5, s);
                line(vec2(0.0, 0.0), vec2(7.5, 0.0));
                line(vec2(5.0, 0.0), vec2(5.0, 3.0));
                line(vec2(7.5, 0.0), vec2(7.5, 3.0));
            }
            Page::Log => {
                for (y, w) in [(-5.0, 14.0), (0.0, 14.0), (5.0, 9.0)] {
                    line(vec2(-7.0, y), vec2(-7.0 + w, y));
                }
            }
        }
    }
}

/// The service state as a pill.
fn service_pill(s: Status) -> (Tone, &'static str) {
    match s {
        Status::Running => (Tone::Good, "Running"),
        Status::Starting => (Tone::Warn, "Starting…"),
        Status::Stopping => (Tone::Warn, "Stopping…"),
        Status::Stopped => (Tone::Bad, "Stopped"),
        Status::NotInstalled => (Tone::Bad, "Not installed"),
        Status::Unknown => (Tone::Warn, "Unknown"),
    }
}

/// One status tile on the overview: what it is, how it's doing, a line of
/// detail and an optional button. Returns true when the button is clicked.
fn tile(ui: &mut egui::Ui, title: &str, tone: Tone, status: &str, detail: &str, action: Option<(&str, bool)>) -> bool {
    let mut clicked = false;
    card(ui, |ui| {
        ui.set_min_height(112.0);
        // Columns stretch every widget across; a tile's button shouldn't.
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(title).small().strong().color(MUTED));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    theme::dot(ui, tone);
                });
            });
            let color = if tone == Tone::Good || tone == Tone::Neutral { TEXT } else { tone.color() };
            ui.label(RichText::new(status).strong().size(16.0).color(color));
            if !detail.is_empty() {
                ui.add(egui::Label::new(muted(detail).small()).wrap());
            }
            if let Some((label, enabled)) = action {
                clicked = ui.add_enabled(enabled, egui::Button::new(label).small()).clicked();
            }
        });
    });
    clicked
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
    DomainOff,
}

/// Results of work done off the UI thread (the network and the service
/// manager can take a while).
enum Done {
    Message(Result<String, String>),
    Router(Vec<String>),
    UpdateChecked(Result<Option<Available>, String>),
    /// The DNS records to create for the host typed in.
    Records(String, Result<(Vec<DnsRecord>, PublicIps), String>),
    /// What a DNS check of that host found: whether it's right, line by line.
    DnsChecked(String, (bool, Vec<(Finding, String)>)),
}

/// The guided domain setup for browser sign-in, as it's filled in.
struct DomainForm {
    host: String,
    email: String,
    /// The records to create, for the host they were made for, and this
    /// network's addresses they came from.
    records: Option<(String, Vec<DnsRecord>, PublicIps)>,
    /// The last check of those records.
    check: Option<(bool, Vec<(Finding, String)>)>,
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
    /// Time limits being edited (minutes to connect, longest session in hours).
    limits: Option<(u32, f64)>,
    // Browser sign-in
    passkey_link: Option<(String, i64)>,
    domain: Option<DomainForm>,
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
        let value = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
        let data = value("--data").map(PathBuf::from);
        // Setup passes --setup-domain [--host H] [--email E] when browser
        // sign-in was chosen there: its guided setup is one of the steps to finish.
        let domain = args.iter().any(|a| a == "--setup-domain").then(|| DomainForm {
            host: value("--host").unwrap_or_default(),
            email: value("--email").unwrap_or_default(),
            records: None,
            check: None,
        });
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
            limits: None,
            passkey_link: None,
            domain,
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
            Done::Records(host, Ok((records, ips))) => {
                if let Some(f) = &mut self.domain {
                    f.records = Some((host, records, ips));
                    f.check = None;
                }
            }
            Done::Records(_, Err(e)) => self.say(Err(format!("Could not find this network's public address: {e}"))),
            Done::DnsChecked(host, verdict) => {
                // Only if it's still the name being set up.
                if let Some(f) = &mut self.domain
                    && f.records.as_ref().is_some_and(|(h, _, _)| *h == host)
                {
                    f.check = Some(verdict);
                }
            }
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

    /// What's left once Setup has secured the PC (Setup itself asks nothing),
    /// in order, each with the button that does it. Gone once all are done.
    fn finish_setup_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        struct Step {
            title: &'static str,
            detail: &'static str,
            done: bool,
            go: Page,
        }
        let mut steps = vec![
            Step {
                title: "Let your computers find this PC",
                detail: "Paste a GitHub token that can only use Gists: this PC publishes its address there, encrypted and signed.",
                done: o.beacon.is_some(),
                go: Page::Network,
            },
            Step {
                title: "Set up 6-digit codes",
                detail: "Scan a QR code with an authenticator app on your phone. Every sign-in needs a fresh code.",
                done: o.totp,
                go: Page::Codes,
            },
            Step {
                title: "Add the computers you connect from",
                detail: "Install the RDP Gate app on your Mac or PC, then paste the key it shows.",
                done: o.devices > 0,
                go: Page::Computers,
            },
        ];
        // Chosen in Setup: the domain it was given is filled in.
        if self.domain.is_some() || o.browser_url.is_some() {
            steps.push(Step {
                title: "Browser sign-in with your domain",
                detail: "Create the DNS records it shows, check them, and turn it on.",
                done: o.browser_url.is_some(),
                go: Page::Browser,
            });
        }
        if steps.iter().all(|s| s.done) {
            return;
        }
        let mut go = None;
        titled_card(ui, "Finish setting up", Some("Setup has secured this PC. These steps let your computers sign in."), |ui| {
            for (i, s) in steps.iter().enumerate() {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    theme::dot(ui, if s.done { Tone::Good } else { Tone::Neutral });
                    ui.vertical(|ui| {
                        let title = RichText::new(format!("{}. {}", i + 1, s.title)).strong();
                        ui.label(if s.done { title.color(MUTED) } else { title.color(TEXT) });
                        if !s.done {
                            ui.add(egui::Label::new(muted(s.detail).small()).wrap());
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if s.done {
                            theme::pill(ui, Tone::Good, "Done");
                        } else if ui.button("Set up…").clicked() {
                            go = Some(s.go);
                        }
                    });
                });
            }
            if o.devices == 0 {
                ui.add_space(6.0);
                ui.hyperlink_to("Download the RDP Gate app for your Mac or PC", "https://github.com/parthh37/rdpgate/releases/latest");
            }
        });
        gap(ui);
        if let Some(p) = go {
            self.page = p;
            self.status = None;
            // Straight to the QR code rather than one more button.
            if p == Page::Codes && !o.totp && self.enrolling.is_none() {
                self.begin_codes(false);
            }
            if p == Page::Browser && self.domain.is_none() && o.browser_url.is_none() {
                self.domain = Some(DomainForm { host: String::new(), email: String::new(), records: None, check: None });
            }
        }
    }

    fn overview_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        let ctx = ui.ctx().clone();
        let idle = self.busy.is_none();
        self.finish_setup_ui(ui, o);

        // Everything that stops a computer from getting in, or leaves RDP exposed.
        let mut problems = vec![];
        if self.service != Status::Running {
            problems.push("the service isn't running");
        }
        if o.protection_pending {
            problems.push("Remote Desktop is still reachable without RDP Gate");
        }
        if o.beacon.as_ref().is_none_or(|b| b.error.is_some()) {
            problems.push("your computers can't find this PC");
        }
        if !o.totp {
            problems.push("6-digit codes aren't set up");
        }
        // Behind carrier-grade NAT, IPv6 is the way in.
        let ipv6 = o.beacon.as_ref().and_then(|b| b.ip6.clone()).filter(|_| o.ipv6);
        if o.behind_nat && ipv6.is_none() {
            problems.push("this PC can't be reached from the internet");
        }
        card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::logo(ui, 52.0);
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    if problems.is_empty() {
                        theme::pill(ui, Tone::Good, "Protected");
                        ui.label(RichText::new("Remote Desktop is closed to the internet").heading().strong().color(TEXT));
                        ui.label(muted("It opens only for an enrolled computer that signs in, and only for that computer's address."));
                    } else {
                        theme::pill(ui, Tone::Warn, "Needs attention");
                        ui.label(RichText::new(format!("{} thing(s) to fix", problems.len())).heading().strong().color(TEXT));
                        let mut text = problems.join(", ");
                        if let Some(c) = text.get_mut(..1) {
                            c.make_ascii_uppercase();
                        }
                        ui.add(egui::Label::new(muted(format!("{text}."))).wrap());
                    }
                });
            });
        });
        gap(ui);

        let (service_tone, service_text) = service_pill(self.service);
        let service_detail = match self.service {
            Status::Stopped => "Nobody can sign in.",
            Status::NotInstalled => "Run RDP Gate Server Setup again.",
            _ => "Starts with Windows and restarts itself.",
        };
        let fp = &o.server_fingerprint;
        let short_fp = fp.get(..14).unwrap_or(fp);
        let mut go = None;
        ui.columns(3, |cols| {
            let service_action = match self.service {
                Status::Stopped => Some(("Start", idle)),
                Status::Running => Some(("Restart", idle)),
                _ => None,
            };
            if tile(&mut cols[0], "SERVICE", service_tone, service_text, service_detail, service_action) {
                if self.service == Status::Stopped {
                    self.run(&ctx, "Starting the service…", || {
                        Done::Message(service::ensure_running().map(|_| "The RDP Gate service is starting.".into()))
                    });
                } else {
                    self.restart(&ctx, "Restarted.");
                }
            }
            if o.protection_pending {
                if tile(
                    &mut cols[1],
                    "REMOTE DESKTOP",
                    Tone::Warn,
                    "Still open",
                    "Reachable without RDP Gate until a computer signs in through it.",
                    Some(("Close it now", idle)),
                ) {
                    self.confirm = Some(Confirm::Protect);
                }
            } else {
                tile(&mut cols[1], "REMOTE DESKTOP", Tone::Good, "Closed", "Only to everyone who hasn't signed in.", None);
            }
            let (tone, status, detail) = match &o.beacon {
                Some(b) if b.error.is_some() => (Tone::Bad, "Beacon problem".to_string(), b.error.clone().unwrap_or_default()),
                Some(b) => match (b.ip.as_deref(), ipv6.as_deref()) {
                    (Some(v4), Some(v6)) => (Tone::Good, format!("Published {v4}"), format!("and IPv6 {v6}. Updated {}", when(b.published))),
                    (None, Some(v6)) => (Tone::Good, "Published (IPv6)".to_string(), format!("{v6}. Updated {}", when(b.published))),
                    (ip, _) => (Tone::Good, format!("Published {}", ip.unwrap_or("?")), format!("Updated {}", when(b.published))),
                },
                None => (Tone::Bad, "No beacon".to_string(), "Your computers can't find this PC.".to_string()),
            };
            if tile(&mut cols[2], "FINDING THIS PC", tone, &status, &detail, Some(("Network…", true))) {
                go = Some(Page::Network);
            }
        });
        ui.add_space(4.0);
        ui.columns(3, |cols| {
            let (tone, status) = if o.totp { (Tone::Good, "Set up") } else { (Tone::Bad, "Not set up") };
            let detail = if o.totp { "From any authenticator app." } else { "Nobody can sign in yet." };
            if tile(&mut cols[0], "6-DIGIT CODES", tone, status, detail, Some(("6-digit codes…", true))) {
                go = Some(Page::Codes);
            }
            let status = match o.devices {
                0 => "None yet".to_string(),
                1 => "1 enrolled".to_string(),
                n => format!("{n} enrolled"),
            };
            let tone = if o.devices == 0 { Tone::Warn } else { Tone::Good };
            if tile(&mut cols[1], "COMPUTERS", tone, &status, "Only enrolled computers can sign in.", Some(("Computers…", true))) {
                go = Some(Page::Computers);
            }
            let router_tone = match (o.behind_nat, &ipv6) {
                (true, None) => Tone::Bad,
                (true, Some(_)) => Tone::Warn,
                _ => Tone::Neutral,
            };
            let lan = if o.lan {
                format!("Home network sign-in on (this PC is {}).", o.lan_ip.as_deref().unwrap_or("not on a home network right now"))
            } else {
                "Sign-in only from outside.".into()
            };
            tile(&mut cols[2], "ROUTER", router_tone, &o.router, &lan, None);
        });
        if let Some(p) = go {
            self.page = p;
        }

        if o.behind_nat {
            gap(ui);
            if ipv6.is_some() {
                theme::notice(
                    ui,
                    Tone::Warn,
                    "Your router's own IPv4 address isn't public (carrier-grade NAT, or a second router in front), so \
                     computers reach this PC over IPv6 instead. That works from networks that have IPv6 too (most mobile \
                     networks do), if your router's IPv6 firewall lets them in: see Network.",
                    false,
                );
            } else {
                theme::notice(
                    ui,
                    Tone::Bad,
                    "Your router's own internet address isn't public (carrier-grade NAT, or a second router in front). \
                     Nothing on the internet can reach this PC: ask your internet provider for a public IPv4 address, \
                     or turn on IPv6 on your router (Network > IPv6).",
                    false,
                );
            }
        }
        for w in &o.warnings {
            ui.add_space(6.0);
            theme::notice(ui, Tone::Warn, &format!("Warning: {w}"), false);
        }

        gap(ui);
        titled_card(ui, "Open access", Some("Addresses Remote Desktop is open for right now."), |ui| {
            if o.grants.is_empty() {
                ui.horizontal(|ui| {
                    theme::dot(ui, Tone::Neutral);
                    ui.label(muted("Nobody has access open right now."));
                });
            } else {
                let t = rdpgate_server::state::now();
                egui::Grid::new("grants").striped(true).num_columns(4).spacing([28.0, 8.0]).min_col_width(100.0).show(ui, |ui| {
                    ui.label(muted("ADDRESS").small().strong());
                    ui.label(muted("WHO").small().strong());
                    ui.label(muted("REMOTE DESKTOP").small().strong());
                    ui.label(muted("OPEN UNTIL").small().strong());
                    ui.end_row();
                    for g in &o.grants {
                        let connected = g.connected(t);
                        ui.horizontal(|ui| {
                            theme::dot(ui, if connected { Tone::Good } else { Tone::Info });
                            ui.monospace(&g.ip);
                        });
                        ui.label(&g.who);
                        ui.label(if connected {
                            "Connected"
                        } else if g.last_connected.is_some() {
                            "Disconnected"
                        } else {
                            "Waiting to connect"
                        });
                        let until = if connected {
                            format!("While connected, at most {}", when(Some(g.hard_expires)))
                        } else {
                            when(Some(g.closes(t)))
                        };
                        ui.label(until).on_hover_text(format!(
                            "Stays open while Remote Desktop is connected, and {} min after it disconnects, but never past {}.",
                            rdpgate_server::grants::GRACE.as_secs() / 60,
                            when(Some(g.hard_expires))
                        ));
                        ui.end_row();
                    }
                });
            }
        });

        gap(ui);
        titled_card(
            ui,
            "Time limits",
            Some("A sign-in opens Remote Desktop for a while to connect. Once connected, it stays open for as long as the session lasts, up to the longest session."),
            |ui| {
                let (mut minutes, mut hours) = self.limits.unwrap_or((o.grant_minutes, o.max_hours));
                egui::Grid::new("limits").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    ui.label("Time to connect after signing in");
                    ui.add(egui::DragValue::new(&mut minutes).range(1..=240).suffix(" min"));
                    ui.end_row();
                    ui.label("Longest session");
                    ui.add(egui::DragValue::new(&mut hours).range(0.5..=168.0).speed(0.5).fixed_decimals(1).suffix(" h"));
                    ui.end_row();
                });
                let changed = (minutes, hours) != (o.grant_minutes, o.max_hours);
                self.limits = changed.then_some((minutes, hours));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.add_enabled(changed, primary("Save")).clicked() {
                        match admin::set_time_limits(&self.data, minutes, hours) {
                            Ok(()) => {
                                self.limits = None;
                                self.say(Ok(format!(
                                    "Saved: {minutes} min to connect, sessions up to {hours:.1} h. Applies within a few seconds, \
                                     to sessions already open too, without disconnecting anyone."
                                )));
                                self.refresh();
                            }
                            Err(e) => self.say(Err(e)),
                        }
                    }
                    if changed && ui.button("Cancel").clicked() {
                        self.limits = None;
                    }
                });
            },
        );

        gap(ui);
        titled_card(ui, "Updates", None, |ui| {
            ui.horizontal(|ui| {
                theme::pill(ui, Tone::Info, &format!("Version {}", o.version));
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
            ui.add_space(4.0);
            match self.update.clone() {
                Some(av) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, Tone::Good, &format!("Version {} is available", av.version));
                        if ui.add_enabled(idle, primary("Install update")).clicked() {
                            self.confirm = Some(Confirm::InstallUpdate(Box::new(av)));
                        }
                    });
                }
                None => {
                    if ui.add_enabled(idle, egui::Button::new("Check for updates")).clicked() {
                        let pre = rdpgate_server::config::Config::load(&self.data).map(|c| c.update_prereleases).unwrap_or(true);
                        self.run(&ctx, "Checking for updates…", move || {
                            Done::UpdateChecked(rdpgate_core::update::check(rdpgate_server::updater::VERSION, pre))
                        });
                    }
                }
            }
            ui.add_space(4.0);
            ui.label(muted(format!("Server key fingerprint {short_fp}…")).small()).on_hover_text(fp);
        });
    }

    fn computers_ui(&mut self, ui: &mut egui::Ui) {
        theme::page_title(ui, "Computers", "Each computer you connect from has its own key. Only enrolled computers can sign in.");

        titled_card(ui, "Add a computer", None, |ui| {
            ui.label(muted("1. On that computer, install the RDP Gate app and set it up. It shows a key that starts with rdpgate-ed25519: (and a Copy button)."));
            ui.label(muted("2. Paste it below. Pasting the whole \"rdpgate-server device-add …\" line works too."));
            ui.add_space(4.0);
            let label = theme::field_label(ui, "Key");
            let pasted = ui
                .add(
                    TextEdit::multiline(&mut self.add_key)
                        .hint_text("rdpgate-ed25519:…")
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10, 8)),
                )
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
            let label = theme::field_label(ui, "Name");
            ui.add(TextEdit::singleline(&mut self.add_name).hint_text("e.g. laptop").desired_width(260.0)).labelled_by(label.id);
            ui.add_space(4.0);
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
                theme::notice(ui, Tone::Good, &format!("Enrolled {name}. Its fingerprint is {fp}: check it matches the one shown on that computer."), false);
                ui.add_space(4.0);
                ui.label(muted("3. Paste this server card into the app on that computer:"));
                self.card_ui(ui);
            }
        });

        gap(ui);
        let devices = self.devices.clone();
        titled_card(ui, "Enrolled", None, |ui| {
            if devices.is_empty() {
                ui.label(muted("No computers yet."));
                return;
            }
            egui::Grid::new("devices").striped(true).num_columns(4).spacing([24.0, 8.0]).show(ui, |ui| {
                ui.label(muted("NAME").small().strong());
                ui.label(muted("FINGERPRINT").small().strong());
                ui.label(muted("LAST SIGN-IN").small().strong());
                ui.label("");
                ui.end_row();
                for d in &devices {
                    ui.horizontal(|ui| {
                        theme::dot(ui, if d.locked { Tone::Bad } else { Tone::Good });
                        ui.label(RichText::new(&d.name).strong());
                    });
                    ui.monospace(d.fingerprint.get(..14).unwrap_or(&d.fingerprint));
                    ui.label(when(d.last_auth));
                    ui.horizontal(|ui| {
                        if d.locked {
                            theme::pill(ui, Tone::Bad, "Locked (10 wrong codes)");
                            if ui.button("Unlock").clicked() {
                                let r = admin::unlock_device(&self.data, &d.name).map(|()| format!("Unlocked {}.", d.name));
                                self.say(r);
                                self.refresh();
                            }
                        }
                        if ui.button("Remove…").clicked() {
                            self.confirm = Some(Confirm::RemoveComputer(d.name.clone()));
                        }
                    });
                    ui.end_row();
                }
            });
        });

        if self.added.is_none() {
            gap(ui);
            titled_card(
                ui,
                "Server card",
                Some("Every computer needs this once (the app asks for it). It lets the app find and check this PC."),
                |ui| self.card_ui(ui),
            );
        }
    }

    fn card_ui(&mut self, ui: &mut egui::Ui) {
        match admin::card(&self.data) {
            Ok(card) => {
                theme::code_box(ui, &card, 3);
                if ui.button("Copy server card").clicked() {
                    ui.ctx().copy_text(card);
                    self.say(Ok("Server card copied. Keep it private: it reveals where to find this PC.".into()));
                }
            }
            Err(e) => {
                theme::notice(ui, Tone::Bad, &e, false);
            }
        }
    }

    fn codes_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        theme::page_title(
            ui,
            "6-digit codes",
            "Signing in takes the computer's key plus a code from an authenticator app on your phone (Google or Microsoft Authenticator, 1Password, …).",
        );
        if let Some((e, qr)) = &self.enrolling {
            let mut confirm = false;
            let mut cancel = false;
            card(ui, |ui| {
                ui.horizontal_top(|ui| {
                    draw_qr(ui, qr);
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("1. Scan this with the authenticator app").strong());
                        ui.label(muted("Add an account in the app and point the camera at the code."));
                        ui.add_space(6.0);
                        ui.label(muted("Or type this key into the app instead:"));
                        ui.label(RichText::new(&e.key).monospace());
                        ui.label(RichText::new("Don't photograph or screenshot it: anyone with this key can make your codes.").small().color(theme::WARN));
                        ui.add_space(12.0);
                        let label = ui.label(RichText::new("2. Type the 6-digit code the app shows now").strong());
                        ui.horizontal(|ui| {
                            let r = ui
                                .add(
                                    TextEdit::singleline(&mut self.code)
                                        .char_limit(6)
                                        .desired_width(110.0)
                                        .font(egui::FontId::monospace(20.0)),
                                )
                                .labelled_by(label.id);
                            confirm = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            confirm |= ui.add_enabled(self.code.trim().len() == 6, primary("Turn codes on")).clicked();
                            cancel = ui.button("Cancel").clicked();
                        });
                    });
                });
            });
            if cancel {
                self.enrolling = None;
                self.code.clear();
            }
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
        card(ui, |ui| {
            if o.totp {
                theme::pill(ui, Tone::Good, "Set up");
                ui.label(muted("Every sign-in from a computer needs a fresh code. Each code works once."));
                ui.add_space(6.0);
                if ui.button("Use a new phone…").clicked() {
                    self.confirm = Some(Confirm::ReplaceCodes);
                }
            } else {
                theme::pill(ui, Tone::Bad, "Not set up");
                ui.label(muted("Nobody can sign in until they are."));
                ui.add_space(6.0);
                if ui.add(primary("Set up 6-digit codes")).clicked() {
                    self.begin_codes(false);
                }
            }
        });
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
        theme::page_title(ui, "Network", "How your computers find this PC, and how they reach it.");

        titled_card(
            ui,
            "Beacon",
            Some("This PC publishes its address, encrypted and signed, in a secret GitHub gist. It needs a GitHub token that can only use Gists, ideally from a GitHub account used just for this."),
            |ui| {
                match &o.beacon {
                    Some(b) => {
                        ui.horizontal_wrapped(|ui| {
                            theme::pill(ui, if b.error.is_some() { Tone::Bad } else { Tone::Good }, "Publishing");
                            let ips: Vec<&str> = [b.ip.as_deref(), b.ip6.as_deref()].into_iter().flatten().collect();
                            let ips = if ips.is_empty() { "?".to_string() } else { ips.join(" and ") };
                            ui.label(muted(format!("Gist {}  ·  last address {ips}  ·  published {}", b.gist, when(b.published))).small());
                        });
                        if let Some(e) = &b.error {
                            theme::notice(ui, Tone::Bad, &format!("Last error: {e}"), false);
                        }
                    }
                    None => {
                        theme::pill(ui, Tone::Bad, "Not set up");
                    }
                }
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.hyperlink_to("Create a token on GitHub", "https://github.com/settings/personal-access-tokens/new");
                    ui.label(muted("with Account permissions > Gists: Read and write, and nothing else."));
                });
                let label = theme::field_label(ui, "GitHub token");
                ui.add(TextEdit::singleline(&mut *self.token).password(true).desired_width(400.0)).labelled_by(label.id);
                let label = theme::field_label(ui, "Gist (optional)");
                ui.add(TextEdit::singleline(&mut self.gist).hint_text("leave empty to create a new one").desired_width(400.0))
                    .labelled_by(label.id);
                ui.add_space(4.0);
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
            },
        );

        gap(ui);
        titled_card(ui, "Sign-in from this network", None, |ui| {
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
            ui.label(muted("For a laptop on the same Wi-Fi. Give this PC a reserved address in your router so it keeps the same one.").small());
        });

        gap(ui);
        titled_card(ui, "IPv6", None, |ui| {
            let mut on = o.ipv6;
            if ui.checkbox(&mut on, "Accept sign-in over IPv6, and publish this PC's IPv6 address in the beacon").changed() {
                match admin::set_ipv6(&self.data, on) {
                    Ok(()) => self.restart(&ctx, if on { "Sign-in over IPv6 is on." } else { "Sign-in over IPv6 is off." }),
                    Err(e) => self.say(Err(e)),
                }
            }
            if o.ipv6 {
                match o.beacon.as_ref().and_then(|b| b.ip6.as_deref()) {
                    Some(ip) => {
                        ui.horizontal_wrapped(|ui| {
                            theme::pill(ui, Tone::Good, "Published");
                            ui.label(muted("This PC's public IPv6 address is"));
                            ui.monospace(ip);
                        });
                    }
                    None if o.beacon.is_some() => {
                        ui.label(muted("No public IPv6 address found for this PC yet (the beacon checks every 5 minutes). Your internet provider or router may not offer IPv6."));
                    }
                    None => {}
                }
                ui.label(muted(format!(
                    "IPv6 needs no port forwarding, but your router's IPv6 firewall must let TCP {} (sign-in) and TCP {} (Remote Desktop) in to this PC. \
                     Look for \"IPv6 firewall\", \"pinhole\" or \"allow inbound\" in its settings. Your computers try IPv6 first, then IPv4.",
                    o.listen_port, o.rdp_port
                ))
                .small());
            }
        });

        gap(ui);
        titled_card(ui, "Router", None, |ui| {
            ui.label(muted(format!(
                "Your router must send TCP {} (sign-in) and TCP {} (Remote Desktop) to this PC. Remote Desktop stays closed in Windows Firewall until someone signs in.",
                o.public_port, o.rdp_public_port
            )));
            ui.horizontal(|ui| {
                theme::pill(ui, if o.behind_nat { Tone::Bad } else { Tone::Neutral }, &o.router);
            });
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
        });
    }

    fn browser_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        theme::page_title(
            ui,
            "Browser sign-in",
            "Optional: sign in from a web browser with a passkey. It needs a domain name you control pointing at this PC. The RDP Gate app doesn't need any of this.",
        );
        if self.domain.is_some() {
            self.domain_ui(ui, o);
            return;
        }
        card(ui, |ui| {
            match &o.browser_url {
                Some(url) => {
                    theme::pill(ui, Tone::Good, "On");
                    ui.label(muted("Your sign-in page (bookmark the full address on each device; the domain alone shows nothing):"));
                    theme::code_line(ui, url);
                }
                None => {
                    theme::pill(ui, Tone::Neutral, "Off");
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let label = if o.browser_url.is_some() { "Change the domain…" } else { "Set up with my domain…" };
                if ui.add_enabled(self.busy.is_none(), egui::Button::new(label)).clicked() {
                    self.domain = Some(DomainForm {
                        host: o.public_host.clone().unwrap_or_default(),
                        email: o.cert_email.clone().unwrap_or_default(),
                        records: None,
                        check: None,
                    });
                    self.status = None;
                }
                if o.browser_url.is_some() && ui.add_enabled(self.busy.is_none(), egui::Button::new("Turn off…")).clicked() {
                    self.confirm = Some(Confirm::DomainOff);
                }
            });
        });

        if o.browser_url.is_none() {
            return;
        }
        gap(ui);
        titled_card(ui, "Passkeys", None, |ui| {
            if o.passkeys.is_empty() {
                ui.label(muted("No passkeys yet."));
            }
            egui::Grid::new("passkeys").striped(true).num_columns(4).spacing([24.0, 8.0]).show(ui, |ui| {
                for p in &o.passkeys {
                    ui.label(RichText::new(&p.name).strong());
                    ui.label(muted(format!("added {}", when(Some(p.added)))));
                    ui.label(muted(format!("last used {}", when(p.last_used))));
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
                ui.label(muted(format!("Open it on the phone or computer whose passkey you want to add. It works once, until {}:", when(Some(expires)))));
                theme::code_line(ui, &link);
                if ui.button("Copy link").clicked() {
                    ui.ctx().copy_text(link);
                    self.say(Ok("Link copied. Treat it like a password.".into()));
                }
            }
        });
    }

    fn log_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Activity log").heading().strong().color(TEXT));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Open log folder").clicked() {
                    let _ = std::process::Command::new("explorer.exe").arg(self.data.join("logs")).spawn();
                }
                if ui.button("Refresh").clicked() {
                    self.log = admin::log_tail(&self.data, 400);
                }
            });
        });
        ui.label(muted("Sign-ins, firewall openings and closings, beacon and update activity. Newest at the bottom."));
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(theme::INPUT)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(egui::CornerRadius::same(12))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                    ui.add(egui::Label::new(log_job(&self.log)).wrap_mode(egui::TextWrapMode::Extend));
                });
            });
    }

    /// The guided domain setup: the name, the DNS records to create (checked
    /// for you), then the certificate email and turning it on.
    fn domain_ui(&mut self, ui: &mut egui::Ui, o: &Overview) {
        let ctx = ui.ctx().clone();
        let idle = self.busy.is_none();
        let Some(f) = self.domain.as_mut() else { return };
        let (mut find, mut check, mut turn_on) = (false, false, false);
        let step = match (&f.records, &f.check) {
            (None, _) => 0,
            (Some(_), Some((true, _))) => 2,
            (Some(_), _) => 1,
        };
        theme::steps(ui, &["Domain name", "DNS records", "Turn on"], step);
        ui.add_space(10.0);

        titled_card(
            ui,
            "1. Domain name",
            Some("Browsers only use passkeys with a domain name, never an IP address. Use a name under a domain you control (from any registrar, or Cloudflare)."),
            |ui| {
                let label = theme::field_label(ui, "Domain name for this PC");
                let r = ui
                    .add(TextEdit::singleline(&mut f.host).hint_text("e.g. rdp.example.com").desired_width(360.0))
                    .labelled_by(label.id);
                if r.changed() {
                    f.records = None;
                    f.check = None;
                }
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(4.0);
                let label = if f.records.is_some() { "Find the records again" } else { "Show the DNS records to create" };
                find = (ui.add_enabled(idle && !f.host.trim().is_empty(), primary(label)).clicked() || enter) && idle;
            },
        );

        if let Some((host, records, _)) = &f.records {
            gap(ui);
            titled_card(
                ui,
                "2. DNS records",
                Some("At your DNS provider, create (or update) these, then check them here. Most providers want only the part before your domain in Name."),
                |ui| {
                    egui::Grid::new("dns").striped(true).num_columns(5).spacing([20.0, 8.0]).show(ui, |ui| {
                        for h in ["TYPE", "NAME", "VALUE", "TTL", ""] {
                            ui.label(muted(h).small().strong());
                        }
                        ui.end_row();
                        for r in records {
                            ui.monospace(r.kind);
                            ui.monospace(&r.name).on_hover_text(format!("= {host}"));
                            ui.monospace(&r.value);
                            ui.label(muted("300 (or Auto)"));
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(r.value.clone());
                            }
                            ui.end_row();
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(muted("Cloudflare: set Proxy status to \"DNS only\" (grey cloud). The proxy would hide this PC.").small());
                    ui.label(muted("If your home addresses change, keep the records current with dynamic DNS (\"DDNS\" at your registrar or router).").small());
                    if records.iter().any(|r| r.kind == "AAAA") {
                        ui.label(muted(format!("For IPv6 visitors your router's IPv6 firewall must also let TCP {} in to this PC.", o.listen_port)).small());
                    }
                    ui.add_space(6.0);
                    if let Some((_, lines)) = &f.check {
                        for (finding, line) in lines {
                            let (tone, color) = match finding {
                                Finding::Good => (Tone::Good, TEXT),
                                Finding::Hint => (Tone::Info, MUTED),
                                Finding::Wrong => (Tone::Bad, theme::BAD),
                            };
                            ui.horizontal(|ui| {
                                theme::dot(ui, tone);
                                ui.add(egui::Label::new(RichText::new(line).color(color)).wrap());
                            });
                        }
                        ui.add_space(4.0);
                    }
                    check = ui.add_enabled(idle, egui::Button::new(if f.check.is_some() { "Check again" } else { "Check the records" })).clicked();
                },
            );

            gap(ui);
            let ok = f.check.as_ref().is_some_and(|(ok, _)| *ok);
            titled_card(ui, "3. Certificate and turning it on", None, |ui| {
                ui.label(muted("The certificate comes free from Let's Encrypt, automatically, through port 443."));
                if o.public_port != 443 {
                    theme::notice(
                        ui,
                        Tone::Warn,
                        &format!("Your router forwards port {} instead of 443. Let's Encrypt only checks port 443, so also forward the router's TCP 443 to this PC's port {}.", o.public_port, o.listen_port),
                        false,
                    );
                }
                let label = theme::field_label(ui, "Email for certificate expiry notices (optional)");
                ui.add(TextEdit::singleline(&mut f.email).hint_text("you@example.com").desired_width(360.0)).labelled_by(label.id);
                if o.public_host.as_deref().is_some_and(|h| *h != *host) && !o.passkeys.is_empty() {
                    ui.add_space(4.0);
                    theme::notice(ui, Tone::Warn, "The domain changes, so passkeys made for the old one stop working. Add new ones afterwards.", false);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    turn_on = ui.add_enabled(idle && ok, primary("Turn on browser sign-in")).clicked();
                    if f.check.as_ref().is_some_and(|(ok, _)| !ok) {
                        turn_on |= ui
                            .add_enabled(idle, egui::Button::new("Turn on anyway"))
                            .on_hover_text("Sign-in and the certificate only work once the records are right.")
                            .clicked();
                    }
                });
                if !ok {
                    ui.label(muted("Check the records first.").small());
                }
            });
        }
        ui.add_space(10.0);
        let cancel = ui.button("Cancel").clicked();

        // Act once the form is no longer borrowed.
        let (host, email) = (f.host.clone(), f.email.clone());
        let made_for = f.records.as_ref().map(|(h, _, ips)| (h.clone(), *ips));
        if cancel {
            self.domain = None;
            return;
        }
        if find {
            match admin::clean_host(&host) {
                Ok(host) => {
                    let data = self.data.clone();
                    self.run(&ctx, "Finding this network's public addresses…", move || {
                        let r = admin::dns_records(&data, &host);
                        Done::Records(host, r)
                    });
                }
                Err(e) => self.say(Err(e)),
            }
        } else if check && let Some((host, ips)) = made_for.clone() {
            self.run(&ctx, "Checking the DNS records…", move || {
                let verdict = admin::dns_verdict(&host, &ips, &admin::resolve_host(&host));
                Done::DnsChecked(host, verdict)
            });
        } else if turn_on && let Some((host, _)) = made_for {
            match admin::domain_on(&self.data, &host, &email) {
                Ok(_) => {
                    self.domain = None;
                    self.restart(
                        &ctx,
                        "Browser sign-in is on. The first visit can take up to a minute while the certificate is issued; \
                         test it from outside your network (a phone on mobile data, say).",
                    );
                }
                Err(e) => self.say(Err(e)),
            }
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
            Confirm::DomainOff => (
                "Turn browser sign-in off?".to_string(),
                "Nobody can sign in from a browser until it's set up again. Passkeys are kept and work again with the same domain. \
                 The RDP Gate app isn't affected."
                    .to_string(),
                "Turn off",
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
            Confirm::DomainOff => match admin::domain_off(&self.data) {
                Ok(()) => self.restart(ctx, "Browser sign-in is off."),
                Err(e) => self.say(Err(e)),
            },
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

/// The log with refusals in red and openings in green, so they stand out.
fn log_job(log: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let font = egui::FontId::monospace(12.5);
    for line in log.lines() {
        let color = if line.contains("DENY") || line.contains("BAN") {
            theme::BAD
        } else if line.contains("GRANT") {
            theme::GOOD
        } else if line.contains("error") || line.contains("failed") || line.contains("WARN") {
            theme::WARN
        } else {
            MUTED
        };
        let format = |color| egui::TextFormat { font_id: font.clone(), color, ..Default::default() };
        job.append(line, 0.0, format(color));
        job.append("\n", 0.0, format(color));
    }
    job
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

        let nav = egui::Frame::new().fill(theme::BAR).inner_margin(egui::Margin::symmetric(12, 14));
        egui::Panel::left("nav").resizable(false).exact_size(214.0).frame(nav).show(ui, |ui| {
            theme::brand(ui, "RDP Gate Server", "Manage this PC");
            ui.add_space(18.0);
            for p in Page::ALL {
                if nav_item(ui, p, self.page == p) && self.page != p {
                    self.page = p;
                    self.status = None;
                    if p == Page::Log {
                        self.log = admin::log_tail(&self.data, 400);
                    }
                }
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.label(muted(format!("Version {}", rdpgate_server::updater::VERSION)).small());
                let (tone, text) = service_pill(self.service);
                ui.horizontal(|ui| {
                    ui.label(muted("Service").small());
                    theme::pill(ui, tone, text);
                });
                ui.add_space(2.0);
                ui.separator();
            });
        });

        let body = egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::symmetric(22, 18));
        egui::CentralPanel::default().frame(body).show(ui, |ui| {
            if let Some(label) = self.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(label);
                });
                ui.add_space(4.0);
            }
            if let Some((ok, msg)) = self.status.clone() {
                if theme::notice(ui, Tone::from_ok(ok), &msg, true) {
                    self.status = None;
                }
                ui.add_space(10.0);
            }
            if self.page == Page::Log {
                self.log_ui(ui);
                return;
            }
            let o = match &self.overview {
                Ok(o) => o.clone(),
                Err(e) if e.contains("os error 5") => {
                    // The folder is there but this window may not read it: not
                    // "isn't set up", which would send people to run init again.
                    theme::page_title(
                        ui,
                        "This window can't read RDP Gate's settings",
                        "Windows refused access to C:\\ProgramData\\RDPGate. Close this window and open RDP Gate Server again, \
                         choosing Yes when Windows asks for administrator permission. If it still fails, run RDP Gate Server Setup \
                         again: it repairs the folder's permissions.",
                    );
                    theme::notice(ui, Tone::Bad, e, false);
                    return;
                }
                Err(e) => {
                    theme::page_title(
                        ui,
                        "RDP Gate isn't set up on this PC",
                        "Run RDP Gate Server Setup (RDP-Gate-Server-Setup-….exe) to install the service, then open this window again.",
                    );
                    theme::notice(ui, Tone::Bad, e, false);
                    return;
                }
            };
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                match self.page {
                    Page::Overview => self.overview_ui(ui, &o),
                    Page::Computers => self.computers_ui(ui),
                    Page::Codes => self.codes_ui(ui, &o),
                    Page::Network => self.network_ui(ui, &o),
                    Page::Browser => self.browser_ui(ui, &o),
                    Page::Log => {}
                }
                ui.add_space(8.0);
            });
        });
        self.confirm_ui(&ctx);
    }
}

/// A row in the side bar: icon and title, lit when it's the open page.
fn nav_item(ui: &mut egui::Ui, page: Page, selected: bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, selected, page.title()));
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, 9.0, Color32::from_rgba_unmultiplied(59, 108, 240, 52));
        let bar = egui::Rect::from_min_size(rect.min + egui::vec2(0.0, 8.0), egui::vec2(3.0, rect.height() - 16.0));
        p.rect_filled(bar, 2.0, theme::ACCENT);
    } else if response.hovered() {
        p.rect_filled(rect, 9.0, Color32::from_white_alpha(8));
    }
    let color = if selected { Color32::WHITE } else if response.hovered() { TEXT } else { MUTED };
    let y = rect.center().y;
    page.paint_icon(p, egui::pos2(rect.min.x + 24.0, y), color);
    p.text(egui::pos2(rect.min.x + 44.0, y), egui::Align2::LEFT_CENTER, page.title(), egui::FontId::proportional(14.0), color);
    response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
}
