use clap::{Args, Parser, Subcommand};
use rdpgate_client::settings::{Audio, COLORS, Choice, Display, Keys, Resize, SCALES, Speed};
use rdpgate_client::{self as client, FollowEvent, RdpCheck, RdpSettings, winpass};
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "rdpgate", version, about = "Sign in to your RDP Gate server and open Remote Desktop")]
struct Cli {
    /// Settings folder (default: your user's app-config folder)
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    /// Read the passphrase from the first line of stdin (for scripts)
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this computer's device key
    Init {
        /// Name for this computer, e.g. macbook
        #[arg(long)]
        name: String,
        /// Windows account to pre-fill in Remote Desktop
        #[arg(long)]
        username: Option<String>,
        /// Replace an existing device key
        #[arg(long)]
        force: bool,
    },
    /// Save the server card printed by `rdpgate-server device-add` / `card`
    Card { card: String },
    /// Sign in (passphrase + 6-digit code, or nothing once auto mode
    /// remembers this computer) and open Remote Desktop
    Connect {
        /// 6-digit code (prompted if omitted). Signs in with passphrase and
        /// code even when this computer is remembered.
        #[arg(long)]
        code: Option<String>,
        /// Sign in with passphrase and code even when this computer is remembered
        #[arg(long)]
        with_code: bool,
        /// Keep me signed in: after this sign-in, connect with no passphrase
        /// or code until this computer's hardware changes (`rdpgate forget`
        /// undoes it). Remembered for next time.
        #[arg(long)]
        keep_signed_in: bool,
        /// Try this server address first, e.g. 203.0.113.7:47443
        #[arg(long)]
        address: Option<SocketAddr>,
        /// Only sign in; don't launch Remote Desktop
        #[arg(long)]
        no_launch: bool,
        /// Keep running and move access with this computer when its IP
        /// address changes (needs auto mode on for it on the server)
        #[arg(long)]
        follow: bool,
    },
    /// Close the firewall for this network now
    Lock,
    /// Stop remembering this computer: sign in with passphrase and code again
    Forget,
    /// Show this computer's enrollment command and the pinned server
    Show,
    /// Show or change the Remote Desktop settings used at every connect
    /// (no options: show them)
    Settings(SettingsArgs),
    /// Remember your Windows password in the system's credential store, so
    /// Remote Desktop signs in by itself (Windows; on a Mac it can be copied)
    Password {
        /// Windows account it belongs to (default: the one already set)
        #[arg(long)]
        user: Option<String>,
        /// Forget the saved password
        #[arg(long, conflicts_with_all = ["user", "copy"])]
        forget: bool,
        /// Copy the saved password to paste into Remote Desktop (cleared after 45 s)
        #[arg(long, conflicts_with = "user")]
        copy: bool,
    },
    /// Check for and install a signed update of this tool
    Update {
        /// Only check; don't install
        #[arg(long)]
        check: bool,
    },
    /// Turn automatic updates on or off
    AutoUpdate {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

#[derive(Args)]
struct SettingsArgs {
    /// full-screen, all-monitors or window
    #[arg(long)]
    display: Option<Display>,
    /// Window size for --display window, e.g. 1600x900 (or "auto")
    #[arg(long, value_parser = parse_size)]
    size: Option<(u32, u32)>,
    /// When the window is resized: resolution, scale or off
    #[arg(long)]
    resize: Option<Resize>,
    /// Display scale in percent (100, 125, 150, 175, 200, 250, 300, 400, 500), or 0 to match this computer
    #[arg(long, value_parser = parse_scale)]
    scale: Option<u32>,
    /// Colour depth: 32, 24, 16 or 15
    #[arg(long, value_parser = parse_colors)]
    colors: Option<u32>,
    /// Connection bar in full screen
    #[arg(long, value_parser = on_off)]
    connection_bar: Option<bool>,
    /// Where Windows key combinations go: here, remote or full-screen
    #[arg(long)]
    keys: Option<Keys>,
    #[arg(long, value_parser = on_off)]
    clipboard: Option<bool>,
    /// All of this computer's drives
    #[arg(long, value_parser = on_off)]
    drives: Option<bool>,
    #[arg(long, value_parser = on_off)]
    printers: Option<bool>,
    /// Remote sound: here, remote or off
    #[arg(long)]
    audio: Option<Audio>,
    #[arg(long, value_parser = on_off)]
    microphone: Option<bool>,
    #[arg(long, value_parser = on_off)]
    cameras: Option<bool>,
    #[arg(long, value_parser = on_off)]
    smart_cards: Option<bool>,
    /// Connection speed: auto, lan, broadband or slow
    #[arg(long)]
    speed: Option<Speed>,
    /// Desktop background
    #[arg(long, value_parser = on_off)]
    wallpaper: Option<bool>,
    #[arg(long, value_parser = on_off)]
    font_smoothing: Option<bool>,
    /// Window animations and themes
    #[arg(long, value_parser = on_off)]
    visual_effects: Option<bool>,
    #[arg(long, value_parser = on_off)]
    auto_reconnect: Option<bool>,
    /// Back to the defaults (before any other option given)
    #[arg(long)]
    reset: bool,
}

fn on_off(s: &str) -> Result<bool, String> {
    match s {
        "on" | "yes" | "true" => Ok(true),
        "off" | "no" | "false" => Ok(false),
        _ => Err("use on or off".into()),
    }
}

fn parse_size(s: &str) -> Result<(u32, u32), String> {
    if s == "auto" {
        return Ok((0, 0));
    }
    let (w, h) = s.split_once(['x', 'X']).ok_or("use WIDTHxHEIGHT, e.g. 1600x900, or auto")?;
    let n = |v: &str| v.trim().parse::<u32>().ok().filter(|v| (200..=8192).contains(v)).ok_or("each side 200 to 8192 pixels");
    Ok((n(w)?, n(h)?))
}

fn parse_scale(s: &str) -> Result<u32, String> {
    s.trim_end_matches('%').parse().ok().filter(|v| SCALES.contains(v)).ok_or_else(|| format!("use one of {SCALES:?}"))
}

fn parse_colors(s: &str) -> Result<u32, String> {
    s.parse().ok().filter(|v| COLORS.contains(v)).ok_or_else(|| format!("use one of {COLORS:?}"))
}

fn print_settings(s: &RdpSettings) {
    let yn = |b: bool| if b { "on" } else { "off" };
    let size = match s.window_size() {
        Some((w, h)) => format!("{w}x{h}"),
        None => "auto".into(),
    };
    let scale = if s.scale == 0 { "auto".into() } else { format!("{}%", s.scale) };
    println!("Display:        {} (window size {size}, on resize: {}, scale {scale}, {}-bit colour)", s.display.name(), s.resize.name(), s.colors);
    println!("Full screen:    connection bar {}, Windows keys go to: {}", yn(s.connection_bar), s.keys.name());
    println!(
        "Share:          clipboard {}, drives {}, printers {}, microphone {}, cameras {}, smart cards {}",
        yn(s.clipboard),
        yn(s.drives),
        yn(s.printers),
        yn(s.microphone),
        yn(s.cameras),
        yn(s.smart_cards)
    );
    println!("Sound:          {}", s.audio.name());
    println!(
        "Experience:     speed {}, wallpaper {}, font smoothing {}, visual effects {}, auto-reconnect {}",
        s.speed.name(),
        yn(s.wallpaper),
        yn(s.font_smoothing),
        yn(s.visual_effects),
        yn(s.auto_reconnect)
    );
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

struct Input {
    stdin_pass: bool,
    lines: std::io::StdinLock<'static>,
}

impl Input {
    fn line(&mut self, prompt: &str) -> client::Result<String> {
        print!("{prompt}");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        self.lines.read_line(&mut s).map_err(|e| e.to_string())?;
        Ok(s.trim().to_string())
    }

    fn secret(&mut self, prompt: &str) -> client::Result<Zeroizing<String>> {
        if self.stdin_pass {
            let mut s = String::new();
            self.lines.read_line(&mut s).map_err(|e| e.to_string())?;
            return Ok(Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string()));
        }
        rpassword::prompt_password(prompt).map(Zeroizing::new).map_err(|e| e.to_string())
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime")
}

fn run(cli: Cli) -> client::Result<()> {
    rdpgate_core::update::cleanup_previous();
    let dir = cli.dir.unwrap_or_else(client::default_dir);
    let mut input = Input { stdin_pass: cli.passphrase_stdin, lines: std::io::stdin().lock() };
    match cli.cmd {
        Cmd::Init { name, username, force } => {
            let pass = input.secret(&format!("Choose a passphrase for this computer's key (min {} chars): ", client::MIN_PASSPHRASE))?;
            if !input.stdin_pass {
                let again = input.secret("Repeat it: ")?;
                if *again != *pass {
                    return Err("passphrases do not match".into());
                }
            }
            let id = client::create_device(&dir, &name, username, &pass, force)?;
            println!("\nDevice key created in {}\n", dir.display());
            println!("On the server, run (as Administrator):\n\n    {}\n", id.enroll_command());
            println!("Fingerprint: {}  (the server prints it too; check they match)", id.fingerprint);
            println!("\nThen save the server card it prints:  rdpgate card rdpgate-card:...");
            Ok(())
        }
        Cmd::Card { card } => {
            let fp = client::set_card(&dir, &card)?;
            println!("Server card saved. Server key fingerprint: {fp}");
            println!("Check it matches \"Server key\" in rdpgate-server status.");
            Ok(())
        }
        Cmd::Connect { code, with_code, keep_signed_in, address, no_launch, follow } => {
            if keep_signed_in {
                client::set_keep_signed_in(&dir, true)?;
            }
            let mut cfg = client::load_config(&dir)?;
            client::card(&cfg)?;
            cfg.connect_override = address;
            let rt = runtime();
            let remembered = (code.is_none() && !with_code).then(|| client::trust::recall(&dir)).flatten();
            let (grant, key) = match remembered {
                Some(r) => {
                    println!("This computer is remembered: connecting without a passphrase or code.");
                    (rt.block_on(client::open(&dir, &cfg, &r.key, &r.token))?, r.key)
                }
                None => {
                    let pass = input.secret("Passphrase: ")?;
                    let key = client::unlock(&dir, &pass)?;
                    let code = match code {
                        Some(c) => c,
                        None => input.line("6-digit code: ")?,
                    };
                    let grant = rt.block_on(client::sign_in(&dir, &cfg, &key, &code))?;
                    if grant.remembered {
                        println!("You'll stay signed in: next time, rdpgate connect needs no passphrase or code.");
                    } else if let Some(why) = client::not_kept(&grant).filter(|_| cfg.keep_signed_in) {
                        println!("Couldn't keep you signed in: {why}");
                    }
                    (grant, key)
                }
            };
            println!(
                "Access open for {}: start Remote Desktop within {}. {}",
                grant.ip,
                client::minutes_left(grant.expires),
                grant.while_connected()
            );
            match rt.block_on(client::verify_rdp(&grant))? {
                RdpCheck::Verified => println!("Remote Desktop certificate verified: this is your computer."),
                RdpCheck::Unchecked(why) => println!("Warning: couldn't verify the Remote Desktop certificate ({why})."),
            }
            let file = client::write_rdp_file(&dir, &cfg, &grant)?;
            if no_launch {
                println!("Connect to {}  (connection file: {})", grant.rdp_target(), file.display());
            } else {
                client::launch_rdp(&file)?;
                if winpass::is_saved(&dir) && !winpass::fills_in() {
                    println!("Windows App can't take your saved Windows password: rdpgate password --copy, then paste it when asked.");
                }
            }
            // Once a day, quietly take a signed update (if enabled).
            if client::update_due(&cfg) {
                client::mark_update_checked(&dir);
                if let Ok(Some(av)) = client::check_update()
                    && client::install_update(&av, rdpgate_core::update::Component::Cli).is_ok()
                {
                    println!("rdpgate updated to {} (takes effect next time).", av.version);
                }
            }
            match grant.auto {
                _ if !follow => {}
                None => println!("This computer isn't remembered (rdpgate connect --keep-signed-in), so there's nothing to follow."),
                Some(_) => {
                    println!("Access moves with this computer the moment its IP address changes. Keep this running; Ctrl+C stops.");
                    let stop = std::sync::atomic::AtomicBool::new(false);
                    rt.block_on(client::keep_following(&dir, &cfg, &key, grant, &stop, |ev| match ev {
                        FollowEvent::Moved { grant, check, .. } => {
                            println!("This computer's address changed: access moved to {}.", grant.ip);
                            if let RdpCheck::Unchecked(why) = check {
                                println!("Warning: couldn't verify the Remote Desktop certificate ({why}).");
                            }
                        }
                        FollowEvent::Closed => println!("Access has closed. Run rdpgate connect again when you need it."),
                        FollowEvent::Ended(e) => println!("Auto mode ended: {e}"),
                    }));
                }
            }
            Ok(())
        }
        Cmd::Update { check } => {
            println!("Installed: {}", client::VERSION);
            client::mark_update_checked(&dir);
            let Some(av) = client::check_update()? else {
                println!("Up to date.");
                return Ok(());
            };
            println!("Available: {} (signature verified)  {}", av.version, av.url);
            if !check {
                client::install_update(&av, rdpgate_core::update::Component::Cli)?;
                println!("Updated rdpgate to {}.", av.version);
            }
            Ok(())
        }
        Cmd::AutoUpdate { state } => {
            client::set_auto_update(&dir, state == "on")?;
            println!("Automatic updates {state}.");
            Ok(())
        }
        Cmd::Lock => {
            let cfg = client::load_config(&dir)?;
            let key = match client::trust::recall(&dir) {
                Some(r) => r.key,
                None => client::unlock(&dir, &input.secret("Passphrase: ")?)?,
            };
            let ip = runtime().block_on(client::lock(&dir, &cfg, &key))?;
            println!("Access closed for {ip}.");
            Ok(())
        }
        Cmd::Forget => {
            client::set_keep_signed_in(&dir, false)?;
            println!("This computer is no longer remembered here. Next time, sign in with your passphrase and code.");
            println!("To forget it on the server too: rdpgate-server device-forget <name>");
            Ok(())
        }
        Cmd::Show => {
            let cfg = client::load_config(&dir)?;
            let id = client::identity(&dir)?;
            println!("Version:     {}{}", client::VERSION, if cfg.auto_update { " (auto-update on)" } else { " (auto-update off)" });
            println!("Device:      {}\nFingerprint: {}", id.device, id.fingerprint);
            let remembered = client::trust::is_remembered(&dir);
            println!("Remembered:  {}\n", if remembered { "yes (signed in: no passphrase or code needed)" } else { "no" });
            match client::card(&cfg) {
                Ok(card) => {
                    println!("Server key:  {}", rdpgate_core::wire::fingerprint(&card.server_key()));
                    println!("Found via:   {}{}", if card.gist.is_some() { "encrypted beacon" } else { "" },
                        card.host.as_deref().map(|h| format!(" host {h}")).unwrap_or_default());
                    if let Some(a) = cfg.last_known {
                        println!("Last seen:   {a}");
                    }
                }
                Err(_) => println!("Server:      no server card yet (rdpgate card <card>)"),
            }
            let saved = if winpass::is_saved(&dir) { format!(" (password saved in {})", winpass::store_name()) } else { String::new() };
            println!("Windows user: {}{saved}\n", cfg.rdp_username.as_deref().unwrap_or("(asked by Remote Desktop)"));
            print_settings(&cfg.rdp);
            println!("\nEnroll on the server with:\n\n    {}", id.enroll_command());
            Ok(())
        }
        Cmd::Settings(a) => {
            let cfg = client::load_config(&dir)?;
            let mut s = if a.reset { RdpSettings::default() } else { cfg.rdp.clone() };
            macro_rules! set {
                ($($f:ident),*) => { $(if let Some(v) = a.$f { s.$f = v; })* };
            }
            set!(display, resize, scale, colors, connection_bar, keys, clipboard, drives, printers, audio, microphone, cameras, smart_cards, speed, wallpaper, font_smoothing, visual_effects, auto_reconnect);
            if let Some((w, h)) = a.size {
                (s.width, s.height) = (w, h);
                if w != 0 && s.display != Display::Window {
                    println!("Note: the window size applies with --display window.");
                }
            }
            if s != cfg.rdp {
                client::set_rdp_settings(&dir, &s)?;
                println!("Saved. These apply the next time Remote Desktop opens:\n");
            }
            print_settings(&s);
            Ok(())
        }
        Cmd::Password { user, forget, copy } => {
            if forget {
                winpass::forget(&dir);
                println!("Saved Windows password forgotten. Remote Desktop asks for it again.");
                return Ok(());
            }
            if copy {
                winpass::copy_for_paste(&dir)?;
                println!("Copied. Paste it into Remote Desktop; the clipboard is cleared in 45 seconds.");
                return Ok(());
            }
            if !winpass::supported() {
                return Err("saving the Windows password isn't supported on this system yet".into());
            }
            let cfg = client::load_config(&dir)?;
            let user = match user.or(cfg.rdp_username) {
                Some(u) => u,
                None => input.line("Windows user: ")?,
            };
            let pass = input.secret(&format!("Windows password for {user}: "))?;
            if !input.stdin_pass && *input.secret("Repeat it: ")? != *pass {
                return Err("passwords do not match".into());
            }
            winpass::save(&dir, &user, &pass)?;
            println!("Saved in {} for {user}.", winpass::store_name());
            if winpass::fills_in() {
                println!("Remote Desktop now signs in with it. rdpgate password --forget removes it.");
            } else {
                println!("Windows App can't take a saved password, so it still asks: rdpgate password --copy copies it to paste.");
            }
            Ok(())
        }
    }
}
