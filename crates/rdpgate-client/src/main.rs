use clap::{Parser, Subcommand};
use rdpgate_client::{self as client, FollowEvent, RdpCheck};
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
    /// Sign in (passphrase + 6-digit code) and open Remote Desktop
    Connect {
        /// 6-digit code (prompted if omitted)
        #[arg(long)]
        code: Option<String>,
        /// Try this server address first, e.g. 203.0.113.7:443
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
    /// Show this computer's enrollment command and the pinned server
    Show,
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
        Cmd::Connect { code, address, no_launch, follow } => {
            let mut cfg = client::load_config(&dir)?;
            client::card(&cfg)?;
            cfg.connect_override = address;
            let pass = input.secret("Passphrase: ")?;
            let key = client::unlock(&dir, &pass)?;
            let code = match code {
                Some(c) => c,
                None => input.line("6-digit code: ")?,
            };
            let rt = runtime();
            let grant = rt.block_on(client::sign_in(&dir, &cfg, &key, &code))?;
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
                None => println!(
                    "Auto mode is off for this computer on the server (rdpgate-server device-auto {} on), so there's nothing to follow.",
                    cfg.device
                ),
                Some(_) => {
                    println!("Auto mode: access moves with this computer if its IP address changes. Keep this running; Ctrl+C stops.");
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
            let pass = input.secret("Passphrase: ")?;
            let key = client::unlock(&dir, &pass)?;
            let ip = runtime().block_on(client::lock(&dir, &cfg, &key))?;
            println!("Access closed for {ip}.");
            Ok(())
        }
        Cmd::Show => {
            let cfg = client::load_config(&dir)?;
            let id = client::identity(&dir)?;
            println!("Version:     {}{}", client::VERSION, if cfg.auto_update { " (auto-update on)" } else { " (auto-update off)" });
            println!("Device:      {}\nFingerprint: {}\n", id.device, id.fingerprint);
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
            println!("\nEnroll on the server with:\n\n    {}", id.enroll_command());
            Ok(())
        }
    }
}
