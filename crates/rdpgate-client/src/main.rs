use clap::{Parser, Subcommand};
use rdpgate_client::{self as client, RdpCheck};
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
    },
    /// Close the firewall for this network now
    Lock,
    /// Show this computer's enrollment command and the pinned server
    Show,
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
        Cmd::Connect { code, address, no_launch } => {
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
                "Access open for {}: start Remote Desktop within {} (it stays open while you're connected).",
                grant.ip,
                client::minutes_left(grant.expires)
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
            let id = client::identity(&dir)?;
            let cfg = client::load_config(&dir)?;
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
