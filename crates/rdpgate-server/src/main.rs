use clap::{Parser, Subcommand};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use rdpgate_core::{totp, wire};
use rdpgate_server::config::{BeaconConfig, Config, default_data_dir, valid_name};
use rdpgate_server::identity::Identity;
use rdpgate_server::log::local;
use rdpgate_server::state::{Device, EnrollToken, Store, TotpState, now, token_hash};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "rdpgate-server", version, about = "RDP Gate: opens Remote Desktop only for signed-in devices and passkeys")]
struct Cli {
    /// Data directory (default: C:\ProgramData\RDPGate on Windows)
    #[arg(long, global = true)]
    data: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once at startup
enum Cmd {
    /// Create the configuration and server identity (run once)
    Init {
        /// Optional DNS name for browser (passkey) sign-in, e.g. rdp.example.com.
        /// Without it, only the desktop app can sign in (found via the beacon).
        #[arg(long)]
        host: Option<String>,
        /// Port your router forwards to this agent
        #[arg(long, default_value_t = 443)]
        public_port: u16,
        /// Local listen address (repeatable; default 0.0.0.0:443)
        #[arg(long)]
        listen: Vec<String>,
        /// Browser portal certificate: "acme" (Let's Encrypt) or "files"
        #[arg(long, default_value = "acme")]
        tls: String,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        /// Email for Let's Encrypt expiry notices (optional)
        #[arg(long)]
        email: Option<String>,
        /// Use the Let's Encrypt staging CA (testing only)
        #[arg(long)]
        staging: bool,
        /// Local Remote Desktop port
        #[arg(long, default_value_t = 3389)]
        rdp_port: u16,
        /// External RDP port forwarded by the router (default: same as --rdp-port)
        #[arg(long)]
        rdp_public_port: Option<u16>,
        /// Also open UDP for signed-in addresses (faster, but UDP sources can be forged)
        #[arg(long)]
        allow_udp: bool,
        /// Name shown in your passkey manager
        #[arg(long, default_value = "owner")]
        user: String,
        /// "windows" or "dry-run"
        #[arg(long)]
        firewall: Option<String>,
        /// Overwrite an existing config.json (devices, passkeys and identity are kept)
        #[arg(long)]
        force: bool,
    },
    /// Publish this server's IP as an encrypted beacon in a secret GitHub gist
    BeaconSetup {
        /// Reuse an existing gist instead of creating one
        #[arg(long)]
        gist: Option<String>,
    },
    /// Print the server card to paste into RDP Gate on your computers
    Card,
    /// Run in the foreground (the Windows service does this for you)
    Run {
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Show configuration, identity, beacon and open firewall grants
    Status,
    /// Set up 6-digit codes for desktop sign-in (shows a QR code)
    TotpSetup {
        #[arg(long)]
        force: bool,
        /// Invert the QR code for terminals with a light background
        #[arg(long)]
        invert: bool,
    },
    /// Print a one-time link that adds a passkey (needs --host)
    PasskeyEnroll {
        #[arg(long, default_value_t = 15)]
        minutes: u32,
    },
    PasskeyList,
    PasskeyRemove { name: String },
    /// Enroll a computer (paste the line its RDP Gate app printed)
    DeviceAdd { name: String, public_key: String },
    DeviceList,
    /// Remove a computer; it can no longer sign in
    DeviceRemove { name: String },
    /// Unlock a computer that was locked after too many wrong codes
    DeviceUnlock { name: String },
    /// Register and start the Windows service (Administrator)
    ServiceInstall,
    /// Stop and remove the Windows service (Administrator)
    ServiceUninstall,
}

fn main() {
    let cli = Cli::parse();
    let data = cli.data.unwrap_or_else(default_data_dir);
    if let Err(e) = dispatch(cli.cmd, &data) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn print_card(cfg: &Config, id: &Identity) {
    println!("Server card (paste it into RDP Gate on each of your computers):\n");
    println!("{}\n", id.card(cfg).encode());
    println!("Server key fingerprint: {}", id.fingerprint());
    println!("Keep the card private: it lets a computer find this server's IP (it can't sign in by itself).");
    if cfg.beacon.is_none() && cfg.public_host.is_none() {
        println!("\nNote: no beacon or host name is set, so computers can't find this server yet.");
        println!("Run: rdpgate-server beacon-setup");
    }
}

fn dispatch(cmd: Cmd, data: &Path) -> Result<(), String> {
    match cmd {
        Cmd::Init {
            host, public_port, listen, tls, cert, key, email, staging, rdp_port, rdp_public_port,
            allow_udp, user, firewall, force,
        } => {
            // SYSTEM + Administrators only, even if someone created the folder first.
            rdpgate_server::secure_dir::harden(data)?;
            if Config::path(data).exists() && !force {
                return Err("config.json already exists (use --force to overwrite it)".into());
            }
            let mut c = Config::new(host.as_deref());
            c.public_port = public_port;
            if !listen.is_empty() {
                c.listen = listen;
            }
            c.tls.mode = tls;
            c.tls.cert_file = cert;
            c.tls.key_file = key;
            c.tls.email = email;
            c.tls.staging = staging;
            c.rdp_port = rdp_port;
            c.rdp_public_port = rdp_public_port.unwrap_or(rdp_port);
            c.allow_udp = allow_udp;
            if let Some(f) = firewall {
                c.firewall = f;
            }
            c.save(data)?;
            Store::new(data).init(&user)?;
            let id = Identity::load_or_create(data)?;
            println!("Wrote {}", Config::path(data).display());
            println!("Server key fingerprint: {}", id.fingerprint());
            if let Some(url) = c.portal_url("") {
                println!("Browser sign-in page: {url}");
            }
            println!("\nNext: beacon-setup (so your computers can find this PC), totp-setup, then device-add for each computer.");
            Ok(())
        }
        Cmd::BeaconSetup { gist } => {
            let mut cfg = Config::load(data)?;
            println!("Create a GitHub token at https://github.com/settings/personal-access-tokens/new");
            println!("with Account permissions > Gists: Read and write (nothing else).\n");
            let token = Zeroizing::new(rpassword::prompt_password("GitHub token: ").map_err(|e| e.to_string())?);
            let token = token.trim().to_string();
            if token.is_empty() {
                return Err("no token entered".into());
            }
            let gist_id = match gist {
                Some(g) if rdpgate_core::beacon::valid_gist_id(&g) => g,
                Some(_) => return Err("that doesn't look like a gist id".into()),
                None => rdpgate_core::beacon::create_gist(&token)?,
            };
            cfg.beacon = Some(BeaconConfig { gist_id: gist_id.clone(), token });
            let id = Identity::load_or_create(data)?;
            print!("Finding this network's public IP… ");
            std::io::stdout().flush().ok();
            let ip = rdpgate_server::beacon::discover_public_ip()?;
            println!("{ip}");
            rdpgate_server::beacon::publish(&cfg, &id, ip)?;
            cfg.save(data)?;
            println!("Encrypted beacon published to secret gist {gist_id}.");
            println!("Restart the service to keep it updated: Restart-Service RDPGate\n");
            print_card(&cfg, &id);
            Ok(())
        }
        Cmd::Card => {
            let cfg = Config::load(data)?;
            let id = Identity::load_or_create(data)?;
            print_card(&cfg, &id);
            Ok(())
        }
        Cmd::Run { service } => {
            if service {
                return rdpgate_server::service::run_as_service(data.to_path_buf());
            }
            let (tx, rx) = tokio::sync::watch::channel(false);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async {
                    let _ = tokio::signal::ctrl_c().await;
                });
                let _ = tx.send(true);
            });
            rdpgate_server::run_server(data, true, rx)
        }
        Cmd::Status => status(data),
        Cmd::TotpSetup { force, invert } => totp_setup(data, force, invert),
        Cmd::PasskeyEnroll { minutes } => {
            if !(1..=60).contains(&minutes) {
                return Err("--minutes must be 1-60".into());
            }
            let cfg = Config::load(data)?;
            let Some(url) = cfg.portal_url("enroll").filter(|_| cfg.web_login) else {
                return Err("browser sign-in needs a DNS name: run init --force --host rdp.example.com".into());
            };
            let token = rdpgate_core::random_token::<24>();
            let expires = now() + minutes as i64 * 60;
            Store::new(data).update(|st| {
                st.enroll_tokens.retain(|t| t.expires > now());
                st.enroll_tokens.push(EnrollToken { hash: token_hash(&token), expires });
                Ok(())
            })?;
            println!("Open this link on the device whose passkey you want to add.");
            println!("It works once, until {}:\n", local(expires));
            println!("    {url}#{token}\n");
            println!("Treat it like a password. The service must be running and reachable for the page to load.");
            Ok(())
        }
        Cmd::PasskeyList => {
            let st = Store::new(data).load()?;
            if st.passkeys.is_empty() {
                println!("No passkeys. Add one with: rdpgate-server passkey-enroll");
            }
            for p in &st.passkeys {
                println!("{:<24} added {}  last used {}", p.name, local(p.added), p.last_used.map(local).unwrap_or("never".into()));
            }
            Ok(())
        }
        Cmd::PasskeyRemove { name } => Store::new(data).update(|st| {
            let before = st.passkeys.len();
            st.passkeys.retain(|p| p.name != name);
            if st.passkeys.len() == before {
                return Err(format!("no passkey named {name:?}"));
            }
            println!("Removed passkey {name:?}.");
            Ok(())
        }),
        Cmd::DeviceAdd { name, public_key } => {
            if !valid_name(&name) {
                return Err("device name: 1-32 letters, digits, dots, dashes or underscores".into());
            }
            let key = wire::parse_public_key(&public_key)?;
            let encoded = wire::encode_public_key(&key);
            let cfg = Config::load(data)?;
            Store::new(data).update(|st| {
                if st.devices.iter().any(|d| d.name == name) {
                    return Err(format!("a device named {name:?} already exists"));
                }
                if let Some(d) = st.devices.iter().find(|d| d.public_key == encoded) {
                    return Err(format!("that key is already enrolled as {:?}", d.name));
                }
                st.devices.push(Device { name: name.clone(), public_key: encoded.clone(), added: now(), last_auth: None, failed_codes: 0 });
                Ok(())
            })?;
            println!("Enrolled {name:?}. Device fingerprint: {}", wire::fingerprint(&key));
            println!("Check it matches the fingerprint shown on that computer.\n");
            print_card(&cfg, &Identity::load_or_create(data)?);
            Ok(())
        }
        Cmd::DeviceList => {
            let st = Store::new(data).load()?;
            if st.devices.is_empty() {
                println!("No devices. Set up the RDP Gate app on a computer, then run device-add here.");
            }
            for d in &st.devices {
                let fp = wire::parse_public_key(&d.public_key).map(|k| wire::fingerprint(&k)).unwrap_or_default();
                let locked = if d.failed_codes >= rdpgate_server::state::MAX_FAILED_CODES { "  LOCKED (device-unlock)" } else { "" };
                println!("{:<20} {fp}  added {}  last sign-in {}{locked}", d.name, local(d.added), d.last_auth.map(local).unwrap_or("never".into()));
            }
            Ok(())
        }
        Cmd::DeviceRemove { name } => Store::new(data).update(|st| {
            let before = st.devices.len();
            st.devices.retain(|d| d.name != name);
            if st.devices.len() == before {
                return Err(format!("no device named {name:?}"));
            }
            println!("Removed {name:?}. It can no longer sign in. (Open grants close on their normal schedule.)");
            Ok(())
        }),
        Cmd::DeviceUnlock { name } => Store::new(data).update(|st| {
            let d = st.devices.iter_mut().find(|d| d.name == name).ok_or(format!("no device named {name:?}"))?;
            d.failed_codes = 0;
            println!("Unlocked {name:?}.");
            Ok(())
        }),
        Cmd::ServiceInstall => {
            Config::load(data)?;
            rdpgate_server::service::install(data)?;
            println!("Service \"RDPGate\" installed and started.");
            Ok(())
        }
        Cmd::ServiceUninstall => {
            rdpgate_server::service::uninstall()?;
            println!("Service \"RDPGate\" removed.");
            Ok(())
        }
    }
}

fn status(data: &Path) -> Result<(), String> {
    let cfg = Config::load(data)?;
    let st = Store::new(data).load()?;
    let id = Identity::load_or_create(data)?;
    println!("Server key:     {}", id.fingerprint());
    println!("Listen:         {}", cfg.listen.join(", "));
    println!("RDP port:       {} (clients connect to {}){}", cfg.rdp_port, cfg.rdp_public_port, if cfg.allow_udp { ", UDP on" } else { ", TCP only" });
    if cfg.allow_private_sources {
        println!("                private source addresses are allowed (LAN sign-in)");
    }
    println!("Firewall:       {}", cfg.firewall);
    match &cfg.beacon {
        Some(b) => {
            let s: serde_json::Value = std::fs::read(data.join("beacon.json"))
                .ok()
                .and_then(|r| serde_json::from_slice(&r).ok())
                .unwrap_or_default();
            println!("Beacon:         gist {} (last IP {}, published {})", b.gist_id, s["ip"].as_str().unwrap_or("?"),
                s["published"].as_i64().map(local).unwrap_or_else(|| "not yet".into()));
            if let Some(e) = s["error"].as_str() {
                println!("                last error: {e}");
            }
        }
        None => println!("Beacon:         off (rdpgate-server beacon-setup)"),
    }
    match cfg.portal_url("") {
        Some(url) if cfg.web_login => println!("Browser login:  {url}"),
        _ => println!("Browser login:  off (needs a DNS name)"),
    }
    println!("Desktop login:  {}", if cfg.desktop_login { "on" } else { "off" });
    println!("Grant window:   {} min, max {} h", cfg.grant_minutes, cfg.max_hours);
    println!("6-digit codes:  {}", if st.totp.is_some() { "set up" } else { "not set up (totp-setup)" });
    println!("Passkeys:       {}", st.passkeys.len());
    println!("Devices:        {}", st.devices.len());
    let grants: Vec<serde_json::Value> = std::fs::read(data.join("grants.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let warnings: Vec<String> = std::fs::read(data.join("warnings.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    for w in &warnings {
        println!("WARNING:        {w}");
    }
    println!("\nOpen firewall grants: {}", grants.len());
    for g in grants {
        println!(
            "  {:<40} {:<24} until {}",
            g["ip"].as_str().unwrap_or("?"),
            g["who"].as_str().unwrap_or("?"),
            local(g["expires"].as_i64().unwrap_or(0))
        );
    }
    Ok(())
}

fn totp_setup(data: &Path, force: bool, invert: bool) -> Result<(), String> {
    let store = Store::new(data);
    let st = store.load()?;
    if st.totp.is_some() && !force {
        return Err("6-digit codes are already set up (use --force to replace; old codes stop working)".into());
    }
    let secret = totp::new_secret();
    let account = format!("{}@{}", st.user_name, Identity::load_or_create(data)?.fingerprint().get(..9).unwrap_or("server"));
    let uri = totp::uri("RDP Gate", &account, &secret);
    let qr = QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    // Terminals usually draw light text on a dark background, so by default the
    // "dark" modules are drawn as background and vice versa.
    let (dark, light) = if invert { (Dense1x2::Dark, Dense1x2::Light) } else { (Dense1x2::Light, Dense1x2::Dark) };
    println!("\n{}", qr.render::<Dense1x2>().dark_color(dark).light_color(light).quiet_zone(true).build());
    let b32 = totp::base32(&secret);
    let grouped: Vec<String> = b32.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into()).collect();
    println!("Scan it with your authenticator app, or type this key:\n\n    {}\n", grouped.join(" "));
    println!("Don't photograph or screenshot it: anyone with this key can generate your codes.");
    let stdin = std::io::stdin();
    for _ in 0..3 {
        print!("\nEnter the 6-digit code your app shows now: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("no input".into());
        }
        let Some(step) = totp::validate(&secret, line.trim(), now() as u64, 0) else {
            println!("That code doesn't match. Make sure the phone sets its clock automatically.");
            continue;
        };
        let secret = secret.clone();
        store.update(|st| {
            st.totp = Some(TotpState { secret, last_step: step });
            Ok(())
        })?;
        println!("6-digit codes enabled.");
        return Ok(());
    }
    Err("6-digit codes were not enabled".into())
}
