use clap::{Parser, Subcommand};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use rdpgate_server::admin;
use rdpgate_server::config::{Config, default_data_dir};
use rdpgate_server::identity::Identity;
use rdpgate_server::log::local;
use rdpgate_server::state::Store;
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
        /// Port your router forwards to this agent (never 80 or 443)
        #[arg(long, default_value_t = rdpgate_server::config::DEFAULT_PORT)]
        public_port: u16,
        /// Local listen address (repeatable; default 0.0.0.0:47443)
        #[arg(long)]
        listen: Vec<String>,
        /// Certificate for --host, PEM (turns browser sign-in on, with --key)
        #[arg(long, requires_all = ["host", "key"])]
        cert: Option<PathBuf>,
        /// Private key for --cert, PEM
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// Local Remote Desktop port
        #[arg(long, default_value_t = 3389)]
        rdp_port: u16,
        /// External RDP port forwarded by the router (default: same as --rdp-port)
        #[arg(long)]
        rdp_public_port: Option<u16>,
        /// Also open UDP for signed-in addresses (faster, but UDP sources can be forged)
        #[arg(long)]
        allow_udp: bool,
        /// Don't forward ports on the router automatically (UPnP)
        #[arg(long)]
        no_upnp: bool,
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
    /// Allow ("on") or refuse ("off") sign-in from computers on this PC's own
    /// network, e.g. your laptop on the same Wi-Fi
    Lan {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Forward the needed ports on the router now (UPnP) and report
    Router {
        /// Remove the forwards RDP Gate made instead (used when uninstalling)
        #[arg(long)]
        remove: bool,
    },
    /// Run in the foreground (the Windows service does this for you)
    Run {
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Show configuration, identity, beacon and open firewall grants
    Status,
    /// Close Remote Desktop to everyone who hasn't signed in (Administrator).
    /// Drops Remote Desktop sessions that didn't come through RDP Gate.
    Protect {
        /// Don't do it now: let the service do it once someone has signed in
        /// through RDP Gate and connected (safe while installing over RDP)
        #[arg(long)]
        after_sign_in: bool,
        /// Don't ask before disconnecting this Remote Desktop session
        #[arg(long)]
        yes: bool,
        /// Only record that Setup has already locked Remote Desktop down
        #[arg(long, hide = true)]
        already_applied: bool,
    },
    /// Set up 6-digit codes for desktop sign-in (shows a QR code)
    TotpSetup {
        #[arg(long)]
        force: bool,
        /// Invert the QR code for terminals with a light background
        #[arg(long)]
        invert: bool,
    },
    /// Guided setup for browser (passkey) sign-in with your own domain name:
    /// DNS record, a live check, certificate, and the first passkey
    DomainSetup {
        /// Domain name, e.g. rdp.example.com (asked if not given)
        #[arg(long)]
        host: Option<String>,
        /// Certificate covering the domain, PEM (asked if not given)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Its private key, PEM (asked if not given)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Turn browser sign-in off again
        #[arg(long)]
        remove: bool,
    },
    /// Print a one-time link that adds a passkey (needs domain-setup first)
    PasskeyEnroll {
        #[arg(long, default_value_t = 15)]
        minutes: u32,
    },
    PasskeyList,
    PasskeyRemove { name: String },
    /// Enroll a computer (paste the line its RDP Gate app printed)
    DeviceAdd {
        name: String,
        /// The computer's key (rdpgate-ed25519:…); asked for if left out
        public_key: Option<String>,
    },
    DeviceList,
    /// Remove a computer; it can no longer sign in
    DeviceRemove { name: String },
    /// Unlock a computer that was locked after too many wrong codes
    DeviceUnlock { name: String },
    /// Auto mode for a computer: after one sign-in with passphrase and code
    /// it is remembered and connects with no passphrase or code until its
    /// hardware changes, and its access follows it when its IP changes.
    /// "off" forgets it
    DeviceAuto {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Stop remembering a computer (auto mode or "Keep me signed in"): it
    /// signs in with passphrase and code again
    DeviceForget { name: String },
    /// Let computers stay signed in when the person signing in ticks "Keep me
    /// signed in" in the app ("on", the default), or not ("off" also forgets
    /// every computer kept signed in that isn't in auto mode)
    KeepSignedIn {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Check for and install a signed update, then restart the service
    Update {
        /// Only check; don't install
        #[arg(long)]
        check: bool,
    },
    /// Register and start the Windows service (Administrator)
    ServiceInstall,
    /// Stop and remove the Windows service (Administrator)
    ServiceUninstall,
    /// Start the service if it is stopped (Administrator)
    ServiceStart,
    /// Start the service if it is stopped (run by the scheduled watchdog task)
    #[command(hide = true)]
    ServiceWatchdog,
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
            host, public_port, listen, cert, key, rdp_port, rdp_public_port,
            allow_udp, no_upnp, user, firewall, force,
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
            if let (Some(cert), Some(key)) = (cert, key) {
                let (cert, key) = (std::path::absolute(cert).map_err(|e| e.to_string())?, std::path::absolute(key).map_err(|e| e.to_string())?);
                rdpgate_server::cert::read(&cert, &key, c.public_host.as_deref())?;
                c.tls.cert_file = Some(cert);
                c.tls.key_file = Some(key);
                c.web_login = true;
            }
            c.rdp_port = rdp_port;
            c.rdp_public_port = rdp_public_port.unwrap_or(rdp_port);
            c.allow_udp = allow_udp;
            c.upnp = !no_upnp;
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
            Config::load(data)?;
            println!("Create a GitHub token at https://github.com/settings/personal-access-tokens/new");
            println!("with Account permissions > Gists: Read and write (nothing else).\n");
            let token = Zeroizing::new(rpassword::prompt_password("GitHub token: ").map_err(|e| e.to_string())?);
            println!("Publishing the first beacon…");
            let gist_id = admin::beacon_setup(data, &token, gist.as_deref())?;
            println!("Encrypted beacon published to secret gist {gist_id}.");
            println!("Restart the service to keep it updated: Restart-Service RDPGate\n");
            print_card(&Config::load(data)?, &Identity::load_or_create(data)?);
            Ok(())
        }
        Cmd::Lan { state } => {
            let on = state == "on";
            let lan_ip = admin::set_lan(data, on)?;
            if on {
                match lan_ip {
                    Some(ip) => println!("Computers on this network can sign in. They reach this PC at {ip} (published in the encrypted beacon)."),
                    None => println!("Sign-in from this network allowed, but this PC has no private network address right now."),
                }
                println!("Give this PC a reserved address in your router's DHCP settings so that address stays the same.");
            } else {
                println!("Sign-in from this PC's own network is off.");
            }
            if rdpgate_server::service::restart().is_ok() {
                println!("Service restarted.");
            }
            Ok(())
        }
        Cmd::Router { remove: true } => {
            for line in rdpgate_server::router::remove() {
                println!("{line}");
            }
            Ok(())
        }
        Cmd::Router { remove: false } => {
            let cfg = Config::load(data)?;
            let st = rdpgate_server::router::apply(&cfg);
            for line in st.summary(&cfg) {
                println!("{line}");
            }
            if !st.all_mapped() {
                // Distinct exit code so the installer knows to show manual steps.
                std::process::exit(2);
            }
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
            match rdpgate_server::run_server(data, true, rx)? {
                rdpgate_server::app::Exit::Restart => println!("Updated. Start it again to run the new version."),
                rdpgate_server::app::Exit::Stopped => {}
            }
            Ok(())
        }
        Cmd::Update { check } => {
            let pre = Config::load(data).map(|c| c.update_prereleases).unwrap_or(true);
            let current = rdpgate_server::updater::VERSION;
            println!("Installed: {current}");
            let Some(av) = rdpgate_core::update::check(current, pre)? else {
                println!("Up to date.");
                return Ok(());
            };
            println!("Available: {} (signature verified)  {}", av.version, av.url);
            if check {
                return Ok(());
            }
            rdpgate_server::updater::install(&av)?;
            println!("Installed {}.", av.version);
            match rdpgate_server::service::restart() {
                Ok(()) => println!("Service restarted on the new version."),
                Err(e) => println!("Restart the service to finish ({e})."),
            }
            Ok(())
        }
        Cmd::Status => status(data),
        Cmd::Protect { after_sign_in, yes, already_applied } => protect(data, after_sign_in, yes, already_applied),
        Cmd::TotpSetup { force, invert } => totp_setup(data, force, invert),
        Cmd::PasskeyEnroll { minutes } => passkey_enroll(data, minutes),
        Cmd::DomainSetup { host, cert, key, remove } => domain_setup(data, host, cert, key, remove),
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
        Cmd::PasskeyRemove { name } => {
            admin::remove_passkey(data, &name)?;
            println!("Removed passkey {name:?}.");
            Ok(())
        }
        Cmd::DeviceAdd { name, public_key } => {
            let public_key = match public_key {
                Some(k) => k,
                // The command often arrives split over two lines; then
                // PowerShell runs the first line alone, and when both were
                // pasted together the second line answers this prompt.
                None => ask("Paste this computer's key (rdpgate-ed25519:…), shown in its RDP Gate app: ")?
                    .ok_or("no key entered")?,
            };
            let fingerprint = admin::add_device(data, &name, &public_key)?;
            println!("Enrolled {name:?}. Device fingerprint: {fingerprint}");
            println!("Check it matches the fingerprint shown on that computer.\n");
            print_card(&Config::load(data)?, &Identity::load_or_create(data)?);
            Ok(())
        }
        Cmd::DeviceList => {
            let devices = admin::devices(data)?;
            if devices.is_empty() {
                println!("No devices. Set up the RDP Gate app on a computer, then run device-add here.");
            }
            for d in &devices {
                let locked = if d.locked { "  LOCKED (device-unlock)" } else { "" };
                let auto = match (d.auto, d.remembered) {
                    (true, Some(t)) => format!("  auto mode, remembered since {}", local(t)),
                    (true, None) => "  auto mode (not remembered yet)".into(),
                    (false, Some(t)) => format!("  kept signed in since {}", local(t)),
                    (false, None) => String::new(),
                };
                println!(
                    "{:<20} {}  added {}  last sign-in {}{auto}{locked}",
                    d.name,
                    d.fingerprint,
                    local(d.added),
                    admin::when(d.last_auth)
                );
            }
            Ok(())
        }
        Cmd::DeviceRemove { name } => {
            admin::remove_device(data, &name)?;
            println!("Removed {name:?}. It can no longer sign in. (Open grants close on their normal schedule.)");
            Ok(())
        }
        Cmd::DeviceUnlock { name } => {
            admin::unlock_device(data, &name)?;
            println!("Unlocked {name:?}.");
            Ok(())
        }
        Cmd::DeviceAuto { name, state } => {
            admin::set_device_auto(data, &name, state == "on")?;
            if state == "on" {
                println!("Auto mode on for {name:?}. After its next sign-in with passphrase and code it is remembered.");
            } else {
                println!("Auto mode off for {name:?}. It is forgotten and signs in with passphrase and code again.");
            }
            Ok(())
        }
        Cmd::DeviceForget { name } => {
            admin::forget_device(data, &name)?;
            println!("Forgot {name:?}. It signs in with passphrase and code again.");
            Ok(())
        }
        Cmd::KeepSignedIn { state } => {
            admin::set_keep_signed_in(data, state == "on")?;
            if state == "on" {
                println!("Computers can stay signed in: \"Keep me signed in\" in the app remembers a computer until its hardware changes.");
            } else {
                println!("Staying signed in is off. Only computers in auto mode are remembered; the others sign in with passphrase and code again.");
            }
            Ok(())
        }
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
        Cmd::ServiceStart => {
            if rdpgate_server::service::ensure_running()? {
                println!("Service \"RDPGate\" is starting.");
            } else {
                println!("Service \"RDPGate\" was already running.");
            }
            Ok(())
        }
        Cmd::ServiceWatchdog => {
            if rdpgate_server::service::ensure_running()? {
                let _ = rdpgate_server::log::init(Some(data.join("logs")), false);
                rdpgate_server::logln!("WATCHDOG the service was stopped; started it again");
            }
            Ok(())
        }
    }
}

fn passkey_enroll(data: &Path, minutes: u32) -> Result<(), String> {
    let (link, expires) = admin::passkey_link(data, minutes)?;
    println!("Open this link on the device whose passkey you want to add.");
    println!("It works once, until {}:\n", local(expires));
    println!("    {link}\n");
    println!("Treat it like a password. The service must be running and reachable for the page to load.");
    Ok(())
}

/// Reads one line; `None` at end of input.
fn ask(prompt: &str) -> Result<Option<String>, String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

fn yes_no(prompt: &str, default: bool) -> Result<bool, String> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    Ok(match ask(&format!("{prompt} {hint} "))?.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("y" | "yes") => true,
        Some("n" | "no") => false,
        _ => default,
    })
}

fn domain_setup(data: &Path, host: Option<String>, cert: Option<PathBuf>, key: Option<PathBuf>, remove: bool) -> Result<(), String> {
    let mut cfg = Config::load(data)?;
    if remove {
        cfg.web_login = false;
        cfg.public_host = None;
        cfg.save(data)?;
        restart_service(data)?;
        println!("Browser sign-in is off. Passkeys are kept and work again if you set the same domain up later.");
        return Ok(());
    }

    println!("Browser sign-in with a passkey: guided setup");
    println!("============================================\n");
    println!("Browsers only use passkeys with a domain name, never an IP address. You need:");
    println!("  - a domain you control, e.g. example.com (from any registrar, or Cloudflare);");
    println!("  - a name under it for this PC, e.g. rdp.example.com, with DNS records (A, and AAAA for IPv6)");
    println!("    pointing at your home's public addresses;");
    println!("  - if your home IP changes, dynamic DNS to keep that record current (most registrars and");
    println!("    routers have it built in: look for \"DDNS\" or \"Dynamic DNS\");");
    println!("  - a certificate for that name, as PEM files you renew (see step 3);");
    println!("  - port {} on your router reaching this PC (already done for the app).", cfg.public_port);
    println!("The desktop app doesn't need any of this.\n");

    // ---- 1. domain
    println!("Step 1 of 4: domain name");
    let host = match host {
        Some(h) => h,
        None => {
            let current = cfg.public_host.clone().unwrap_or_default();
            let prompt = if current.is_empty() {
                "  Domain name for this PC (e.g. rdp.example.com): ".to_string()
            } else {
                format!("  Domain name for this PC [{current}]: ")
            };
            match ask(&prompt)? {
                Some(h) if !h.is_empty() => h,
                _ if !current.is_empty() => current,
                _ => return Err("no domain name entered".into()),
            }
        }
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if !rdpgate_server::config::valid_host(&host) {
        return Err(format!("{host:?} isn't a domain name like rdp.example.com"));
    }

    // ---- 2. DNS
    println!("\nStep 2 of 4: DNS records");
    print!("  Finding this network's public addresses… ");
    std::io::stdout().flush().ok();
    let (records, public) = admin::dns_records(data, &host)?;
    println!("{}\n", public.describe());
    println!("  At your DNS provider, create (or update) {}:\n", if records.len() > 1 { "these records" } else { "this record" });
    println!("      Type   Name                         Value                                    TTL");
    for r in &records {
        println!("      {:<6} {:<28} {:<40} 300 (or Auto)", r.kind, format!("{}  (= {host})", r.name), r.value);
    }
    println!("\n  Most providers want only the part before your domain in Name (\"{}\").", records[0].name);
    println!("  Cloudflare: set Proxy status to \"DNS only\" (grey cloud). The proxy would hide this PC.");
    loop {
        let (ok, lines) = admin::dns_verdict(&host, &public, &admin::resolve_host(&host));
        for (finding, line) in &lines {
            let mark = match finding {
                admin::Finding::Good => "✓",
                admin::Finding::Hint => "·",
                admin::Finding::Wrong => "✗",
            };
            println!("  {mark} {line}");
        }
        if ok {
            break;
        }
        match ask("  Press Enter to check again, or type \"skip\" to continue anyway: ")? {
            Some(a) if a.eq_ignore_ascii_case("skip") => {
                println!("  Continuing. Sign-in and the certificate only work once the records are right.");
                break;
            }
            None => return Err("cancelled; nothing was changed".into()),
            _ => {}
        }
    }

    // ---- 3. certificate
    println!("\nStep 3 of 4: certificate");
    println!("  Browsers need a certificate for {host} from a public authority. RDP Gate doesn't fetch one");
    println!("  itself: Let's Encrypt only checks ports 80 and 443, which RDP Gate never uses. Get one with a");
    println!("  DNS check instead (win-acme, or certbot with your DNS provider's plugin), and enter its files.");
    println!("  Renewed files are picked up within an hour.");
    let file = |given: Option<PathBuf>, what: &str, current: Option<&Path>| -> Result<String, String> {
        if let Some(p) = given {
            return Ok(p.display().to_string());
        }
        let current = current.map(|p| p.display().to_string()).unwrap_or_default();
        let prompt = if current.is_empty() { format!("  {what}: ") } else { format!("  {what} [{current}]: ") };
        match ask(&prompt)? {
            Some(p) if !p.is_empty() => Ok(p),
            Some(_) if !current.is_empty() => Ok(current),
            _ => Err("no certificate file entered; nothing was changed".into()),
        }
    };
    let cert = file(cert, "Certificate file (PEM, full chain)", cfg.tls.cert_file.as_deref())?;
    let key = file(key, "Private key file (PEM)", cfg.tls.key_file.as_deref())?;

    // ---- 4. save
    println!("\nStep 4 of 4: turning browser sign-in on");
    if cfg.public_host.as_deref().is_some_and(|h| h != host) {
        println!("  ! The domain changes, so passkeys made for the old one stop working. Add new ones below.");
    }
    let url = admin::domain_on(data, &host, &cert, &key)?;
    restart_service(data)?;
    println!("\n  Your sign-in page (bookmark the FULL address on each device; the domain alone shows nothing):\n");
    println!("      {url}\n");
    println!("  Test it from outside your network, e.g. a phone on mobile data: many routers can't");
    println!("  reach their own public address from inside.\n");

    if Store::new(data).load()?.passkeys.is_empty() {
        if yes_no("Create a link to add your first passkey now?", true)? {
            println!();
            passkey_enroll(data, 15)?;
        } else {
            println!("Add one later with: rdpgate-server passkey-enroll");
        }
    } else {
        println!("Add more passkeys with: rdpgate-server passkey-enroll");
    }
    Ok(())
}

/// Restarts the service to apply new settings. Restarting closes every open
/// grant, which drops Remote Desktop sessions that came through RDP Gate,
/// so it asks first while anyone has access open.
fn restart_service(data: &Path) -> Result<(), String> {
    let open = std::fs::read(data.join("grants.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
        .map_or(0, |g| g.len());
    if open > 0 {
        println!("  Access is open right now ({open} address(es), probably including yours). Restarting the");
        println!("  service closes it and disconnects Remote Desktop sessions that came through RDP Gate.");
        if !yes_no("  Restart now?", false)? {
            println!("  Not restarted. The new settings apply at the next restart: Restart-Service RDPGate");
            return Ok(());
        }
    }
    match rdpgate_server::service::restart() {
        Ok(()) => println!("  Service restarted with the new settings."),
        Err(e) => println!("  Restart the service to apply the settings: Restart-Service RDPGate ({e})"),
    }
    Ok(())
}

fn protect(data: &Path, after_sign_in: bool, yes: bool, already_applied: bool) -> Result<(), String> {
    let cfg = Config::load(data)?;
    let store = Store::new(data);
    if after_sign_in || already_applied {
        rdpgate_server::protect::set_pending(&store, after_sign_in)?;
        if after_sign_in {
            println!("Protection is pending. Remote Desktop stays reachable as it is now until a computer signs in");
            println!("through RDP Gate and connects; then the service closes it to everyone else by itself.");
            println!("To do it sooner: rdpgate-server protect");
        }
        return Ok(());
    }
    // SESSIONNAME is RDP-Tcp#N inside a Remote Desktop session.
    let over_rdp = std::env::var("SESSIONNAME").is_ok_and(|s| s.to_ascii_uppercase().starts_with("RDP-TCP"));
    if over_rdp && !yes {
        println!("You are connected over Remote Desktop. Turning protection on disconnects every session that");
        println!("didn't come through RDP Gate, including this one unless you signed in through RDP Gate first.");
        print!("Continue? [y/N] ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
        if !line.trim().eq_ignore_ascii_case("y") {
            return Err("cancelled; nothing was changed".into());
        }
    }
    println!("Locking Remote Desktop behind RDP Gate (this can take a minute)…");
    let fw = rdpgate_server::firewall::for_config(&cfg);
    let disabled = rdpgate_server::protect::apply(&*fw, &store)?;
    for r in &disabled {
        println!("  disabled firewall rule: {r}");
    }
    println!("Protection is on: Remote Desktop opens only for addresses that sign in through RDP Gate.");
    Ok(())
}

fn status(data: &Path) -> Result<(), String> {
    let cfg = Config::load(data)?;
    let st = Store::new(data).load()?;
    let id = Identity::load_or_create(data)?;
    println!("Version:        {}{}", rdpgate_server::updater::VERSION, if cfg.auto_update { " (auto-update on)" } else { " (auto-update off)" });
    println!("Server key:     {}", id.fingerprint());
    println!("Listen:         {}", cfg.listen.join(", "));
    println!("RDP port:       {} (clients connect to {}){}", cfg.rdp_port, cfg.rdp_public_port, if cfg.allow_udp { ", UDP on" } else { ", TCP only" });
    if cfg.allow_private_sources {
        println!("                private source addresses are allowed (LAN sign-in)");
    }
    println!("Firewall:       {}", cfg.firewall);
    if st.protection_pending {
        println!("Protection:     PENDING: Remote Desktop is reachable without RDP Gate until a computer signs in");
        println!("                and connects through it (or run: rdpgate-server protect)");
    } else {
        println!("Protection:     on");
    }
    match &cfg.beacon {
        Some(b) => {
            let s: serde_json::Value = std::fs::read(data.join("beacon.json"))
                .ok()
                .and_then(|r| serde_json::from_slice(&r).ok())
                .unwrap_or_default();
            let ips: Vec<&str> = [s["ip"].as_str(), s["ip6"].as_str()].into_iter().flatten().collect();
            let ips = if ips.is_empty() { "?".to_string() } else { ips.join(" and ") };
            println!("Beacon:         gist {} (last IP {ips}, published {})", b.gist_id,
                s["published"].as_i64().map(local).unwrap_or_else(|| "not yet".into()));
            if let Some(e) = s["error"].as_str() {
                println!("                last error: {e}");
            }
        }
        None => println!("Beacon:         off (rdpgate-server beacon-setup)"),
    }
    let router: serde_json::Value = std::fs::read(data.join("router.json"))
        .ok()
        .and_then(|r| serde_json::from_slice(&r).ok())
        .unwrap_or_default();
    match (cfg.upnp, router["found"].as_bool()) {
        (false, _) => println!("Router:         automatic forwarding off (forward ports by hand)"),
        (true, None) => println!("Router:         not checked yet"),
        (true, Some(false)) => println!("Router:         no UPnP router found; forward ports by hand"),
        (true, Some(true)) => {
            let n = router["mapped"].as_array().map_or(0, |a| a.len());
            println!("Router:         {n} port forward(s) in place via UPnP{}",
                if router["failed"].as_array().is_some_and(|a| !a.is_empty()) { ", some refused" } else { "" });
            if router["behind_nat"].as_bool() == Some(true) {
                println!("WARNING:        the router's internet address isn't public (carrier-grade NAT?): run rdpgate-server router");
            }
        }
    }
    match cfg.portal_url("") {
        Some(url) if cfg.web_login => println!("Browser login:  {url}"),
        _ => println!("Browser login:  off (needs a DNS name)"),
    }
    println!("Desktop login:  {}", if cfg.desktop_login { "on" } else { "off" });
    println!("IPv6:           {}", if cfg.ipv6 { "on (sign-in over IPv6, address in the beacon)" } else { "off" });
    println!("Grant window:   {} min, max {} h", cfg.grant_minutes, cfg.max_hours);
    println!("Keep awake:     {}", if cfg.keep_awake { "while someone is signed in" } else { "off" });
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
    let enrollment = admin::totp_begin(data, force).map_err(|e| {
        if e.contains("already set up") { "6-digit codes are already set up (use --force to replace; old codes stop working)".into() } else { e }
    })?;
    let qr = QrCode::new(enrollment.uri.as_bytes()).map_err(|e| e.to_string())?;
    // Terminals usually draw light text on a dark background, so by default the
    // "dark" modules are drawn as background and vice versa.
    let (dark, light) = if invert { (Dense1x2::Dark, Dense1x2::Light) } else { (Dense1x2::Light, Dense1x2::Dark) };
    println!("\n{}", qr.render::<Dense1x2>().dark_color(dark).light_color(light).quiet_zone(true).build());
    println!("Scan it with your authenticator app, or type this key:\n\n    {}\n", enrollment.key);
    println!("Don't photograph or screenshot it: anyone with this key can generate your codes.");
    let stdin = std::io::stdin();
    for _ in 0..3 {
        print!("\nEnter the 6-digit code your app shows now: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("no input".into());
        }
        if !admin::totp_confirm(data, &enrollment, &line)? {
            println!("That code doesn't match. Make sure the phone sets its clock automatically.");
            continue;
        }
        println!("6-digit codes enabled.");
        return Ok(());
    }
    Err("6-digit codes were not enabled".into())
}
