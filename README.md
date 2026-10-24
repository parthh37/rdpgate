<p align="center"><img src="docs/assets/logo.png" width="96" height="96" alt=""></p>

<h1 align="center">RDP Gate</h1>

<p align="center"><b>Windows Remote Desktop that stays closed to the internet until you sign in.</b><br>
One agent on the Windows PC. A small app on your Mac or PC. No static IP, no DNS name, no VPN.</p>

<p align="center">
<a href="https://github.com/parthh37/rdpgate/actions/workflows/ci.yml"><img src="https://github.com/parthh37/rdpgate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/parthh37/rdpgate/releases/latest"><img src="https://img.shields.io/github/v/release/parthh37/rdpgate?include_prereleases" alt="Release"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

---

Exposing Remote Desktop (TCP 3389) to the internet invites constant password guessing and every future RDP vulnerability. RDP Gate keeps the port **closed** in Windows Firewall. When you sign in, it opens it **for your current IP address only**, keeps it open while you're connected, and closes it again when you leave.

- **Signing in** takes this computer's private key **plus** a 6-digit code from any authenticator app. You can optionally also sign in from a browser with a passkey (needs your own domain).
- **No static IP, no DNS, no DuckDNS.** The server publishes its address as an **encrypted, signed beacon** in a secret GitHub gist. The gist only ever holds ciphertext, though GitHub (like any website) sees the IP address each update comes from.
- **Spoof-resistant end to end.** Your computers pin the server's identity key, so a fake server, a hijacked address or a man-in-the-middle on the RDP port is detected *before* anything is sent or Remote Desktop opens. See [Spoofing](#spoofing).
- **One thing on the server:** `rdpgate-server.exe`, installed by a normal Setup wizard that also hardens RDP and the firewall and runs it as a Windows service.
- **Easy install, signed auto-updates:** Setup wizards for Windows, a drag-to-Applications disk image for Mac. Every program updates itself, but only to releases signed with the project's release key.
- **Written in Rust**, built on rustls, RustCrypto and webauthn-rs. No OpenSSL, no runtime dependencies.

Website: **https://parthh37.github.io/rdpgate/** · Step-by-step guide: **[Operation guide](https://parthh37.github.io/rdpgate/guide.html)**

<p align="center">
<img src="docs/assets/screenshots/server-overview.png" width="560" alt="RDP Gate Server: the overview of the PC you connect to">
<img src="docs/assets/screenshots/app-open.png" width="230" alt="The RDP Gate app with access open for one IP address">
</p>
<p align="center"><sub>RDP Gate Server on the Windows PC, and the app on the computer you connect from (sample data). More on the <a href="https://parthh37.github.io/rdpgate/#screens">website</a>.</sub></p>

## How it works

```
                         secret GitHub gist
                 ┌────── "v1.<ciphertext>" ◀────── publishes {ip, port, time}
                 │       (signed by the server key,      when the IP changes
                 ▼        encrypted with the beacon key)          │
 Your Mac / PC                                         Windows PC at home
┌───────────────────────────┐  TLS 1.3 :443    ┌────────────────────────────────────┐
│ RDP Gate app              │ ───────────────▶ │ rdpgate-server (Windows service)   │
│ 1. read + decrypt beacon  │ ◀── server proves│  proves identity key first         │
│ 2. check server identity  │     its key      │  checks device signature + code    │
│ 3. device key + code      │ ───────────────▶ │  adds ONE firewall rule:           │
│ 4. check RDP certificate  │                  │   allow TCP 3389 from YOUR IP      │
│ 5. open Remote Desktop    │ ───── RDP ─────▶ │ Remote Desktop (NLA + password)    │
└───────────────────────────┘    :3389         └────────────────────────────────────┘
```

What an attacker on the internet has to get past, from the outside in:

| Layer | What it does |
|---|---|
| **Hidden** | Port 3389 is closed by default. The sign-in port answers only clients that speak the RDP Gate protocol (or browsers asking for your exact domain), limits each source to a few connections, and goes silent for sources that keep failing. |
| **Enrolled device** | Every desktop request is signed with an Ed25519 key you enrolled on the server. The signature covers the TLS 1.3 session's exported keying material, so a captured request can't be replayed or relayed. The key is stored encrypted under your passphrase (Argon2id with 64 MiB, then XChaCha20-Poly1305). |
| **Second factor** | A one-time 6-digit code (each code works once; 10 wrong codes lock that computer until you unlock it), or a passkey with fingerprint, face or PIN. |
| **One public address, for a while** | The allow rule names a single public IP. Private and carrier-NAT addresses are refused, because they can stand for many machines. The rule lasts 10 minutes if you don't connect, stays while you're connected, and is capped at 12 hours. Leftover rules are swept at every start and every few minutes. |
| **Windows itself** | Network Level Authentication, TLS-only RDP, your Windows password and an account lockout policy, all set by the installer. |

## Spoofing

| If someone… | What happens |
|---|---|
| …fakes your IP address to use your opening | The grant uses the address from a completed TCP + TLS handshake, never headers or anything the client sends. Blind TCP spoofing can't finish a handshake. UDP (no handshake) is **off** unless you enable it. |
| …runs a fake server (hijacks DNS, gets a certificate, or takes over your old IP) | Before the app sends anything, the server must sign this TLS connection's keying material with the identity key your app pinned from the server card. A fake server fails, even with a valid certificate. The app reports it and sends nothing: not even its device name or your code. |
| …forges or replays the beacon | Beacons are signed with the server key (a stolen GitHub token can't forge one) and time-stamped (the app refuses any beacon older than one it has seen). An attacker can at most delete it; the app then falls back to the last address that worked. |
| …intercepts the RDP connection after the firewall opens | The server reads its own Remote Desktop certificate and sends its fingerprint over the authenticated channel. The app checks the RDP port presents that same certificate and **refuses to launch Remote Desktop** if it doesn't. |
| …replays a sign-in | Every request is bound to one TLS connection. Each code works once. Each passkey challenge works once. |
| …phishes a passkey | Passkeys only work on your exact domain. The one remaining gap is a hijacked domain combined with a live relay, so browser sign-in is off unless you configure a domain, and the desktop app doesn't depend on DNS at all. |

## Limitations (please read)

- **Shared public IPs.** While access is open, anyone behind the same public IP (hotel Wi-Fi, an office, mobile-carrier NAT) can reach the Windows *login screen*. They still need your Windows password. Close access when you're done (button in the app, or `rdpgate lock`). The planned [tunnel mode](ROADMAP.md) removes this.
- **Not independently audited.** The building blocks are well reviewed, and RDP Gate has had an internal adversarial review (all findings fixed), but no third-party audit. `webauthn-rs 0.6.1-dev` is a pre-release (pure Rust; 0.5 needs OpenSSL).
- **Not code-signed by Apple/Microsoft yet.** On macOS, right-click the app and choose **Open** the first time. On Windows, at the SmartScreen prompt choose **More info**, then **Run anyway**. Verify downloads with `SHA256SUMS.txt`. (Updates are signed with RDP Gate's own release key regardless.)
- **Nothing is unbreakable.** RDP Gate removes the internet-facing attack surface. It can't protect a Windows PC that's already compromised, or a stolen laptop together with your passphrase and phone.
- **Windows Home** can't host Remote Desktop.
- **Sleep.** A sleeping PC can't answer, and nothing on the internet can wake it. Setup turns off sleep on mains power for desktops (not laptops), and the service keeps the PC awake from sign-in until access closes. Choosing Sleep, closing a laptop lid or a flat battery still put it to sleep.

## Setup

You need: a Windows 10/11 **Pro, Enterprise or Education** PC, or Windows Server; admin access to your router; a GitHub account for the beacon (ideally one used only for this, see step 1); and on a Mac, Microsoft's free **[Windows App](https://apps.apple.com/app/windows-app/id1295203466)**.

### 1. Install the server

**First, make a GitHub token for the beacon, on a GitHub account used just for this.** A token with Gists access can read and change *every* gist on its account, including your other secret gists, and GitHub can't limit it to one gist. With a free account used only for the beacon, a leaked token exposes nothing else. (Secret gists are unlisted, not private: anyone with the link can read one. That's why the beacon is encrypted.) On that account, create a fine-grained token at <https://github.com/settings/personal-access-tokens/new> with **only** *Account permissions → Gists: Read and write*.

Then download **`RDP-Gate-Server-Setup-<version>.exe`** from [Releases](https://github.com/parthh37/rdpgate/releases) and run it on the Windows PC. The wizard asks for:
- **when to close Remote Desktop**: *now*, or *after your first sign-in* through RDP Gate. Pick the second if you're installing over Remote Desktop (Setup pre-selects it when it detects that), because closing it now would disconnect you and nothing is enrolled yet to get back in;
- whether to set up browser sign-in with your own domain (a guided step; only for passkeys),
- whether to set up the IP beacon now, allow sign-in from computers on your home network (for example a laptop on the same Wi-Fi), set an account lockout policy, stop the PC sleeping, or allow UDP.

When the beacon setup opens, paste the token at its hidden prompt. Right after it, in the same window, a QR code appears for your authenticator app: scan it and type the code it shows (untick **Set up 6-digit codes now** to skip this). If you reinstall over an earlier install, the codes you already have are kept.

<details><summary>Prefer a script? (portable zip)</summary>

Unzip `RDP-Gate-<version>-Windows-Server.zip` and, in PowerShell as Administrator, run `Set-ExecutionPolicy -Scope Process Bypass; .\install-server.ps1`. The same options are available as switches: `-Protect Now|AfterSignIn`, `-DomainSetup` / `-PublicHost`, `-AllowUdp`, `-Lan On|Off`, `-SkipLockout`, `-SkipSleep`, `-NoBeacon`, `-NoTotp`, `-RdpPublicPort`.
</details>

Setup does the following, in this order (with *after your first sign-in*, the two firewall steps wait: the service does them once a computer has signed in through RDP Gate **and** connected to Remote Desktop, and that address keeps its own opening so its session stays up; `rdpgate-server status` shows `Protection: PENDING` until then, and `rdpgate-server protect` does it immediately):
- installs `rdpgate-server.exe` to `C:\Program Files\RDPGate`. Its data goes in `C:\ProgramData\RDPGate`, which it takes ownership of and locks to SYSTEM and Administrators.
- sets Windows Firewall to **block inbound by default** and disables every rule that exposes the RDP port, including "any port" and port-range rules. It **stops** if Group Policy still exposes RDP.
- only then turns on Remote Desktop with NLA, TLS, high encryption and patched-CredSSP only.
- sets account lockout to 15 minutes after 10 wrong passwords (unless you untick it).
- stops a desktop PC sleeping or hibernating on mains power, so it can always be reached (unless you untick it). On a laptop it only warns, and battery settings are never changed.
- creates the server identity, publishes the first beacon, and starts the `RDPGate` service. It runs as SYSTEM and starts at boot whether or not anyone signs in to Windows. Windows restarts it after any failure, it exits and restarts itself if part of it stops working, and a scheduled task (`\RDPGate\Watchdog` in Task Scheduler) starts it again within 5 minutes if it was stopped any other way.

Uninstall it from **Settings → Apps → RDP Gate Server**. It asks whether to **put back the settings Setup changed**: Windows Firewall (on or off, as before), the Remote Desktop firewall rules and settings, the lockout policy, sleep on mains power, and the router forwards RDP Gate added. Setup records these before its first change. Answer *No* to keep Remote Desktop blocked from the network. Your RDP Gate data in `C:\ProgramData\RDPGate` is kept either way. From a script: `uninstall-server.ps1 -Restore [-RemoveData]`.

If Windows Firewall is off when you install, Setup turns it on (it's what keeps Remote Desktop closed).

### 2. Your router (usually automatic)

You don't need to touch Windows Firewall: Setup opens the sign-in port for RDP Gate only and keeps Remote Desktop closed, and the service re-checks this at every start.

Setup also **forwards the ports on your router automatically** (UPnP), and the service keeps those forwards renewed. `rdpgate-server status` shows whether it worked. If your router has UPnP turned off, or refuses, forward these by hand:

| External | → Windows PC | Purpose |
|---|---|---|
| TCP 443 | 443 | Sign-in |
| TCP 3389 | 3389 | Remote Desktop: closed until someone signs in |

Either way, give the PC a fixed (reserved) LAN address in your router's DHCP settings. If Setup reports **carrier-grade NAT**, your ISP shares one public IP among many customers and nothing can reach your PC from outside: ask the ISP for a public IPv4 address (often free).

The Mac and PC apps only make outgoing connections and need no open ports.

### 3. Set up 6-digit codes (on the server)

Setup does this in its window, right after the beacon. To do it later (or with a new phone), open **RDP Gate Server** from the Start menu → **6-digit codes**: it shows the QR code and asks for the code your app shows. (Command line: `rdpgate-server totp-setup`.)

### 4. Enroll each computer you'll connect from

- **Mac:** open **`RDP-Gate-<version>-macOS.dmg`** and drag **RDP Gate** to Applications. The first time, right-click it and choose **Open** (the build isn't notarized yet).
- **Windows:** run **`RDP-Gate-Setup-<version>.exe`**. It installs just for you, with no administrator rights needed, and adds a Start menu entry.

Enter a name for this computer and a passphrase. The app then shows this computer's key (`rdpgate-ed25519:…`) with a **Copy** button. On the server, open **RDP Gate Server** from the Start menu → **Computers**, paste it under **Add a computer** and choose **Add computer**.

The window shows the device fingerprint (check it matches the app) and a **server card** (`rdpgate-card:…`) with **Copy server card**. Paste the card into the app. The card pins the server's identity key and holds the beacon key. Keep it private: it reveals where to find your PC, though it can't sign in by itself. (Command line: `rdpgate-server device-add macbook rdpgate-ed25519:…`.)

### 5. Connect

- **App:** passphrase + 6-digit code → **Sign in and open Remote Desktop**. The app finds the server, verifies it, opens the firewall, checks the RDP certificate, and launches Remote Desktop.
- **Command line:** `rdpgate connect` (and `rdpgate lock` when you're done).

Test from outside your home network, for example over a phone hotspot. To sign in from inside your own network too (a laptop on the same Wi-Fi), tick **Also allow sign-in from computers on my home network** in Setup, or run `rdpgate-server lan on`. The server then puts its home-network address in the encrypted beacon, and the app connects to it directly when you are at home (no router loop-back needed) and to your public address everywhere else. Give the PC a reserved address in your router so that address stays the same. Sign-in from the router's own address is always refused: some routers make every connection from the internet look like it, so a grant for it could open Remote Desktop to everyone.

### Optional: browser sign-in with a passkey

Browsers bind passkeys to a domain name, never an IP, so this needs a domain you control with a DNS "A" record pointing at your home IP (plus dynamic DNS if that IP changes). Tick it in Setup, or run the guided setup at any time:

```powershell
rdpgate-server domain-setup      # domain, DNS record + live check, certificate, first passkey
rdpgate-server passkey-enroll    # more passkeys: one-time link, open it on your Mac/iPhone/PC
```

It shows the exact DNS record to create, checks it until it resolves to your IP (and warns about a Cloudflare proxy or a stray AAAA record), and keeps your beacon, devices and other settings. `domain-setup --remove` turns browser sign-in off.

The sign-in page shows which IP it opened, lets you close access early, and shows the Remote Desktop certificate fingerprint to compare.

## Updates

Every program keeps itself up to date, and only ever installs a release signed with the RDP Gate release key:

| Program | Automatic | By hand |
|---|---|---|
| Server | Checks daily. Installs only while nobody has access open, then restarts the service. `"auto_update": false` in config.json turns it off. | Start menu → **Check for RDP Gate updates** (asks before installing), or `rdpgate-server update` (`--check` to only look) |
| Desktop app | Checks once a day at launch. Installs and offers **Restart now**. There's a toggle under *This computer and server*. | **Check for updates** at the bottom of every screen, even before setup |
| `rdpgate` CLI | Once a day, after a successful `connect`. | `rdpgate update`, `rdpgate auto-update on\|off` |

Each release has a manifest (`rdpgate-update.json`) listing every file's SHA-256 and size, signed with Ed25519. The programs embed the public key. They refuse a manifest with a bad signature, anything older than what they run, and any download that doesn't match its signed hash. GitHub, a network attacker or anyone who can edit release files can't push code to your machines without the release key.

## Releasing (maintainers)

*Actions → Release → Run workflow*, then pick `patch`, `minor` or `major`. The workflow:
1. works out the next version;
2. builds and tests on Windows and macOS, compiling the Setup installers and the disk image;
3. signs the update manifest with the `RDPGATE_UPDATE_KEY` secret;
4. **only then** commits the version bump, tags it, and publishes the release.

A failed build publishes nothing. Locally, `scripts/bump-version.sh minor` bumps the version, and `scripts/build-release.sh` builds unsigned packages for testing.

The release key's private half lives in the repository secret and in the maintainer's offline backup. Losing it means users must reinstall manually once to trust a new key.

## Administration

Everything here is also in the **RDP Gate Server** window (Start menu, and a desktop icon if you kept it in Setup). It asks for Administrator rights when it opens and works over Remote Desktop:

| Page | What you can do |
|---|---|
| Overview | Whether the service is running (Start / Restart), whether Remote Desktop is closed to others (and close it now if it's still pending), the beacon, the router, open access, updates |
| Computers | Add a computer (paste its key), copy the server card, see last sign-ins, unlock or remove a computer |
| 6-digit codes | Set them up or move them to a new phone: a QR code to scan, then confirm a code |
| Network | The GitHub token for the beacon, sign-in from your home network, forwarding the router ports |
| Browser sign-in | The guided domain setup, passkeys, one-time links to add a passkey |
| Activity log | Sign-ins, refusals, firewall openings and closings, beacon and update activity |

Setup also puts an **RDP Gate icon next to the clock** for everyone who signs in (untick it in Setup if you don't want it). Its dot shows the service at a glance: green running, amber starting or stopping, red stopped. Hover it for the state, click it to open RDP Gate Server, right-click it to start a stopped service. If the service stays stopped, it tells you with a notification. On Windows 11, new icons first appear under the **^** arrow: drag it onto the taskbar to keep it in view.

The same from PowerShell as Administrator:

```text
rdpgate-server status                  # identity, beacon, warnings, open firewall grants
rdpgate-server card                    # print the server card again
rdpgate-server device-list | device-remove NAME | device-unlock NAME
rdpgate-server passkey-list | passkey-remove NAME
rdpgate-server beacon-setup            # new token or gist
rdpgate-server domain-setup            # browser sign-in with your domain (guided); --remove to turn off
rdpgate-server protect                 # close Remote Desktop to non-signed-in addresses now (if pending)
rdpgate-server update [--check]        # signed self-update
rdpgate-server lan on|off              # sign-in from computers on this network (e.g. your laptop at home)
rdpgate-server router                  # forward router ports now (UPnP) and report
rdpgate-server totp-setup --force      # new authenticator secret
```

Logs: `C:\ProgramData\RDPGate\logs\rdpgate.log`. Every refusal (`DENY`), sign-in (`GRANT open`), RDP connection, lockout, beacon update and closure is recorded.

Settings live in `C:\ProgramData\RDPGate\config.json`; restart the service after editing (`Restart-Service RDPGate`):

| Key | Default | Meaning |
|---|---|---|
| `public_port` | 443 | External port forwarded to the agent |
| `listen` | `["0.0.0.0:443"]` | Add `"[::]:443"` for IPv6 |
| `rdp_port` / `rdp_public_port` | 3389 | Local RDP port / external port clients use |
| `allow_udp` | false | Also open UDP for signed-in addresses |
| `upnp` | true | Forward the ports on the router automatically |
| `allow_private_sources` | false | Grant LAN / carrier-NAT source addresses, and publish this PC's LAN address in the beacon (`rdpgate-server lan on` or `off`) |
| `grant_minutes` | 10 | Time to start a session after signing in |
| `max_hours` | 12 | Hard cap on one grant |
| `keep_awake` | true | Keep the PC from sleeping while a grant is open (`powercfg /requests` shows it) |
| `desktop_login` / `web_login` | true / with domain | Turn either sign-in method off |
| `public_host`, `tls` | — | Domain and certificate for browser sign-in |
| `beacon` | — | `{ "gist_id": …, "token": … }`, set by `beacon-setup` |
| `auto_update` / `update_prereleases` | true / true | Signed self-updates; include pre-releases (all 0.x) |

Uninstall: `& "C:\Program Files\RDPGate\uninstall-server.ps1"` (add `-RemoveData` to delete settings).

## Troubleshooting

- **"answered but is NOT your server"**: something other than your server answered at that address. If the server was reinstalled (new identity), paste the new server card. Otherwise, treat it as a spoofing attempt.
- **"The server refused this computer"**: the device isn't enrolled, or your IP is temporarily blocked after repeated failures.
- **"this computer is locked after too many wrong codes"**: run `rdpgate-server device-unlock NAME` on the server.
- **"is not a public address"**: you signed in from your own network. Either test from outside, or run `rdpgate-server lan on`.
- **Can't reach the server from outside**: run `rdpgate-server router`. It re-applies the router forwards and tells you if UPnP is off or the ISP uses carrier-grade NAT.
- **"Port 443 is already used by …" during Setup**: another program (IIS, a VPN server) holds the port. Stop it, or run the script with `-ListenPort 8443` and forward the router's 443 to 8443.
- **Beacon errors in `status`**: check the GitHub token still has Gists access (`rdpgate-server beacon-setup` to replace it).
- **Microsoft account with "passwordless" sign-in**: RDP needs a password. Turn off "Require Windows Hello sign-in for Microsoft accounts", or use a local account.

## Building from source

```bash
cargo test --workspace
cargo build --release -p rdpgate-server -p rdpgate-client -p rdpgate-app
./scripts/build-release.sh        # macOS: builds every package into dist/ (needs cargo-xwin for Windows)
```

| Crate | |
|---|---|
| `crates/rdpgate-core` | Wire protocol (Ed25519 + TLS channel binding), beacon & server card, RDP certificate probe, TOTP, encrypted key file |
| `crates/rdpgate-server` | The Windows agent: TLS, beacon publisher, passkey portal, firewall grants, service |
| `crates/rdpgate-client` | Client library and the `rdpgate` command-line tool |
| `crates/rdpgate-app` | The desktop app (egui) for macOS and Windows |
| `crates/rdpgate-release` | Release tooling: signing key and signed update manifest |
| `packaging/` | Inno Setup scripts (`server.iss`, `client.iss`), PowerShell hardening, macOS bundle files |

## Roadmap

See [ROADMAP.md](ROADMAP.md). Next up: **tunnel mode** (RDP through the authenticated connection, with no port 3389 forwarding and no shared-IP exposure), signed builds, and privilege separation.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
