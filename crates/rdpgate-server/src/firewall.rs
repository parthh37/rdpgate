//! Opening and closing the RDP port for one IP address at a time.
//!
//! Baseline (set by the installer): Windows Firewall blocks all inbound
//! traffic by default and every built-in "Remote Desktop" allow rule is
//! disabled. A successful sign-in adds one allow rule, scoped to the RDP port
//! and to exactly the signed-in source address. Nothing here ever adds a
//! *block* rule: in Windows Firewall block rules beat allow rules, so the
//! default-deny policy is what keeps everyone else out.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;

pub trait Firewall: Send + Sync + 'static {
    /// Returns warnings about anything that would let RDP traffic in around us.
    fn audit(&self) -> Vec<String>;
    fn allow(&self, ip: IpAddr) -> Result<(), String>;
    fn revoke(&self, ip: IpAddr) -> Result<(), String>;
    /// Removes every rule we ever created, tracked or not.
    fn revoke_all(&self) -> Result<(), String>;
    /// Addresses that currently have one of our allow rules.
    fn list_allowed(&self) -> Result<HashSet<IpAddr>, String>;
    /// Remote addresses with an established TCP connection to the RDP port.
    fn connected_peers(&self) -> Result<HashSet<IpAddr>, String>;
    /// Makes sure the sign-in ports are open for this program (and only this
    /// program), re-creating the rule if it is missing or out of date.
    fn ensure_portal(&self, ports: &[u16]) -> Result<(), String>;
}

#[cfg_attr(not(windows), allow(unused_variables))]
pub fn for_config(cfg: &crate::config::Config) -> std::sync::Arc<dyn Firewall> {
    #[cfg(windows)]
    if cfg.firewall == "windows" {
        return std::sync::Arc::new(windows_fw::WindowsFirewall::new(cfg.rdp_port, cfg.allow_udp));
    }
    std::sync::Arc::new(DryRun::default())
}

/// Removes leftover rules before anything else can fail (config errors, a
/// busy port): a rule must never outlive the process that tracked it.
pub fn early_sweep() -> Result<(), String> {
    #[cfg(windows)]
    return windows_fw::WindowsFirewall::new(3389, false).revoke_all();
    #[cfg(not(windows))]
    Ok(())
}

/// Logs what it would do. Used for development on macOS/Linux and in tests.
#[derive(Default)]
pub struct DryRun {
    pub allowed: Mutex<HashSet<IpAddr>>,
    pub peers: Mutex<HashSet<IpAddr>>,
}

impl Firewall for DryRun {
    fn audit(&self) -> Vec<String> {
        vec!["firewall is in dry-run mode: nothing is actually opened or closed".into()]
    }
    fn allow(&self, ip: IpAddr) -> Result<(), String> {
        crate::logln!("FIREWALL (dry-run) allow {ip}");
        self.allowed.lock().unwrap().insert(ip);
        Ok(())
    }
    fn revoke(&self, ip: IpAddr) -> Result<(), String> {
        crate::logln!("FIREWALL (dry-run) revoke {ip}");
        self.allowed.lock().unwrap().remove(&ip);
        Ok(())
    }
    fn revoke_all(&self) -> Result<(), String> {
        self.allowed.lock().unwrap().clear();
        Ok(())
    }
    fn list_allowed(&self) -> Result<HashSet<IpAddr>, String> {
        Ok(self.allowed.lock().unwrap().clone())
    }
    fn connected_peers(&self) -> Result<HashSet<IpAddr>, String> {
        Ok(self.peers.lock().unwrap().clone())
    }
    fn ensure_portal(&self, ports: &[u16]) -> Result<(), String> {
        crate::logln!("FIREWALL (dry-run) would allow TCP {ports:?} for this program");
        Ok(())
    }
}

#[cfg(windows)]
pub mod windows_fw {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    pub const RULE_PREFIX: &str = "RDPGate-Allow-";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CHILD_TIMEOUT: Duration = Duration::from_secs(20);

    pub struct WindowsFirewall {
        port: u16,
        udp: bool,
    }

    impl WindowsFirewall {
        pub fn new(port: u16, udp: bool) -> Self {
            WindowsFirewall { port, udp }
        }
    }

    /// Absolute paths, so a planted netsh.exe on PATH is never run as SYSTEM.
    fn system32(exe: &str) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{root}\System32\{exe}")
    }

    /// Runs a child process with a deadline, so a hung netsh/PowerShell can't
    /// stall grant expiry. Returns (success, combined output).
    fn run(exe: &str, args: &[&str]) -> Result<(bool, String), String> {
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("{exe}: {e}"))?;
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{exe} timed out"));
                }
                Err(e) => return Err(format!("{exe}: {e}")),
            }
        }
        let out = child.wait_with_output().map_err(|e| format!("{exe}: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        Ok((out.status.success(), text))
    }

    fn netsh(args: &[&str]) -> Result<(bool, String), String> {
        run(&system32("netsh.exe"), args)
    }

    fn powershell(script: &str) -> Result<String, String> {
        let (ok, out) = run(
            &system32(r"WindowsPowerShell\v1.0\powershell.exe"),
            &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        )?;
        if ok { Ok(out) } else { Err(format!("powershell: {}", out.trim())) }
    }

    /// The IP comes from the TCP socket, never from client input, and is
    /// re-rendered from a parsed `IpAddr`, so it cannot smuggle extra
    /// netsh arguments.
    fn rule_name(ip: IpAddr) -> String {
        format!("{RULE_PREFIX}{ip}")
    }

    fn rule_exists(ip: IpAddr) -> Result<bool, String> {
        // `show rule` exits non-zero when nothing matches, in every language.
        netsh(&["advfirewall", "firewall", "show", "rule", &format!("name={}", rule_name(ip))]).map(|(ok, _)| ok)
    }

    impl Firewall for WindowsFirewall {
        fn audit(&self) -> Vec<String> {
            let port = self.port;
            // ActiveStore = effective policy, including Group Policy rules.
            // A rule exposes RDP if it allows inbound TCP to the RDP port, to
            // any port, or to a range containing it, and isn't limited to some
            // unrelated program.
            let script = format!(
                r#"$p = {port}
Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {{ $_.Enabled -ne 'True' -or $_.DefaultInboundAction -eq 'Allow' }} | ForEach-Object {{ 'PROFILE ' + $_.Name }}
Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DisplayName -notlike '{RULE_PREFIX}*' -and $_.DisplayName -notlike 'RDPGate-Portal*' }} |
  ForEach-Object {{
    $r = $_
    $pf = $r | Get-NetFirewallPortFilter
    if ($pf.Protocol -notin @('TCP','Any')) {{ return }}
    $hit = $false
    foreach ($lp in @($pf.LocalPort)) {{
      if ($lp -eq 'Any' -or $lp -eq "$p") {{ $hit = $true }}
      elseif ($lp -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $p -and [int]$Matches[2] -ge $p) {{ $hit = $true }}
    }}
    if (-not $hit) {{ return }}
    $app = ($r | Get-NetFirewallApplicationFilter).Program
    $svc = ($r | Get-NetFirewallServiceFilter).Service
    if ($app -notin @('Any','System','%SystemRoot%\system32\svchost.exe','C:\Windows\system32\svchost.exe') -and $svc -ne 'TermService') {{ return }}
    if ($svc -notin @('Any','TermService')) {{ return }}
    'RULE ' + $r.PolicyStoreSourceType + ' ' + $r.DisplayName
  }}"#
            );
            let mut warnings = Vec::new();
            match powershell(&script) {
                Ok(out) => {
                    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                        if let Some(p) = line.strip_prefix("PROFILE ") {
                            warnings.push(format!("firewall profile {p} is off or allows inbound traffic by default: RDP is reachable without signing in"));
                        } else if let Some(r) = line.strip_prefix("RULE ") {
                            warnings.push(format!("firewall rule [{r}] lets anyone reach port {port}: disable it (rules from Group Policy must be changed there)"));
                        }
                    }
                }
                Err(e) => warnings.push(format!("firewall audit failed: {e}")),
            }
            warnings
        }

        fn allow(&self, ip: IpAddr) -> Result<(), String> {
            let name = format!("name={}", rule_name(ip));
            let port = format!("localport={}", self.port);
            let remote = format!("remoteip={ip}");
            let add = |proto: &str| -> Result<(), String> {
                let (ok, out) = netsh(&[
                    "advfirewall", "firewall", "add", "rule", &name, "dir=in", "action=allow", proto, &port, &remote,
                    "profile=any", "edge=no", "enable=yes",
                ])?;
                if ok { Ok(()) } else { Err(format!("netsh add rule: {}", out.trim())) }
            };
            add("protocol=TCP")?;
            // UDP only if enabled: it has no handshake, so a forged source
            // address would get through.
            if self.udp
                && let Err(e) = add("protocol=UDP")
            {
                let _ = self.revoke(ip); // don't leave a half-made grant behind
                return Err(e);
            }
            Ok(())
        }

        fn revoke(&self, ip: IpAddr) -> Result<(), String> {
            let (ok, out) = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name(ip))])?;
            if ok || !rule_exists(ip)? { Ok(()) } else { Err(format!("netsh delete rule: {}", out.trim())) }
        }

        fn revoke_all(&self) -> Result<(), String> {
            powershell(&format!(
                "Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
            ))
            .map(|_| ())
        }

        fn list_allowed(&self) -> Result<HashSet<IpAddr>, String> {
            let out = powershell(&format!(
                "Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.DisplayName }}"
            ))?;
            Ok(out.lines().filter_map(|l| l.trim().strip_prefix(RULE_PREFIX)?.parse().ok()).collect())
        }

        fn connected_peers(&self) -> Result<HashSet<IpAddr>, String> {
            tcp_table::established_peers(self.port)
        }

        fn ensure_portal(&self, ports: &[u16]) -> Result<(), String> {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            // Single-quoted PowerShell string: double any single quote.
            let exe = exe.display().to_string().replace('\'', "''");
            let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
            powershell(&format!(
                "Get-NetFirewallRule -DisplayName 'RDPGate-Portal*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
                 New-NetFirewallRule -Name 'RDPGate-Portal' -DisplayName 'RDPGate-Portal (sign-in)' -Direction Inbound -Action Allow \
                 -Protocol TCP -LocalPort {} -Program '{exe}' -Profile Any | Out-Null",
                ports.join(",")
            ))
            .map(|_| ())
        }
    }

    mod tcp_table {
        use std::collections::HashSet;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        /// Calls GetExtendedTcpTable, growing a u32-aligned buffer as needed.
        fn fetch(af: u32) -> Result<Vec<u32>, String> {
            let mut size: u32 = 0;
            let mut buf: Vec<u32> = Vec::new();
            for _ in 0..8 {
                let ptr = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() };
                let rc = unsafe { GetExtendedTcpTable(ptr, &mut size, 0, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
                match rc {
                    NO_ERROR if !buf.is_empty() => {
                        buf.truncate((size as usize).div_ceil(4));
                        return Ok(buf);
                    }
                    NO_ERROR | ERROR_INSUFFICIENT_BUFFER => {
                        // Room for connections opened between the two calls.
                        buf = vec![0u32; (size as usize).div_ceil(4) + 256];
                        size = (buf.len() * 4) as u32;
                    }
                    other => return Err(format!("GetExtendedTcpTable failed: {other}")),
                }
            }
            Err("GetExtendedTcpTable: connection table kept growing".into())
        }

        fn port_of(raw: u32) -> u16 {
            u16::from_be(raw as u16)
        }

        pub fn established_peers(port: u16) -> Result<HashSet<IpAddr>, String> {
            let mut out = HashSet::new();
            let estab = MIB_TCP_STATE_ESTAB as u32;

            let buf = fetch(AF_INET as u32)?;
            let bytes = buf.len() * 4;
            if bytes >= 4 {
                let tbl = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let n = unsafe { (*tbl).dwNumEntries } as usize;
                let rows_ptr = unsafe { std::ptr::addr_of!((*tbl).table) } as *const MIB_TCPROW_OWNER_PID;
                let header = rows_ptr as usize - tbl as usize;
                if header + n * size_of::<MIB_TCPROW_OWNER_PID>() > bytes {
                    return Err("IPv4 connection table is truncated".into());
                }
                for r in unsafe { std::slice::from_raw_parts(rows_ptr, n) } {
                    if r.dwState == estab && port_of(r.dwLocalPort) == port {
                        out.insert(IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())));
                    }
                }
            }

            let buf = fetch(AF_INET6 as u32)?;
            let bytes = buf.len() * 4;
            if bytes >= 4 {
                let tbl = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let n = unsafe { (*tbl).dwNumEntries } as usize;
                let rows_ptr = unsafe { std::ptr::addr_of!((*tbl).table) } as *const MIB_TCP6ROW_OWNER_PID;
                let header = rows_ptr as usize - tbl as usize;
                if header + n * size_of::<MIB_TCP6ROW_OWNER_PID>() > bytes {
                    return Err("IPv6 connection table is truncated".into());
                }
                for r in unsafe { std::slice::from_raw_parts(rows_ptr, n) } {
                    if r.dwState == estab && port_of(r.dwLocalPort) == port {
                        out.insert(IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)).to_canonical());
                    }
                }
            }
            Ok(out)
        }
    }
}
