//! One-click fixes for the warnings the service reports, for the Fix
//! buttons in RDP Gate Server (which runs as Administrator).

/// What a warning's Fix button does.
#[derive(Debug, Clone, PartialEq)]
pub enum Fix {
    /// Turn every Windows Firewall profile on, blocking inbound by default.
    FirewallOn,
    /// Disable the local firewall rule with this display name.
    DisableRule(String),
    /// Ask Windows Time to set the clock now.
    SyncClock,
}

impl Fix {
    /// The button's label.
    pub fn label(&self) -> &'static str {
        match self {
            Fix::FirewallOn => "Turn the firewall on",
            Fix::DisableRule(_) => "Disable this rule",
            Fix::SyncClock => "Sync the clock now",
        }
    }

    /// What to confirm before doing it, if anything.
    pub fn confirm(&self) -> Option<String> {
        match self {
            Fix::FirewallOn => Some(
                "Windows Firewall is turned on for every network type. Remote Desktop then opens only for computers that \
                 sign in through RDP Gate: a session that didn't come through RDP Gate is disconnected."
                    .into(),
            ),
            Fix::DisableRule(n) => Some(format!(
                "The firewall rule \"{n}\" is disabled. A Remote Desktop session that relies on it, rather than on signing \
                 in through RDP Gate, is disconnected."
            )),
            Fix::SyncClock => None,
        }
    }
}

/// The fix for a warning from the service, if there is one.
pub fn fix_for(warning: &str) -> Option<Fix> {
    if warning.starts_with(crate::firewall::PROFILE_WARNING) {
        return Some(Fix::FirewallOn);
    }
    if warning.starts_with("this PC's clock is") {
        return Some(Fix::SyncClock);
    }
    // "firewall rule [Local Name] lets anyone reach port 3389: ...". Only
    // local rules: Group Policy ones must be changed there.
    let rule = warning.strip_prefix("firewall rule [Local ")?;
    let end = rule.rfind("] lets anyone reach port")?;
    Some(Fix::DisableRule(rule[..end].to_string()))
}

/// Does `fix` (`rdp_port`: the Remote Desktop port). Blocking (PowerShell).
/// Returns what was done.
pub fn apply(fix: &Fix, rdp_port: u16) -> Result<String, String> {
    match fix {
        Fix::FirewallOn => {
            imp::powershell(
                "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
            )?;
            Ok("Windows Firewall is on again. RDP Gate's warning clears within a minute.".into())
        }
        Fix::DisableRule(name) => {
            let quoted = name.replace('\'', "''");
            // Exact name (not a wildcard), local rules only, and only those
            // that really let RDP through.
            let out = imp::powershell(&format!(
                "{}\n$n = '{quoted}'\nGet-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.DisplayName -eq $n -and (Test-ExposesRdp $_ {rdp_port}) }} | \
                 ForEach-Object {{ $_ | Disable-NetFirewallRule; 'DISABLED' }}",
                imp::exposes_rdp()
            ))?;
            let n = out.lines().filter(|l| l.trim() == "DISABLED").count();
            if n == 0 {
                return Err(format!("no enabled local rule named \"{name}\" exposes Remote Desktop any more"));
            }
            Ok(format!("Disabled the firewall rule \"{name}\". RDP Gate's warning clears at its next check."))
        }
        Fix::SyncClock => {
            crate::clock::fix_windows_time()?;
            Ok("Windows was asked to set its clock from internet time.".into())
        }
    }
}

#[cfg(windows)]
mod imp {
    pub use crate::firewall::windows_fw::{exposes_rdp, powershell};
}

#[cfg(not(windows))]
mod imp {
    pub fn powershell(_: &str) -> Result<String, String> {
        Err("only on Windows".into())
    }
    pub fn exposes_rdp() -> &'static str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_fix_for_each_warning() {
        assert_eq!(
            fix_for("firewall profile Public is off or allows inbound traffic by default: Remote Desktop is reachable"),
            Some(Fix::FirewallOn)
        );
        assert_eq!(fix_for(&crate::clock::warning(19_800)), Some(Fix::SyncClock));
        assert_eq!(
            fix_for("firewall rule [Local Remote [Desktop] Custom] lets anyone reach port 3389: disable it"),
            Some(Fix::DisableRule("Remote [Desktop] Custom".into()))
        );
        assert_eq!(fix_for("firewall rule [GroupPolicy RDP] lets anyone reach port 3389: disable it"), None);
        assert_eq!(fix_for("firewall audit failed: timed out"), None);
    }
}
