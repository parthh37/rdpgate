<#
.SYNOPSIS
    Installs RDP Gate on this Windows PC and puts Remote Desktop behind it.

.DESCRIPTION
    In this order, so Remote Desktop is never reachable while half-configured:
    1. Copies rdpgate-server.exe to "C:\Program Files\RDPGate" and adds it to PATH.
    2. Secures C:\ProgramData\RDPGate (SYSTEM + Administrators only, even if
       the folder already existed).
    3. Locks down Windows Firewall: inbound blocked by default, every rule that
       exposes the Remote Desktop port disabled, HTTPS allowed for
       rdpgate-server.exe only. Stops if Group Policy still exposes RDP.
       With -Protect AfterSignIn (the default when this runs inside a Remote
       Desktop session) only the HTTPS rule is added now, so the session you
       are installing over isn't cut off. The service locks down by itself
       once a computer has signed in through RDP Gate and connected.
    4. Only then turns on Remote Desktop with Network Level Authentication and
       TLS (rolled back if anything fails).
    5. Sets an account lockout policy (unless -SkipLockout).
    6. Stops a desktop PC sleeping or hibernating on mains power, so it can
       always be reached (unless -SkipSleep). Laptops only get a warning.
    7. Creates the configuration and server identity, sets up the encrypted
       IP beacon in a secret GitHub gist (asks for a token), sets up 6-digit
       codes (shows a QR code; unless -NoTotp), and starts the "RDPGate"
       service.
    8. Forwards the sign-in and Remote Desktop ports on the router with UPnP
       when the router allows it (unless -NoUpnp), and warns about
       carrier-grade NAT.
    9. With -PublicHost or -DomainSetup, runs the guided domain setup for
       browser (passkey) sign-in: DNS record, check, certificate, passkey.

    Run it again at any time to upgrade or re-apply the hardening; enrolled
    devices, passkeys, codes and the server identity are kept.

.EXAMPLE
    .\install-server.ps1

.EXAMPLE
    .\install-server.ps1 -PublicHost rdp.example.com -Email me@example.com -RdpPublicPort 53389

.EXAMPLE
    # Installing over Remote Desktop: keep this session until the first sign-in
    .\install-server.ps1 -Protect AfterSignIn
#>
[CmdletBinding()]
param(
    # Optional DNS name for browser (passkey) sign-in. Not needed for the desktop app.
    [string] $PublicHost,
    # Run the guided domain setup for browser sign-in (asks for the domain)
    [switch] $DomainSetup,
    # When to close Remote Desktop to everyone who hasn't signed in:
    # Now, AfterSignIn (keeps the session you're installing over), or Auto
    # (AfterSignIn inside a Remote Desktop session, otherwise Now)
    [ValidateSet('Auto', 'Now', 'AfterSignIn')]
    [string] $Protect = 'Auto',
    # Optional email for Let's Encrypt certificate notices (with -PublicHost)
    [string] $Email,
    # Local port the agent listens on
    [int] $ListenPort = 443,
    # External port your router forwards to -ListenPort
    [int] $PublicPort = 443,
    # External port your router forwards to Remote Desktop (default: same as the local RDP port)
    [int] $RdpPublicPort = 0,
    # Also open UDP for signed-in addresses (faster, but UDP sources can be forged)
    [switch] $AllowUdp,
    # Sign-in from computers on this PC's own network (e.g. a laptop on the
    # same Wi-Fi): On, Off, or Keep (as configured; off on a new install)
    [ValidateSet('Keep', 'On', 'Off')]
    [string] $Lan = 'Keep',
    # Don't set up the GitHub gist beacon now (you can run "rdpgate-server beacon-setup" later)
    [switch] $NoBeacon,
    # Don't set up 6-digit codes now (you can run "rdpgate-server totp-setup" later)
    [switch] $NoTotp,
    # Use the Let's Encrypt staging CA (testing only)
    [switch] $Staging,
    # Don't change the account lockout policy
    [switch] $SkipLockout,
    # Don't stop this PC sleeping on mains power (a sleeping PC can't be reached)
    [switch] $SkipSleep,
    # Don't forward ports on the router automatically (UPnP)
    [switch] $NoUpnp,
    # Run by the Setup wizard: files are already in place; pause at the end
    [switch] $FromInstaller
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = Join-Path $env:ProgramFiles 'RDPGate'
$DataDir    = Join-Path $env:ProgramData 'RDPGate'
$Exe        = Join-Path $InstallDir 'rdpgate-server.exe'
$TsKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RdpTcpKey  = "$TsKey\WinStations\RDP-Tcp"

if ($FromInstaller) {
    # Keep the window open on failure so the message can be read.
    trap {
        Write-Host "`nERROR: $_" -ForegroundColor Red
        Read-Host 'Setup could not finish. Press Enter to close'
        exit 1
    }
}

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    WARNING: $m" -ForegroundColor Yellow }

# A rule exposes RDP if it allows inbound TCP to the RDP port (or any port, or
# a range containing it) and isn't limited to some unrelated program/service.
function Test-ExposesRdp($Rule, [int] $Port) {
    $pf = $Rule | Get-NetFirewallPortFilter
    if ($pf.Protocol -notin @('TCP', 'Any')) { return $false }
    $hit = $false
    foreach ($lp in @($pf.LocalPort)) {
        if ($lp -eq 'Any' -or $lp -eq "$Port") { $hit = $true }
        elseif ($lp -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $Port -and [int]$Matches[2] -ge $Port) { $hit = $true }
    }
    if (-not $hit) { return $false }
    $app = ($Rule | Get-NetFirewallApplicationFilter).Program
    $svc = ($Rule | Get-NetFirewallServiceFilter).Service
    $appOk = $app -in @('Any', 'System', '%SystemRoot%\system32\svchost.exe', "$env:SystemRoot\system32\svchost.exe")
    if (-not $appOk -and $svc -ne 'TermService') { return $false }
    if ($svc -notin @('Any', 'TermService')) { return $false }
    return $true
}

# Idle seconds before the PC sleeps (STANDBYIDLE) or hibernates (HIBERNATEIDLE)
# in the active power plan, as @{ AC = ...; DC = ... }; 0 means never. $null if
# this PC doesn't have the setting. powercfg translates its labels, but the
# values always end with the AC index, then the DC index.
function Get-SleepTimeouts([string] $Setting) {
    # powercfg complains on stderr about settings this PC lacks; under 'Stop',
    # Windows PowerShell would turn that into an exception.
    $ErrorActionPreference = 'Continue'
    $values = @(& powercfg.exe /query SCHEME_CURRENT SUB_SLEEP $Setting 2>$null |
        Select-String '0x([0-9a-fA-F]{8})' |
        ForEach-Object { [Convert]::ToUInt32($_.Matches[0].Groups[1].Value, 16) })
    if ($values.Count -lt 2) { return $null }
    return @{ AC = $values[-2]; DC = $values[-1] }
}

# ---------------------------------------------------------------------------
Step 'Checking this PC'
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -match 'Home') {
    throw "Windows Home cannot accept Remote Desktop connections. Use Windows Pro, Enterprise, Education or Server."
}
if (-not (Test-Path (Join-Path $Here 'rdpgate-server.exe'))) {
    throw "rdpgate-server.exe must be in the same folder as this script."
}
# RDP Gate depends on Windows Defender Firewall: start it if it's off.
$fwSvc = Get-Service MpsSvc -ErrorAction SilentlyContinue
if (-not $fwSvc) { throw "Windows Defender Firewall (MpsSvc) is missing from this PC. RDP Gate depends on it." }
if ($fwSvc.Status -ne 'Running') {
    Warn 'Windows Defender Firewall was not running: turning it on.'
    if ($fwSvc.StartType -eq 'Disabled') {
        # Set-Service is refused for this protected service on some versions.
        try { Set-Service MpsSvc -StartupType Automatic }
        catch { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc' -Name Start -Value 2 -Type DWord }
    }
    Start-Service MpsSvc -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    if ((Get-Service MpsSvc).Status -ne 'Running') {
        throw "Could not start Windows Defender Firewall (MpsSvc). Turn it on (Windows Security > Firewall & network protection, or Group Policy if it's managed), then run this again."
    }
    Ok 'Windows Defender Firewall service started'
}
$rdpPort = [int](Get-ItemProperty -Path $RdpTcpKey).PortNumber
Ok "$($os.Caption), Remote Desktop port $rdpPort"
$overRdp = "$env:SESSIONNAME" -like 'RDP-Tcp*'
if ($Protect -eq 'Auto') { $Protect = if ($overRdp) { 'AfterSignIn' } else { 'Now' } }
$deferred = $Protect -eq 'AfterSignIn'
if ($deferred) {
    Ok 'Protection turns on after the first sign-in through RDP Gate (this session is kept)'
} elseif ($overRdp) {
    Warn 'You are connected over Remote Desktop: locking down the firewall will disconnect you, and no computer can sign in yet. Use -Protect AfterSignIn to keep this session.'
}

# ---------------------------------------------------------------------------
Step 'Installing files'
if (Get-Service RDPGate -ErrorAction SilentlyContinue) { Stop-Service RDPGate -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if ((Resolve-Path $Here).Path.TrimEnd('\') -ne $InstallDir.TrimEnd('\')) {
    Copy-Item (Join-Path $Here 'rdpgate-server.exe') $Exe -Force
}
foreach ($f in 'uninstall-server.ps1', 'install-server.ps1') {
    $src = Join-Path $Here $f
    if ((Test-Path $src) -and ((Resolve-Path $src).Path -ne (Join-Path $InstallDir $f))) { Copy-Item $src $InstallDir -Force }
}
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($machinePath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$InstallDir", 'Machine')
}
if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path += ";$InstallDir" }
Ok "Installed $Exe"

# The sign-in port must be free for the agent.
$busy = Get-NetTCPConnection -LocalPort $ListenPort -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -and ((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path -ne $Exe) } |
    Select-Object -First 1
if ($busy) {
    $who = (Get-Process -Id $busy.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    throw "Port $ListenPort is already used by '$who'. Stop that program, or install with -ListenPort <another port> and forward your router's port $PublicPort to it."
}

# Any user can create folders in ProgramData, so one made in advance would
# stay theirs. Refuse links, take ownership, and replace every ACL entry.
if (Test-Path $DataDir) {
    $item = Get-Item $DataDir -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$DataDir is a junction or symlink. Remove it and run this again." }
    Get-ChildItem $DataDir -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
        ForEach-Object { throw "$($_.FullName) is a junction or symlink. Remove it and run this again." }
} else {
    New-Item -ItemType Directory -Path $DataDir | Out-Null
}
foreach ($icaclsArgs in @(
        @('/setowner', '*S-1-5-32-544', '/T', '/C', '/Q'),
        @('/reset', '/T', '/C', '/Q'),
        @('/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '/T', '/C', '/Q'))) {
    & icacls.exe $DataDir @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure $DataDir (icacls $($icaclsArgs -join ' '))" }
}
Ok "Data folder $DataDir (SYSTEM + Administrators only)"

# ---------------------------------------------------------------------------
# What this PC looked like before RDP Gate, so Uninstall can put it back.
# Taken once: running Setup again (upgrades) keeps the original.
$Backup = Join-Path $DataDir 'pre-install.json'
if (-not (Test-Path $Backup)) {
    Step 'Recording the current settings (Uninstall can restore them)'
    function Get-RegValue($Path, $Name) {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($v) { return [int]$v.$Name } else { return $null }
    }
    # secedit's export uses fixed key names; "net accounts" output is translated.
    $inf = Join-Path $env:TEMP "rdpgate-secpol-$PID.inf"
    & secedit.exe /export /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
    $secpol = @{}
    if (Test-Path $inf) {
        Get-Content $inf | ForEach-Object { if ($_ -match '^\s*(LockoutBadCount|ResetLockoutCount|LockoutDuration)\s*=\s*(-?\d+)') { $secpol[$Matches[1]] = [int]$Matches[2] } }
        Remove-Item $inf -Force -ErrorAction SilentlyContinue
    }
    $credsspKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
    $standby = Get-SleepTimeouts 'STANDBYIDLE'
    $hib     = Get-SleepTimeouts 'HIBERNATEIDLE'
    $before = [ordered]@{
        Taken            = (Get-Date).ToString('o')
        FirewallProfiles = @(Get-NetFirewallProfile | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)"; DefaultInboundAction = "$($_.DefaultInboundAction)" } })
        # Rules that let Remote Desktop in now; Setup or the service disables them.
        RdpRules         = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -notlike 'RDPGate-*' -and ($_.Group -eq '@FirewallAPI.dll,-28752' -or (Test-ExposesRdp $_ $rdpPort)) } |
            ForEach-Object { $_.Name })
        DenyTSConnections  = Get-RegValue $TsKey 'fDenyTSConnections'
        UserAuthentication = Get-RegValue $RdpTcpKey 'UserAuthentication'
        SecurityLayer      = Get-RegValue $RdpTcpKey 'SecurityLayer'
        MinEncryptionLevel = Get-RegValue $RdpTcpKey 'MinEncryptionLevel'
        CredSspOracle      = Get-RegValue $credsspKey 'AllowEncryptionOracle'
        CredSspKeyExisted  = [bool](Test-Path $credsspKey)
        TermServiceStart   = "$((Get-Service TermService).StartType)"
        LockoutThreshold   = $secpol['LockoutBadCount']
        LockoutWindow      = $secpol['ResetLockoutCount']
        LockoutDuration    = $secpol['LockoutDuration']
        StandbyAcSeconds   = if ($standby) { [int64]$standby.AC } else { $null }
        HibernateAcSeconds = if ($hib) { [int64]$hib.AC } else { $null }
    }
    $before | ConvertTo-Json -Depth 4 | Set-Content -Path $Backup -Encoding UTF8
    Ok "Saved to $Backup"
}

# ---------------------------------------------------------------------------
if ($deferred) {
    Step 'Turning the firewall on and opening the sign-in port (Remote Desktop stays reachable for now)'
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })
    if ($off) {
        # Turning the firewall on would cut this session off without a rule
        # for Remote Desktop. This temporary one is removed at lock-down;
        # its display name deliberately doesn't start with "RDPGate-" so
        # every exposure check still sees it.
        Get-NetFirewallRule -Name 'RDPGate-Temp-KeepRdp' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name 'RDPGate-Temp-KeepRdp' -DisplayName 'Remote Desktop (kept open by RDP Gate Setup until the first sign-in)' `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rdpPort -Profile Any | Out-Null
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        Ok "Firewall turned on for: $(($off | ForEach-Object { $_.Name }) -join ', '); Remote Desktop kept reachable until the first sign-in"
    }
} else {
    Step 'Locking down Windows Firewall (this can take a minute)'
    Get-NetFirewallRule -Name 'RDPGate-Temp-KeepRdp' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $wasOff = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
    if ($wasOff) { Warn "Windows Firewall was off for: $($wasOff -join ', '). Turning it on." }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    $disabled = 0
    Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue |   # built-in "Remote Desktop" group
        Where-Object { $_.Enabled -eq 'True' } |
        ForEach-Object { $_ | Disable-NetFirewallRule; $disabled++ }
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notlike 'RDPGate-*' -and (Test-ExposesRdp $_ $rdpPort) } |
        ForEach-Object { Write-Host "    disabling rule: $($_.DisplayName)"; $_ | Disable-NetFirewallRule; $disabled++ }
}
Get-NetFirewallRule -DisplayName 'RDPGate-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'RDPGate-Portal' -DisplayName 'RDPGate-Portal (HTTPS sign-in)' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort $ListenPort -Program $Exe -Profile Any | Out-Null
if (-not $deferred) { Ok "Inbound blocked by default; $disabled rule(s) that exposed Remote Desktop disabled" }
Ok "TCP $ListenPort allowed for rdpgate-server.exe only"

# The effective policy includes Group Policy, which can't be changed here.
$profiles = Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -eq 'Allow' }
$stillOpen = Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -notlike 'RDPGate-*' -and (Test-ExposesRdp $_ $rdpPort) }
if ($deferred) {
    # Expected for now; the service locks these down after the first sign-in.
    $n = @($profiles).Count + @($stillOpen).Count
    if ($n) { Ok "$n firewall setting(s) still let Remote Desktop in; they're closed after the first sign-in" }
} elseif ($profiles -or $stillOpen) {
    $names = @($profiles | ForEach-Object { "profile $($_.Name)" }) + @($stillOpen | ForEach-Object { "rule '$($_.DisplayName)' ($($_.PolicyStoreSourceType))" })
    throw "Group Policy still exposes Remote Desktop: $($names -join '; '). Change that policy, then run this again. Remote Desktop was NOT turned on."
}

# ---------------------------------------------------------------------------
Step 'Turning on Remote Desktop (hardened)'
try {
    Set-ItemProperty -Path $RdpTcpKey -Name UserAuthentication -Value 1 -Type DWord   # Network Level Authentication
    Set-ItemProperty -Path $RdpTcpKey -Name SecurityLayer      -Value 2 -Type DWord   # TLS only
    Set-ItemProperty -Path $RdpTcpKey -Name MinEncryptionLevel -Value 3 -Type DWord   # High
    $credssp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
    New-Item -Path $credssp -Force | Out-Null
    Set-ItemProperty -Path $credssp -Name AllowEncryptionOracle -Value 0 -Type DWord  # refuse unpatched CredSSP clients
    Set-ItemProperty -Path $TsKey -Name fDenyTSConnections -Value 0 -Type DWord
    Set-Service TermService -StartupType Automatic
    Start-Service TermService -ErrorAction SilentlyContinue
} catch {
    Set-ItemProperty -Path $TsKey -Name fDenyTSConnections -Value 1 -Type DWord
    throw "Turning on Remote Desktop failed, so it was turned off again: $_"
}
if ($deferred) { Ok "Remote Desktop on: NLA required, TLS, port $rdpPort (closed to others after the first sign-in)" }
else { Ok "Remote Desktop on: NLA required, TLS, port $rdpPort, reachable only after sign-in" }

# ---------------------------------------------------------------------------
if (-not $SkipLockout) {
    Step 'Account lockout policy'
    & net.exe accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15 | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok '10 wrong passwords lock an account for 15 minutes' }
    else { Warn 'Could not set the lockout policy (domain policy may control it).' }
}

# ---------------------------------------------------------------------------
Step 'Sleep settings'
# The service keeps this PC awake while someone is signed in. Before that, a
# sleeping PC can't answer a sign-in, and nothing on the internet can wake it.
$sleep     = Get-SleepTimeouts 'STANDBYIDLE'
$hibernate = Get-SleepTimeouts 'HIBERNATEIDLE'
# PCSystemType 2 = mobile. (Win32_Battery would also count a desktop's UPS.)
$isLaptop  = (Get-CimInstance Win32_ComputerSystem).PCSystemType -eq 2

$sleepAc     = if ($sleep)     { $sleep.AC }     else { 0 }
$hibernateAc = if ($hibernate) { $hibernate.AC } else { 0 }
$idleMinutes = [math]::Ceiling((@($sleepAc, $hibernateAc) | Where-Object { $_ -gt 0 } | Measure-Object -Minimum).Minimum / 60)
$unreachable = "it can't be reached while asleep. Change it under Settings > System > Power"

if ($sleepAc -eq 0 -and $hibernateAc -eq 0) {
    Ok 'This PC never sleeps on mains power'
} elseif ($SkipSleep) {
    Warn "Left as is (-SkipSleep): this PC sleeps after $idleMinutes min idle, and $unreachable."
} elseif ($isLaptop) {
    # Laptops: never sleeping can drain the battery or overheat one in a bag.
    Warn "This is a laptop and sleeps after $idleMinutes min idle on mains power; $unreachable."
} else {
    # Mains power only: battery settings are left alone.
    $failed = $false
    if ($sleepAc -gt 0)     { & powercfg.exe /change standby-timeout-ac 0;   if ($LASTEXITCODE -ne 0) { $failed = $true } }
    if ($hibernateAc -gt 0) { & powercfg.exe /change hibernate-timeout-ac 0; if ($LASTEXITCODE -ne 0) { $failed = $true } }
    if ($failed) { Warn "Could not change the power plan (Group Policy may control it); this PC sleeps after $idleMinutes min idle." }
    else { Ok "Never sleeps or hibernates on mains power (was $idleMinutes min idle); skip with -SkipSleep" }
}

# ---------------------------------------------------------------------------
Step 'Configuring RDP Gate'
if (-not (Test-Path (Join-Path $DataDir 'config.json'))) {
    $initArgs = @('init', '--data', $DataDir, '--public-port', $PublicPort, '--listen', "0.0.0.0:$ListenPort", '--rdp-port', $rdpPort)
    if ($RdpPublicPort -gt 0) { $initArgs += @('--rdp-public-port', $RdpPublicPort) }
    if ($AllowUdp)          { $initArgs += '--allow-udp' }
    if ($NoUpnp)            { $initArgs += '--no-upnp' }
    if ($Staging)           { $initArgs += '--staging' }
    & $Exe @initArgs
    if ($LASTEXITCODE -ne 0) { throw 'rdpgate-server init failed' }
} else {
    Ok "Keeping existing configuration in $DataDir"
}

$cfg = Get-Content (Join-Path $DataDir 'config.json') -Raw | ConvertFrom-Json
$hasBeacon = $cfg.PSObject.Properties.Name -contains 'beacon'
if (-not $hasBeacon -and -not $NoBeacon) {
    Write-Host ""
    Write-Host "    Your computers find this PC through an encrypted, signed beacon in a secret GitHub gist."
    Write-Host "    The gist only holds ciphertext, but GitHub sees the IP address each update comes from."
    Write-Host "    You need a token limited to Gists (read and write), ideally on a GitHub account used only for this."
    & $Exe beacon-setup --data $DataDir
    if ($LASTEXITCODE -ne 0) { Warn 'Beacon not set up. Run "rdpgate-server beacon-setup" later.' }
}

# In this window rather than on Setup's last page, where the step was easy to
# miss and, after a reinstall that kept the data folder, only printed an error.
$st = Get-Content (Join-Path $DataDir 'state.json') -Raw | ConvertFrom-Json
$totpOn = $st.PSObject.Properties.Name -contains 'totp'
if ($totpOn) {
    Step '6-digit codes'
    Ok 'Already set up (kept from an earlier install). New phone: rdpgate-server totp-setup --force'
} elseif (-not $NoTotp) {
    Step 'Setting up 6-digit codes (scan the QR code with your authenticator app)'
    & $Exe totp-setup --data $DataDir
    $totpOn = $LASTEXITCODE -eq 0
    if (-not $totpOn) { Warn '6-digit codes not set up. Run "rdpgate-server totp-setup" later.' }
}

# Tell the service whether it still has to lock Remote Desktop down.
if ($deferred) { & $Exe protect --data $DataDir --after-sign-in | Out-Null }
else { & $Exe protect --data $DataDir --already-applied | Out-Null }
if ($LASTEXITCODE -ne 0) { throw 'Could not record the protection setting' }

if (Get-Service RDPGate -ErrorAction SilentlyContinue) { & $Exe service-uninstall | Out-Null }
& $Exe service-install --data $DataDir
if ($LASTEXITCODE -ne 0) { throw 'service-install failed' }
if ($Lan -ne 'Keep') {
    # Restarts the service so the beacon includes (or drops) this PC's local address.
    & $Exe lan $Lan.ToLower() --data $DataDir | ForEach-Object { Ok $_ }
    if ($LASTEXITCODE -ne 0) { Warn "Could not change sign-in from this network. Run: rdpgate-server lan $($Lan.ToLower())" }
}
Start-Sleep -Seconds 3
$state = (Get-Service RDPGate).Status
if ($state -ne 'Running') { Warn "Service state is $state. Check $DataDir\logs\rdpgate.log" } else { Ok 'Service RDPGate is running' }

# ---------------------------------------------------------------------------
$routerDone = $false
if (-not $NoUpnp) {
    Step 'Setting up your router (UPnP)'
    & $Exe router --data $DataDir | ForEach-Object { Write-Host "    $_" }
    $routerDone = ($LASTEXITCODE -eq 0)
}

# ---------------------------------------------------------------------------
if ($PublicHost -or $DomainSetup) {
    Step 'Browser sign-in with your domain (guided)'
    $domainArgs = @('domain-setup', '--data', $DataDir)
    if ($PublicHost) { $domainArgs += @('--host', $PublicHost) }
    if ($Email)      { $domainArgs += @('--email', $Email) }
    & $Exe @domainArgs
    if ($LASTEXITCODE -ne 0) { Warn 'Browser sign-in is not set up. Run "rdpgate-server domain-setup" later.' }
}

# ---------------------------------------------------------------------------
$lan = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.PrefixOrigin -in 'Dhcp', 'Manual' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
$thumb = (Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction SilentlyContinue).SSLCertificateSHA1Hash
$rdpExt = if ($RdpPublicPort -gt 0) { $RdpPublicPort } else { $rdpPort }
$udpLine = if ($AllowUdp) { "`n     UDP $rdpExt  ->  $($lan):$rdpPort   (faster Remote Desktop)" } else { '' }

Write-Host ""
Write-Host "RDP Gate is installed." -ForegroundColor Green
$routerStep = if ($routerDone) {
    "1. Your router was set up automatically (the service keeps it that way). In the router's`n   settings, give this PC ($lan) a reserved address so the forwards keep pointing at it."
} else {
    "1. On your router, forward these ports to this PC ($lan) and give it a reserved address:`n     TCP $PublicPort   ->  $($lan):$ListenPort    (sign-in)`n     TCP $rdpExt  ->  $($lan):$rdpPort   (Remote Desktop: closed until someone signs in)$udpLine"
}
$fwText = if ($deferred) {
    "Windows Firewall: TCP $ListenPort is open for RDP Gate. Remote Desktop is still reachable as`nbefore, so this session keeps working. As soon as a computer signs in through RDP Gate`nand connects, the service closes Remote Desktop to everyone else (or run: rdpgate-server protect)."
} else {
    "Windows Firewall is configured: TCP $ListenPort is open for RDP Gate only, and Remote`nDesktop stays closed until someone signs in. The service re-checks this at every start."
}
$totpStep = if ($totpOn) {
    "2. 6-digit codes are set up. For a new phone: rdpgate-server totp-setup --force"
} else {
    "2. Set up 6-digit codes (scan the QR code with your phone):`n     rdpgate-server totp-setup"
}
Write-Host @"

$fwText

$routerStep

$totpStep

3. On each Mac or PC, install the RDP Gate app and set it up. Run the
   "rdpgate-server device-add ..." command it shows you here, then paste the
   server card this prints back into the app.

4. Test from outside your network (for example a phone hotspot).

Remote Desktop certificate thumbprint (the app also checks this automatically):
     $thumb
Status: rdpgate-server status      Logs: $DataDir\logs\rdpgate.log
"@
if (-not ($PublicHost -or $DomainSetup)) { Write-Host "Browser sign-in (optional): rdpgate-server domain-setup" }
if ($FromInstaller) { Read-Host "`nPress Enter to finish" | Out-Null }
