<#
.SYNOPSIS
    Removes RDP Gate from this PC.

.DESCRIPTION
    Stops and deletes the RDPGate service and removes every RDPGate firewall
    rule.

    With -Restore it also undoes what Setup changed, from the record Setup
    made before its first change (C:\ProgramData\RDPGate\pre-install.json):
    Windows Firewall profiles and the rules that let Remote Desktop in,
    Remote Desktop's settings, the account lockout policy, the sleep timeouts
    on mains power, and the port forwards RDP Gate added on the router. If
    Remote Desktop was reachable from the internet before, it will be again.

    Without -Restore, Remote Desktop stays blocked from the network.
    -RestoreRdpRules only re-enables the built-in "Remote Desktop" firewall
    rules (for installs older than the record).

.EXAMPLE
    .\uninstall-server.ps1 -Restore

.EXAMPLE
    .\uninstall-server.ps1 -Restore -RemoveData
#>
[CmdletBinding()]
param(
    # Undo the changes Setup made, from the record it kept
    [switch] $Restore,
    # Also delete C:\ProgramData\RDPGate (devices, passkeys, TOTP secret, logs)
    [switch] $RemoveData,
    # Re-enable the built-in Windows "Remote Desktop" firewall rules
    [switch] $RestoreRdpRules,
    # Run by the Setup uninstaller, which removes the program files itself
    [switch] $FromInstaller
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'RDPGate'
$DataDir    = Join-Path $env:ProgramData 'RDPGate'
$Exe        = Join-Path $InstallDir 'rdpgate-server.exe'
$Backup     = Join-Path $DataDir 'pre-install.json'
$TsKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RdpTcpKey  = "$TsKey\WinStations\RDP-Tcp"
$CredSspKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'

# Puts a DWORD back, or deletes it if it didn't exist before.
function Restore-Value($Path, $Name, $Value) {
    if ($null -eq $Value) { Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -Type DWord }
}

# One step failing shouldn't stop the rest from being put back.
function Try-Step($What, [scriptblock] $Do) {
    try { & $Do; Write-Host "  restored: $What" }
    catch { Write-Host "  could not restore $($What): $_" -ForegroundColor Yellow }
}

# Everyone's tray icon, so its file can be deleted (it would show "not installed").
Get-Process rdpgate-tray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Restore first, while the service still holds any open grant: this way a
# session that came through RDP Gate is kept if the old rules allow it.
$restored = $false
if ($Restore -and (Test-Path $Backup)) {
    $b = Get-Content $Backup -Raw | ConvertFrom-Json
    Write-Host "Restoring the settings from before RDP Gate ($($b.Taken)):"

    Try-Step 'Windows Firewall profiles' {
        foreach ($p in @($b.FirewallProfiles)) {
            Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.DefaultInboundAction
        }
    }
    Try-Step "$(@($b.RdpRules).Count) Remote Desktop firewall rule(s)" {
        foreach ($n in @($b.RdpRules)) { Enable-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
    }
    Try-Step 'Remote Desktop settings' {
        Restore-Value $RdpTcpKey 'UserAuthentication' $b.UserAuthentication
        Restore-Value $RdpTcpKey 'SecurityLayer'      $b.SecurityLayer
        Restore-Value $RdpTcpKey 'MinEncryptionLevel' $b.MinEncryptionLevel
        if ($b.CredSspKeyExisted) { Restore-Value $CredSspKey 'AllowEncryptionOracle' $b.CredSspOracle }
        elseif (Test-Path $CredSspKey) { Remove-ItemProperty -Path $CredSspKey -Name 'AllowEncryptionOracle' -ErrorAction SilentlyContinue }
        # Turning Remote Desktop off would cut off a session this runs in.
        $overRdp = "$env:SESSIONNAME" -like 'RDP-Tcp*'
        if ($b.DenyTSConnections -eq 1 -and $overRdp) {
            Write-Host '  Remote Desktop was off before, but you are connected through it: left on. Turn it off in Settings > System > Remote Desktop.' -ForegroundColor Yellow
        } else {
            Restore-Value $TsKey 'fDenyTSConnections' $b.DenyTSConnections
        }
        if ($b.TermServiceStart) { Set-Service TermService -StartupType $b.TermServiceStart }
    }
    if ($null -ne $b.LockoutThreshold) {
        Try-Step 'account lockout policy' {
            & net.exe accounts "/lockoutthreshold:$($b.LockoutThreshold)" | Out-Null
            if ($b.LockoutThreshold -gt 0 -and $null -ne $b.LockoutDuration -and $null -ne $b.LockoutWindow) {
                # The window may not be longer than the duration: set the duration first.
                & net.exe accounts "/lockoutduration:$($b.LockoutDuration)" | Out-Null
                & net.exe accounts "/lockoutwindow:$($b.LockoutWindow)" | Out-Null
            }
            if ($LASTEXITCODE -ne 0) { throw 'net accounts failed (domain policy may control it)' }
        }
    }
    Try-Step 'sleep settings on mains power' {
        if ($null -ne $b.StandbyAcSeconds)   { & powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE $b.StandbyAcSeconds }
        if ($null -ne $b.HibernateAcSeconds) { & powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE $b.HibernateAcSeconds }
        & powercfg.exe /setactive SCHEME_CURRENT
    }
    if (Test-Path $Exe) {
        Try-Step 'router port forwards' { & $Exe router --remove | ForEach-Object { Write-Host "    $_" } }
    }
    Remove-Item $Backup -Force -ErrorAction SilentlyContinue
    $restored = $true
} elseif ($Restore) {
    Write-Host 'No record of the settings from before RDP Gate (installed by an older version), so they are left as they are.' -ForegroundColor Yellow
    if (Test-Path $Exe) { & $Exe router --remove | ForEach-Object { Write-Host "  $_" } }
}

# ---------------------------------------------------------------------------
Get-ScheduledTask -TaskPath '\RDPGate\' -TaskName 'Watchdog' -ErrorAction SilentlyContinue |
    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
if (Get-Service RDPGate -ErrorAction SilentlyContinue) {
    Stop-Service RDPGate -Force -ErrorAction SilentlyContinue
    & sc.exe delete RDPGate | Out-Null
    Write-Host 'Service removed.'
}
Get-NetFirewallRule -DisplayName 'RDPGate-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -Name 'RDPGate-Temp-KeepRdp' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host 'Firewall rules removed.'

if ($RestoreRdpRules) {
    Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
    Write-Host 'Built-in Remote Desktop firewall rules re-enabled.' -ForegroundColor Yellow
} elseif (-not $restored) {
    Write-Host 'Remote Desktop stays blocked from the network (use -Restore to undo Setup''s changes).'
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$newPath = (($machinePath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')

if (-not $FromInstaller -and (Test-Path $InstallDir)) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item $DataDir -Recurse -Force
    Write-Host "Deleted $DataDir"
} elseif (Test-Path $DataDir) {
    Write-Host "Kept $DataDir (use -RemoveData to delete it)."
}
Write-Host 'RDP Gate uninstalled.' -ForegroundColor Green
