<#
.SYNOPSIS
    Removes RDP Gate from this PC.

.DESCRIPTION
    Stops and deletes the RDPGate service and removes every RDPGate firewall
    rule. Remote Desktop stays blocked from the network afterwards unless you
    pass -RestoreRdpRules, which re-enables the built-in "Remote Desktop"
    firewall rules (only do that if RDP is NOT reachable from the internet).

.EXAMPLE
    .\uninstall-server.ps1 -RemoveData
#>
[CmdletBinding()]
param(
    # Also delete C:\ProgramData\RDPGate (devices, passkeys, TOTP secret, logs)
    [switch] $RemoveData,
    # Re-enable the built-in Windows "Remote Desktop" firewall rules
    [switch] $RestoreRdpRules
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'RDPGate'
$DataDir    = Join-Path $env:ProgramData 'RDPGate'

if (Get-Service RDPGate -ErrorAction SilentlyContinue) {
    Stop-Service RDPGate -Force -ErrorAction SilentlyContinue
    & sc.exe delete RDPGate | Out-Null
    Write-Host 'Service removed.'
}
Get-NetFirewallRule -DisplayName 'RDPGate-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host 'Firewall rules removed.'

if ($RestoreRdpRules) {
    Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
    Write-Host 'Built-in Remote Desktop firewall rules re-enabled.' -ForegroundColor Yellow
} else {
    Write-Host 'Remote Desktop stays blocked from the network (use -RestoreRdpRules to undo).'
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$newPath = (($machinePath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')

if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item $DataDir -Recurse -Force
    Write-Host "Deleted $DataDir"
} elseif (Test-Path $DataDir) {
    Write-Host "Kept $DataDir (use -RemoveData to delete it)."
}
Write-Host 'RDP Gate uninstalled.' -ForegroundColor Green
