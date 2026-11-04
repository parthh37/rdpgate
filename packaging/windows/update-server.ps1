<#
.SYNOPSIS
    Checks for a signed RDP Gate Server update and offers to install it.

.DESCRIPTION
    For checking from PowerShell (RDP Gate Server does the same from its
    Overview, without a console). Asks for
    Administrator rights, shows the installed and the newest version, and
    installs after you confirm. Installing restarts the RDPGate service on
    the new version; computers signed in right now keep their access and
    Remote Desktop sessions through RDP Gate stay connected.

    The service also updates itself once a day; this is for checking or
    updating sooner.
#>
[CmdletBinding()]
param()

# Not 'Stop': in Windows PowerShell, the program's error lines on stderr
# would end the script before you could read them.
$Exe = Join-Path $PSScriptRoot 'rdpgate-server.exe'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ErrorAction Stop
    } catch {
        Write-Host 'Checking for updates needs Administrator rights.' -ForegroundColor Yellow
        Read-Host 'Press Enter to close' | Out-Null
    }
    exit
}

Write-Host "RDP Gate Server: checking for updates...`n"
$out = & $Exe update --check 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host "  $_" }

if ($code -eq 0 -and ($out -match '^Available:')) {
    Write-Host "`nInstalling restarts the RDP Gate service on the new version. Computers signed in right now"
    Write-Host 'keep their access, and Remote Desktop sessions through RDP Gate stay connected.'
    Write-Host 'If you leave it, the service installs it by itself within a day.'
    if ((Read-Host "`nInstall now? [Y/n]") -notmatch '^(n|no)$') {
        Write-Host ''
        & $Exe update 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
}

Read-Host "`nPress Enter to close" | Out-Null
