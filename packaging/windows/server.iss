; RDP Gate Server installer (Inno Setup 6).
; Build: ISCC /DAppVersion=0.2.0 /DSourceDir=<folder with rdpgate-server.exe> /DOutputDir=<out> server.iss
;
; Installs to C:\Program Files\RDPGate, then runs install-server.ps1, which
; secures the data folder, locks down Windows Firewall, turns on hardened
; Remote Desktop and starts the RDPGate service.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\target\release"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{A5FE3D7B-0A22-4ED0-A6B0-89CFE28791B3}
AppName=RDP Gate Server
AppVersion={#AppVersion}
AppVerName=RDP Gate Server {#AppVersion}
AppPublisher=RDP Gate
AppPublisherURL=https://github.com/parthh37/rdpgate
AppSupportURL=https://github.com/parthh37/rdpgate/issues
AppUpdatesURL=https://github.com/parthh37/rdpgate/releases
; install-server.ps1 expects this exact folder.
DefaultDirName={autopf}\RDPGate
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=RDP-Gate-Server-Setup-{#AppVersion}
SetupIconFile=rdpgate.ico
UninstallDisplayIcon={app}\rdpgate.ico
UninstallDisplayName=RDP Gate Server
LicenseFile=..\..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Messages]
WelcomeLabel2=This installs the RDP Gate agent on this PC and configures Windows Firewall (and, if it allows it, your router) for you.%n%nRemote Desktop will stay closed to the internet. It opens only for a computer you enrolled, after it signs in with its key and a 6-digit code (or a passkey), and only for that computer's IP address.%n%nWindows Home is not supported (it cannot accept Remote Desktop connections).

[Tasks]
Name: "beacon"; Description: "Set up the encrypted IP beacon now (asks for a Gists-only GitHub token, ideally from an account used only for this)"
Name: "router"; Description: "Forward ports on my router automatically (UPnP), if the router allows it"
Name: "lockout"; Description: "Set an account lockout policy (10 wrong passwords lock an account for 15 minutes)"
Name: "awake"; Description: "Stop this PC sleeping on mains power, so it can always be reached (on a laptop: only a warning)"
Name: "udp"; Description: "Also open UDP for Remote Desktop (faster, but UDP senders can be forged)"; Flags: unchecked

[Files]
Source: "{#SourceDir}\rdpgate-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "install-server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall-server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "rdpgate.ico"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "{code:HardenParams}"; StatusMsg: "Hardening Remote Desktop and starting the RDP Gate service..."; Flags: waituntilterminated
Filename: "{cmd}"; Parameters: "/c """"{app}\rdpgate-server.exe"" totp-setup & pause"""; Description: "Set up 6-digit codes now (shows a QR code for your phone)"; Flags: postinstall waituntilterminated
Filename: "https://parthh37.github.io/rdpgate/guide.html#client"; Description: "Open the guide for enrolling your computers"; Flags: postinstall shellexec nowait unchecked

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall-server.ps1"" -FromInstaller"; RunOnceId: "RDPGateUninstall"; Flags: waituntilterminated runhidden

[UninstallDelete]
Type: files; Name: "{app}\*.old.exe"
Type: files; Name: "{app}\*.new.exe"

[Code]
var
  HostPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  HostPage := CreateInputQueryPage(wpSelectTasks,
    'Browser sign-in (optional)',
    'Do you also want to sign in from a web browser with a passkey?',
    'Browsers only use passkeys with a domain name you own that points at this network, for example rdp.example.com.' + #13#10 + #13#10 +
    'Leave this empty to use the RDP Gate app only. No domain name is needed for that.');
  HostPage.Add('Domain name (optional):', False);
end;

// Letters, digits, dots and dashes only, with at least one dot. This also
// keeps the value safe to pass on the PowerShell command line.
function ValidHost(H: String): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := (Length(H) > 3) and (Length(H) < 254) and (Pos('.', H) > 1);
  for I := 1 to Length(H) do
  begin
    C := H[I];
    if not (((C >= 'a') and (C <= 'z')) or ((C >= 'A') and (C <= 'Z')) or ((C >= '0') and (C <= '9')) or (C = '.') or (C = '-')) then
      Result := False;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  H: String;
begin
  Result := True;
  if CurPageID = HostPage.ID then
  begin
    H := Trim(HostPage.Values[0]);
    if (H <> '') and not ValidHost(H) then
    begin
      MsgBox('Enter a domain name like rdp.example.com, or leave it empty.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function HardenParams(Param: String): String;
var
  H: String;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\install-server.ps1') + '" -FromInstaller';
  H := Trim(HostPage.Values[0]);
  if (H <> '') and ValidHost(H) then
    Result := Result + ' -PublicHost ' + H;
  if not WizardIsTaskSelected('beacon') then
    Result := Result + ' -NoBeacon';
  if not WizardIsTaskSelected('router') then
    Result := Result + ' -NoUpnp';
  if not WizardIsTaskSelected('lockout') then
    Result := Result + ' -SkipLockout';
  if not WizardIsTaskSelected('awake') then
    Result := Result + ' -SkipSleep';
  if WizardIsTaskSelected('udp') then
    Result := Result + ' -AllowUdp';
end;

// Stop the running service so its executable can be replaced on upgrade.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop RDPGate', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(3000);
  Result := '';
end;
