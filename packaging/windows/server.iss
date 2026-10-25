; RDP Gate Server installer (Inno Setup 6).
; Build: ISCC /DAppVersion=0.2.0 /DSourceDir=<folder with rdpgate-server.exe> /DOutputDir=<out> server.iss
;
; Installs to C:\Program Files\RDPGate, then runs install-server.ps1 with no
; window, which secures the data folder, locks down Windows Firewall (now, or
; after the first sign-in when installing over Remote Desktop), turns on
; hardened Remote Desktop and starts the RDPGate service. Nothing is typed
; into a console: RDP Gate Server opens at the end to finish setting up (the
; beacon, 6-digit codes, computers and, if chosen, browser sign-in).

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
Name: "domain"; Description: "Also sign in from a web browser with a passkey, using my own domain name (set up in RDP Gate Server after Setup)"; Flags: unchecked
Name: "lan"; Description: "Also allow sign-in from computers on my home network (for example a laptop on the same Wi-Fi)"; Flags: unchecked
Name: "router"; Description: "Forward ports on my router automatically (UPnP), if the router allows it"
Name: "lockout"; Description: "Set an account lockout policy (10 wrong passwords lock an account for 15 minutes)"
Name: "awake"; Description: "Stop this PC sleeping on mains power, so it can always be reached (on a laptop: only a warning)"
Name: "udp"; Description: "Also open UDP for Remote Desktop (faster, but UDP senders can be forged)"; Flags: unchecked
Name: "desktopicon"; Description: "Put an RDP Gate Server icon on the desktop"
Name: "trayicon"; Description: "Show the service's status in the notification area (next to the clock) when anyone signs in"

[Files]
Source: "{#SourceDir}\rdpgate-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\RDP Gate Server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\rdpgate-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "install-server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall-server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "update-server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "rdpgate.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; The window for managing the server: computers, codes, network, updates.
Name: "{autoprograms}\RDP Gate Server"; Filename: "{app}\RDP Gate Server.exe"; WorkingDir: "{app}"; IconFilename: "{app}\rdpgate.ico"; Comment: "Manage RDP Gate on this PC"
Name: "{autodesktop}\RDP Gate Server"; Filename: "{app}\RDP Gate Server.exe"; WorkingDir: "{app}"; IconFilename: "{app}\rdpgate.ico"; Comment: "Manage RDP Gate on this PC"; Tasks: desktopicon
; The notification-area icon, for everyone who signs in. It runs without
; Administrator rights; RDP Gate Server asks for them when opened from it.
Name: "{commonstartup}\RDP Gate status"; Filename: "{app}\rdpgate-tray.exe"; WorkingDir: "{app}"; Comment: "Shows whether the RDP Gate service is running"; Tasks: trayicon
; Updates are checked and installed from RDP Gate Server's Overview (and by
; the service itself); update-server.ps1 stays in {app} for the command line.

[Run]
; install-server.ps1 and the tray icon start from [Code] (CurStepChanged), so a
; failure shows in a message rather than a console window.
Filename: "{app}\RDP Gate Server.exe"; Parameters: "{code:WindowParams}"; Description: "Open RDP Gate Server to finish setting up (finding this PC, 6-digit codes, your computers)"; Flags: postinstall shellexec nowait
Filename: "https://parthh37.github.io/rdpgate/guide.html#client"; Description: "Open the guide for enrolling your computers"; Flags: postinstall shellexec nowait unchecked

[UninstallDelete]
Type: files; Name: "{app}\*.old.exe"
Type: files; Name: "{app}\*.new.exe"

[Code]
var
  ProtectPage: TInputOptionWizardPage;
  HostPage: TInputQueryWizardPage;

// Setup is running inside a Remote Desktop session (SESSIONNAME=RDP-Tcp#N).
function OverRemoteDesktop: Boolean;
begin
  Result := Pos('RDP-TCP', Uppercase(GetEnv('SESSIONNAME'))) = 1;
end;

procedure InitializeWizard;
var
  Note: String;
begin
  if OverRemoteDesktop then
    Note := 'You are connected over Remote Desktop right now, so the second option is selected: the first would disconnect you, and no computer can sign in yet to get you back in.'
  else
    Note := 'Choose the second option if you might install or manage this PC over Remote Desktop before your computers are set up.';
  ProtectPage := CreateInputOptionPage(wpSelectTasks,
    'When to close Remote Desktop',
    'RDP Gate closes Remote Desktop to everyone who hasn''t signed in. When should that start?',
    'Closing it disconnects every Remote Desktop session that didn''t come through RDP Gate. With "after my first sign-in", Remote Desktop stays as it is until one of your computers has signed in through RDP Gate and connected; the service then closes it to everyone else by itself.' + #13#10 + #13#10 + Note,
    True, False);
  ProtectPage.Add('Now, during Setup (I''m sitting at this PC)');
  ProtectPage.Add('After my first sign-in through RDP Gate (keeps this session; closes automatically)');
  if OverRemoteDesktop then
    ProtectPage.SelectedValueIndex := 1
  else
    ProtectPage.SelectedValueIndex := 0;

  HostPage := CreateInputQueryPage(ProtectPage.ID,
    'Browser sign-in with your domain',
    'Which domain name should point at this PC?',
    'Browsers only use passkeys with a domain name, never an IP address. Before you continue you need:' + #13#10 +
    '  1. A domain you control, e.g. example.com (any registrar, or Cloudflare).' + #13#10 +
    '  2. A name under it for this PC, e.g. rdp.example.com. At the end of Setup, RDP Gate Server shows the' + #13#10 +
    '      exact DNS records to create (A for IPv4, AAAA for IPv6) and checks them for you.' + #13#10 +
    '  3. If your home addresses change: dynamic DNS ("DDNS") at your registrar or router to keep them current.' + #13#10 +
    '  4. A certificate for that name, as PEM files you renew (win-acme, or certbot with a DNS plugin).' + #13#10 +
    '      RDP Gate doesn''t fetch one itself: Let''s Encrypt only checks ports 80 and 443, which RDP Gate never uses.' + #13#10 +
    '  5. Port 47443 on your router reaching this PC (Setup does this when your router allows it).');
  HostPage.Add('Domain name (e.g. rdp.example.com):', False);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = HostPage.ID) and not WizardIsTaskSelected('domain');
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
  if CurPageID = ProtectPage.ID then
  begin
    if OverRemoteDesktop and (ProtectPage.SelectedValueIndex = 0) then
      Result := MsgBox('You are connected over Remote Desktop. Closing it now will disconnect you, and no computer can sign in through RDP Gate yet.' + #13#10 + #13#10 + 'Close Remote Desktop now anyway?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  end;
  if CurPageID = HostPage.ID then
  begin
    H := Trim(HostPage.Values[0]);
    if not ValidHost(H) then
    begin
      MsgBox('Enter a domain name like rdp.example.com, or go Back and untick browser sign-in.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

// The beacon, 6-digit codes and browser sign-in aren't set up here: the
// script asks nothing with -FromInstaller, and RDP Gate Server does them.
function HardenParams(ErrorFile: String): String;
begin
  Result := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\install-server.ps1') + '" -FromInstaller -ErrorFile "' + ErrorFile + '"';
  if ProtectPage.SelectedValueIndex = 1 then
    Result := Result + ' -Protect AfterSignIn'
  else
    Result := Result + ' -Protect Now';
  if WizardIsTaskSelected('lan') then
    Result := Result + ' -Lan On'
  else
    Result := Result + ' -Lan Off';
  if not WizardIsTaskSelected('router') then
    Result := Result + ' -NoUpnp';
  if not WizardIsTaskSelected('lockout') then
    Result := Result + ' -SkipLockout';
  if not WizardIsTaskSelected('awake') then
    Result := Result + ' -SkipSleep';
  if WizardIsTaskSelected('udp') then
    Result := Result + ' -AllowUdp';
end;

// RDP Gate Server opens on browser sign-in, filled in, when it was chosen.
// The values were checked on the domain page, so they're safe to pass.
function WindowParams(Param: String): String;
var
  H: String;
begin
  Result := '';
  if WizardIsTaskSelected('domain') then
  begin
    H := Trim(HostPage.Values[0]);
    Result := '--setup-domain';
    if ValidHost(H) then
      Result := Result + ' --host ' + H;
  end;
end;

// Hardens the PC with no window, then starts the tray icon as the person
// running Setup (rather than at their next sign-in).
procedure CurStepChanged(CurStep: TSetupStep);
var
  RC, I: Integer;
  ErrorFile, Msg: String;
  Lines: TArrayOfString;
begin
  if CurStep <> ssPostInstall then
    Exit;
  ErrorFile := ExpandConstant('{tmp}\install-error.txt');
  WizardForm.StatusLabel.Caption := 'Hardening Remote Desktop and starting the RDP Gate service...';
  WizardForm.FilenameLabel.Caption := 'This can take a minute.';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), HardenParams(ErrorFile), ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, RC) then
    RC := -1;
  if RC <> 0 then
  begin
    Msg := 'Windows PowerShell could not run the setup script.';
    if LoadStringsFromFile(ErrorFile, Lines) and (GetArrayLength(Lines) > 0) then
    begin
      Msg := '';
      for I := 0 to GetArrayLength(Lines) - 1 do
        Msg := Msg + Lines[I] + #13#10;
    end;
    SuppressibleMsgBox('RDP Gate could not finish setting up this PC:' + #13#10 + #13#10 + Trim(Msg) + #13#10 + #13#10 +
      'Details are in ' + ExpandConstant('{commonappdata}\RDPGate\logs\setup.log') + '. Fix the problem, then run RDP Gate Server Setup again.',
      mbError, MB_OK, IDOK);
  end
  else if WizardIsTaskSelected('trayicon') then
    ExecAsOriginalUser(ExpandConstant('{app}\rdpgate-tray.exe'), '', ExpandConstant('{app}'), SW_SHOWNORMAL, ewNoWait, RC);
end;

// ---- uninstall ---------------------------------------------------------------
var
  RestoreSettings: Boolean;

function InitializeUninstall(): Boolean;
begin
  // Silent uninstalls keep Remote Desktop blocked (the safe answer).
  RestoreSettings := SuppressibleMsgBox('Also put back the settings RDP Gate Setup changed?' + #13#10 + #13#10 +
    'Windows Firewall, the Remote Desktop firewall rules and settings, the account lockout policy, sleep on mains power, and the port forwards RDP Gate added on your router return to how they were before you installed it.' + #13#10 + #13#10 +
    'If Remote Desktop was reachable from the internet before, it will be again. Choose No to keep Remote Desktop blocked from the network.',
    mbConfirmation, MB_YESNO, IDNO) = IDYES;
  Result := True;
end;

// Runs before the program files are deleted: the script needs rdpgate-server.exe
// to remove the router forwards.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Params: String;
  RC: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\uninstall-server.ps1') + '" -FromInstaller';
    if RestoreSettings then
      Params := Params + ' -Restore';
    Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, RC);
  end;
end;

// Stop the running service so its executable can be replaced on upgrade.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  // The watchdog task would start the service again mid-upgrade; Setup re-enables it.
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Change /TN "\RDPGate\Watchdog" /DISABLE', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop RDPGate', '', SW_HIDE, ewWaitUntilTerminated, RC);
  // Everyone's tray icon, so its file can be replaced; Setup starts it again.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM rdpgate-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(3000);
  Result := '';
end;
