; RDP Gate client installer (Inno Setup 6).
; Build: ISCC /DAppVersion=0.2.0 /DSourceDir=<folder with "RDP Gate.exe" and rdpgate.exe> /DOutputDir=<out> client.iss
;
; Installs for the current user (no administrator needed) into
; %LOCALAPPDATA%\Programs\RDP Gate, which also lets the app update itself.

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
AppId={{4A703DD9-1E35-4BC0-97F5-543BA6E61C9A}
AppName=RDP Gate
AppVersion={#AppVersion}
AppVerName=RDP Gate {#AppVersion}
AppPublisher=RDP Gate
AppPublisherURL=https://github.com/parthh37/rdpgate
AppSupportURL=https://github.com/parthh37/rdpgate/issues
AppUpdatesURL=https://github.com/parthh37/rdpgate/releases
DefaultDirName={autopf}\RDP Gate
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=RDP-Gate-Setup-{#AppVersion}
SetupIconFile=rdpgate.ico
UninstallDisplayIcon={app}\rdpgate.ico
LicenseFile=..\..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "addtopath"; Description: "Add the rdpgate command-line tool to PATH"; Flags: unchecked

[Files]
Source: "{#SourceDir}\RDP Gate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\rdpgate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "rdpgate.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\RDP Gate"; Filename: "{app}\RDP Gate.exe"; IconFilename: "{app}\rdpgate.ico"
Name: "{autodesktop}\RDP Gate"; Filename: "{app}\RDP Gate.exe"; IconFilename: "{app}\rdpgate.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\RDP Gate.exe"; Description: "{cm:LaunchProgram,RDP Gate}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\*.old.exe"
Type: files; Name: "{app}\*.new.exe"
Type: files; Name: "{app}\RDP Gate.rdp"

[Code]
function NeedsAddPath(Dir: String): Boolean;
var
  Current: String;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

// Take our folder back out of the user's PATH on uninstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Current, Dir: String;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
    exit;
  Dir := ExpandConstant('{app}');
  P := Pos(';' + Uppercase(Dir), Uppercase(Current));
  if P > 0 then
  begin
    Delete(Current, P, Length(Dir) + 1);
    RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current);
  end;
end;
