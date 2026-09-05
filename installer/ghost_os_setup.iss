; Ghost OS v1.0.0 - Inno Setup Script
; Generates GhostOS-Setup.exe installer

#define MyAppName "Ghost OS"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Ghost OS"
#define MyAppExeName "GhostOS.exe"
#define MyAUMID "GhostOS.SystemGuardian.v1"

[Setup]
AppId={{D8C8B190-7F89-4A99-8D88-E500A78E1100}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Ghost OS
DefaultGroupName=Ghost OS
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=GhostOS-Setup
SetupIconFile=..\assets\ghost_os.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=force
RestartApplications=no
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start Ghost OS automatically with Windows"; GroupDescription: "Windows Startup:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\GhostOS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs overwritereadonly

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\ghost_os.ico"; AppUserModelID: "{#MyAUMID}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\assets\ghost_os.ico"; AppUserModelID: "{#MyAUMID}"

[Registry]
; Register HKCU Run autostart key if task is selected
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "GhostOS"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; Flags: uninsdeletevalue

; Register AppUserModelId for Windows Action Center Toast Notifications
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\{#MyAUMID}"; ValueType: string; ValueName: "DisplayName"; ValueData: "{#MyAppName}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\{#MyAUMID}"; ValueType: string; ValueName: "IconUri"; ValueData: "{app}\assets\ghost_os.ico"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Ghost OS now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up app installation directory files on uninstall
Type: filesandordirs; Name: "{app}"

[Code]
// Helper function to stop any running GhostOS processes before install or uninstall
procedure StopRunningGhostProcess();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM GhostOS.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
end;

function InitializeSetup(): Boolean;
begin
  StopRunningGhostProcess();
  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  StopRunningGhostProcess();
  Result := True;
end;
