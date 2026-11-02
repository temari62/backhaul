; Inno Setup script for Backhaul — builds dist\Backhaul-Setup-<version>.exe
;
; Compile with build-installer.ps1 (preferred), which passes the version:
;   ISCC.exe /DMyAppVersion=0.4.0 installer\backhaul.iss
;
; Needs Inno Setup 6 (https://jrsoftware.org/isdl.php) and dist\Backhaul.exe
; already built (build-app.ps1 does that).

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

#define MyAppName "Backhaul"
#define MyAppExe "Backhaul.exe"
#define MyAppPublisher "Backhaul"
#define MyAppURL "https://github.com/temari62/backhaul"

[Setup]
; AppId ties every version to the same Add/Remove Programs entry, so an update
; replaces the previous install instead of adding a second one. Never change it.
AppId={{8E6D1F2A-4C3B-4E7A-9A1D-7B2C5F0E9A11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExe}
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=Backhaul-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Writing to Program Files needs admin; the app itself also runs elevated.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Let a silent update (from the in-app updater) close and relaunch a running
; Backhaul through the Restart Manager.
CloseApplications=yes
RestartApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\{#MyAppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

; Note: "Start with Windows" is deliberately not offered here. The app sets
; that up itself (Settings → Start with Windows) as a scheduled task running
; with administrator rights, which avoids a UAC prompt at every sign-in that a
; Run-key entry for this elevated app would cause.

[Run]
; Offer to launch after an interactive install. Skipped on a silent update,
; where the Restart Manager relaunches the version it closed instead.
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; \
  Flags: nowait postinstall skipifsilent
