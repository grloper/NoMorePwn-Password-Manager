; Inno Setup script — builds NoMorePwn-Setup.exe from the PyInstaller output.
;
;   ISCC.exe build\installer.iss        (run from the repo root)
;
; Installs the portable NoMorePwn.exe into a per-user Programs folder (no
; admin required), adds Start-menu / optional desktop shortcuts, and an
; optional "launch at sign-in" shortcut that starts the app into the tray.

#define MyAppName "NoMorePwn"
#define MyAppExeName "NoMorePwn.exe"
#define MyAppPublisher "grloper"
#define MyAppURL "https://github.com/grloper/NoMorePwn-Password-Manager"

#define MyAppVersion GetEnv("NOMOREPWN_VERSION")
#if MyAppVersion == ""
  #undef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

[Setup]
AppId={{7C9E6A2B-3F4D-4A1E-9B8C-2D5F1A6E3C40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\NoMorePwn
DefaultGroupName=NoMorePwn
DisableProgramGroupPage=yes
DisableDirPage=auto
; NOTE: relative paths here resolve against THIS FILE's directory (build\),
; so everything pointing at the repo root needs a leading "..\".
OutputDir=..\dist
OutputBaseFilename=NoMorePwn-Setup
SetupIconFile=..\assets\NoMorePwn.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "startupicon"; Description: "Start NoMorePwn at sign-in (locked, in the tray)"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\dist\NoMorePwn.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NoMorePwn"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall NoMorePwn"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NoMorePwn"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\NoMorePwn"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch NoMorePwn now"; Flags: nowait postinstall skipifsilent
