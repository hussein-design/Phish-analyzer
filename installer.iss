; Inno Setup 6 script for Phish Analyzer Desktop
;
; Wraps the PyInstaller --onedir output (dist\PhishAnalyzerDesktop\) into a
; single self-contained installer .exe that end-users download from GitHub
; Releases.
;
; What the installer does:
;   • Installs all app files to {autopf}\PhishAnalyzerDesktop  (Program Files)
;   • Creates a Start Menu shortcut
;   • Creates an optional Desktop shortcut
;   • Registers an uninstaller (visible in Windows "Apps & features")
;   • Does NOT require administrator rights if the user installs to their own
;     AppData folder (the PrivilegesRequired=lowest line handles this).
;
; Build (requires Inno Setup 6 — https://jrsoftware.org/isinfo.php):
;   iscc installer.iss
; Or from the CI workflow (see .github/workflows/build-windows.yml).

#define MyAppName      "Phish Analyzer Desktop"
#define MyAppVersion   GetEnv("APP_VERSION")
#define MyAppPublisher "PhishAnalyzer"
#define MyAppURL       "https://github.com/your-username/phish-analyzer"
#define MyAppExeName   "PhishAnalyzerDesktop.exe"
#define MyAppIconFile  "assets\icons\app.ico"
#define SourceDir      "dist\PhishAnalyzerDesktop"

[Setup]
; Unique GUID — do NOT change after the first release (used for upgrade detection)
AppId={{A3F8C2D1-7B4E-4F9A-8C3D-2E1F0A5B6C7D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; Allow install without admin — falls back to {localappdata} automatically
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=dist
OutputBaseFilename=PhishAnalyzerSetup-{#MyAppVersion}
SetupIconFile={#MyAppIconFile}
Compression=lzma2/ultra64
SolidCompression=yes
; Embed a manifest so Windows shows the correct DPI-aware app icon
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
WizardStyle=modern
; Require Windows 10 or later (PySide6 requirement)
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Copy everything PyInstaller produced into the install directory
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}";     Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
; Desktop (optional, unchecked by default)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch immediately after install
Filename: "{app}\{#MyAppExeName}"; \
    Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up any .pyc caches written into the install dir at runtime
Type: filesandordirs; Name: "{app}\__pycache__"
