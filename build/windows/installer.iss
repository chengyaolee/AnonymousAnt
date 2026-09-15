; Inno Setup Script for AnonymousAnt Windows Installer
[Setup]
AppName=AnonymousAnt
AppVersion=1.1.0
AppPublisher=AnonymousAnt
DefaultDirName={autopf}\AnonymousAnt
DefaultGroupName=AnonymousAnt
OutputDir=..\dist
OutputBaseFilename=AnonymousAnt-Setup-x64
Compression=lzma2/ultra
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\ant-ui.exe

[Files]
Source: "staging\ant-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\ant-ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\antclient.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\install_service.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\uninstall_service.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AnonymousAnt"; Filename: "{app}\ant-ui.exe"
Name: "{group}\Uninstall AnonymousAnt"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AnonymousAnt"; Filename: "{app}\ant-ui.exe"

[Run]
; Install and start the privileged background service
Filename: "sc.exe"; Parameters: "create AnonymousAntService binPath= ""{app}\ant-daemon.exe"" start= auto DisplayName= ""AnonymousAnt VPN Service"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "start AnonymousAntService"; Flags: runhidden
; Launch UI on install completion
Filename: "{app}\ant-ui.exe"; Description: "Launch AnonymousAnt"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop AnonymousAntService"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete AnonymousAntService"; Flags: runhidden
