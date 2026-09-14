; Inno Setup Script for AnonymousAnt Windows Installer
[Setup]
AppName=AnonymousAnt
AppVersion=1.0.0
DefaultDirName={autopf}\AnonymousAnt
DefaultGroupName=AnonymousAnt
OutputDir=..\dist
OutputBaseFilename=AnonymousAnt-Setup-x64
Compression=lzma2/ultra
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\..\bin\windows\ant-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\bin\windows\ant-ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\bin\windows\antclient.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "wintun\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AnonymousAnt"; Filename: "{app}\ant-ui.exe"
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
