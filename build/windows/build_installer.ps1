# PowerShell script to compile Inno Setup installer for AnonymousAnt
param(
    [string]$InnoSetupPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "==> Building Windows portable package first..."
bash build/windows/build_windows_dist.sh

if (!(Test-Path $InnoSetupPath)) {
    Write-Warning "Inno Setup compiler (ISCC.exe) not found at: $InnoSetupPath"
    Write-Host "Please install Inno Setup from https://jrsoftware.org/isdl.php"
    Write-Host "You can still use the portable release at: build/dist/AnonymousAnt-Windows-x64.zip"
    exit 0
}

Write-Host "==> Compiling Windows Setup installer via Inno Setup..."
& $InnoSetupPath "build/windows/installer.iss"

Write-Host "==> Setup installer built successfully at: build/dist/AnonymousAnt-Setup-x64.exe"
