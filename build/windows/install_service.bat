@echo off
echo Installing AnonymousAnt Windows Service...

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Administrator privileges required. Right click and Run as Administrator.
    pause
    exit /b 1
)

set BIN_DIR=%~dp0..\..\bin\windows
set SERVICE_EXE=%BIN_DIR%\ant-daemon.exe

sc create AnonymousAntService binPath= "%SERVICE_EXE%" start= auto DisplayName= "AnonymousAnt Service"
sc start AnonymousAntService

echo AnonymousAnt Service successfully registered and started!
pause
