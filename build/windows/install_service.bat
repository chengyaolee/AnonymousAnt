@echo off
echo ===================================================
echo   AnonymousAnt - Install Background Windows Service
echo ===================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required.
    echo Please right-click install_service.bat and select "Run as administrator".
    pause
    exit /b 1
)

set DIR=%~dp0
set SERVICE_EXE=%DIR%ant-daemon.exe

echo Registering AnonymousAntService...
sc.exe stop AnonymousAntService >nul 2>&1
sc.exe delete AnonymousAntService >nul 2>&1
sc.exe create AnonymousAntService binPath= "\"%SERVICE_EXE%\"" start= auto DisplayName= "AnonymousAnt VPN Service"
sc.exe start AnonymousAntService

echo.
echo [SUCCESS] AnonymousAnt service installed and running!
echo You can now launch start_ui.bat or ant-ui.exe.
pause
