@echo off
echo =====================================================
echo   AnonymousAnt - Uninstall Background Windows Service
echo =====================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required.
    echo Please right-click uninstall_service.bat and select "Run as administrator".
    pause
    exit /b 1
)

echo Stopping AnonymousAntService...
sc.exe stop AnonymousAntService >nul 2>&1
echo Removing AnonymousAntService...
sc.exe delete AnonymousAntService >nul 2>&1

echo.
echo [SUCCESS] AnonymousAnt service removed.
pause
