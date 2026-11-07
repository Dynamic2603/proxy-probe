@echo off
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

echo ======================================================================
echo   proxy-probe: Scan with Zapret2 Anti-DPI Relay
echo ======================================================================
echo.
uv run py -m proxy_probe.cli --antidpi %*
echo.
pause
