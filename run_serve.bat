@echo off
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

echo ======================================================================
echo   proxy-probe: Zapret2 Anti-DPI Isolated Relay Service
echo ======================================================================
echo.
uv run py -m proxy_probe.antidpi serve %*
echo.
pause
