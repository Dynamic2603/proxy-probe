@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ======================================================================
echo   proxy-probe: Scan with Zapret2 Anti-DPI Relay
echo ======================================================================
echo.
uv run py -m proxy_probe.cli --antidpi
echo.
pause
