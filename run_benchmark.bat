@echo off
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

echo ======================================================================
echo   proxy-probe: Zapret2 Anti-DPI Strategy Benchmark
echo ======================================================================
echo.
uv run py -m proxy_probe.antidpi benchmark --limit 15 --top 10 --concurrency 15 --timeout 1.8 %*
echo.
pause
