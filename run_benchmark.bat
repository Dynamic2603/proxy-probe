@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ======================================================================
echo   proxy-probe: Zapret2 Anti-DPI Strategy Benchmark
echo ======================================================================
echo.
uv run py -m proxy_probe.antidpi benchmark --limit 15 --top 10 --concurrency 15 --timeout 1.8 --profile
echo.
pause
