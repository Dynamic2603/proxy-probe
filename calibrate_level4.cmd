@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
cd /d "%~dp0"

uv run py -m proxy_probe.antidpi benchmark --level 4 %*

echo.
pause
endlocal
