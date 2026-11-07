@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%comspec%' -ArgumentList '/c \"\"%~f0\" %*\"' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

uv run py -m proxy_probe.antidpi benchmark --level 3 %*

echo.
pause
endlocal
