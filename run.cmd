@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
cd /d "%~dp0"

set "NEED_ADMIN=1"
for %%A in (%*) do (
    if /i "%%A"=="--no-antidpi" set "NEED_ADMIN=0"
    if /i "%%A"=="--no-elevate" set "NEED_ADMIN=0"
)

if "%NEED_ADMIN%"=="1" (
    net session >nul 2>&1
    if %errorlevel% neq 0 (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%comspec%' -ArgumentList '/c \"\"%~f0\" %*\"' -WorkingDirectory '%~dp0' -Verb RunAs"
        exit /b
    )
)

uv run pxp %*

echo.
pause
endlocal
