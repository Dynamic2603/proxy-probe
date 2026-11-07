@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

cd /d "%~dp0"

where uv >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] 'uv' not found in PATH. Please install uv: https://astral.sh/uv
    pause
    exit /b 1
)

uv run pxp %*
set "EXIT_CODE=%errorlevel%"

if %EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Process exited with code %EXIT_CODE%.
    pause
)

endlocal & exit /b %EXIT_CODE%
