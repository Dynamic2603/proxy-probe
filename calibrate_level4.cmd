@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

where uv >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] 'uv' not found in PATH. Please install uv: https://astral.sh/uv
    pause
    exit /b 1
)

echo ======================================================================
echo   proxy-probe: Глубокий перебор всех 484 стратегий каталога (Уровень 4)
echo ======================================================================
echo.

uv run py -m proxy_probe.antidpi benchmark --level 4 %*
set "EXIT_CODE=%errorlevel%"

if %EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Process exited with code %EXIT_CODE%.
)

echo.
pause
endlocal & exit /b %EXIT_CODE%
