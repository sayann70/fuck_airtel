@echo off
:: Self-elevate to admin if not already
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -Command "[Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $s = [System.IO.File]::ReadAllText('%~dp0scripts\bypass.ps1', [System.Text.Encoding]::UTF8); $sb = [scriptblock]::Create($s); & $sb -Undo"
pause
