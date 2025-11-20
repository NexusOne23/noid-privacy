@echo off
REM ========================================
REM NoID Privacy Pro - Interactive Launcher
REM ========================================
REM
REM This script launches NoIDPrivacy-Interactive.ps1 with
REM Administrator privileges (auto-elevation).
REM
REM Author: NoID Privacy Pro Team
REM Version: 2.1.0
REM ========================================

setlocal

title NoID Privacy Pro v2.1.0

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Check if already running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    REM Already admin, run PowerShell script directly
    echo Running NoID Privacy Pro Interactive Menu with Administrator privileges...
    echo.
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%NoIDPrivacy-Interactive.ps1" %*
    pause
    exit /b
)

REM Not admin - request elevation
echo Requesting Administrator privileges...
echo.

REM Use PowerShell to elevate and run the script
powershell.exe -Command "Start-Process PowerShell.exe -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File \"%SCRIPT_DIR%NoIDPrivacy-Interactive.ps1\" %*' -Verb RunAs"

REM Exit this non-elevated instance
exit /b
