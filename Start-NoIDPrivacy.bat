@echo off
REM ========================================
REM NoID Privacy - Interactive Launcher
REM ========================================
REM
REM This script launches NoIDPrivacy-Interactive.ps1 with
REM Administrator privileges (auto-elevation).
REM
REM Author: NexusOne23
REM Version: 2.2.5
REM ========================================

setlocal

title NoID Privacy v2.2.5

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
set "NOID_INTERACTIVE_SCRIPT=%SCRIPT_DIR%NoIDPrivacy-Interactive.ps1"

REM Check if already running as administrator (robust method that works even if Server service is disabled)
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorLevel% == 0 goto run_admin

REM Not admin - request elevation
echo Requesting Administrator privileges...
echo.

REM Use PowerShell to elevate, wait for the elevated instance and preserve its
REM exit code (mirrors the :run_admin branch). Exit code 740
REM (ERROR_ELEVATION_REQUIRED) marks a cancelled/failed elevation itself.
"%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$arguments = '-ExecutionPolicy Bypass -NoProfile -File ' + [char]34 + $env:NOID_INTERACTIVE_SCRIPT + [char]34; try { $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -Wait -PassThru -ErrorAction Stop } catch { exit 740 }; exit $proc.ExitCode"
if "%ERRORLEVEL%"=="740" (
    echo Elevation was cancelled or failed.
    exit /b 1
)

REM Exit this non-elevated instance, forwarding the elevated script's exit code
exit /b %ERRORLEVEL%

:run_admin
REM Already admin, run PowerShell script directly and preserve its exit code.
echo Running NoID Privacy Interactive Menu with Administrator privileges...
echo.
"%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File "%NOID_INTERACTIVE_SCRIPT%"
set "NOID_EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %NOID_EXIT_CODE%
