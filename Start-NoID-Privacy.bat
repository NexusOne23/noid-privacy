@echo off
REM =======================================================================================
REM NoID Privacy - Easy Launcher
REM Automatically starts in Interactive Mode with language selection
REM =======================================================================================

REM Set UTF-8 Code Page for correct umlauts/special characters display
chcp 65001 >nul 2>&1

REM Enable ANSI Colors (Windows 10+)
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

REM Define ANSI Color Codes (ESC = ASCII 27 = 0x1B)
REM Use PowerShell to generate ESC character for ANSI codes
for /f %%A in ('powershell -Command "[char]27"') do set "ESC=%%A"
set "CYAN=%ESC%[96m"
set "GREEN=%ESC%[92m"
set "RED=%ESC%[91m"
set "YELLOW=%ESC%[93m"
set "RESET=%ESC%[0m"

:: Banner
echo.
echo %CYAN%=============================================================================%RESET%
echo %CYAN%%RESET%
echo %CYAN%                NoID Privacy - Windows 11 25H2 Baseline%RESET%
echo %CYAN%%RESET%
echo %CYAN%               Maximum Security + Privacy + Performance%RESET%
echo %CYAN%%RESET%
echo %CYAN%=============================================================================%RESET%
echo.

:: Check for Administrator rights
:: Best Practice 25H2: Use fltmc instead of deprecated "net session"
:: fltmc (Filter Manager Control) requires admin rights and works in all Windows versions
fltmc >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%[ERROR] Administrator rights required!%RESET%
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo %GREEN%[OK] Administrator rights confirmed%RESET%
echo.

:: Check PowerShell version (5.1 minimum required)
:: Best Practice 25H2: Check both Major and Minor version
powershell -Command "if ($PSVersionTable.PSVersion -lt [Version]'5.1') { exit 1 }" >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%[ERROR] PowerShell 5.1 or higher required!%RESET%
    echo.
    echo Current version check failed - please ensure PS 5.1+
    echo Please update PowerShell: https://aka.ms/powershell
    echo.
    pause
    exit /b 1
)

echo %GREEN%[OK] PowerShell version OK%RESET%
echo.

:: Unblock all PowerShell files (Zone.Identifier from ZIP download)
:: CRITICAL: Windows marks files downloaded from Internet with Zone.Identifier
:: This prevents scripts from running ("Internet security settings prevent execution")
:: Solution: Automatically unblock all .ps1 and .psm1 files
powershell -ExecutionPolicy Bypass -NoProfile -Command "Get-ChildItem -Path '%~dp0' -Recurse -Include *.ps1,*.psm1 -File | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1
echo %GREEN%[OK] PowerShell files unblocked%RESET%
echo.

:: Check if script exists
if not exist "%~dp0Apply-Win11-25H2-SecurityBaseline.ps1" (
    echo %RED%[ERROR] Main script not found!%RESET%
    echo.
    echo Expected: %~dp0Apply-Win11-25H2-SecurityBaseline.ps1
    echo.
    pause
    exit /b 1
)

echo %GREEN%[OK] Script found%RESET%
echo.

:: Start in Interactive Mode
echo %YELLOW%Starting NoID Privacy in Interactive Mode...%RESET%
echo.
echo %YELLOW%=============================================================================%RESET%
echo.

:: Run PowerShell with ExecutionPolicy Bypass
:: CRITICAL: Use -Command with escaped double quotes (handles spaces AND special chars like apostrophes)
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "& \"%~dp0Apply-Win11-25H2-SecurityBaseline.ps1\" -Interactive"

:: Check result
if %errorLevel% equ 0 (
    echo.
    echo %CYAN%=============================================================================%RESET%
    echo.
    echo %GREEN%[SUCCESS] NoID Privacy completed successfully!%RESET%
    echo.
) else (
    echo.
    echo %CYAN%=============================================================================%RESET%
    echo.
    echo %RED%[ERROR] NoID Privacy encountered an error!%RESET%
    echo %YELLOW%         Check the log files in: %ProgramData%\SecurityBaseline\Logs%RESET%
    echo.
)

pause
