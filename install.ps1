#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NoID Privacy - One-Liner Installer
    
.DESCRIPTION
    Downloads the latest release and starts interactive setup.
    
    Usage:
    irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 | iex
    
    Or safer (2-step):
    irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 -OutFile install.ps1
    .\install.ps1
    
.NOTES
    Author: NexusOne23
    Project: NoID Privacy - Windows 11 Security & Privacy Hardening
    GitHub: https://github.com/NexusOne23/noid-privacy
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Clear screen for clean output
Clear-Host

# Banner
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  NoID Privacy - Installer" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Windows 11 Security & Privacy Hardening Toolkit" -ForegroundColor White
Write-Host "  Enterprise-Grade Protection for Everyone" -ForegroundColor Gray
Write-Host ""

# Check Admin privileges
Write-Host "[1/5] Checking Administrator privileges..." -ForegroundColor Yellow
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host "  WARNING: ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "This installer requires Administrator privileges." -ForegroundColor White
    Write-Host ""
    Write-Host "Please:" -ForegroundColor Yellow
    Write-Host "  1. Right-click PowerShell" -ForegroundColor White
    Write-Host "  2. Select 'Run as Administrator'" -ForegroundColor White
    Write-Host "  3. Run the installer again" -ForegroundColor White
    Write-Host ""
    Read-Host "Press ENTER to exit"
    exit 1
}
Write-Host "    [OK] Running as Administrator" -ForegroundColor Green

# Check Windows version
Write-Host ""
Write-Host "[2/5] Checking Windows version..." -ForegroundColor Yellow
$build = [System.Environment]::OSVersion.Version.Build
if ($build -lt 22000) {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host "  WARNING: WINDOWS 11 REQUIRED" -ForegroundColor Red
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "This tool requires Windows 11 (Build 22000+)" -ForegroundColor White
    Write-Host "Your version: Build $build" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please upgrade to Windows 11 first." -ForegroundColor White
    Write-Host ""
    Read-Host "Press ENTER to exit"
    exit 1
}
Write-Host "    [OK] Windows 11 detected (Build $build)" -ForegroundColor Green

# Download latest release
Write-Host ""
Write-Host "[3/5] Downloading latest release..." -ForegroundColor Yellow
$downloadPath = "$env:TEMP\noid-privacy-latest.zip"
$extractPath = "$env:TEMP\noid-privacy"

try {
    # Get latest release info from GitHub API
    Write-Host "    -> Fetching release information..." -ForegroundColor Gray
    $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/NexusOne23/noid-privacy/releases/latest" -UseBasicParsing
    $version = $latestRelease.tag_name
    $zipUrl = $latestRelease.assets[0].browser_download_url
    
    Write-Host "    -> Latest version: $version" -ForegroundColor Gray
    Write-Host "    -> Downloading..." -ForegroundColor Gray
    
    # Download ZIP
    Invoke-WebRequest -Uri $zipUrl -OutFile $downloadPath -UseBasicParsing
    
    $sizeInMB = [Math]::Round((Get-Item $downloadPath).Length / 1MB, 2)
    Write-Host "    [OK] Downloaded: $sizeInMB MB" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host "  WARNING: DOWNLOAD FAILED" -ForegroundColor Red
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Could not download the latest release." -ForegroundColor White
    Write-Host "Error: $_" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please try:" -ForegroundColor White
    Write-Host "  - Check your internet connection" -ForegroundColor Gray
    Write-Host "  - Visit: https://github.com/NexusOne23/noid-privacy/releases" -ForegroundColor Gray
    Write-Host "  - Download manually and run Apply script" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Press ENTER to exit"
    exit 1
}

# Extract ZIP
Write-Host ""
Write-Host "[4/5] Extracting..." -ForegroundColor Yellow
try {
    # Remove old extraction if exists
    if (Test-Path $extractPath) {
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Extract
    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
    Write-Host "    [OK] Extracted to: $extractPath" -ForegroundColor Green
    
    # Find the Apply script (might be in a subdirectory)
    $applyScript = Get-ChildItem -Path $extractPath -Recurse -Filter "Apply-Win11-25H2-SecurityBaseline.ps1" -ErrorAction Stop | Select-Object -First 1
    
    if (-not $applyScript) {
        throw "Apply script not found in package!"
    }
    
    # Change to script directory
    $scriptDirectory = $applyScript.Directory.FullName
    Set-Location $scriptDirectory
    Write-Host "    [OK] Working directory: $scriptDirectory" -ForegroundColor Green
    
    # Unblock all PowerShell files (critical for ZIP downloads!)
    Write-Host "    -> Unblocking PowerShell files..." -ForegroundColor Gray
    Get-ChildItem -Path $scriptDirectory -Recurse -Include "*.ps1", "*.psm1", "*.psd1" -ErrorAction SilentlyContinue | 
        ForEach-Object {
            try {
                Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue
            }
            catch {
                # Silently continue if unblock fails
            }
        }
    Write-Host "    [OK] Files unblocked (Zone.Identifier removed)" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host "  WARNING: EXTRACTION FAILED" -ForegroundColor Red
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Could not extract the package." -ForegroundColor White
    Write-Host "Error: $_" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press ENTER to exit"
    exit 1
}

# Launch NoID Privacy
Write-Host ""
Write-Host "[5/5] Launching NoID Privacy..." -ForegroundColor Yellow
Write-Host ""
Start-Sleep -Seconds 1

Write-Host "===========================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Starting Interactive Mode..." -ForegroundColor Cyan
Write-Host ""
Start-Sleep -Seconds 2

# Execute the Apply script in Interactive mode
# CRITICAL: Use explicit -ExecutionPolicy Bypass to ensure script runs even if system policy is Restricted
# CRITICAL: Use -Command (not -File) to handle paths with spaces/apostrophes (like "User's Temp Folder")
try {
    $scriptPath = $applyScript.FullName
    $command = "& `"$scriptPath`" -Interactive"
    $processArgs = @(
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-Command", $command
    )
    & powershell.exe $processArgs
}
catch {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host "  WARNING: EXECUTION FAILED" -ForegroundColor Red
    Write-Host "===========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Could not execute NoID Privacy." -ForegroundColor White
    Write-Host "Error: $_" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "You can try running manually:" -ForegroundColor White
    Write-Host "  cd $scriptDirectory" -ForegroundColor Gray
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Press ENTER to exit"
    exit 1
}

# Cleanup (optional - commented out to allow re-runs)
# Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
# Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Thank you for using NoID Privacy!" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""
