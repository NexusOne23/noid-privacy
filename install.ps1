#Requires -Version 5.1

<#
.SYNOPSIS
    NoID Privacy - One-Line Installer
    
.DESCRIPTION
    Downloads and installs the latest version of NoID Privacy from GitHub.
    This script checks prerequisites, downloads the latest release, extracts it,
    and prepares it for execution.
    
.EXAMPLE
    # Run from web (one-liner)
    irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 | iex
    
.NOTES
    Author: NexusOne23
    Version: 1.0.0
    Requires: PowerShell 5.1+, Windows 11, Admin Rights
#>

function Install-NoIDPrivacy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstallPath = "$env:USERPROFILE\NoIDPrivacy",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck
    )

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Colors
$ColorSuccess = 'Green'
$ColorError = 'Red'
$ColorWarning = 'Yellow'
$ColorInfo = 'Cyan'

function Write-ColorOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$Color = 'White',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )
    
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    }
    else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LatestRelease {
    try {
        Write-ColorOutput "Fetching latest release from GitHub..." -Color $ColorInfo
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NexusOne23/noid-privacy/releases/latest" -UseBasicParsing
        return $release
    }
    catch {
        Write-ColorOutput "No releases found. Using main branch instead..." -Color $ColorWarning
        return $null
    }
}

function Test-SafeInstallPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        $fullPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    catch {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    
    $normalized = $fullPath.TrimEnd('\').ToLowerInvariant()
    
    # Block drive roots (e.g. C:\)
    if ($normalized -match '^[a-z]:$') {
        Write-ColorOutput "ERROR: Installation path '$fullPath' is a drive root and is not allowed." -Color $ColorError
        return $false
    }
    
    # Block critical system locations
    $blocked = @()
    if ($env:WINDIR) { $blocked += $env:WINDIR.TrimEnd('\\').ToLowerInvariant() }
    if ($env:ProgramFiles) { $blocked += $env:ProgramFiles.TrimEnd('\\').ToLowerInvariant() }
    if (${env:ProgramFiles(x86)}) { $blocked += ${env:ProgramFiles(x86)}.TrimEnd('\\').ToLowerInvariant() }
    if ($env:SystemRoot) { $blocked += $env:SystemRoot.TrimEnd('\\').ToLowerInvariant() }
    if ($env:USERPROFILE) { $blocked += $env:USERPROFILE.TrimEnd('\\').ToLowerInvariant() }
    
    foreach ($b in $blocked) {
        if ([string]::IsNullOrEmpty($b)) { continue }
        if ($normalized -eq $b -or $normalized.StartsWith($b + '\\')) {
            Write-ColorOutput "ERROR: Installation path '$fullPath' is too close to a critical system directory ($b)." -Color $ColorError
            return $false
        }
    }
    
    return $true
}

# Banner
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "        NoID Privacy - One-Line Installer                 " -ForegroundColor Cyan
Write-Host "   Professional Windows 11 Security & Privacy Hardening Framework   " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Administrator
if (-not $SkipAdminCheck) {
    Write-ColorOutput "Checking administrator privileges..." -Color $ColorInfo
    if (-not (Test-Administrator)) {
        Write-ColorOutput "ERROR: Administrator rights required!" -Color $ColorError
        Write-ColorOutput "   Please run PowerShell as Administrator and try again." -Color $ColorWarning
        Write-ColorOutput @"

To run as Administrator:
1. Press Win + X
2. Click "Terminal (Admin)" or "PowerShell (Admin)"
3. Run the install command again

"@ -Color $ColorInfo
        exit 1
    }
    Write-ColorOutput "Administrator privileges confirmed" -Color $ColorSuccess
}

# Step 2: Check PowerShell Version
Write-ColorOutput "Checking PowerShell version..." -Color $ColorInfo
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-ColorOutput "ERROR: PowerShell 5.1 or higher required!" -Color $ColorError
    Write-ColorOutput "   Current version: $($psVersion.ToString())" -Color $ColorWarning
    exit 1
}
Write-ColorOutput "PowerShell version OK ($($psVersion.ToString()))" -Color $ColorSuccess

# Step 3: Check Windows Version
Write-ColorOutput "Checking Windows version..." -Color $ColorInfo
$osInfo = Get-ComputerInfo
$buildNumber = [int]$osInfo.OsBuildNumber

if ($buildNumber -lt 22000) {
    Write-ColorOutput "ERROR: Windows 11 required!" -Color $ColorError
    Write-ColorOutput "   Current build: $buildNumber (Windows 10 or older)" -Color $ColorWarning
    exit 1
}

$osVersion = if ($buildNumber -ge 26200) { "25H2" }
             elseif ($buildNumber -ge 26100) { "24H2" }
             elseif ($buildNumber -ge 22631) { "23H2" }
             else { "Unknown" }

Write-ColorOutput "Windows 11 $osVersion detected (Build $buildNumber)" -Color $ColorSuccess

# Step 4: Create Install Directory
Write-ColorOutput "Creating installation directory..." -Color $ColorInfo
if (-not (Test-SafeInstallPath -Path $InstallPath)) {
    Write-ColorOutput "Installation aborted due to unsafe install path." -Color $ColorError
    exit 1
}
if (Test-Path $InstallPath) {
    Write-ColorOutput "Directory already exists: $InstallPath" -Color $ColorWarning
    $response = Read-Host "   Overwrite existing installation? (Y/N)"
    if ($response -ne 'Y') {
        Write-ColorOutput "Installation cancelled by user" -Color $ColorWarning
        exit 0
    }
    Write-ColorOutput "Removing old installation..." -Color $ColorInfo
    Remove-Item -Path $InstallPath -Recurse -Force
}

New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
Write-ColorOutput "Install directory created: $InstallPath" -Color $ColorSuccess

# Step 5: Download Latest Release or Main Branch
$downloadUrl = $null
$downloadPath = Join-Path $env:TEMP "NoIDPrivacy.zip"

$release = Get-LatestRelease

if ($release) {
    Write-ColorOutput "Latest release: $($release.tag_name)" -Color $ColorInfo
    $zipAsset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
    
    if ($zipAsset) {
        $downloadUrl = $zipAsset.browser_download_url
        Write-ColorOutput "Downloading release: $($zipAsset.name)" -Color $ColorInfo
    }
}

if (-not $downloadUrl) {
    Write-ColorOutput "Downloading from main branch..." -Color $ColorInfo
    $downloadUrl = "https://github.com/NexusOne23/noid-privacy/archive/refs/heads/main.zip"
}

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing
    Write-ColorOutput "Download complete" -Color $ColorSuccess
}
catch {
    Write-ColorOutput "ERROR: Download failed!" -Color $ColorError
    Write-ColorOutput "   $($_.Exception.Message)" -Color $ColorWarning
    exit 1
}

# Step 6: Extract Archive
Write-ColorOutput "Extracting files..." -Color $ColorInfo
try {
    Expand-Archive -Path $downloadPath -DestinationPath $InstallPath -Force
    
    # Move files from subdirectory to root (GitHub zip structure)
    $subDir = Get-ChildItem -Path $InstallPath -Directory | Select-Object -First 1
    if ($subDir) {
        Get-ChildItem -Path $subDir.FullName -Recurse | ForEach-Object {
            $dest = Join-Path $InstallPath $_.FullName.Substring($subDir.FullName.Length + 1)
            if ($_.PSIsContainer) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
            }
            else {
                Move-Item -Path $_.FullName -Destination $dest -Force
            }
        }
        Remove-Item -Path $subDir.FullName -Recurse -Force
    }
    
    Remove-Item -Path $downloadPath -Force
    Write-ColorOutput "Files extracted successfully" -Color $ColorSuccess
}
catch {
    Write-ColorOutput "ERROR: Extraction failed!" -Color $ColorError
    Write-ColorOutput "   $($_.Exception.Message)" -Color $ColorWarning
    exit 1
}

# Step 7: Unblock Files
Write-ColorOutput "Unblocking PowerShell scripts..." -Color $ColorInfo
Get-ChildItem -Path $InstallPath -Recurse -Include *.ps1, *.psm1, *.psd1 | Unblock-File
Write-ColorOutput "All files unblocked" -Color $ColorSuccess

# Step 8: Display Success Message
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "                 INSTALLATION COMPLETE!                        " -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installation Path: $InstallPath" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Green
Write-Host ""
Write-Host "1. Review the documentation:" -ForegroundColor Green
Write-Host "   README: $InstallPath\README.md" -ForegroundColor Green
Write-Host ""
Write-Host "2. Create a system backup (CRITICAL!):" -ForegroundColor Green
Write-Host "   - System Restore Point" -ForegroundColor Green
Write-Host "   - Full system image" -ForegroundColor Green
Write-Host "   - VM snapshot (if applicable)" -ForegroundColor Green
Write-Host ""
Write-Host "3. Run the interactive setup:" -ForegroundColor Green
Write-Host "   cd `"$InstallPath`"" -ForegroundColor Green
Write-Host "   .\Start-NoIDPrivacy.bat" -ForegroundColor Green
Write-Host ""
Write-Host "4. Or run directly with PowerShell:" -ForegroundColor Green
Write-Host "   cd `"$InstallPath`"" -ForegroundColor Green
Write-Host "   .\NoIDPrivacy.ps1 -Module All" -ForegroundColor Green
Write-Host ""
Write-Host "5. After execution, verify settings:" -ForegroundColor Green
Write-Host "   .\Tools\Verify-Complete-Hardening.ps1" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT WARNINGS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "- This tool modifies CRITICAL system settings" -ForegroundColor Yellow
Write-Host "- BACKUP your system BEFORE running" -ForegroundColor Yellow
Write-Host "- Test in a VM first (recommended)" -ForegroundColor Yellow
Write-Host "- Domain-joined systems: Coordinate with IT" -ForegroundColor Yellow
Write-Host "- Read SECURITY.md for security considerations" -ForegroundColor Yellow
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "- README.md - Complete guide" -ForegroundColor Cyan
Write-Host "- CHANGELOG.md - Version history" -ForegroundColor Cyan
Write-Host "- SECURITY.md - Security policy" -ForegroundColor Cyan
Write-Host "- LICENSE - GPL v3.0 dual-license" -ForegroundColor Cyan
Write-Host ""
Write-Host "Community & Support:" -ForegroundColor Cyan
Write-Host "- GitHub Issues: https://github.com/NexusOne23/noid-privacy/issues" -ForegroundColor Cyan
Write-Host "- Discussions: https://github.com/NexusOne23/noid-privacy/discussions" -ForegroundColor Cyan

Write-Host ""
Write-Host ""
Write-ColorOutput "Press any key to start interactive menu..." -Color $ColorInfo -NoNewline
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# Auto-start interactive menu after user confirmation
Write-ColorOutput "Starting NoID Privacy..." -Color $ColorInfo

try {
    Push-Location $InstallPath
    & .\Start-NoIDPrivacy.bat
    Pop-Location
}
catch {
    Write-ColorOutput "Could not auto-start. Please run manually:" -Color $ColorWarning
    Write-ColorOutput "   cd `"$InstallPath`"" -Color $ColorInfo
    Write-ColorOutput "   .\Start-NoIDPrivacy.bat" -Color $ColorInfo
}

Write-Host ""
Write-ColorOutput "NoID Privacy - Keeping Windows 11 secure and private!" -Color $ColorSuccess
}

# Call the function
Install-NoIDPrivacy @PSBoundParameters
