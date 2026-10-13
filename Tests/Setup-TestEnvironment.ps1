#Requires -Version 5.1

<#
.SYNOPSIS
    Setup Pester testing environment for NoID Privacy

.DESCRIPTION
    Installs the exact Pester version used by CI (5.9.0) for the current user
    and creates the Tests/Unit, Tests/Integration and Tests/Results folders
    if they are missing.

.NOTES
    Author: NexusOne23
    Version: 2.2.6
    Requires: PowerShell 5.1+

.EXAMPLE
    .\Setup-TestEnvironment.ps1
    Install Pester 5.9.0 and create the test folders
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipPesterInstall
)

Write-Host "NoID Privacy - Test Environment Setup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: PowerShell 5.1 or higher required" -ForegroundColor Red
    exit 1
}

# Install/Update Pester
if (-not $SkipPesterInstall) {
    Write-Host "Checking Pester installation..." -ForegroundColor Yellow

    $requiredPesterVersion = [Version]'5.9.0'
    $pesterModule = Get-Module -Name Pester -ListAvailable | Where-Object Version -eq $requiredPesterVersion | Select-Object -First 1

    if ($null -eq $pesterModule) {
        Write-Host "Installing Pester $requiredPesterVersion..." -ForegroundColor Yellow

        try {
            # Windows ships a Microsoft-signed Pester 3.4.0 whose publisher
            # differs from Pester 5, so a side-by-side install needs
            # -SkipPublisherCheck in addition to -Force.
            Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser -RequiredVersion $requiredPesterVersion -ErrorAction Stop
            Write-Host "[OK] Pester $requiredPesterVersion installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to install Pester: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "[OK] Exact Pester $($pesterModule.Version) already installed" -ForegroundColor Green
    }
}

# Create test directories
Write-Host ""
Write-Host "Creating test directory structure..." -ForegroundColor Yellow

$testRoot = $PSScriptRoot
$directories = @(
    "Unit",
    "Integration",
    "Results"
)

foreach ($dir in $directories) {
    $path = Join-Path $testRoot $dir
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "[OK] Created: $dir/" -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Exists: $dir/" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Test environment setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Run tests: .\Run-Tests.ps1" -ForegroundColor White
Write-Host "  2. Create module tests in Tests/Unit/" -ForegroundColor White
Write-Host "  3. View results in Tests/Results/" -ForegroundColor White
Write-Host ""
