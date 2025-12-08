<#
.SYNOPSIS
    Setup Pester testing environment for NoID Privacy
    
.DESCRIPTION
    Installs and configures Pester v5 testing framework.
    Creates sample test structure for all modules.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: PowerShell 5.1+
    
.EXAMPLE
    .\Setup-TestEnvironment.ps1
    Install Pester and setup test structure
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
    
    $pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    
    if ($null -eq $pesterModule -or $pesterModule.Version -lt [Version]"5.0.0") {
        Write-Host "Installing Pester v5..." -ForegroundColor Yellow
        
        try {
            Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser -MinimumVersion 5.0.0
            Write-Host "[OK] Pester v5 installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to install Pester: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "[OK] Pester v$($pesterModule.Version) already installed" -ForegroundColor Green
    }
}

# Create test directories
Write-Host ""
Write-Host "Creating test directory structure..." -ForegroundColor Yellow

$testRoot = $PSScriptRoot
$directories = @(
    "Unit",
    "Integration",
    "Validation",
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
