<#
.SYNOPSIS
    Run all Pester tests for NoID Privacy
    
.DESCRIPTION
    Executes Pester v5 tests with proper configuration.
    Generates test results and code coverage reports.
    
.PARAMETER TestType
    Type of tests to run (Unit, Integration, Validation, All)
    
.PARAMETER OutputFormat
    Output format for test results (NUnitXml, JUnitXml, None)
    
.PARAMETER CodeCoverage
    Enable code coverage analysis
    
.NOTES
    Author: NexusOne23
    Version: 2.2.1
    Requires: PowerShell 5.1+, Pester 5.0+
    
.EXAMPLE
    .\Run-Tests.ps1
    Run all tests with default settings
    
.EXAMPLE
    .\Run-Tests.ps1 -TestType Unit -CodeCoverage
    Run only unit tests with code coverage
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Unit", "Integration", "Validation", "All")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("NUnitXml", "JUnitXml", "None")]
    [string]$OutputFormat = "NUnitXml",
    
    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage
)

# Check Pester availability
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($null -eq $pesterModule -or $pesterModule.Version -lt [Version]"5.0.0") {
    Write-Host "ERROR: Pester v5.0+ required. Run Setup-TestEnvironment.ps1 first." -ForegroundColor Red
    exit 1
}

# Import Pester
Import-Module Pester -MinimumVersion 5.0.0

Write-Host "NoID Privacy - Test Runner" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Pester Version: $($pesterModule.Version)" -ForegroundColor Gray
Write-Host ""

# Determine test paths
$testRoot = $PSScriptRoot
$testPaths = @()

switch ($TestType) {
    "Unit" { $testPaths += Join-Path $testRoot "Unit" }
    "Integration" { $testPaths += Join-Path $testRoot "Integration" }
    "Validation" { $testPaths += Join-Path $testRoot "Validation" }
    "All" { 
        $testPaths += Join-Path $testRoot "Unit"
        $testPaths += Join-Path $testRoot "Integration"
        $testPaths += Join-Path $testRoot "Validation"
    }
}

# Filter out non-existent paths
$testPaths = $testPaths | Where-Object { Test-Path $_ }

if ($testPaths.Count -eq 0) {
    Write-Host "WARNING: No test files found in: $TestType" -ForegroundColor Yellow
    Write-Host "Create test files in Tests/$TestType/*.Tests.ps1" -ForegroundColor Yellow
    exit 0
}

# Prepare output directory
$resultsPath = Join-Path $testRoot "Results"
if (-not (Test-Path $resultsPath)) {
    New-Item -ItemType Directory -Path $resultsPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultFile = Join-Path $resultsPath "TestResults_$timestamp.xml"

# Configure Pester
$pesterConfig = New-PesterConfiguration

# Set test paths
$pesterConfig.Run.Path = $testPaths

# Output configuration
if ($OutputFormat -ne "None") {
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputFormat = $OutputFormat
    $pesterConfig.TestResult.OutputPath = $resultFile
}

# Code coverage configuration
if ($CodeCoverage) {
    $pesterConfig.CodeCoverage.Enabled = $true
    $pesterConfig.CodeCoverage.Path = @(
        (Join-Path (Split-Path $testRoot -Parent) "Core\*.ps1"),
        (Join-Path (Split-Path $testRoot -Parent) "Utils\*.ps1"),
        (Join-Path (Split-Path $testRoot -Parent) "Modules\*\*.ps1")
    )
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $resultsPath "CodeCoverage_$timestamp.xml"
}

# Output configuration
$pesterConfig.Output.Verbosity = "Detailed"

# Run tests
Write-Host "Running $TestType tests..." -ForegroundColor Yellow
Write-Host ""

$testResults = Invoke-Pester -Configuration $pesterConfig

# Display summary
Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Total Tests:  $($testResults.TotalCount)" -ForegroundColor White
Write-Host "Passed:       $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed:       $($testResults.FailedCount)" -ForegroundColor $(if ($testResults.FailedCount -gt 0) { "Red" } else { "White" })
Write-Host "Skipped:      $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration:     $($testResults.Duration)" -ForegroundColor White

if ($OutputFormat -ne "None") {
    Write-Host ""
    Write-Host "Results saved to: $resultFile" -ForegroundColor Cyan
}

if ($CodeCoverage) {
    Write-Host ""
    Write-Host "Code Coverage:" -ForegroundColor Cyan
    Write-Host "  Analyzed:   $($testResults.CodeCoverage.AnalyzedFiles.Count) files" -ForegroundColor White
    Write-Host "  Coverage:   $([math]::Round($testResults.CodeCoverage.CoveragePercent, 2))%" -ForegroundColor $(if ($testResults.CodeCoverage.CoveragePercent -ge 80) { "Green" } else { "Yellow" })
}

Write-Host ""

# Exit code based on test results
if ($testResults.FailedCount -gt 0) {
    exit 1
}
else {
    exit 0
}
