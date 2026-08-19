#Requires -Version 5.1

<#
.SYNOPSIS
    Run all Pester tests for NoID Privacy

.DESCRIPTION
    Executes Pester v5 tests with proper configuration.
    Generates test results and code coverage reports.

.PARAMETER TestType
    Type of tests to run (Unit, Integration, All)

.PARAMETER OutputFormat
    Output format for test results (NUnitXml, JUnitXml, None)

.PARAMETER CodeCoverage
    Enable code coverage analysis

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1, Pester 5.9.0

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
    [ValidateSet("Unit", "Integration", "All")]
    [string]$TestType = "All",

    [Parameter(Mandatory = $false)]
    [ValidateSet("NUnitXml", "JUnitXml", "None")]
    [string]$OutputFormat = "NUnitXml",

    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage
)

# Check exact Pester availability
$requiredPesterVersion = [Version]'5.9.0'
$pesterModule = Get-Module -Name Pester -ListAvailable | Where-Object Version -eq $requiredPesterVersion | Select-Object -First 1

if ($null -eq $pesterModule) {
    Write-Host "ERROR: Exact Pester $requiredPesterVersion required. Run Setup-TestEnvironment.ps1 first." -ForegroundColor Red
    exit 1
}

# Import Pester
Import-Module Pester -RequiredVersion $requiredPesterVersion -ErrorAction Stop

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
    "All" {
        $testPaths += Join-Path $testRoot "Unit"
        $testPaths += Join-Path $testRoot "Integration"
    }
}

# Filter out non-existent paths
$testPaths = $testPaths | Where-Object { Test-Path $_ }

if ($testPaths.Count -eq 0) {
    Write-Host "ERROR: No test directories found for test type: $TestType" -ForegroundColor Red
    exit 1
}

# Prepare output directory
$resultsPath = Join-Path $testRoot "Results"
if (-not (Test-Path $resultsPath)) {
    New-Item -ItemType Directory -Path $resultsPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$resultNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$resultId = "${timestamp}_$resultNonce"
$resultFile = Join-Path $resultsPath "TestResults_$resultId.xml"

# Configure Pester
$pesterConfig = New-PesterConfiguration

# Set test paths
$pesterConfig.Run.Path = $testPaths
$pesterConfig.Run.PassThru = $true

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
        (Join-Path (Split-Path $testRoot -Parent) "Core/*.ps1"),
        (Join-Path (Split-Path $testRoot -Parent) "Utils/*.ps1"),
        (Join-Path (Split-Path $testRoot -Parent) "Modules/*/*.ps1")
    )
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $resultsPath "CodeCoverage_$resultId.xml"
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

# Exit code based on test results.
#
# FailedCount alone is blind to the two ways coverage disappears without a single
# assertion failing: a *.Tests.ps1 file that throws during Pester's discovery
# phase (FailedContainersCount) and a top-level BeforeAll that throws
# (FailedBlocksCount). In both cases every test in that file is never executed
# and never counted, so a renamed helper, a bad merge, or a module that cannot be
# imported at all silently removes an entire module's coverage while the run
# reports "Failed: 0" and exits 0. Gate on the aggregate verdict instead.
$harnessBlocked = [int]$testResults.FailedContainersCount + [int]$testResults.FailedBlocksCount
if ($harnessBlocked -gt 0) {
    Write-Host "ERROR: $($testResults.FailedContainersCount) test file(s) failed discovery and $($testResults.FailedBlocksCount) block(s) failed setup." -ForegroundColor Red
    Write-Host '       Their tests were NEVER RUN and are not counted in the failure total.' -ForegroundColor Red
    foreach ($container in @($testResults.Containers | Where-Object { $_.Result -eq 'Failed' })) {
        $reason = @($container.ErrorRecord)[0]
        Write-Host "       - $($container.Item): $(if ($reason) { $reason.Exception.Message } else { 'setup failed' })" -ForegroundColor Red
    }
    exit 1
}
if ($testResults.TotalCount -eq 0) {
    Write-Host 'ERROR: Pester discovered zero tests.' -ForegroundColor Red
    exit 1
}
elseif ($testResults.Result -ne 'Passed' -or $testResults.FailedCount -gt 0) {
    exit 1
}
else {
    exit 0
}
