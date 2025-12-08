#Requires -Modules Pester

<#
.SYNOPSIS
    Run all Pester tests for NoID Privacy Framework
    
.DESCRIPTION
    Executes all unit and integration tests and generates a summary report
    
.EXAMPLE
    .\Run-AllTests.ps1
    
.EXAMPLE
    .\Run-AllTests.ps1 -OutputFile TestResults.xml
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string]$OutputLevel = 'Detailed'
)

$TestsRoot = $PSScriptRoot

Write-Host "NoID Privacy - Test Suite" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Configure Pester
$pesterConfig = New-PesterConfiguration
$pesterConfig.Run.Path = $TestsRoot
$pesterConfig.Run.PassThru = $true
$pesterConfig.Output.Verbosity = $OutputLevel
$pesterConfig.CodeCoverage.Enabled = $false

# Add output file if specified
if ($OutputFile) {
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = $OutputFile
    $pesterConfig.TestResult.OutputFormat = 'NUnitXml'
}

# Run tests
Write-Host "Running tests..." -ForegroundColor Yellow
Write-Host ""

$testResults = Invoke-Pester -Configuration $pesterConfig

# Summary
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.TotalCount)" -ForegroundColor White
Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor $(if ($testResults.FailedCount -gt 0) { "Red" } else { "White" })
Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration: $([math]::Round($testResults.Duration.TotalSeconds, 2))s" -ForegroundColor White
Write-Host ""

if ($OutputFile) {
    Write-Host "Test results saved to: $OutputFile" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($testResults.FailedCount -gt 0) {
    exit 1
}
else {
    exit 0
}
