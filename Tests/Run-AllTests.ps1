#Requires -Version 5.1

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

$requiredPesterVersion = [Version]'5.9.0'
$pesterModule = Get-Module -Name Pester -ListAvailable | Where-Object Version -eq $requiredPesterVersion | Select-Object -First 1
if ($null -eq $pesterModule) {
    Write-Host "ERROR: Exact Pester $requiredPesterVersion is required." -ForegroundColor Red
    exit 1
}
Import-Module Pester -RequiredVersion $requiredPesterVersion -ErrorAction Stop

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

# An automated aggregate runner must never block on a module's product prompt.
# Individual prompt tests can still override the process variable explicitly.
$previousNonInteractive = [Environment]::GetEnvironmentVariable('NOIDPRIVACY_NONINTERACTIVE', 'Process')
try {
    $env:NOIDPRIVACY_NONINTERACTIVE = 'true'
    Write-Host "Running tests..." -ForegroundColor Yellow
    Write-Host ""
    $testResults = Invoke-Pester -Configuration $pesterConfig
}
finally {
    if ($null -eq $previousNonInteractive) {
        Remove-Item Env:NOIDPRIVACY_NONINTERACTIVE -ErrorAction SilentlyContinue
    }
    else {
        $env:NOIDPRIVACY_NONINTERACTIVE = $previousNonInteractive
    }
}

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

# Exit with appropriate code.
#
# Same blindness as Run-Tests.ps1: a file that throws in discovery
# (FailedContainersCount) or a top-level BeforeAll that throws
# (FailedBlocksCount) removes every test in that file from the run WITHOUT
# adding to FailedCount, so the suite reports zero failures for coverage that
# never executed.
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
