<#
.SYNOPSIS
    Test exact selected Microsoft Edge policy registry state

.DESCRIPTION
    Public wrapper for Test-EdgePolicies.
    Verifies exact type and data for the selected Edge v139 baseline values and
    separately labelled privacy additions. This does not claim edge://policy
    runtime acceptance. Without an explicit AllowExtensions decision it reports
    the common controls and the live extension-block state separately; it never
    invents a profile choice.
    Returns user-friendly compliance report.

.PARAMETER Detailed
    Show detailed policy-by-policy results

.EXAMPLE
    Test-EdgeHardening
    Run compliance check with summary

.EXAMPLE
    Test-EdgeHardening -Detailed
    Show detailed policy-by-policy compliance status

.OUTPUTS
    PSCustomObject with compliance status and details

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires Administrator privileges: the module-level
    "#Requires -RunAsAdministrator" in EdgeHardening.psm1 gates Import-Module
    itself, even though this compliance check is read-only.
#>

function Test-EdgeHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Detailed,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions
    )

    $intentKnown = $PSBoundParameters.ContainsKey('AllowExtensions')

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Edge Security Compliance Test" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        # An intent-bound check evaluates the exact selected plan. A bare
        # standalone check measures live state without treating a hardcoded
        # extension choice as user intent.
        if ($intentKnown) {
            $testResult = Test-EdgePolicies -AllowExtensions:$AllowExtensions
            $testResult | Add-Member -NotePropertyName IntentKnown -NotePropertyValue $true -Force
        }
        else {
            # One target-plan/read pass prevents a TOCTOU mixture of two Edge
            # versions or registry states. The extension row is observed but
            # excluded from the intent-independent scorecard.
            $allResult = Test-EdgePolicies -AllowExtensions:$false -ObserveExtensionWithoutIntent
            foreach ($requiredProperty in @(
                    'SelectedCount', 'ApplicableCount', 'NotApplicableCount',
                    'CompliantCount', 'NonCompliantCount', 'Details'
                )) {
                if (-not $allResult.PSObject.Properties[$requiredProperty]) {
                    $rootCause = if ($allResult.PSObject.Properties['Message']) {
                        [string]$allResult.Message
                    }
                    else { 'Edge policy inspection returned an incomplete contract' }
                    throw "Edge policy state unavailable: $rootCause"
                }
            }
            if ([int]$allResult.SelectedCount -eq 0 -and @($allResult.Details).Count -eq 0) {
                $rootCause = if ($allResult.PSObject.Properties['Message']) {
                    [string]$allResult.Message
                }
                else { 'Edge policy inspection returned no target evidence' }
                throw "Edge policy state unavailable: $rootCause"
            }
            $extensionDetail = @($allResult.Details | Where-Object {
                    [string]$_.Path -ieq 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -and
                    [string]$_.Policy -eq '1'
                })
            if ($extensionDetail.Count -ne 1) {
                throw "Standalone Edge state could not identify the extension block-all target"
            }
            $commonDetails = @($allResult.Details | Where-Object {
                    -not ([string]$_.Path -ieq 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -and
                        [string]$_.Policy -eq '1')
                })
            $commonNotApplicable = @($commonDetails | Where-Object Status -eq 'NotApplicable').Count
            $commonCompliant = @($commonDetails | Where-Object Status -eq 'Compliant').Count
            $commonFailed = @($commonDetails | Where-Object { $_.Status -notin @('Compliant','NotApplicable') }).Count
            $commonApplicable = $commonDetails.Count - $commonNotApplicable
            $commonPercentage = if ($commonApplicable -gt 0) {
                [math]::Round(($commonCompliant / $commonApplicable) * 100, 1)
            }
            else { 0 }
            $extensionMeasuredInactive = (
                [string]$extensionDetail[0].Status -eq 'WrongTypeOrValue' -or
                ([string]$extensionDetail[0].Status -eq 'ReadFailedOrMissing' -and
                    [string]$extensionDetail[0].Error -in @('Registry key does not exist','Registry value does not exist'))
            )
            $extensionStatus = if ([string]$extensionDetail[0].Status -eq 'Compliant') { 'LiveActive' }
                elseif ($extensionMeasuredInactive) { 'LiveInactive' }
                else { 'LiveStateUnavailable' }
            $extensionActive = if ($extensionStatus -eq 'LiveActive') { $true }
                elseif ($extensionStatus -eq 'LiveInactive') { $false }
                else { $null }
            $extensionObservation = [PSCustomObject]@{
                Policy = [string]$extensionDetail[0].Policy
                Path = [string]$extensionDetail[0].Path
                Origin = [string]$extensionDetail[0].Origin
                MinimumVersion = $extensionDetail[0].MinimumVersion
                ExpectedType = [string]$extensionDetail[0].ExpectedType
                Expected = $extensionDetail[0].Expected
                ActualType = $extensionDetail[0].ActualType
                Actual = $extensionDetail[0].Actual
                Status = $extensionStatus
                Error = if ($extensionStatus -eq 'LiveStateUnavailable') {
                    "Live extension state unavailable: $([string]$extensionDetail[0].Error)"
                }
                else { 'Observed live state only; no extension profile intent was supplied.' }
                Compliant = $extensionActive
                Optional = $true
            }
            $testResult = [PSCustomObject]@{
                Compliant             = $null
                IntentKnown           = $false
                Message               = "Edge common owned state: $commonCompliant/$commonApplicable applicable values exact; extension block-all is $(switch ($extensionStatus) { 'LiveActive' { 'ACTIVE' }; 'LiveInactive' { 'INACTIVE' }; default { 'UNAVAILABLE' } }) (no profile intent supplied)"
                # The scorecard covers only the common, intent-independent
                # policy set. Extension block-all is a separate live
                # observation and must not distort those counters.
                SelectedCount         = [int]$allResult.SelectedCount
                ApplicableCount       = [int]$commonApplicable
                NotApplicableCount    = [int]$commonNotApplicable
                CompliantCount        = [int]$commonCompliant
                NonCompliantCount     = [int]$commonFailed
                SkippedCount          = 1
                CompliancePercentage  = [double]$commonPercentage
                RuntimePolicyVerified = $null
                ExtensionBlocklistActive = $extensionActive
                Details               = @($commonDetails) + @($extensionObservation)
            }
        }

        # Display summary
        Write-Host "  Testing selected Microsoft Edge owned registry state..." -ForegroundColor White
        Write-Host ""

        if (-not $intentKnown) {
            Write-Host "  Status: LIVE STATE (no profile intent supplied)" -ForegroundColor Cyan
            Write-Host "  $($testResult.Message)" -ForegroundColor Cyan
        }
        elseif ($testResult.Compliant) {
            Write-Host "  Status: COMPLIANT" -ForegroundColor Green
            Write-Host "  $($testResult.Message)" -ForegroundColor Green
        }
        else {
            Write-Host "  Status: NON-COMPLIANT" -ForegroundColor Yellow
            Write-Host "  $($testResult.Message)" -ForegroundColor Yellow
        }

        Write-Host ""

        # Show details if requested
        if ($Detailed -and $testResult.Details) {
            Write-Host "  Policy Details:" -ForegroundColor White
            Write-Host ("  " + ("-" * 70)) -ForegroundColor Gray

            foreach ($detail in $testResult.Details) {
                $statusColor = if ($detail.Status -eq 'NotApplicable') { 'DarkGray' }
                    elseif ($detail.Status -in @('LiveActive', 'LiveInactive')) { 'Cyan' }
                    elseif ($detail.Status -eq 'LiveStateUnavailable') { 'Red' }
                    elseif ($detail.Compliant) { "Green" } else { "Yellow" }
                $statusSymbol = if ($detail.Status -eq 'NotApplicable') { '[-]' }
                    elseif ($detail.Status -eq 'LiveActive') { '[ON]' }
                    elseif ($detail.Status -eq 'LiveInactive') { '[OFF]' }
                    elseif ($detail.Status -eq 'LiveStateUnavailable') { '[?]' }
                    elseif ($detail.Compliant) { "[X]" } else { "[ ]" }

                Write-Host "  $statusSymbol " -ForegroundColor $statusColor -NoNewline
                Write-Host "$($detail.Policy)" -ForegroundColor White

                if ($detail.Status -eq 'NotApplicable') {
                    Write-Host "      NotApplicable: $($detail.Error)" -ForegroundColor DarkGray
                }
                elseif ($detail.Status -in @('LiveActive', 'LiveInactive')) {
                    Write-Host "      $($detail.Error)" -ForegroundColor Cyan
                }
                elseif ($detail.Status -eq 'LiveStateUnavailable') {
                    Write-Host "      $($detail.Error)" -ForegroundColor Red
                }
                elseif (-not $detail.Compliant) {
                    Write-Host "      Expected: $($detail.Expected)" -ForegroundColor Gray
                    Write-Host "      Actual:   $($detail.Actual)" -ForegroundColor Gray
                }
            }

            Write-Host ""
        }

        # Show summary statistics
        if ($testResult.PSObject.Properties.Name -contains 'CompliantCount') {
            Write-Host "  Summary:" -ForegroundColor White
            Write-Host "  - Compliant:     $($testResult.CompliantCount)" -ForegroundColor Green
            Write-Host "  - Non-Compliant: $($testResult.NonCompliantCount)" -ForegroundColor $(if ($testResult.NonCompliantCount -gt 0) { "Yellow" } else { "Green" })
            Write-Host "  - NotApplicable: $($testResult.NotApplicableCount)" -ForegroundColor DarkGray
            Write-Host "  - Compliance:    $($testResult.CompliancePercentage)%" -ForegroundColor White
            Write-Host ""
        }

        if ($intentKnown -and -not $testResult.Compliant) {
            Write-Host "  Recommendation: Run Invoke-EdgeHardening to apply the selected profile" -ForegroundColor Yellow
            Write-Host ""
        }

        return $testResult
    }
    catch {
        Write-Host "  ERROR: Compliance test failed" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""

        return [PSCustomObject]@{
            Compliant                 = $false
            IntentKnown              = $intentKnown
            Message                  = "Test failed: $($_.Exception.Message)"
            SelectedCount            = 0
            ApplicableCount          = 0
            NotApplicableCount       = 0
            CompliantCount           = 0
            NonCompliantCount        = 0
            SkippedCount             = 0
            CompliancePercentage     = 0
            RuntimePolicyVerified    = $null
            ExtensionBlocklistActive = $null
            Details                  = @()
        }
    }
}
