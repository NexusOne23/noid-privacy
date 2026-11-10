<#
.SYNOPSIS
    Test exact selected Microsoft Edge policy registry state

.DESCRIPTION
    Public wrapper for Test-EdgePolicies.
    Verifies exact type and data for the selected Edge v151 baseline values and
    separately labelled privacy additions. This does not claim edge://policy
    runtime acceptance. Without an explicit AllowExtensions decision it reports
    the common controls and the live extension-block and dynamic-code states
    separately; it never invents a profile choice.
    Returns user-friendly compliance report.

.PARAMETER Detailed
    Show detailed policy-by-policy results

.PARAMETER AllowExtensions
    The saved extension choice. Pass it together with AllowBrowserDynamicCode
    (for example -AllowExtensions:$true -AllowBrowserDynamicCode:$true) or
    pass neither.

.PARAMETER AllowBrowserDynamicCode
    The saved printing choice ($true writes DynamicCodeSettings=0). Pass it
    together with AllowExtensions or pass neither.

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
    Version: 2.3.1
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
        [switch]$AllowExtensions,

        [Parameter(Mandatory = $false)]
        [switch]$AllowBrowserDynamicCode
    )

    # A missing switch would silently mean "lockdown"; a partial intent is
    # rejected instead of guessed.
    $extensionChoiceKnown = $PSBoundParameters.ContainsKey('AllowExtensions')
    $dynamicCodeChoiceKnown = $PSBoundParameters.ContainsKey('AllowBrowserDynamicCode')
    if ($extensionChoiceKnown -ne $dynamicCodeChoiceKnown) {
        throw 'Pass both -AllowExtensions and -AllowBrowserDynamicCode (each as -Name:$true or -Name:$false), or neither'
    }
    $intentKnown = $extensionChoiceKnown

    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "  Edge Security Compliance Test" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        # An intent-bound check evaluates the exact selected plan. A bare
        # standalone check measures live state without treating a hardcoded
        # extension choice as user intent.
        if ($intentKnown) {
            $testResult = Test-EdgePolicies -AllowExtensions:$AllowExtensions -AllowBrowserDynamicCode:$AllowBrowserDynamicCode
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
            $isExtensionRow = {
                param($Detail)
                [string]$Detail.Path -ieq 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -and
                    [string]$Detail.Policy -eq '1'
            }
            $isDynamicCodeRow = {
                param($Detail)
                [string]$Detail.Path -ieq 'HKLM:\Software\Policies\Microsoft\Edge' -and
                    [string]$Detail.Policy -ceq 'DynamicCodeSettings'
            }
            $extensionDetail = @($allResult.Details | Where-Object { & $isExtensionRow $_ })
            if ($extensionDetail.Count -ne 1) {
                throw "Standalone Edge state could not identify the extension block-all target"
            }
            $dynamicCodeDetail = @($allResult.Details | Where-Object { & $isDynamicCodeRow $_ })
            if ($dynamicCodeDetail.Count -ne 1) {
                throw "Standalone Edge state could not identify the dynamic-code target"
            }
            $commonDetails = @($allResult.Details | Where-Object { -not (& $isExtensionRow $_) -and -not (& $isDynamicCodeRow $_) })
            $commonNotApplicable = @($commonDetails | Where-Object Status -eq 'NotApplicable').Count
            $commonCompliant = @($commonDetails | Where-Object Status -eq 'Compliant').Count
            $commonFailed = @($commonDetails | Where-Object { $_.Status -notin @('Compliant','NotApplicable') }).Count
            $commonApplicable = $commonDetails.Count - $commonNotApplicable
            $commonPercentage = if ($commonApplicable -gt 0) {
                [math]::Round(($commonCompliant / $commonApplicable) * 100, 1)
            }
            else { 0 }
            # Both optional targets were planned with their lockdown value, so a
            # compliant row means the lockdown is live.
            $newObservation = {
                param($Detail, [string]$Subject)
                $measuredInactive = (
                    [string]$Detail.Status -eq 'WrongTypeOrValue' -or
                    ([string]$Detail.Status -eq 'ReadFailedOrMissing' -and
                        [string]$Detail.Error -in @('Registry key does not exist','Registry value does not exist'))
                )
                $status = if ([string]$Detail.Status -eq 'Compliant') { 'LiveActive' }
                    elseif ($measuredInactive) { 'LiveInactive' }
                    else { 'LiveStateUnavailable' }
                [PSCustomObject]@{
                    Policy = [string]$Detail.Policy
                    Path = [string]$Detail.Path
                    Origin = [string]$Detail.Origin
                    MinimumVersion = $Detail.MinimumVersion
                    ExpectedType = [string]$Detail.ExpectedType
                    Expected = $Detail.Expected
                    ActualType = $Detail.ActualType
                    Actual = $Detail.Actual
                    Status = $status
                    Error = if ($status -eq 'LiveStateUnavailable') {
                        "Live $Subject state unavailable: $([string]$Detail.Error)"
                    }
                    else { 'Observed live state only; no Edge profile intent was supplied.' }
                    Compliant = if ($status -eq 'LiveActive') { $true } elseif ($status -eq 'LiveInactive') { $false } else { $null }
                    Optional = $true
                }
            }
            $extensionObservation = & $newObservation $extensionDetail[0] 'extension'
            $dynamicCodeObservation = & $newObservation $dynamicCodeDetail[0] 'dynamic-code'
            $describe = {
                param([string]$Status)
                switch ($Status) { 'LiveActive' { 'ACTIVE' }; 'LiveInactive' { 'INACTIVE' }; default { 'UNAVAILABLE' } }
            }
            $testResult = [PSCustomObject]@{
                Compliant             = $null
                IntentKnown           = $false
                Message               = "Edge common owned state: $commonCompliant/$commonApplicable applicable values exact; extension block-all is $(& $describe $extensionObservation.Status); dynamic-code block is $(& $describe $dynamicCodeObservation.Status) (no profile intent supplied)"
                # The scorecard covers only the common, intent-independent
                # policy set. Extension block-all and the dynamic-code block
                # are separate live observations and must not distort those
                # counters.
                SelectedCount         = [int]$allResult.SelectedCount
                ApplicableCount       = [int]$commonApplicable
                NotApplicableCount    = [int]$commonNotApplicable
                CompliantCount        = [int]$commonCompliant
                NonCompliantCount     = [int]$commonFailed
                SkippedCount          = 2
                CompliancePercentage  = [double]$commonPercentage
                RuntimePolicyVerified = $null
                ExtensionBlocklistActive = $extensionObservation.Compliant
                BrowserDynamicCodeBlockActive = $dynamicCodeObservation.Compliant
                Details               = @($commonDetails) + @($extensionObservation) + @($dynamicCodeObservation)
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
            Write-Host "  - Passed:         $($testResult.CompliantCount)" -ForegroundColor Green
            Write-Host "  - Failed:         $($testResult.NonCompliantCount)" -ForegroundColor $(if ($testResult.NonCompliantCount -gt 0) { "Red" } else { "Green" })
            Write-Host "  - Not applicable: $($testResult.NotApplicableCount)" -ForegroundColor DarkGray
            Write-Host "  - Result:         $($testResult.CompliancePercentage)% of checked targets passed" -ForegroundColor White
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
            BrowserDynamicCodeBlockActive = $null
            Details                  = @()
        }
    }
}
