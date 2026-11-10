#Requires -Version 5.1

function Invoke-EdgeHardening {
    <#
    .SYNOPSIS
        Apply the Microsoft Edge v151 baseline profile plus explicit privacy additions.

    .DESCRIPTION
        The strict profile selects all 24 Microsoft v151 baseline values and
        nine separately labelled NoID Privacy values. The default profile does
        not alter the extension install policy, selecting 23 baseline values plus
        the nine privacy additions. By default DynamicCodeSettings carries Edge's
        own default 0, because the baseline value 1 makes Edge crash when it
        prints; AllowBrowserDynamicCode:$false selects the baseline value.
        Backup, Apply, Verify and Restore share one canonical
        target inventory. Registry exactness does not claim edge://policy runtime
        effectiveness, which still depends on Edge version and documented device
        management prerequisites.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions,

        [Parameter(Mandatory = $false)]
        [switch]$AllowBrowserDynamicCode
    )

    $startTime = Get-Date
    $result = [PSCustomObject]@{
        ModuleName             = 'EdgeHardening'
        Success                = $false
        Status                 = 'Failed'
        PoliciesSelected       = 0
        PoliciesApplied        = 0
        PoliciesPreviewed      = 0
        PoliciesSkipped        = 0
        PoliciesNotApplicable  = 0
        BaselineSelected       = 0
        PrivacySelected        = 0
        BackupCreated          = $false
        ComplianceVerified     = $null
        CompliancePercent      = 0
        RuntimePolicyVerified  = $null
        RuntimeApplicability   = 'NotEvaluated'
        AllowExtensions        = $null
        AllowBrowserDynamicCode = $null
        EdgeVersion            = $null
        Errors                 = [System.Collections.Generic.List[string]]::new()
        Warnings               = [System.Collections.Generic.List[string]]::new()
        Duration               = $null
    }

    try {

        if (-not $PSBoundParameters.ContainsKey('AllowExtensions')) {
            if (Test-NonInteractiveMode) {
                $AllowExtensions = [bool](Get-NonInteractiveValue -Module 'EdgeHardening' -Key 'allowExtensions' -Required)
                Write-NonInteractiveDecision -Module 'EdgeHardening' -Decision 'Browser extension blocklist' -Value $(if ($AllowExtensions) { 'Unmanaged; existing administrator policy preserved' } else { 'Block-all Microsoft baseline value selected' })
            }
            else {
                Write-Host ''
                Write-Host '===================================================================' -ForegroundColor Cyan
                Write-Host '  BROWSER EXTENSIONS POLICY' -ForegroundColor Cyan
                Write-Host '===================================================================' -ForegroundColor Cyan
                Write-Host ''
                Write-Host 'The Microsoft security baseline includes a policy that blocks ALL Edge' -ForegroundColor White
                Write-Host 'extensions. NoID Privacy can apply the hardening with or without that policy.' -ForegroundColor White
                Write-Host ''
                Write-Host '  [Y] Leave the extension blocklist unmanaged (NoID Privacy default; 32 selected values)' -ForegroundColor Green
                Write-Host '      - No new block-all policy is added' -ForegroundColor Gray
                Write-Host '      - Existing blocks remain; this choice does not unblock extensions' -ForegroundColor Gray
                Write-Host '      - An existing administrator blocklist policy is preserved untouched' -ForegroundColor Gray
                Write-Host ''
                Write-Host '  [N] Microsoft-baseline lockdown (33 selected values)' -ForegroundColor Cyan
                Write-Host '      - Blocks ALL extension installs and disables already-installed extensions' -ForegroundColor Gray
                Write-Host '      - Only extension IDs you add yourself to ExtensionInstallAllowlist' -ForegroundColor Gray
                Write-Host '        (registry/Intune) stay usable - NoID Privacy does not manage that allowlist' -ForegroundColor Gray
                Write-Host '      - Restore returns the blocklist to its exact saved pre-state' -ForegroundColor Gray
                Write-Host ''
                do {
                    Write-Host 'Leave the extension blocklist unmanaged? [Y/N] (default: Y): ' -ForegroundColor White -NoNewline
                    $choice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'Y' }
                    $choice = $choice.Trim().ToUpperInvariant()
                    if ($choice -notin @('Y', 'N')) {
                        Write-Host ''
                        Write-Host 'Invalid input. Please enter Y or N.' -ForegroundColor Red
                        Write-Host ''
                    }
                } while ($choice -notin @('Y', 'N'))
                $AllowExtensions = ($choice -eq 'Y')
                Write-Log -Level INFO -Message "User selected Edge extension profile: $(if ($AllowExtensions) { 'blocklist unmanaged; existing policy preserved' } else { 'block-all selected' })" -Module 'EdgeHardening'
            }
        }

        if (-not $PSBoundParameters.ContainsKey('AllowBrowserDynamicCode')) {
            if (Test-NonInteractiveMode) {
                $AllowBrowserDynamicCode = [bool](Get-NonInteractiveValue -Module 'EdgeHardening' -Key 'allowBrowserDynamicCode' -Required)
                Write-NonInteractiveDecision -Module 'EdgeHardening' -Decision 'Dynamic code in the Edge browser process' -Value $(if ($AllowBrowserDynamicCode) { 'Edge default (DynamicCodeSettings=0); Edge can print' } else { 'Blocked, Microsoft baseline value (DynamicCodeSettings=1); Edge cannot print' })
            }
            else {
                Write-Host ''
                Write-Host '===================================================================' -ForegroundColor Cyan
                Write-Host '  PRINTING FROM EDGE' -ForegroundColor Cyan
                Write-Host '===================================================================' -ForegroundColor Cyan
                Write-Host ''
                Write-Host 'The Microsoft security baseline stops the Edge browser process from' -ForegroundColor White
                Write-Host 'creating dynamic code. Microsoft notes that this can break printer' -ForegroundColor White
                Write-Host 'drivers; in our tests Edge then crashed when printing, also to PDF.' -ForegroundColor White
                Write-Host ''
                Write-Host '  [Y] Keep printing in Edge working (NoID Privacy default)' -ForegroundColor Green
                Write-Host '      - DynamicCodeSettings=0, the Edge default' -ForegroundColor Gray
                Write-Host '      - The sandbox settings of the baseline stay in place' -ForegroundColor Gray
                Write-Host ''
                Write-Host '  [N] Microsoft-baseline lockdown (DynamicCodeSettings=1)' -ForegroundColor Cyan
                Write-Host '      - Blocks dynamic code in the Edge browser process' -ForegroundColor Gray
                Write-Host '      - Edge can no longer print' -ForegroundColor Gray
                Write-Host ''
                do {
                    Write-Host 'Keep printing in Edge working? [Y/N] (default: Y): ' -ForegroundColor White -NoNewline
                    $choice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'Y' }
                    $choice = $choice.Trim().ToUpperInvariant()
                    if ($choice -notin @('Y', 'N')) {
                        Write-Host ''
                        Write-Host 'Invalid input. Please enter Y or N.' -ForegroundColor Red
                        Write-Host ''
                    }
                } while ($choice -notin @('Y', 'N'))
                $AllowBrowserDynamicCode = ($choice -eq 'Y')
                Write-Log -Level INFO -Message "User selected Edge dynamic-code setting: $(if ($AllowBrowserDynamicCode) { 'Edge default (printing works)' } else { 'blocked (Microsoft baseline)' })" -Module 'EdgeHardening'
            }
        }

        $runtimeApplicability = Get-EdgeRuntimeApplicability
        $edge = Get-EdgeInstallationStatus
        $targets = @(Get-EdgePolicyTargets -AllowExtensions:$AllowExtensions `
                -AllowBrowserDynamicCode:$AllowBrowserDynamicCode `
                -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge)
        $result.AllowExtensions = [bool]$AllowExtensions
        $result.AllowBrowserDynamicCode = [bool]$AllowBrowserDynamicCode
        $applicableTargets = @($targets | Where-Object { [bool]$_.Applicable })
        $notApplicableTargets = @($targets | Where-Object { -not [bool]$_.Applicable })
        $result.PoliciesSelected = $targets.Count
        $result.PoliciesNotApplicable = $notApplicableTargets.Count
        $result.BaselineSelected = @($targets | Where-Object { $_.Origin -eq 'MicrosoftBaseline' }).Count
        $result.PrivacySelected = @($targets | Where-Object { $_.Origin -eq 'NoIDPrivacy' }).Count

        if (@($edge.UnreadablePaths).Count -gt 0) {
            $warning = "$(@($edge.UnreadablePaths).Count) residual Edge executable candidate(s) had no parseable version and were excluded from version selection."
            $result.Warnings.Add($warning)
            Write-Log -Level WARNING -Message $warning -Module 'EdgeHardening'
        }
        if (@($edge.Installations).Count -gt 1) {
            $olderCount = @($edge.Installations | Where-Object {
                    [string]$_.Path -cne [string]$edge.Path -and
                    [version]$_.Version -lt [version]$edge.Version
                }).Count
            if ($olderCount -gt 0) {
                $warning = "$olderCount older residual Edge installation(s) were detected; the newest installation remains authoritative for machine-policy staging."
                $result.Warnings.Add($warning)
                Write-Log -Level WARNING -Message $warning -Module 'EdgeHardening'
            }
        }

        if ($edge.Installed) {
            $result.EdgeVersion = [string]$edge.Version
            if ([int]$edge.Major -lt 151) {
                $result.RuntimeApplicability = "EdgeOlderThan151Detected;PoliciesStagedForUpdate;$($runtimeApplicability.EvidenceSource)"
                $warning = "Microsoft Edge $($edge.Version) is older than the v151 source baseline; documented machine policies were staged, but current runtime consumption is not asserted."
                $result.Warnings.Add($warning)
                Write-Log -Level WARNING -Message $warning -Module 'EdgeHardening'
            }
            else {
                $result.RuntimeApplicability = "Edge151OrLaterDetected;$($runtimeApplicability.EvidenceSource)"
            }
        }
        else {
            $result.RuntimeApplicability = 'EdgeNotDetected;PoliciesStagedForFutureInstall'
            # Nothing is at risk: the policies wait for a future Edge install.
            Write-Log -Level INFO -Message 'Microsoft Edge was not detected; registry policies are staged for a future install, and runtime effectiveness cannot be evaluated.' -Module 'EdgeHardening'
        }

        if ($notApplicableTargets.Count -gt 0) {
            # Pure management-state applicability fact: the targets are already
            # reported per value as NotApplicable, so this stays an INFO note
            # instead of inflating the module warning count on every run.
            $managementNotApplicableCount = @($notApplicableTargets | Where-Object RequiresManagedWindows).Count
            $managedNote = "$($notApplicableTargets.Count) Edge policies are NotApplicable (management prerequisites: $managementNotApplicableCount). Per-target reasons are preserved in verification and HTML reports."
            Write-Log -Level INFO -Message $managedNote -Module 'EdgeHardening'
        }

        Write-Host ''
        $printingNote = if ($AllowBrowserDynamicCode) { ' (DynamicCodeSettings at the Edge default 0)' } else { '' }
        Write-Host "Selected: $($result.BaselineSelected) Microsoft v151 baseline policies$printingNote + $($result.PrivacySelected) privacy values" -ForegroundColor Green
        Write-Host ''

        if (-not $DryRun -and -not $PSCmdlet.ShouldProcess('Selected Microsoft Edge policy values', 'Backup, apply and exact readback')) {
            $result.Status = 'Skipped'
            return $result
        }

        if (-not $DryRun) {
            Write-Host '[1/4] Saving the current settings...' -ForegroundColor Cyan
            if (-not (Initialize-BackupSystem)) { throw 'Backup system initialization returned failure' }
            if (-not (Start-ModuleBackup -ModuleName 'EdgeHardening')) { throw 'EdgeHardening module backup folder was not created' }

            $backupResult = Backup-EdgePolicies -AllowExtensions:$AllowExtensions `
                -AllowBrowserDynamicCode:$AllowBrowserDynamicCode -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge
            if (-not $backupResult -or -not $backupResult.Success -or $backupResult.Errors.Count -gt 0 -or
                [int]$backupResult.DeclaredTargets -ne $targets.Count -or
                [int]$backupResult.TargetsBackedUp -ne $applicableTargets.Count -or
                [int]$backupResult.NotApplicable -ne $notApplicableTargets.Count) {
                $backupErrors = if ($backupResult) { @($backupResult.Errors) -join '; ' } else { 'no result' }
                throw "Edge backup failed or incomplete: $backupErrors"
            }
            $sealedSnapshot = Get-Content -LiteralPath $backupResult.BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $null = Assert-EdgePrestate -Snapshot $sealedSnapshot
            $registered = @($global:BackupIndex | Where-Object { $_.Module -eq 'EdgeHardening' })
            if ($registered.Count -ne 1 -or -not (Complete-ModuleBackup -ItemsBackedUp 1 -Status 'Success')) {
                throw "Edge backup manifest must seal exactly one artifact; found $($registered.Count)"
            }
            $null = Assert-EdgePrestate -Snapshot $sealedSnapshot
            $result.BackupCreated = $true
            Write-NoIDDetail '  Saved' -ForegroundColor Green
            Write-Host ''
        }
        else {
            Write-Host '[1/4] Preview only (DryRun): nothing is saved or changed' -ForegroundColor Cyan
            Write-Host ''
        }

        Write-Host $(if ($DryRun) { '[2/4] Checking what would change...' } else { '[2/4] Applying...' }) -ForegroundColor Cyan
        $applyResult = if ($DryRun) {
            Set-EdgePolicies -DryRun -AllowExtensions:$AllowExtensions `
                -AllowBrowserDynamicCode:$AllowBrowserDynamicCode -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge
        }
        else {
            Set-EdgePolicies -AllowExtensions:$AllowExtensions -Snapshot $sealedSnapshot
        }
        $completedTargetCount = if ($DryRun) { [int]$applyResult.Previewed } else { [int]$applyResult.Applied }
        if (-not $applyResult -or -not $applyResult.Success -or $applyResult.Errors.Count -gt 0 -or
            [int]$applyResult.Selected -ne $applicableTargets.Count -or
            $completedTargetCount -ne $applicableTargets.Count -or
            [int]$applyResult.NotApplicable -ne $notApplicableTargets.Count -or [int]$applyResult.Skipped -ne 0) {
            if ($applyResult) {
                foreach ($errorItem in @($applyResult.Errors)) { $result.Errors.Add([string]$errorItem) }
                $result.PoliciesApplied = [int]$applyResult.Applied
                $result.PoliciesPreviewed = [int]$applyResult.Previewed
                $result.PoliciesSkipped = [int]$applyResult.Skipped
            }
            throw 'Edge target processing did not complete every selected value exactly'
        }
        $result.PoliciesApplied = [int]$applyResult.Applied
        $result.PoliciesPreviewed = [int]$applyResult.Previewed
        Write-Host ''

        if (-not $DryRun) {
            Write-Host '[3/4] Checking...' -ForegroundColor Cyan
            $verifyResult = Test-EdgePolicies -AllowExtensions:$AllowExtensions -Snapshot $sealedSnapshot
            $result.ComplianceVerified = [bool]$verifyResult.Compliant
            $result.CompliancePercent = [double]$verifyResult.CompliancePercentage
            if (-not $verifyResult.Compliant -or [int]$verifyResult.SelectedCount -ne $targets.Count -or
                [int]$verifyResult.ApplicableCount -ne $applicableTargets.Count -or
                [int]$verifyResult.NotApplicableCount -ne $notApplicableTargets.Count -or
                [int]$verifyResult.CompliantCount -ne $applicableTargets.Count -or
                [int]$verifyResult.NonCompliantCount -ne 0) {
                throw "Edge exact registry verification failed: $($verifyResult.Message)"
            }
            Write-Host "  $($verifyResult.CompliantCount) passed, $($verifyResult.NonCompliantCount) failed, $($verifyResult.NotApplicableCount) not applicable on this PC (Edge version or device management)" -ForegroundColor Green
        }
        else {
            Write-Host '[3/4] Not checked in a preview (DryRun)' -ForegroundColor Cyan
        }
        Write-Host ''

        $result.Success = if ($DryRun) {
            ($result.PoliciesPreviewed -eq $applicableTargets.Count -and
                $result.PoliciesPreviewed + $result.PoliciesNotApplicable -eq $result.PoliciesSelected -and
                $result.Errors.Count -eq 0)
        }
        else {
            ($result.BackupCreated -and $result.PoliciesApplied -eq $applicableTargets.Count -and
                $result.PoliciesApplied + $result.PoliciesNotApplicable -eq $result.PoliciesSelected -and
                $result.ComplianceVerified -and $result.CompliancePercent -eq 100 -and
                $result.Errors.Count -eq 0)
        }
        if (-not $result.Success) {
            throw 'Edge completion counters did not reconcile with the selected inventory'
        }
        $result.Status = if ($DryRun) { 'DryRun' } else { 'Applied' }

        Write-Host '[4/4] Done' -ForegroundColor Cyan
        $completedLabel = if ($DryRun) { 'previewed' } else { 'applied and verified' }
        $completedCount = if ($DryRun) { $result.PoliciesPreviewed } else { $result.PoliciesApplied }
        # After Apply the framework prints the module result line; a preview keeps its own count.
        $completedLine = "  $completedCount Edge settings $completedLabel; $($result.PoliciesNotApplicable) not applicable on this PC (Edge version or device management)"
        if ($DryRun) { Write-Host $completedLine -ForegroundColor Green } else { Write-NoIDDetail $completedLine -ForegroundColor Green }
        Write-Host '  Restart Edge so every policy takes effect; edge://policy shows what Edge loaded.' -ForegroundColor Cyan
        Write-Host ''
        Write-Log -Level $(if ($DryRun) { 'INFO' } else { 'SUCCESS' }) -Message "Edge owned state completed: applied=$($result.PoliciesApplied), previewed=$($result.PoliciesPreviewed), NotApplicable=$($result.PoliciesNotApplicable), declared=$($result.PoliciesSelected)" -Module 'EdgeHardening'
    }
    catch {
        $result.Success = $false
        $result.Status = 'Failed'
        $message = "Edge hardening failed: $($_.Exception.Message)"
        if ($message -notin @($result.Errors)) { $result.Errors.Add($message) }
        Write-Log -Level ERROR -Message $message -Module 'EdgeHardening'
        if (-not $DryRun -and [string]$global:CurrentModule -eq 'EdgeHardening') {
            try {
                if (-not (Save-IncompleteModuleBackup -ModuleName 'EdgeHardening')) {
                    $result.Errors.Add('Failed to retain/classify the incomplete EdgeHardening backup')
                }
            }
            catch { $result.Errors.Add("Incomplete EdgeHardening backup retention failed: $($_.Exception.Message)") }
        }
        Write-Host "  ERROR: $message" -ForegroundColor Red
    }
    finally {
        $result.Duration = (Get-Date) - $startTime
    }

    return $result
}
