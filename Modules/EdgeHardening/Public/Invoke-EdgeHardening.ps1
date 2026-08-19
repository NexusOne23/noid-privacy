#Requires -Version 5.1

function Invoke-EdgeHardening {
    <#
    .SYNOPSIS
        Apply the Microsoft Edge v139 baseline profile plus explicit privacy additions.

    .DESCRIPTION
        The strict profile selects all 19 Microsoft v139 baseline values and
        seven separately labelled NoID Privacy values. The default profile does
        not alter the extension install policy, selecting 18 baseline values plus
        the seven privacy additions. Backup, Apply, Verify and Restore share one canonical
        target inventory. Registry exactness does not claim edge://policy runtime
        effectiveness, which still depends on Edge version and documented device
        management prerequisites.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions
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
                Write-Host '  [Y] Leave the extension blocklist unmanaged (NoID Privacy default; 25 selected values)' -ForegroundColor Green
                Write-Host '      - No block-all policy is added; extensions keep working' -ForegroundColor Gray
                Write-Host '      - New extension installs stay possible' -ForegroundColor Gray
                Write-Host '      - An existing administrator blocklist policy is preserved untouched' -ForegroundColor Gray
                Write-Host ''
                Write-Host '  [N] Microsoft-baseline lockdown (26 selected values)' -ForegroundColor Cyan
                Write-Host '      - Blocks ALL extension installs and disables already-installed extensions' -ForegroundColor Gray
                Write-Host '      - Only extension IDs you add yourself to ExtensionInstallAllowlist' -ForegroundColor Gray
                Write-Host '        (registry/Intune) stay usable - NoID Privacy does not manage that allowlist' -ForegroundColor Gray
                Write-Host '      - Restore removes the policy and re-enables extensions' -ForegroundColor Gray
                Write-Host ''
                do {
                    Write-Host 'Leave the extension blocklist unmanaged? [Y/N] (default: Y): ' -ForegroundColor Yellow -NoNewline
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

        $runtimeApplicability = Get-EdgeRuntimeApplicability
        $edge = Get-EdgeInstallationStatus
        $targets = @(Get-EdgePolicyTargets -AllowExtensions:$AllowExtensions `
                -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge)
        $result.AllowExtensions = [bool]$AllowExtensions
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
            if ([int]$edge.Major -lt 139) {
                $result.RuntimeApplicability = "EdgeOlderThan139Detected;PoliciesStagedForUpdate;$($runtimeApplicability.EvidenceSource)"
                $warning = "Microsoft Edge $($edge.Version) is older than the v139 source baseline; documented machine policies were staged, but current runtime consumption is not asserted."
                $result.Warnings.Add($warning)
                Write-Log -Level WARNING -Message $warning -Module 'EdgeHardening'
            }
            else {
                $result.RuntimeApplicability = "Edge139OrLaterDetected;$($runtimeApplicability.EvidenceSource)"
            }
        }
        else {
            $result.RuntimeApplicability = 'EdgeNotDetected;PoliciesStagedForFutureInstall'
            $warning = 'Microsoft Edge was not detected; registry policies can be staged, but runtime effectiveness cannot be evaluated.'
            $result.Warnings.Add($warning)
            Write-Log -Level WARNING -Message $warning -Module 'EdgeHardening'
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
        Write-Host '========================================' -ForegroundColor Cyan
        Write-Host '  EDGE HARDENING MODULE' -ForegroundColor Cyan
        Write-Host '========================================' -ForegroundColor Cyan
        Write-Host "Selected: $($result.BaselineSelected) Microsoft v139 baseline + $($result.PrivacySelected) NoID Privacy values" -ForegroundColor White
        Write-Host 'The LGPO **delvals. row is metadata and is never counted or applied.' -ForegroundColor DarkGray
        Write-Host ''

        if (-not $DryRun -and -not $PSCmdlet.ShouldProcess('Selected Microsoft Edge policy values', 'Backup, apply and exact readback')) {
            $result.Status = 'Skipped'
            return $result
        }

        if (-not $DryRun) {
            Write-Host '[1/4] BACKUP - Sealing exact selected prestate...' -ForegroundColor Cyan
            if (-not (Initialize-BackupSystem)) { throw 'Backup system initialization returned failure' }
            if (-not (Start-ModuleBackup -ModuleName 'EdgeHardening')) { throw 'EdgeHardening module backup folder was not created' }

            $backupResult = Backup-EdgePolicies -AllowExtensions:$AllowExtensions `
                -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge
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
            Write-Host "  Exact prestate sealed for $($applicableTargets.Count)/$($targets.Count) applicable selected values; NotApplicable=$($notApplicableTargets.Count)." -ForegroundColor Green
        }
        else {
            Write-Host '[1/4] BACKUP - Not created in DryRun.' -ForegroundColor Yellow
        }

        Write-Host $(if ($DryRun) { '[2/4] PREVIEW - Validating the canonical selected inventory...' } else { '[2/4] APPLY - Writing the canonical selected inventory...' }) -ForegroundColor Cyan
        $applyResult = if ($DryRun) {
            Set-EdgePolicies -DryRun -AllowExtensions:$AllowExtensions `
                -RuntimeApplicability $runtimeApplicability -EdgeInstallationStatus $edge
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

        if (-not $DryRun) {
            Write-Host '[3/4] VERIFY - Reading back exact type and data...' -ForegroundColor Cyan
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
        }
        else {
            Write-Host '[3/4] VERIFY - Not performed in DryRun.' -ForegroundColor Yellow
        }

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
        $result.Status = if ($DryRun) { 'DryRun' } else { 'Applied' }

        Write-Host '[4/4] COMPLETE' -ForegroundColor Green
        $completedLabel = if ($DryRun) { 'previewed' } else { 'applied/verified' }
        $completedCount = if ($DryRun) { $result.PoliciesPreviewed } else { $result.PoliciesApplied }
        Write-Host "  Owned registry state: $completedCount applicable $completedLabel; $($result.PoliciesNotApplicable) NotApplicable; $($result.PoliciesSelected) declared" -ForegroundColor Green
        Write-Host '  Runtime policy status: NotChecked (inspect edge://policy on the target Windows 11 device)' -ForegroundColor Yellow
        Write-Host '  Browser restart is required for policies without dynamic refresh.' -ForegroundColor Gray
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
