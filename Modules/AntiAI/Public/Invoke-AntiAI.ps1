#Requires -Version 5.1
#Requires -RunAsAdministrator

function Invoke-AntiAI {
    <#
    .SYNOPSIS
        Applies and verifies the canonical reversible Windows 11 AI policy set.

    .DESCRIPTION
        Uses one config-derived target inventory for Backup, Apply and Verify.
        The BAVR snapshot preserves exact key/value existence, registry kind and
        unexpanded data. Copilot URI handlers are backed up and removed from the
        real HKLM Classes source and the interactive user's loaded HKU source.

        Registry verification proves requested state, not runtime enforcement on
        an edition/build/app version where Microsoft documents a policy as
        inapplicable. The current consumer Copilot MSIX app is not falsely claimed
        blocked by the deprecated TurnOffWindowsCopilot compatibility policy.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $startTime = Get-Date
    $result = [PSCustomObject]@{
        Success              = $false
        TotalFeatures        = 12
        Applied              = 0
        Previewed            = 0
        Failed               = 0
        DeclaredPolicyTargets = 0
        AppliedPolicyTargets = 0
        UriSourceChecksApplied = 0
        PreviewedPolicyTargets = 0
        NotApplicablePolicyTargets = 0
        ApplicableTargetPlan  = @()
        NotApplicableTargetPlan = @()
        VerificationPassed   = $null
        Applicability        = $null
        Warnings             = @()
        Errors               = @()
        RequiresReboot       = $false
        StartTime            = $startTime
        EndTime              = $null
        Duration             = $null
    }
    $moduleBackupPath = $null

    try {
        # Establish and validate the complete target scope even in DryRun. A
        # malformed config must never be hidden behind a backup-mode branch.
        $targets = @(Get-AntiAIRegistryTargets)
        $declaredCount = Get-AntiAIDeclaredPolicyCount
        $result.DeclaredPolicyTargets = $declaredCount

        $result.Applicability = Get-AntiAIApplicability
        if (-not $result.Applicability.SupportedWindowsProfile) {
            throw 'AntiAI requires Windows 11 24H2/25H2 or the explicitly recognized 26H2 Experimental Preview path, which is currently not runtime-validated or release-approved'
        }
        foreach ($warning in @($result.Applicability.Warnings)) {
            $result.Warnings += [string]$warning
            Write-Log -Level WARNING -Message ([string]$warning) -Module 'AntiAI'
        }
        foreach ($note in @($result.Applicability.ApplicabilityNotes)) {
            Write-Log -Level INFO -Message ([string]$note) -Module 'AntiAI'
        }
        $targetPlan = Get-AntiAITargetPlan -Targets $targets -Applicability $result.Applicability
        $applicableTargets = @($targetPlan.ApplicableTargets)
        $notApplicableTargets = @($targetPlan.NotApplicableTargets)
        $result.NotApplicablePolicyTargets = [int]$targetPlan.NotApplicableCount
        $result.ApplicableTargetPlan = @($applicableTargets | ForEach-Object {
                [PSCustomObject]@{ Path = [string]$_.Path; Name = [string]$_.Name }
            })
        $result.NotApplicableTargetPlan = @($notApplicableTargets | ForEach-Object {
                [PSCustomObject]@{ Path = [string]$_.Path; Name = [string]$_.Name }
            })

        Write-Host ''
        Write-Host '========================================' -ForegroundColor Cyan
        Write-Host '  ANTI-AI MODULE' -ForegroundColor Cyan
        Write-Host '========================================' -ForegroundColor Cyan
        Write-Host ''
        Write-Host "Canonical reversible scope: $declaredCount registry targets + 4 URI source hives" -ForegroundColor White
        Write-Host 'Runtime applicability is reported separately from registry verification.' -ForegroundColor Gray
        Write-Host 'The current consumer Copilot MSIX needs an effective AppLocker/App Control policy.' -ForegroundColor Yellow
        if ($DryRun) {
            Write-Host '[DRY RUN - validation and preview only]' -ForegroundColor Yellow
        }
        Write-Host ''

        Write-Host '[1/4] BACKUP - Sealing exact prestate...' -ForegroundColor Cyan
        if (-not $DryRun) {
            if (-not (Initialize-BackupSystem)) {
                throw 'Backup system initialization returned failure'
            }
            $moduleBackupPath = Start-ModuleBackup -ModuleName 'AntiAI'
            if ([string]::IsNullOrWhiteSpace([string]$moduleBackupPath) -or
                -not (Test-Path -LiteralPath $moduleBackupPath -PathType Container -ErrorAction Stop)) {
                throw 'AntiAI module backup folder was not created'
            }

            $preState = [System.Collections.Generic.List[object]]::new()
            $readFailures = [System.Collections.Generic.List[string]]::new()
            foreach ($target in $applicableTargets) {
                $entry = [PSCustomObject]@{
                    Path       = [string]$target.Path
                    Name       = [string]$target.Name
                    KeyExisted = $false
                    Exists     = $false
                    Type       = $null
                    Value      = $null
                }
                try {
                    if (Test-Path -LiteralPath $target.Path -PathType Container -ErrorAction Stop) {
                        $entry.KeyExisted = $true
                        $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                        if ($key.GetValueNames() -contains [string]$target.Name) {
                            $entry.Exists = $true
                            $entry.Type = $key.GetValueKind([string]$target.Name).ToString()
                            $entry.Value = $key.GetValue(
                                [string]$target.Name,
                                $null,
                                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                            )
                        }
                    }
                }
                catch {
                    $readFailures.Add("$($target.Path)::$($target.Name): $($_.Exception.Message)")
                }
                $preState.Add($entry)
            }
            if ($readFailures.Count -gt 0) {
                throw "AntiAI prestate contains unreadable targets: $($readFailures -join '; ')"
            }

            $snapshot = [PSCustomObject]@{
                SchemaVersion           = 4
                DeclaredTargetCount     = $targets.Count
                ApplicableTargetCount   = $applicableTargets.Count
                NotApplicableTargetCount = $notApplicableTargets.Count
                Entries                 = @($preState)
                NotApplicableTargets    = @($notApplicableTargets | Select-Object Path, Name, Reason)
            }
            $null = Assert-AntiAIRegistrySnapshot -Snapshot $snapshot
            $preStatePath = Register-Backup -Type 'AntiAI' -Data $snapshot -Name 'AntiAI_PreState'
            if (-not $preStatePath) {
                throw 'AntiAI prestate snapshot registration failed'
            }
            $roundTrip = Get-Content -LiteralPath $preStatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $null = Assert-AntiAIRegistrySnapshot -Snapshot $roundTrip

            $userRoot = (Get-AntiAIUserContext).Root
            $uriSources = @(
                @{ Path = 'HKLM:\SOFTWARE\Classes\ms-copilot'; Name = 'URI_HKLM_ms-copilot' },
                @{ Path = "$userRoot\Software\Classes\ms-copilot"; Name = 'URI_HKU_ms-copilot' },
                @{ Path = 'HKLM:\SOFTWARE\Classes\ms-edge-copilot'; Name = 'URI_HKLM_ms-edge-copilot' },
                @{ Path = "$userRoot\Software\Classes\ms-edge-copilot"; Name = 'URI_HKU_ms-edge-copilot' }
            )
            foreach ($source in $uriSources) {
                if (-not (Backup-RegistryKey -KeyPath $source.Path -BackupName $source.Name)) {
                    throw "URI handler source backup failed: $($source.Path)"
                }
            }

            $artifacts = @($global:BackupIndex | Where-Object { $_.Module -eq 'AntiAI' })
            if ($artifacts.Count -ne 5) {
                throw "AntiAI backup must contain exactly five artifacts; got $($artifacts.Count)"
            }
            if (-not (Assert-AntiAIPrestate -Snapshot $snapshot -UriSources $uriSources)) {
                throw 'AntiAI final prestate reconciliation returned failure'
            }
            if (-not (Complete-ModuleBackup -ItemsBackedUp $artifacts.Count -Status 'Success')) {
                throw 'AntiAI backup manifest completion failed'
            }
            Write-Host "  Sealed $($artifacts.Count) validated artifacts" -ForegroundColor Green
        }
        else {
            Write-Host '  Skipped writes (DryRun)' -ForegroundColor Gray
        }
        Write-Host ''

        Write-Host '[2/4] APPLY - Configuring canonical AI controls...' -ForegroundColor Cyan
        if (-not $DryRun) {
            $null = Assert-AntiAIPrestate -Snapshot $snapshot -UriSources $uriSources
            $currentPlan = Get-AntiAITargetPlan -Targets $targets -Applicability (Get-AntiAIApplicability)
            $sealedPlanIdentity = @($applicableTargets | ForEach-Object { "$($_.Path)::$($_.Name)" } | Sort-Object) -join "`n"
            $currentPlanIdentity = @($currentPlan.ApplicableTargets | ForEach-Object { "$($_.Path)::$($_.Name)" } | Sort-Object) -join "`n"
            if ($currentPlanIdentity -cne $sealedPlanIdentity) {
                throw 'AntiAI applicability changed after backup; refusing to apply targets outside the sealed plan'
            }
        }
        $registryApply = Set-AntiAIRegistryTargets `
            -Targets $applicableTargets `
            -DeclaredCount $declaredCount `
            -DryRun:$DryRun
        if (-not $registryApply.Success) {
            $result.Failed++
            $result.Errors += @($registryApply.Errors)
        }
        $result.AppliedPolicyTargets = [int]$registryApply.Applied
        $result.PreviewedPolicyTargets = [int]$registryApply.Previewed

        $uriApply = Disable-CopilotURIHandlers -DryRun:$DryRun
        if (-not $uriApply.Success) {
            $result.Failed++
            $result.Errors += @($uriApply.Errors)
        }

        if ($DryRun) {
            if ($registryApply.Success) { $result.Previewed += [int]$registryApply.FeatureGroups }
            if ($uriApply.Success) { $result.Previewed++ }
        }
        else {
            if ($registryApply.Success) { $result.Applied += [int]$registryApply.FeatureGroups }
            if ($uriApply.Success) {
                $result.Applied++
                $result.UriSourceChecksApplied = [int]$uriApply.Verified
            }
            if ($registryApply.Success -and @($applicableTargets | Where-Object {
                        [string]$_.Path -like 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                    }).Count -gt 0) {
                $result.RequiresReboot = $true
            }
        }
        Write-Host "  Registry targets: $($registryApply.Applied) applied; $($registryApply.Previewed) previewed; $($targetPlan.NotApplicableCount) not applicable; $declaredCount declared" `
            -ForegroundColor $(if ($registryApply.Success) { 'Green' } else { 'Red' })
        Write-Host "  URI source hives: $($uriApply.Verified)/$($uriApply.Declared) verified absent; $($uriApply.Previewed) previewed" `
            -ForegroundColor $(if ($uriApply.Success) { 'Green' } else { 'Red' })
        Write-Host ''

        Write-Host '[3/4] VERIFY - Checking exact owned state...' -ForegroundColor Cyan
        if ($DryRun) {
            Write-Host '  Skipped (DryRun)' -ForegroundColor Gray
        }
        elseif ($result.Failed -gt 0) {
            Write-Host '  Skipped because Apply was incomplete' -ForegroundColor Yellow
        }
        else {
            $verification = Test-AntiAICompliance `
                -ApplicableTargets $applicableTargets `
                -NotApplicableTargets $notApplicableTargets
            $result.VerificationPassed = ($verification.OverallStatus -eq 'PASS')
            if (-not $result.VerificationPassed) {
                $result.Failed++
                $result.Errors += "AntiAI verification failed: $($verification.FailedChecks)/$($verification.TotalChecks) checks failed"
            }
            Write-Host "  $($verification.Passed)/$($verification.TotalChecks) exact checks passed" `
                -ForegroundColor $(if ($result.VerificationPassed) { 'Green' } else { 'Red' })
        }
        Write-Host ''

        $result.Success = if ($DryRun) {
            $result.Failed -eq 0 -and $result.Errors.Count -eq 0 -and
                ($result.PreviewedPolicyTargets + $result.NotApplicablePolicyTargets) -eq $declaredCount
        }
        else {
            $result.Failed -eq 0 -and $result.Errors.Count -eq 0 -and
                ($result.AppliedPolicyTargets + $result.NotApplicablePolicyTargets) -eq $declaredCount -and
                $result.VerificationPassed -eq $true
        }
        $result.EndTime = Get-Date
        $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds

        Write-Host '[4/4] COMPLETE' -ForegroundColor Cyan
        if ($result.Success) {
            Write-Host '  SUCCESS - declared registry/URI state applied and exactly verified' -ForegroundColor Green
        }
        else {
            Write-Host '  FAILED - AntiAI did not satisfy its complete declared-state contract' -ForegroundColor Red
        }
        Write-Host "  Registry scope: $($result.AppliedPolicyTargets) applied; $($result.PreviewedPolicyTargets) previewed; $($result.NotApplicablePolicyTargets) not applicable; $declaredCount declared" -ForegroundColor Gray
        Write-Host "  Errors: $($result.Errors.Count); warnings: $($result.Warnings.Count)" -ForegroundColor Gray
        if ($moduleBackupPath) {
            Write-Host "  Backup: $moduleBackupPath" -ForegroundColor Cyan
        }
        if ($result.RequiresReboot) {
            Write-Host '  Reboot required for applicable Recall/AI policies to be reevaluated.' -ForegroundColor Yellow
        }
        if ($result.Errors.Count -gt 0) {
            foreach ($errorMessage in $result.Errors) {
                Write-Host "  - $errorMessage" -ForegroundColor Red
            }
        }

        if ($result.Success -and -not $DryRun) {
            Write-Log -Level SUCCESS -Message "AntiAI complete: $($result.AppliedPolicyTargets) applicable registry targets applied/verified, $($result.NotApplicablePolicyTargets) not applicable, $declaredCount declared, four URI source checks passed" -Module 'AntiAI'
        }
        elseif ($DryRun -and $result.Success) {
            Write-Log -Level INFO -Message "DryRun classified all $declaredCount AntiAI targets: $($result.PreviewedPolicyTargets) applicable previews, $($result.NotApplicablePolicyTargets) not applicable; four URI sources previewed" -Module 'AntiAI'
        }
        else {
            Write-Log -Level ERROR -Message 'AntiAI completion marker withheld because the complete contract was not satisfied' -Module 'AntiAI'
        }
        return $result
    }
    catch {
        $result.Success = $false
        $result.Failed++
        $result.Errors += "Critical error: $($_.Exception.Message)"
        if ([string]$global:CurrentModule -eq 'AntiAI') {
            try {
                if (-not (Save-IncompleteModuleBackup -ModuleName 'AntiAI')) {
                    $result.Errors += 'Incomplete AntiAI backup could not be retained/classified safely'
                }
            }
            catch {
                $result.Errors += "Incomplete AntiAI backup retention failed: $($_.Exception.Message)"
            }
        }
        $result.EndTime = Get-Date
        $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds
        Write-Log -Level ERROR -Message $result.Errors[-1] -Module 'AntiAI'
        return $result
    }
}
