function Invoke-PrivacyHardening {
    <#
    .SYNOPSIS
        Apply privacy hardening with telemetry control, OneDrive/Store policy configuration, and exact BAVR

    .DESCRIPTION
        Interactive privacy hardening module with 3 operating modes:
        - MSRecommended (default): Least-disruptive selected controls without relaxing stricter existing policy
        - Strict: Maximum privacy for Enterprise/Edu
        - Paranoid: Hardcore mode (not recommended)

        Follows Backup-Apply-Verify-Restore pattern for safety.

    .PARAMETER Mode
        Privacy mode: MSRecommended, Strict, or Paranoid

    .PARAMETER DryRun
        Show what would be done without making changes

    .EXAMPLE
        Invoke-PrivacyHardening

    .EXAMPLE
        Invoke-PrivacyHardening -Mode Strict
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("MSRecommended", "Strict", "Paranoid")]
        [string]$Mode,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Invoke-PrivacyHardening requires an elevated administrator token'
        }
        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!

        Write-Log -Level INFO -Message "Starting Privacy Hardening Module..." -Module "Privacy"

        # Mode selection - NonInteractive or Interactive
        $modeConfirmed = $false
        if (!$Mode) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $Mode = Get-NonInteractiveValue -Module "Privacy" -Key "mode" -Required
                Write-NonInteractiveDecision -Module "Privacy" -Decision "Privacy Mode" -Value $Mode
                $modeConfirmed = $true
            }
            else {
                # Interactive mode
                while (-not $modeConfirmed) {
                    Write-Host ""
                    Write-Host "===================================================================" -ForegroundColor Cyan
                    Write-Host "  PRIVACY HARDENING - MODE SELECTION" -ForegroundColor Cyan
                    Write-Host "===================================================================" -ForegroundColor Cyan
                    Write-Host ""

                    Write-Host "Mode 1: MSRecommended (DEFAULT)" -ForegroundColor Green
                    Write-Host "  - Selected registry/policy hardening; existing stricter app permissions are preserved" -ForegroundColor Gray
                    Write-Host "  - AllowTelemetry = Required (1)" -ForegroundColor Gray
                    Write-Host "  - Services NOT disabled" -ForegroundColor Gray
                    Write-Host "  - AppPrivacy/Settings Sync: Existing policy is left untouched" -ForegroundColor Gray
                    Write-Host "  - Best for: Compatibility-focused standalone workstations`n" -ForegroundColor Gray

                    Write-Host "Mode 2: Strict" -ForegroundColor Yellow
                    Write-Host "  - Strict selected controls; effectiveness remains edition/build dependent" -ForegroundColor Gray
                    Write-Host "  - AllowTelemetry = Off (Enterprise/Edu only, Pro falls back)" -ForegroundColor Gray
                    Write-Host "  - Services: DiagTrack + dmwappushservice disabled" -ForegroundColor Gray
                    Write-Host "  - Force Deny: Location, App-Diagnose, Generative AI" -ForegroundColor Gray
                    Write-Host "  - Other app-permission policies are preserved (not relaxed)" -ForegroundColor Gray
                    Write-Host "  - Win+V local-history policy is preserved; cloud sync is disabled" -ForegroundColor Gray
                    Write-Host "  - Cellular text-message cloud backup is disabled where supported" -ForegroundColor Gray
                    Write-Host "  - Best for: Privacy-focused home users, small business`n" -ForegroundColor Gray

                    Write-Host "Mode 3: Paranoid" -ForegroundColor Red
                    Write-Host "  - Hardcore (NOT recommended)" -ForegroundColor Gray
                    Write-Host "  - Everything from Strict + WerSvc disabled" -ForegroundColor Gray
                    Write-Host "  - Tasks disabled (CEIP, AppExperience)" -ForegroundColor Gray
                    Write-Host "  - Force Deny: broad declared app permissions (Mic, Camera, etc.)" -ForegroundColor Gray
                    Write-Host "  - Online fonts and automatic device companion-app downloads are disabled" -ForegroundColor Gray
                    Write-Host "  - WARNING: microphone/camera and other denied capabilities will be unavailable to affected apps" -ForegroundColor Red
                    Write-Host "  - Best for: Air-gapped, kiosk, extreme privacy only`n" -ForegroundColor Gray

                    do {
                        Write-Host "Select mode [1-3] (default: 1): " -ForegroundColor Yellow -NoNewline
                        $modeSelection = Read-Host
                        if ([string]::IsNullOrWhiteSpace($modeSelection)) { $modeSelection = "1" }

                        if ($modeSelection -notin @('1', '2', '3')) {
                            Write-Host ""
                            Write-Host "Invalid input. Please enter 1, 2, or 3." -ForegroundColor Red
                            Write-Host ""
                        }
                    } while ($modeSelection -notin @('1', '2', '3'))

                    $Mode = switch ($modeSelection) {
                        "1" { "MSRecommended" }
                        "2" { "Strict" }
                        "3" { "Paranoid" }
                    }
                    Write-Host "`nSelected mode: $Mode`n" -ForegroundColor Cyan
                    Write-Log -Level DEBUG -Message "User selected privacy mode: $Mode" -Module "Privacy"

                    # Load configuration for warnings
                    $configPath = Join-Path $PSScriptRoot "..\Config\Privacy-$Mode.json"
                    if (!(Test-Path $configPath)) {
                        Write-Log -Level ERROR -Message "Configuration file not found: $configPath" -Module "Privacy"
                        return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Config not found" }
                    }

                    $privacyConfig = Get-Content $configPath -Raw | ConvertFrom-Json

                    # Display warnings and confirm
                    if ($privacyConfig.Warnings.Count -gt 0) {
                        Write-Host ""
                        Write-Host "===================================================================" -ForegroundColor Cyan
                        Write-Host "  MODE WARNINGS" -ForegroundColor Cyan
                        Write-Host "===================================================================" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "WARNINGS for $Mode mode:" -ForegroundColor White
                        foreach ($warning in $privacyConfig.Warnings) {
                            Write-Host "  - $warning" -ForegroundColor Yellow
                        }
                        Write-Host ""
                        Write-Host "Do you want to continue?" -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "  [Y] YES - Continue with $Mode mode (default)" -ForegroundColor Green
                        Write-Host "      - Applies $Mode hardening despite the warnings above" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  [N] NO - Return to mode selection" -ForegroundColor Cyan
                        Write-Host "      - Pick a different privacy mode" -ForegroundColor Gray
                        Write-Host ""

                        do {
                            Write-Host "Your choice [Y/N] (default: Y): " -ForegroundColor Yellow -NoNewline
                            $confirm = Read-Host
                            if ([string]::IsNullOrWhiteSpace($confirm)) { $confirm = "Y" }
                            $confirm = $confirm.ToUpperInvariant()

                            if ($confirm -notin @('Y', 'N')) {
                                Write-Host ""
                                Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                                Write-Host ""
                            }
                        } while ($confirm -notin @('Y', 'N'))

                        if ($confirm -eq "Y") {
                            $modeConfirmed = $true
                        }
                        else {
                            # Loop back to mode selection
                            $modeConfirmed = $false
                            Write-Host ""
                            Write-Host "Returning to mode selection..." -ForegroundColor Cyan
                            Write-Host ""
                        }
                    }
                    else {
                        # No warnings - confirm automatically
                        $modeConfirmed = $true
                    }
                }
            }
        }

        # ALWAYS load config fresh when Mode is provided as parameter (NonInteractive/GUI mode)
        # This fixes issues where stale/empty $config variable from previous runs caused problems
        $configPath = Join-Path $PSScriptRoot "..\Config\Privacy-$Mode.json"
        if (!(Test-Path $configPath)) {
            Write-Log -Level ERROR -Message "Configuration file not found: $configPath" -Module "Privacy"
            return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Config not found" }
        }

        # Force fresh load - don't rely on potentially stale $config variable
        $privacyConfig = Get-Content $configPath -Raw | ConvertFrom-Json
        Write-Log -Level INFO -Message "Privacy config loaded: $configPath" -Module "Privacy"

        # Add Mode to config object
        if ($privacyConfig.PSObject.Properties.Name -contains 'Mode') {
            $privacyConfig.PSObject.Properties.Remove('Mode')
        }
        $privacyConfig | Add-Member -NotePropertyName 'Mode' -NotePropertyValue $Mode -Force
        Write-Log -Level INFO -Message "Privacy mode: $($privacyConfig.Mode)" -Module "Privacy"

        # Use $privacyConfig instead of $config to avoid any scope issues
        $config = $privacyConfig

        # MSRecommended only: Prompt for Cloud Clipboard (AllowCrossDeviceClipboard)
        if ($Mode -eq "MSRecommended") {
            $disableCloudClipboard = $null

            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value if provided
                $configCloudClipboard = Get-NonInteractiveValue -Module "Privacy" -Key "disableCloudClipboard" -Required
                $disableCloudClipboard = if ($configCloudClipboard) { "Y" } else { "N" }
                Write-NonInteractiveDecision -Module "Privacy" -Decision "Cloud Clipboard" -Value $(if ($disableCloudClipboard -eq "Y") { "Disable" } else { "Preserve current policy/state" })
            }
            else {
                # Interactive prompt
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  CLOUD CLIPBOARD SETTING" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Cloud Clipboard syncs your clipboard between devices via Microsoft Cloud." -ForegroundColor Gray
                Write-Host "This can be convenient but sends clipboard data (including passwords)" -ForegroundColor Gray
                Write-Host "through Microsoft servers." -ForegroundColor Gray
                Write-Host ""
                Write-Host "  Y = Disable Cloud Clipboard (recommended for privacy)" -ForegroundColor Green
                Write-Host "  N = Preserve current Cloud Clipboard policy/state (does not enable it)" -ForegroundColor Yellow
                Write-Host ""

                do {
                    Write-Host "Disable Cloud Clipboard? [Y/N] (default: Y): " -ForegroundColor Yellow -NoNewline
                    $disableCloudClipboard = Read-Host
                    if ([string]::IsNullOrWhiteSpace($disableCloudClipboard)) { $disableCloudClipboard = "Y" }
                    $disableCloudClipboard = $disableCloudClipboard.ToUpperInvariant()

                    if ($disableCloudClipboard -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($disableCloudClipboard -notin @('Y', 'N'))
            }

            # Preserve means no mutation. Never weaken an existing stricter
            # policy or turn Cloud Clipboard on as a side effect of hardening.
            if ($disableCloudClipboard -eq "N") {
                Write-Log -Level INFO -Message "User chose to preserve the current Cloud Clipboard policy/state" -Module "Privacy"
                $systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                if ($config.InputAndSync.PSObject.Properties.Name -contains $systemPath) {
                    $config.InputAndSync.$systemPath.PSObject.Properties.Remove('AllowCrossDeviceClipboard')
                }
            }
            else {
                Write-Log -Level INFO -Message "User chose to DISABLE Cloud Clipboard" -Module "Privacy"
            }
        }

        # Tier 1: Policy-based in-box app removal (Microsoft's native
        # RemoveDefaultMicrosoftStorePackages policy). Independent of Mode --
        # asked once regardless of MSRecommended/Strict/Paranoid. Applicability
        # is edition/build gated (Enterprise/Education, Windows 11 24H2/build
        # 26100+); everywhere else the declared targets are NotApplicable and
        # nothing is written. The policy values have exact BAVR, but their later
        # AppX/data-removal effect does not: restoring the policy only re-allows
        # reprovisioning and cannot itself bring an app or its local data back.
        $tier1Selected = $false
        $tier1Definition = Get-PrivacyTier1PolicyDefinition
        if (Test-NonInteractiveMode) {
            $tier1Selected = [bool](Get-NonInteractiveValue -Module "Privacy" -Key "applyStorePackagePolicy" -Required)
            Write-NonInteractiveDecision -Module "Privacy" -Decision "Policy-based in-box app removal (Tier 1)" -Value $(if ($tier1Selected) { "Apply curated default list" } else { "Not applied" })
            if ($tier1Selected) {
                Write-Log -Level WARNING -Message 'Tier 1 is device-wide and can delete local app data; policy state restores exactly, while separate original-user app recovery is best-effort and cannot recover data' -Module 'Privacy'
            }
        }
        else {
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  TIER 1: POLICY-BASED IN-BOX APP REMOVAL" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""

            # The same fail-closed classifier that gates Apply/Verify decides whether
            # the destructive prompt is shown at all: on ineligible systems the
            # declared Tier 1 targets are NotApplicable and nothing can be written,
            # so prompting would only mislead.
            $tier1Applicability = Get-PrivacyApplicability
            $tier1Gate = Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' -Name 'Enabled' -Applicability $tier1Applicability

            if (-not [bool]$tier1Gate.Applicable) {
                Write-Host "Not available on this system (edition: $($tier1Applicability.EditionFamily), build $($tier1Applicability.BuildNumber))." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  $($tier1Gate.Reason)." -ForegroundColor Gray
                Write-Host ""
                Write-Host "Nothing is written; the declared Tier 1 targets are reported as" -ForegroundColor Gray
                Write-Host "Not Applicable. Tier 2 below removes consumer apps on any edition." -ForegroundColor Gray
                Write-Host ""
                Write-Log -Level INFO -Message "Tier 1 prompt skipped - not applicable on this system: $($tier1Gate.Reason)" -Module "Privacy"
            }
            else {
                Write-Host "Windows 11 Enterprise/Education (24H2, build 26100+) can enforce" -ForegroundColor Gray
                Write-Host "Microsoft's native RemoveDefaultMicrosoftStorePackages policy: a" -ForegroundColor Gray
                Write-Host "curated list of in-box apps stays uninstalled at every sign-in." -ForegroundColor Gray
                Write-Host ""
                Write-Host "The policy values are backed up and restored exactly. Their" -ForegroundColor Gray
                Write-Host "downstream removal effect is NOT an exact restore: restoring" -ForegroundColor Gray
                Write-Host "the policy only re-allows reprovisioning; it does not itself" -ForegroundColor Gray
                Write-Host "bring back an app or local data Windows already removed. A sealed" -ForegroundColor Gray
                Write-Host "original-user inventory enables separate best-effort app recovery." -ForegroundColor Gray
                Write-Host ""
                Write-Host "DESTRUCTIVE EFFECT:" -ForegroundColor Red
                Write-Host "  - Applies device-wide to every user." -ForegroundColor Yellow
                Write-Host "  - Windows can delete local app data when these apps are removed." -ForegroundColor Yellow
                Write-Host "  - Exact BAVR restores policy; separate local-first/Store fallback can recover apps, never data." -ForegroundColor Yellow
                Write-Host "Apps selected for removal by the curated policy:" -ForegroundColor White
                foreach ($target in @($tier1Definition.RemovalTargets)) {
                    Write-Host "  - $($target.Description) [$($target.PolicyId)]" -ForegroundColor Gray
                }
                Write-Host ""
                Write-Host "Apply policy-based in-box app removal (curated default list)?" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  [N] NO - Do not apply the removal policy (default)" -ForegroundColor Green
                Write-Host "      - Nothing is written; the declared Tier 1 targets stay NotChecked" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Apply the curated removal policy" -ForegroundColor Cyan
                Write-Host "      - Device-wide for every user; Windows can delete local app data" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $tier1Answer = Read-Host
                    if ([string]::IsNullOrWhiteSpace($tier1Answer)) { $tier1Answer = "N" }
                    $tier1Answer = $tier1Answer.ToUpperInvariant()

                    if ($tier1Answer -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($tier1Answer -notin @('Y', 'N'))
                $tier1Selected = ($tier1Answer -eq 'Y')
                Write-Log -Level INFO -Message "User chose Tier 1 policy-based app removal: $tier1Selected" -Module "Privacy"
            }
        }
        $config | Add-Member -NotePropertyName 'Tier1PolicyRemovalSelected' -NotePropertyValue $tier1Selected -Force

        # Tier 2: Classic per-user AppX removal (all editions). Own always-shown
        # prompt, default No. NEVER an exact restore: only a precise pre-removal
        # action log is sealed; actual restore is the separate, explicitly
        # best-effort Restore-BloatwareApps winget reinstall path.
        $tier2Mode = 'none'
        $weatherWidgetSelected = $false
        $tier2Catalog = Get-PrivacyBloatwareConfig
        if (Test-NonInteractiveMode) {
            $tier2Mode = [string](Get-NonInteractiveValue -Module "Privacy" -Key "removeBloatwareApps" -Required)
            if ($tier2Mode -notin @('none', 'standard')) { $tier2Mode = 'none' }
            $weatherWidgetSelected = [bool](Get-NonInteractiveValue -Module "Privacy" -Key "removeWeatherWidget" -Required)
            if ($weatherWidgetSelected -and $tier2Mode -ne 'standard') {
                throw 'removeWeatherWidget can be true only when Tier 2 bloatware removal is selected'
            }
            Write-NonInteractiveDecision -Module "Privacy" -Decision "Classic bloatware app removal (Tier 2)" -Value $tier2Mode
            Write-NonInteractiveDecision -Module "Privacy" -Decision "Weather/Widgets board removal" -Value $weatherWidgetSelected
            if ($tier2Mode -eq 'standard') {
                Write-Log -Level WARNING -Message 'Tier 2 removes listed apps for the interactive user and can delete local app data; sealed local re-registration/Store fallback cannot recover that data' -Module 'Privacy'
            }
        }
        else {
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  TIER 2: CLASSIC BLOATWARE APP REMOVAL" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Removes a curated list of consumer apps (Copilot, News, Weather," -ForegroundColor Gray
            Write-Host "Xbox extras, Solitaire and similar) for the current user only, on" -ForegroundColor Gray
            Write-Host "ANY Windows 11 edition." -ForegroundColor Gray
            Write-Host ""
            Write-Host "  THIS IS NOT AN EXACT RESTORE." -ForegroundColor Yellow
            Write-Host "  A precise pre-removal app inventory is sealed for the record, but" -ForegroundColor Gray
            Write-Host "  restore is separate: staged package registration first, then winget" -ForegroundColor Gray
            Write-Host "  (Restore-BloatwareApps) -- never automatic, never guaranteed to" -ForegroundColor Gray
            Write-Host "  match the exact prior version or provisioning state." -ForegroundColor Gray
            Write-Host ""
            Write-Host "DESTRUCTIVE EFFECT:" -ForegroundColor Red
            Write-Host "  - Local data belonging to a removed app can be deleted." -ForegroundColor Yellow
            Write-Host "  - Reinstall does not recover app data, licenses, or the exact prior version." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Exact current removal catalog:" -ForegroundColor White
            foreach ($appName in $tier2Catalog.RemoveApps) { Write-Host "  - $appName" -ForegroundColor Gray }
            Write-Host ""
            Write-Host "Remove standard bloatware apps for the current user?" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [N] NO - Keep the listed apps (default)" -ForegroundColor Green
            Write-Host "      - Nothing is removed for the current user" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [Y] YES - Remove the listed apps for the current user" -ForegroundColor Cyan
            Write-Host "      - Local data belonging to a removed app can be deleted" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                $tier2Answer = Read-Host
                if ([string]::IsNullOrWhiteSpace($tier2Answer)) { $tier2Answer = "N" }
                $tier2Answer = $tier2Answer.ToUpperInvariant()

                if ($tier2Answer -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($tier2Answer -notin @('Y', 'N'))
            $tier2Mode = if ($tier2Answer -eq 'Y') { 'standard' } else { 'none' }
            Write-Log -Level INFO -Message "User chose Tier 2 bloatware removal mode: $tier2Mode" -Module "Privacy"

            if ($tier2Mode -eq 'standard') {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  OPTIONAL: WEATHER / WIDGETS BOARD" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Package: Windows Web Experience Pack" -ForegroundColor White
                Write-Host "  $($tier2Catalog.OptionalRemoveApps.WeatherWidget)" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "This package provides the taskbar Weather/Widgets board." -ForegroundColor Gray
                Write-Host "Removing it takes that board away for the current user." -ForegroundColor Gray
                Write-Host ""
                Write-Host "Options:" -ForegroundColor Cyan
                Write-Host "  [N] No  - Keep the Weather/Widgets board" -ForegroundColor Green
                Write-Host "        > Default; a valid choice that does not reduce the" -ForegroundColor Gray
                Write-Host "          verification result" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] Yes - Remove it along with the other Tier 2 apps" -ForegroundColor Yellow
                Write-Host "        > The taskbar board disappears for this user" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Also remove the Weather/Widgets board? [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $weatherWidgetAnswer = Read-Host
                    if ([string]::IsNullOrWhiteSpace($weatherWidgetAnswer)) { $weatherWidgetAnswer = 'N' }
                    $weatherWidgetAnswer = $weatherWidgetAnswer.ToUpperInvariant()
                    if ($weatherWidgetAnswer -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($weatherWidgetAnswer -notin @('Y', 'N'))
                $weatherWidgetSelected = ($weatherWidgetAnswer -eq 'Y')
                Write-Host ""
                Write-Log -Level INFO -Message "User chose Weather/Widgets board removal: $weatherWidgetSelected" -Module 'Privacy'
            }
        }
        $config | Add-Member -NotePropertyName 'Tier2BloatwareRemovalSelected' -NotePropertyValue ($tier2Mode -eq 'standard') -Force
        $config | Add-Member -NotePropertyName 'WeatherWidgetRemovalSelected' -NotePropertyValue $weatherWidgetSelected -Force

        if ($DryRun) {
            $runtimePlan = Get-PrivacyRuntimeTargetPlan -Config $config
            Write-Log -Level INFO -Message "DRY RUN MODE - previewed $($runtimePlan.ApplicableChecks) applicable checks; $($runtimePlan.NotCheckedChecks) not checked; $($runtimePlan.NotApplicableChecks) not applicable; no changes made" -Module "Privacy"
            return [PSCustomObject]@{
                Success = $true
                Status = 'DryRun'
                Mode = $Mode
                VerificationPassed = $null
                DeclaredChecks = [int]$runtimePlan.DeclaredChecks
                Previewed = [int]$runtimePlan.ApplicableChecks
                NotChecked = [int]$runtimePlan.NotCheckedChecks
                NotApplicable = [int]$runtimePlan.NotApplicableChecks
                ChangesMade = 0
            }
        }

        # PHASE 1: Initialize Session-based backup
        Write-Host "`n[1/4] BACKUP - Initializing Session-based backup..." -ForegroundColor Cyan
        $moduleBackupPath = $null
        $privacyBloatwareActionLog = $null
        try {
            if (-not (Initialize-BackupSystem)) {
                throw "Backup system initialization returned failure"
            }
            $moduleBackupPath = Start-ModuleBackup -ModuleName "Privacy"
            if (-not $moduleBackupPath) {
                throw "Privacy module backup folder was not created"
            }
            Write-Log -Level INFO -Message "Session backup initialized: $moduleBackupPath" -Module "Privacy"
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to initialize backup system: $_" -Module "Privacy"
            if ([string]$global:CurrentModule -eq 'Privacy') {
                $null = Save-IncompleteModuleBackup -ModuleName 'Privacy' -Confirm:$false
            }
            return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Backup initialization failed: $($_.Exception.Message)" }
        }

        # Create backup using Backup-PrivacySettings (uses Register-Backup internally)
        if ($moduleBackupPath) {
            Write-Host "Creating comprehensive backup..." -ForegroundColor Cyan
            $backupResult = Backup-PrivacySettings -Config $config
            if (-not $backupResult -or -not $backupResult.Success) {
                throw 'Privacy backup failed; Apply is blocked'
            }

            # Seal only the exact set of artifacts that was registered for this
            # module. Semantic item counts are not sufficient for BAVR integrity.
            $registeredArtifacts = @($global:BackupIndex | Where-Object { $_.Module -eq 'Privacy' })
            $null = Assert-PrivacyPrestate -SnapshotPath $backupResult.SnapshotPath -Artifacts $registeredArtifacts
            $backupCompleted = Complete-ModuleBackup -ItemsBackedUp $registeredArtifacts.Count -Status "Success"
            if (-not $backupCompleted) {
                throw 'Privacy backup manifest completion failed; Apply is blocked'
            }

            Write-Log -Level INFO -Message "Backup completed: $($registeredArtifacts.Count) validated artifacts" -Module "Privacy"
            $null = Assert-PrivacyPrestate `
                -SnapshotPath $backupResult.SnapshotPath `
                -Artifacts $registeredArtifacts `
                -WindowsSearchPreflightAlreadyProven
            $privacySnapshot = Get-Content -LiteralPath $backupResult.SnapshotPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $privacyBloatwareActionLog = if ($backupResult.BloatwareActionLogPath) {
                Get-Content -LiteralPath $backupResult.BloatwareActionLogPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
            } else { $null }
        }

        # PHASE 2: APPLY
        Write-Host "`n[2/4] APPLY - Applying privacy settings..." -ForegroundColor Cyan

        # Apply the exact plan sealed with the prestate. Configuration files are
        # not re-read here, so backup and mutation cannot silently diverge.
        $results = @()
        $registryWrites = Set-PrivacyRegistryTargets -Snapshot $privacySnapshot
        $results += ($registryWrites -eq [int]$privacySnapshot.TargetCount)

        # Services (Strict/Paranoid only)
        $sealedServices = @($privacySnapshot.ApplicableServiceNames | ForEach-Object {
                [PSCustomObject]@{ Name = [string]$_ }
            })
        if ($sealedServices.Count -gt 0) {
            $results += Disable-TelemetryServices -Services $sealedServices
        }

        # Tasks (Paranoid only)
        $sealedTasks = @($privacySnapshot.ApplicableScheduledTaskPaths | ForEach-Object { [string]$_ })
        if ($sealedTasks.Count -gt 0) {
            $results += Disable-TelemetryTasks -Tasks $sealedTasks
        }

        # Tier 2 classic bloatware removal (all editions, best-effort, NOT an
        # exact restore). Its per-app outcome is reported separately in the
        # module result and is never folded into the BAVR Verified/Failed totals.
        $bloatwareActionResult = $null
        if ([bool]($config.PSObject.Properties['Tier2BloatwareRemovalSelected'] -and $config.Tier2BloatwareRemovalSelected)) {
            Write-Host "Removing Tier 2 bloatware apps for the current user (best-effort, NOT an exact restore)..." -ForegroundColor Cyan
            if (-not $privacyBloatwareActionLog) { throw 'Tier 2 was selected but no sealed action inventory is available for Apply' }
            # The informed consent for this destructive step already happened:
            # the module's own explicit prompt (interactive, default No, exact
            # catalog shown) or the explicit removeBloatwareApps config opt-in
            # (noninteractive). PowerShell's native High-impact confirmation
            # must not fire here - it inverts the default to Yes, and the GUI
            # host runs in a hidden console where the prompt cannot be answered
            # and would stall the apply run.
            $bloatwareActionResult = Remove-BloatwareApps -ActionLog $privacyBloatwareActionLog -Confirm:$false
            $results += [bool]$bloatwareActionResult.Success
        }

        $applyPassed = (@($results).Count -gt 0 -and @($results | Where-Object { $_ -ne $true }).Count -eq 0)
        if (-not $applyPassed) {
            Write-Log -Level ERROR -Message "One or more Privacy apply operations failed" -Module "Privacy"
        }

        # PHASE 3: VERIFY
        Write-Host "`n[3/4] VERIFY - Checking applied settings..." -ForegroundColor Cyan
        $verifyResult = Test-PrivacyCompliance -Config $config -Snapshot $privacySnapshot -BloatwareActionResult $bloatwareActionResult

        $verificationPassed = $false
        if ($verifyResult -is [PSCustomObject]) {
            # Show result
            $pct = $verifyResult.Percentage
            if ($verifyResult.Failed -eq 0 -and $verifyResult.Passed -eq $verifyResult.TotalChecks) {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($pct%)" -ForegroundColor Green
                Write-Log -Level SUCCESS -Message "Verification: $pct% applicable compliance ($($verifyResult.Passed)/$($verifyResult.TotalChecks)); $($verifyResult.NotApplicable) not applicable" -Module "Privacy"
            }
            else {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($pct%)" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "Verification: $pct% compliance - some policies may be overridden by Group Policy" -Module "Privacy"
            }
            if ($verifyResult.Failed -gt 0) {
                Write-Log -Level ERROR -Message "$($verifyResult.Failed) Privacy setting(s) failed verification" -Module "Privacy"
            }
            $verificationPassed = ($verifyResult.DeclaredChecks -gt 0 -and
                $verifyResult.Failed -eq 0 -and
                ($verifyResult.Passed + $verifyResult.NotChecked + $verifyResult.NotApplicable) -eq $verifyResult.DeclaredChecks)
        }
        elseif ($verifyResult) {
            Write-Log -Level SUCCESS -Message "Verification passed" -Module "Privacy"
            $verificationPassed = $true
        }
        else {
            Write-Log -Level ERROR -Message "Verification produced no result" -Module "Privacy"
        }

        # PHASE 4: COMPLETE
        Write-Host "`n[4/4] COMPLETE - Privacy hardening finished!" -ForegroundColor Green
        if ($moduleBackupPath) {
            Write-Host "`nBackup location: $moduleBackupPath" -ForegroundColor Gray
            Write-Host "This backup is part of your NoID Privacy session folder under Backups\Session_<ID>\Privacy\" -ForegroundColor Gray
        }
        Write-Host ""

        $moduleSuccess = ($applyPassed -and $verificationPassed)
        if ($moduleSuccess) {
            Write-Log -Level SUCCESS -Message "Privacy hardening completed successfully in $Mode mode" -Module "Privacy"
        }
        else {
            Write-Log -Level ERROR -Message "Privacy hardening did not meet Apply/Verify completion criteria in $Mode mode" -Module "Privacy"
        }

        # GUI parsing marker for the active applicable registry/service/task set.
        $settingsCount = if ($verifyResult -and $verifyResult.DeclaredChecks) { $verifyResult.DeclaredChecks } else { 0 }
        $verifiedCount = if ($verifyResult) { [int]$verifyResult.Passed } else { 0 }
        $notApplicableCount = if ($verifyResult) { [int]$verifyResult.NotApplicable } else { 0 }
        $notCheckedCount = if ($verifyResult) { [int]$verifyResult.NotChecked } else { 0 }
        Write-Log -Level $(if ($moduleSuccess) { 'SUCCESS' } else { 'ERROR' }) -Message "Privacy declared scope: $verifiedCount verified, $notCheckedCount not checked, $notApplicableCount not applicable, $settingsCount total" -Module "Privacy"

        # Return result object for consistency with other modules. BloatwareActions
        # is outside the exact-BAVR check count, but an explicitly selected removal
        # failure still fails the module's Apply result.
        return [PSCustomObject]@{
            Success            = $moduleSuccess
            Mode               = $Mode
            DisableCloudClipboard = ($disableCloudClipboard -eq 'Y')
            Tier1PolicyRemovalSelected = [bool]$tier1Selected
            # Read back the value that was actually sealed into $config (line 440)
            # and therefore drove the backup and the removal, so the returned
            # decision cannot drift from the applied one. The previous
            # `[bool]$tier2Selected` named a variable that is never assigned in this
            # file - it is a different function's local in Backup-PrivacySettings -
            # and StrictMode does not reach into a module scope, so a destructive
            # Tier 2 removal of up to 27 AppX packages was recorded as "not
            # selected" in the durable intent state the verifier later reconciles.
            Tier2BloatwareRemovalSelected = [bool]$config.Tier2BloatwareRemovalSelected
            WeatherWidgetRemovalSelected = [bool]$weatherWidgetSelected
            VerificationPassed = $verificationPassed
            DeclaredChecks     = $settingsCount
            Verified           = $verifiedCount
            Failed             = $(if ($verifyResult) { [int]$verifyResult.Failed } else { $settingsCount })
            NotChecked         = $notCheckedCount
            NotApplicable      = $notApplicableCount
            BloatwareActions   = $bloatwareActionResult
        }

    }
    catch {
        Write-Log -Level ERROR -Message "Privacy hardening failed: $_" -Module "Privacy"
        if (-not $DryRun -and [string]$global:CurrentModule -eq 'Privacy') {
            try {
                if (-not (Save-IncompleteModuleBackup -ModuleName 'Privacy' -Confirm:$false)) {
                    Write-Log -Level ERROR -Message 'Failed to retain/classify the incomplete Privacy backup' -Module 'Privacy'
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Incomplete Privacy backup retention failed: $($_.Exception.Message)" -Module 'Privacy'
            }
        }
        return [PSCustomObject]@{
            Success            = $false
            Mode               = $Mode
            BackupPath         = $null
            VerificationPassed = $false
            Error              = $_.Exception.Message
        }
    }
}
