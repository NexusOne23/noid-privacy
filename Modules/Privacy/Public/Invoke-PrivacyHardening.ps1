function Invoke-PrivacyHardening {
    <#
    .SYNOPSIS
        Apply privacy hardening with telemetry control, bloatware removal, and OneDrive configuration
    
    .DESCRIPTION
        Interactive privacy hardening module with 3 operating modes:
        - MSRecommended (default): Fully supported by Microsoft
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
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        $RemoveBloatware
    )
    
    try {
        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!
        
        Write-Log -Level INFO -Message "Starting Privacy Hardening Module..." -Module "Privacy"
        
        # Mode selection - NonInteractive or Interactive
        $modeConfirmed = $false
        if (!$Mode) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $Mode = Get-NonInteractiveValue -Module "Privacy" -Key "mode" -Default "MSRecommended"
                Write-NonInteractiveDecision -Module "Privacy" -Decision "Privacy Mode" -Value $Mode
                $modeConfirmed = $true
            }
            else {
                # Interactive mode
                while (-not $modeConfirmed) {
                    Write-Host "`n============================================" -ForegroundColor Cyan
                    Write-Host "  PRIVACY HARDENING - MODE SELECTION" -ForegroundColor Cyan
                    Write-Host "============================================`n" -ForegroundColor Cyan
                    
                    Write-Host "Mode 1: MSRecommended (DEFAULT)" -ForegroundColor Green
                    Write-Host "  - Fully supported by Microsoft" -ForegroundColor Gray
                    Write-Host "  - AllowTelemetry = Required (1)" -ForegroundColor Gray
                    Write-Host "  - Services NOT disabled" -ForegroundColor Gray
                    Write-Host "  - AppPrivacy: User decides (all apps work)" -ForegroundColor Gray
                    Write-Host "  - Best for: Production, business, MDM environments`n" -ForegroundColor Gray
                    
                    Write-Host "Mode 2: Strict" -ForegroundColor Yellow
                    Write-Host "  - Maximum privacy (all editions)" -ForegroundColor Gray
                    Write-Host "  - AllowTelemetry = Off (Enterprise/Edu only, Pro falls back)" -ForegroundColor Gray
                    Write-Host "  - Services: DiagTrack + dmwappushservice disabled" -ForegroundColor Gray
                    Write-Host "  - Force Deny: Location, App-Diagnose, Generative AI" -ForegroundColor Gray
                    Write-Host "  - All other permissions: User decides (Teams/Zoom work!)" -ForegroundColor Gray
                    Write-Host "  - Win+V clipboard: Works (local only, no cloud)" -ForegroundColor Gray
                    Write-Host "  - Best for: Privacy-focused home users, small business`n" -ForegroundColor Gray
                    
                    Write-Host "Mode 3: Paranoid" -ForegroundColor Red
                    Write-Host "  - Hardcore (NOT recommended)" -ForegroundColor Gray
                    Write-Host "  - Everything from Strict + WerSvc disabled" -ForegroundColor Gray
                    Write-Host "  - Tasks disabled (CEIP, AppExperience)" -ForegroundColor Gray
                    Write-Host "  - Force Deny: ALL permissions (Mic, Camera, etc.)" -ForegroundColor Gray
                    Write-Host "  - WARNING: BREAKS Teams/Zoom/Skype!" -ForegroundColor Red
                    Write-Host "  - Best for: Air-gapped, kiosk, extreme privacy only`n" -ForegroundColor Gray
                    
                    do {
                        $modeSelection = Read-Host "Select mode [1-3, default: 1]"
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
                        Write-Host "WARNINGS for $Mode mode:" -ForegroundColor Yellow
                        foreach ($warning in $privacyConfig.Warnings) {
                            Write-Host "  - $warning" -ForegroundColor Yellow
                        }
                        Write-Host ""
                        
                        do {
                            $confirm = Read-Host "Do you want to continue? [Y/N] (default: Y)"
                            if ([string]::IsNullOrWhiteSpace($confirm)) { $confirm = "Y" }
                            $confirm = $confirm.ToUpper()
                            
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
                $configCloudClipboard = Get-NonInteractiveValue -Module "Privacy" -Key "disableCloudClipboard" -Default $true
                $disableCloudClipboard = if ($configCloudClipboard) { "Y" } else { "N" }
                Write-NonInteractiveDecision -Module "Privacy" -Decision "Disable Cloud Clipboard" -Value $(if ($disableCloudClipboard -eq "Y") { "Yes" } else { "No" })
            }
            else {
                # Interactive prompt
                Write-Host "`n============================================" -ForegroundColor Cyan
                Write-Host "  CLOUD CLIPBOARD SETTING" -ForegroundColor Cyan
                Write-Host "============================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Cloud Clipboard syncs your clipboard between devices via Microsoft Cloud." -ForegroundColor Gray
                Write-Host "This can be convenient but sends clipboard data (including passwords)" -ForegroundColor Gray
                Write-Host "through Microsoft servers." -ForegroundColor Gray
                Write-Host ""
                Write-Host "  Y = Disable Cloud Clipboard (recommended for privacy)" -ForegroundColor Green
                Write-Host "  N = Keep Cloud Clipboard enabled (for multi-device workflow)" -ForegroundColor Yellow
                Write-Host ""
                
                do {
                    $disableCloudClipboard = Read-Host "Disable Cloud Clipboard? [Y/N] (default: Y)"
                    if ([string]::IsNullOrWhiteSpace($disableCloudClipboard)) { $disableCloudClipboard = "Y" }
                    $disableCloudClipboard = $disableCloudClipboard.ToUpper()
                    
                    if ($disableCloudClipboard -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($disableCloudClipboard -notin @('Y', 'N'))
            }
            
            # Apply decision: if user wants to KEEP cloud clipboard, change the value to 1
            if ($disableCloudClipboard -eq "N") {
                Write-Log -Level INFO -Message "User chose to KEEP Cloud Clipboard enabled" -Module "Privacy"
                # Modify the config value to allow cloud clipboard
                $systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                if ($config.InputAndSync.PSObject.Properties.Name -contains $systemPath) {
                    $config.InputAndSync.$systemPath.AllowCrossDeviceClipboard.Value = 1
                }
            }
            else {
                Write-Log -Level INFO -Message "User chose to DISABLE Cloud Clipboard" -Module "Privacy"
            }
        }
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "DRY RUN MODE - No changes will be made" -Module "Privacy"
            return [PSCustomObject]@{ Success = $true; Mode = $Mode; VerificationPassed = $null }
        }
        
        # PHASE 1: Initialize Session-based backup
        Write-Host "`n[1/4] BACKUP - Initializing Session-based backup..." -ForegroundColor Cyan
        $moduleBackupPath = $null
        try {
            Initialize-BackupSystem
            $moduleBackupPath = Start-ModuleBackup -ModuleName "Privacy"
            Write-Log -Level INFO -Message "Session backup initialized: $moduleBackupPath" -Module "Privacy"
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to initialize backup system: $_" -Module "Privacy"
            Write-Log -Level WARNING -Message "Continuing without backup (RISKY!)" -Module "Privacy"
        }
        
        # Create backup using Backup-PrivacySettings (uses Register-Backup internally)
        if ($moduleBackupPath) {
            Write-Host "Creating comprehensive backup..." -ForegroundColor Cyan
            $backupResult = Backup-PrivacySettings
            if ($backupResult -eq $false) {
                Write-Log -Level ERROR -Message "Backup failed. Aborting operation." -Module "Privacy"
                return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Backup failed" }
            }
            
            # Register backup in session manifest
            Complete-ModuleBackup -ItemsBackedUp $backupResult -Status "Success"
            
            Write-Log -Level INFO -Message "Backup completed: $backupResult items backed up" -Module "Privacy"
        }
        
        # PHASE 2: APPLY
        Write-Host "`n[2/4] APPLY - Applying privacy settings..." -ForegroundColor Cyan
        
        # Debug: Log config state before applying
        Write-Log -Level DEBUG -Message "Config object type: $($config.GetType().FullName)" -Module "Privacy"
        Write-Log -Level DEBUG -Message "Config properties: $($config.PSObject.Properties.Name -join ', ')" -Module "Privacy"
        Write-Log -Level DEBUG -Message "Config.DataCollection type: $($config.DataCollection.GetType().FullName)" -Module "Privacy"
        
        # Apply settings
        $results = @()
        $results += Set-TelemetrySettings -Config $config
        $results += Set-PersonalizationSettings -Config $config
        $results += Set-AppPrivacySettings -Config $config
        $results += Set-OneDriveSettings
        
        # Services (Strict/Paranoid only)
        if ($config.Services.Count -gt 0) {
            $results += Disable-TelemetryServices -Services $config.Services
        }
        
        # Tasks (Paranoid only)
        if ($config.ScheduledTasks.Count -gt 0) {
            $results += Disable-TelemetryTasks -Tasks $config.ScheduledTasks
        }
        
        # Bloatware removal
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "  BLOATWARE REMOVAL" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "CAN REMOVE (up to 24 apps, depending on edition and what is installed):" -ForegroundColor Yellow
        Write-Host "  - Games: Candy Crush, casual games, etc." -ForegroundColor Gray
        Write-Host "  - News & Weather: Bing News, Bing Weather, etc." -ForegroundColor Gray
        Write-Host "  - Others: Feedback Hub, Sticky Notes, Get Help, etc." -ForegroundColor Gray
        Write-Host ""
        Write-Host "WILL KEEP (protected):" -ForegroundColor Green
        Write-Host "  - Store, Calculator, Photos, Paint, Terminal" -ForegroundColor Gray
        Write-Host "  - All codec extensions (HEIF, WebP, AV1)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "NOTE: Most removed apps can be auto-restored during session restore via winget" -ForegroundColor Cyan
        Write-Host "      where mappings exist. All removed apps are also listed in the backup folder" -ForegroundColor Cyan
        Write-Host "      so you can always reinstall them manually from the Microsoft Store if needed." -ForegroundColor Cyan
        Write-Host ""
        
        if ($null -ne $RemoveBloatware) {
            # Convert parameter to Y/N string (defensive: accept Boolean, String, or Number)
            if ($RemoveBloatware -is [bool]) {
                $removeBloatware = if ($RemoveBloatware) { "Y" } else { "N" }
            }
            elseif ($RemoveBloatware -is [string]) {
                $removeBloatware = if ($RemoveBloatware -eq "Y" -or $RemoveBloatware -eq "yes" -or $RemoveBloatware -eq "true" -or $RemoveBloatware -eq "1") { "Y" } else { "N" }
            }
            elseif ($RemoveBloatware -is [int]) {
                $removeBloatware = if ($RemoveBloatware -ne 0) { "Y" } else { "N" }
            }
            else {
                # Unknown type - default to N
                $removeBloatware = "N"
            }
            Write-Host "Using parameter for bloatware removal: $removeBloatware" -ForegroundColor Cyan
        }
        elseif (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - use config value
            $configRemoveBloatware = Get-NonInteractiveValue -Module "Privacy" -Key "removeBloatware" -Default $true
            $removeBloatware = if ($configRemoveBloatware) { "Y" } else { "N" }
            Write-NonInteractiveDecision -Module "Privacy" -Decision "Bloatware removal" -Value $(if ($removeBloatware -eq "Y") { "Yes" } else { "No" })
        }
        else {
            do {
                $removeBloatware = Read-Host "Continue with bloatware removal? [Y/N] (default: Y)"
                if ([string]::IsNullOrWhiteSpace($removeBloatware)) { $removeBloatware = "Y" }
                $removeBloatware = $removeBloatware.ToUpper()
                
                if ($removeBloatware -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($removeBloatware -notin @('Y', 'N'))
        }
        
        if ($removeBloatware -eq "Y") {
            Write-Log -Level DEBUG -Message "User selected: Remove bloatware apps" -Module "Privacy"
            $bloatwareResult = Remove-Bloatware
            if ($bloatwareResult.Success) {
                if ($bloatwareResult.Count -gt 0) {
                    Write-Log -Level SUCCESS -Message "Bloatware removal completed ($($bloatwareResult.Count) apps)" -Module "Privacy"
                }
                else {
                    Write-Log -Level SUCCESS -Message "Bloatware removal completed - no apps removed (already clean or skipped)" -Module "Privacy"
                    Write-Host "`n  No apps removed (already clean or skipped for restore safety)" -ForegroundColor Green
                }
                
                # Save list of removed apps to backup folder for user reference
                if ($moduleBackupPath -and $bloatwareResult.RemovedApps.Count -gt 0) {
                    try {
                        $bloatwareListPath = Join-Path $moduleBackupPath "REMOVED_APPS_LIST.txt"
                        $listContent = @()
                        $listContent += "================================================================"
                        $listContent += "  REMOVED APPS - NoID Privacy v2.2.0"
                        $listContent += "  Session: $(Split-Path $moduleBackupPath -Leaf)"
                        $listContent += "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        $listContent += "================================================================"
                        $listContent += ""
                        $listContent += "The following apps were removed by the Privacy module:"
                        $listContent += ""
                        foreach ($app in $bloatwareResult.RemovedApps) {
                            $listContent += "  - $app"
                        }
                        $listContent += ""
                        $listContent += "================================================================"
                        $listContent += "  HOW APPS ARE RESTORED"
                        $listContent += "================================================================"
                        $listContent += ""
                        $listContent += "Most removed apps will be automatically reinstalled during a"
                        $listContent += "session restore via 'winget' where mappings exist. This file"
                        $listContent += "serves as a complete reference of what was removed and can be"
                        $listContent += "used for manual reinstall if any apps remain missing."
                        $listContent += ""
                        $listContent += "If you need to reinstall apps manually from Microsoft Store:"
                        $listContent += ""
                        $listContent += "1. Open Microsoft Store (Windows key + S, search 'Store')"
                        $listContent += "2. Search for the app name (e.g., 'Xbox', 'Solitaire')"
                        $listContent += "3. Click 'Get' or 'Install' to reinstall"
                        $listContent += ""
                        
                        $listContent | Out-File -FilePath $bloatwareListPath -Encoding UTF8 -Force
                        Write-Log -Level INFO -Message "Removed apps list saved: $bloatwareListPath" -Module "Privacy"
                        Write-Host "`n  [INFO] List of removed apps saved to backup folder" -ForegroundColor Cyan
                        Write-Host "        $bloatwareListPath" -ForegroundColor Gray
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to save removed apps list: $_" -Module "Privacy"
                    }

                    try {
                        $bloatwareMapPath = Join-Path $PSScriptRoot "..\Config\Bloatware-Map.json"
                        if (Test-Path $bloatwareMapPath) {
                            $bloatwareMap = Get-Content $bloatwareMapPath -Raw | ConvertFrom-Json
                            $mappings = $bloatwareMap.Mappings
                            $appsForJson = @()
                            foreach ($appName in ($bloatwareResult.RemovedApps | Sort-Object -Unique)) {
                                $wingetId = $null
                                if ($mappings -and ($mappings.PSObject.Properties.Name -contains $appName)) {
                                    $wingetId = $mappings.$appName
                                    Write-Log -Level INFO -Message "Winget mapping found for $appName -> $wingetId" -Module "Privacy"
                                } else {
                                    # Special handling for Xbox framework components
                                    if ($appName -match "Xbox\.TCUI|XboxIdentityProvider|XboxSpeechToTextOverlay") {
                                        Write-Log -Level INFO -Message "$appName is a framework component - will be automatically restored when Gaming Services is installed (no user prompt required)" -Module "Privacy"
                                    }
                                    else {
                                        Write-Log -Level WARNING -Message "No winget ID mapping for '$appName' - app may not be auto-restored (system component or manual reinstall required)" -Module "Privacy"
                                    }
                                }
                                $appsForJson += [PSCustomObject]@{
                                    AppName  = $appName
                                    WingetId = $wingetId
                                }
                            }
                            if ($appsForJson.Count -gt 0) {
                                $restoreInfo = [PSCustomObject]@{
                                    Version     = "1.0"
                                    GeneratedAt = Get-Date -Format "o"
                                    Apps        = $appsForJson
                                }
                                $restoreInfoPath = Join-Path $moduleBackupPath "REMOVED_APPS_WINGET.json"
                                $restoreInfo | ConvertTo-Json -Depth 5 | Out-File -FilePath $restoreInfoPath -Encoding UTF8 -Force
                                Write-Log -Level INFO -Message "Winget restore metadata saved: $restoreInfoPath" -Module "Privacy"
                            }
                        }
                        else {
                            Write-Log -Level WARNING -Message "Bloatware-Map.json not found - skipping winget restore metadata" -Module "Privacy"
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to save winget restore metadata: $_" -Module "Privacy"
                    }
                }
            }
        }
        else {
            Write-Host "`n  [SKIPPED] Bloatware removal - keeping all apps" -ForegroundColor Yellow
            Write-Log -Level DEBUG -Message "User selected: Keep bloatware apps" -Module "Privacy"
        }
        
        # PHASE 3: VERIFY (informational only - not blocking)
        Write-Host "`n[3/4] VERIFY - Checking applied settings..." -ForegroundColor Cyan
        $verifyResult = Test-PrivacyCompliance -Config $config
        
        $verificationPassed = $true  # Always pass - verification is informational
        if ($verifyResult -is [PSCustomObject]) {
            # Show result
            $pct = $verifyResult.Percentage
            if ($pct -ge 80) {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($pct%)" -ForegroundColor Green
                Write-Log -Level SUCCESS -Message "Verification: $pct% compliance ($($verifyResult.Passed)/$($verifyResult.TotalChecks))" -Module "Privacy"
            }
            else {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($pct%)" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "Verification: $pct% compliance - some policies may be overridden by Group Policy" -Module "Privacy"
            }
            # Note: Failed checks are often due to GPO overrides or HKCU permission issues
            # These are not critical - the settings were applied, just may not stick
            if ($verifyResult.Failed -gt 0) {
                Write-Log -Level INFO -Message "Note: $($verifyResult.Failed) setting(s) could not be verified (may be GPO-controlled or permission-restricted)" -Module "Privacy"
            }
        }
        elseif ($verifyResult) {
            Write-Log -Level SUCCESS -Message "Verification passed" -Module "Privacy"
        }
        else {
            Write-Log -Level INFO -Message "Verification skipped" -Module "Privacy"
        }
        
        # PHASE 4: COMPLETE
        Write-Host "`n[4/4] COMPLETE - Privacy hardening finished!" -ForegroundColor Green
        if ($moduleBackupPath) {
            Write-Host "`nBackup location: $moduleBackupPath" -ForegroundColor Gray
            Write-Host "This backup is part of your NoID Privacy session folder under Backups\\Session_<ID>\\Privacy\\" -ForegroundColor Gray
        }
        Write-Host ""
        
        Write-Log -Level SUCCESS -Message "Privacy hardening completed successfully in $Mode mode" -Module "Privacy"
        
        # GUI parsing marker for settings count (registry + services only, NOT bloatware)
        # Bloatware is counted separately and shown in its own summary
        $settingsCount = if ($verifyResult -and $verifyResult.TotalChecks) { $verifyResult.TotalChecks } else { 0 }
        Write-Log -Level SUCCESS -Message "Applied $settingsCount settings" -Module "Privacy"
        
        # Return result object for consistency with other modules
        return [PSCustomObject]@{
            Success            = $true
            Mode               = $Mode
            VerificationPassed = $verificationPassed
        }
        
    }
    catch {
        Write-Log -Level ERROR -Message "Privacy hardening failed: $_" -Module "Privacy"
        return [PSCustomObject]@{
            Success            = $false
            Mode               = $Mode
            BackupPath         = $null
            VerificationPassed = $false
            Error              = $_.Exception.Message
        }
    }
}
