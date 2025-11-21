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
        
        # Interactive mode selection if not specified
        $modeConfirmed = $false
        if (!$Mode) {
            while (-not $modeConfirmed) {
                Write-Host "`n============================================" -ForegroundColor Cyan
                Write-Host "  PRIVACY HARDENING - MODE SELECTION" -ForegroundColor Cyan
                Write-Host "============================================`n" -ForegroundColor Cyan
                
                Write-Host "Mode 1: MSRecommended (DEFAULT)" -ForegroundColor Green
                Write-Host "  - Fully supported by Microsoft" -ForegroundColor Gray
                Write-Host "  - AllowTelemetry = Required (1)" -ForegroundColor Gray
                Write-Host "  - Services NOT disabled" -ForegroundColor Gray
                Write-Host "  - AppPrivacy: Selective (Mic/Camera user decides)" -ForegroundColor Gray
                Write-Host "  - Best for: Production, business environments`n" -ForegroundColor Gray
                
                Write-Host "Mode 2: Strict" -ForegroundColor Yellow
                Write-Host "  - Maximum privacy (Enterprise/Edu)" -ForegroundColor Gray
                Write-Host "  - AllowTelemetry = Off (0)" -ForegroundColor Gray
                Write-Host "  - Services: DiagTrack + dmwappushservice disabled" -ForegroundColor Gray
                Write-Host "  - AppPrivacy: Force Deny Mic/Camera (BREAKS Teams/Zoom!)" -ForegroundColor Gray
                Write-Host "  - Best for: High-security, standalone systems`n" -ForegroundColor Gray
                
                Write-Host "Mode 3: Paranoid" -ForegroundColor Red
                Write-Host "  - Hardcore (NOT recommended)" -ForegroundColor Gray
                Write-Host "  - Everything from Strict + WerSvc disabled" -ForegroundColor Gray
                Write-Host "  - Tasks disabled (CEIP, AppExperience)" -ForegroundColor Gray
                Write-Host "  - WARNING: Breaks error analysis, support limited" -ForegroundColor Gray
                Write-Host "  - Best for: Air-gapped, extreme privacy only`n" -ForegroundColor Gray
                
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
                Write-Log -Level INFO -Message "User selected privacy mode: $Mode" -Module "Privacy"
                
                # Load configuration for warnings
                $configPath = Join-Path $PSScriptRoot "..\Config\Privacy-$Mode.json"
                if (!(Test-Path $configPath)) {
                    Write-Log -Level ERROR -Message "Configuration file not found: $configPath" -Module "Privacy"
                    return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Config not found" }
                }
                
                $config = Get-Content $configPath -Raw | ConvertFrom-Json
                
                # Display warnings and confirm
                if ($config.Warnings.Count -gt 0) {
                    Write-Host "WARNINGS for $Mode mode:" -ForegroundColor Yellow
                    foreach ($warning in $config.Warnings) {
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
        else {
            # Mode provided as parameter - load config directly
            $configPath = Join-Path $PSScriptRoot "..\Config\Privacy-$Mode.json"
            if (!(Test-Path $configPath)) {
                Write-Log -Level ERROR -Message "Configuration file not found: $configPath" -Module "Privacy"
                return [PSCustomObject]@{ Success = $false; Mode = $Mode; Error = "Config not found" }
            }
            
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            Write-Log -Level INFO -Message "Privacy mode parameter specified: $Mode" -Module "Privacy"
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
        Write-Host "  - Games & Xbox: Solitaire, Xbox apps, Candy Crush, etc." -ForegroundColor Gray
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
            Write-Log -Level INFO -Message "User selected: Remove bloatware apps" -Module "Privacy"
            $bloatwareResult = Remove-Bloatware
            if ($bloatwareResult.Success) {
                if ($bloatwareResult.Count -gt 0) {
                    Write-Log -Level SUCCESS -Message "Bloatware removal completed ($($bloatwareResult.Count) apps)" -Module "Privacy"
                }
                else {
                    Write-Log -Level SUCCESS -Message "Bloatware removal completed - no matching apps found (system already clean)" -Module "Privacy"
                    Write-Host "`n  System already clean - no matching bloatware apps found" -ForegroundColor Green
                }
                
                # Save list of removed apps to backup folder for user reference
                if ($moduleBackupPath -and $bloatwareResult.RemovedApps.Count -gt 0) {
                    try {
                        $bloatwareListPath = Join-Path $moduleBackupPath "REMOVED_APPS_LIST.txt"
                        $listContent = @()
                        $listContent += "================================================================"
                        $listContent += "  REMOVED APPS - NoID Privacy Pro v2.1.0"
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
            Write-Log -Level INFO -Message "User selected: Keep bloatware apps" -Module "Privacy"
        }
        
        # PHASE 3: VERIFY
        Write-Host "`n[3/4] VERIFY - Checking applied settings..." -ForegroundColor Cyan
        $verifyResult = Test-PrivacyCompliance -Config $config
        
        $verificationPassed = $false
        if ($verifyResult -is [PSCustomObject]) {
            # New detailed result format
            if ($verifyResult.Compliant) {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($($verifyResult.Percentage)%)" -ForegroundColor Green
                Write-Log -Level SUCCESS -Message "Verification passed - all settings applied correctly" -Module "Privacy"
                $verificationPassed = $true
            }
            else {
                Write-Host "  Compliance: $($verifyResult.Passed)/$($verifyResult.TotalChecks) checks passed ($($verifyResult.Percentage)%)" -ForegroundColor Yellow
                Write-Host "  WARNING: $($verifyResult.Failed) check(s) failed:`n" -ForegroundColor Yellow
                foreach ($failedCheck in $verifyResult.FailedChecks) {
                    Write-Host "    - $failedCheck" -ForegroundColor Red
                }
                Write-Host ""
                Write-Log -Level WARNING -Message "Verification detected $($verifyResult.Failed) issue(s). Check warnings in log." -Module "Privacy"
            }
        }
        elseif ($verifyResult) {
            # Legacy boolean result
            Write-Log -Level SUCCESS -Message "Verification passed - all settings applied correctly" -Module "Privacy"
            $verificationPassed = $true
        }
        else {
            Write-Log -Level WARNING -Message "Verification detected issues. Check logs for details." -Module "Privacy"
        }
        
        # PHASE 4: COMPLETE
        Write-Host "`n[4/4] COMPLETE - Privacy hardening finished!" -ForegroundColor Green
        if ($moduleBackupPath) {
            Write-Host "`nBackup location: $moduleBackupPath" -ForegroundColor Gray
            Write-Host "This backup is part of your NoID Privacy Pro session folder under Backups\\Session_<ID>\\Privacy\\" -ForegroundColor Gray
        }
        Write-Host ""
        
        Write-Log -Level SUCCESS -Message "Privacy hardening completed successfully in $Mode mode" -Module "Privacy"
        
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
