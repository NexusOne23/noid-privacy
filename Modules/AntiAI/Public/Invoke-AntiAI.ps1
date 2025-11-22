#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Disables all Windows 11 AI features using official Microsoft policies.

.DESCRIPTION
    Maximum AI deactivation module - Disables 8+ Windows 11 AI features:
    
    DEACTIVATED AI FEATURES:
    1. Generative AI Master Switch - Blocks ALL apps from using on-device AI models
    2. Windows Recall - Screenshots everything (EXTREME privacy risk!) - Component removed
    3. Windows Copilot - System AI assistant (chat, proactive suggestions)
    4. Click to Do - Screenshot AI analysis with action suggestions
    5. Paint Cocreator - Cloud-based text-to-image generation
    6. Paint Generative Fill - AI-powered image editing
    7. Paint Image Creator - DALL-E art generator
    8. Notepad AI - Write, Summarize, Rewrite features (GPT)
    9. Settings Agent - AI-powered Settings search
    
    AUTOMATICALLY BLOCKED (by Master Switch):
    - Photos Generative Erase / Background effects
    - Clipchamp Auto Compose
    - Snipping Tool AI-OCR / Quick Redact
    - All future generative AI apps
    
    RECALL ENTERPRISE PROTECTION (Maximum Compliance):
    - App Deny List: Browser, Terminal, Password managers, RDP never captured
    - URI Deny List: Banking, Email, Login pages never captured
    - Storage Duration: Maximum 30 days retention
    - Storage Space: Maximum 10 GB allocated
    
    Uses only official Microsoft policies (WindowsAI CSP, AppPrivacy, Paint, Notepad).
    No registry hacks, 100% MS Best Practice compliant.
    
    WARNING: Recall component removal requires reboot!

.PARAMETER SkipBackup
    Skip backup creation (NOT RECOMMENDED - use only for testing)

.PARAMETER DryRun
    Preview actions without applying changes

.EXAMPLE
    Invoke-AntiAI
    Disables all AI features with automatic backup.

.EXAMPLE
    Invoke-AntiAI -DryRun
    Preview actions without applying changes.

.NOTES
    Author: NoID Privacy Pro
    Version: 2.1.0
    Requires: Windows 11 24H2 or later, Administrator privileges
    Impact: All AI features completely disabled, reboot required
#>
function Invoke-AntiAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup
    )
    
    $startTime = Get-Date
    
    Write-Host "" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  ANTI-AI MODULE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Disables 8+ Windows 11 AI features:" -ForegroundColor White
    Write-Host "  - Generative AI Master Switch (blocks ALL AI models)" -ForegroundColor Gray
    Write-Host "  - Windows Recall (screenshot capture)" -ForegroundColor Gray
    Write-Host "  - Windows Copilot (AI assistant)" -ForegroundColor Gray
    Write-Host "  - Click to Do, Paint AI, Notepad AI" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Uses 24 official Microsoft policies (22 official + 2 community-verified)" -ForegroundColor Gray
    Write-Host "REBOOT REQUIRED for Recall component removal" -ForegroundColor Yellow
    Write-Host ""
    
    if ($DryRun) {
        Write-Host "[DRY RUN MODE - Preview only, no changes]" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Initialize result tracking (PSCustomObject for Framework compatibility)
    $result = [PSCustomObject]@{
        Success            = $false
        TotalFeatures      = 9  # Master Switch, Recall, Copilot, ClickToDo, Paint(3x), Notepad, SettingsAgent
        Applied            = 0
        Failed             = 0
        Warnings           = @()
        Errors             = @()
        RequiresReboot     = $false
        VerificationPassed = $null
        StartTime          = $startTime
        EndTime            = $null
        Duration           = $null
    }
    
    # BAVR Pattern: Backup, Apply (9 features), Verify, Complete
    # No step counting during apply - clean sequential output
    
    try {
        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!
        
        # Initialize Session-based backup system
        $moduleBackupPath = $null
        $backupCount = 0
        
        # PHASE 1: BACKUP
        Write-Host "[1/4] BACKUP - Creating restore point..." -ForegroundColor Cyan
        
        if (-not $SkipBackup -and -not $DryRun) {
            try {
                Initialize-BackupSystem
                $moduleBackupPath = Start-ModuleBackup -ModuleName "AntiAI"
                Write-Host "  Backup initialized: $moduleBackupPath" -ForegroundColor Green
                Write-Host ""
            }
            catch {
                Write-Host "  WARNING: Backup failed - continuing without backup (RISKY!)" -ForegroundColor Yellow
                Write-Host ""
                $result.Warnings += "Backup initialization failed: $_"
            }
        }
        else {
            if ($DryRun) {
                Write-Host "  Skipped (DryRun mode)" -ForegroundColor Gray
            }
            else {
                Write-Host "  Skipped (SkipBackup flag)" -ForegroundColor Yellow
            }
            Write-Host ""
        }
        
        # PHASE 2: APPLY
        Write-Host "[2/4] APPLY - Disabling AI features..." -ForegroundColor Cyan
        Write-Host ""
        
        # Feature 1: Generative AI Master Switch
        if ($moduleBackupPath -and -not $DryRun) {
            $result1 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -BackupName "AppPrivacy_GenerativeAI"
            if ($result1) { $backupCount++ }
            $result2 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" -BackupName "CapabilityAccessManager_SystemAIModels"
            if ($result2) { $backupCount++ }
        }
        
        Write-Host "  Generative AI Master Switch..." -ForegroundColor White -NoNewline
        $masterResult = Set-SystemAIModels -DryRun:$DryRun
        if ($masterResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $masterResult.Errors
        }
        
        # Feature 2: Windows Recall (Core + Protection)
        if ($moduleBackupPath -and -not $DryRun) {
            $result1 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -BackupName "WindowsAI_Device"
            if ($result1) { $backupCount++ }
            $result2 = Backup-RegistryKey -KeyPath "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -BackupName "WindowsAI_User"
            if ($result2) { $backupCount++ }
        }
        
        Write-Host "  Windows Recall (component removal)..." -ForegroundColor White -NoNewline
        $recallResult = Disable-Recall -DryRun:$DryRun
        if ($recallResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
            $result.RequiresReboot = $true
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $recallResult.Errors
        }
        
        Write-Host "  Recall Enterprise Protection..." -ForegroundColor White -NoNewline
        $protectionResult = Set-RecallProtection -DryRun:$DryRun
        if ($protectionResult.Success) {
            Write-Host " OK" -ForegroundColor Green
        }
        else {
            Write-Host " WARNING" -ForegroundColor Yellow
            $result.Warnings += "Recall protection incomplete but core disable succeeded"
        }
        
        # Feature 3: Windows Copilot
        if ($moduleBackupPath -and -not $DryRun) {
            # Backup BEFORE applying changes
            $result1 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -BackupName "WindowsCopilot_Device"
            if ($result1) { $backupCount++ }
            $result2 = Backup-RegistryKey -KeyPath "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -BackupName "WindowsCopilot_User"
            if ($result2) { $backupCount++ }
            $result3 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -BackupName "Explorer_Copilot"
            if ($result3) { $backupCount++ }
            $result4 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -BackupName "Explorer_Advanced_Device"
            if ($result4) { $backupCount++ }
            $result5 = Backup-RegistryKey -KeyPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -BackupName "Explorer_Advanced_User"
            if ($result5) { $backupCount++ }
            $result6 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Windows.Copilot.CopilotManager" -BackupName "Copilot_ActivationType"
            if ($result6) { $backupCount++ }
            
            # CRITICAL: Create JSON backup for Explorer Advanced HKLM (Protected Key)
            # .reg import often fails for this key due to permissions/ownership
            try {
                $expPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                if (Test-Path $expPath) {
                    $expVal = Get-ItemProperty -Path $expPath -Name "ShowCopilotButton" -ErrorAction SilentlyContinue
                    if ($expVal) {
                        $expData = @{ "ShowCopilotButton" = $expVal.ShowCopilotButton }
                        $expJson = $expData | ConvertTo-Json
                        $jsonBackup = Register-Backup -Type "AntiAI" -Data $expJson -Name "Explorer_Advanced_Device_JSON"
                        if ($jsonBackup) { $backupCount++ }
                    }
                }
            } catch { 
                Write-Host "  WARNING: Failed to create JSON backup for Explorer Advanced: $_" -ForegroundColor Yellow 
            }
        }
        
        Write-Host "  Windows Copilot..." -ForegroundColor White -NoNewline
        $copilotResult = Disable-Copilot -DryRun:$DryRun
        if ($copilotResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $copilotResult.Errors
        }
        
        # Feature 4: Click to Do
        if ($moduleBackupPath -and -not $DryRun) {
            # Backup BEFORE applying changes (WindowsAI already backed up in Feature 2)
            # No additional backup needed - uses same path as Recall
        }
        
        Write-Host "  Click to Do..." -ForegroundColor White -NoNewline
        $clickResult = Disable-ClickToDo -DryRun:$DryRun
        if ($clickResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $clickResult.Errors
        }
        
        # Feature 5-7: Paint AI (3 features)
        if ($moduleBackupPath -and -not $DryRun) {
            # Backup BEFORE applying changes
            $result1 = Backup-RegistryKey -KeyPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint" -BackupName "Paint_Policies"
            if ($result1) { $backupCount++ }
        }
        
        Write-Host "  Paint AI (Cocreator, Fill, Creator)..." -ForegroundColor White -NoNewline
        $paintResult = Disable-PaintAI -DryRun:$DryRun
        if ($paintResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied += 3
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed += 3
            $result.Errors += $paintResult.Errors
        }
        
        # Feature 8: Notepad AI
        if ($moduleBackupPath -and -not $DryRun) {
            # Backup BEFORE applying changes
            $result1 = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\WindowsNotepad" -BackupName "Notepad_Policies"
            if ($result1) { $backupCount++ }
        }
        
        Write-Host "  Notepad AI..." -ForegroundColor White -NoNewline
        $notepadResult = Disable-NotepadAI -DryRun:$DryRun
        if ($notepadResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $notepadResult.Errors
        }
        
        # Feature 9: Settings Agent
        if ($moduleBackupPath -and -not $DryRun) {
            # Backup BEFORE applying changes (WindowsAI already backed up in Feature 2)
            # No additional backup needed - uses same path as Recall
        }
        
        Write-Host "  Settings Agent..." -ForegroundColor White -NoNewline
        $settingsResult = Disable-SettingsAgent -DryRun:$DryRun
        if ($settingsResult.Success) {
            Write-Host " OK" -ForegroundColor Green
            $result.Applied++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $result.Failed++
            $result.Errors += $settingsResult.Errors
        }
        
        Write-Host ""
        
        # Register backup in session manifest
        if ($moduleBackupPath) {
            Complete-ModuleBackup -ItemsBackedUp $backupCount -Status "Success"
        }
        
        # PHASE 3: VERIFY
        Write-Host "[3/4] VERIFY - Checking compliance..." -ForegroundColor Cyan
        
        if (-not $DryRun -and $result.Failed -eq 0) {
            try {
                $complianceResult = Test-AntiAICompliance
                
                if ($complianceResult.OverallStatus -eq "PASS") {
                    Write-Host "  All $($complianceResult.TotalChecks) compliance checks passed" -ForegroundColor Green
                    $result.VerificationPassed = $true
                }
                else {
                    Write-Host "  WARNING: $($complianceResult.FailedChecks)/$($complianceResult.TotalChecks) checks failed" -ForegroundColor Yellow
                    $result.VerificationPassed = $false
                    $result.Warnings += "Some compliance checks failed - policies may not be fully effective"
                }
            }
            catch {
                Write-Host "  WARNING: Verification failed - $($_.Exception.Message)" -ForegroundColor Yellow
                $result.Warnings += "Compliance verification skipped due to error"
                $result.VerificationPassed = $null
            }
        }
        else {
            if ($DryRun) {
                Write-Host "  Skipped (DryRun mode)" -ForegroundColor Gray
            }
            else {
                Write-Host "  Skipped (errors occurred)" -ForegroundColor Yellow
            }
            $result.VerificationPassed = $null
        }
        Write-Host ""
        
        # Calculate final status
        $result.Success = ($result.Failed -eq 0)
        $result.EndTime = Get-Date
        $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds
        
        # PHASE 4: COMPLETE
        Write-Host "[4/4] COMPLETE - AI hardening finished!" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "Status:        " -NoNewline
        if ($result.Success) {
            Write-Host "SUCCESS - All AI features disabled!" -ForegroundColor Green
        }
        else {
            Write-Host "COMPLETED WITH ERRORS" -ForegroundColor Yellow
        }
        
        Write-Host "Features:      $($result.Applied)/$($result.TotalFeatures) disabled" -ForegroundColor $(if ($result.Failed -eq 0) { 'Green' } else { 'Yellow' })
        Write-Host "Errors:        $($result.Failed)" -ForegroundColor $(if ($result.Failed -eq 0) { 'Green' } else { 'Red' })
        Write-Host "Warnings:      $($result.Warnings.Count)" -ForegroundColor $(if ($result.Warnings.Count -eq 0) { 'Green' } else { 'Yellow' })
        
        if ($null -ne $result.VerificationPassed) {
            Write-Host "Verification:  " -NoNewline
            if ($result.VerificationPassed) {
                Write-Host "PASSED - All policies verified" -ForegroundColor Green
            }
            else {
                Write-Host "FAILED - Some policies not verified" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Duration:      $([math]::Round($result.Duration, 2)) seconds" -ForegroundColor Cyan
        
        if ($moduleBackupPath) {
            Write-Host "Backup:        $moduleBackupPath" -ForegroundColor Cyan
            Write-Host "Items Backed:  $backupCount registry keys" -ForegroundColor Cyan
        }
        elseif (-not $SkipBackup -and -not $DryRun) {
            Write-Host "Backup:        FAILED" -ForegroundColor Red
        }
        else {
            Write-Host "Backup:        SKIPPED" -ForegroundColor Yellow
        }
        
        if ($result.RequiresReboot) {
            Write-Host "`nREBOOT REQUIRED:  " -NoNewline -ForegroundColor Red
            Write-Host "Recall component removal needs system restart!" -ForegroundColor Yellow
        }
        
        if ($result.Errors.Count -gt 0) {
            Write-Host ""
            Write-Host "Errors:" -ForegroundColor Red
            foreach ($err in $result.Errors) {
                Write-Host "  - $err" -ForegroundColor Red
            }
        }
        
        Write-Host ""
        
        # Return result object as PSCustomObject (Framework expects this type)
        return [PSCustomObject]$result
    }
    catch {
        $result.Success = $false
        $result.Errors += "Critical error: $($_.Exception.Message)"
        Write-Error "AntiAI module failed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }
}
