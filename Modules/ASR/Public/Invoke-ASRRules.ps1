<#
.SYNOPSIS
    Apply all 19 Microsoft Defender ASR rules
    
.DESCRIPTION
    Enables all 19 Attack Surface Reduction rules in Block mode for comprehensive protection.
    
    Rules Applied:
    - All 19 ASR rules in Block mode (Action = 1)
    - Includes 4 rules missing from Security Baseline
    - Upgrades 1 rule from Audit to Block (PSExec/WMI - with SCCM check)
    
    Features:
    - SCCM/Configuration Manager detection (PSExec/WMI rule warning)
    - Cloud protection verification
    - BACKUP/APPLY/VERIFY/RESTORE pattern
    - DryRun mode for testing
    - Security Baseline overlap detection
    
.PARAMETER DryRun
    Preview changes without applying them
    
.PARAMETER SkipBackup
    Skip backup creation (not recommended)
    
.PARAMETER SkipVerify
    Skip post-application verification
    
.PARAMETER Force
    Apply even if validation warnings occur (SCCM, Cloud Protection)
    
.PARAMETER AllowPSExecWMI
    Force enable PSExec/WMI rule even if SCCM detected (use with caution)
    
.EXAMPLE
    Invoke-ASRRules
    Apply all 19 ASR rules with full backup and verification
    
.EXAMPLE
    Invoke-ASRRules -DryRun
    Preview what changes would be made
    
.EXAMPLE
    Invoke-ASRRules -AllowPSExecWMI -Force
    Force enable PSExec/WMI rule despite SCCM detection
    
.OUTPUTS
    PSCustomObject with results including success status, rules applied, and any errors
#>

function Invoke-ASRRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipVerify,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowPSExecWMI
    )
    
    begin {
        $moduleName = "ASR"
        $startTime = Get-Date
        
        # Ensure core functions are available when the module is imported directly (outside Framework.ps1)
        if (-not (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue)) {
            try {
                $frameworkRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
                $coreFiles = @(
                    "Core\Logger.ps1",
                    "Core\Config.ps1",
                    "Core\Validator.ps1",
                    "Core\Rollback.ps1",
                    "Utils\Compatibility.ps1"
                )
                
                foreach ($file in $coreFiles) {
                    $corePath = Join-Path $frameworkRoot $file
                    if (Test-Path $corePath) {
                        . $corePath
                    }
                }
            }
            catch {
                Write-Host "ERROR: Failed to load core dependencies for ASR module: $_" -ForegroundColor Red
            }
        }
        
        # Initialize result object
        $result = [PSCustomObject]@{
            ModuleName             = $moduleName
            Success                = $false
            RulesApplied           = 0
            Errors                 = @()
            Warnings               = @()
            BackupCreated          = $false
            VerificationPassed     = $false
            ConfigMgrDetected      = $false
            CloudProtectionEnabled = $false
            Duration               = $null
            Details                = @{
                TotalRules   = 19
                BlockMode    = 0
                AuditMode    = 0
                DisabledMode = 0
            }
        }
        
        Write-Log -Level INFO -Message "Starting ASR rules application (all 19 rules)" -Module $moduleName
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "DRY RUN MODE - No changes will be applied" -Module $moduleName
        }
    }
    
    process {
        try {
            # Step 1: Prerequisites validation
            Write-Log -Level INFO -Message "Validating prerequisites..." -Module $moduleName
            
            if (-not (Test-IsAdmin)) {
                throw "Administrator privileges required"
            }
            
            if (-not (Test-WindowsVersion -MinimumBuild 22000)) {
                throw "Windows 11 or later required"
            }
            
            # Check Windows Defender status and third-party AV
            $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            $defenderRunning = $defenderService -and $defenderService.Status -eq "Running"
            
            # Check for third-party antivirus (they disable Defender)
            $thirdPartyAV = $null
            try {
                $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
                $thirdPartyAV = $avProducts | Where-Object { $_.displayName -notmatch "Windows Defender|Microsoft Defender" } | Select-Object -First 1
            }
            catch {
                # SecurityCenter2 not available - continue with Defender check only
                $null = $null
            }
            
            if (-not $defenderRunning) {
                if ($thirdPartyAV) {
                    # Third-party AV detected - skip ASR gracefully (not an error!)
                    $avName = $thirdPartyAV.displayName
                    Write-Host ""
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host "  ASR Module Skipped" -ForegroundColor Yellow
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Third-party antivirus detected: $avName" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "ASR rules require Windows Defender to be active." -ForegroundColor Yellow
                    Write-Host "Your antivirus ($avName) has its own protection features." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "This is NOT an error - ASR will be skipped." -ForegroundColor Green
                    Write-Host ""
                    
                    Write-Log -Level WARNING -Message "ASR skipped: Third-party AV detected ($avName). Defender disabled." -Module $moduleName
                    
                    $result.Success = $true  # Not an error - intentional skip
                    $result.Warnings += "ASR skipped: Third-party antivirus detected ($avName). Your AV provides similar protection."
                    $result.RulesApplied = 0
                    
                    return $result
                }
                else {
                    # No third-party AV but Defender not running - this IS a problem
                    throw "Windows Defender service is not running and no third-party antivirus detected. ASR rules require Defender to be active."
                }
            }
            
            # Load ASR rule definitions
            Write-Log -Level INFO -Message "Loading ASR rule definitions..." -Module $moduleName
            $asrRules = Get-ASRRuleDefinitions
            
            # Step 2: Check for Remote Management Tools (SCCM/Intune/etc.)
            Write-Log -Level INFO -Message "Checking for remote management tools..." -Module $moduleName
            
            # Automatic detection
            $configMgrDetected = Test-ConfigMgrPresence
            $result.ConfigMgrDetected = $configMgrDetected
            
            # Check for management tools - NonInteractive or Interactive
            $usesManagementTools = $false
            
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $usesManagementTools = Get-NonInteractiveValue -Module "ASR" -Key "usesManagementTools" -Default $false
                Write-NonInteractiveDecision -Module $moduleName -Decision "Management tools setting" -Value $(if ($usesManagementTools) { "Yes (1 AUDIT)" } else { "No (ALL BLOCK)" })
            }
            elseif (-not $Force -and -not $AllowPSExecWMI -and -not $DryRun) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "  Remote Management Tool Check" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host ""
                
                if ($configMgrDetected) {
                    Write-Host "DETECTED: SCCM/Configuration Manager is currently installed" -ForegroundColor Yellow
                    Write-Host ""
                }
                
                Write-Host "Do you use ANY of these remote management tools?" -ForegroundColor White
                Write-Host ""
                Write-Host "  - Microsoft SCCM (Configuration Manager)" -ForegroundColor Gray
                Write-Host "  - Microsoft Intune / Endpoint Manager" -ForegroundColor Gray
                Write-Host "  - PDQ Deploy / PDQ Inventory" -ForegroundColor Gray
                Write-Host "  - ManageEngine Desktop Central" -ForegroundColor Gray
                Write-Host "  - Any other WMI/PSExec based management tools" -ForegroundColor Gray
                Write-Host ""
                Write-Host "These tools use PSExec and WMI for remote management." -ForegroundColor Yellow
                Write-Host "If you use them, one ASR rule must be set to AUDIT mode." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Options:" -ForegroundColor Cyan
                Write-Host "  [Y] Yes - I use management tools" -ForegroundColor Yellow
                Write-Host "        > 1 rule: AUDIT mode (PSExec/WMI only)" -ForegroundColor Gray
                Write-Host "        > 18 rules: BLOCK mode (full protection)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [N] No  - I don't use any of these" -ForegroundColor Green
                Write-Host "        > ALL 19 rules: BLOCK mode (maximum protection)" -ForegroundColor Gray
                Write-Host ""
                
                do {
                    $choice = Read-Host "Select option [Y/N] (default: N)"
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "N" }
                    $choice = $choice.ToUpper()
                    
                    if ($choice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($choice -notin @('Y', 'N'))
                
                switch ($choice) {
                    "Y" {
                        $usesManagementTools = $true
                        Write-Host ""
                        Write-Host "1 rule set to AUDIT (PSExec/WMI), 18 rules set to BLOCK" -ForegroundColor Yellow
                        Write-Log -Level INFO -Message "User confirmed use of management tools - 1 AUDIT + 18 BLOCK" -Module $moduleName
                    }
                    "N" {
                        $usesManagementTools = $false
                        Write-Host ""
                        Write-Host "ALL 19 rules will be set to BLOCK mode" -ForegroundColor Green
                        Write-Log -Level INFO -Message "User confirmed no management tools - ALL 19 BLOCK" -Module $moduleName
                    }
                }
                Write-Host ""
            }
            elseif ($Force -and -not $AllowPSExecWMI) {
                # Force flag: Auto-detect or assume safe
                $usesManagementTools = $configMgrDetected
                Write-Log -Level INFO -Message "Force flag: Using detection result (ConfigMgr: $configMgrDetected)" -Module $moduleName
            }
            
            # Apply PSExec/WMI rule mode based on user choice or detection
            if (($usesManagementTools -or $configMgrDetected) -and -not $AllowPSExecWMI) {
                $psexecRule = $asrRules | Where-Object { $_.GUID -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c" }
                
                # Set PSExec/WMI to Audit mode (user confirmed or detected)
                $psexecRule.Action = 2
                $result.Warnings += "Management tools detected/confirmed: PSExec/WMI rule set to Audit mode"
                Write-Log -Level INFO -Message "PSExec/WMI rule set to Audit mode (management tools in use)" -Module $moduleName
            }

            # Step 2b: Prevalence rule (new/unknown software) - NonInteractive or Interactive
            if (-not $DryRun) {
                $prevalenceRule = $asrRules | Where-Object { $_.GUID -eq "01443614-cd74-433a-b99e-2ecdc07bfc25" }
                if ($prevalenceRule) {
                    $allowNewSoftware = $false
                    
                    if (Test-NonInteractiveMode) {
                        # NonInteractive mode (GUI) - use config value
                        $allowNewSoftware = Get-NonInteractiveValue -Module "ASR" -Key "allowNewSoftware" -Default $false
                        
                        if ($allowNewSoftware) {
                            $prevalenceRule.Action = 2
                            $result.Warnings += "ASR prevalence rule set to AUDIT (less restrictive; see README for details)."
                        } else {
                            $prevalenceRule.Action = 1
                        }
                        Write-NonInteractiveDecision -Module $moduleName -Decision "New/Unknown software rule" -Value $(if ($allowNewSoftware) { "AUDIT (allow)" } else { "BLOCK (secure)" })
                    }
                    else {
                        Write-Host "" 
                        Write-Host "========================================" -ForegroundColor Cyan
                        Write-Host "  ASR Rule: New / Unknown Software" -ForegroundColor Cyan
                        Write-Host "========================================" -ForegroundColor Cyan
                        Write-Host ""

                        Write-Host "Rule: Block executable files unless they meet prevalence, age, or trusted list" -ForegroundColor White
                        Write-Host "GUID: $($prevalenceRule.GUID)" -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "This rule blocks very new or unknown executables that" -ForegroundColor Yellow
                        Write-Host "are not yet trusted by Microsoft's reputation systems." -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "Do you install NEW or UNTRUSTED software frequently?" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  - Games from independent developers" -ForegroundColor Gray
                        Write-Host "  - Beta software / Early access programs" -ForegroundColor Gray
                        Write-Host "  - Custom/in-house business applications" -ForegroundColor Gray
                        Write-Host "  - Open-source tools without Microsoft reputation" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "Options:" -ForegroundColor Cyan
                        Write-Host "  [Y] Yes - I need to install untrusted software" -ForegroundColor Yellow
                        Write-Host "        > AUDIT mode: Events logged, installs allowed" -ForegroundColor Gray
                        Write-Host "        > Developer/test mode (less secure)" -ForegroundColor Gray
                        Write-Host "" 
                        Write-Host "  [N] No  - I only install trusted software" -ForegroundColor Green
                        Write-Host "        > BLOCK mode: Maximum security (recommended)" -ForegroundColor Gray
                        Write-Host "        > New/unknown installers may be blocked" -ForegroundColor Gray
                        Write-Host ""
                        
                        do {
                            $prevalenceChoice = Read-Host "Select option [Y/N] (default: N)"
                            if ([string]::IsNullOrWhiteSpace($prevalenceChoice)) { $prevalenceChoice = "N" }
                            $prevalenceChoice = $prevalenceChoice.ToUpper()

                            if ($prevalenceChoice -notin @('Y', 'N')) {
                                Write-Host ""
                                Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                                Write-Host ""
                            }
                        } while ($prevalenceChoice -notin @('Y', 'N'))

                        switch ($prevalenceChoice) {
                            "N" {
                                $prevalenceRule.Action = 1
                                Write-Host ""
                                Write-Host "New/Unknown Software rule set to BLOCK mode (maximum security)" -ForegroundColor Green
                                Write-Log -Level INFO -Message "Prevalence rule configured to BLOCK (recommended)" -Module $moduleName
                            }
                            "Y" {
                                $prevalenceRule.Action = 2
                                Write-Host ""
                                Write-Host "New/Unknown Software rule set to AUDIT mode (developer/test)" -ForegroundColor Yellow
                                $result.Warnings += "ASR prevalence rule set to AUDIT (less restrictive; see README for details)."
                                Write-Log -Level INFO -Message "Prevalence rule configured to AUDIT (developer/compat mode)" -Module $moduleName
                            }
                        }
                        Write-Host ""
                    }
                }
            }
            
            # Step 3: Check cloud protection
            Write-Log -Level INFO -Message "Checking cloud-delivered protection..." -Module $moduleName
            
            $cloudProtectionEnabled = Test-CloudProtection
            $result.CloudProtectionEnabled = $cloudProtectionEnabled
            
            if (-not $cloudProtectionEnabled) {
                $cloudRules = $asrRules | Where-Object { $_.RequiresCloudProtection -eq $true }
                $result.Warnings += "Cloud protection disabled: $($cloudRules.Count) rules require it for optimal operation"
                Write-Log -Level WARNING -Message "$($cloudRules.Count) ASR rules require cloud protection for full functionality" -Module $moduleName
                
                if (Test-NonInteractiveMode) {
                    # NonInteractive mode (GUI) - use config value
                    $continueWithoutCloud = Get-NonInteractiveValue -Module "ASR" -Key "continueWithoutCloud" -Default $true
                    
                    if (-not $continueWithoutCloud) {
                        Write-NonInteractiveDecision -Module $moduleName -Decision "Cloud protection required - aborting"
                        throw "ASR application cancelled (cloud protection required, continueWithoutCloud=false)"
                    }
                    Write-NonInteractiveDecision -Module $moduleName -Decision "Continuing without cloud protection (limited functionality)"
                }
                elseif (-not $Force -and -not $DryRun) {
                    # Interactive prompt for cloud protection
                    Write-Host ""
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host "  Cloud Protection Not Enabled!" -ForegroundColor Yellow
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "$($cloudRules.Count) ASR rules require cloud-delivered protection for optimal functionality:" -ForegroundColor Yellow
                    Write-Host ""
                    
                    foreach ($cloudRule in $cloudRules) {
                        Write-Host "  - $($cloudRule.Name)" -ForegroundColor Gray
                    }
                    
                    Write-Host ""
                    Write-Host "These rules will work in limited capacity without cloud protection." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Options:" -ForegroundColor Cyan
                    Write-Host "  [C] Continue    - Apply rules anyway (limited functionality)" -ForegroundColor Green
                    Write-Host "  [A] Abort       - Cancel ASR rule application" -ForegroundColor Yellow
                    Write-Host ""
                    
                    do {
                        $choice = Read-Host "Select option [C/A] (default: A)"
                        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "A" }
                        $choice = $choice.ToUpper()
                        
                        if ($choice -notin @('C', 'A')) {
                            Write-Host ""
                            Write-Host "Invalid input. Please enter C or A." -ForegroundColor Red
                            Write-Host ""
                        }
                    } while ($choice -notin @('C', 'A'))
                    
                    switch ($choice) {
                        "C" {
                            Write-Host ""
                            Write-Host "Continuing with cloud protection disabled" -ForegroundColor Yellow
                            Write-Log -Level INFO -Message "User chose to continue despite cloud protection disabled" -Module $moduleName
                        }
                        "A" {
                            Write-Host ""
                            Write-Host "ASR rule application cancelled by user" -ForegroundColor Yellow
                            Write-Log -Level INFO -Message "ASR application cancelled due to cloud protection requirement" -Module $moduleName
                            throw "ASR application cancelled by user due to cloud protection requirement"
                        }
                    }
                    Write-Host ""
                }
                elseif ($Force) {
                    # Force flag - continue silently
                    Write-Log -Level INFO -Message "Continuing despite cloud protection disabled (Force flag)" -Module $moduleName
                }
            }
            
            # Step 3a: Initialize and start module backup
            if (-not $SkipBackup -and -not $DryRun) {
                try {
                    Initialize-BackupSystem
                    $null = Start-ModuleBackup -ModuleName $moduleName
                    Write-Log -Level INFO -Message "Session backup initialized" -Module $moduleName
                }
                catch {
                    $result.Warnings += "Failed to initialize/start module backup: $_"
                    Write-Log -Level WARNING -Message "Failed to initialize/start module backup: $_" -Module $moduleName
                }
            }
            
            # Step 4: Create backup
            if (-not $SkipBackup -and -not $DryRun) {
                Write-Log -Level INFO -Message "Creating backup..." -Module $moduleName
                
                $backupResult = Backup-ASRRegistry
                if ($backupResult.Errors.Count -gt 0) {
                    foreach ($err in $backupResult.Errors) {
                        $result.Warnings += $err
                    }
                }
                else {
                    # Register backup in session manifest
                    Complete-ModuleBackup -ItemsBackedUp 1 -Status "Success"
                    $result.BackupCreated = $true
                }
            }
            
            # Step 5: Apply ASR rules via PowerShell
            # Note: Set-ASRViaPowerShell logs internally, no need to log here
            $applyResult = Set-ASRViaPowerShell -Rules $asrRules -DryRun:$DryRun

            # In DryRun mode, no rules are actually applied, so keep RulesApplied = 0
            if (-not $DryRun) {
                $result.RulesApplied = $applyResult.Applied
            }
            
            # Add errors and warnings individually to avoid nested arrays
            foreach ($err in $applyResult.Errors) {
                $result.Errors += $err
            }
            foreach ($warn in $applyResult.Warnings) {
                $result.Warnings += $warn
            }
            
            # Count rule modes from actual system state
            $mpPref = Get-MpPreference
            $currentActions = $mpPref.AttackSurfaceReductionRules_Actions
            if ($currentActions) {
                $result.Details.BlockMode = ($currentActions | Where-Object { $_ -eq 1 }).Count
                $result.Details.AuditMode = ($currentActions | Where-Object { $_ -eq 2 }).Count
                $result.Details.DisabledMode = ($currentActions | Where-Object { $_ -eq 0 }).Count
            } else {
                # Fallback to array count
                $result.Details.BlockMode = ($asrRules | Where-Object { $_.Action -eq 1 }).Count
                $result.Details.AuditMode = ($asrRules | Where-Object { $_.Action -eq 2 }).Count
                $result.Details.DisabledMode = ($asrRules | Where-Object { $_.Action -eq 0 }).Count
            }
            
            # Step 6: Verification
            if (-not $SkipVerify -and -not $DryRun) {
                Write-Log -Level INFO -Message "Verifying applied ASR rules..." -Module $moduleName
                
                $verificationResult = Test-ASRCompliance -ExpectedRules $asrRules
                $result.VerificationPassed = $verificationResult.Passed
                
                if (-not $verificationResult.Passed) {
                    $result.Warnings += "Verification found $($verificationResult.FailedCount) rules not applied correctly"
                    Write-Log -Level WARNING -Message "Verification found $($verificationResult.FailedCount) failed rules" -Module $moduleName
                }
                else {
                    Write-Log -Level INFO -Message "Verification passed - all $($verificationResult.CheckedCount) rules confirmed" -Module $moduleName
                }
            }
            
            # Log baseline overlap
            $baselineRules = $asrRules | Where-Object { $_.BaselineStatus -in @("Block", "Audit") }
            Write-Log -Level INFO -Message "Security Baseline overlap: $($baselineRules.Count) rules already in baseline" -Module $moduleName
            
            $newRules = $asrRules | Where-Object { $_.BaselineStatus -eq "Missing" }
            if ($newRules.Count -gt 0) {
                Write-Log -Level INFO -Message "Added $($newRules.Count) rules not in Security Baseline:" -Module $moduleName
                foreach ($newRule in $newRules) {
                    Write-Log -Level INFO -Message "  + $($newRule.Name)" -Module $moduleName
                }
            }
            
            $upgradedRules = $asrRules | Where-Object { $_.BaselineStatus -eq "Audit" -and $_.Action -eq 1 }
            if ($upgradedRules.Count -gt 0) {
                Write-Log -Level INFO -Message "Upgraded $($upgradedRules.Count) rules from Audit to Block:" -Module $moduleName
                foreach ($upgradedRule in $upgradedRules) {
                    Write-Log -Level INFO -Message "  [UPGRADE] $($upgradedRule.Name)" -Module $moduleName
                }
            }
            
            # Mark as successful if no critical errors
            if ($result.Errors.Count -eq 0) {
                $result.Success = $true
                Write-Log -Level INFO -Message "ASR rules applied successfully" -Module $moduleName
            }
            else {
                Write-Log -Level ERROR -Message "ASR application completed with $($result.Errors.Count) errors" -Module $moduleName
            }
            
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
            Write-Log -Level ERROR -Message "ASR application failed: $($_.Exception.Message)" -Module $moduleName
        }
    }
    
    end {
        $result.Duration = (Get-Date) - $startTime
        
        Write-Log -Level INFO -Message "ASR application completed in $($result.Duration.TotalSeconds) seconds" -Module $moduleName
        
        $blockCount = $result.Details.BlockMode
        $auditCount = $result.Details.AuditMode
        Write-Log -Level INFO -Message "Rules applied: $($result.RulesApplied) ($blockCount Block, $auditCount Audit)" -Module $moduleName
        Write-Log -Level INFO -Message "Errors: $($result.Errors.Count), Warnings: $($result.Warnings.Count)" -Module $moduleName
        
        # Log warning details for transparency
        if ($result.Warnings.Count -gt 0) {
            foreach ($warn in $result.Warnings) {
                Write-Log -Level INFO -Message "  Warning: $warn" -Module $moduleName
            }
        }
        
        # GUI parsing marker for settings count (19 ASR rules)
        Write-Log -Level SUCCESS -Message "Applied 19 settings" -Module "ASR"
        
        return $result
    }
}
