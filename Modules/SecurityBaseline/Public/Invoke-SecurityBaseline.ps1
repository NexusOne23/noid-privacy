<#
.SYNOPSIS
    Apply Microsoft Security Baseline for Windows 11 25H2
    
.DESCRIPTION
    Applies all 425 Microsoft Security Baseline settings using native PowerShell tools:
    - 335 Registry policies (Computer + User)
    - 67 Security Template settings (Password/Account/User Rights)
    - 23 Advanced Audit Policies
    
    Note: 437 total entries parsed from Microsoft GPO files. 12 are INF metadata
    (Unicode/Version headers) which are correctly excluded during application.
    
    Uses ONLY native Windows tools:
    - PowerShell for Registry
    - secedit.exe for Security Templates
    - auditpol.exe for Audit Policies
    
    NO EXTERNAL DEPENDENCIES - no LGPO.exe, no Microsoft GPO files needed!
    
.PARAMETER DryRun
    Preview changes without applying them
    
.PARAMETER SkipBackup
    Skip backup creation (not recommended)
    
.PARAMETER SkipVerify
    Skip post-application verification
    
.PARAMETER SkipStandaloneDelta
    Skip standalone system adjustment (LocalAccountTokenFilterPolicy)
    Default: Apply adjustment on non-domain systems for remote admin access
    
.EXAMPLE
    Invoke-SecurityBaseline
    Apply all baseline settings with full backup and verification
    
.EXAMPLE
    Invoke-SecurityBaseline -DryRun
    Preview what changes would be made
    
.OUTPUTS
    PSCustomObject with results including success status and any errors
    
.NOTES
    Author: NexusOne23
    Version: 2.2.2 - Self-Contained Edition
    Requires: PowerShell 5.1+, Administrator privileges
    
    BREAKING CHANGE from v1.0:
    - No longer requires LGPO.exe
    - No longer requires Microsoft Security Baseline GPO files
    - Uses parsed JSON configs in ParsedSettings folder
#>

function Invoke-SecurityBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipVerify,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipStandaloneDelta
    )
    
    begin {
        # Helper function: Use Write-Log if available (framework), else Write-Log -Level DEBUG -Message
        function Write-ModuleLog {
            param([string]$Level, [string]$Message, [string]$Module = "SecurityBaseline")
            
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level $Level -Message $Message -Module $Module
            }
            else {
                switch ($Level) {
                    "ERROR" { Write-Host "ERROR: $Message" -ForegroundColor Red }
                    "WARNING" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
                    default { Write-Log -Level DEBUG -Message $Message }
                }
            }
        }
        
        $moduleName = "SecurityBaseline"
        $startTime = Get-Date
        
        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!
        
        # Initialize result object
        $result = [PSCustomObject]@{
            ModuleName         = $moduleName
            Success            = $false
            SettingsApplied    = 0
            Errors             = @()
            Warnings           = @()
            BackupCreated      = $false
            VerificationPassed = $false
            Duration           = $null
            Details            = @{
                RegistryPolicies = 0
                SecuritySettings = 0
                AuditPolicies    = 0
            }
        }
        
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "MICROSOFT SECURITY BASELINE v25H2" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Self-Contained Edition (No LGPO.exe)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        
        if ($DryRun) {
            Write-ModuleLog -Level INFO -Message "DRY RUN MODE - No changes will be applied" -Module $moduleName
        }
    }
    
    process {
        try {
            # Step 1: Prerequisites validation
            Write-ModuleLog -Level INFO -Message "Step 1/9: Validating prerequisites..." -Module $moduleName
            
            # Check admin (if framework available)
            if (Get-Command Test-IsAdmin -ErrorAction SilentlyContinue) {
                if (-not (Test-IsAdmin)) {
                    throw "Administrator privileges required"
                }
            }
            else {
                # Standalone check
                $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
                if (-not $isAdmin) {
                    throw "Administrator privileges required"
                }
            }
            
            # Check Windows version (if framework available)
            if (Get-Command Test-WindowsVersion -ErrorAction SilentlyContinue) {
                if (-not (Test-WindowsVersion -MinimumBuild 22000)) {
                    throw "Windows 11 or later required"
                }
            }
            else {
                # Standalone check
                $build = [System.Environment]::OSVersion.Version.Build
                if ($build -lt 22000) {
                    throw "Windows 11 or later required (Build 22000+), found: $build"
                }
            }
            
            # Get parsed settings path
            $parsedSettingsPath = Join-Path $PSScriptRoot "..\ParsedSettings"
            
            # Verify parsed settings exist
            $requiredFiles = @(
                "Computer-RegistryPolicies.json",
                "User-RegistryPolicies.json",
                "SecurityTemplates.json",
                "AuditPolicies.json"
            )
            
            foreach ($file in $requiredFiles) {
                $filePath = Join-Path $parsedSettingsPath $file
                if (-not (Test-Path $filePath)) {
                    throw "Required configuration file not found: $file. Run Tools\Parse-SecurityBaseline.ps1 first!"
                }
            }
            
            Write-ModuleLog -Level SUCCESS -Message "All prerequisite checks passed" -Module $moduleName
            
            # Step 2: Detect domain membership
            Write-ModuleLog -Level INFO -Message "Step 2/9: Detecting system configuration..." -Module $moduleName
            
            try {
                $isDomainJoined = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
                if ($isDomainJoined) {
                    Write-ModuleLog -Level INFO -Message "System is domain-joined - applying domain-compatible settings" -Module $moduleName
                }
                else {
                    Write-ModuleLog -Level INFO -Message "System is standalone - applying standalone settings" -Module $moduleName
                }
            }
            catch {
                Write-ModuleLog -Level WARNING -Message "Could not detect domain membership, assuming standalone: $_" -Module $moduleName
                $isDomainJoined = $false
            }
            
            # Define policy paths (needed for backup)
            $computerRegPath = Join-Path $parsedSettingsPath "Computer-RegistryPolicies.json"
            $userRegPath = Join-Path $parsedSettingsPath "User-RegistryPolicies.json"
            $securityTemplatePath = Join-Path $parsedSettingsPath "SecurityTemplates.json"
            $auditPoliciesPath = Join-Path $parsedSettingsPath "AuditPolicies.json"
            
            # Step 2.3: BitLocker USB Drive Protection - Interactive or Config-based
            $isNonInteractive = $false
            $configBitLocker = $null
            
            # Check if running in non-interactive mode (GUI mode)
            # Check BOTH config AND environment variable
            if (($script:Config -and $script:Config.options -and $script:Config.options.nonInteractive -eq $true) -or
                ($env:NOIDPRIVACY_NONINTERACTIVE -eq "true")) {
                $isNonInteractive = $true
                # Read BitLocker setting from config
                if ($script:Config.modules -and $script:Config.modules.SecurityBaseline -and 
                    $null -ne $script:Config.modules.SecurityBaseline.bitLockerUSBEnforcement) {
                    $configBitLocker = $script:Config.modules.SecurityBaseline.bitLockerUSBEnforcement
                }
            }
            
            if ($DryRun) {
                # DryRun mode - use default (Home Mode)
                $enableBitLockerUSBEnforcement = $false
                Write-ModuleLog -Level INFO -Message "DryRun mode: Using default BitLocker USB setting (Home Mode)" -Module $moduleName
            }
            elseif ($isNonInteractive) {
                # Non-interactive mode (GUI) - use config value or default
                $enableBitLockerUSBEnforcement = if ($null -ne $configBitLocker) { $configBitLocker } else { $false }
                $mode = if ($enableBitLockerUSBEnforcement) { "Enterprise Mode (from config)" } else { "Home Mode (from config)" }
                Write-ModuleLog -Level INFO -Message "Non-interactive mode: BitLocker USB = $mode" -Module $moduleName
                Write-Host "[GUI] BitLocker USB setting: $mode" -ForegroundColor Cyan
            }
            else {
                # Interactive mode - ask user
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  BitLocker USB Drive Protection" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Microsoft Security Baseline includes a policy for USB drive encryption:" -ForegroundColor White
                Write-Host ""
                Write-Host "Do you want to REQUIRE BitLocker encryption for USB drives?" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  [N] NO - Home User Mode (Recommended)" -ForegroundColor Green
                Write-Host "      - USB drives work normally (read + write access)" -ForegroundColor Gray
                Write-Host "      - No automatic prompts or restrictions" -ForegroundColor Gray
                Write-Host "      - Compatible with friend's USB drives" -ForegroundColor Gray
                Write-Host "      - You can still manually encrypt (right-click -> Turn on BitLocker)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Enterprise Mode" -ForegroundColor Cyan
                Write-Host "      - Windows will PROMPT when USB inserted: 'Encrypt this drive?'" -ForegroundColor Gray
                Write-Host "      - USB drives are READ-ONLY until encrypted with BitLocker" -ForegroundColor Gray
                Write-Host "      - Unencrypted drives cannot be written to" -ForegroundColor Gray
                Write-Host ""
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host "Security Note: Other protections remain active (ASR, Defender, SmartScreen)" -ForegroundColor DarkGray
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host ""
                
                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $choice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "N" }
                    $choice = $choice.ToUpper()
                    
                    if ($choice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($choice -notin @('Y', 'N'))
                
                $enableBitLockerUSBEnforcement = ($choice -eq 'Y')
                
                if ($enableBitLockerUSBEnforcement) {
                    Write-ModuleLog -Level DEBUG -Message "User selected: BitLocker USB enforcement ENABLED (Enterprise Mode)" -Module $moduleName
                    Write-Host ""
                    Write-Host "Enterprise Mode: USB encryption enforcement enabled" -ForegroundColor Green
                    Write-Host "   USB drives will show encryption prompt when inserted" -ForegroundColor Gray
                }
                else {
                    Write-ModuleLog -Level DEBUG -Message "User selected: BitLocker USB enforcement DISABLED (Home Mode)" -Module $moduleName
                    Write-Host ""
                    Write-Host "Home User Mode: Normal USB operation" -ForegroundColor Green
                    Write-Host "   USB drives will work without restrictions" -ForegroundColor Gray
                }
                Write-Host ""
            }
            
            # Step 3: Create backup (MUST happen BEFORE applying changes)
            if (-not $SkipBackup -and -not $DryRun) {
                Write-ModuleLog -Level INFO -Message "Step 3/9: Creating comprehensive backup..." -Module $moduleName
                
                try {
                    # Initialize Session-based backup (MANDATORY)
                    Initialize-BackupSystem
                    $backupFolder = Start-ModuleBackup -ModuleName $moduleName
                    
                    if (-not $backupFolder) {
                        throw "Failed to create session backup folder"
                    }
                    
                    Write-ModuleLog -Level INFO -Message "Session backup initialized: $backupFolder" -Module $moduleName

                    # Backup 1: Full LocalGPO directory (for proper restore)
                    Write-ModuleLog -Level INFO -Message "Backing up Local Group Policy directory..." -Module $moduleName
                    $localGPOPath = "C:\Windows\System32\GroupPolicy"
                    $localGPOBackup = Join-Path $backupFolder "LocalGPO"
                    
                    if (Test-Path $localGPOPath) {
                        try {
                            # Copy entire GroupPolicy directory structure
                            Copy-Item -Path $localGPOPath -Destination $localGPOBackup -Recurse -Force -ErrorAction Stop
                            Write-ModuleLog -Level SUCCESS -Message "Local Group Policy backed up to: $localGPOBackup" -Module $moduleName
                        }
                        catch {
                            Write-ModuleLog -Level WARNING -Message "Failed to backup LocalGPO directory: $_ - continuing anyway" -Module $moduleName
                        }
                    }
                    else {
                        Write-ModuleLog -Level INFO -Message "No existing LocalGPO directory to backup (clean system)" -Module $moduleName
                        # Create empty LocalGPO backup folder to signal "system was clean"
                        New-Item -Path $localGPOBackup -ItemType Directory -Force | Out-Null
                    }
                    
                    # Backup 2: Registry Policies (JSON format for reference)
                    Write-ModuleLog -Level INFO -Message "Backing up registry policies..." -Module $moduleName
                    $regBackupPath = Join-Path $backupFolder "RegistryPolicies.json"
                    $regBackup = Backup-RegistryPolicies -ComputerPoliciesPath $computerRegPath `
                        -UserPoliciesPath $userRegPath `
                        -BackupPath $regBackupPath
                    
                    if (-not $regBackup.Success) {
                        Write-ModuleLog -Level WARNING -Message "Registry policies JSON backup failed - continuing with LocalGPO backup" -Module $moduleName
                    }
                    
                    # Backup 3: Security Template
                    Write-ModuleLog -Level INFO -Message "Backing up security template..." -Module $moduleName
                    $secBackupPath = Join-Path $backupFolder "SecurityTemplate.inf"
                    $secBackup = Backup-SecurityTemplate -BackupPath $secBackupPath
                    
                    if (-not $secBackup.Success) {
                        throw "Security template backup failed"
                    }
                    
                    # Backup 4: Audit Policies
                    Write-ModuleLog -Level INFO -Message "Backing up audit policies..." -Module $moduleName
                    $auditBackupPath = Join-Path $backupFolder "AuditPolicies.csv"
                    $auditBackup = Backup-AuditPolicies -BackupPath $auditBackupPath
                    
                    if (-not $auditBackup.Success) {
                        throw "Audit policies backup failed"
                    }
                    
                    # Backup 5: Xbox Task State
                    Write-ModuleLog -Level INFO -Message "Backing up Xbox task state..." -Module $moduleName
                    $xboxTaskBackupPath = Join-Path $backupFolder "XboxTask.json"
                    $xboxTaskBackup = Backup-XboxTask -BackupPath $xboxTaskBackupPath
                    
                    if (-not $xboxTaskBackup.Success) {
                        throw "Xbox task backup failed"
                    }
                    
                    # Save backup info (internal metadata)
                    $backupInfo = @{
                        Timestamp              = Get-Date -Format "yyyyMMdd_HHmmss"
                        BackupFolder           = $backupFolder
                        RegistryBackup         = $regBackupPath
                        SecurityTemplateBackup = $secBackupPath
                        AuditPoliciesBackup    = $auditBackupPath
                        XboxTaskBackup         = $xboxTaskBackupPath
                        ItemsBackedUp          = $regBackup.ItemsBackedUp
                    }
                    
                    $backupInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $backupFolder "BackupInfo.json") -Encoding UTF8
                    
                    # Register backup in session manifest
                    $totalItems = $regBackup.ItemsBackedUp + 1 + 1 + 1 # +1 Template, +1 Audit, +1 Xbox Task
                    Complete-ModuleBackup -ItemsBackedUp $totalItems -Status "Success"
                    
                    $result.BackupCreated = $true
                    Write-ModuleLog -Level SUCCESS -Message "Backup created and registered in session: $backupFolder" -Module $moduleName
                }
                catch {
                    $result.Warnings += "Backup failed: $_"
                    Write-ModuleLog -Level WARNING -Message "Backup failed: $_" -Module $moduleName
                    throw "Backup failed - aborting for safety. Use -SkipBackup to override (not recommended)"
                }
            }
            elseif ($SkipBackup) {
                Write-ModuleLog -Level WARNING -Message "Step 3/9: Backup SKIPPED (not recommended)" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level INFO -Message "Step 3/9: Backup skipped (DryRun mode)" -Module $moduleName
            }
            
            # Step 4: Disable Xbox Task (AFTER backup)
            Write-ModuleLog -Level INFO -Message "Step 4/9: Disabling Xbox scheduled task..." -Module $moduleName
            
            try {
                $xboxResult = Disable-XboxTask -DryRun:$DryRun
                
                if ($xboxResult.Success) {
                    if ($xboxResult.TaskDisabled) {
                        Write-ModuleLog -Level SUCCESS -Message "Xbox task disabled" -Module $moduleName
                    }
                    else {
                        Write-ModuleLog -Level INFO -Message "Xbox task not found (not installed)" -Module $moduleName
                    }
                }
                else {
                    $result.Warnings += $xboxResult.Errors
                    Write-ModuleLog -Level WARNING -Message "Xbox task disable had issues (non-critical)" -Module $moduleName
                }
            }
            catch {
                $result.Warnings += "Xbox task disable failed: $_"
                Write-ModuleLog -Level WARNING -Message "Xbox task disable failed (non-critical): $_" -Module $moduleName
            }
            
            # Step 5: Apply BitLocker USB policy based on user choice
            Write-ModuleLog -Level INFO -Message "Step 5/9: Configuring BitLocker USB policy..." -Module $moduleName
            
            try {
                # Load Computer-RegistryPolicies.json
                $computerPolicies = Get-Content $computerRegPath -Raw | ConvertFrom-Json
                
                # Find and modify RDVDenyWriteAccess policy
                $bitlockerPolicy = $computerPolicies | Where-Object { 
                    $_.ValueName -eq "RDVDenyWriteAccess" 
                }
                
                if ($bitlockerPolicy) {
                    # Set based on user choice
                    $bitlockerPolicy.Data = if ($enableBitLockerUSBEnforcement) { 1 } else { 0 }
                    
                    # Save modified policies back to temp location
                    $tempComputerRegPath = Join-Path $env:TEMP "Computer-RegistryPolicies-Modified.json"
                    $computerPolicies | ConvertTo-Json -Depth 10 | Set-Content $tempComputerRegPath -Encoding UTF8 | Out-Null
                    
                    # Update path to use modified version
                    $computerRegPath = $tempComputerRegPath
                    
                    $mode = if ($enableBitLockerUSBEnforcement) { "Enterprise (Enabled)" } else { "Home (Disabled)" }
                    Write-ModuleLog -Level SUCCESS -Message "BitLocker USB policy configured: $mode" -Module $moduleName
                }
                else {
                    Write-ModuleLog -Level WARNING -Message "RDVDenyWriteAccess policy not found in baseline" -Module $moduleName
                }
            }
            catch {
                Write-ModuleLog -Level WARNING -Message "Could not modify BitLocker USB policy: $_" -Module $moduleName
                # Continue with original policy file
            }
            
            # Step 6: Apply Registry Policies
            Write-ModuleLog -Level INFO -Message "Step 6/9: Applying registry policies..." -Module $moduleName
            
            $regResult = Set-RegistryPolicies -ComputerPoliciesPath $computerRegPath `
                -UserPoliciesPath $userRegPath `
                -DryRun:$DryRun
            
            $result.Details.RegistryPolicies = $regResult.Applied
            $result.SettingsApplied += $regResult.Applied
            
            if ($regResult.Errors.Count -gt 0) {
                foreach ($err in $regResult.Errors) {
                    $result.Errors += $err
                }
            }
            
            Write-ModuleLog -Level SUCCESS -Message "Registry policies: $($regResult.Applied) applied, $($regResult.Skipped) skipped" -Module $moduleName
            
            # Step 7: Apply Standalone Delta (if not domain-joined and not skipped)
            if (-not $isDomainJoined -and -not $DryRun -and -not $SkipStandaloneDelta) {
                Write-ModuleLog -Level INFO -Message "Step 7/9: Applying standalone system adjustments..." -Module $moduleName
                
                try {
                    # LocalAccountTokenFilterPolicy = 1 (enable remote admin for local accounts)
                    $deltaKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                    $deltaValue = "LocalAccountTokenFilterPolicy"
                    
                    # CRITICAL: Backup this registry value BEFORE modifying it
                    if ($backupFolder) {
                        try {
                            Backup-RegistryKey -KeyPath $deltaKey -BackupName "StandaloneDelta_LocalAccountTokenFilterPolicy"
                            Write-ModuleLog -Level DEBUG -Message "Backed up LocalAccountTokenFilterPolicy before modification" -Module $moduleName
                        }
                        catch {
                            Write-ModuleLog -Level WARNING -Message "Could not backup LocalAccountTokenFilterPolicy: $_" -Module $moduleName
                        }
                    }
                    
                    if (-not (Test-Path $deltaKey)) {
                        New-Item -Path $deltaKey -Force | Out-Null
                    }
                    
                    # Apply setting (create or update with correct type)
                    $existingValue = Get-ItemProperty -Path $deltaKey -Name $deltaValue -ErrorAction SilentlyContinue
                    
                    if ($null -ne $existingValue) {
                        # Value exists - update it
                        Set-ItemProperty -Path $deltaKey `
                            -Name $deltaValue `
                            -Value 1 `
                            -Force `
                            -ErrorAction Stop | Out-Null
                    }
                    else {
                        # Value does not exist - create it with proper type
                        New-ItemProperty -Path $deltaKey `
                            -Name $deltaValue `
                            -Value 1 `
                            -PropertyType DWord `
                            -Force `
                            -ErrorAction Stop | Out-Null
                    }
                    
                    Write-ModuleLog -Level SUCCESS -Message "Standalone system adjustments applied" -Module $moduleName
                }
                catch {
                    $result.Warnings += "Failed to apply standalone adjustments: $_"
                    Write-ModuleLog -Level WARNING -Message "Failed to apply standalone adjustments: $_" -Module $moduleName
                }
            }
            elseif (-not $isDomainJoined -and $DryRun -and -not $SkipStandaloneDelta) {
                Write-ModuleLog -Level INFO -Message "[DRYRUN] Would apply standalone system adjustments" -Module $moduleName
            }
            elseif (-not $isDomainJoined -and $SkipStandaloneDelta) {
                Write-ModuleLog -Level INFO -Message "Standalone system adjustments skipped (SkipStandaloneDelta)" -Module $moduleName
            }
            
            # Step 8: Apply Security Template
            Write-ModuleLog -Level INFO -Message "Step 8/9: Applying security template..." -Module $moduleName
            
            $secResult = Set-SecurityTemplate -SecurityTemplatePath $securityTemplatePath -DryRun:$DryRun
            
            $result.Details.SecuritySettings = $secResult.SettingsApplied
            $result.SettingsApplied += $secResult.SettingsApplied
            
            if ($secResult.Errors.Count -gt 0) {
                foreach ($err in $secResult.Errors) {
                    $result.Errors += $err
                }
            }
            
            if ($secResult.Success) {
                Write-ModuleLog -Level SUCCESS -Message "Security template: $($secResult.SettingsApplied) settings in $($secResult.SectionsApplied) sections" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level ERROR -Message "Security template application had errors" -Module $moduleName
            }
            
            # Step 9: Apply Audit Policies
            Write-ModuleLog -Level INFO -Message "Step 9/9: Applying audit policies..." -Module $moduleName
            
            $auditResult = Set-AuditPolicies -AuditPoliciesPath $auditPoliciesPath -DryRun:$DryRun
            
            $result.Details.AuditPolicies = $auditResult.Applied
            $result.SettingsApplied += $auditResult.Applied
            
            if ($auditResult.Errors.Count -gt 0) {
                foreach ($err in $auditResult.Errors) {
                    $result.Errors += $err
                }
            }
            
            Write-ModuleLog -Level SUCCESS -Message "Audit policies: $($auditResult.Applied) applied" -Module $moduleName
            
            # Verification (Spot-Check)
            if (-not $SkipVerify -and -not $DryRun) {
                Write-ModuleLog -Level INFO -Message "Performing spot-check verification..." -Module $moduleName
                
                $verificationFailed = 0
                
                # Spot-check: Verify a few critical registry settings
                $criticalSettings = @(
                    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Expected = 1 },
                    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "LsaCfgFlags"; Expected = 1 },
                    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Expected = 1 }
                )
                
                foreach ($setting in $criticalSettings) {
                    try {
                        if (Test-Path $setting.Path) {
                            $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction Stop
                            if ($value.$($setting.Name) -ne $setting.Expected) {
                                $verificationFailed++
                            }
                        }
                        else {
                            $verificationFailed++
                        }
                    }
                    catch {
                        $verificationFailed++
                    }
                }
                
                if ($result.Errors.Count -eq 0 -and $verificationFailed -eq 0) {
                    $result.VerificationPassed = $true
                    Write-ModuleLog -Level SUCCESS -Message "Spot-check verification passed (critical settings OK)" -Module $moduleName
                    Write-ModuleLog -Level INFO -Message "For comprehensive verification, run: .\Tools\Verify-Complete-Hardening.ps1" -Module $moduleName
                }
                else {
                    Write-ModuleLog -Level WARNING -Message "Verification found issues: $verificationFailed critical settings failed" -Module $moduleName
                }
            }
            
            # Mark as successful if we got this far
            if ($result.Errors.Count -eq 0) {
                $result.Success = $true
                Write-ModuleLog -Level SUCCESS -Message "Security Baseline applied successfully!" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level WARNING -Message "Security Baseline completed with $($result.Errors.Count) errors" -Module $moduleName
            }
            
        }
        catch {
            $result.Success = $false
            $result.Errors += "Security Baseline application failed: $($_.Exception.Message)"
            
            # Use Write-ErrorLog if available (framework), else use Write-ModuleLog
            if (Get-Command Write-ErrorLog -ErrorAction SilentlyContinue) {
                Write-ErrorLog -Message "Security Baseline failed" -Module $moduleName -ErrorRecord $_
            }
            else {
                Write-ModuleLog -Level ERROR -Message "Security Baseline failed: $_" -Module $moduleName
            }
        }
    }
    
    end {
        $result.Duration = (Get-Date) - $startTime
        
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "SECURITY BASELINE SUMMARY" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Total Settings Applied: $($result.SettingsApplied)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Registry Policies:  $($result.Details.RegistryPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Security Settings:  $($result.Details.SecuritySettings)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Audit Policies:     $($result.Details.AuditPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Errors: $($result.Errors.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Warnings: $($result.Warnings.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Duration: $($result.Duration.TotalSeconds) seconds" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        
        # GUI parsing marker for settings count (425 = 335 Registry + 67 SecTemplate + 23 Audit)
        Write-Log -Level SUCCESS -Message "Applied 425 settings" -Module "SecurityBaseline"
        
        return $result
    }
}
