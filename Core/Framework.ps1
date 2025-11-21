<#
.SYNOPSIS
    Main orchestration engine for NoID Privacy Pro Framework
    
.DESCRIPTION
    Core framework that orchestrates module execution, manages configuration,
    logging, validation, and rollback functionality.
    
.NOTES
    Author: NexusOne23
    Version: 2.1.0
    Requires: PowerShell 5.1+
    
.EXAMPLE
    .\Framework.ps1 -DryRun
    Run in dry-run mode to preview changes
    
.EXAMPLE
    .\Framework.ps1 -ModulesOnly SecurityBaseline,ASR
    Run only specific modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ModulesOnly,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipBackup,
    
    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging
)

# Script-level variables
$script:FrameworkVersion = "2.1.0"
$script:FrameworkRoot = Split-Path -Parent $PSScriptRoot
$script:ExecutionStartTime = Get-Date

# Import core and utility modules
$script:ModulesToLoad = @(
    [PSCustomObject]@{ Path = "Core\Logger.ps1"; Name = "Logger" },
    [PSCustomObject]@{ Path = "Core\Config.ps1"; Name = "Config" },
    [PSCustomObject]@{ Path = "Core\Validator.ps1"; Name = "Validator" },
    [PSCustomObject]@{ Path = "Core\Rollback.ps1"; Name = "Rollback" },
    [PSCustomObject]@{ Path = "Utils\Registry.ps1"; Name = "Registry Utils" },
    [PSCustomObject]@{ Path = "Utils\Service.ps1"; Name = "Service Utils" },
    [PSCustomObject]@{ Path = "Utils\Hardware.ps1"; Name = "Hardware Utils" },
    # NOTE: Utils\GPO.ps1 removed - v2.0 SecurityBaseline is self-contained, no LGPO.exe dependency
    [PSCustomObject]@{ Path = "Utils\Localization.ps1"; Name = "Localization Utils" },
    [PSCustomObject]@{ Path = "Utils\Compatibility.ps1"; Name = "Compatibility Utils" },
    [PSCustomObject]@{ Path = "Utils\Dependencies.ps1"; Name = "Dependencies Utils" }
)

Write-Host "NoID Privacy Pro Framework v$script:FrameworkVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($moduleInfo in $script:ModulesToLoad) {
    $modulePath = Join-Path $script:FrameworkRoot $moduleInfo.Path
    
    if (Test-Path -Path $modulePath) {
        try {
            . $modulePath
            Write-Host "[OK] Loaded: $($moduleInfo.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to load: $($moduleInfo.Name)" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "[ERROR] Module not found: $($moduleInfo.Name) ($modulePath)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

function Initialize-Framework {
    <#
    .SYNOPSIS
        Initialize the framework and all subsystems
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Initializing framework..." -ForegroundColor Cyan
    
    # Only initialize logger if not already initialized (NoIDPrivacy.ps1 may have already done it)
    if ([string]::IsNullOrEmpty($script:LoggerConfig.LogFilePath)) {
        $logLevel = if ($VerboseLogging) { [LogLevel]::DEBUG } else { [LogLevel]::INFO }
        $logDirectory = Join-Path $script:FrameworkRoot "Logs"
        Initialize-Logger -LogDirectory $logDirectory -MinimumLevel $logLevel
    }
    
    Write-Log -Level INFO -Message "NoID Privacy Pro Framework v$script:FrameworkVersion starting" -Module "Framework"
    Write-Log -Level INFO -Message "PowerShell version: $($PSVersionTable.PSVersion)" -Module "Framework"
    
    # Load configuration
    if ($ConfigPath) {
        Initialize-Config -ConfigPath $ConfigPath
    }
    else {
        Initialize-Config
    }
    
    # Initialize backup system
    if (-not $SkipBackup) {
        Initialize-BackupSystem
        
        # Create system restore point
        Write-Host "Creating system restore point..." -ForegroundColor Yellow
        $restorePointCreated = New-SystemRestorePoint
        
        if (-not $restorePointCreated) {
            Write-Log -Level WARNING -Message "System restore point creation failed or unavailable" -Module "Framework"
        }
    }
    else {
        Write-Log -Level WARNING -Message "Backup system SKIPPED (not recommended)" -Module "Framework"
    }
    
    Write-Host ""
}

function Test-FrameworkPrerequisites {
    <#
    .SYNOPSIS
        Validate all prerequisites before execution
        
    .OUTPUTS
        Boolean indicating if prerequisites are met
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Host "Validating system prerequisites..." -ForegroundColor Cyan
    Write-Host ""
    
    $prereqsPassed = Test-Prerequisites
    
    if (-not $prereqsPassed.Success) {
        Write-Log -Level ERROR -Message "Prerequisite validation failed" -Module "Framework"
        Write-Host ""
        Write-Host "PREREQUISITE CHECK FAILED" -ForegroundColor Red
        Write-Host "Please resolve the issues above before continuing." -ForegroundColor Red
        return $false
    }
    
    Write-Host ""
    Write-Host "All basic prerequisite checks passed" -ForegroundColor Green
    Write-Host ""
    
    # Check if system is domain-joined (interactive warning)
    Write-Host "Checking domain status..." -ForegroundColor Cyan
    $null = Test-DomainJoined -Interactive
    Write-Host ""
    
    # Confirm system backup exists (interactive prompt)
    Write-Host "Verifying system backup..." -ForegroundColor Cyan
    $backupStatus = Confirm-SystemBackup
    
    if (-not $backupStatus.UserConfirmed) {
        Write-Log -Level ERROR -Message "System backup confirmation failed" -Module "Framework"
        return $false
    }
    
    Write-Host ""
    Write-Host "All prerequisite checks completed successfully" -ForegroundColor Green
    Write-Host ""
    
    return $true
}

function Get-ModulesToExecute {
    <#
    .SYNOPSIS
        Determine which modules should be executed
        
    .OUTPUTS
        Array of module names to execute
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    
    if ($ModulesOnly -and $ModulesOnly.Count -gt 0) {
        Write-Log -Level INFO -Message "Running specific modules: $($ModulesOnly -join ', ')" -Module "Framework"
        return $ModulesOnly
    }
    else {
        $enabledModules = Get-EnabledModules
        Write-Log -Level INFO -Message "Running all enabled modules: $($enabledModules -join ', ')" -Module "Framework"
        return $enabledModules
    }
}

# NOTE: Invoke-HardeningModule has been removed.
# Use Invoke-Hardening instead for module execution.

function Start-HardeningProcess {
    <#
    .SYNOPSIS
        Main execution entry point
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "STARTING HARDENING PROCESS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($DryRun) {
        Write-Host "MODE: DRY RUN (Preview only)" -ForegroundColor Yellow
        Write-Log -Level WARNING -Message "Running in DRY RUN mode - no changes will be applied" -Module "Framework"
    }
    else {
        Write-Host "MODE: APPLY CHANGES" -ForegroundColor Green
        Write-Log -Level INFO -Message "Running in APPLY mode - changes will be applied" -Module "Framework"
    }
    
    Write-Host ""
    
    # Get modules to execute
    $modulesToRun = Get-ModulesToExecute
    
    if ($modulesToRun.Count -eq 0) {
        Write-Log -Level WARNING -Message "No modules enabled for execution" -Module "Framework"
        Write-Host "No modules to execute. Check your configuration." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Modules to execute: $($modulesToRun.Count)" -ForegroundColor Cyan
    foreach ($mod in $modulesToRun) {
        Write-Host "  - $mod" -ForegroundColor White
    }
    Write-Host ""
    
    # Confirmation prompt (unless in dry run)
    if (-not $DryRun) {
        Write-Host "WARNING: This will modify your system settings." -ForegroundColor Yellow
        Write-Host "A backup and restore point have been created." -ForegroundColor Yellow
        Write-Host ""
        
        do {
            $confirmation = Read-Host "Do you want to continue? [Y/N] (default: Y)"
            if ([string]::IsNullOrWhiteSpace($confirmation)) { $confirmation = "Y" }
            $confirmation = $confirmation.ToUpper()
            
            if ($confirmation -notin @('Y', 'N')) {
                Write-Host ""
                Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                Write-Host ""
            }
        } while ($confirmation -notin @('Y', 'N'))
        
        if ($confirmation -ne "Y") {
            Write-Log -Level INFO -Message "Execution cancelled by user" -Module "Framework"
            Write-Host ""
            Write-Host "Execution cancelled." -ForegroundColor Yellow
            Write-Host ""
            return
        }
        
        Write-Host ""
    }
    
    # Execute modules using Invoke-Hardening
    Write-Log -Level INFO -Message "Starting module execution: $($modulesToRun -join ', ')" -Module "Framework"
    
    # Determine correct module parameter based on what user selected
    if ($modulesToRun.Count -eq 1) {
        $hardeningResult = Invoke-Hardening -Module $modulesToRun[0] -DryRun:$DryRun
    }
    else {
        $hardeningResult = Invoke-Hardening -Module "All" -DryRun:$DryRun
    }
    
    # Summary (correctly use hardeningResult.ModuleResults)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $totalDuration = (Get-Date) - $script:ExecutionStartTime
    
    # Correct calculation from ModuleResults
    $totalModules = $hardeningResult.ModulesExecuted
    $successCount = ($hardeningResult.ModuleResults | Where-Object { $_.Success }).Count
    $failureCount = $totalModules - $successCount
    
    Write-Host "Total modules executed: $totalModules" -ForegroundColor White
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failureCount" -ForegroundColor $(if ($failureCount -gt 0) { "Red" } else { "White" })
    Write-Host "Total duration: $([math]::Round($totalDuration.TotalMinutes, 2)) minutes" -ForegroundColor White
    
    if ($hardeningResult.Warnings.Count -gt 0) {
        Write-Host "Warnings: $($hardeningResult.Warnings.Count)" -ForegroundColor Yellow
    }
    if ($hardeningResult.Errors.Count -gt 0) {
        Write-Host "Errors: $($hardeningResult.Errors.Count)" -ForegroundColor Red
    }
    
    Write-Host ""
    
    Write-Log -Level INFO -Message "Hardening process completed" -Module "Framework"
    Write-Log -Level INFO -Message "Log file: $(Get-LogFilePath)" -Module "Framework"
    
    Write-Host "Log file: $(Get-LogFilePath)" -ForegroundColor Cyan
    Write-Host ""
    
    # Reboot recommendation
    if (-not $DryRun -and $successCount -gt 0) {
        Write-Host "RECOMMENDATION: Restart your computer for all changes to take effect." -ForegroundColor Yellow
        Write-Host ""
    }
}

function Invoke-Hardening {
    <#
    .SYNOPSIS
        Execute hardening module(s)
        
    .PARAMETER Module
        Module name to execute (SecurityBaseline, ASR, DNS, etc.) or "All"
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .OUTPUTS
        PSCustomObject with execution results
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity", "All")]
        [string]$Module,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $startTime = Get-Date
    $results = [PSCustomObject]@{
        Success         = $true
        ModulesExecuted = 0
        Duration        = $null
        Errors          = @()
        Warnings        = @()
        ModuleResults   = @()
    }
    
    # Get module list to execute
    $modulesToExecute = @()
    
    if ($Module -eq "All") {
        # Get all enabled modules from config (sorted by priority)
        $modulesToExecute = Get-EnabledModules
    }
    else {
        # Single module - check if it's enabled in config
        $moduleConfig = $script:Config.modules.$Module
        
        if ($null -eq $moduleConfig) {
            Write-Log -Level WARNING -Message "Module '$Module' not found in configuration" -Module "Framework"
            $results.Warnings += "Module '$Module' not configured"
            return $results
        }
        
        if ($moduleConfig.enabled -eq $false) {
            Write-Log -Level INFO -Message "Module '$Module' is disabled in configuration - skipping" -Module "Framework"
            Write-Host "Module '$Module' is disabled - skipping execution" -ForegroundColor Gray
            return $results
        }
        
        $modulesToExecute = @($Module)
    }
    
    Write-Log -Level INFO -Message "Executing modules: $($modulesToExecute -join ', ')" -Module "Framework"
    
    # Initialize backup system ONCE before all modules
    if (-not $DryRun) {
        try {
            Initialize-BackupSystem
            Write-Log -Level INFO -Message "Backup session initialized for all modules" -Module "Framework"
        }
        catch {
            Write-ErrorLog -Message "Failed to initialize backup system" -Module "Framework" -ErrorRecord $_
            $warnMsg = "Backup system initialization failed - proceeding without automatic backup"
            $results.Warnings += $warnMsg
        }
    }
    
    # Execute each module
    foreach ($moduleName in $modulesToExecute) {
        try {
            Write-Log -Level INFO -Message "========================================" -Module "Framework"
            Write-Log -Level INFO -Message "Module: $moduleName" -Module "Framework"
            Write-Log -Level INFO -Message "========================================" -Module "Framework"
            
            # Module Confirmation Prompt (skip in DryRun or if only 1 module)
            if (-not $DryRun -and $modulesToExecute.Count -gt 1) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  MODULE: $moduleName" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                
                # Module-specific description
                switch ($moduleName) {
                    "SecurityBaseline" {
                        Write-Host "Microsoft Security Baseline for Windows 11 25H2" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 425 hardening settings:" -ForegroundColor Gray
                        Write-Host "    - 335 Registry policies (password, firewall, BitLocker)" -ForegroundColor Gray
                        Write-Host "    - 67 Security template settings (user rights, audit)" -ForegroundColor Gray
                        Write-Host "    - 23 Advanced audit policies" -ForegroundColor Gray
                        Write-Host "    - VBS + Credential Guard + Memory Integrity" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: Enterprise-grade security, may break legacy software" -ForegroundColor Yellow
                    }
                    "ASR" {
                        Write-Host "Attack Surface Reduction Rules" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 19 Microsoft Defender ASR rules:" -ForegroundColor Gray
                        Write-Host "    - Block ransomware, exploits, malicious scripts" -ForegroundColor Gray
                        Write-Host "    - Block credential theft (lsass.exe protection)" -ForegroundColor Gray
                        Write-Host "    - Block Office macros, email executables" -ForegroundColor Gray
                        Write-Host "    - Block untrusted USB execution, Safe Mode reboot" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll be asked about SCCM/Intune usage" -ForegroundColor Yellow
                    }
                    "DNS" {
                        Write-Host "Secure DNS with DNS-over-HTTPS" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Configures encrypted DNS:" -ForegroundColor Gray
                        Write-Host "    - Choose provider: Cloudflare, Quad9, or AdGuard" -ForegroundColor Gray
                        Write-Host "    - Enable DoH encryption (HTTPS)" -ForegroundColor Gray
                        Write-Host "    - Blocks DNS hijacking and snooping" -ForegroundColor Gray
                        Write-Host "    - IPv4 + IPv6 configuration" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll choose provider and DoH mode interactively" -ForegroundColor Yellow
                    }
                    "Privacy" {
                        Write-Host "Telemetry & Privacy Hardening" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies up to 48 privacy settings (mode-dependent):" -ForegroundColor Gray
                        Write-Host "    - Telemetry control (3 modes: MSRecommended/Strict/Paranoid)" -ForegroundColor Gray
                        Write-Host "    - MSRecommended: 32 registry settings (default, max compatibility)" -ForegroundColor DarkGray
                        Write-Host "    - Strict/Paranoid: 33-36 settings + services disabled" -ForegroundColor DarkGray
                        Write-Host "    - Disable ads, tips, personalization" -ForegroundColor Gray
                        Write-Host "    - Remove bloatware (up to 24 apps, if present)" -ForegroundColor Gray
                        Write-Host "    - OneDrive hardening (keeps sync functional)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll choose privacy mode interactively" -ForegroundColor Yellow
                    }
                    "AntiAI" {
                        Write-Host "Disable Windows 11 AI Features" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Disables 24 AI policies:" -ForegroundColor Gray
                        Write-Host "    - Windows Recall (screenshot capture)" -ForegroundColor Gray
                        Write-Host "    - Windows Copilot (AI assistant)" -ForegroundColor Gray
                        Write-Host "    - Click to Do (screenshot analysis)" -ForegroundColor Gray
                        Write-Host "    - Paint AI (Cocreator, Generative Fill, Image Creator)" -ForegroundColor Gray
                        Write-Host "    - Notepad AI (Write, Summarize, Rewrite)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: All AI features disabled, reboot required" -ForegroundColor Yellow
                    }
                    "EdgeHardening" {
                        Write-Host "Microsoft Edge v139 Security Baseline" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 20 Edge security policies:" -ForegroundColor Gray
                        Write-Host "    - Enhanced Security Mode (Strict)" -ForegroundColor Gray
                        Write-Host "    - SmartScreen + PUA protection" -ForegroundColor Gray
                        Write-Host "    - Site Isolation + SSL/TLS hardening" -ForegroundColor Gray
                        Write-Host "    - Extension blocklist (blocks all by default)" -ForegroundColor Gray
                        Write-Host "    - Tracking Prevention (Strict mode)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: Maximum Edge security, extensions blocked by default" -ForegroundColor Yellow
                    }
                    "AdvancedSecurity" {
                        Write-Host "Advanced Security Hardening (Beyond MS Baseline)" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 11 security features (42 individual settings):" -ForegroundColor Gray
                        Write-Host "    - RDP hardening + optional complete disable" -ForegroundColor Gray
                        Write-Host "    - WDigest credential protection" -ForegroundColor Gray
                        Write-Host "    - Admin Shares disable (domain-aware)" -ForegroundColor Gray
                        Write-Host "    - Risky ports/services block (LLMNR, NetBIOS, UPnP)" -ForegroundColor Gray
                        Write-Host "    - Legacy TLS 1.0/1.1 disable, WPAD disable, PSv2 removal" -ForegroundColor Gray
                        Write-Host "    - SRP .lnk protection (CVE-2025-9491)" -ForegroundColor Gray
                        Write-Host "    - Windows Update (3 simple GUI settings)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll choose profile (Home/Enterprise/AirGapped)" -ForegroundColor Yellow
                    }
                    default {
                        Write-Host "This module will apply changes to your system." -ForegroundColor White
                        Write-Host ""
                    }
                }
                
                Write-Host ""
                Write-Host "Options:" -ForegroundColor White
                Write-Host "  [Y] Yes    - Apply this module" -ForegroundColor Green
                Write-Host "  [N] No     - Skip this module" -ForegroundColor Yellow
                Write-Host "  [A] Abort  - Stop entire process" -ForegroundColor Red
                Write-Host ""
                
                do {
                    $response = Read-Host "Continue with ${moduleName}? [Y/N/A] (default: Y)"
                    if ([string]::IsNullOrWhiteSpace($response)) { $response = "Y" }
                    $response = $response.ToUpper()
                } while ($response -notin @('Y', 'N', 'A', 'YES', 'NO', 'ABORT'))
                
                if ($response -in @('A', 'ABORT')) {
                    Write-Log -Level WARNING -Message "User aborted execution at module: $moduleName" -Module "Framework"
                    Write-Host ""
                    Write-Host "Execution aborted by user" -ForegroundColor Red
                    Write-Host ""
                    $results.Warnings += "Execution aborted by user at module: $moduleName"
                    break
                }
                elseif ($response -in @('N', 'NO')) {
                    Write-Log -Level INFO -Message "User skipped module: $moduleName" -Module "Framework"
                    Write-Host ""
                    Write-Host "Skipping module: $moduleName" -ForegroundColor Yellow
                    Write-Host ""
                    continue
                }
                
                Write-Host ""
                Write-Host "Proceeding with $moduleName..." -ForegroundColor Green
                Write-Host ""
            }
            
            $moduleResult = $null
            $modulePath = Join-Path $script:FrameworkRoot "Modules\$moduleName"
            
            # Check if module exists
            if (-not (Test-Path $modulePath)) {
                $errMsg = "Module not found: $moduleName (Path: $modulePath)"
                Write-Log -Level WARNING -Message $errMsg -Module "Framework"
                $results.Warnings += $errMsg
                continue
            }
            
            # Check module implementation status (FIX #2)
            $moduleConfig = $script:Config.modules.$moduleName
            if ($moduleConfig.PSObject.Properties.Name -contains 'status') {
                if ($moduleConfig.status -ne 'IMPLEMENTED') {
                    Write-Log -Level WARNING -Message "Skipping module '$moduleName' - Status: $($moduleConfig.status) (not IMPLEMENTED)" -Module "Framework"
                    Write-Host "  [SKIP] $moduleName - Not yet implemented" -ForegroundColor Yellow
                    continue
                }
            }
            
            # Load and execute module based on name
            switch ($moduleName) {
                "SecurityBaseline" {
                    $manifestPath = Join-Path $modulePath "SecurityBaseline.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        $moduleResult = Invoke-SecurityBaseline -DryRun:$DryRun
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "ASR" {
                    $manifestPath = Join-Path $modulePath "ASR.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        $moduleResult = Invoke-ASRRules -DryRun:$DryRun
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "DNS" {
                    $manifestPath = Join-Path $modulePath "DNS.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        
                        # DNS module handles provider selection interactively
                        # For non-interactive/automation, use config.json provider
                        if ($script:Config.modules.DNS.PSObject.Properties.Name -contains 'provider' -and $script:Config.modules.DNS.provider) {
                            $moduleResult = Invoke-DNSConfiguration -Provider $script:Config.modules.DNS.provider -DryRun:$DryRun
                        }
                        else {
                            # Interactive mode - module will ask for provider
                            $moduleResult = Invoke-DNSConfiguration -DryRun:$DryRun
                        }
                        
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "Privacy" {
                    $manifestPath = Join-Path $modulePath "Privacy.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        
                        # Privacy module handles mode selection interactively
                        # For non-interactive/automation, use config.json mode
                        $privacyArgs = @{ DryRun = $DryRun }
                        
                        if ($script:Config.modules.Privacy.PSObject.Properties.Name -contains 'mode' -and $script:Config.modules.Privacy.mode) {
                            Write-Log -Level INFO -Message "Privacy mode: $($script:Config.modules.Privacy.mode)" -Module "Framework"
                            $privacyArgs["Mode"] = $script:Config.modules.Privacy.mode
                        }
                        
                        if ($script:Config.modules.Privacy.PSObject.Properties.Name -contains 'removeBloatware') {
                            $rb = $script:Config.modules.Privacy.removeBloatware
                            # Convert string "Y"/"N" to boolean if needed (defensive coding)
                            if ($rb -is [string]) {
                                $rb = ($rb -eq "Y" -or $rb -eq "yes" -or $rb -eq "true" -or $rb -eq "1")
                            }
                            Write-Log -Level INFO -Message "Privacy removeBloatware: $rb" -Module "Framework"
                            $privacyArgs["RemoveBloatware"] = $rb
                        }

                        if ($privacyArgs.Count -gt 1) {
                             # If we have config args, run non-interactively (or at least with those args)
                             $moduleResult = Invoke-PrivacyHardening @privacyArgs
                        }
                        else {
                            # Interactive mode - module will ask for mode selection
                            $moduleResult = Invoke-PrivacyHardening -DryRun:$DryRun
                        }
                        
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "AntiAI" {
                    $manifestPath = Join-Path $modulePath "AntiAI.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        
                        # AntiAI module applies maximum AI deactivation (no modes)
                        Write-Log -Level INFO -Message "Disabling all Windows 11 AI features (8+ features)" -Module "Framework"
                        $moduleResult = Invoke-AntiAI -DryRun:$DryRun
                        
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "EdgeHardening" {
                    $manifestPath = Join-Path $modulePath "EdgeHardening.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        
                        # EdgeHardening applies Microsoft Edge security baseline
                        Write-Log -Level INFO -Message "Applying Microsoft Edge v139 Security Baseline (20 policies)" -Module "Framework"
                        $moduleResult = Invoke-EdgeHardening -DryRun:$DryRun
                        
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                "AdvancedSecurity" {
                    $manifestPath = Join-Path $modulePath "AdvancedSecurity.psd1"
                    if (Test-Path $manifestPath) {
                        if (-not (Get-Module -Name $moduleName)) {
                            Import-Module $manifestPath -ErrorAction Stop
                        }
                        
                        # AdvancedSecurity handles profile selection interactively or from config
                        if ($script:Config.modules.AdvancedSecurity.PSObject.Properties.Name -contains 'profile' -and $script:Config.modules.AdvancedSecurity.profile) {
                            Write-Log -Level INFO -Message "AdvancedSecurity profile: $($script:Config.modules.AdvancedSecurity.profile)" -Module "Framework"
                            $moduleResult = Invoke-AdvancedSecurity -Profile $script:Config.modules.AdvancedSecurity.profile -DryRun:$DryRun
                        }
                        else {
                            # Interactive mode - module will ask for profile
                            $moduleResult = Invoke-AdvancedSecurity -DryRun:$DryRun
                        }
                        
                    }
                    else {
                        throw "Module manifest not found: $manifestPath"
                    }
                }
                
                default {
                    $warnMsg = "Module '$moduleName' is not yet implemented"
                    Write-Log -Level WARNING -Message $warnMsg -Module "Framework"
                    $results.Warnings += $warnMsg
                    continue
                }
            }
            
            # Store module result
            if ($moduleResult) {
                # If module returned an array, use the last element as the actual result
                # (handles cases where helper functions inadvertently output to pipeline)
                if ($moduleResult -is [array]) {
                    Write-Log -Level DEBUG -Message "Module '$moduleName' returned array ($($moduleResult.Count) items), using last element as result object" -Module "Framework"
                    $moduleResult = $moduleResult[-1]
                }
                
                $results.ModuleResults += $moduleResult
                $results.ModulesExecuted++
                
                # Handle different return types: Boolean or PSCustomObject
                $success = $false
                
                if ($moduleResult -is [bool]) {
                    # Module returned simple boolean (e.g., Privacy module)
                    $success = $moduleResult
                }
                elseif ($moduleResult -is [PSCustomObject]) {
                    # Module returned object with Success property (e.g., ASR, DNS modules)
                    $hasSuccess = $null -ne ($moduleResult.PSObject.Properties | Where-Object { $_.Name -eq 'Success' })
                    $success = if ($hasSuccess) { $moduleResult.Success } else { $false }
                }
                else {
                    # Unknown type - assume failure
                    Write-Log -Level WARNING -Message "Module '$moduleName' returned unexpected type: $($moduleResult.GetType().Name)" -Module "Framework"
                }
                
                if ($success) {
                    Write-Log -Level SUCCESS -Message "Module '$moduleName' completed successfully" -Module "Framework"
                }
                else {
                    Write-Log -Level WARNING -Message "Module '$moduleName' completed with errors" -Module "Framework"
                    
                    # Only add errors if moduleResult is an object with Errors property
                    if ($moduleResult -is [PSCustomObject]) {
                        $hasErrors = $null -ne ($moduleResult.PSObject.Properties | Where-Object { $_.Name -eq 'Errors' })
                        if ($hasErrors -and $moduleResult.Errors.Count -gt 0) {
                            $results.Errors += $moduleResult.Errors
                        }
                    }
                }
            }
        }
        catch {
            Write-ErrorLog -Message "Failed to execute module '$moduleName'" -Module "Framework" -ErrorRecord $_
            $errMsg = "Module '$moduleName' execution failed: $($_.Exception.Message)"
            $results.Errors += $errMsg
            $results.Success = $false
        }
    }
    
    # Calculate duration
    $results.Duration = (Get-Date) - $startTime
    
    # Final success status
    if ($results.Errors.Count -gt 0) {
        $results.Success = $false
    }
    
    Write-Log -Level INFO -Message "Hardening execution completed - Modules: $($results.ModulesExecuted), Errors: $($results.Errors.Count), Warnings: $($results.Warnings.Count)" -Module "Framework"
    
    return $results
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module

# Main execution (only if script is run directly, not dot-sourced)
# This allows Framework.ps1 to be used standalone OR dot-sourced by NoIDPrivacy.ps1
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.Line -notmatch '^\s*\.\s+') {
    try {
        Initialize-Framework
        
        $prereqsPassed = Test-FrameworkPrerequisites
        
        if ($prereqsPassed) {
            Start-HardeningProcess
        }
        else {
            Write-Host "Execution aborted due to failed prerequisites." -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host ""
        Write-Host "CRITICAL ERROR" -ForegroundColor Red
        Write-Host "An unexpected error occurred:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""
        Write-Host "Stack trace:" -ForegroundColor Gray
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        
        if ($null -ne (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            Write-Log -Level ERROR -Message "Critical framework error" -Module "Framework" -Exception $_.Exception
        }
        
        exit 1
    }
}
