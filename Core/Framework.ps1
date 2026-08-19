<#
.SYNOPSIS
    Main orchestration engine for NoID Privacy Framework

.DESCRIPTION
    Core framework that orchestrates module execution, manages configuration,
    logging, validation, and rollback functionality.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+

    This file is a DOT-SOURCED LIBRARY -- it has no param() block and is not run
    standalone. The production entry points dot-source it and drive execution via
    Invoke-Hardening:
      - NoIDPrivacy.ps1             (CLI; Test-FrameworkPrerequisites + Invoke-Hardening)
      - NoIDPrivacy-Interactive.ps1 (wizard; Invoke-HardeningWorkflow -> Invoke-Hardening)
      - GUI (HardeningEngine.cs runs NoIDPrivacy.ps1 NonInteractive)
#>

# Note: This script is dot-sourced as a library, not called directly with parameters.
# All configuration comes from config.json via Initialize-Config.

# Script-level variables
# Read version from the canonical VERSION file (single source of truth) so that a
# `Bump-Version.ps1` run reaches every reference automatically -- inline rather than
# via Get-FrameworkVersion because Config.ps1 is not yet dot-sourced at this point.
$script:FrameworkRoot = Split-Path -Parent $PSScriptRoot
$_versionFile = Join-Path $script:FrameworkRoot "VERSION"
$script:FrameworkVersion = if (Test-Path -LiteralPath $_versionFile) {
    (Get-Content -LiteralPath $_versionFile -Raw -Encoding UTF8).Trim()
} else { "0.0.0" }
$script:ExecutionStartTime = Get-Date

# Import core and utility modules
$script:ModulesToLoad = @(
    [PSCustomObject]@{ Path = "Core\Logger.ps1"; Name = "Logger" },
    [PSCustomObject]@{ Path = "Core\Config.ps1"; Name = "Config" },
    [PSCustomObject]@{ Path = "Core\Validator.ps1"; Name = "Validator" },
    [PSCustomObject]@{ Path = "Core\Rollback.ps1"; Name = "Rollback" },
    [PSCustomObject]@{ Path = "Core\IntentState.ps1"; Name = "Intent State" },
    [PSCustomObject]@{ Path = "Core\QuickActions.ps1"; Name = "Quick Actions" },
    [PSCustomObject]@{ Path = "Core\NonInteractive.ps1"; Name = "NonInteractive" },
    [PSCustomObject]@{ Path = "Utils\Hardware.ps1"; Name = "Hardware Utils" },
    [PSCustomObject]@{ Path = "Utils\Compatibility.ps1"; Name = "Compatibility Utils" },
    [PSCustomObject]@{ Path = "Utils\Dependencies.ps1"; Name = "Dependencies Utils" }
)

Write-Host "NoID Privacy Framework v$script:FrameworkVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($moduleInfo in $script:ModulesToLoad) {
    $modulePath = Join-Path $script:FrameworkRoot $moduleInfo.Path

    if (Test-Path -LiteralPath $modulePath -PathType Leaf) {
        try {
            . $modulePath
            Write-Host "[OK] Loaded: $($moduleInfo.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to load: $($moduleInfo.Name)" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            throw "Failed to load framework dependency '$($moduleInfo.Name)': $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "[ERROR] Module not found: $($moduleInfo.Name) ($modulePath)" -ForegroundColor Red
        throw "Framework dependency not found: $($moduleInfo.Name) ($modulePath)"
    }
}

Write-Host ""

$script:NoIDModuleDependencyFunctionNames = @(
    'Assert-SessionManifest'
    'Backup-RegistryKey'
    'Backup-ScheduledTask'
    'Backup-ServiceConfiguration'
    'Complete-ModuleBackup'
    'ConvertTo-NativeRegistryPath'
    'Dismount-UserRegistryHiveAfterRestore'
    'Get-BackupSessions'
    'Get-NonInteractiveValue'
    'Get-SessionManifest'
    'Get-WindowsVersion'
    'Initialize-BackupSystem'
    'Initialize-Logger'
    'Mount-UserRegistryHiveForRestore'
    'Read-NoIDIntentState'
    'Register-Backup'
    'Register-BackupFile'
    'Resolve-SessionChildPath'
    'Restore-Session'
    'Save-IncompleteModuleBackup'
    'Start-ModuleBackup'
    'Test-IsAdmin'
    'Test-NonInteractiveMode'
    'Test-ThirdPartySecurityProduct'
    'Test-WindowsVersion'
    'Write-ErrorLog'
    'Write-Log'
    'Write-NonInteractiveDecision'
)

function Initialize-NoIDModuleDependencyBridge {
    <#
    .SYNOPSIS
        Bind the closed Core/Utils dependency surface into an imported module.

    .DESCRIPTION
        PowerShell modules have an isolated session state and cannot resolve
        functions that the entry script dot-sourced into its script scope.
        Copy only the statically audited dependency functions into the target
        module's script scope. The original ScriptBlocks retain their framework
        script-scope binding, including the validated configuration object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]$ImportedModule
    )

    $definitions = @{}
    foreach ($dependencyName in $script:NoIDModuleDependencyFunctionNames) {
        $sourceFunction = Get-Item -LiteralPath "Function:$dependencyName" -ErrorAction Stop
        $definitions[$dependencyName] = $sourceFunction.ScriptBlock
    }

    & $ImportedModule {
        param([Parameter(Mandatory = $true)][hashtable]$DependencyDefinitions)

        foreach ($dependency in $DependencyDefinitions.GetEnumerator()) {
            $null = Set-Item -LiteralPath "Function:script:$($dependency.Key)" `
                -Value $dependency.Value -Force -ErrorAction Stop
        }
    } $definitions

    $missingDependencies = @(& $ImportedModule {
            param([Parameter(Mandatory = $true)][string[]]$RequiredNames)

            foreach ($requiredName in $RequiredNames) {
                if (-not (Get-Command -Name $requiredName -CommandType Function -ErrorAction SilentlyContinue)) {
                    $requiredName
                }
            }
        } $script:NoIDModuleDependencyFunctionNames)
    if ($missingDependencies.Count -gt 0) {
        throw "Module '$($ImportedModule.Name)' dependency bridge is incomplete: $($missingDependencies -join ', ')"
    }
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

    # Check if system is domain-joined (interactive warning only in CLI mode)
    Write-Host "Checking domain status..." -ForegroundColor Cyan
    if (Test-NonInteractiveMode) {
        # GUI mode - just check, don't prompt. An unknown result must not be
        # treated as standalone because that changes module safety decisions.
        $domainCheck = Test-DomainJoined
    }
    else {
        # CLI mode - show interactive warning
        $domainCheck = Test-DomainJoined -Interactive
    }
    if (-not $domainCheck.QuerySucceeded) {
        Write-Log -Level ERROR -Message 'Domain-membership detection failed; refusing to assume a standalone workstation' -Module 'Framework'
        return $false
    }
    if (-not (Test-NonInteractiveMode) -and $domainCheck.IsDomainJoined -and -not $domainCheck.UserConfirmed) {
        Write-Log -Level INFO -Message "Aborting per user cancellation on domain-joined system" -Module "Framework"
        return $false
    }
    Write-Host ""

    # Confirm system backup exists (interactive prompt only in CLI mode)
    Write-Host "Verifying system backup..." -ForegroundColor Cyan
    if (Test-NonInteractiveMode) {
        # GUI mode - auto-confirm (backup is created by engine)
        Write-Host "[GUI] Backup verification: Auto-confirmed" -ForegroundColor Cyan
        $backupStatus = [PSCustomObject]@{ UserConfirmed = $true }
    }
    else {
        # CLI mode - interactive prompt
        $backupStatus = Confirm-SystemBackup
    }

    if (-not $backupStatus.UserConfirmed) {
        Write-Log -Level ERROR -Message "System backup confirmation failed" -Module "Framework"
        return $false
    }

    Write-Host ""
    Write-Host "All prerequisite checks completed successfully" -ForegroundColor Green
    Write-Host ""

    return $true
}

function New-NoIDFailedModuleRecord {
    <#
    .SYNOPSIS
        Builds the module result record for a module that failed before it could
        return one.

    .DESCRIPTION
        The GUI result contract reconciles modulesFailed against the emitted
        module records (HardeningEngine.TryApplyResultContract). Incrementing the
        counter without adding a record produced a payload the wrapper rejects,
        which made it report "Engine did not emit the required NOID_RESULT_JSON
        contract marker" - literally false, the marker was emitted - and discard
        the per-module summaries together with the BAVR session path the
        operator needs in order to restore.

        Field names match the projection in NoIDPrivacy.ps1 (ModuleName,
        Success, Status, AppliedSettingsCount).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Pure result-record factory; it builds and returns an object without mutating system state.'
    )]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )

    return [PSCustomObject]@{
        ModuleName           = $ModuleName
        Success              = $false
        Status               = 'Failed'
        AppliedSettingsCount = 0
    }
}

function Invoke-Hardening {
    <#
    .SYNOPSIS
        Execute hardening module(s)

    .PARAMETER Module
        Single module to execute, or "All" for every enabled module.

    .PARAMETER Modules
        Explicit subset of modules to execute (use instead of -Module when running 2-6 modules).
        When provided, only the listed modules run (NOT all enabled modules).

    .PARAMETER DryRun
        Preview changes without applying them

    .OUTPUTS
        PSCustomObject with execution results
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
        [ValidateSet("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity", "All")]
        [string]$Module,

        [Parameter(Mandatory = $true, ParameterSetName = 'Multiple')]
        [ValidateScript({
            $valid = @("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity")
            foreach ($m in $_) {
                if ($m -notin $valid) { throw "Invalid module name '$m'. Valid: $($valid -join ', ')" }
            }
            $true
        })]
        [string[]]$Modules,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $startTime = Get-Date
    $warningLogCountAtStart = Get-LogLevelCount -Level WARNING
    $results = [PSCustomObject]@{
        Success         = $true
        Status          = 'Running'
        ModulesExecuted = 0
        ModulesSkipped  = 0
        ModulesFailed   = 0
        Aborted         = $false
        Duration        = $null
        TotalSettingsApplied = 0
        BackupPath      = ''
        Errors          = @()
        Warnings        = @()
        WarningsLogged  = 0
        ModuleResults   = @()
    }
    $updateWarningLogCount = {
        $results.WarningsLogged = (Get-LogLevelCount -Level WARNING) - $warningLogCountAtStart
        if ($results.WarningsLogged -lt 0) {
            throw 'Logger warning counter moved backwards during hardening execution'
        }
    }

    # Get module list to execute
    $modulesToExecute = @()

    if ($PSCmdlet.ParameterSetName -eq 'Multiple') {
        # User-specified subset -- filter by enabled flag
        foreach ($m in $Modules) {
            $moduleConfig = $script:Config.modules.$m
            if ($null -eq $moduleConfig) {
                Write-Log -Level WARNING -Message "Module '$m' not found in configuration -- skipping" -Module "Framework"
                $results.Errors += "Module '$m' not configured"
                $results.ModuleResults += New-NoIDFailedModuleRecord -ModuleName $m
                $results.ModulesExecuted++
                $results.ModulesFailed++
                continue
            }
            if ($moduleConfig.enabled -eq $false) {
                Write-Log -Level INFO -Message "Module '$m' is disabled in configuration -- skipping" -Module "Framework"
                $results.ModulesSkipped++
                continue
            }
            $modulesToExecute += $m
        }
        if ($modulesToExecute.Count -eq 0) {
            Write-Log -Level WARNING -Message "No enabled modules in -Modules selection" -Module "Framework"
            $results.Success = $false
            $results.Status = 'NoModulesSelected'
            if ($results.Errors.Count -eq 0) {
                $results.Errors += 'No enabled modules were selected for execution'
            }
            & $updateWarningLogCount
            return $results
        }
    }
    elseif ($Module -eq "All") {
        # Get all enabled modules from config (sorted by priority)
        # A PowerShell function that emits no objects assigns $null, not @().
        # Normalize the pipeline result so an intentionally empty enabled set
        # reaches the explicit NoModulesSelected contract under StrictMode.
        $modulesToExecute = @(Get-EnabledModules)
    }
    else {
        # Single module - check if it's enabled in config
        $moduleConfig = $script:Config.modules.$Module

        if ($null -eq $moduleConfig) {
            Write-Log -Level WARNING -Message "Module '$Module' not found in configuration" -Module "Framework"
            $results.Success = $false
            $results.Status = 'ConfigurationError'
            $results.ModuleResults += New-NoIDFailedModuleRecord -ModuleName $Module
            $results.ModulesExecuted = 1
            $results.ModulesFailed = 1
            $results.Errors += "Module '$Module' not configured"
            & $updateWarningLogCount
            return $results
        }

        if ($moduleConfig.enabled -eq $false) {
            Write-Log -Level INFO -Message "Module '$Module' is disabled in configuration - skipping" -Module "Framework"
            Write-Host "Module '$Module' is disabled - skipping execution" -ForegroundColor Gray
            $results.Success = $false
            $results.Status = 'Skipped'
            $results.ModulesSkipped = 1
            & $updateWarningLogCount
            return $results
        }

        $modulesToExecute = @($Module)
    }

    if ($modulesToExecute.Count -eq 0) {
        $results.Success = $false
        $results.Status = 'NoModulesSelected'
        if ($results.Errors.Count -eq 0) {
            $results.Errors += 'No enabled modules were selected for execution'
        }
        & $updateWarningLogCount
        return $results
    }

    # Full-module Apply and action-scoped Apply/Restore share targets. Serialize
    # all mutations so the sealed overlap/LIFO decision cannot race a second
    # process after its final state read.
    $mutationMutex = $null
    $mutationMutexHeld = $false
    try {
        if (-not $DryRun) {
            $mutationMutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
            try {
                $mutationMutexHeld = $mutationMutex.WaitOne(0, $false)
            }
            catch [Threading.AbandonedMutexException] {
                $mutationMutexHeld = $true
            }
            if (-not $mutationMutexHeld) {
                $results.Success = $false
                $results.Status = 'Busy'
                $results.Errors += 'Another NoID Privacy Apply or Restore operation is already running'
                $results.Duration = (Get-Date) - $startTime
                & $updateWarningLogCount
                return $results
            }
        }

        Write-Log -Level INFO -Message "Executing modules: $($modulesToExecute -join ', ')" -Module "Framework"

    # Initialize backup system ONCE before all modules
    if (-not $DryRun) {
        try {
            if (-not (Initialize-BackupSystem)) {
                throw 'Backup system initialization returned failure'
            }
            Write-Log -Level INFO -Message "Backup session initialized for all modules" -Module "Framework"

            # Set session type from GUI config (for backup identification)
            # SessionType is in options block when sent from GUI
            if ($script:Config.options -and $script:Config.options.PSObject.Properties.Name -contains 'sessionType' -and $script:Config.options.sessionType) {
                Set-SessionType -SessionType $script:Config.options.sessionType
                Write-Log -Level DEBUG -Message "Session type from GUI config: $($script:Config.options.sessionType)" -Module "Framework"
            }
            else {
                # CLI mode: Auto-detect session type based on module count
                $autoSessionType = if ($modulesToExecute.Count -ge 7) { "wizard" }
                elseif ($modulesToExecute.Count -eq 1) { "advanced" }
                else { "manual" }
                Set-SessionType -SessionType $autoSessionType
                Write-Log -Level DEBUG -Message "Session type auto-detected: $autoSessionType (based on $($modulesToExecute.Count) modules)" -Module "Framework"
            }

        }
        catch {
            Write-ErrorLog -Message "Failed to initialize backup system" -Module "Framework" -ErrorRecord $_
            $results.Success = $false
            $results.Errors += "Backup initialization/prestate capture failed: $($_.Exception.Message)"
            $results.Duration = (Get-Date) - $startTime
            & $updateWarningLogCount
            return $results
        }
    }

    # Execute each module
    foreach ($moduleName in $modulesToExecute) {
        try {
            Write-Log -Level INFO -Message "========================================" -Module "Framework"
            Write-Log -Level INFO -Message "Module: $moduleName" -Module "Framework"
            Write-Log -Level INFO -Message "========================================" -Module "Framework"

            # Module Confirmation Prompt for interactive CLI runs.
            # Skipped in DryRun and in NonInteractive/GUI mode.
            if (-not $DryRun -and -not (Test-NonInteractiveMode)) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  MODULE: $moduleName" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""

                # Module-specific description
                switch ($moduleName) {
                    "SecurityBaseline" {
                        Write-Host "Microsoft Security Baseline for Windows 11 24H2 / 25H2" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 425 hardening settings:" -ForegroundColor Gray
                        Write-Host "    - 335 Registry policies (password, firewall, BitLocker)" -ForegroundColor Gray
                        Write-Host "    - 67 Security template settings (user rights, audit)" -ForegroundColor Gray
                        Write-Host "    - 23 Advanced audit policies" -ForegroundColor Gray
                        Write-Host "    - VBS + Credential Guard* + Memory Integrity (*Ent/Edu only)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: Microsoft enterprise-baseline security, may break legacy software" -ForegroundColor Yellow
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
                        Write-Host "    - Choose provider: Quad9 (default), Cloudflare, or AdGuard" -ForegroundColor Gray
                        Write-Host "    - Enable DoH encryption (HTTPS)" -ForegroundColor Gray
                        Write-Host "    - Blocks DNS hijacking and snooping" -ForegroundColor Gray
                        Write-Host "    - IPv4 + IPv6 configuration" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll choose provider and DoH mode interactively" -ForegroundColor Yellow
                    }
                    "Privacy" {
                        Write-Host "Telemetry & Privacy Hardening" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies privacy settings based on selected mode:" -ForegroundColor Gray
                        Write-Host "    - Telemetry control (3 modes: MSRecommended/Strict/Paranoid)" -ForegroundColor Gray
                        Write-Host "    - MSRecommended: 63 declared (36 base + 27 Tier 1 decision targets)" -ForegroundColor DarkGray
                        Write-Host "    - Strict: 88 declared; Paranoid: 117 declared (including the same 27 Tier 1 targets)" -ForegroundColor DarkGray
                        Write-Host "    - Disable ads, tips, personalization" -ForegroundColor Gray
                        Write-Host "    - Tier 1: exact policy-state BAVR; removed apps/data are not restored" -ForegroundColor Gray
                        Write-Host "      Default No = NotChecked; unsupported/managed = NotApplicable" -ForegroundColor Gray
                        Write-Host "    - Tier 2: sealed per-user removal inventory; reinstall is separate and explicitly non-exact" -ForegroundColor Gray
                        Write-Host "    - OneDrive hardening (keeps sync functional)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: Mode and both destructive app-removal choices are prompted separately" -ForegroundColor Yellow
                    }
                    "AntiAI" {
                        Write-Host "Disable Windows 11 AI Features" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Configures 43 registry targets plus 4 URI checks across 12 reversible groups:" -ForegroundColor Gray
                        Write-Host "    - Windows Recall + Export Block" -ForegroundColor Gray
                        Write-Host "    - Windows Copilot compatibility controls, URI handlers, Edge AI" -ForegroundColor Gray
                        Write-Host "    - Click to Do" -ForegroundColor Gray
                        Write-Host "    - Paint AI (3), Notepad AI, Settings Agent" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: Declared controls applied; effectiveness varies by build/edition/app; reboot required" -ForegroundColor Yellow
                    }
                    "EdgeHardening" {
                        Write-Host "Microsoft Edge v139 Security Baseline" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies Edge security policies:" -ForegroundColor Gray
                        Write-Host "    - SmartScreen + PUA, site isolation and browser-process mitigations" -ForegroundColor Gray
                        Write-Host "    - Site Isolation + SSL/TLS hardening" -ForegroundColor Gray
                        Write-Host "    - Tracking Prevention + Privacy settings" -ForegroundColor Gray
                        Write-Host "    - Extension blocklist (MS baseline; allowed by default, opt-in block)" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Impact: Strong Edge security; extensions ALLOWED by default (opt-in block via prompt)" -ForegroundColor Yellow
                    }
                    "AdvancedSecurity" {
                        Write-Host "Advanced Security Hardening (Beyond MS Baseline)" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  > Applies 14 security features (60 declared checks at maximum selected scope):" -ForegroundColor Gray
                        Write-Host "    - RDP hardening + optional complete disable" -ForegroundColor Gray
                        Write-Host "    - Admin Shares disable (domain-aware)" -ForegroundColor Gray
                        Write-Host "    - Risky ports/services block (LLMNR, NetBIOS, UPnP)" -ForegroundColor Gray
                        Write-Host "    - Legacy TLS 1.0/1.1 disable and WPAD disable" -ForegroundColor Gray
                        Write-Host "    - Legacy SRP .lnk path-rule registry state (runtime not asserted)" -ForegroundColor Gray
                        Write-Host "    - Windows Update (2 policy values + 1 Windows Settings preference)" -ForegroundColor Gray
                        Write-Host "    - Wireless Display (Miracast) security" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "  Note: You'll choose profile (Balanced/Enterprise/Maximum)" -ForegroundColor Yellow
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
                    Write-Host "Continue with ${moduleName}? [Y/N/A] (default: Y): " -ForegroundColor Yellow -NoNewline
                    $response = Read-Host
                    if ([string]::IsNullOrWhiteSpace($response)) { $response = "Y" }
                    $response = $response.ToUpperInvariant()

                    if ($response -notin @('Y', 'N', 'A', 'YES', 'NO', 'ABORT')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y, N, or A." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($response -notin @('Y', 'N', 'A', 'YES', 'NO', 'ABORT'))

                if ($response -in @('A', 'ABORT')) {
                    Write-Log -Level WARNING -Message "User aborted execution at module: $moduleName" -Module "Framework"
                    Write-Host ""
                    Write-Host "Execution aborted by user" -ForegroundColor Red
                    Write-Host ""
                    $results.Warnings += "Execution aborted by user at module: $moduleName"
                    $results.Success = $false
                    $results.Status = 'Aborted'
                    $results.Aborted = $true
                    break
                }
                elseif ($response -in @('N', 'NO')) {
                    Write-Log -Level INFO -Message "User skipped module: $moduleName" -Module "Framework"
                    Write-Host ""
                    Write-Host "Skipping module: $moduleName" -ForegroundColor Yellow
                    Write-Host ""
                    $results.ModulesSkipped++
                    $results.Success = $false
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
                Write-Log -Level ERROR -Message $errMsg -Module "Framework"
                $results.Errors += $errMsg
                $results.ModuleResults += New-NoIDFailedModuleRecord -ModuleName $moduleName
                $results.ModulesExecuted++
                $results.ModulesFailed++
                $results.Success = $false
                continue
            }

            # Check module implementation status (FIX #2)
            $moduleConfig = $script:Config.modules.$moduleName
            if ($moduleConfig.PSObject.Properties.Name -contains 'status') {
                if ($moduleConfig.status -ne 'IMPLEMENTED') {
                    Write-Log -Level WARNING -Message "Skipping module '$moduleName' - Status: $($moduleConfig.status) (not IMPLEMENTED)" -Module "Framework"
                    Write-Host "  [SKIP] $moduleName - Not yet implemented" -ForegroundColor Yellow
                    $results.ModulesSkipped++
                    $results.Success = $false
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)

                        # DNS module handles provider selection
                        # ONLY pass config values in NonInteractive mode (GUI)
                        # In interactive mode, let the module prompt the user!
                        if (Test-NonInteractiveMode) {
                            # GUI mode - use config values
                            $moduleResult = Invoke-DNSConfiguration -Provider $script:Config.modules.DNS.provider -DryRun:$DryRun
                        }
                        else {
                            # Interactive CLI mode - module will ask for provider and DoH mode
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)

                        # Privacy module handles mode selection
                        # ONLY pass config values in NonInteractive mode (GUI)
                        if (Test-NonInteractiveMode) {
                            # GUI mode - use config values
                            $privacyArgs = @{ DryRun = $DryRun }

                            if ($script:Config.modules.Privacy.PSObject.Properties.Name -contains 'mode' -and $script:Config.modules.Privacy.mode) {
                                Write-Log -Level INFO -Message "Privacy mode: $($script:Config.modules.Privacy.mode)" -Module "Privacy"
                                $privacyArgs["Mode"] = $script:Config.modules.Privacy.mode
                            }

                            $moduleResult = Invoke-PrivacyHardening @privacyArgs
                        }
                        else {
                            # Interactive CLI mode - module will ask for mode selection
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)

                        # AntiAI has one canonical reversible target inventory (no modes).
                        Write-Log -Level INFO -Message "Applying 43 reversible AntiAI registry targets plus four URI source controls across 12 groups" -Module "AntiAI"
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)

                        # EdgeHardening applies Microsoft Edge security baseline
                        Write-Log -Level INFO -Message "Applying Edge profile: 19 Microsoft v139 baseline values plus 7 explicit privacy additions; extension block-all is optional" -Module "EdgeHardening"
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
                        Initialize-NoIDModuleDependencyBridge -ImportedModule (Get-Module -Name $moduleName -ErrorAction Stop)

                        # AdvancedSecurity handles profile selection
                        # ONLY pass config values in NonInteractive mode (GUI)
                        if (Test-NonInteractiveMode) {
                            # GUI mode - use config values (securityProfile)
                            $secProfile = $script:Config.modules.AdvancedSecurity.securityProfile
                            if ($secProfile) {
                                Write-Log -Level INFO -Message "AdvancedSecurity profile: $secProfile" -Module "AdvancedSecurity"
                                $moduleResult = Invoke-AdvancedSecurity -SecurityProfile $secProfile -DryRun:$DryRun
                            }
                            else {
                                $moduleResult = Invoke-AdvancedSecurity -DryRun:$DryRun
                            }
                        }
                        else {
                            # Interactive CLI mode - module will ask for profile
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

            # Store and validate the module result. A module that returns while
            # its backup is still active never reached the sealed Backup gate.
            if ($null -ne $moduleResult) {
                # Exactly one structured result is valid; silently choosing the last
                # object can turn pipeline contamination into a false success.
                if ($moduleResult -is [array]) {
                    throw "Module '$moduleName' returned $($moduleResult.Count) pipeline objects instead of exactly one result"
                }

                if ($moduleResult -is [PSCustomObject] -and -not $moduleResult.PSObject.Properties['ModuleName']) {
                    $moduleResult | Add-Member -NotePropertyName ModuleName -NotePropertyValue $moduleName
                }

                $appliedSettingsCount = 0
                if (-not $DryRun -and $moduleResult -is [PSCustomObject]) {
                    $appliedSettingsCount = switch ($moduleName) {
                        'SecurityBaseline' { if ($moduleResult.PSObject.Properties['SettingsApplied']) { [int]$moduleResult.SettingsApplied } else { 0 }; break }
                        'ASR'              { if ($moduleResult.PSObject.Properties['RulesApplied']) { [int]$moduleResult.RulesApplied } else { 0 }; break }
                        'DNS'              { if ($moduleResult.PSObject.Properties['ChecksApplied']) { [int]$moduleResult.ChecksApplied } else { 0 }; break }
                        'Privacy'          { if ($moduleResult.PSObject.Properties['Verified']) { [int]$moduleResult.Verified } else { 0 }; break }
                        'AntiAI'           {
                            $registryCount = if ($moduleResult.PSObject.Properties['AppliedPolicyTargets']) { [int]$moduleResult.AppliedPolicyTargets } else { 0 }
                            $uriCount = if ($moduleResult.PSObject.Properties['UriSourceChecksApplied']) { [int]$moduleResult.UriSourceChecksApplied } else { 0 }
                            $registryCount + $uriCount
                            break
                        }
                        'EdgeHardening'    { if ($moduleResult.PSObject.Properties['PoliciesApplied']) { [int]$moduleResult.PoliciesApplied } else { 0 }; break }
                        'AdvancedSecurity' { if ($moduleResult.PSObject.Properties['SettingsApplied']) { [int]$moduleResult.SettingsApplied } else { 0 }; break }
                        default            { 0 }
                    }
                }
                if ($moduleResult -is [PSCustomObject]) {
                    $moduleResult | Add-Member -NotePropertyName AppliedSettingsCount -NotePropertyValue $appliedSettingsCount -Force
                }
                $results.TotalSettingsApplied += $appliedSettingsCount
                $results.ModuleResults += $moduleResult
                $results.ModulesExecuted++

                # Every production module uses the structured result contract.
                # Treat legacy Boolean output as an unsupported type so the
                # framework and the exported GUI contract cannot disagree.
                $success = $false
                $unexpectedResultMessage = $null

                if ($moduleResult -is [bool]) {
                    $unexpectedResultMessage = "Module '$moduleName' returned an unsupported Boolean result instead of the structured module contract"
                    Write-Log -Level WARNING -Message $unexpectedResultMessage -Module 'Framework'
                }
                elseif ($moduleResult -is [PSCustomObject]) {
                    # Module returned object with Success property (e.g., ASR, DNS modules)
                    $hasSuccess = $null -ne ($moduleResult.PSObject.Properties | Where-Object { $_.Name -eq 'Success' })
                    $success = if ($hasSuccess) { [bool]$moduleResult.Success } else { $false }
                }
                else {
                    $unexpectedResultMessage = "Module '$moduleName' returned unexpected type: $($moduleResult.GetType().Name)"
                    Write-Log -Level WARNING -Message $unexpectedResultMessage -Module 'Framework'
                }

                if (-not $DryRun -and -not [string]::IsNullOrWhiteSpace([string]$global:CurrentModule)) {
                    $activeBackupModule = [string]$global:CurrentModule
                    try {
                        if ($activeBackupModule -eq $moduleName) {
                            if (-not (Save-IncompleteModuleBackup -ModuleName $moduleName -Confirm:$false)) {
                                $results.Errors += "Incomplete backup retention/classification failed for module '$moduleName'"
                            }
                        }
                        else {
                            if (-not (Save-IncompleteModuleBackup `
                                    -ModuleName $activeBackupModule `
                                    -Confirm:$false)) {
                                $results.Errors += "Incomplete foreign backup retention/classification failed for module '$activeBackupModule'"
                            }
                            $results.Errors += "Module '$moduleName' returned with a different unsealed backup active: '$activeBackupModule'"
                        }
                    }
                    catch {
                        $retentionError = "Incomplete backup retention/classification threw for module '$activeBackupModule': $($_.Exception.Message)"
                        $results.Errors += $retentionError
                        Write-Log -Level ERROR -Message $retentionError -Module 'Framework'
                    }
                    $results.Errors += "Module '$moduleName' returned before sealing its backup; Apply cannot be trusted"
                    $success = $false
                }

                $moduleWasSkipped = ($moduleResult -is [PSCustomObject] -and
                    $moduleResult.PSObject.Properties['Status'] -and
                    [string]$moduleResult.Status -eq 'Skipped')
                if ($moduleWasSkipped) {
                    $results.ModulesSkipped++
                    $results.Success = $false
                    Write-Log -Level INFO -Message "Module '$moduleName' was explicitly skipped; no settings counted as applied" -Module 'Framework'
                }
                elseif ($success) {
                    Write-Log -Level SUCCESS -Message "Module '$moduleName' completed successfully" -Module "Framework"
                }
                else {
                    Write-Log -Level WARNING -Message "Module '$moduleName' completed with errors" -Module "Framework"
                    $results.ModulesFailed++
                    $results.Success = $false

                    # Preserve the error contracts already returned by modules.
                    # Some modules expose Errors[], while older structured paths
                    # use Error or ErrorMessage. Do not discard a concrete root
                    # cause and replace it with the generic fallback.
                    $moduleErrorDetailAdded = $false
                    if ($moduleResult -is [PSCustomObject]) {
                        $hasErrors = $null -ne ($moduleResult.PSObject.Properties | Where-Object { $_.Name -eq 'Errors' })
                        if ($hasErrors) {
                            foreach ($moduleError in @($moduleResult.Errors)) {
                                if (-not [string]::IsNullOrWhiteSpace([string]$moduleError)) {
                                    $results.Errors += [string]$moduleError
                                    $moduleErrorDetailAdded = $true
                                }
                            }
                        }
                        foreach ($errorPropertyName in @('Error', 'ErrorMessage')) {
                            $errorProperty = $moduleResult.PSObject.Properties[$errorPropertyName]
                            if ($errorProperty -and
                                -not [string]::IsNullOrWhiteSpace([string]$errorProperty.Value)) {
                                $results.Errors += "Module '$moduleName': $([string]$errorProperty.Value)"
                                $moduleErrorDetailAdded = $true
                            }
                        }
                    }
                    if (-not $moduleErrorDetailAdded) {
                        $results.Errors += if ($unexpectedResultMessage) {
                            $unexpectedResultMessage
                        }
                        else {
                            "Module '$moduleName' reported failure without an error detail"
                        }
                    }
                }

                # Keep the exported per-module machine contract aligned with
                # framework-level fail-closed decisions (for example, a module
                # returned success while leaving an unsealed backup active).
                if ($moduleResult -is [PSCustomObject]) {
                    $moduleResult | Add-Member -NotePropertyName Success -NotePropertyValue ([bool]$success) -Force
                    if ($moduleWasSkipped) {
                        $moduleResult | Add-Member -NotePropertyName Status -NotePropertyValue 'Skipped' -Force
                    }
                    elseif ($success) {
                        $moduleResult | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($DryRun) { 'DryRun' } else { 'Success' }) -Force
                    }
                    else {
                        $moduleResult | Add-Member -NotePropertyName Status -NotePropertyValue 'Failed' -Force
                    }
                }

                # Always collect warnings from modules (regardless of success)
                # Warnings are informational (e.g., "rule set to AUDIT mode") - not errors
                if ($moduleResult -is [PSCustomObject]) {
                    $hasWarnings = $null -ne ($moduleResult.PSObject.Properties | Where-Object { $_.Name -eq 'Warnings' })
                    if ($hasWarnings -and @($moduleResult.Warnings).Count -gt 0) {
                        $results.Warnings += @($moduleResult.Warnings)
                    }
                }
            }
            else {
                if (-not $DryRun -and -not [string]::IsNullOrWhiteSpace([string]$global:CurrentModule)) {
                    $activeBackupModule = [string]$global:CurrentModule
                    try {
                        if (-not (Save-IncompleteModuleBackup -ModuleName $activeBackupModule -Confirm:$false)) {
                            $results.Errors += "Incomplete backup retention/classification failed for module '$activeBackupModule'"
                        }
                    }
                    catch {
                        $retentionError = "Incomplete backup retention/classification threw for module '$activeBackupModule': $($_.Exception.Message)"
                        $results.Errors += $retentionError
                        Write-Log -Level ERROR -Message $retentionError -Module 'Framework'
                    }
                    if ($activeBackupModule -cne $moduleName) {
                        $results.Errors += "Module '$moduleName' returned no result with a different unsealed backup active: '$activeBackupModule'"
                    }
                }
                $results.ModuleResults += New-NoIDFailedModuleRecord -ModuleName $moduleName
                # The wrapper reconciles modules.Count against modulesExecuted:
                # a record without the matching count is rejected just as hard
                # as a count without a record.
                $results.ModulesExecuted++
                $results.ModulesFailed++
                $results.Success = $false
                $results.Errors += "Module '$moduleName' returned no result"
            }
        }
        catch {
            $moduleExecutionError = $_
            if (-not $DryRun -and -not [string]::IsNullOrWhiteSpace([string]$global:CurrentModule)) {
                $activeBackupModule = [string]$global:CurrentModule
                try {
                    if (-not (Save-IncompleteModuleBackup -ModuleName $activeBackupModule -Confirm:$false)) {
                        $results.Errors += "Incomplete backup retention/classification failed for module '$activeBackupModule'"
                    }
                }
                catch {
                    $retentionError = "Incomplete backup retention/classification threw for module '$activeBackupModule': $($_.Exception.Message)"
                    $results.Errors += $retentionError
                    Write-Log -Level ERROR -Message $retentionError -Module 'Framework'
                }
                if ($activeBackupModule -cne $moduleName) {
                    $results.Errors += "Module '$moduleName' threw with a different unsealed backup active: '$activeBackupModule'"
                }
            }
            Write-ErrorLog -Message "Failed to execute module '$moduleName'" -Module "Framework" -ErrorRecord $moduleExecutionError
            $errMsg = "Module '$moduleName' execution failed: $($moduleExecutionError.Exception.Message)"
            $results.Errors += $errMsg
            $results.ModuleResults += New-NoIDFailedModuleRecord -ModuleName $moduleName
            # Same reconciliation as above: record and executed-count travel
            # together or the wrapper rejects the whole payload.
            $results.ModulesExecuted++
            $results.ModulesFailed++
            $results.Success = $false
        }
    }

    # Calculate duration
    $results.Duration = (Get-Date) - $startTime

    # Update session display name for backup identification (after all modules complete)
    if (-not $DryRun) {
        try {
            Update-SessionDisplayName
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to finalize session metadata: $_" -Module "Framework"
            $results.Errors += "Session metadata finalization failed: $($_.Exception.Message)"
            $results.Success = $false
        }
    }

    $applySucceeded = ($results.Errors.Count -eq 0 -and
        $results.ModulesFailed -eq 0 -and
        -not $results.Aborted -and
        $results.ModulesExecuted -gt 0 -and
        $results.ModulesSkipped -eq 0)
    # Persist every successfully applied module and every explicit no-mutation
    # DNS KEEP decision, even if another requested module was skipped or
    # failed. A partial run must not erase the authoritative intent for the
    # scopes whose live state was actually changed or deliberately preserved.
    if (-not $DryRun -and @($results.ModuleResults).Count -gt 0) {
        try {
            $intentPath = Write-NoIDApplyIntentState `
                -ModuleResults @($results.ModuleResults) `
                -SessionPath ([string]$global:BackupBasePath)
            if (-not [string]::IsNullOrWhiteSpace([string]$intentPath)) {
                Write-Log -Level SUCCESS -Message "Durable Apply intent recorded: $intentPath" -Module 'Framework'
            }
        }
        catch {
            $results.Errors += "Durable Apply-intent recording failed: $($_.Exception.Message)"
            $applySucceeded = $false
            Write-ErrorLog -Message 'Successful mutations could not be bound to durable Apply intent' -Module 'Framework' -ErrorRecord $_
        }
    }
    $results.Success = $applySucceeded
    $results.Status = if ($results.Success) { 'Success' }
        elseif ($results.Aborted) { 'Aborted' }
        elseif ($results.ModulesExecuted -eq 0 -and $results.ModulesSkipped -gt 0) { 'Skipped' }
        else { 'Failed' }
    $results.BackupPath = if (-not $DryRun -and $global:BackupBasePath) {
        [System.IO.Path]::GetFullPath([string]$global:BackupBasePath)
    }
    else { '' }

    & $updateWarningLogCount
    Write-Log -Level INFO -Message "Hardening execution completed - Modules: $($results.ModulesExecuted), Errors: $($results.Errors.Count), Warnings: $($results.WarningsLogged)" -Module "Framework"

        return $results
    }
    finally {
        if ($mutationMutexHeld) {
            try { $mutationMutex.ReleaseMutex() }
            catch {
                Write-Verbose "Mutation mutex release failed: $($_.Exception.Message)"
            }
        }
        if ($mutationMutex) {
            $mutationMutex.Dispose()
        }
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
