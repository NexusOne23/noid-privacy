<#
.SYNOPSIS
    Apply the Windows-client-applicable subset of 19 declared Defender ASR rules

.DESCRIPTION
    Declares all 19 current Defender ASR rule identities. Microsoft documents
    the Webshell rule as Exchange-server-only, so Windows 11 applies/verifies
    18 rules and reports that one rule NotApplicable.

    Rules Applied:
    - 18 Windows-client-applicable rules
    - One Exchange-server-only rule reported NotApplicable
    - Upgrades 1 rule from Audit to Block (PSExec/WMI - with SCCM check)

    Features:
    - SCCM/Configuration Manager detection (PSExec/WMI rule warning)
    - Cloud protection verification
    - BACKUP/APPLY/VERIFY/RESTORE pattern
    - DryRun mode for testing
    - Security Baseline overlap detection

.PARAMETER DryRun
    Preview changes without applying them

.PARAMETER Force
    Apply even if validation warnings occur (SCCM, Cloud Protection)

.PARAMETER AllowPSExecWMI
    Force enable PSExec/WMI rule even if SCCM detected (use with caution)

.EXAMPLE
    Invoke-ASRRules
    Apply all Windows-client-applicable rules with full backup and verification

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
                # Public -> ASR -> Modules -> framework root (where Core\ and Utils\ live).
                $frameworkRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
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
            Status                 = 'Running'
            RulesApplied           = 0
            RulesPreviewed         = 0
            RulesSkipped           = 0
            RulesNotApplicable     = 0
            Errors                 = @()
            Warnings               = @()
            BackupCreated          = $false
            VerificationPassed     = $null
            ConfigMgrDetected      = $false
            ConfigMgrDetectionSucceeded = $false
            CloudProtectionEnabled = $false
            Duration               = $null
            Details                = @{
                TotalRules   = 19
                Applicable   = 0
                NotApplicable = 0
                BlockMode    = 0
                AuditMode    = 0
                DisabledMode = 0
                RequestedActions = @()
            }
        }

        Write-Log -Level INFO -Message 'Starting ASR rules application (19 declared rules; Windows-client applicability is evaluated before backup)' -Module $moduleName

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

            if (-not (Test-WindowsVersion -MinimumBuild 26100)) {
                throw "Windows 11 24H2 (Build 26100) or later required"
            }

            # Applicability is independent of Defender authority and must be
            # accounted even when the Defender-specific module is skipped.
            Write-Log -Level INFO -Message "Loading ASR rule definitions..." -Module $moduleName
            $asrRules = Get-ASRRuleDefinitions
            $asrPlan = Get-ASRApplicabilityPlan -Rules $asrRules
            $applicableAsrRules = @($asrPlan.Applicable)
            $notApplicableAsrRules = @($asrPlan.NotApplicable)
            $result.RulesNotApplicable = [int]$asrPlan.NotApplicableCount
            $result.Details.Applicable = [int]$asrPlan.ApplicableCount
            $result.Details.NotApplicable = [int]$asrPlan.NotApplicableCount
            if ([int]$asrPlan.DeclaredCount -ne [int]$result.Details.TotalRules) {
                throw "ASR applicability count mismatch: declared=$($asrPlan.DeclaredCount), expected=$($result.Details.TotalRules)"
            }
            foreach ($entry in $notApplicableAsrRules) {
                Write-Log -Level INFO -Message "ASR NotApplicable on Windows client: $($entry.Name) -- $($entry.Reason)" -Module $moduleName
            }

            # Check for third-party security products (AV or EDR/XDR)
            # This must happen BEFORE the Defender service check because:
            # - Some endpoint products stop WinDefend entirely (typically Security-Center-registered AV)
            # - Others put WinDefend into Passive Mode (typically enterprise EDR/XDR like CrowdStrike, SentinelOne)
            # - In both cases, ASR rules are not enforceable by NoID Privacy (ASR is a Defender-only API)
            if (-not (Get-Command Test-ThirdPartySecurityProduct -ErrorAction SilentlyContinue)) {
                # Standalone module execution: dot-source Utils/Dependencies.ps1 from project root
                $utilsDepsPath = Join-Path $PSScriptRoot "..\..\..\Utils\Dependencies.ps1"
                if (Test-Path -LiteralPath $utilsDepsPath) {
                    . $utilsDepsPath
                }
            }

            $securityProduct = if (Get-Command Test-ThirdPartySecurityProduct -ErrorAction SilentlyContinue) {
                Test-ThirdPartySecurityProduct
            }
            else {
                # Dependencies.ps1 unavailable: product identity is unknown.
                # The independent Defender authority gate below remains decisive.
                Write-Log -Level WARNING -Message "Utils/Dependencies.ps1 not available; cannot detect third-party security products" -Module $moduleName
                [PSCustomObject]@{
                    Detected            = $false
                    ProductName         = $null
                    DetectionMethod     = $null
                    DefenderPassiveMode = $false
                }
            }

            # Product registration alone does not establish enforcement
            # authority. Defender must positively report active primary mode;
            # query failure or any non-Normal mode is an honest skip.
            $defenderAuthority = $null
            try {
                $defenderAuthority = Get-MpComputerStatus -ErrorAction Stop
            }
            catch {
                $result.Status = 'Skipped'
                $result.RulesSkipped = [int]$result.Details.Applicable
                $result.Warnings += "ASR skipped: Defender enforcement authority could not be established: $($_.Exception.Message)"
                Write-Log -Level WARNING -Message $result.Warnings[-1] -Module $moduleName
                # The end block is the single output gate. Emitting the result
                # here as well would return two pipeline objects to Framework.
                return
            }
            $defenderIsPrimary = (
                [string]$defenderAuthority.AMRunningMode -eq 'Normal' -and
                [bool]$defenderAuthority.AntivirusEnabled -and
                [bool]$defenderAuthority.RealTimeProtectionEnabled
            )

            if (-not $defenderIsPrimary) {
                $avName = if ($securityProduct.ProductName) {
                    [string]$securityProduct.ProductName
                }
                else {
                    "Defender mode '$([string]$defenderAuthority.AMRunningMode)'"
                }
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  ASR Module Skipped" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Defender is not proven as the active primary engine: $avName" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "ASR (Attack Surface Reduction) is a Microsoft-Defender-specific API and" -ForegroundColor Yellow
                Write-Host "cannot be configured by NoID Privacy when Defender is not the primary engine." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "If another endpoint product is primary, it may provide its own attack-surface" -ForegroundColor Gray
                Write-Host "reduction features. NoID Privacy has not verified equivalent protection; consult the" -ForegroundColor Gray
                Write-Host "product's documentation or management console before relying on it." -ForegroundColor Gray
                Write-Host ""
                Write-Host "ASR is skipped and reported as unverified." -ForegroundColor Yellow
                Write-Host ""

                Write-Log -Level WARNING -Message "ASR skipped: Defender primary enforcement was not established ($avName; mode=$($defenderAuthority.AMRunningMode)). NoID Privacy cannot verify equivalent third-party coverage." -Module $moduleName

                $result.Success = $false
                $result.Status = 'Skipped'
                $result.Warnings += "ASR skipped: Defender is not the proven primary engine ($avName). Equivalent third-party attack-surface reduction was not verified."
                $result.RulesApplied = 0
                $result.RulesSkipped = [int]$result.Details.Applicable

                # The end block is the single output gate. Emitting the result
                # here as well would return two pipeline objects to Framework.
                return
            }
            if ($securityProduct.Detected) {
                Write-Log -Level INFO -Message "Third-party product registration detected ($($securityProduct.ProductName)), but Defender explicitly reports active primary enforcement; ASR remains applicable" -Module $moduleName
            }

            # Re-query immediately before continuing so authority drift cannot
            # hide behind the earlier detection result.
            $defenderService = Get-Service -Name 'WinDefend' -ErrorAction Stop
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
            if ([string]$defenderStatus.AMRunningMode -ne 'Normal') {
                $result.Status = 'Skipped'
                $result.RulesSkipped = [int]$result.Details.Applicable
                $result.Warnings += "ASR skipped: Defender reports '$($defenderStatus.AMRunningMode)' and is not the active enforcement engine"
                # The end block is the single output gate. Emitting the result
                # here as well would return two pipeline objects to Framework.
                return
            }
            if ($defenderService.Status -ne 'Running' -or
                -not [bool]$defenderStatus.AntivirusEnabled -or
                -not [bool]$defenderStatus.RealTimeProtectionEnabled) {
                throw 'Microsoft Defender Antivirus and real-time protection must be active before ASR rules can be enforced'
            }

            # Step 2: Check for Remote Management Tools (SCCM/Intune/etc.)
            Write-Log -Level INFO -Message "Checking for remote management tools..." -Module $moduleName

            # Automatic detection
            $configMgrDetectionResult = Test-ConfigMgrPresence
            $configMgrDetectionSucceeded = $null -ne $configMgrDetectionResult
            $configMgrDetected = $configMgrDetectionSucceeded -and [bool]$configMgrDetectionResult
            $result.ConfigMgrDetected = $configMgrDetected
            $result.ConfigMgrDetectionSucceeded = $configMgrDetectionSucceeded

            # Check for management tools - NonInteractive or Interactive
            $usesManagementTools = $false

            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $usesManagementTools = Get-NonInteractiveValue -Module "ASR" -Key "usesManagementTools" -Required
                if (-not $configMgrDetectionSucceeded) {
                    $detectionWarning = "ConfigMgr presence could not be inspected; the explicit usesManagementTools=$usesManagementTools decision is authoritative and automatic detection did not override it"
                    $result.Warnings += $detectionWarning
                    Write-Log -Level WARNING -Message $detectionWarning -Module $moduleName
                }
            }
            elseif (-not $Force -and -not $AllowPSExecWMI -and -not $DryRun) {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  Remote Management Tool Check" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""

                if ($configMgrDetected) {
                    Write-Host "DETECTED: SCCM/Configuration Manager is currently installed" -ForegroundColor Yellow
                    Write-Host ""
                }
                elseif (-not $configMgrDetectionSucceeded) {
                    Write-Host "ConfigMgr presence could not be inspected; your explicit answer below is authoritative." -ForegroundColor Yellow
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
                Write-Host "  [N] No  - I don't use any of these (default)" -ForegroundColor Green
                Write-Host "      - ALL 18 Windows-client-applicable rules: BLOCK mode" -ForegroundColor Gray
                Write-Host "      - 1 Exchange-server rule: NotApplicable" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] Yes - I use management tools" -ForegroundColor Cyan
                Write-Host "      - 1 rule: AUDIT mode (PSExec/WMI only)" -ForegroundColor Gray
                Write-Host "      - 17 applicable rules: BLOCK mode" -ForegroundColor Gray
                Write-Host "      - 1 Exchange-server rule: NotApplicable" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $choice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "N" }
                    $choice = $choice.ToUpperInvariant()

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
                        Write-Host "1 applicable rule set to AUDIT (PSExec/WMI), 17 set to BLOCK" -ForegroundColor Yellow
                        Write-Log -Level INFO -Message "User confirmed use of management tools - 1 AUDIT + 17 BLOCK + 1 NotApplicable" -Module $moduleName
                    }
                    "N" {
                        $usesManagementTools = $false
                        Write-Host ""
                        if ($configMgrDetected) {
                            # SCCM detection overrides the user's N answer below; the
                            # confirmation must reflect the state that is actually applied.
                            Write-Host "SCCM was detected on this host: PSExec/WMI stays AUDIT, all other applicable rules BLOCK (except the New/Unknown Software rule you choose next)" -ForegroundColor Yellow
                            Write-Log -Level INFO -Message "User confirmed no management tools, but SCCM was detected - PSExec/WMI forced to AUDIT: 1 AUDIT + 17 BLOCK + 1 NotApplicable" -Module $moduleName
                        }
                        else {
                            Write-Host "All applicable rules will BLOCK, except the New/Unknown Software rule you choose next" -ForegroundColor Green
                            Write-Log -Level INFO -Message "User confirmed no management tools - 18 BLOCK + 1 NotApplicable" -Module $moduleName
                        }
                    }
                }
                Write-Host ""
            }
            elseif ($Force -and -not $AllowPSExecWMI) {
                # Force can use a positive/negative inspection result, but an
                # inspection failure is not a decision and must not silently
                # weaken or strengthen the rule.
                if (-not $configMgrDetectionSucceeded) {
                    throw 'ConfigMgr presence could not be determined in Force mode; specify -AllowPSExecWMI or run interactively'
                }
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
            if (Test-NonInteractiveMode) {
                $effectiveManagementRule = if ($usesManagementTools -or $configMgrDetected) {
                    'AUDIT for WMI/PSExec compatibility'
                }
                else {
                    'BLOCK; other rules keep their own applicability/mode decisions'
                }
                Write-NonInteractiveDecision -Module $moduleName -Decision 'Management tools rule' -Value $effectiveManagementRule
            }

            # Step 2b: Prevalence rule (new/unknown software) - NonInteractive or Interactive
            $prevalenceRule = $asrRules | Where-Object { $_.GUID -eq "01443614-cd74-433a-b99e-2ecdc07bfc25" }
            if ($prevalenceRule) {
                $allowNewSoftware = $true

                if (Test-NonInteractiveMode) {
                    # NonInteractive mode (GUI) - use config value
                    $allowNewSoftware = Get-NonInteractiveValue -Module "ASR" -Key "allowNewSoftware" -Required

                    if ($allowNewSoftware) {
                        $prevalenceRule.Action = 2
                        Write-Log -Level INFO -Message "ASR prevalence rule set to AUDIT (default; events are logged, new software remains installable)" -Module $moduleName
                    } else {
                        $prevalenceRule.Action = 1
                    }
                    Write-NonInteractiveDecision -Module $moduleName -Decision "New/Unknown software rule" -Value $(if ($allowNewSoftware) { "AUDIT (allow)" } else { "BLOCK (secure)" })
                }
                elseif (-not $DryRun) {
                    Write-Host ""
                    Write-Host "===================================================================" -ForegroundColor Cyan
                    Write-Host "  ASR Rule: New / Unknown Software" -ForegroundColor Cyan
                    Write-Host "===================================================================" -ForegroundColor Cyan
                    Write-Host ""

                    Write-Host "Rule: Block executable files unless they meet prevalence, age, or trusted list" -ForegroundColor White
                    Write-Host "GUID: $($prevalenceRule.GUID)" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "This rule blocks very new or unknown executables that" -ForegroundColor Yellow
                    Write-Host "are not yet trusted by Microsoft's reputation systems." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Do you install NEW software frequently?" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  - Games from independent developers" -ForegroundColor Gray
                    Write-Host "  - Beta software / Early access programs" -ForegroundColor Gray
                    Write-Host "  - Custom/in-house business applications" -ForegroundColor Gray
                    Write-Host "  - Open-source tools without Microsoft reputation" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "Options:" -ForegroundColor Cyan
                    Write-Host "  [Y] Yes - I install new software at least occasionally (default)" -ForegroundColor Green
                    Write-Host "      - AUDIT mode: Events logged, installs allowed" -ForegroundColor Gray
                    Write-Host "      - Recommended for most users (indie games, betas, new tools)" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [N] No  - I rarely install new software" -ForegroundColor Cyan
                    Write-Host "      - BLOCK mode: Maximum security" -ForegroundColor Gray
                    Write-Host "      - New/unknown installers may be blocked" -ForegroundColor Gray
                    Write-Host ""

                    do {
                        Write-Host "Your choice [Y/N] (default: Y): " -ForegroundColor Yellow -NoNewline
                        $prevalenceChoice = Read-Host
                        if ([string]::IsNullOrWhiteSpace($prevalenceChoice)) { $prevalenceChoice = "Y" }
                        $prevalenceChoice = $prevalenceChoice.ToUpperInvariant()

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
                            Write-Log -Level INFO -Message "Prevalence rule configured to BLOCK (maximum security)" -Module $moduleName
                        }
                        "Y" {
                            $prevalenceRule.Action = 2
                            Write-Host ""
                            Write-Host "New/Unknown Software rule set to AUDIT mode (events logged, installs allowed)" -ForegroundColor Green
                            Write-Log -Level INFO -Message "Prevalence rule configured to AUDIT (default; events are logged, new software remains installable)" -Module $moduleName
                        }
                    }
                    Write-Host ""
                }
                else {
                    $prevalenceRule.Action = 2
                    Write-Log -Level INFO -Message 'DryRun interactive default: prevalence rule = AUDIT' -Module $moduleName
                }
            }

            # Step 3: Check cloud protection
            Write-Log -Level INFO -Message "Checking cloud-delivered protection..." -Module $moduleName

            $cloudProtectionEnabled = Test-CloudProtection
            $result.CloudProtectionEnabled = $cloudProtectionEnabled

            if (-not $cloudProtectionEnabled) {
                $cloudRules = $applicableAsrRules | Where-Object { $_.RequiresCloudProtection -eq $true }
                $result.Warnings += "Cloud protection disabled: $($cloudRules.Count) rules require it for optimal operation"
                Write-Log -Level WARNING -Message "$($cloudRules.Count) ASR rules require cloud protection for full functionality" -Module $moduleName

                if (Test-NonInteractiveMode) {
                    # NonInteractive mode (GUI) - use config value
                    $continueWithoutCloud = Get-NonInteractiveValue -Module "ASR" -Key "continueWithoutCloud" -Required

                    if (-not $continueWithoutCloud) {
                        Write-NonInteractiveDecision -Module $moduleName -Decision "Cloud protection required - aborting"
                        throw "ASR application cancelled (cloud protection required, continueWithoutCloud=false)"
                    }
                    Write-NonInteractiveDecision -Module $moduleName -Decision "Continuing without cloud protection (limited functionality)"
                }
                elseif (-not $Force -and -not $DryRun) {
                    # Interactive prompt for cloud protection
                    Write-Host ""
                    Write-Host "===================================================================" -ForegroundColor Cyan
                    Write-Host "  Cloud Protection Not Enabled!" -ForegroundColor Cyan
                    Write-Host "===================================================================" -ForegroundColor Cyan
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
                    Write-Host "  [A] Abort       - Cancel ASR rule application (default)" -ForegroundColor Green
                    Write-Host "  [C] Continue    - Apply rules anyway (limited functionality)" -ForegroundColor Cyan
                    Write-Host ""

                    do {
                        Write-Host "Your choice [C/A] (default: A): " -ForegroundColor Yellow -NoNewline
                        $choice = Read-Host
                        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "A" }
                        $choice = $choice.ToUpperInvariant()

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
            if (-not $DryRun) {
                try {
                    if (-not (Initialize-BackupSystem)) { throw 'Backup initialization returned failure' }
                    $moduleBackupPath = Start-ModuleBackup -ModuleName $moduleName
                    if (-not $moduleBackupPath) { throw 'ASR module backup folder was not created' }
                    Write-Log -Level INFO -Message "Session backup initialized" -Module $moduleName
                }
                catch {
                    throw "Failed to initialize/start ASR backup: $($_.Exception.Message)"
                }
            }
            # Step 4: Create backup
            if (-not $DryRun) {
                Write-Log -Level INFO -Message "Creating backup..." -Module $moduleName

                $backupResult = Backup-ASRRegistry -Rules $applicableAsrRules -NotApplicableRules $notApplicableAsrRules
                if (-not $backupResult.Success -or $backupResult.Errors.Count -gt 0) {
                    throw "ASR backup failed: $($backupResult.Errors -join '; ')"
                }
                else {
                    # Register backup in session manifest
                    $asrBackupItems = @($global:BackupIndex | Where-Object { $_.Module -eq $moduleName }).Count
                    $null = Assert-ASRPrestate -ExpectedRules $applicableAsrRules -ExpectedNotApplicable $notApplicableAsrRules
                    if (-not (Complete-ModuleBackup -ItemsBackedUp $asrBackupItems -Status 'Success')) {
                        throw 'ASR backup manifest completion failed'
                    }
                    $sealedSnapshot = Assert-ASRPrestate -ExpectedRules $applicableAsrRules -ExpectedNotApplicable $notApplicableAsrRules
                    $result.BackupCreated = $true
                }
            }

            # Step 5: Apply ASR rules via PowerShell
            # Note: Set-ASRViaPowerShell logs internally, no need to log here
            $rulesForApply = if ($DryRun) {
                @($applicableAsrRules)
            }
            else {
                @($sealedSnapshot.Targets | ForEach-Object {
                        [PSCustomObject]@{
                            Name             = [string]$_.Name
                            GUID             = [string]$_.GUID
                            Action           = [int]$_.RequestedAction
                            BaselineStatus   = [string]$_.BaselineStatus
                            UserConfigurable = [bool]$_.UserConfigurable
                        }
                    })
            }
            $result.Details.RequestedActions = @($rulesForApply | ForEach-Object {
                    [PSCustomObject]@{
                        Guid   = ([Guid]([string]$_.GUID)).ToString('D').ToLowerInvariant()
                        Action = [int]$_.Action
                    }
                })
            $applyResult = Set-ASRViaPowerShell -Rules $rulesForApply -DryRun:$DryRun

            # In DryRun mode, no rules are actually applied, so keep RulesApplied = 0
            if (-not $DryRun) {
                $result.RulesApplied = $applyResult.Applied
            }
            else {
                $result.RulesPreviewed = $applyResult.Applied
            }

            # Add errors and warnings individually to avoid nested arrays
            foreach ($err in $applyResult.Errors) {
                $result.Errors += $err
            }
            foreach ($warn in $applyResult.Warnings) {
                $result.Warnings += $warn
            }

            # Count rule modes from actual system state
            if ($DryRun) {
                # Fallback to array count
                $result.Details.BlockMode = @($rulesForApply | Where-Object { $_.Action -eq 1 }).Count
                $result.Details.AuditMode = @($rulesForApply | Where-Object { $_.Action -eq 2 }).Count
                $result.Details.DisabledMode = @($rulesForApply | Where-Object { $_.Action -eq 0 }).Count
            }
            else {
                try {
                    $mpPref = Get-MpPreference -ErrorAction Stop
                    $configuredMap = (ConvertFrom-ASRPreference -Preference $mpPref).Map
                    $declaredActions = @($rulesForApply | ForEach-Object {
                            if ($configuredMap.ContainsKey([string]$_.GUID)) { $configuredMap[[string]$_.GUID] }
                        })
                    $result.Details.BlockMode = @($declaredActions | Where-Object { $_ -eq 1 }).Count
                    $result.Details.AuditMode = @($declaredActions | Where-Object { $_ -eq 2 }).Count
                    $result.Details.DisabledMode = @($declaredActions | Where-Object { $_ -eq 0 }).Count
                }
                catch {
                    $result.Errors += "Could not enumerate declared ASR rule state: $($_.Exception.Message)"
                }
            }

            # Step 6: Verification
            if (-not $DryRun) {
                Write-Log -Level INFO -Message "Verifying applied ASR rules..." -Module $moduleName

                $verificationResult = Test-ASRCompliance -ExpectedRules $rulesForApply
                $result.VerificationPassed = $verificationResult.Passed

                if (-not $verificationResult.Passed) {
                    $result.Errors += "Verification found $($verificationResult.FailedCount) rules not applied correctly"
                    Write-Log -Level ERROR -Message "Verification found $($verificationResult.FailedCount) failed rules" -Module $moduleName
                }
                else {
                    Write-Log -Level INFO -Message "Verification passed - all $($verificationResult.CheckedCount) rules confirmed" -Module $moduleName
                }
            }

            # Log baseline overlap
            $baselineRules = $rulesForApply | Where-Object { $_.BaselineStatus -in @("Block", "Audit") }
            Write-Log -Level INFO -Message "Security Baseline overlap: $($baselineRules.Count) rules already in baseline" -Module $moduleName

            $newRules = $rulesForApply | Where-Object { $_.BaselineStatus -eq "Missing" }
            if ($newRules.Count -gt 0) {
                Write-Log -Level INFO -Message "Added $($newRules.Count) rules not in Security Baseline:" -Module $moduleName
                foreach ($newRule in $newRules) {
                    Write-Log -Level INFO -Message "  + $($newRule.Name)" -Module $moduleName
                }
            }

            $upgradedRules = $rulesForApply | Where-Object { $_.BaselineStatus -eq "Audit" -and $_.Action -eq 1 }
            if ($upgradedRules.Count -gt 0) {
                Write-Log -Level INFO -Message "Upgraded $($upgradedRules.Count) rules from Audit to Block:" -Module $moduleName
                foreach ($upgradedRule in $upgradedRules) {
                    Write-Log -Level INFO -Message "  [UPGRADE] $($upgradedRule.Name)" -Module $moduleName
                }
            }

            # Mark as successful if no critical errors
            if ($result.Errors.Count -eq 0 -and ($DryRun -or $result.VerificationPassed)) {
                $result.Success = $true
                $result.Status = if ($DryRun) { 'DryRun' } else { 'Success' }
                Write-Log -Level INFO -Message $(if ($DryRun) { 'ASR DryRun preview completed successfully' } else { 'ASR rules applied successfully' }) -Module $moduleName
            }
            else {
                Write-Log -Level ERROR -Message "ASR application completed with $($result.Errors.Count) errors" -Module $moduleName
            }

        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
            Write-Log -Level ERROR -Message "ASR application failed: $($_.Exception.Message)" -Module $moduleName
            if (-not $DryRun -and [string]$global:CurrentModule -eq $moduleName) {
                try {
                    if (-not (Save-IncompleteModuleBackup -ModuleName $moduleName -Confirm:$false)) {
                        $result.Errors += 'Failed to retain/classify the incomplete ASR backup'
                    }
                }
                catch {
                    $result.Errors += "Incomplete ASR backup retention failed: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        $result.Duration = (Get-Date) - $startTime

        Write-Log -Level INFO -Message "ASR application completed in $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -Module $moduleName

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

        # GUI parsing marker for settings count -- read from canonical SettingsCounts.json
        $settingsCountsPath = Join-Path $PSScriptRoot "..\..\..\Config\SettingsCounts.json"
        try {
            if (-not (Test-Path -LiteralPath $settingsCountsPath -PathType Leaf)) {
                throw "Canonical SettingsCounts.json is missing: $settingsCountsPath"
            }
            $asrCount = [int](Get-Content -LiteralPath $settingsCountsPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop).modules.ASR.rules
            if ($asrCount -lt 1) { throw 'Canonical ASR rule count is invalid' }
        }
        catch {
            $result.Success = $false
            $result.Errors += "Canonical ASR count could not be loaded: $($_.Exception.Message)"
            Write-Log -Level ERROR -Message $result.Errors[-1] -Module $moduleName
        }
        if ($result.Status -eq 'Skipped') {
            Write-Log -Level INFO -Message "Skipped $($result.RulesSkipped) ASR settings; verifier state=NotChecked" -Module 'ASR'
        }
        elseif ($result.Success -and -not $DryRun) {
            Write-Log -Level SUCCESS -Message "Applied $($result.RulesApplied) settings; NotApplicable $($result.RulesNotApplicable); declared $asrCount" -Module "ASR"
        }
        elseif ($DryRun) {
            Write-Log -Level INFO -Message "DryRun preview completed; previewed=$($result.RulesPreviewed), NotApplicable=$($result.RulesNotApplicable), applied=0" -Module 'ASR'
        }
        else {
            Write-Log -Level ERROR -Message 'Applied-settings count not asserted because ASR apply/verification failed' -Module 'ASR'
        }

        return $result
    }
}
