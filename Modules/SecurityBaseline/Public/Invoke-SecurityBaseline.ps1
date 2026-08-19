<#
.SYNOPSIS
    Apply the Microsoft Windows 11 25H2-derived Security Baseline profile

.DESCRIPTION
    Applies the repository's 425-target profile derived from the Microsoft
    Windows 11 25H2 Security Baseline on supported Windows 11 24H2 and 25H2
    clients using Windows PowerShell and inbox Windows tools:
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

.PARAMETER SkipStandaloneDelta
    Skip standalone system adjustment (LocalAccountTokenFilterPolicy)
    Default: Apply adjustment on non-domain systems for remote admin access

.PARAMETER StandardUserElevationMode
    Strict keeps the Microsoft Security Baseline behavior and automatically
    denies standard-user elevation requests (ConsentPromptBehaviorUser=0).
    SecureDesktop permits standard users to enter separate administrator
    credentials on the secure desktop (ConsentPromptBehaviorUser=1). This
    system-wide standard-user policy does not change an administrator account's
    own elevation prompts.

.EXAMPLE
    Invoke-SecurityBaseline
    Apply every applicable profile target with scoped backup and verification

.EXAMPLE
    Invoke-SecurityBaseline -DryRun
    Preview what changes would be made

.OUTPUTS
    PSCustomObject with results including success status and any errors

.NOTES
    Author: NexusOne23
    Version: 2.2.5 - Self-Contained Edition
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
        [switch]$SkipStandaloneDelta,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Strict', 'SecureDesktop')]
        [string]$StandardUserElevationMode = 'Strict'
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
                    default { Write-Host "DEBUG: $Message" -ForegroundColor Gray }
                }
            }
        }

        $moduleName = "SecurityBaseline"
        $startTime = Get-Date
        $tempComputerRegPath = $null
        $tempSecurityTemplatePath = $null
        $backupFolder = $null
        $securityTemplateServiceNamesWithPrestate = @()

        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!

        # Initialize result object
        $result = [PSCustomObject]@{
            ModuleName         = $moduleName
            Success            = $false
            SettingsApplied    = 0
            SettingsNotApplicable = 0
            SettingsDeclared   = 0
            SettingsPreviewed  = 0
            Errors             = @()
            Warnings           = @()
            BackupCreated      = $false
            VerificationPassed = $null
            RequiresReboot     = $false
            Duration           = $null
            Details            = @{
                RegistryPolicies = 0
                SecuritySettings = 0
                AuditPolicies    = 0
                BitLockerUSBEnforcement = $null
                SubmitAllSamples = $null
                SmartScreenWarnMode = $null
                StandardUserElevationMode = $null
                ConsentPromptBehaviorUser = $null
                InteractiveAccountIsAdministrator = $null
                AsrActionOverrides = @()
            }
        }

        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "MICROSOFT SECURITY BASELINE v25H2-DERIVED" -Module $moduleName
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

            # This module contains one parsed 25H2-derived profile and one BAVR
            # contract. Microsoft ships 24H2 and 25H2 on the same servicing
            # branch; the exact upstream delta and the 24H2 safety review are
            # recorded in Docs/SECURITY-BASELINE-PROVENANCE.md. There is no
            # separate 24H2 profile or runtime UX branch.
            if (Get-Command Test-WindowsVersion -ErrorAction SilentlyContinue) {
                $windowsInfo = Get-WindowsVersion
                if (-not $windowsInfo.IsSupported -or $windowsInfo.Release -notin @('24H2', '25H2', '26H2')) {
                    throw "The Microsoft Security Baseline 25H2-derived profile requires a supported Windows 11 24H2 or 25H2 client; the recognized 26H2 Experimental Preview carry-forward is currently not runtime-validated or release-approved; detected $($windowsInfo.Version) ($($windowsInfo.FullBuild))"
                }
                if ($windowsInfo.SupportLevel -eq 'Experimental') {
                    $baselinePreviewWarning = 'Windows 11 26H2 is recognized only as an Experimental Preview and is currently not runtime-validated or release-approved; applying the Microsoft 25H2 baseline as an explicitly carried-forward profile because Microsoft has not published a final 26H2 baseline'
                    $result.Warnings += $baselinePreviewWarning
                    Write-ModuleLog -Level WARNING -Message $baselinePreviewWarning -Module $moduleName
                }
            }
            else {
                $standaloneOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $standaloneVersionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $build = [int]$standaloneVersionKey.GetValue('CurrentBuildNumber', $standaloneOs.BuildNumber)
                $displayVersion = [string]$standaloneVersionKey.GetValue('DisplayVersion', '')
                $installationType = [string]$standaloneVersionKey.GetValue('InstallationType', '')
                $isClient = ([int]$standaloneOs.ProductType -eq 1 -and $installationType -notmatch '(?i)Server')
                $is24H2 = ($displayVersion -eq '24H2' -and $build -ge 26100 -and $build -lt 26200)
                $is25H2 = ($displayVersion -eq '25H2' -and $build -ge 26200 -and $build -lt 26300)
                $is26H2Preview = ($displayVersion -eq '26H2' -and $build -ge 26300 -and $build -lt 28000)
                if (-not $isClient -or (-not $is24H2 -and -not $is25H2 -and -not $is26H2Preview)) {
                    throw "The Microsoft Security Baseline 25H2-derived profile requires a Windows 11 client on 24H2 or 25H2; the recognized 26H2 Experimental Preview carry-forward is currently not runtime-validated or release-approved; found DisplayVersion='$displayVersion', Build=$build, ProductType=$($standaloneOs.ProductType)"
                }
                if ($is26H2Preview) {
                    $baselinePreviewWarning = 'Windows 11 26H2 is recognized only as an Experimental Preview and is currently not runtime-validated or release-approved; applying the Microsoft 25H2 baseline as an explicitly carried-forward profile because Microsoft has not published a final 26H2 baseline'
                    $result.Warnings += $baselinePreviewWarning
                    Write-ModuleLog -Level WARNING -Message $baselinePreviewWarning -Module $moduleName
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
                    throw "Required runtime profile file not found: $file. Reinstall a verified release; the raw Microsoft-source parser deliberately cannot overwrite the NoID Privacy runtime profile."
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
                throw "Domain-membership detection failed; refusing to assume standalone: $($_.Exception.Message)"
            }

            # Define policy paths (needed for backup)
            $computerRegPath = Join-Path $parsedSettingsPath "Computer-RegistryPolicies.json"
            $userRegPath = Join-Path $parsedSettingsPath "User-RegistryPolicies.json"
            $securityTemplatePath = Join-Path $parsedSettingsPath "SecurityTemplates.json"
            $auditPoliciesPath = Join-Path $parsedSettingsPath "AuditPolicies.json"
            $userContext = Get-SecurityBaselineUserContext
            $userRegistryRoot = $userContext.Root
            $interactiveAccountIsAdministrator = [bool]$userContext.IsAdministrator
            $result.Details.InteractiveAccountIsAdministrator = $interactiveAccountIsAdministrator
            Write-ModuleLog -Level INFO -Message 'User-scope baseline policies are bound to the interactive desktop user hive' -Module $moduleName
            Write-ModuleLog -Level INFO -Message "Interactive everyday account local-Administrators membership: $interactiveAccountIsAdministrator" -Module $moduleName

            # Step 2.3: BitLocker USB Drive Protection - Interactive or Config-based
            $isNonInteractive = $false

            # The validated configuration is the decision authority. A stray
            # process/user environment variable must never suppress prompts or
            # manufacture security choices on its own.
            $isNonInteractive = Test-NonInteractiveMode

            if ($isNonInteractive) {
                $enableBitLockerUSBEnforcement = [bool](Get-NonInteractiveValue `
                        -Module 'SecurityBaseline' `
                        -Key 'bitLockerUSBEnforcement' `
                        -Required)
                $mode = if ($enableBitLockerUSBEnforcement) { "Enterprise Mode (from config)" } else { "Home Mode (from config)" }
                Write-ModuleLog -Level INFO -Message "Non-interactive mode: BitLocker USB = $mode" -Module $moduleName
                Write-Host "[GUI] BitLocker USB setting: $mode" -ForegroundColor Cyan
            }
            elseif ($DryRun) {
                # Interactive DryRun - use the safe default without prompting.
                $enableBitLockerUSBEnforcement = $false
                Write-ModuleLog -Level INFO -Message "Interactive DryRun: Using default BitLocker USB setting (Home Mode)" -Module $moduleName
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
                Write-Host "      - The policy does not encrypt the drive automatically; enable BitLocker separately" -ForegroundColor Gray
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
                    $choice = $choice.ToUpperInvariant()

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
                    Write-Host "Enterprise Mode: removable-drive write restriction enabled" -ForegroundColor Green
                    Write-Host "   Unprotected removable drives will be mounted read-only; encryption remains a separate action" -ForegroundColor Gray
                }
                else {
                    Write-ModuleLog -Level DEBUG -Message "User selected: BitLocker USB enforcement DISABLED (Home Mode)" -Module $moduleName
                    Write-Host ""
                    Write-Host "Home User Mode: Normal USB operation" -ForegroundColor Green
                    Write-Host "   USB drives will work without restrictions" -ForegroundColor Gray
                }
                Write-Host ""
            }
            $result.Details.BitLockerUSBEnforcement = [bool]$enableBitLockerUSBEnforcement

            # Step 2.3b: Defender sample submission - Interactive or Config-based.
            # Documented privacy deviation: Microsoft's 25H2 baseline sets
            # SubmitSamplesConsent=3 (send ALL samples, may upload personal
            # documents). NoID Privacy defaults to 1 (safe samples only); the choice
            # below restores Microsoft's 3 deliberately. Never silent.
            if ($isNonInteractive) {
                $submitAllSamples = [bool](Get-NonInteractiveValue `
                        -Module 'SecurityBaseline' `
                        -Key 'submitAllSamples' `
                        -Required)
                $sampleMode = if ($submitAllSamples) { "All samples (Microsoft baseline value, from config)" } else { "Safe samples only (privacy default, from config)" }
                Write-ModuleLog -Level INFO -Message "Non-interactive mode: Defender sample submission = $sampleMode" -Module $moduleName
                Write-Host "[GUI] Defender sample submission: $sampleMode" -ForegroundColor Cyan
            }
            elseif ($DryRun) {
                $submitAllSamples = $false
                Write-ModuleLog -Level INFO -Message "Interactive DryRun: Using default Defender sample submission (safe samples only)" -Module $moduleName
            }
            else {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  Defender Sample Submission (Cloud Analysis)" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Microsoft's baseline automatically uploads ALL suspicious file samples" -ForegroundColor White
                Write-Host "to Microsoft for cloud analysis - including files that may contain" -ForegroundColor White
                Write-Host "personal information." -ForegroundColor White
                Write-Host ""
                Write-Host "Send ALL file samples to Microsoft?" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  [N] NO - Safe samples only (Privacy Default, Recommended)" -ForegroundColor Green
                Write-Host "      - Uploads only samples unlikely to contain personal data" -ForegroundColor Gray
                Write-Host "      - Documents are never uploaded automatically" -ForegroundColor Gray
                Write-Host "      - Cloud protection and Block-at-First-Seen stay fully active" -ForegroundColor Gray
                Write-Host "      - Documented NoID Privacy deviation from the Microsoft baseline" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - All samples (Microsoft Baseline)" -ForegroundColor Cyan
                Write-Host "      - Any suspicious file can be uploaded automatically," -ForegroundColor Gray
                Write-Host "        including documents with potentially personal content" -ForegroundColor Gray
                Write-Host "      - Maximum cloud-analysis coverage (Microsoft's 25H2 value)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host "Security Note: Both choices keep MAPS cloud protection, Block-at-First-Seen and all ASR rules active" -ForegroundColor DarkGray
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $sampleChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($sampleChoice)) { $sampleChoice = "N" }
                    $sampleChoice = $sampleChoice.ToUpperInvariant()

                    if ($sampleChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($sampleChoice -notin @('Y', 'N'))

                $submitAllSamples = ($sampleChoice -eq 'Y')

                if ($submitAllSamples) {
                    Write-ModuleLog -Level DEBUG -Message "User selected: Defender sample submission ALL SAMPLES (Microsoft baseline value)" -Module $moduleName
                    Write-Host ""
                    Write-Host "All samples: Microsoft baseline value 3 will be applied" -ForegroundColor Green
                }
                else {
                    Write-ModuleLog -Level DEBUG -Message "User selected: Defender sample submission SAFE SAMPLES ONLY (privacy default)" -Module $moduleName
                    Write-Host ""
                    Write-Host "Safe samples only: documented privacy deviation (value 1) will be applied" -ForegroundColor Green
                }
                Write-Host ""
            }
            $result.Details.SubmitAllSamples = [bool]$submitAllSamples

            # Step 2.3c: OS SmartScreen level - Interactive or Config-based.
            # Block is Microsoft's baseline value and the default. Warn is the
            # documented security-reducing compatibility choice: SmartScreen
            # stays active but trusted downloads regain "Run anyway". The GUI
            # exposes the same decision as its SmartScreen quick action.
            if ($isNonInteractive) {
                $smartScreenWarnMode = [bool](Get-NonInteractiveValue `
                        -Module 'SecurityBaseline' `
                        -Key 'smartScreenWarnMode' `
                        -Required)
                $screenMode = if ($smartScreenWarnMode) { "Warn (compatibility choice, from config)" } else { "Block (Microsoft baseline, from config)" }
                Write-ModuleLog -Level INFO -Message "Non-interactive mode: SmartScreen level = $screenMode" -Module $moduleName
                Write-Host "[GUI] SmartScreen level: $screenMode" -ForegroundColor Cyan
            }
            elseif ($DryRun) {
                $smartScreenWarnMode = $false
                Write-ModuleLog -Level INFO -Message "Interactive DryRun: Using default SmartScreen level (Block)" -Module $moduleName
            }
            else {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  SmartScreen Level for Downloaded Files" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Microsoft's baseline sets SmartScreen to Block: unrecognized or" -ForegroundColor White
                Write-Host "unsigned downloads are stopped hard, without a 'Run anyway' option." -ForegroundColor White
                Write-Host ""
                Write-Host "Switch SmartScreen from Block to Warn?" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  [N] NO - Keep Block (Microsoft Baseline, Recommended)" -ForegroundColor Green
                Write-Host "      - Unknown installers are stopped with no bypass button" -ForegroundColor Gray
                Write-Host "      - Strongest protection against fresh malware droppers" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Use Warn, I often install new/unsigned software" -ForegroundColor Cyan
                Write-Host "      - SmartScreen stays active and still warns" -ForegroundColor Gray
                Write-Host "      - Trusted downloads regain the 'Run anyway' option" -ForegroundColor Gray
                Write-Host "      - Documented security-reducing compatibility choice" -ForegroundColor Gray
                Write-Host ""
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host "Security Note: Block is Microsoft's baseline value. Warn keeps SmartScreen active but allows starting flagged apps after an explicit warning." -ForegroundColor DarkGray
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $screenChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($screenChoice)) { $screenChoice = "N" }
                    $screenChoice = $screenChoice.ToUpperInvariant()

                    if ($screenChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($screenChoice -notin @('Y', 'N'))

                $smartScreenWarnMode = ($screenChoice -eq 'Y')

                if ($smartScreenWarnMode) {
                    Write-ModuleLog -Level DEBUG -Message "User selected: SmartScreen level WARN (compatibility choice)" -Module $moduleName
                    Write-Host ""
                    Write-Host "SmartScreen level Warn will be applied (SmartScreen stays active)" -ForegroundColor Green
                }
                else {
                    Write-ModuleLog -Level DEBUG -Message "User selected: SmartScreen level BLOCK (Microsoft baseline)" -Module $moduleName
                    Write-Host ""
                    Write-Host "SmartScreen level Block will be applied (Microsoft baseline value)" -ForegroundColor Green
                }
                Write-Host ""
            }
            $result.Details.SmartScreenWarnMode = [bool]$smartScreenWarnMode

            # Step 2.4: Standard-user elevation behavior. Strict is the baseline
            # default. The SecureDesktop option is Microsoft's documented choice
            # for standard-user elevation with separate administrator credentials.
            if (-not $PSBoundParameters.ContainsKey('StandardUserElevationMode')) {
                # A GUI/non-interactive DryRun must preview the actual selected
                # decision. Only an interactive DryRun with no explicit choice
                # uses Strict without opening a prompt.
                if ($isNonInteractive) {
                    $StandardUserElevationMode = Get-NonInteractiveValue `
                        -Module 'SecurityBaseline' `
                        -Key 'standardUserElevationMode' `
                        -Required
                    if ($StandardUserElevationMode -notin @('Strict', 'SecureDesktop')) {
                        throw "Invalid non-interactive standardUserElevationMode: $StandardUserElevationMode"
                    }
                    Write-Host "[GUI] Standard-user elevation: $StandardUserElevationMode" -ForegroundColor Cyan
                    Write-ModuleLog -Level INFO -Message "Non-interactive decision: standard-user elevation = $StandardUserElevationMode" -Module $moduleName
                }
                elseif ($DryRun) {
                    $StandardUserElevationMode = 'Strict'
                    Write-ModuleLog -Level INFO -Message 'Interactive DryRun: standard-user elevation = Strict (baseline default)' -Module $moduleName
                }
                else {
                    $StandardUserElevationMode = Read-StandardUserElevationModeChoice `
                        -InteractiveAccountIsAdministrator:$interactiveAccountIsAdministrator
                    Write-ModuleLog -Level INFO -Message "User decision: standard-user elevation = $StandardUserElevationMode" -Module $moduleName
                    Write-Host ""
                }
            }
            else {
                Write-ModuleLog -Level INFO -Message "Explicit parameter decision: standard-user elevation = $StandardUserElevationMode" -Module $moduleName
            }

            $consentPromptBehaviorUser = if ($StandardUserElevationMode -eq 'SecureDesktop') { 1 } else { 0 }
            $result.Details.StandardUserElevationMode = $StandardUserElevationMode
            $result.Details.ConsentPromptBehaviorUser = $consentPromptBehaviorUser

            # Apply the selected value through the same secedit template path as
            # the rest of the baseline; the canonical parsed baseline remains strict.
            $securityTemplateConfig = Get-Content -LiteralPath $securityTemplatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $computerTemplateName = 'MSFT Windows 11 25H2 - Computer'
            $uacInfName = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'
            if (-not ($securityTemplateConfig.PSObject.Properties.Name -contains $computerTemplateName)) {
                throw "Security template section not found: $computerTemplateName"
            }
            $registryValues = $securityTemplateConfig.$computerTemplateName.'Registry Values'
            if (-not ($registryValues.PSObject.Properties.Name -contains $uacInfName)) {
                throw "Security template value not found: $uacInfName"
            }
            $registryValues.PSObject.Properties[$uacInfName].Value = "4,$consentPromptBehaviorUser"
            $tempSecurityTemplatePath = Join-Path $env:TEMP "SecurityTemplates-$([guid]::NewGuid().ToString('N')).json"
            [System.IO.File]::WriteAllText(
                $tempSecurityTemplatePath,
                ($securityTemplateConfig | ConvertTo-Json -Depth 20),
                [System.Text.UTF8Encoding]::new($false)
            )
            $securityTemplatePath = $tempSecurityTemplatePath
            Write-ModuleLog -Level INFO -Message "ConsentPromptBehaviorUser selected value: $consentPromptBehaviorUser ($StandardUserElevationMode)" -Module $moduleName

            # Step 3: Create backup (MUST happen BEFORE applying changes)
            if (-not $DryRun) {
                Write-ModuleLog -Level INFO -Message "Step 3/9: Creating comprehensive backup..." -Module $moduleName

                try {
                    # Initialize Session-based backup (MANDATORY)
                    if (-not (Initialize-BackupSystem)) {
                        throw 'Backup system initialization returned failure'
                    }
                    $backupFolder = Start-ModuleBackup -ModuleName $moduleName

                    if (-not $backupFolder) {
                        throw "Failed to create session backup folder"
                    }

                    Write-ModuleLog -Level INFO -Message "Session backup initialized: $backupFolder" -Module $moduleName

                    # This implementation writes effective registry values directly;
                    # it never edits %WinDir%\System32\GroupPolicy. Backing up and later
                    # replacing that unrelated tree would overwrite local/domain policy
                    # changes made after Apply, so LocalGPO is deliberately not a restore
                    # target. Exact value prestate below counters registry tattooing.

                    # Backup 1: Registry Policies
                    Write-ModuleLog -Level INFO -Message "Backing up registry policies..." -Module $moduleName
                    $regBackupPath = Join-Path $backupFolder "RegistryPolicies.json"
                    $regBackup = Backup-RegistryPolicies -ComputerPoliciesPath $computerRegPath `
                        -UserPoliciesPath $userRegPath `
                        -UserRegistryRoot $userRegistryRoot `
                        -BackupPath $regBackupPath

                    if (-not $regBackup.Success) {
                        throw "Registry policies backup failed: $($regBackup.Errors -join '; ')"
                    }
                    $null = Register-BackupFile -FilePath $regBackupPath -Type 'SecurityBaseline' -Name 'RegistryPolicies' -Target 'RegistryPolicies'

                    # Backup 2: Security Template
                    Write-ModuleLog -Level INFO -Message "Backing up security template..." -Module $moduleName
                    $secBackupPath = Join-Path $backupFolder "SecurityTemplate.inf"
                    $secBackup = Backup-SecurityTemplate -BackupPath $secBackupPath -SecurityTemplatePath $securityTemplatePath

                    if (-not $secBackup.Success) {
                        throw "Security template backup failed"
                    }
                    $null = Register-BackupFile -FilePath $secBackupPath -Type 'SecurityBaseline' -Name 'SecurityTemplate' -Target 'SecurityTemplate'

                    # Explicit targeted backup closes the secedit-export gap for
                    # a value that may be at an effective default and omitted
                    # from SecurityTemplate.inf.
                    $uacBackupPath = Join-Path $backupFolder 'UACStandardUserElevation.json'
                    $uacBackup = Backup-UACStandardUserElevation -BackupPath $uacBackupPath
                    if (-not $uacBackup.Success) {
                        throw "UAC standard-user elevation backup failed: $($uacBackup.Errors -join '; ')"
                    }
                    $null = Register-BackupFile -FilePath $uacBackupPath `
                        -Type 'SecurityBaseline' `
                        -Name 'UACStandardUserElevation' `
                        -Target 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'

                    $templateRegistryBackupPath = Join-Path $backupFolder 'SecurityTemplateRegistryState.json'
                    $templateRegistryBackup = Backup-SecurityTemplateRegistryState `
                        -SecurityTemplatePath $securityTemplatePath `
                        -BackupPath $templateRegistryBackupPath `
                        -IncludeStandaloneDelta:(-not $isDomainJoined -and -not $SkipStandaloneDelta)
                    if (-not $templateRegistryBackup.Success) {
                        throw "Security-template registry state backup failed: $($templateRegistryBackup.Errors -join '; ')"
                    }
                    $null = Register-BackupFile -FilePath $templateRegistryBackupPath `
                        -Type 'SecurityBaseline' `
                        -Name 'SecurityTemplateRegistryState' `
                        -Target 'SecurityTemplateRegistryValues'

                    # Backup 3: Audit Policies
                    Write-ModuleLog -Level INFO -Message "Backing up audit policies..." -Module $moduleName
                    $auditBackupPath = Join-Path $backupFolder "AuditPolicies.json"
                    $expectedAuditTargets = Get-Content -LiteralPath $auditPoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    $expectedAuditTargetCount = @($expectedAuditTargets).Count
                    if ($expectedAuditTargetCount -lt 1) { throw 'Audit policy target inventory is empty' }
                    $auditBackup = Backup-AuditPolicies -BackupPath $auditBackupPath -AuditPoliciesPath $auditPoliciesPath

                    if (-not $auditBackup.Success -or $auditBackup.Count -ne $expectedAuditTargetCount) {
                        throw "Audit policies backup failed or returned an incomplete target count"
                    }
                    $null = Register-BackupFile -FilePath $auditBackupPath -Type 'SecurityBaseline' -Name 'AuditPolicies' -Target 'AuditPolicies'

                    # Backup 4: Xbox Task State
                    Write-ModuleLog -Level INFO -Message "Backing up Xbox task state..." -Module $moduleName
                    $xboxTaskBackupPath = Join-Path $backupFolder "XboxTask.json"
                    $xboxTaskBackup = Backup-XboxTask -BackupPath $xboxTaskBackupPath

                    if (-not $xboxTaskBackup.Success) {
                        throw "Xbox task backup failed"
                    }
                    $null = Register-BackupFile -FilePath $xboxTaskBackupPath -Type 'SecurityBaseline' -Name 'XboxTask' -Target 'XboxTask'

                    $securityTemplateServiceInventory = @(Get-Service -ErrorAction Stop)
                    foreach ($serviceName in @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')) {
                        $serviceMatches = @($securityTemplateServiceInventory | Where-Object { [string]$_.Name -eq $serviceName })
                        if ($serviceMatches.Count -gt 1) { throw "Service inventory is ambiguous: $serviceName" }
                        if ($serviceMatches.Count -eq 0) { continue }
                        $serviceBackup = Backup-ServiceConfiguration -ServiceName $serviceName -StartupOnly
                        if (-not $serviceBackup.Success -or -not $serviceBackup.Exists) {
                            throw "Service state backup failed: $serviceName ($($serviceBackup.Error))"
                        }
                        $securityTemplateServiceNamesWithPrestate += $serviceName
                    }
                    if (-not (Assert-SecurityBaselinePrestate)) {
                        throw 'SecurityBaseline complete prestate reconciliation returned failure'
                    }

                    # Register backup in session manifest
                    $totalItems = @($global:BackupIndex | Where-Object { $_.Module -eq $moduleName }).Count
                    $backupCompleted = Complete-ModuleBackup -ItemsBackedUp $totalItems -Status "Success"
                    if (-not $backupCompleted) {
                        throw 'SecurityBaseline backup manifest completion failed'
                    }
                    if (-not (Assert-SecurityBaselinePrestate)) {
                        throw 'SecurityBaseline sealed prestate changed before Apply'
                    }

                    $result.BackupCreated = $true
                    Write-ModuleLog -Level SUCCESS -Message "Backup created and registered in session: $backupFolder" -Module $moduleName
                }
                catch {
                    $result.Warnings += "Backup failed: $_"
                    Write-ModuleLog -Level WARNING -Message "Backup failed: $_" -Module $moduleName
                    throw 'Backup failed; Apply is blocked by the BAVR safety contract'
                }
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
                    elseif ([bool]$xboxResult.TaskExists) {
                        # Present but not disabled: the only way to reach this is a
                        # DryRun preview. Do not report it as "not installed" - the
                        # Apply that follows will disable it.
                        Write-ModuleLog -Level INFO -Message "[DRYRUN] Xbox task present; would be disabled" -Module $moduleName
                    }
                    else {
                        Write-ModuleLog -Level INFO -Message "Xbox task not found (not installed)" -Module $moduleName
                    }
                }
                else {
                    $result.Errors += $xboxResult.Errors
                    Write-ModuleLog -Level ERROR -Message "Xbox task disable failed" -Module $moduleName
                }
            }
            catch {
                $result.Errors += "Xbox task disable failed: $($_.Exception.Message)"
                Write-ModuleLog -Level ERROR -Message "Xbox task disable failed: $_" -Module $moduleName
            }

            # Step 5: Apply the BitLocker USB, sample-submission and SmartScreen choices
            Write-ModuleLog -Level INFO -Message "Step 5/9: Configuring BitLocker USB, sample-submission and SmartScreen policies..." -Module $moduleName

            try {
                # Load Computer-RegistryPolicies.json
                $computerPolicies = Get-Content $computerRegPath -Raw | ConvertFrom-Json

                # Decision identities are path + value name. A future baseline
                # may legitimately repeat a value name under another key; a
                # name-only lookup would silently rewrite both entries.
                $bitlockerPolicy = @($computerPolicies | Where-Object {
                        [string]$_.KeyName -ceq '[System\CurrentControlSet\Policies\Microsoft\FVE' -and
                        [string]$_.ValueName -ceq 'RDVDenyWriteAccess'
                    })
                $submitSamplesPolicy = @($computerPolicies | Where-Object {
                        [string]$_.KeyName -ceq '[Software\Policies\Microsoft\Windows Defender\Spynet' -and
                        [string]$_.ValueName -ceq 'SubmitSamplesConsent'
                    })
                $smartScreenPolicy = @($computerPolicies | Where-Object {
                        [string]$_.KeyName -ceq '[Software\Policies\Microsoft\Windows\System' -and
                        [string]$_.ValueName -ceq 'ShellSmartScreenLevel'
                    })

                if ($bitlockerPolicy.Count -eq 1 -and $submitSamplesPolicy.Count -eq 1 -and $smartScreenPolicy.Count -eq 1) {
                    # Set based on user choices
                    $bitlockerPolicy[0].Data = if ($enableBitLockerUSBEnforcement) { 1 } else { 0 }
                    $submitSamplesPolicy[0].Data = if ($submitAllSamples) { 3 } else { 1 }
                    $smartScreenPolicy[0].Data = if ($smartScreenWarnMode) { 'Warn' } else { 'Block' }

                    # The PSExec/WMI ASR rule (d1e49aac-...) is the one baseline registry
                    # value the ASR module also owns: Microsoft ships it as "2" (Audit,
                    # ConfigMgr consideration), the ASR module writes the user's Block/
                    # Audit decision. Verification treats that decision as the
                    # authoritative final expectation (Verify-Complete-Hardening patches
                    # the target from the durable ASR intent), so a standalone
                    # SecurityBaseline Apply must not stomp it back to the package
                    # value. Same precedence as the verifier: durable ASR intent, then
                    # the durable QuickAction override, then the sealed package value.
                    # The decision used is recorded in Details.AsrActionOverrides so the
                    # rewritten SecurityBaseline intent record stays self-consistent for
                    # baseline-scoped verification.
                    $psexecWmiRuleGuid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
                    $psexecWmiPolicy = @($computerPolicies | Where-Object {
                            [string]$_.KeyName -ceq '[Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' -and
                            [string]$_.ValueName -ieq $psexecWmiRuleGuid
                        })
                    if ($psexecWmiPolicy.Count -ne 1) {
                        throw 'PSExec/WMI ASR rule policy not found in baseline'
                    }
                    $asrRuleAction = $null
                    $asrRuleActionSource = $null
                    $durableIntent = $null
                    try { $durableIntent = Read-NoIDIntentState -AllowMissing }
                    catch {
                        Write-ModuleLog -Level WARNING -Message "Durable Apply-intent record is unavailable; the PSExec/WMI ASR rule keeps the sealed package value: $($_.Exception.Message)" -Module $moduleName
                    }
                    if ($durableIntent) {
                        $asrIntentRecord = $durableIntent.modules.PSObject.Properties['ASR']
                        if ($asrIntentRecord) {
                            $asrIntentMatches = @($asrIntentRecord.Value.intent.requestedActions | Where-Object {
                                    ([Guid]([string]$_.Guid)).ToString('D').ToLowerInvariant() -ceq $psexecWmiRuleGuid
                                })
                            if ($asrIntentMatches.Count -eq 1 -and [int]$asrIntentMatches[0].Action -in @(1, 2)) {
                                $asrRuleAction = [int]$asrIntentMatches[0].Action
                                $asrRuleActionSource = 'durable ASR intent'
                            }
                        }
                        if ($null -eq $asrRuleAction) {
                            $baselineIntentRecord = $durableIntent.modules.PSObject.Properties['SecurityBaseline']
                            if ($baselineIntentRecord) {
                                $overrideMatches = @($baselineIntentRecord.Value.intent.asrActionOverrides | Where-Object {
                                        ([Guid]([string]$_.Guid)).ToString('D').ToLowerInvariant() -ceq $psexecWmiRuleGuid
                                    })
                                if ($overrideMatches.Count -eq 1 -and [int]$overrideMatches[0].Action -in @(1, 2)) {
                                    $asrRuleAction = [int]$overrideMatches[0].Action
                                    $asrRuleActionSource = 'durable QuickAction override'
                                }
                            }
                        }
                    }
                    if ($null -ne $asrRuleAction) {
                        $psexecWmiPolicy[0].Data = [string]$asrRuleAction
                        $result.Details.AsrActionOverrides = @([PSCustomObject]@{ Guid = $psexecWmiRuleGuid; Action = $asrRuleAction })
                        $ruleMode = if ($asrRuleAction -eq 1) { 'Block' } else { 'Audit' }
                        Write-ModuleLog -Level SUCCESS -Message "PSExec/WMI ASR rule aligned with the recorded user decision: $ruleMode ($asrRuleAction, $asrRuleActionSource)" -Module $moduleName
                    }
                    else {
                        Write-ModuleLog -Level INFO -Message "PSExec/WMI ASR rule keeps the sealed package value: Audit (2, Microsoft baseline; no recorded user decision)" -Module $moduleName
                    }

                    # Save modified policies back to temp location (UTF-8 NO-BOM; consumed by Set-RegistryPolicies via ConvertFrom-Json)
                    $tempComputerRegPath = Join-Path $env:TEMP "Computer-RegistryPolicies-$([guid]::NewGuid().ToString('N')).json"
                    [System.IO.File]::WriteAllText($tempComputerRegPath, ($computerPolicies | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))

                    # Update path to use modified version
                    $computerRegPath = $tempComputerRegPath

                    $mode = if ($enableBitLockerUSBEnforcement) { "Enterprise (Enabled)" } else { "Home (Disabled)" }
                    Write-ModuleLog -Level SUCCESS -Message "BitLocker USB policy configured: $mode" -Module $moduleName
                    $sampleMode = if ($submitAllSamples) { "All samples (3, Microsoft baseline)" } else { "Safe samples only (1, privacy default)" }
                    Write-ModuleLog -Level SUCCESS -Message "Defender sample submission configured: $sampleMode" -Module $moduleName
                    $screenMode = if ($smartScreenWarnMode) { "Warn (compatibility choice)" } else { "Block (Microsoft baseline)" }
                    Write-ModuleLog -Level SUCCESS -Message "SmartScreen level configured: $screenMode" -Module $moduleName
                }
                else {
                    throw 'RDVDenyWriteAccess, SubmitSamplesConsent or ShellSmartScreenLevel policy not found in baseline'
                }
            }
            catch {
                $result.Errors += "Could not configure the BitLocker USB / sample-submission / SmartScreen policies: $($_.Exception.Message)"
                throw
            }

            # Step 6: Apply Registry Policies
            Write-ModuleLog -Level INFO -Message "Step 6/9: Applying registry policies..." -Module $moduleName

            $regResult = Set-RegistryPolicies -ComputerPoliciesPath $computerRegPath `
                -UserPoliciesPath $userRegPath `
                -UserRegistryRoot $userRegistryRoot `
                -DryRun:$DryRun

            $result.Details.RegistryPolicies = $regResult.Applied
            $result.SettingsApplied += $regResult.Applied

            if ($regResult.Errors.Count -gt 0) {
                foreach ($err in $regResult.Errors) {
                    $result.Errors += $err
                }
            }

            if ($regResult.Success) {
                Write-ModuleLog -Level SUCCESS -Message "Registry policies: $($regResult.Applied) applied and verified" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level ERROR -Message "Registry policy application/verification failed" -Module $moduleName
            }

            # Step 7: Apply Standalone Delta (if not domain-joined and not skipped)
            if (-not $isDomainJoined -and -not $DryRun -and -not $SkipStandaloneDelta) {
                Write-ModuleLog -Level INFO -Message "Step 7/9: Applying standalone system adjustments..." -Module $moduleName

                try {
                    # LocalAccountTokenFilterPolicy = 1 (enable remote admin for local accounts)
                    $deltaKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                    $deltaValue = "LocalAccountTokenFilterPolicy"

                    # The exact value/existence prestate was sealed in
                    # SecurityTemplateRegistryState.json before Apply.
                    if (-not (Test-Path $deltaKey)) {
                        New-Item -Path $deltaKey -Force -ErrorAction Stop | Out-Null
                    }

                    $deltaNames = @((Get-Item -LiteralPath $deltaKey -ErrorAction Stop).GetValueNames())
                    if ($deltaNames -contains $deltaValue) {
                        Remove-ItemProperty -LiteralPath $deltaKey -Name $deltaValue -Force -ErrorAction Stop
                    }
                    New-ItemProperty -Path $deltaKey -Name $deltaValue -Value ([int]1) `
                        -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    $deltaRegistryKey = Get-Item -LiteralPath $deltaKey -ErrorAction Stop
                    if ($deltaRegistryKey.GetValueKind($deltaValue).ToString() -ne 'DWord' -or
                        [int]$deltaRegistryKey.GetValue($deltaValue) -ne 1) {
                        throw 'LocalAccountTokenFilterPolicy post-write verification failed'
                    }

                    Write-ModuleLog -Level SUCCESS -Message "Standalone system adjustments applied" -Module $moduleName
                }
                catch {
                    $result.Errors += "Failed to apply standalone adjustments: $($_.Exception.Message)"
                    Write-ModuleLog -Level ERROR -Message "Failed to apply standalone adjustments: $_" -Module $moduleName
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

            if ($DryRun) {
                $dryRunServiceInventory = @(Get-Service -ErrorAction Stop)
                $securityTemplateServiceNamesWithPrestate = @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc' |
                    Where-Object {
                        $candidateName = [string]$_
                        $serviceMatches = @($dryRunServiceInventory | Where-Object { [string]$_.Name -eq $candidateName })
                        if ($serviceMatches.Count -gt 1) { throw "Service inventory is ambiguous: $candidateName" }
                        $serviceMatches.Count -eq 1
                    })
            }
            else {
                # Reconcile as late as possible so an external service change
                # after backup is never silently overwritten by secedit.
                $null = Assert-SecurityBaselineServicePrestate `
                    -ServiceNamesWithSealedPrestate $securityTemplateServiceNamesWithPrestate
            }
            $secResult = Set-SecurityTemplate `
                -SecurityTemplatePath $securityTemplatePath `
                -ServiceNamesWithSealedPrestate $securityTemplateServiceNamesWithPrestate `
                -DryRun:$DryRun

            $result.Details.SecuritySettings = $secResult.SettingsApplied
            $result.SettingsApplied += $secResult.SettingsApplied
            $result.SettingsNotApplicable += $secResult.SettingsNotApplicable

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

            if (-not $DryRun) {
                try {
                    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    $uacKey = Get-Item -LiteralPath $uacPath -ErrorAction Stop
                    $uacActual = $uacKey.GetValue('ConsentPromptBehaviorUser')
                    $uacType = $uacKey.GetValueKind('ConsentPromptBehaviorUser').ToString()
                    if ([int]$uacActual -ne $consentPromptBehaviorUser -or $uacType -ne 'DWord') {
                        throw "expected DWord/$consentPromptBehaviorUser, got $uacType/$uacActual"
                    }
                    Write-ModuleLog -Level SUCCESS -Message "ConsentPromptBehaviorUser verified: $uacActual ($StandardUserElevationMode)" -Module $moduleName
                }
                catch {
                    $result.Errors += "ConsentPromptBehaviorUser verification failed: $($_.Exception.Message)"
                    Write-ModuleLog -Level ERROR -Message "ConsentPromptBehaviorUser verification failed: $_" -Module $moduleName
                }
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

            if ($auditResult.Success) {
                Write-ModuleLog -Level SUCCESS -Message "Audit policies: $($auditResult.Applied) applied and verified" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level ERROR -Message 'Audit policy application/verification failed' -Module $moduleName
            }

            # Every selected registry, security-template, and audit setting is
            # verified inside its apply helper. Aggregate those full results;
            # a four-value spot check must never certify the whole baseline.
            if (-not $DryRun) {
                Write-ModuleLog -Level INFO -Message 'Aggregating full per-setting verification results...' -Module $moduleName
                if ($result.BackupCreated -and $regResult.Success -and $secResult.Success -and
                    $auditResult.Success -and $result.Errors.Count -eq 0) {
                    $result.VerificationPassed = $true
                    Write-ModuleLog -Level SUCCESS -Message 'Full selected-setting verification passed' -Module $moduleName
                }
                else {
                    $result.Errors += 'Full SecurityBaseline verification did not pass'
                    Write-ModuleLog -Level ERROR -Message 'Full SecurityBaseline verification did not pass' -Module $moduleName
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
            if (-not $DryRun -and [string]$global:CurrentModule -eq $moduleName) {
                try {
                    if (-not (Save-IncompleteModuleBackup -ModuleName $moduleName -Confirm:$false)) {
                        $result.Errors += 'Failed to retain/classify the incomplete SecurityBaseline backup'
                    }
                }
                catch {
                    $result.Errors += "Incomplete SecurityBaseline backup retention failed: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        if ($DryRun) {
            $result.SettingsPreviewed = $result.SettingsApplied
            $result.SettingsApplied = 0
        }
        $result.Duration = (Get-Date) - $startTime
        $result.RequiresReboot = ($result.Success -and -not $DryRun -and $result.SettingsApplied -gt 0)

        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "SECURITY BASELINE SUMMARY" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Total Settings Applied: $($result.SettingsApplied)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Total Settings Previewed: $($result.SettingsPreviewed)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Settings Not Applicable: $($result.SettingsNotApplicable)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Registry Policies:  $($result.Details.RegistryPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Security Settings:  $($result.Details.SecuritySettings)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Audit Policies:     $($result.Details.AuditPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Standard-user UAC:  $($result.Details.StandardUserElevationMode) (ConsentPromptBehaviorUser=$($result.Details.ConsentPromptBehaviorUser))" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Everyday admin:     $($result.Details.InteractiveAccountIsAdministrator)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Errors: $($result.Errors.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Warnings: $($result.Warnings.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Duration: $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName

        # GUI parsing marker for settings count -- read from canonical SettingsCounts.json
        $settingsCountsPath = Join-Path $PSScriptRoot "..\..\..\Config\SettingsCounts.json"
        try {
            if (-not (Test-Path -LiteralPath $settingsCountsPath -PathType Leaf -ErrorAction Stop)) {
                throw "Canonical SettingsCounts.json is missing: $settingsCountsPath"
            }
            $sbCount = [int](Get-Content -LiteralPath $settingsCountsPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop).modules.SecurityBaseline.subtotal
            if ($sbCount -lt 1) { throw 'Canonical SecurityBaseline count is invalid' }
            $result.SettingsDeclared = $sbCount
            $accountedSettings = if ($DryRun) {
                $result.SettingsPreviewed + $result.SettingsNotApplicable
            }
            else {
                $result.SettingsApplied + $result.SettingsNotApplicable
            }
            if ($result.Success -and $accountedSettings -ne $sbCount) {
                throw "SecurityBaseline target accounting mismatch: accounted=$accountedSettings, declared=$sbCount"
            }
        }
        catch {
            $result.Success = $false
            $result.RequiresReboot = $false
            $result.Errors += "Canonical SecurityBaseline count could not be loaded: $($_.Exception.Message)"
            Write-ModuleLog -Level ERROR -Message $result.Errors[-1] -Module $moduleName
            $sbCount = $null
        }
        if ($result.Success -and -not $DryRun -and $result.VerificationPassed) {
            Write-Log -Level SUCCESS -Message "Applied $($result.SettingsApplied) settings; $($result.SettingsNotApplicable) not applicable; $sbCount declared" -Module "SecurityBaseline"
        }
        elseif ($DryRun) {
            Write-Log -Level INFO -Message "DryRun preview completed; applied settings = 0" -Module 'SecurityBaseline'
        }
        elseif (-not $DryRun) {
            Write-Log -Level ERROR -Message "Applied-settings count not asserted because SecurityBaseline apply/verification failed" -Module 'SecurityBaseline'
        }

        # Cleanup the temp BitLocker-modified policy file if Step 5 created one
        if ($tempComputerRegPath -and (Test-Path $tempComputerRegPath)) {
            Remove-Item $tempComputerRegPath -Force -ErrorAction SilentlyContinue
        }
        if ($tempSecurityTemplatePath -and (Test-Path $tempSecurityTemplatePath)) {
            Remove-Item $tempSecurityTemplatePath -Force -ErrorAction SilentlyContinue
        }

        return $result
    }
}
