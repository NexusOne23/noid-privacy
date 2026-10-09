<#
.SYNOPSIS
    Apply the Microsoft Windows 11 26H2-derived Security Baseline profile

.DESCRIPTION
    Applies the repository's 425-target profile derived from the Microsoft
    Windows 11 26H2 Security Baseline on supported Windows 11 24H2, 25H2 and
    explicit 26H2 clients using Windows PowerShell and inbox Windows tools:
    - 335 Registry policies (Computer + User)
    - 67 Security Template settings (Password/Account/User Rights)
    - 23 Advanced Audit Policies

    Note: 438 total entries parsed from Microsoft GPO files. 13 are metadata:
    12 INF headers (Unicode/Version) and the native firewall policy-format entry.

    Uses ONLY native Windows tools:
    - PowerShell for Registry
    - secedit.exe for Security Templates
    - auditpol.exe for Audit Policies

    NO EXTERNAL DEPENDENCIES - no LGPO.exe, no Microsoft GPO files needed!

.PARAMETER DryRun
    Preview changes without applying them

.PARAMETER StandardUserElevationMode
    Strict keeps the Microsoft Security Baseline behavior and automatically
    denies standard-user elevation requests (ConsentPromptBehaviorUser=0).
    SecureDesktop permits standard users to enter separate administrator
    credentials on the secure desktop (ConsentPromptBehaviorUser=1). This
    system-wide standard-user policy does not change an administrator account's
    own elevation prompts.

.PARAMETER AdminProtectionMode
    Credentials keeps the Microsoft Security Baseline: Administrator protection
    (TypeOfAdminApprovalMode=2) asks for PIN, password or Windows Hello for every
    administrator action. Consent keeps Administrator protection with Microsoft's
    documented Yes/No prompt on the secure desktop
    (ConsentPromptBehaviorEnhancedAdmin=2). Classic turns Administrator protection
    off (TypeOfAdminApprovalMode=1) for Hyper-V, WSL and developer tools that must
    run elevated; the baseline's Yes/No consent prompt for administrators stays.
    Credentials and Classic set Microsoft's v2 baseline value
    ConsentPromptBehaviorEnhancedAdmin=1; it has no effect while protection is off.

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
    Version: 2.2.6 - Self-Contained Edition
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
        [ValidateSet('Strict', 'SecureDesktop')]
        [string]$StandardUserElevationMode = 'Strict',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Credentials', 'Consent', 'Classic')]
        [string]$AdminProtectionMode = 'Credentials'
    )

    begin {
        # Helper function: use the framework Write-Log when available, else Write-Host.
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
                AdminProtectionMode = $null
                TypeOfAdminApprovalMode = $null
                ConsentPromptBehaviorEnhancedAdmin = $null
                InteractiveAccountIsAdministrator = $null
                AsrActionOverrides = @()
            }
        }

        Write-ModuleLog -Level INFO -Message "===================================================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "MICROSOFT SECURITY BASELINE v26H2-DERIVED" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Self-Contained Edition (No LGPO.exe)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "===================================================================" -Module $moduleName

        if ($DryRun) {
            Write-ModuleLog -Level INFO -Message "DRY RUN MODE - No changes will be applied" -Module $moduleName
        }
    }

    process {
        try {
            # Step 1: Prerequisites validation
            Write-ModuleLog -Level INFO -Message "Step 1/8: Validating prerequisites..." -Module $moduleName

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

            # This module contains one parsed 26H2-derived profile and one BAVR
            # contract for the fully supported 24H2, 25H2 and 26H2 releases. The
            # exact upstream/provenance decisions are recorded in
            # Docs/SECURITY-BASELINE-PROVENANCE.md. Do not silently route any
            # supported release to older content or a second unreviewed profile.
            if (Get-Command Get-WindowsVersion -ErrorAction SilentlyContinue) {
                $windowsInfo = Get-WindowsVersion
                if (-not $windowsInfo.IsSupported -or $windowsInfo.Release -notin @('24H2', '25H2', '26H2')) {
                    throw "The Microsoft Security Baseline 26H2-derived profile requires a supported Windows 11 24H2, 25H2 or explicit 26H2 client; detected $($windowsInfo.Version) ($($windowsInfo.FullBuild))"
                }
                $operatingSystemSku = $windowsInfo.OperatingSystemSKU
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
                $is26H2 = ($displayVersion -eq '26H2' -and $build -ge 26300 -and $build -lt 28000)
                if (-not $isClient -or (-not $is24H2 -and -not $is25H2 -and -not $is26H2)) {
                    throw "The Microsoft Security Baseline 26H2-derived profile requires a Windows 11 client on 24H2, 25H2 or explicit 26H2; found DisplayVersion='$displayVersion', Build=$build, ProductType=$($standaloneOs.ProductType)"
                }
                $operatingSystemSku = $standaloneOs.OperatingSystemSKU
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

            # Define policy paths (needed for backup)
            $computerRegPath = Join-Path $parsedSettingsPath "Computer-RegistryPolicies.json"
            $userRegPath = Join-Path $parsedSettingsPath "User-RegistryPolicies.json"
            $securityTemplatePath = Join-Path $parsedSettingsPath "SecurityTemplates.json"
            $auditPoliciesPath = Join-Path $parsedSettingsPath "AuditPolicies.json"

            # Use the same owned target set for Backup, Apply and Verify.
            # Native firewall format metadata is not ours to capture/restore;
            # historical backups containing it remain readable by their own
            # declared inventory. The canonical Microsoft source stays intact.
            $sourceComputerPolicies = Get-Content -LiteralPath $computerRegPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $computerPolicies = @(Get-RecoverableSecurityBaselinePolicies -Policies $sourceComputerPolicies)
            $deviceGuardPlan = Get-SecurityBaselineDeviceGuardPlan -Policies $computerPolicies
            $homeVbsTargets = @(Get-SecurityBaselineHomeVbsTargets -OperatingSystemSku $operatingSystemSku -Policies $computerPolicies)
            Write-ModuleLog -Level INFO -Message 'BAVR decision: LSA protection, Credential Guard and HVCI use enabled-without-new-UEFI-lock modes for Windows-based recovery. This reduces resistance to privileged reconfiguration. Existing locks and saved Restore values remain unchanged. See Docs/SECURITY-BASELINE-RECOVERY.md.' -Module $moduleName
            $tempComputerRegPath = Join-Path $env:TEMP "Computer-RegistryPolicies-$([guid]::NewGuid().ToString('N')).json"
            [IO.File]::WriteAllText($tempComputerRegPath, ($computerPolicies | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
            $computerRegPath = $tempComputerRegPath
            $userContext = Get-SecurityBaselineUserContext
            $userRegistryRoot = $userContext.Root
            $interactiveAccountIsAdministrator = [bool]$userContext.IsAdministrator
            $result.Details.InteractiveAccountIsAdministrator = $interactiveAccountIsAdministrator
            Write-ModuleLog -Level INFO -Message 'User-scope baseline policies are bound to the interactive desktop user hive' -Module $moduleName
            Write-ModuleLog -Level INFO -Message "Interactive everyday account local-Administrators membership: $interactiveAccountIsAdministrator" -Module $moduleName

            # Step 2: Collect the explicit application choices. The same profile,
            # including Remote UAC filtering, applies to standalone and domain-
            # joined systems; no membership query is needed for this module.
            Write-ModuleLog -Level INFO -Message "Step 2/8: Collecting application choices..." -Module $moduleName

            # Step 2a: BitLocker USB Drive Protection - Interactive or Config-based
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
                Write-Host "Do you want to REQUIRE BitLocker encryption for USB drives?" -ForegroundColor White
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
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor White -NoNewline
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
                    Write-Host "  Unprotected removable drives will be mounted read-only; encryption remains a separate action" -ForegroundColor Gray
                }
                else {
                    Write-ModuleLog -Level DEBUG -Message "User selected: BitLocker USB enforcement DISABLED (Home Mode)" -Module $moduleName
                    Write-Host ""
                    Write-Host "Home User Mode: Normal USB operation" -ForegroundColor Green
                    Write-Host "  USB drives will work without restrictions" -ForegroundColor Gray
                }
            }
            $result.Details.BitLockerUSBEnforcement = [bool]$enableBitLockerUSBEnforcement

            # Step 2b: Defender sample submission - Interactive or Config-based.
            # Documented privacy deviation: Microsoft's 26H2 baseline sets
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
                Write-Host "Send ALL file samples to Microsoft?" -ForegroundColor White
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
                Write-Host "      - Maximum cloud-analysis coverage (Microsoft's 26H2 value)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host "Security Note: Both choices keep MAPS cloud protection, Block-at-First-Seen and all ASR rules active" -ForegroundColor DarkGray
                Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor White -NoNewline
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
                    Write-Host "Safe samples only (privacy default) will be applied" -ForegroundColor Green
                }
            }
            $result.Details.SubmitAllSamples = [bool]$submitAllSamples

            # Step 2c: OS SmartScreen level - Interactive or Config-based.
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
                Write-Host "Switch SmartScreen from Block to Warn?" -ForegroundColor White
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
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor White -NoNewline
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
            }
            $result.Details.SmartScreenWarnMode = [bool]$smartScreenWarnMode

            # Step 2d: Standard-user elevation behavior. Strict is the baseline
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
                    if ($StandardUserElevationMode -eq 'SecureDesktop') {
                        Write-Host "Secure-desktop credential prompt for standard users will be applied" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Strict standard-user elevation will be applied (Microsoft baseline value)" -ForegroundColor Green
                    }
                }
            }
            else {
                Write-ModuleLog -Level INFO -Message "Explicit parameter decision: standard-user elevation = $StandardUserElevationMode" -Module $moduleName
            }

            $consentPromptBehaviorUser = if ($StandardUserElevationMode -eq 'SecureDesktop') { 1 } else { 0 }
            $result.Details.StandardUserElevationMode = $StandardUserElevationMode
            $result.Details.ConsentPromptBehaviorUser = $consentPromptBehaviorUser

            # Step 2e: Administrator protection. Credentials is the baseline
            # default; Consent and Classic are Microsoft's documented options.
            if (-not $PSBoundParameters.ContainsKey('AdminProtectionMode')) {
                if ($isNonInteractive) {
                    $AdminProtectionMode = Get-NonInteractiveValue `
                        -Module 'SecurityBaseline' `
                        -Key 'adminProtectionMode' `
                        -Required
                    if ($AdminProtectionMode -cnotin @('Credentials', 'Consent', 'Classic')) {
                        throw "Invalid non-interactive adminProtectionMode: $AdminProtectionMode"
                    }
                    Write-Host "[GUI] Administrator protection: $AdminProtectionMode" -ForegroundColor Cyan
                    Write-ModuleLog -Level INFO -Message "Non-interactive decision: administrator protection = $AdminProtectionMode" -Module $moduleName
                }
                elseif ($DryRun) {
                    $AdminProtectionMode = 'Credentials'
                    Write-ModuleLog -Level INFO -Message 'Interactive DryRun: administrator protection = Credentials (baseline default)' -Module $moduleName
                }
                else {
                    $AdminProtectionMode = Read-AdminProtectionModeChoice
                    Write-ModuleLog -Level INFO -Message "User decision: administrator protection = $AdminProtectionMode" -Module $moduleName
                    Write-Host ""
                    switch ($AdminProtectionMode) {
                        'Consent' { Write-Host "Administrator protection with Yes/No confirmation will be applied" -ForegroundColor Green }
                        'Classic' { Write-Host "Classic User Account Control without Administrator protection will be applied" -ForegroundColor Green }
                        default { Write-Host "Administrator protection with PIN, password or Windows Hello will be applied (Microsoft baseline value)" -ForegroundColor Green }
                    }
                }
            }
            else {
                Write-ModuleLog -Level INFO -Message "Explicit parameter decision: administrator protection = $AdminProtectionMode" -Module $moduleName
            }
            $typeOfAdminApprovalMode = if ($AdminProtectionMode -eq 'Classic') { 1 } else { 2 }
            $result.Details.AdminProtectionMode = $AdminProtectionMode
            $result.Details.TypeOfAdminApprovalMode = $typeOfAdminApprovalMode

            # Apply the selected value through the same secedit template path as
            # the rest of the baseline; the canonical parsed baseline remains strict.
            $securityTemplateConfig = Get-Content -LiteralPath $securityTemplatePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $computerTemplateName = 'MSFT Windows 11 26H2 - Computer'
            $uacInfName = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'
            if (-not ($securityTemplateConfig.PSObject.Properties.Name -contains $computerTemplateName)) {
                throw "Security template section not found: $computerTemplateName"
            }
            $registryValues = $securityTemplateConfig.$computerTemplateName.'Registry Values'
            if (-not ($registryValues.PSObject.Properties.Name -contains $uacInfName)) {
                throw "Security template value not found: $uacInfName"
            }
            $registryValues.PSObject.Properties[$uacInfName].Value = "4,$consentPromptBehaviorUser"
            $adminApprovalInfName = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\TypeOfAdminApprovalMode'
            if (-not ($registryValues.PSObject.Properties.Name -contains $adminApprovalInfName)) {
                throw "Security template value not found: $adminApprovalInfName"
            }
            $registryValues.PSObject.Properties[$adminApprovalInfName].Value = "4,$typeOfAdminApprovalMode"
            # Microsoft's v2 baseline sets the Administrator protection prompt to
            # credentials (1); the Consent choice selects the Yes/No prompt (2).
            $adminProtectionPromptInfName = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorEnhancedAdmin'
            if (-not ($registryValues.PSObject.Properties.Name -contains $adminProtectionPromptInfName)) {
                throw "Security template value not found: $adminProtectionPromptInfName"
            }
            $adminProtectionPrompt = if ($AdminProtectionMode -eq 'Consent') { 2 } else { 1 }
            $registryValues.PSObject.Properties[$adminProtectionPromptInfName].Value = "4,$adminProtectionPrompt"
            $tempSecurityTemplatePath = Join-Path $env:TEMP "SecurityTemplates-$([guid]::NewGuid().ToString('N')).json"
            [System.IO.File]::WriteAllText(
                $tempSecurityTemplatePath,
                ($securityTemplateConfig | ConvertTo-Json -Depth 20),
                [System.Text.UTF8Encoding]::new($false)
            )
            $securityTemplatePath = $tempSecurityTemplatePath
            Write-ModuleLog -Level INFO -Message "ConsentPromptBehaviorUser selected value: $consentPromptBehaviorUser ($StandardUserElevationMode)" -Module $moduleName
            Write-ModuleLog -Level INFO -Message "TypeOfAdminApprovalMode selected value: $typeOfAdminApprovalMode ($AdminProtectionMode)" -Module $moduleName
            Write-ModuleLog -Level INFO -Message "ConsentPromptBehaviorEnhancedAdmin selected value: $adminProtectionPrompt ($AdminProtectionMode)" -Module $moduleName

            # Step 3: Create backup (MUST happen BEFORE applying changes)
            if (-not $DryRun) {
                Write-ModuleLog -Level INFO -Message "Step 3/8: Creating comprehensive backup..." -Module $moduleName

                try {
                    # Initialize Session-based backup (MANDATORY)
                    Restore-NoIDPendingAsrRuntime -Confirm:$false
                    if (-not (Initialize-BackupSystem)) {
                        throw 'Backup system initialization returned failure'
                    }
                    $backupFolder = Start-ModuleBackup -ModuleName $moduleName

                    if (-not $backupFolder) {
                        throw "Failed to create session backup folder"
                    }

                    Write-ModuleLog -Level INFO -Message "Session backup initialized: $backupFolder" -Module $moduleName

                    # Device Guard needs native policy processing. Capture only
                    # its eight GPO values/editor registrations and all derived
                    # local controls before any Save can notify Windows. Never
                    # replace a shared historical Registry.pol or GPO directory.
                    $deviceGuardGpoBackupPath = Join-Path $backupFolder 'DeviceGuardGpo.json'
                    $deviceGuardGpoSnapshot = Backup-SecurityBaselineDeviceGuardGpo -BackupPath $deviceGuardGpoBackupPath
                    $null = Register-BackupFile -FilePath $deviceGuardGpoBackupPath -Type 'SecurityBaseline' `
                        -Name 'DeviceGuardGpo' -Target 'SecurityBaselineDeviceGuardGpo'

                    # Backup 1: Registry Policies
                    Write-ModuleLog -Level INFO -Message "Backing up registry policies..." -Module $moduleName
                    $regBackupPath = Join-Path $backupFolder "RegistryPolicies.json"
                    $regBackup = Backup-RegistryPolicies -ComputerPoliciesPath $computerRegPath `
                        -UserPoliciesPath $userRegPath `
                        -UserRegistryRoot $userRegistryRoot `
                        -AdditionalComputerTargets $deviceGuardPlan.LocalBackupTargets `
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
                        -BackupPath $templateRegistryBackupPath
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
                    Initialize-NoIDDeviceGuardRecovery -SessionPath $global:BackupBasePath
                    if (-not (Assert-SecurityBaselinePrestate)) {
                        throw 'SecurityBaseline sealed prestate changed before Apply'
                    }

                    $result.BackupCreated = $true
                    Write-ModuleLog -Level SUCCESS -Message "Backup created and registered in session: $backupFolder" -Module $moduleName
                }
                catch {
                    $result.Warnings += "Backup failed: $_"
                    Write-ModuleLog -Level WARNING -Message "Backup failed: $_" -Module $moduleName
                    throw "Backup failed; Apply is blocked by the BAVR safety contract. Cause: $($_.Exception.Message)"
                }
            }
            else {
                Write-ModuleLog -Level INFO -Message "Step 3/8: Backup skipped (DryRun mode)" -Module $moduleName
            }

            # Native Device Guard decisions (AFTER the sealed backup). A native
            # GPO Save can trigger policy processing; all artifacts are already
            # sealed. Let Windows process this changed local policy normally,
            # including at startup. A computer-wide forced refresh would also
            # replay unrelated policies and could overwrite the selected ASR action.
            if (-not $DryRun) {
                if ($homeVbsTargets.Count -gt 0) {
                    $registrySnapshot = Get-Content -LiteralPath $regBackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    $result.Details.HomeVbsConfigured = Set-SecurityBaselineHomeVbs `
                        -OperatingSystemSku $operatingSystemSku -Policies $computerPolicies `
                        -RegistrySnapshot $registrySnapshot -Confirm:$false
                    if (-not $result.Details.HomeVbsConfigured) { throw 'Home VBS activation was not configured' }
                    Write-ModuleLog -Level INFO -Message 'Windows Home: local VBS and memory integrity activation configured with the baseline MAT requirement. Verify running protection after restart.' -Module $moduleName
                }
                $result.Details.DeviceGuardGpoChanged = Set-SecurityBaselineDeviceGuardGpo `
                    -Snapshot $deviceGuardGpoSnapshot -Confirm:$false
            }

            # Step 4: Disable Xbox Task (AFTER backup)
            Write-ModuleLog -Level INFO -Message "Step 4/8: Disabling Xbox scheduled task..." -Module $moduleName

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
            Write-ModuleLog -Level INFO -Message "Step 5/8: Configuring BitLocker USB, sample-submission and SmartScreen policies..." -Module $moduleName

            try {
                # Load the owned registry plan written before Backup
                $computerPolicies = Get-Content -LiteralPath $computerRegPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop

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

                    # The PSExec/WMI ASR rule (d1e49aac-...) is the configurable
                    # decision among the 15 ASR values shared with this baseline.
                    # Microsoft ships it as "2" (Audit,
                    # ConfigMgr consideration), the ASR module writes the user's Block/
                    # Audit decision. Verification treats that decision as the
                    # authoritative final expectation (Verify-Complete-Hardening patches
                    # the target from the durable ASR intent), so a standalone
                    # SecurityBaseline Apply must not stomp it back to the package
                    # value. An earlier ASR choice in this same sealed session comes
                    # first: durable intent is published only after the module loop.
                    # Otherwise retain durable ASR intent, the durable QuickAction
                    # override, then the sealed package value, in that order.
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
                    if (-not $DryRun -and -not [string]::IsNullOrWhiteSpace($backupFolder)) {
                        $sessionAsrDecision = Get-SecurityBaselineSessionAsrDecision `
                            -SessionPath (Split-Path -Path $backupFolder -Parent)
                        if ($null -ne $sessionAsrDecision) {
                            $asrRuleAction = [int]$sessionAsrDecision.Action
                            $asrRuleActionSource = [string]$sessionAsrDecision.Source
                        }
                    }
                    $durableIntent = $null
                    try {
                        if ($null -eq $asrRuleAction) { $durableIntent = Read-NoIDIntentState -AllowMissing }
                    }
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
            Write-ModuleLog -Level INFO -Message "Step 6/8: Applying registry policies..." -Module $moduleName

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

            # Step 7: Apply Security Template. LocalAccountTokenFilterPolicy is
            # deliberately left at the Microsoft 26H2 baseline value 0 on both
            # standalone and domain-joined systems; there is no implicit remote-
            # administration compatibility override.
            Write-ModuleLog -Level INFO -Message "Step 7/8: Applying security template..." -Module $moduleName

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

                # The template sets the prompt policy of Administrator protection;
                # this checks the result. Its prestate is sealed in
                # SecurityTemplateRegistryState.
                try {
                    $adminProtection = Set-AdminProtectionPromptBehavior -AdminProtectionMode $AdminProtectionMode
                    $result.Details.ConsentPromptBehaviorEnhancedAdmin = $adminProtection.Value
                    Write-ModuleLog -Level SUCCESS -Message "Administrator protection verified: TypeOfAdminApprovalMode=$($adminProtection.TypeOfAdminApprovalMode), ConsentPromptBehaviorEnhancedAdmin=$($adminProtection.Value) ($AdminProtectionMode)" -Module $moduleName
                }
                catch {
                    $result.Errors += "Administrator protection verification failed: $($_.Exception.Message)"
                    Write-ModuleLog -Level ERROR -Message "Administrator protection verification failed: $_" -Module $moduleName
                }
            }

            # Step 8: Apply Audit Policies
            Write-ModuleLog -Level INFO -Message "Step 8/8: Applying audit policies..." -Module $moduleName

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
            # One blank line before the framework's module result line, as after every other module.
            if (Test-NoIDPlainConsole) { Write-Host "" }

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
        # A later verification or metadata failure does not undo settings that
        # were applied. Preserve their restart recommendation on partial runs.
        $result.RequiresReboot = (-not $DryRun -and $result.SettingsApplied -gt 0)

        Write-ModuleLog -Level INFO -Message "===================================================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "SECURITY BASELINE SUMMARY" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "===================================================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Total Settings Applied: $($result.SettingsApplied)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Total Settings Previewed: $($result.SettingsPreviewed)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Settings Not Applicable: $($result.SettingsNotApplicable)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Registry Policies:  $($result.Details.RegistryPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Security Settings:  $($result.Details.SecuritySettings)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Audit Policies:     $($result.Details.AuditPolicies)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Standard-user UAC:  $($result.Details.StandardUserElevationMode) (ConsentPromptBehaviorUser=$($result.Details.ConsentPromptBehaviorUser))" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Admin protection:   $($result.Details.AdminProtectionMode) (TypeOfAdminApprovalMode=$($result.Details.TypeOfAdminApprovalMode))" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "  - Everyday admin:     $($result.Details.InteractiveAccountIsAdministrator)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Errors: $($result.Errors.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Warnings: $($result.Warnings.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Duration: $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "===================================================================" -Module $moduleName

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

        # Cleanup the owned registry plan created before Backup and patched in Step 5
        if ($tempComputerRegPath -and (Test-Path $tempComputerRegPath)) {
            Remove-Item $tempComputerRegPath -Force -ErrorAction SilentlyContinue
        }
        if ($tempSecurityTemplatePath -and (Test-Path $tempSecurityTemplatePath)) {
            Remove-Item $tempSecurityTemplatePath -Force -ErrorAction SilentlyContinue
        }

        return $result
    }
}
