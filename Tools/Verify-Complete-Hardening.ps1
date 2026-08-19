<#
.SYNOPSIS
    Complete verification of all applied hardening settings.

.DESCRIPTION
    Measures NoID Privacy-managed Windows state from live operating-system
    sources. A parameterless standalone run always inspects all seven modules;
    Repository defaults and backup sessions never select its scope or expected
    values.

    A scoped post-Apply run is a separate transaction-bound contract. It must
    receive the exact module list and temporary configuration used by Apply;
    ASR additionally requires the exact sealed session because its final rule
    actions can depend on live endpoint-management detection.

    Canonical per-module expected counts live in the EXPECTED_*_COUNT constants
    declared just below this header (do not duplicate them in prose -- comments
    drift, the constants are the source of truth). The final report shows the
    reconciled (actual) counts derived from each module's source data, not the
    raw constants.

    Result counters:
      - Verified   : check passed
      - Failed     : check failed (expected != actual)
      - NotChecked : conclusive live evidence is unavailable. Every detail
                     states whether this is a proven exclusion (ByChoice), a
                     missing durable decision (NoSavedChoice), or a runtime /
                     enforcement-authority failure (CannotVerify), with a
                     stable reason, evidence source and affected-target count.
                     Counted separately from Verified so compliance percentages
                     reflect positive verification, not unknown state.
      - NotApplicable: the target is declared but unsupported or absent on the
                       detected Windows edition/build. Never counted as passed.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    # Optional closed module scope for post-Apply profile verification. An
    # omitted value deliberately retains the standalone verifier's complete
    # seven-module behavior.
    [Parameter(Mandatory = $false)]
    [string]$ModulesCsv,

    # Exact effective Apply configuration. Valid only with ModulesCsv; a
    # standalone run never consumes config state as verification authority.
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    # Sealed BAVR session produced by the exact Apply run. Scoped
    # post-Apply verification requires it for ASR so user/detection-dependent
    # rule actions are checked against the applied plan rather than guessed.
    [Parameter(Mandatory = $false)]
    [string]$AppliedSessionPath,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AdvancedSecuritySkipFirewallLayer,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AdvancedSecurityDisableRDP,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$EdgeAllowExtensions,

    # The HTML report is a compliance attestation and names its subject machine
    # by default. This switch produces the shareable variant with the computer
    # name redacted; personal identities (SIDs, user profile paths, e-mail
    # addresses) are always redacted regardless.
    [Parameter(Mandatory = $false)]
    [switch]$RedactComputerName
)

$ErrorActionPreference = 'Stop'

$declaredModuleNames = @(
    'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
    'EdgeHardening', 'AdvancedSecurity'
)
$appliedScopeRun = -not [string]::IsNullOrWhiteSpace($ModulesCsv)
$selectedModuleNames = if (-not $appliedScopeRun) {
    @($declaredModuleNames)
}
else {
    @($ModulesCsv.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
if ($selectedModuleNames.Count -eq 0) {
    throw 'Verification module scope cannot be empty'
}
$duplicateSelectedModules = @($selectedModuleNames | Group-Object | Where-Object Count -gt 1)
if ($duplicateSelectedModules.Count -gt 0) {
    throw "Verification module scope contains duplicates: $($duplicateSelectedModules.Name -join ', ')"
}
$unknownSelectedModules = @($selectedModuleNames | Where-Object { $_ -cnotin $declaredModuleNames })
if ($unknownSelectedModules.Count -gt 0) {
    throw "Verification module scope contains unknown names: $($unknownSelectedModules -join ', ')"
}
$selectedModuleSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($selectedModuleName in $selectedModuleNames) {
    if (-not $selectedModuleSet.Add([string]$selectedModuleName)) {
        throw "Verification module scope contains a duplicate: $selectedModuleName"
    }
}
function Test-VerificationModuleSelected {
    param([Parameter(Mandatory)][string]$Name)
    return $selectedModuleSet.Contains($Name)
}

$totalSteps = 0
foreach ($selectedModuleName in $selectedModuleNames) {
    $totalSteps += if ($selectedModuleName -ceq 'SecurityBaseline') { 3 } else { 1 }
}
$verificationStep = 0
function Write-VerificationStep {
    param([Parameter(Mandatory)][string]$Message)
    $script:verificationStep++
    Write-Host "[$script:verificationStep/$totalSteps] $Message" -ForegroundColor Yellow
}

# Expected per-module counts. The canonical file is required: a partial or
# malformed checkout cannot produce a trustworthy complete-verification report.
$rootPathForCounts = Split-Path $PSScriptRoot -Parent
$settingsCountsPath = Join-Path $rootPathForCounts "Config\SettingsCounts.json"
$settingsCounts = if (Test-Path -LiteralPath $settingsCountsPath -PathType Leaf) {
    Get-Content -LiteralPath $settingsCountsPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
}
else { throw "Canonical settings count file is missing: $settingsCountsPath" }

function _GetCount {
    param([string]$ModuleName, [string]$Key)
    if ($settingsCounts -and $settingsCounts.modules -and $settingsCounts.modules.$ModuleName) {
        $m = $settingsCounts.modules.$ModuleName
        if ($m.PSObject.Properties.Name -contains $Key) {
            $value = [int]$m.$Key
            if ($value -gt 0) { return $value }
        }
    }
    throw "Canonical count is missing or invalid: $ModuleName.$Key"
}

function _GetPrivacyModeCount {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MSRecommended', 'Strict', 'Paranoid')]
        [string]$Mode
    )

    $privacy = $settingsCounts.modules.Privacy
    if ($privacy -and $privacy.PSObject.Properties.Name -contains 'modeTotals' -and
        $privacy.modeTotals -and $privacy.modeTotals.PSObject.Properties.Name -contains $Mode) {
        $value = [int]$privacy.modeTotals.$Mode
        if ($value -gt 0) { return $value }
    }
    throw "Canonical Privacy mode count is missing or invalid: $Mode"
}

$EXPECTED_REGISTRY_COUNT = _GetCount -ModuleName 'SecurityBaseline' -Key 'registry'
$EXPECTED_SECURITY_COUNT = _GetCount -ModuleName 'SecurityBaseline' -Key 'securityTemplate'
$EXPECTED_AUDIT_COUNT    = _GetCount -ModuleName 'SecurityBaseline' -Key 'auditPolicies'
$EXPECTED_ASR_COUNT      = _GetCount -ModuleName 'ASR'              -Key 'rules'
$EXPECTED_EDGE_COUNT     = _GetCount -ModuleName 'EdgeHardening'    -Key 'policies'
$EXPECTED_ADVANCED_COUNT = _GetCount -ModuleName 'AdvancedSecurity' -Key 'settings'
$EXPECTED_DNS_COUNT      = _GetCount -ModuleName 'DNS'              -Key 'checks'
$EXPECTED_PRIVACY_COUNT  = _GetCount -ModuleName 'Privacy'          -Key 'total'
$EXPECTED_ANTIAI_COUNT   = _GetCount -ModuleName 'AntiAI'           -Key 'total'
$privacyModeCounts = @(
    foreach ($privacyModeName in @('MSRecommended', 'Strict', 'Paranoid')) {
        _GetPrivacyModeCount -Mode $privacyModeName
    }
)
$EXPECTED_PRIVACY_PRODUCT_COUNT = [int](
    ($privacyModeCounts | Measure-Object -Maximum).Maximum
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NoID Privacy - Verification" -ForegroundColor Cyan
Write-Host $(if ($selectedModuleNames.Count -eq $declaredModuleNames.Count) {
        $(if ($appliedScopeRun) { '  Applied Scope Check: all modules' } else { '  Complete Live-State Check' })
    } else {
        "  Applied Scope Check: $($selectedModuleNames -join ', ')"
    }) -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date

# Get root path (since script is in Tools/ subdirectory)
$rootPath = Split-Path $PSScriptRoot -Parent

$privacyPresentationHelperPath = Join-Path $PSScriptRoot 'Private\Get-PrivacyVerificationPresentation.ps1'
if (-not (Test-Path -LiteralPath $privacyPresentationHelperPath -PathType Leaf)) {
    throw "Privacy presentation helper is missing: $privacyPresentationHelperPath"
}
. $privacyPresentationHelperPath

$modulePresentationHelperPath = Join-Path $PSScriptRoot 'Private\Get-VerificationModulePresentation.ps1'
if (-not (Test-Path -LiteralPath $modulePresentationHelperPath -PathType Leaf)) {
    throw "Verification module presentation helper is missing: $modulePresentationHelperPath"
}
. $modulePresentationHelperPath

$notCheckedAccountingHelperPath = Join-Path $PSScriptRoot 'Private\Get-VerificationNotCheckedAccounting.ps1'
if (-not (Test-Path -LiteralPath $notCheckedAccountingHelperPath -PathType Leaf)) {
    throw "Verification NotChecked accounting helper is missing: $notCheckedAccountingHelperPath"
}
. $notCheckedAccountingHelperPath

if (Test-VerificationModuleSelected 'DNS') {
    $dnsKeepHelperPath = Join-Path $PSScriptRoot 'Private\Test-DNSKeepDecision.ps1'
    if (-not (Test-Path -LiteralPath $dnsKeepHelperPath -PathType Leaf)) {
        throw "Required DNS intent helper is missing: $dnsKeepHelperPath"
    }
    . $dnsKeepHelperPath
    foreach ($dnsHelper in @(
            'ConvertTo-DnsCanonicalAddress.ps1',
            'DnsInterfaceDoh.ps1'
        )) {
        $dnsHelperPath = Join-Path $rootPath "Modules\DNS\Private\$dnsHelper"
        if (-not (Test-Path -LiteralPath $dnsHelperPath -PathType Leaf)) {
            throw "Required DNS verification helper is missing: $dnsHelperPath"
        }
        . $dnsHelperPath
    }
    $dnsTakeoverEvidenceHelperPath = Join-Path $PSScriptRoot 'Private\Test-DNSManagedTakeoverEvidence.ps1'
    if (-not (Test-Path -LiteralPath $dnsTakeoverEvidenceHelperPath -PathType Leaf)) {
        throw "Required DNS takeover-evidence helper is missing: $dnsTakeoverEvidenceHelperPath"
    }
    . $dnsTakeoverEvidenceHelperPath
}

$securityProductHelperPath = Join-Path $rootPath 'Utils\SecurityProducts.ps1'
if (-not (Test-Path -LiteralPath $securityProductHelperPath -PathType Leaf)) {
    throw "Security-product identity helper is missing: $securityProductHelperPath"
}
. $securityProductHelperPath

# AntiAI is the only verifier section that consumes the shared interactive-user
# context. Do not make a DNS-only (or any other non-AntiAI) verification depend
# on an unrelated SecurityBaseline helper. When AntiAI is selected, resolve the
# everyday Explorer account instead of classifying the elevated PowerShell
# identity used after separate administrator credentials were supplied for UAC.
$verifierUserContext = $null
if (Test-VerificationModuleSelected 'AntiAI') {
    $securityBaselineUserContextPath = Join-Path $rootPath 'Modules\SecurityBaseline\Private\Get-SecurityBaselineUserContext.ps1'
    if (-not (Test-Path -LiteralPath $securityBaselineUserContextPath -PathType Leaf)) {
        throw "SecurityBaseline user-context helper is missing: $securityBaselineUserContextPath"
    }
    . $securityBaselineUserContextPath
    $verifierUserContext = Get-SecurityBaselineUserContext
}

# Choice-aware expectations exist only inside an exact scoped post-Apply run.
# A standalone run is a live measurement and must not consume repository
# defaults, a GUI state file, or a backup session as hidden intent.
$frameworkConfig = $null
$frameworkConfigPath = $null
$frameworkConfigBase64 = [string]$env:NOIDPRIVACY_CONFIG_JSON_BASE64
$verificationConfigSha256 = ''
if ($appliedScopeRun) {
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and
        -not [string]::IsNullOrWhiteSpace($frameworkConfigBase64)) {
        throw 'Scoped post-Apply verification received both file-backed and in-memory Apply configuration'
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -and
        [string]::IsNullOrWhiteSpace($frameworkConfigBase64)) {
        throw 'Scoped post-Apply verification requires the exact effective Apply configuration'
    }
    try {
        if (-not [string]::IsNullOrWhiteSpace($frameworkConfigBase64)) {
            $frameworkConfigJson = [System.Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($frameworkConfigBase64)
            )
        }
        else {
            $frameworkConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
            if (-not (Test-Path -LiteralPath $frameworkConfigPath -PathType Leaf)) {
                throw "Effective Apply configuration is missing: $frameworkConfigPath"
            }
            $frameworkConfigJson = Get-Content -LiteralPath $frameworkConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
        }
        $frameworkConfigBytes = [System.Text.Encoding]::UTF8.GetBytes($frameworkConfigJson)
        $frameworkConfigHasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $verificationConfigSha256 = [System.BitConverter]::ToString(
                $frameworkConfigHasher.ComputeHash($frameworkConfigBytes)
            ).Replace('-', '').ToLowerInvariant()
        }
        finally { $frameworkConfigHasher.Dispose() }
        $frameworkConfig = $frameworkConfigJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Effective Apply configuration could not be parsed: $($_.Exception.Message)"
    }
    if (-not $frameworkConfig -or -not $frameworkConfig.modules) {
        throw 'Scoped verification requires a complete effective module configuration'
    }
    $enabledConfigModules = @()
    foreach ($declaredModuleName in $declaredModuleNames) {
        $moduleConfig = $frameworkConfig.modules.$declaredModuleName
        if (-not $moduleConfig -or -not ($moduleConfig.PSObject.Properties.Name -contains 'enabled') -or
            $moduleConfig.enabled -isnot [bool]) {
            throw "Effective module enabled decision is missing or non-Boolean: $declaredModuleName"
        }
        if ([bool]$moduleConfig.enabled) { $enabledConfigModules += $declaredModuleName }
    }
    $scopeDifference = @(Compare-Object `
            -ReferenceObject @($enabledConfigModules | Sort-Object) `
            -DifferenceObject @($selectedModuleNames | Sort-Object))
    if ($scopeDifference.Count -ne 0) {
        throw "Requested verification scope does not match the enabled Apply configuration"
    }
}
else {
    $standaloneIntentParameters = @(
        'ConfigPath', 'AppliedSessionPath', 'AdvancedSecuritySkipFirewallLayer',
        'AdvancedSecurityDisableRDP', 'EdgeAllowExtensions'
    ) | Where-Object { $PSBoundParameters.ContainsKey($_) }
    if ($standaloneIntentParameters.Count -gt 0) {
        throw "Standalone live-state verification does not accept Apply-intent parameters: $($standaloneIntentParameters -join ', ')"
    }
    if (-not [string]::IsNullOrWhiteSpace($frameworkConfigBase64)) {
        throw 'Standalone live-state verification does not consume an inherited in-memory Apply configuration'
    }
}

$standaloneIntentState = $null
$standaloneIntentUsesEarlierEngine = $false
$standaloneIntentStatus = if ($appliedScopeRun) { 'Exact transaction-bound Apply configuration' } else { 'No durable Apply intent found' }
# Applied-scope runs need the intent reader too: the transaction-bound
# SecurityBaseline record of the applied session carries the PSExec/WMI ASR
# decision the Apply actually used (see below).
$intentHelperPath = Join-Path $rootPath 'Core\IntentState.ps1'
if (-not (Test-Path -LiteralPath $intentHelperPath -PathType Leaf)) {
    throw "Apply-intent helper is missing: $intentHelperPath"
}
. $intentHelperPath
if (-not $appliedScopeRun) {
    try {
        $intentCandidate = Read-NoIDIntentState -AllowMissing
        if ($intentCandidate) {
            $currentEngineFingerprint = Get-NoIDEngineContractFingerprint
            $standaloneIntentState = $intentCandidate
            $standaloneIntentUsesEarlierEngine = [string]$intentCandidate.engineContractFingerprint -cne $currentEngineFingerprint
            $standaloneIntentStatus = if (-not $standaloneIntentUsesEarlierEngine) {
                "Durable Apply intent recorded $([string]$intentCandidate.updatedAt)"
            }
            else {
                "Schema-valid durable Apply intent recorded $([string]$intentCandidate.updatedAt) by earlier engine content; current per-module inventory checks still apply"
            }
        }
    }
    catch {
        $standaloneIntentState = $null
        $standaloneIntentUsesEarlierEngine = $false
        $standaloneIntentStatus = "Durable Apply intent is unreadable and was ignored: $($_.Exception.Message)"
    }
    if (-not $standaloneIntentState) {
        Write-Host 'Saved Apply choices are unavailable; affected optional decisions will be reported as INCOMPLETE.' -ForegroundColor Yellow
    }
    elseif ($standaloneIntentUsesEarlierEngine) {
        Write-Host 'Saved Apply choices were recorded by earlier Engine content; current inventories are still validated.' -ForegroundColor Yellow
    }
}

function Get-StandaloneModuleIntent {
    param([Parameter(Mandatory)][string]$ModuleName)
    if (-not $standaloneIntentState -or -not $standaloneIntentState.modules) { return $null }
    $property = $standaloneIntentState.modules.PSObject.Properties[$ModuleName]
    if (-not $property) { return $null }
    return $property.Value.intent
}

$securityBaselineIntent = Get-StandaloneModuleIntent -ModuleName 'SecurityBaseline'
$advancedSecurityIntent = Get-StandaloneModuleIntent -ModuleName 'AdvancedSecurity'
$edgeHardeningIntent = Get-StandaloneModuleIntent -ModuleName 'EdgeHardening'
$dnsIntent = Get-StandaloneModuleIntent -ModuleName 'DNS'
$privacyIntent = Get-StandaloneModuleIntent -ModuleName 'Privacy'
$asrIntent = Get-StandaloneModuleIntent -ModuleName 'ASR'
$antiAIIntent = Get-StandaloneModuleIntent -ModuleName 'AntiAI'
$antiAIPlanIntentKnown = [bool]($antiAIIntent -and
    $antiAIIntent.PSObject.Properties['applicableTargets'] -and
    $antiAIIntent.PSObject.Properties['notApplicableTargets'])

$uacModeIsAuthoritative = $appliedScopeRun -or $null -ne $securityBaselineIntent
$configuredUacMode = $null
if ($appliedScopeRun) {
    if (-not $frameworkConfig.modules.SecurityBaseline -or
        $frameworkConfig.modules.SecurityBaseline.PSObject.Properties.Name -notcontains 'standardUserElevationMode') {
        throw 'The exact Apply configuration is missing SecurityBaseline.standardUserElevationMode'
    }
    $configuredUacMode = [string]$frameworkConfig.modules.SecurityBaseline.standardUserElevationMode
}
elseif ($securityBaselineIntent) {
    $configuredUacMode = [string]$securityBaselineIntent.standardUserElevationMode
}
if ($uacModeIsAuthoritative -and $configuredUacMode -notin @('Strict', 'SecureDesktop')) {
    throw "Invalid SecurityBaseline.standardUserElevationMode in the exact Apply configuration: $configuredUacMode"
}
$configuredConsentPromptBehaviorUser = if (-not $uacModeIsAuthoritative) { $null }
    elseif ($configuredUacMode -eq 'SecureDesktop') { '4,1' }
    else { '4,0' }

$bitLockerUsbChoiceIsAuthoritative = $appliedScopeRun -or $null -ne $securityBaselineIntent
$configuredBitLockerUsbEnforcement = $false
if ($appliedScopeRun -and $frameworkConfig.modules.SecurityBaseline -and
    $frameworkConfig.modules.SecurityBaseline.PSObject.Properties.Name -contains 'bitLockerUSBEnforcement') {
    if ($frameworkConfig.modules.SecurityBaseline.bitLockerUSBEnforcement -isnot [bool]) {
        throw 'SecurityBaseline.bitLockerUSBEnforcement in the exact Apply configuration must be Boolean'
    }
    $configuredBitLockerUsbEnforcement = [bool]$frameworkConfig.modules.SecurityBaseline.bitLockerUSBEnforcement
}
elseif ($securityBaselineIntent) {
    $configuredBitLockerUsbEnforcement = [bool]$securityBaselineIntent.bitLockerUSBEnforcement
}
elseif ($bitLockerUsbChoiceIsAuthoritative) {
    throw 'Authoritative non-interactive verification requires SecurityBaseline.bitLockerUSBEnforcement'
}

# Defender sample submission follows the same decision contract: the shipped
# privacy default is 1 (safe samples only, documented deviation from
# Microsoft's 3), the Apply choice may restore 3. Authoritative
# non-interactive configs pin the expectation; otherwise both decision
# values are legitimate owned state, never drift.
$submitSamplesChoiceIsAuthoritative = $bitLockerUsbChoiceIsAuthoritative
$configuredSubmitAllSamples = $false
if ($appliedScopeRun -and $frameworkConfig.modules.SecurityBaseline -and
    $frameworkConfig.modules.SecurityBaseline.PSObject.Properties.Name -contains 'submitAllSamples') {
    if ($frameworkConfig.modules.SecurityBaseline.submitAllSamples -isnot [bool]) {
        throw 'SecurityBaseline.submitAllSamples in the exact Apply configuration must be Boolean'
    }
    $configuredSubmitAllSamples = [bool]$frameworkConfig.modules.SecurityBaseline.submitAllSamples
}
elseif ($securityBaselineIntent) {
    $configuredSubmitAllSamples = [bool]$securityBaselineIntent.submitAllSamples
}
elseif ($submitSamplesChoiceIsAuthoritative) {
    throw 'Authoritative non-interactive verification requires SecurityBaseline.submitAllSamples'
}

# The OS SmartScreen level is the third documented decision value: Block is
# Microsoft's baseline value and the shipped default, Warn the documented
# security-reducing compatibility choice (interactive Apply prompt, config
# key, or the GUI's SmartScreen quick action).
$smartScreenChoiceIsAuthoritative = $bitLockerUsbChoiceIsAuthoritative
$configuredSmartScreenWarnMode = $false
if ($appliedScopeRun -and $frameworkConfig.modules.SecurityBaseline -and
    $frameworkConfig.modules.SecurityBaseline.PSObject.Properties.Name -contains 'smartScreenWarnMode') {
    if ($frameworkConfig.modules.SecurityBaseline.smartScreenWarnMode -isnot [bool]) {
        throw 'SecurityBaseline.smartScreenWarnMode in the exact Apply configuration must be Boolean'
    }
    $configuredSmartScreenWarnMode = [bool]$frameworkConfig.modules.SecurityBaseline.smartScreenWarnMode
}
elseif ($securityBaselineIntent) {
    $configuredSmartScreenWarnMode = [bool]$securityBaselineIntent.smartScreenWarnMode
}
elseif ($smartScreenChoiceIsAuthoritative) {
    throw 'Authoritative non-interactive verification requires SecurityBaseline.smartScreenWarnMode'
}

# The PSExec/WMI ASR rule (d1e49aac-...) is the one baseline registry value
# whose final expectation belongs to the recorded ASR decision. Apply aligns
# the written value with that decision and records what it used in the
# SecurityBaseline intent record of the same session (asrActionOverrides).
# An applied-scope run is transaction-bound, so it consumes exactly that
# session's record - never the free-floating durable state a standalone run
# reads. A record from another session (or a failed intent write) yields no
# override, the sealed package value stays the expectation, and a divergent
# write then fails verification honestly.
$authoritativeBaselineAsrOverrides = @()
if ($appliedScopeRun) {
    if (-not [string]::IsNullOrWhiteSpace($AppliedSessionPath)) {
        try {
            $appliedManifestPath = Join-Path $AppliedSessionPath 'manifest.json'
            $appliedSessionId = [string](Get-Content -LiteralPath $appliedManifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop).sessionId
            $sessionIntentState = Read-NoIDIntentState -AllowMissing
            $sessionBaselineRecord = if ($sessionIntentState -and $sessionIntentState.modules) {
                $sessionIntentState.modules.PSObject.Properties['SecurityBaseline']
            } else { $null }
            if ($sessionBaselineRecord -and
                -not [string]::IsNullOrWhiteSpace($appliedSessionId) -and
                [string]$sessionBaselineRecord.Value.sourceKind -ceq 'ApplySession' -and
                [string]$sessionBaselineRecord.Value.sourceId -ceq $appliedSessionId) {
                $authoritativeBaselineAsrOverrides = @(
                    $sessionBaselineRecord.Value.intent.asrActionOverrides | Where-Object { $null -ne $_ })
            }
        }
        catch {
            Write-Host "Transaction-bound SecurityBaseline intent record is unavailable; the sealed package value stays the PSExec/WMI expectation: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
elseif ($securityBaselineIntent -and $securityBaselineIntent.PSObject.Properties['asrActionOverrides']) {
    $authoritativeBaselineAsrOverrides = @(
        $securityBaselineIntent.asrActionOverrides | Where-Object { $null -ne $_ })
}

$advancedFirewallDecisionKnown = $PSBoundParameters.ContainsKey('AdvancedSecuritySkipFirewallLayer')
$advancedSkipFirewallLayer = if ($advancedFirewallDecisionKnown) {
    [bool]$AdvancedSecuritySkipFirewallLayer
}
elseif ($appliedScopeRun -and
    $frameworkConfig.modules -and $frameworkConfig.modules.AdvancedSecurity -and
    $frameworkConfig.modules.AdvancedSecurity.PSObject.Properties.Name -contains 'skipFirewallLayer') {
    $advancedFirewallDecisionKnown = $true
    [bool]$frameworkConfig.modules.AdvancedSecurity.skipFirewallLayer
}
elseif ($advancedSecurityIntent) {
    $advancedFirewallDecisionKnown = $true
    [bool]$advancedSecurityIntent.skipFirewallLayer
}
else {
    $false
}
# Resolve the profile BEFORE any choice that the profile overrides. The raw
# config keys are not the engine's decision: Invoke-AdvancedSecurity clamps
# several of them by profile and never reads the stored value outside its own
# gate, so consuming the key verbatim measures a machine against an expectation
# the Apply provably never had. Durable-intent values need no clamping - the
# engine recorded the effective decision there, not the raw request.
$advancedChoicesAuthoritative = $appliedScopeRun -or $null -ne $advancedSecurityIntent
$advancedConfiguredProfile = if ($appliedScopeRun -and $frameworkConfig.modules.AdvancedSecurity) {
    [string]$frameworkConfig.modules.AdvancedSecurity.securityProfile
} elseif ($advancedSecurityIntent) { [string]$advancedSecurityIntent.securityProfile } else { 'Unknown' }
if ($advancedChoicesAuthoritative -and $advancedConfiguredProfile -notin @('Balanced','Enterprise','Maximum')) {
    throw "Authoritative AdvancedSecurity profile is invalid: $advancedConfiguredProfile"
}

$advancedRdpDecisionKnown = $PSBoundParameters.ContainsKey('AdvancedSecurityDisableRDP')
$advancedDisableRdp = if ($advancedRdpDecisionKnown) {
    [bool]$AdvancedSecurityDisableRDP
}
elseif ($appliedScopeRun -and
    $frameworkConfig.modules -and $frameworkConfig.modules.AdvancedSecurity -and
    $frameworkConfig.modules.AdvancedSecurity.PSObject.Properties.Name -contains 'disableRDP') {
    $advancedRdpDecisionKnown = $true
    # Invoke-AdvancedSecurity.ps1:394-398 - Maximum always disables RDP,
    # Enterprise never does (it only hardens NLA/TLS) and only Balanced honours
    # the key. Reading it raw reported "Expected DWord/1, Actual Missing" as a
    # Failed check on an Enterprise host the Apply had deliberately left alone.
    switch ($advancedConfiguredProfile) {
        'Maximum'    { $true }
        'Enterprise' { $false }
        default      { [bool]$frameworkConfig.modules.AdvancedSecurity.disableRDP }
    }
}
elseif ($advancedSecurityIntent) {
    $advancedRdpDecisionKnown = $true
    [bool]$advancedSecurityIntent.disableRDP
}
else {
    $false
}
$advancedDiscoveryExpected = $advancedChoicesAuthoritative -and $advancedConfiguredProfile -eq 'Maximum' -and
    $(if ($appliedScopeRun) { [bool]$frameworkConfig.modules.AdvancedSecurity.disableDiscoveryProtocols } else { [bool]$advancedSecurityIntent.disableDiscoveryProtocols })
$advancedWirelessFullExpected = $advancedChoicesAuthoritative -and $(if ($appliedScopeRun) { [bool]$frameworkConfig.modules.AdvancedSecurity.disableWirelessDisplay } else { [bool]$advancedSecurityIntent.disableWirelessDisplay })
$advancedIPv6Expected = $advancedChoicesAuthoritative -and $advancedConfiguredProfile -eq 'Maximum' -and
    $(if ($appliedScopeRun) { [bool]$frameworkConfig.modules.AdvancedSecurity.disableIPv6 } else { [bool]$advancedSecurityIntent.disableIPv6 })

$edgeExtensionDecisionKnown = $PSBoundParameters.ContainsKey('EdgeAllowExtensions')
$edgeAllowExtensionsSelected = if ($edgeExtensionDecisionKnown) {
    [bool]$EdgeAllowExtensions
}
elseif ($appliedScopeRun -and
    $frameworkConfig.modules -and $frameworkConfig.modules.EdgeHardening -and
    $frameworkConfig.modules.EdgeHardening.PSObject.Properties.Name -contains 'allowExtensions') {
    $edgeExtensionDecisionKnown = $true
    [bool]$frameworkConfig.modules.EdgeHardening.allowExtensions
}
elseif ($edgeHardeningIntent) {
    $edgeExtensionDecisionKnown = $true
    [bool]$edgeHardeningIntent.allowExtensions
}
else { $false }

$privacyChoicesAuthoritative = $false
$upnpConfigured = $false
$adminConfigured = $false

# Standalone use defaults to all seven declared modules. A caller may provide a
# closed module scope only when it is verifying a specific just-applied run.
$totalSettings = 0
$productTargetInventory = 0
foreach ($selectedModuleName in $selectedModuleNames) {
    $selectedModuleDefaultCount = switch ($selectedModuleName) {
        'SecurityBaseline' { $EXPECTED_REGISTRY_COUNT + $EXPECTED_SECURITY_COUNT + $EXPECTED_AUDIT_COUNT }
        'ASR' { $EXPECTED_ASR_COUNT }
        'DNS' { $EXPECTED_DNS_COUNT }
        'Privacy' { $EXPECTED_PRIVACY_COUNT }
        'AntiAI' { $EXPECTED_ANTIAI_COUNT }
        'EdgeHardening' { $EXPECTED_EDGE_COUNT }
        'AdvancedSecurity' { $EXPECTED_ADVANCED_COUNT }
        default { throw "Unexpected selected module: $selectedModuleName" }
    }
    $totalSettings += $selectedModuleDefaultCount
    $productTargetInventory += if ($selectedModuleName -ceq 'Privacy') {
        $EXPECTED_PRIVACY_PRODUCT_COUNT
    }
    else { $selectedModuleDefaultCount }
}

$results = [PSCustomObject]@{
    SelectedModules          = @($selectedModuleNames)
    TotalSettings            = $totalSettings
    ProductTargetInventory   = $productTargetInventory
    RegistrySettings         = $EXPECTED_REGISTRY_COUNT
    SecurityTemplate         = $EXPECTED_SECURITY_COUNT
    AuditPolicies            = $EXPECTED_AUDIT_COUNT
    ASRRules                 = $EXPECTED_ASR_COUNT
    EdgeHardeningPolicies    = $EXPECTED_EDGE_COUNT
    AdvancedSecuritySettings = $EXPECTED_ADVANCED_COUNT
    DNSChecks                = $EXPECTED_DNS_COUNT
    PrivacyChecks            = $EXPECTED_PRIVACY_COUNT
    AntiAIPolicies           = $EXPECTED_ANTIAI_COUNT
    Verified                 = 0
    Failed                   = 0
    NotChecked               = 0  # Declared checks without conclusive live evidence; disposition explains why.
    NotCheckedDeliberate     = 0  # Subset proven excluded by an Apply choice or an authoritative Windows-state choice marker.
    NotCheckedNoSavedChoice  = 0  # Subset whose optional decision cannot be recovered from durable evidence.
    NotCheckedCannotVerify   = 0  # Subset blocked by a runtime query or enforcement-authority failure.
    NotApplicable            = 0  # Declared targets unsupported/absent on this Windows installation
    VerificationComplete     = $false
    AppliedScopeRun          = $appliedScopeRun
    FailedSettings           = @()
    AllSettings              = @()  # Track ALL settings for complete HTML report
    Duration                 = $null
    PrivacyMode              = $null  # Active Privacy mode; selected scope is mode-dependent while product inventory stays stable.
    # Declared target count per mode, so the report can tell "we counted the
    # maximum scope" apart from "we counted a smaller scope" instead of inferring
    # a magnitude from the absence of PrivacyMode.
    PrivacyModeTotals        = [PSCustomObject]@{
        MSRecommended = _GetPrivacyModeCount -Mode 'MSRecommended'
        Strict        = _GetPrivacyModeCount -Mode 'Strict'
        Paranoid      = _GetPrivacyModeCount -Mode 'Paranoid'
    }
    PrivacyProfileScorecards = @()
    IntentReference          = $standaloneIntentStatus
}

# Load configuration files
$baseConfigPath = Join-Path $rootPath "Modules\SecurityBaseline\ParsedSettings"
$asrConfigPath = Join-Path $rootPath "Modules\ASR\Config"
$declaredAsrRules = @()
$sealedAppliedAsrPlan = $null
if (Test-VerificationModuleSelected 'ASR') {
    $declaredAsrRules = Get-Content -LiteralPath (Join-Path $asrConfigPath 'ASR-Rules.json') -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ($declaredAsrRules.Count -ne $EXPECTED_ASR_COUNT) {
        throw "ASR declared-scope drift: JSON=$($declaredAsrRules.Count), expected=$EXPECTED_ASR_COUNT"
    }

    if ($appliedScopeRun -and [string]::IsNullOrWhiteSpace($AppliedSessionPath)) {
        throw 'Scoped post-Apply ASR verification requires the exact applied BAVR session path'
    }
    if (-not [string]::IsNullOrWhiteSpace($AppliedSessionPath)) {
        $sealedAsrPlanHelper = Join-Path $rootPath 'Tools\Private\Get-SealedAppliedAsrPlan.ps1'
        if (-not (Test-Path -LiteralPath $sealedAsrPlanHelper -PathType Leaf)) {
            throw "Sealed ASR plan helper is missing: $sealedAsrPlanHelper"
        }
        . $sealedAsrPlanHelper
        $sealedAppliedAsrPlan = Get-SealedAppliedAsrPlan `
            -SessionPath $AppliedSessionPath `
            -DeclaredRules $declaredAsrRules
    }
    elseif ($asrIntent) {
        $intentActions = @($asrIntent.requestedActions)
        $intentActionMap = @{}
        foreach ($intentAction in $intentActions) {
            $intentGuid = ([Guid]([string]$intentAction.Guid)).ToString('D').ToLowerInvariant()
            if ($intentActionMap.ContainsKey($intentGuid) -or [int]$intentAction.Action -notin @(0, 1, 2, 6)) {
                throw "Durable ASR intent contains a duplicate GUID or unsupported action: $intentGuid"
            }
            $intentActionMap[$intentGuid] = [int]$intentAction.Action
        }
        $applicableDeclaredIds = @($declaredAsrRules | Where-Object {
                -not ($_.PSObject.Properties.Name -contains 'WindowsClientApplicable') -or [bool]$_.WindowsClientApplicable
            } | ForEach-Object { ([Guid]([string]$_.GUID)).ToString('D').ToLowerInvariant() })
        if (@(Compare-Object -ReferenceObject ($applicableDeclaredIds | Sort-Object) `
                -DifferenceObject @($intentActionMap.Keys | Sort-Object)).Count -ne 0) {
            throw 'Durable ASR intent does not match the current applicable declared rule inventory'
        }
        $sealedAppliedAsrPlan = [PSCustomObject]@{
            ActionMap = $intentActionMap
            Source = 'DurableApplyIntent'
        }
    }
}

# =============================================================================
# MUTATION EXCLUSION
# =============================================================================
# Apply, Restore and Quick Actions serialize every mutation on this mutex
# (Core/Framework.ps1, Core/QuickActions.ps1) - but the verifier never took it,
# so the operator could toggle RDP from Quick Actions while a multi-minute
# verification was mid-measurement. The verifier had already counted the old
# value as Verified and then sealed a hash-bound "complete" report for a machine
# whose state it never measured. Hold the same mutex for the whole run: a
# running mutation blocks verification from starting, and a mutation attempted
# during verification receives the same 'Busy' answer it already handles.
# An explicit release happens after the machine contract is emitted; on any
# abnormal termination the abandoned mutex is treated as acquired by the next
# holder, exactly as the two existing acquire sites already do.
$script:NoIDVerifierMutationMutex = [Threading.Mutex]::new($false, 'Global\NoIDPrivacyMutationV1')
$script:NoIDVerifierMutationMutexHeld = $false
try {
    $script:NoIDVerifierMutationMutexHeld = $script:NoIDVerifierMutationMutex.WaitOne(0, $false)
}
catch [Threading.AbandonedMutexException] {
    $script:NoIDVerifierMutationMutexHeld = $true
}
if (-not $script:NoIDVerifierMutationMutexHeld) {
    throw 'Another NoID Privacy Apply, Restore or Quick Action is currently mutating the machine; verification refuses to measure a moving target. Retry when it completes.'
}

# The whole measurement runs inside this try; the paired finally before the
# final status block below is the only release site. Without it, any of the
# reconciliation gates that throw between here and the contract emission left
# the mutex held for the lifetime of an in-process caller (the interactive
# menu keeps running after catching the throw), permanently answering every
# later Apply/Restore/Quick Action with 'Busy'. The body is deliberately not
# re-indented.
try {

# =============================================================================
# HELPER FUNCTION: Extract Registry Checks from JSON Configuration
# =============================================================================
# This function recursively parses module JSON files and extracts registry checks.
# Supports both Privacy-style (Category > Path > Value) and AntiAI-style (Features > Registry > Path > Value)
#
# Returns array of: @{ Path = "HKLM:\..."; Name = "ValueName"; Value = expected; Desc = "Description"; Type = "DWord" }
#
function Get-RegistryChecksFromJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeCategories = @()
    )

    $checks = @()

    if (-not (Test-Path $JsonPath)) {
        Write-Warning "JSON file not found: $JsonPath"
        return $checks
    }

    $config = Get-Content $JsonPath -Raw | ConvertFrom-Json

    # Recursive function to find registry paths in any JSON structure.
    # Take ExcludeCategories explicitly (rather than relying on PowerShell's
    # dynamic-scope lookup from the parent Get-RegistryChecksFromJson) so the
    # data flow is visible at each call site and PSSA can track param usage.
    function Find-RegistrySettings {
        param(
            $Object,
            $ParentPath = "",
            [string[]]$ExcludeCategories = @()
        )

        $foundChecks = @()

        if ($null -eq $Object) { return $foundChecks }

        foreach ($prop in $Object.PSObject.Properties) {
            $propName = $prop.Name
            $propValue = $prop.Value

            # Skip metadata and excluded categories
            # NOTE: EnterpriseProtection is NOT skipped - it contains valid registry paths!
            if ($propName -in @('Mode', 'Description', 'BestFor', 'Warnings', 'Services', 'ScheduledTasks',
                    'Summary', 'AutomaticallyBlockedByMasterSwitch', 'ModuleName', 'Version',
                    'TotalFeatures', 'TotalPolicies', 'URIHandlers', 'Note', 'FilePath',
                    'HostsEntries', 'CloudBased', 'RequiresReboot',
                    'RequiresADMX', 'Impact', 'Name')) {
                continue
            }

            # Skip caller-specified categories on top of the metadata block above
            if ($propName -in $ExcludeCategories) {
                continue
            }

            # Check if this is a registry path (starts with HK)
            if ($propName -match '^HK(LM|CU|CR|U):\\') {
                $regPath = $propName

                # Iterate through values under this registry path
                if ($propValue -is [PSCustomObject]) {
                    foreach ($valueProp in $propValue.PSObject.Properties) {
                        $valueName = $valueProp.Name
                        $valueDef = $valueProp.Value

                        # Extract expected value and description
                        if ($valueDef -is [PSCustomObject]) {
                            $expectedValue = $null
                            $description = $valueName
                            $valueType = "DWord"

                            # Handle different property names for the value
                            if ($null -ne $valueDef.Value) {
                                $expectedValue = $valueDef.Value
                            }
                            if ($null -ne $valueDef.value) {
                                $expectedValue = $valueDef.value
                            }

                            if ($valueDef.Description) {
                                $description = $valueDef.Description
                            }
                            if ($valueDef.Type) {
                                $valueType = $valueDef.Type
                            }
                            if ($valueDef.type) {
                                $valueType = $valueDef.type
                            }

                            # Only add if we have an expected value
                            if ($null -ne $expectedValue) {
                                $foundChecks += [PSCustomObject]@{
                                    Path  = $regPath
                                    Name  = $valueName
                                    Value = $expectedValue
                                    Desc  = $description
                                    Type  = $valueType
                                }
                            }
                        }
                    }
                }
            }
            # Recurse into nested objects (Categories, Features, Registry blocks).
            # Pass ExcludeCategories down so the recursion honors it consistently.
            elseif ($propValue -is [PSCustomObject]) {
                $foundChecks += Find-RegistrySettings -Object $propValue -ParentPath "$ParentPath/$propName" -ExcludeCategories $ExcludeCategories
            }
        }

        return $foundChecks
    }

    $checks = Find-RegistrySettings -Object $config -ExcludeCategories $ExcludeCategories
    return $checks
}

# Helper function for exact registry-data comparison. Registry kind is checked
# by each caller after this function proves exact data (including array order,
# item count and string casing).
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue
    )

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop)) {
            return $false
        }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $Name) { return $false }
        $actual = $key.GetValue(
            $Name,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $expectedJson = [PSCustomObject]@{ Value = $ExpectedValue } | ConvertTo-Json -Compress -Depth 20
        $actualJson = [PSCustomObject]@{ Value = $actual } | ConvertTo-Json -Compress -Depth 20
        return $actualJson -ceq $expectedJson
    }
    catch {
        return $false
    }
}

# Helper function to get actual registry value
function Get-ActualRegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        if (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.GetValueNames() -contains $Name) {
                return $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        return "Not set"
    }
    catch {
        return "Error reading"
    }
}

$htmlFile = ''
$reportGenerated = $false

if (Test-VerificationModuleSelected 'SecurityBaseline') {
Write-VerificationStep "Verifying Registry Settings ($EXPECTED_REGISTRY_COUNT)..."

try {
    # Detect if system is domain-joined for standalone adjustments
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $isDomainJoined = ($computerSystem.PartOfDomain -eq $true)

    # Load registry settings
    $computerSettings = Get-Content -LiteralPath (Join-Path $baseConfigPath 'Computer-RegistryPolicies.json') -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $userSettings = Get-Content -LiteralPath (Join-Path $baseConfigPath 'User-RegistryPolicies.json') -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if (($computerSettings.Count + $userSettings.Count) -ne $EXPECTED_REGISTRY_COUNT) {
        throw "Registry declared-scope drift: computer=$($computerSettings.Count), user=$($userSettings.Count), expected=$EXPECTED_REGISTRY_COUNT"
    }
    $bitLockerUsbSettings = @($computerSettings | Where-Object {
            [string]$_.ValueName -ceq 'RDVDenyWriteAccess'
        })
    if ($bitLockerUsbSettings.Count -ne 1) {
        throw "Expected exactly one RDVDenyWriteAccess registry target; found $($bitLockerUsbSettings.Count)"
    }
    if ($bitLockerUsbChoiceIsAuthoritative) {
        $bitLockerUsbSettings[0].Data = if ($configuredBitLockerUsbEnforcement) { 1 } else { 0 }
    }
    $submitSamplesSettings = @($computerSettings | Where-Object {
            [string]$_.ValueName -ceq 'SubmitSamplesConsent'
        })
    if ($submitSamplesSettings.Count -ne 1) {
        throw "Expected exactly one SubmitSamplesConsent registry target; found $($submitSamplesSettings.Count)"
    }
    if ($submitSamplesChoiceIsAuthoritative) {
        $submitSamplesSettings[0].Data = if ($configuredSubmitAllSamples) { 3 } else { 1 }
    }
    $smartScreenSettings = @($computerSettings | Where-Object {
            [string]$_.ValueName -ceq 'ShellSmartScreenLevel'
        })
    if ($smartScreenSettings.Count -ne 1) {
        throw "Expected exactly one ShellSmartScreenLevel registry target; found $($smartScreenSettings.Count)"
    }
    if ($smartScreenChoiceIsAuthoritative) {
        $smartScreenSettings[0].Data = if ($configuredSmartScreenWarnMode) { 'Warn' } else { 'Block' }
    }
    # Source resolved above: transaction-bound session record (applied scope)
    # or the durable SecurityBaseline intent (standalone).
    foreach ($override in $authoritativeBaselineAsrOverrides) {
        $overrideGuid = ([Guid]([string]$override.Guid)).ToString('D').ToLowerInvariant()
        $overrideTargets = @($computerSettings | Where-Object {
                ([string]$_.KeyName -replace '^\[', '' -replace '\]$', '') -ceq
                    'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' -and
                ([string]$_.ValueName).ToLowerInvariant() -ceq $overrideGuid
            })
        if ($overrideTargets.Count -ne 1 -or [int]$override.Action -notin @(1, 2)) {
            throw "Durable SecurityBaseline ASR override is invalid: $overrideGuid"
        }
        $overrideTargets[0].Data = [string][int]$override.Action
    }

    # User-scope baseline targets belong to the interactive desktop user, not
    # necessarily the credential-elevated administrator identity.
    $registrySessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId
    $registryInteractiveNames = @(Get-Process -Name explorer -IncludeUserName -ErrorAction Stop |
        Where-Object { $_.SessionId -eq $registrySessionId -and -not [string]::IsNullOrWhiteSpace($_.UserName) } |
        ForEach-Object { [string]$_.UserName } | Sort-Object -Unique)
    if ($registryInteractiveNames.Count -ne 1) { throw 'Registry verifier could not resolve exactly one interactive desktop user' }
    $registryUserSid = [string]([System.Security.Principal.NTAccount]::new($registryInteractiveNames[0])).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($registryUserSid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') { throw 'Registry verifier resolved an unsupported interactive-user SID' }
    $registryUserRoot = "Registry::HKEY_USERS\$registryUserSid"
    if (-not (Test-Path -LiteralPath $registryUserRoot -PathType Container)) { throw 'Registry verifier requires the interactive user hive to be loaded' }

    $registryFailed = @()
    $registryPassed = @()

    # Verify computer settings
    foreach ($setting in $computerSettings) {
        # Build full registry path - KeyName has format "[SOFTWARE\..."
        $keyName = $setting.KeyName -replace '^\[', '' -replace '\]$', ''
        $keyPath = "Registry::HKEY_LOCAL_MACHINE\$keyName"

        if ($setting.ValueName -eq '**delvals.') {
            try {
                $remainingNames = if (Test-Path -LiteralPath $keyPath) {
                    $deleteKey = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                    @($deleteKey.GetValueNames())
                }
                else { @() }
                # PReg processes **delvals. at this point in the ordered policy
                # stream, then later directives may deliberately repopulate the
                # same key. The final-state verifier must reject stale values
                # while allowing names declared elsewhere for this exact key.
                $declaredFinalNames = @($computerSettings | Where-Object {
                        (($_.KeyName -replace '^\[', '' -replace '\]$', '') -ieq $keyName) -and
                        ([string]$_.ValueName -notmatch '^\*\*del')
                    } | ForEach-Object { [string]$_.ValueName } | Sort-Object -Unique)
                $unexpectedNames = @($remainingNames | Where-Object { $_ -notin $declaredFinalNames })
                if ($unexpectedNames.Count -eq 0) {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{
                        Path = $keyPath; Name = $setting.ValueName
                        Expected = if ($declaredFinalNames.Count) { "Only declared values: $($declaredFinalNames -join ', ')" } else { 'No values' }
                        Actual = if ($remainingNames.Count) { $remainingNames -join ', ' } else { 'No values' }
                    }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{
                        Path = $keyPath; Name = $setting.ValueName
                        Expected = if ($declaredFinalNames.Count) { "Only declared values: $($declaredFinalNames -join ', ')" } else { 'No values' }
                        Actual = $remainingNames -join ', '
                        Reason = "**delvals. target key still contains unexpected values: $($unexpectedNames -join ', ')"
                    }
                }
            }
            catch {
                $results.Failed++
                $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $setting.ValueName; Expected = 'No values'; Actual = 'Error'; Reason = $_.Exception.Message }
            }
            continue
        }
        elseif ($setting.ValueName -match '^\*\*del\.(.+)$') {
            $targetValueName = $Matches[1]
            try {
                $targetPresent = $false
                if (Test-Path -LiteralPath $keyPath) {
                    $targetPresent = (Get-Item -LiteralPath $keyPath -ErrorAction Stop).GetValueNames() -contains $targetValueName
                }
                if (-not $targetPresent) {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Absent' }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Present'; Reason = 'Delete directive target still exists' }
                }
            }
            catch {
                $results.Failed++
                $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Error'; Reason = $_.Exception.Message }
            }
            continue
        }

        try {
            if (Test-Path $keyPath) {
                $registryKey = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                if ($registryKey.GetValueNames() -contains [string]$setting.ValueName) {
                    $actualValue = $registryKey.GetValue(
                        [string]$setting.ValueName,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $actualType = $registryKey.GetValueKind([string]$setting.ValueName).ToString()
                    $expectedType = switch ([string]$setting.Type) {
                        'REG_DWORD' { 'DWord' }
                        'REG_SZ'    { 'String' }
                        default { throw "Unsupported baseline registry type '$($setting.Type)'" }
                    }
                    $expectedValue = $setting.Data

                    # Apply standalone workstation adjustments
                    if (-not $isDomainJoined) {
                        # LocalAccountTokenFilterPolicy: 0 (domain) -> 1 (standalone) for remote admin
                        if ($setting.ValueName -eq "LocalAccountTokenFilterPolicy") {
                            $expectedValue = 1
                        }
                    }

                    $actualJson = [PSCustomObject]@{ Value=$actualValue } | ConvertTo-Json -Compress -Depth 20
                    $expectedJson = [PSCustomObject]@{ Value=$expectedValue } | ConvertTo-Json -Compress -Depth 20
                    $expectedDisplay = "$expectedType/$expectedJson"
                    $valueMatches = $actualJson -ceq $expectedJson

                    # Security Baseline declares the PSExec/WMI rule as the
                    # REG_SZ string "2" (Audit). When ASR was selected later in
                    # the same run, its sealed requested-action plan is the
                    # authoritative final expectation. A standalone verifier
                    # without an Apply session can only prove the documented
                    # Block/Audit choice set and labels that limitation openly.
                    $isPsExecWmiRule = [string]$setting.ValueName -ieq 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
                    if ($isPsExecWmiRule -and (Test-VerificationModuleSelected 'ASR')) {
                        if ($null -ne $sealedAppliedAsrPlan) {
                            $normalizedRuleId = ([Guid]([string]$setting.ValueName)).ToString('D').ToLowerInvariant()
                            $expectedValue = ([int]$sealedAppliedAsrPlan.ActionMap[$normalizedRuleId]).ToString(
                                [Globalization.CultureInfo]::InvariantCulture)
                            $expectedJson = [PSCustomObject]@{ Value=$expectedValue } | ConvertTo-Json -Compress -Depth 20
                            $expectedDisplay = "$expectedType/$expectedJson"
                            $valueMatches = $actualJson -ceq $expectedJson
                        }
                        else {
                            $valueMatches = $actualValue -is [string] -and [string]$actualValue -cin @('1', '2')
                            $expectedDisplay = 'String/one-of [{"Value":"1"},{"Value":"2"}] (Apply choice unavailable)'
                        }
                    }

                    # BitLocker removable-drive write enforcement is a documented
                    # Y/N Apply choice. Only an authoritative effective config
                    # proves the selection (handled above by rewriting Data);
                    # without one, both documented values count and the
                    # limitation is labeled openly -- same contract as the
                    # PSExec/WMI rule. Value 1 must never fail merely because
                    # the shipped home default is 0.
                    if (-not $bitLockerUsbChoiceIsAuthoritative -and
                        [string]$setting.ValueName -ceq 'RDVDenyWriteAccess') {
                        $valueMatches = $null -ne $actualValue -and [int]$actualValue -in @(0, 1)
                        $expectedDisplay = 'DWord/one-of [{"Value":0},{"Value":1}] (Apply choice unavailable)'
                    }

                    # Defender sample submission is the second documented Y/N
                    # Apply choice: 1 is the shipped privacy default (safe
                    # samples only, a declared deviation from Microsoft's 3),
                    # 3 restores Microsoft's baseline value. Without an
                    # authoritative effective config both decision values are
                    # legitimate owned state -- same contract as
                    # RDVDenyWriteAccess. Values 0/2 stay honest failures.
                    if (-not $submitSamplesChoiceIsAuthoritative -and
                        [string]$setting.ValueName -ceq 'SubmitSamplesConsent') {
                        $valueMatches = $null -ne $actualValue -and [int]$actualValue -in @(1, 3)
                        $expectedDisplay = 'DWord/one-of [{"Value":1},{"Value":3}] (Apply choice unavailable)'
                    }

                    # The OS SmartScreen level is the third documented decision
                    # value, adjustable through the Apply prompt, the config
                    # key, or the GUI's SmartScreen quick action (sealed BAVR
                    # session): Block is Microsoft's baseline value, Warn the
                    # documented security-reducing choice. Only an
                    # authoritative config pins the expectation (handled above
                    # by rewriting Data); otherwise both are owned decision
                    # states with an openly labeled choice set. An absent
                    # value, wrong type or any other string stays an honest
                    # failure; EnableSmartScreen=1 keeps its exact match.
                    if (-not $smartScreenChoiceIsAuthoritative -and
                        [string]$setting.ValueName -ceq 'ShellSmartScreenLevel') {
                        $valueMatches = $actualValue -is [string] -and [string]$actualValue -cin @('Block', 'Warn')
                        $expectedDisplay = 'String/one-of [{"Value":"Block"},{"Value":"Warn"}] (Apply choice unavailable)'
                    }

                    if ($actualType -ceq $expectedType -and $valueMatches) {
                        $results.Verified++
                        $registryPassed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = $expectedDisplay
                            Actual   = "$actualType/$actualJson"
                        }
                    }
                    else {
                        $results.Failed++
                        $registryFailed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = $expectedDisplay
                            Actual   = "$actualType/$actualJson"
                            Reason   = "Type/value mismatch"
                        }
                    }
                }
                else {
                    # Check if this is a DELETE operation (**del..., **delvals)
                    # For DELETE operations, "Value not found" means SUCCESS (value was deleted or never existed)
                    if ($setting.ValueName -match '^\*\*del') {
                        $results.Verified++
                        $registryPassed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = "Deleted/Not present"
                            Actual   = "Value not found (Success)"
                        }
                    }
                    else {
                        $results.Failed++
                        $registryFailed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = $setting.Data
                            Actual   = "Value not found"
                            Reason   = "Value does not exist"
                        }
                    }
                }
            }
            else {
                # Check if this is a DELETE operation (**del..., **delvals)
                # For DELETE operations, "Key not found" means SUCCESS (key was deleted or never existed)
                if ($setting.ValueName -match '^\*\*del') {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{
                        Path     = $keyPath
                        Name     = $setting.ValueName
                        Expected = "Deleted/Not present"
                        Actual   = "Key not found (Success)"
                    }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{
                        Path     = $keyPath
                        Name     = $setting.ValueName
                        Expected = $setting.Data
                        Actual   = "Key not found"
                        Reason   = "Key does not exist"
                    }
                }
            }
        }
        catch {
            $results.Failed++
            $registryFailed += [PSCustomObject]@{
                Path     = $keyPath
                Name     = $setting.ValueName
                Expected = $setting.Data
                Actual   = "Error"
                Reason   = $_.Exception.Message
            }
        }
    }

    # Verify user settings
    foreach ($setting in $userSettings) {
        # Build full registry path - KeyName has format "[SOFTWARE\..."
        $keyName = $setting.KeyName -replace '^\[', '' -replace '\]$', ''
        $keyPath = "$registryUserRoot\$keyName"

        if ($setting.ValueName -eq '**delvals.') {
            try {
                $remainingNames = if (Test-Path -LiteralPath $keyPath) {
                    $deleteKey = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                    @($deleteKey.GetValueNames())
                }
                else { @() }
                $declaredFinalNames = @($userSettings | Where-Object {
                        (($_.KeyName -replace '^\[', '' -replace '\]$', '') -ieq $keyName) -and
                        ([string]$_.ValueName -notmatch '^\*\*del')
                    } | ForEach-Object { [string]$_.ValueName } | Sort-Object -Unique)
                $unexpectedNames = @($remainingNames | Where-Object { $_ -notin $declaredFinalNames })
                if ($unexpectedNames.Count -eq 0) {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{
                        Path = $keyPath; Name = $setting.ValueName
                        Expected = if ($declaredFinalNames.Count) { "Only declared values: $($declaredFinalNames -join ', ')" } else { 'No values' }
                        Actual = if ($remainingNames.Count) { $remainingNames -join ', ' } else { 'No values' }
                    }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{
                        Path = $keyPath; Name = $setting.ValueName
                        Expected = if ($declaredFinalNames.Count) { "Only declared values: $($declaredFinalNames -join ', ')" } else { 'No values' }
                        Actual = $remainingNames -join ', '
                        Reason = "**delvals. target key still contains unexpected values: $($unexpectedNames -join ', ')"
                    }
                }
            }
            catch {
                $results.Failed++
                $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $setting.ValueName; Expected = 'No values'; Actual = 'Error'; Reason = $_.Exception.Message }
            }
            continue
        }
        elseif ($setting.ValueName -match '^\*\*del\.(.+)$') {
            $targetValueName = $Matches[1]
            try {
                $targetPresent = $false
                if (Test-Path -LiteralPath $keyPath) {
                    $targetPresent = (Get-Item -LiteralPath $keyPath -ErrorAction Stop).GetValueNames() -contains $targetValueName
                }
                if (-not $targetPresent) {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Absent' }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Present'; Reason = 'Delete directive target still exists' }
                }
            }
            catch {
                $results.Failed++
                $registryFailed += [PSCustomObject]@{ Path = $keyPath; Name = $targetValueName; Expected = 'Absent'; Actual = 'Error'; Reason = $_.Exception.Message }
            }
            continue
        }

        try {
            if (Test-Path $keyPath) {
                $registryKey = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                if ($registryKey.GetValueNames() -contains [string]$setting.ValueName) {
                    $actualValue = $registryKey.GetValue(
                        [string]$setting.ValueName,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $actualType = $registryKey.GetValueKind([string]$setting.ValueName).ToString()
                    $expectedType = switch ([string]$setting.Type) {
                        'REG_DWORD' { 'DWord' }
                        'REG_SZ'    { 'String' }
                        default { throw "Unsupported baseline user-registry type '$($setting.Type)'" }
                    }
                    $actualJson = [PSCustomObject]@{ Value=$actualValue } | ConvertTo-Json -Compress -Depth 20
                    $expectedJson = [PSCustomObject]@{ Value=$setting.Data } | ConvertTo-Json -Compress -Depth 20

                    if ($actualType -ceq $expectedType -and $actualJson -ceq $expectedJson) {
                        $results.Verified++
                        $registryPassed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = "$expectedType/$expectedJson"
                            Actual   = "$actualType/$actualJson"
                        }
                    }
                    else {
                        $results.Failed++
                        $registryFailed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = "$expectedType/$expectedJson"
                            Actual   = "$actualType/$actualJson"
                            Reason   = "Type/value mismatch"
                        }
                    }
                }
                else {
                    # Check if this is a DELETE operation (**del..., **delvals)
                    # For DELETE operations, "Value not found" means SUCCESS (value was deleted or never existed)
                    if ($setting.ValueName -match '^\*\*del') {
                        $results.Verified++
                        $registryPassed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = "Deleted/Not present"
                            Actual   = "Value not found (Success)"
                        }
                    }
                    else {
                        $results.Failed++
                        $registryFailed += [PSCustomObject]@{
                            Path     = $keyPath
                            Name     = $setting.ValueName
                            Expected = $setting.Data
                            Actual   = "Value not found"
                            Reason   = "Value does not exist"
                        }
                    }
                }
            }
            else {
                # Check if this is a DELETE operation (**del..., **delvals)
                # For DELETE operations, "Key not found" means SUCCESS (key was deleted or never existed)
                if ($setting.ValueName -match '^\*\*del') {
                    $results.Verified++
                    $registryPassed += [PSCustomObject]@{
                        Path     = $keyPath
                        Name     = $setting.ValueName
                        Expected = "Deleted/Not present"
                        Actual   = "Key not found (Success)"
                    }
                }
                else {
                    $results.Failed++
                    $registryFailed += [PSCustomObject]@{
                        Path     = $keyPath
                        Name     = $setting.ValueName
                        Expected = $setting.Data
                        Actual   = "Key not found"
                        Reason   = "Key does not exist"
                    }
                }
            }
        }
        catch {
            $results.Failed++
            $registryFailed += [PSCustomObject]@{
                Path     = $keyPath
                Name     = $setting.ValueName
                Expected = $setting.Data
                Actual   = "Error"
                Reason   = $_.Exception.Message
            }
        }
    }

    # Add to AllSettings for HTML report (with category summary)
    $registryPassedCount = $registryPassed.Count
    if (($registryPassedCount + $registryFailed.Count) -ne $EXPECTED_REGISTRY_COUNT) {
        throw "Registry result reconciliation failed: passed=$registryPassedCount, failed=$($registryFailed.Count), expected=$EXPECTED_REGISTRY_COUNT"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category      = "Registry"
        Total         = $results.RegistrySettings
        Passed        = $registryPassedCount
        Failed        = $registryFailed.Count
        NotChecked    = 0
        NotApplicable = 0
        PassedDetails = $registryPassed
        FailedDetails = $registryFailed
        NotCheckedDetails = @()
        NotApplicableDetails = @()
    }

    if ($registryFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "Registry"
            Count    = $registryFailed.Count
            Details  = $registryFailed
        }
    }

    $registryPresentation = Get-VerificationModulePresentation `
        -Name 'Registry' -Total $results.RegistrySettings -Passed $registryPassedCount `
        -Failed $registryFailed.Count -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "$registryPassedCount/$($results.RegistrySettings) checks passed; $($registryFailed.Count) failed."
    Write-VerificationModulePresentation -Presentation $registryPresentation
}
catch {
    $registryScopeFailure = [PSCustomObject]@{
        Setting = 'Complete SecurityBaseline registry verification scope'; Path = 'SecurityBaseline/Registry'
        Expected = "$EXPECTED_REGISTRY_COUNT executable checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category='Registry'; Total=$EXPECTED_REGISTRY_COUNT; Passed=0; Failed=$EXPECTED_REGISTRY_COUNT
        NotChecked=0; NotApplicable=0; PassedDetails=@(); FailedDetails=@($registryScopeFailure)
        NotCheckedDetails=@(); NotApplicableDetails=@()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category='Registry'; Count=$EXPECTED_REGISTRY_COUNT; Details=@($registryScopeFailure)
    }
    $registryPresentation = Get-VerificationModulePresentation `
        -Name 'Registry' -Total $EXPECTED_REGISTRY_COUNT -Passed 0 -Failed $EXPECTED_REGISTRY_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $registryPresentation
}

Write-VerificationStep "Verifying Audit Policies ($EXPECTED_AUDIT_COUNT)..."

try {
    # Load expected audit policies
    $auditSettings = Get-Content -LiteralPath (Join-Path $baseConfigPath 'AuditPolicies.json') -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ($auditSettings.Count -ne $EXPECTED_AUDIT_COUNT) {
        throw "Audit-policy declared-scope drift: JSON=$($auditSettings.Count), expected=$EXPECTED_AUDIT_COUNT"
    }

    $auditNativeHelper = Join-Path $rootPath 'Modules\SecurityBaseline\Private\Get-AuditPolicyState.ps1'
    if (-not (Test-Path -LiteralPath $auditNativeHelper -PathType Leaf)) {
        throw "Native audit-policy helper is missing: $auditNativeHelper"
    }
    . $auditNativeHelper

    $auditFailed = @()
    $auditPassed = @()
    $seenAuditGuids = [System.Collections.Generic.HashSet[Guid]]::new()

    foreach ($policy in $auditSettings) {
        if ([string]::IsNullOrWhiteSpace($policy.Subcategory)) {
            throw 'AuditPolicies.json contains an empty Subcategory'
        }
        $guid = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$policy.SubcategoryGUID, [ref]$guid) -or
            -not $seenAuditGuids.Add($guid) -or [int]$policy.SettingValue -notin @(0, 1, 2, 3)) {
            throw "Audit policy '$($policy.Subcategory)' has an invalid/duplicate GUID or setting value"
        }
        $actualFlags = [uint32](Get-AuditPolicyState -SubcategoryGuid $guid)
        if ($actualFlags -notin [uint32[]]@(0, 1, 2, 3, 4)) {
            throw "Audit policy $guid returned unsupported native flags 0x$($actualFlags.ToString('X8'))"
        }
        $actualValue = if ($actualFlags -eq 4) { 0 } else { [int]($actualFlags -band 0x3) }
        $expectedValue = [int]$policy.SettingValue
        $detail = [PSCustomObject]@{
            Policy=$policy.Subcategory; Expected=$expectedValue; Actual=$actualValue
            GUID=$guid.ToString('B'); NativeFlags=$actualFlags
        }
        if ($actualValue -eq $expectedValue) {
            $results.Verified++
            $auditPassed += $detail
        }
        else {
            $results.Failed++
            $auditFailed += $detail
        }
    }

    # Add to AllSettings for HTML report
    $auditPassedCount = $auditPassed.Count
    if (($auditPassedCount + $auditFailed.Count) -ne $EXPECTED_AUDIT_COUNT) {
        throw "Audit-policy result reconciliation failed: passed=$auditPassedCount, failed=$($auditFailed.Count), expected=$EXPECTED_AUDIT_COUNT"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category      = "AuditPolicies"
        Total         = $results.AuditPolicies
        Passed        = $auditPassedCount
        Failed        = $auditFailed.Count
        NotChecked    = 0
        NotApplicable = 0
        PassedDetails = $auditPassed
        FailedDetails = $auditFailed
        NotCheckedDetails = @()
        NotApplicableDetails = @()
    }

    if ($auditFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "AuditPolicies"
            Count    = $auditFailed.Count
            Details  = $auditFailed
        }
    }

    $auditPresentation = Get-VerificationModulePresentation `
        -Name 'Audit Policies' -Total $results.AuditPolicies -Passed $auditPassedCount `
        -Failed $auditFailed.Count -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "$auditPassedCount/$($results.AuditPolicies) checks passed; $($auditFailed.Count) failed."
    Write-VerificationModulePresentation -Presentation $auditPresentation
}
catch {
    $auditScopeFailure = [PSCustomObject]@{
        Policy = 'Complete SecurityBaseline audit-policy verification scope'; Path = 'SecurityBaseline/AuditPolicies'
        Expected = "$EXPECTED_AUDIT_COUNT executable checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category='AuditPolicies'; Total=$EXPECTED_AUDIT_COUNT; Passed=0; Failed=$EXPECTED_AUDIT_COUNT
        NotChecked=0; NotApplicable=0; PassedDetails=@(); FailedDetails=@($auditScopeFailure)
        NotCheckedDetails=@(); NotApplicableDetails=@()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category='AuditPolicies'; Count=$EXPECTED_AUDIT_COUNT; Details=@($auditScopeFailure)
    }
    $auditPresentation = Get-VerificationModulePresentation `
        -Name 'Audit Policies' -Total $EXPECTED_AUDIT_COUNT -Passed 0 -Failed $EXPECTED_AUDIT_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $auditPresentation
}

Write-VerificationStep "Verifying Security Template Settings ($EXPECTED_SECURITY_COUNT)..."

$securityTemplateExportPath = $null
$securityTemplateExportLog = $null
try {
    # Export current security settings
    $securityTemplateExportId = [Guid]::NewGuid().ToString('N')
    $securityTemplateExportPath = Join-Path $env:TEMP "NoID_SecurityTemplateVerify_$securityTemplateExportId.inf"
    $securityTemplateExportLog = Join-Path $env:TEMP "NoID_SecurityTemplateVerify_$securityTemplateExportId.log"
    $securityTemplateExport = Start-Process -FilePath 'secedit.exe' `
        -ArgumentList @('/export', '/cfg', "`"$securityTemplateExportPath`"", '/log', "`"$securityTemplateExportLog`"", '/quiet') `
        -Wait -NoNewWindow -PassThru -ErrorAction Stop
    if ($securityTemplateExport.ExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $securityTemplateExportPath -PathType Leaf)) {
        throw "secedit verification export failed with exit code $($securityTemplateExport.ExitCode)"
    }

    # Load expected settings
    $expectedSettings = Get-Content (Join-Path $baseConfigPath "SecurityTemplates.json") -Raw | ConvertFrom-Json
    $uacSettingName = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'
    $uacComputerTemplate = $expectedSettings.'MSFT Windows 11 25H2 - Computer'.'Registry Values'
    if (-not ($uacComputerTemplate.PSObject.Properties.Name -contains $uacSettingName)) {
        throw "ConsentPromptBehaviorUser is missing from SecurityTemplates.json"
    }
    if ($uacModeIsAuthoritative) {
        $uacComputerTemplate.PSObject.Properties[$uacSettingName].Value = $configuredConsentPromptBehaviorUser
    }

    # Parse secedit output
    $currentSettings = Get-Content -LiteralPath $securityTemplateExportPath -ErrorAction Stop
    # Enumerate once with a decisive error contract. A failed SCM query must
    # not be misreported as four absent/NotApplicable Xbox services.
    $allSecurityTemplateServices = @(Get-Service -ErrorAction Stop)

    $securityFailed = @()
    $securityPassed = @()
    $securityNotApplicable = @()
    $securityVerified = 0

    # Verify each GPO
    foreach ($gpoName in $expectedSettings.PSObject.Properties.Name) {
        # Note: We do NOT skip Domain Security on standalone!
        # The standalone delta modifies 1 setting (LocalAccountTokenFilterPolicy),
        # but all 67 settings are still applied and should be verified.

        $gpo = $expectedSettings.$gpoName

        foreach ($sectionName in $gpo.PSObject.Properties.Name) {
            # Skip metadata sections (Unicode, Version)
            if ($sectionName -in @("Unicode", "Version")) {
                continue
            }

            $section = $gpo.$sectionName

            # Iterate through actual settings in this section
            foreach ($settingProperty in $section.PSObject.Properties) {
                $settingName = $settingProperty.Name
                $expectedValue = $settingProperty.Value

                # Find in current settings - look in the matching INI section
                $inSection = $false
                $actualValue = $null

                foreach ($line in $currentSettings) {
                    # Check if we're in the right section
                    if ($line -match "^\[$sectionName\]") {
                        $inSection = $true
                        continue
                    }
                    elseif ($line -match "^\[") {
                        $inSection = $false
                    }

                    # If in right section, look for setting
                    $escapedName = [regex]::Escape($settingName)
                    if ($inSection -and $line -match "^$escapedName\s*=") {
                        $actualValue = ($line -split '=', 2)[1].Trim()
                        break
                    }
                    if ($inSection -and $sectionName -eq 'Service General Setting' -and
                        $line.Trim() -match "^`"$escapedName`"\s*,\s*([0-9]+)\s*,") {
                        $actualValue = switch ([int]$Matches[1]) {
                            2 { 'StartupType=Automatic' }
                            3 { 'StartupType=Manual' }
                            4 { 'StartupType=Disabled' }
                            default { "StartupType=Unknown($($Matches[1]))" }
                        }
                        break
                    }
                }

                if ($null -ne $actualValue) {
                    # Special handling for Privilege Rights - compare SID sets (order-independent)
                    $isMatch = $false
                    if ($sectionName -eq "Privilege Rights") {
                        # Split SIDs and compare as sets
                        $expectedSIDs = $expectedValue -split ',' | ForEach-Object { $_.Trim() } | Sort-Object
                        $actualSIDs = $actualValue -split ',' | ForEach-Object { $_.Trim() } | Sort-Object

                        # Compare arrays (order-independent)
                        if ($expectedSIDs.Count -eq $actualSIDs.Count) {
                            $isMatch = $true
                            for ($i = 0; $i -lt $expectedSIDs.Count; $i++) {
                                if ($expectedSIDs[$i] -ne $actualSIDs[$i]) {
                                    $isMatch = $false
                                    break
                                }
                            }
                        }
                    }
                    elseif ($settingName -eq $uacSettingName -and -not $uacModeIsAuthoritative) {
                        # Interactive choice: only the two explicitly supported
                        # values are valid. Value 3 is deliberately not accepted.
                        $isMatch = $actualValue -in @('4,0', '4,1')
                        $expectedValue = '4,0 (Strict) or 4,1 (SecureDesktop), explicit interactive choice'
                    }
                    else {
                        # Normal string comparison for non-Privilege Rights
                        $isMatch = ($actualValue -eq $expectedValue)
                    }

                    if ($isMatch) {
                        $securityVerified++
                        $results.Verified++
                        $securityPassed += [PSCustomObject]@{
                            GPO      = $gpoName
                            Section  = $sectionName
                            Setting  = $settingName
                            Expected = $expectedValue
                            Actual   = $actualValue
                        }
                    }
                    else {
                        $results.Failed++
                        $securityFailed += [PSCustomObject]@{
                            GPO      = $gpoName
                            Section  = $sectionName
                            Setting  = $settingName
                            Expected = $expectedValue
                            Actual   = $actualValue
                        }
                    }
                }
                else {
                    # Setting not found in secedit output
                    # There are legitimate cases where "Not found" = SUCCESS:

                    # 1. Xbox services may not exist on clean installations
                    $xboxServices = @("XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc")
                    if ($sectionName -eq "Service General Setting" -and $settingName -in $xboxServices) {
                        $xboxServicesFound = @($allSecurityTemplateServices | Where-Object {
                                [string]$_.Name -eq $settingName
                            })
                        if ($xboxServicesFound.Count -eq 0) {
                            $results.NotApplicable++
                            $securityNotApplicable += [PSCustomObject]@{
                                GPO      = $gpoName
                                Section  = $sectionName
                                Setting  = $settingName
                                Expected = $expectedValue
                                Actual   = "Not applicable: Xbox service is not installed"
                                CheckState = 'NotApplicable'
                            }
                        }
                        elseif ($xboxServicesFound.Count -eq 1) {
                            # secedit applies these startup modes but commonly
                            # omits Service General Setting from a later export.
                            # Match the module's immediate post-Apply contract
                            # and verify the effective SCM state directly.
                            $expectedStartType = ([string]$expectedValue -replace '^StartupType=', '')
                            $actualStartType = [string]$xboxServicesFound[0].StartType
                            if ($actualStartType -ceq $expectedStartType) {
                                $securityVerified++
                                $results.Verified++
                                $securityPassed += [PSCustomObject]@{
                                    GPO      = $gpoName
                                    Section  = $sectionName
                                    Setting  = $settingName
                                    Expected = $expectedValue
                                    Actual   = "StartupType=$actualStartType (SCM)"
                                }
                            }
                            else {
                                $results.Failed++
                                $securityFailed += [PSCustomObject]@{
                                    GPO      = $gpoName
                                    Section  = $sectionName
                                    Setting  = $settingName
                                    Expected = $expectedValue
                                    Actual   = "StartupType=$actualStartType (SCM)"
                                }
                            }
                        }
                        else {
                            throw "Service inventory is ambiguous for $settingName"
                        }
                    }
                    # 2. Privilege Rights with empty expected value (nobody should have this right)
                    #    If secedit doesn't list it, it means nobody has it = SUCCESS
                    elseif ($sectionName -eq "Privilege Rights" -and [string]::IsNullOrEmpty($expectedValue)) {
                        $securityVerified++
                        $results.Verified++
                        $securityPassed += [PSCustomObject]@{
                            GPO      = $gpoName
                            Section  = $sectionName
                            Setting  = $settingName
                            Expected = "Empty (nobody has right)"
                            Actual   = "Not found (Success)"
                        }
                    }
                    else {
                        $results.Failed++
                        $securityFailed += [PSCustomObject]@{
                            GPO      = $gpoName
                            Section  = $sectionName
                            Setting  = $settingName
                            Expected = $expectedValue
                            Actual   = "Not found (a non-empty declared target was not exported)"
                        }
                    }
                }
            }
        }
    }

    # Add to AllSettings for HTML report
    $securityPassedCount = $securityPassed.Count
    if (($securityPassedCount + $securityFailed.Count + $securityNotApplicable.Count) -ne $EXPECTED_SECURITY_COUNT) {
        throw "Security-template result reconciliation failed: passed=$securityPassedCount, failed=$($securityFailed.Count), notApplicable=$($securityNotApplicable.Count), expected=$EXPECTED_SECURITY_COUNT"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category      = "SecurityTemplate"
        Total         = $results.SecurityTemplate
        Passed        = $securityPassedCount
        Failed        = $securityFailed.Count
        NotChecked    = 0
        NotApplicable = $securityNotApplicable.Count
        PassedDetails = $securityPassed
        FailedDetails = $securityFailed
        NotCheckedDetails = @()
        NotApplicableDetails = $securityNotApplicable
    }

    if ($securityFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "SecurityTemplate"
            Count    = $securityFailed.Count
            Details  = $securityFailed
        }
    }

    $securityPresentation = Get-VerificationModulePresentation `
        -Name 'Security Template' -Total $results.SecurityTemplate -Passed $securityPassedCount `
        -Failed $securityFailed.Count -NotChecked 0 -NotCheckedDeliberate 0 `
        -NotApplicable $securityNotApplicable.Count `
        -Summary "$securityPassedCount verified; $($securityFailed.Count) failed; $($securityNotApplicable.Count) not applicable ($($results.SecurityTemplate) declared)."
    Write-VerificationModulePresentation -Presentation $securityPresentation
}
catch {
    $securityTemplateScopeFailure = [PSCustomObject]@{
        Setting = 'Complete SecurityBaseline security-template verification scope'; Path = 'SecurityBaseline/SecurityTemplate'
        Expected = "$EXPECTED_SECURITY_COUNT executable checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category='SecurityTemplate'; Total=$EXPECTED_SECURITY_COUNT; Passed=0; Failed=$EXPECTED_SECURITY_COUNT
        NotChecked=0; NotApplicable=0; PassedDetails=@(); FailedDetails=@($securityTemplateScopeFailure)
        NotCheckedDetails=@(); NotApplicableDetails=@()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category='SecurityTemplate'; Count=$EXPECTED_SECURITY_COUNT; Details=@($securityTemplateScopeFailure)
    }
    $securityPresentation = Get-VerificationModulePresentation `
        -Name 'Security Template' -Total $EXPECTED_SECURITY_COUNT -Passed 0 -Failed $EXPECTED_SECURITY_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $securityPresentation
}
finally {
    if ($securityTemplateExportPath) { Remove-Item -LiteralPath $securityTemplateExportPath -Force -ErrorAction SilentlyContinue }
    if ($securityTemplateExportLog) { Remove-Item -LiteralPath $securityTemplateExportLog -Force -ErrorAction SilentlyContinue }
}
}

if (Test-VerificationModuleSelected 'ASR') {
Write-VerificationStep "Verifying ASR Rules ($EXPECTED_ASR_COUNT)..."

$asrNotApplicableRules = @()
$asrNotApplicableDetails = @()
try {
    $asrRules = @($declaredAsrRules)
    if ($asrRules.Count -ne $EXPECTED_ASR_COUNT) {
        throw "ASR declared-scope drift: JSON=$($asrRules.Count), expected=$EXPECTED_ASR_COUNT"
    }
    $asrApplicableRules = @($asrRules | Where-Object {
            -not ($_.PSObject.Properties.Name -contains 'WindowsClientApplicable') -or
            [bool]$_.WindowsClientApplicable
        })
    $asrNotApplicableRules = @($asrRules | Where-Object {
            $_.PSObject.Properties.Name -contains 'WindowsClientApplicable' -and
            -not [bool]$_.WindowsClientApplicable
        })
    foreach ($rule in $asrNotApplicableRules) {
        if ([string]::IsNullOrWhiteSpace([string]$rule.NotApplicableReason)) {
            throw "ASR Windows-client NotApplicable reason is missing: $($rule.GUID)"
        }
    }
    if ($asrApplicableRules.Count + $asrNotApplicableRules.Count -ne $EXPECTED_ASR_COUNT) {
        throw 'ASR Windows-client applicability does not reconcile to declared scope'
    }
    $asrNotApplicableDetails = @($asrNotApplicableRules | ForEach-Object {
            [PSCustomObject]@{
                Rule = [string]$_.Name
                Expected = 'Windows 11 client applicability'
                Actual = [string]$_.NotApplicableReason
                CheckState = 'NotApplicable'
            }
        })

    # Check if Windows Defender is active or if a third-party endpoint product is managing protection
    # Uses 3-layer detection based on REGISTRATION MECHANISM, not product class:
    #   Layer 1 = SecurityCenter2 (Security-Center-registered AV)
    #   Layer 2 = Defender Passive Mode (typically enterprise EDR/XDR)
    #   Layer 3 = Service name lookup (display name only)
    # Layer assignment does not certify a product's capabilities or configuration.
    $securityProduct = [PSCustomObject]@{
        Detected            = $false
        ProductName         = $null
        DetectionMethod     = $null
        DefenderPassiveMode = $false
    }

    # Layer 1: WMI SecurityCenter2 -- AV products registered with Windows Security Center
    # (e.g. Bitdefender, Kaspersky, Avira, Norton, ESET consumer SKUs -- same vendors may
    # also ship enterprise EDR/XDR SKUs that surface in Layer 2 instead)
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
        $thirdPartyAV = @($avProducts | Where-Object {
                -not (Test-IsMicrosoftDefenderSecurityCenterProduct -Product $_)
            })
        if ($thirdPartyAV.Count -gt 0) {
            $registeredNames = @($thirdPartyAV | ForEach-Object { [string]$_.displayName } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $securityProduct.Detected = $true
            $securityProduct.ProductName = if ($registeredNames.Count -gt 0) {
                $registeredNames -join ', '
            }
            else { 'Registered third-party antivirus' }
            $securityProduct.DetectionMethod = "SecurityCenter2"
        }
    }
    catch {
        Write-Verbose "SecurityCenter2 query failed (continuing to Layer 2): $($_.Exception.Message)"
    }

    # Layer 2: Defender Passive Mode (EDR/XDR: CrowdStrike Falcon, SentinelOne, Carbon Black, etc.)
    if (-not $securityProduct.Detected) {
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
            if ($defenderStatus -and $defenderStatus.AMRunningMode -eq "Passive Mode") {
                $securityProduct.Detected = $true
                $securityProduct.DefenderPassiveMode = $true
                $securityProduct.DetectionMethod = "PassiveMode"

                # Layer 3: Known EDR service names for display name
                $edrServices = @(
                    @{ Name = "CSFalconService";      Display = "CrowdStrike Falcon" },
                    @{ Name = "SentinelAgent";         Display = "SentinelOne" },
                    @{ Name = "CbDefense";             Display = "Carbon Black Cloud" },
                    @{ Name = "CylanceSvc";            Display = "Cylance/Arctic Wolf Aurora" },
                    @{ Name = "xagt";                  Display = "Trellix Endpoint Security (HX)" },
                    @{ Name = "masvc";                 Display = "Trellix Agent" },
                    @{ Name = "mfeatp";                Display = "Trellix Adaptive Threat Protection" },
                    @{ Name = "cyserver";              Display = "Palo Alto Cortex XDR" },
                    @{ Name = "EPSecurityService";     Display = "Bitdefender GravityZone" },
                    @{ Name = "EPIntegrationService";  Display = "Bitdefender GravityZone" },
                    @{ Name = "avp";                   Display = "Kaspersky Endpoint Security" },
                    @{ Name = "klnagent";              Display = "Kaspersky Security Center Agent" },
                    @{ Name = "SmcService";            Display = "Broadcom/Symantec Endpoint Protection" },
                    @{ Name = "SepMasterService";      Display = "Broadcom/Symantec Endpoint Protection" },
                    @{ Name = "ekrn";                  Display = "ESET Endpoint Security" },
                    @{ Name = "EraAgentSvc";           Display = "ESET PROTECT Agent" },
                    @{ Name = "Sophos MCS Agent";      Display = "Sophos Endpoint" },
                    @{ Name = "hmpalertsvc";           Display = "Sophos HitmanPro.Alert" }
                )

                $edrServiceInventory = @(Get-Service -ErrorAction Stop)
                foreach ($edr in $edrServices) {
                    $svc = @($edrServiceInventory | Where-Object { [string]$_.Name -eq [string]$edr.Name })
                    if ($svc.Count -gt 1) { throw "EDR service identity is ambiguous: $($edr.Name)" }
                    if ($svc.Count -eq 1 -and $svc[0].Status -eq "Running") {
                        $securityProduct.ProductName = $edr.Display
                        break
                    }
                }

                if (-not $securityProduct.ProductName) {
                    $securityProduct.ProductName = "Unknown Security Product (Defender in Passive Mode)"
                }
            }
        }
        catch {
            Write-Verbose "Get-MpComputerStatus unavailable (continuing): $($_.Exception.Message)"
        }
    }

    # Final authority gate. Neither a successful Get-MpPreference call nor the
    # absence of a registered third-party product proves that Defender actively
    # enforces ASR. Conversely, an installed third-party product does not negate
    # an explicit Defender Normal/active status.
    try {
        $defenderAuthority = Get-MpComputerStatus -ErrorAction Stop
        $defenderIsPrimary = (
            [string]$defenderAuthority.AMRunningMode -eq 'Normal' -and
            [bool]$defenderAuthority.AntivirusEnabled -and
            [bool]$defenderAuthority.RealTimeProtectionEnabled
        )
        if ($defenderIsPrimary) {
            $securityProduct.Detected = $false
            $securityProduct.ProductName = 'Microsoft Defender Antivirus'
            $securityProduct.DetectionMethod = 'DefenderPrimaryAuthority'
        }
        else {
            $securityProduct.Detected = $true
            if (-not $securityProduct.ProductName) {
                $securityProduct.ProductName = "Defender enforcement not authoritative (mode=$($defenderAuthority.AMRunningMode))"
            }
            $securityProduct.DetectionMethod = 'DefenderNonPrimaryAuthority'
        }
    }
    catch {
        $securityProduct.Detected = $true
        $securityProduct.ProductName = "Defender enforcement authority unknown: $($_.Exception.Message)"
        $securityProduct.DetectionMethod = 'DefenderAuthorityQueryFailed'
    }

    # Also check: Defender not running at all + no product detected via SecurityCenter2
    # but product may still be present (fallback for edge cases)
    if (-not $securityProduct.Detected) {
        try {
            $null = Get-MpPreference -ErrorAction Stop
        }
        catch {
            # Get-MpPreference failed = Defender is not functional
            # This means something else is managing AV, even if we can't identify it
            $securityProduct.Detected = $true
            $securityProduct.ProductName = "Unknown Security Product (Defender unavailable)"
            $securityProduct.DetectionMethod = "DefenderUnavailable"
        }
    }

    # If a third-party endpoint product is detected, ASR cannot be enabled by NoID Privacy and the
    # rules also cannot be verified -- ASR is a Defender-specific API. We surface this
    # honestly rather than counting unverified rules as "Passed".
    if ($securityProduct.Detected) {
        Write-Host "  Defender ASR enforcement is not authoritative: $($securityProduct.ProductName)" -ForegroundColor Cyan
        Write-Host "  ASR (Attack Surface Reduction) is a Defender-only API and cannot" -ForegroundColor Yellow
        Write-Host "  be verified by NoID Privacy when Defender is not the primary engine." -ForegroundColor Yellow
        Write-Host "  $($securityProduct.ProductName) may provide equivalent protection (behavioral" -ForegroundColor Gray
        Write-Host "  analysis, exploit prevention, ML-based detection, etc.) -- consult" -ForegroundColor Gray
        Write-Host "  vendor documentation to confirm." -ForegroundColor Gray

        # Do NOT count unverified ASR rules as Passed. Each declared rule remains visible as
        # NotChecked because NoID Privacy cannot prove equivalent coverage from a third-party engine.
        $asrNotChecked = @($asrApplicableRules | ForEach-Object {
            $normalizedRuleId = ([Guid]([string]$_.GUID)).ToString('D').ToLowerInvariant()
            $expectedAction = if ($null -ne $sealedAppliedAsrPlan) {
                [int]$sealedAppliedAsrPlan.ActionMap[$normalizedRuleId]
            }
            else { [int]$_.Action }
            [PSCustomObject]@{
                Rule = [string]$_.Name
                Expected = "Configured Defender ASR action $expectedAction"
                Actual = "Defender ASR authority unavailable: $($securityProduct.ProductName)"
                CheckState = 'NotChecked'
                VerificationDisposition = 'CannotVerify'
                VerificationEvidenceSource = 'RuntimeQuery'
                VerificationReasonCode = 'ASR.DefenderAuthorityUnavailable'
                AffectedTargetCount = 1
            }
        })
        $asrNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
            -Details $asrNotChecked -ExpectedCount $asrApplicableRules.Count `
            -Context 'ASR NotChecked evidence'
        $results.AllSettings += [PSCustomObject]@{
            Category      = "ASR"
            Total         = $EXPECTED_ASR_COUNT
            Passed        = 0
            Failed        = 0
            NotChecked    = $asrApplicableRules.Count
            NotCheckedDeliberate = $asrNotCheckedAccounting.ByChoice
            NotCheckedNoSavedChoice = $asrNotCheckedAccounting.NoSavedChoice
            NotCheckedCannotVerify = $asrNotCheckedAccounting.CannotVerify
            NotApplicable = $asrNotApplicableRules.Count
            PassedDetails = @()
            FailedDetails = @()
            NotCheckedDetails = $asrNotChecked
            NotApplicableDetails = $asrNotApplicableDetails
        }

        $asrPresentation = Get-VerificationModulePresentation `
            -Name 'ASR Rules' -Total $EXPECTED_ASR_COUNT -Passed 0 -Failed 0 `
            -NotChecked $asrApplicableRules.Count -NotCheckedDeliberate $asrNotCheckedAccounting.ByChoice `
            -NotApplicable $asrNotApplicableRules.Count `
            -Summary "0 verified; $($asrApplicableRules.Count) unproven because Defender is not authoritative; $($asrNotApplicableRules.Count) not applicable ($EXPECTED_ASR_COUNT declared)."
        Write-VerificationModulePresentation -Presentation $asrPresentation
    }
    else {
        # Defender is active - verify ASR rules normally
        $mpPreference = Get-MpPreference
        $currentASRIds = @($mpPreference.AttackSurfaceReductionRules_Ids)
        $currentASRActions = @($mpPreference.AttackSurfaceReductionRules_Actions)
        # Get-MpPreference represents an unconfigured ASR state as one null
        # placeholder in each array (same contract as ConvertFrom-ASRPreference);
        # only that exact paired representation collapses to the empty state.
        if ($currentASRIds.Count -eq 1 -and $currentASRActions.Count -eq 1 -and
            $null -eq $currentASRIds[0] -and $null -eq $currentASRActions[0]) {
            $currentASRIds = @()
            $currentASRActions = @()
        }
        if ($currentASRIds.Count -ne $currentASRActions.Count) {
            throw "Defender returned mismatched ASR IDs/actions: $($currentASRIds.Count)/$($currentASRActions.Count)"
        }
        $seenCurrentASR = [System.Collections.Generic.HashSet[Guid]]::new()
        foreach ($currentASRId in @($currentASRIds)) {
            $parsedCurrentASRId = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$currentASRId, [ref]$parsedCurrentASRId) -or
                -not $seenCurrentASR.Add($parsedCurrentASRId)) {
                throw "Defender returned an invalid or duplicate ASR rule ID: $currentASRId"
            }
        }

        $asrFailed = @()
        $asrPassed = @()

        # Check if ASR rules are configured at all
        if ($null -eq $currentASRIds -or $currentASRIds.Count -eq 0) {
            # No ASR rules configured - mark all as failed
            foreach ($rule in $asrApplicableRules) {
                $results.Failed++
                $normalizedRuleId = ([Guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
                $expectedAction = if ($null -ne $sealedAppliedAsrPlan) {
                    [int]$sealedAppliedAsrPlan.ActionMap[$normalizedRuleId]
                }
                else { [int]$rule.Action }
                $expectedActionText = if ($expectedAction -eq 1) { "Block" } elseif ($expectedAction -eq 2) { "Audit" } elseif ($expectedAction -eq 6) { 'Warn' } else { "Disabled" }
                $asrFailed += [PSCustomObject]@{
                    Rule     = $rule.Name
                    GUID     = $rule.GUID
                    Expected = $expectedActionText
                    Actual   = "Not configured"
                }
            }
        }
        else {
            # Rules where both BLOCK (1) and AUDIT (2) are considered "Pass"
            # These are user-configurable rules where either mode is valid
            $flexibleRules = @(
                "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # PSExec/WMI (Management Tools)
                "01443614-cd74-433a-b99e-2ecdc07bfc25"   # Prevalence (New/Unknown Software)
            )

            foreach ($rule in $asrApplicableRules) {
                # Case-insensitive GUID matching (Get-MpPreference may return different case)
                $index = -1
                for ($i = 0; $i -lt $currentASRIds.Count; $i++) {
                    if ($currentASRIds[$i] -eq $rule.GUID) {
                        $index = $i
                        break
                    }
                }

                if ($index -ge 0) {
                    $actualAction = $currentASRActions[$index]
                    $normalizedRuleId = ([Guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
                    $expectedAction = if ($null -ne $sealedAppliedAsrPlan) {
                        [int]$sealedAppliedAsrPlan.ActionMap[$normalizedRuleId]
                    }
                    else { [int]$rule.Action }

                    # Without an Apply session, the standalone verifier cannot
                    # reconstruct the earlier interactive choice for these two
                    # rules. Scoped post-Apply verification always has the
                    # sealed plan and therefore requires the exact action.
                    $isFlexibleRule = $null -eq $sealedAppliedAsrPlan -and $flexibleRules -contains $rule.GUID
                    $isActiveMode = $actualAction -in @(1, 2)  # Block or Audit

                    # For flexible rules: Pass if Block OR Audit
                    # For other rules: Pass only if exact match
                    $rulePassed = if ($isFlexibleRule) { $isActiveMode } else { $actualAction -eq $expectedAction }

                    if ($rulePassed) {
                        $results.Verified++
                        $actionText = if ($actualAction -eq 1) { "Block" } elseif ($actualAction -eq 2) { "Audit" } elseif ($actualAction -eq 6) { "Warn" } else { "Disabled" }
                        $asrPassed += [PSCustomObject]@{
                            Rule     = $rule.Name
                            Expected = if ($isFlexibleRule) { 'Block or Audit (Apply choice unavailable)' } else { $actionText }
                            Actual   = $actionText
                        }
                    }
                    else {
                        $results.Failed++
                        $expectedActionText = if ($expectedAction -eq 1) { "Block" } elseif ($expectedAction -eq 2) { "Audit" } elseif ($expectedAction -eq 6) { "Warn" } else { "Disabled" }
                        $actualActionText = if ($actualAction -eq 1) { "Block" } elseif ($actualAction -eq 2) { "Audit" } elseif ($actualAction -eq 6) { "Warn" } else { "Disabled" }
                        $asrFailed += [PSCustomObject]@{
                            Rule     = $rule.Name
                            GUID     = $rule.GUID
                            Expected = $expectedActionText
                            Actual   = $actualActionText
                        }
                    }
                }
                else {
                    $results.Failed++
                    $normalizedRuleId = ([Guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
                    $expectedAction = if ($null -ne $sealedAppliedAsrPlan) {
                        [int]$sealedAppliedAsrPlan.ActionMap[$normalizedRuleId]
                    }
                    else { [int]$rule.Action }
                    $expectedActionText = if ($expectedAction -eq 1) { "Block" } elseif ($expectedAction -eq 2) { "Audit" } elseif ($expectedAction -eq 6) { 'Warn' } else { "Disabled" }
                    $asrFailed += [PSCustomObject]@{
                        Rule     = $rule.Name
                        GUID     = $rule.GUID
                        Expected = $expectedActionText
                        Actual   = "Not configured"
                    }
                }
            }
        }

        # Add to AllSettings for HTML report
        $asrPassedCount = $asrApplicableRules.Count - $asrFailed.Count
        $results.AllSettings += [PSCustomObject]@{
            Category      = "ASR"
            Total         = $results.ASRRules
            Passed        = $asrPassedCount
            Failed        = $asrFailed.Count
            NotChecked    = 0
            NotApplicable = $asrNotApplicableRules.Count
            PassedDetails = $asrPassed
            FailedDetails = $asrFailed
            NotCheckedDetails = @()
            NotApplicableDetails = $asrNotApplicableDetails
        }

        if ($asrFailed.Count -gt 0) {
            $results.FailedSettings += [PSCustomObject]@{
                Category = "ASR"
                Count    = $asrFailed.Count
                Details  = $asrFailed
            }
        }

        $asrPresentation = Get-VerificationModulePresentation `
            -Name 'ASR Rules' -Total $results.ASRRules -Passed $asrPassedCount `
            -Failed $asrFailed.Count -NotChecked 0 -NotCheckedDeliberate 0 `
            -NotApplicable $asrNotApplicableRules.Count `
            -Summary "$asrPassedCount/$($asrApplicableRules.Count) applicable checks passed; $($asrFailed.Count) failed; $($asrNotApplicableRules.Count) not applicable ($($results.ASRRules) declared)."
        Write-VerificationModulePresentation -Presentation $asrPresentation
    }  # End of else (Defender active)
}
catch {
    $asrScopeFailure = [PSCustomObject]@{
        Rule = 'Complete ASR verification scope'; Path = 'ASR'
        Expected = "$EXPECTED_ASR_COUNT executable checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $knownASRNotApplicable = if ($null -ne $asrNotApplicableRules) { @($asrNotApplicableRules).Count } else { 0 }
    $asrFailureCount = $EXPECTED_ASR_COUNT - $knownASRNotApplicable
    $knownASRNADetails = if ($null -ne $asrNotApplicableDetails) { @($asrNotApplicableDetails) } else { @() }
    $results.AllSettings += [PSCustomObject]@{
        Category='ASR'; Total=$EXPECTED_ASR_COUNT; Passed=0; Failed=$asrFailureCount
        NotChecked=0; NotApplicable=$knownASRNotApplicable; PassedDetails=@(); FailedDetails=@($asrScopeFailure)
        NotCheckedDetails=@(); NotApplicableDetails=$knownASRNADetails
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category='ASR'; Count=$asrFailureCount; Details=@($asrScopeFailure)
    }
    $asrPresentation = Get-VerificationModulePresentation `
        -Name 'ASR Rules' -Total $EXPECTED_ASR_COUNT -Passed 0 -Failed $asrFailureCount `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable $knownASRNotApplicable `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $asrPresentation
}
}

# [ALWAYS] DNS Configuration (5 checks)
if (Test-VerificationModuleSelected 'DNS') {
Write-VerificationStep "Verifying DNS Configuration ($EXPECTED_DNS_COUNT checks)..."

try {
    if ($results.DNSChecks -ne 5) {
        throw "DNS verifier implements exactly five canonical checks but SettingsCounts declares $($results.DNSChecks)"
    }

    $canonicalAddress = {
        param([string]$Address)
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsedAddress)) {
            throw "Invalid DNS address: $Address"
        }
        $parsedAddress.ToString()
    }
    $orderedAddressesMatch = {
        param($Actual, $Expected)
        $actualList = @($Actual)
        $expectedList = @($Expected)
        if ($actualList.Count -ne $expectedList.Count) { return $false }
        for ($index = 0; $index -lt $expectedList.Count; $index++) {
            if ((& $canonicalAddress ([string]$actualList[$index])) -ne
                (& $canonicalAddress ([string]$expectedList[$index]))) {
                return $false
            }
        }
        return $true
    }

    $providersPath = Join-Path $rootPath 'Modules\DNS\Config\Providers.json'
    $providersConfig = Get-Content -LiteralPath $providersPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $requiredProviderKeys = @('cloudflare', 'quad9', 'adguard')
    if (@(Compare-Object -ReferenceObject ($requiredProviderKeys | Sort-Object) `
            -DifferenceObject @($providersConfig.providers.PSObject.Properties.Name | Sort-Object)).Count -gt 0) {
        throw 'DNS provider configuration does not contain exactly the three supported providers'
    }
    $providerDefinitions = @()
    foreach ($providerKey in $requiredProviderKeys) {
        $provider = $providersConfig.providers.$providerKey
        $templateUri = $null
        if (-not [Uri]::TryCreate([string]$provider.doh.template, [UriKind]::Absolute, [ref]$templateUri) -or
            $templateUri.Scheme -ne 'https') {
            throw "Invalid DoH template for provider '$providerKey'"
        }
        $expectedIntentToken = switch ($providerKey) {
            'cloudflare' { 'Cloudflare' }
            'quad9' { 'Quad9' }
            'adguard' { 'AdGuard' }
        }
        if ([string]$provider.intentToken -cne $expectedIntentToken) {
            throw "Invalid canonical DNS intent token for provider '$providerKey'"
        }
        $providerDefinitions += [PSCustomObject]@{
            Key      = $providerKey
            Token    = [string]$provider.intentToken
            Name     = [string]$provider.name
            IPv4     = @([string]$provider.ipv4.primary, [string]$provider.ipv4.secondary)
            IPv6     = @([string]$provider.ipv6.primary, [string]$provider.ipv6.secondary)
            Template = [string]$provider.doh.template
        }
        foreach ($address in @($provider.ipv4.primary, $provider.ipv4.secondary, $provider.ipv6.primary, $provider.ipv6.secondary)) {
            $null = & $canonicalAddress ([string]$address)
        }
    }

    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
        Where-Object { $_.Status -in @('Up', 'Disconnected') })
    if ($adapters.Count -eq 0) {
        throw 'No enabled/disconnected physical adapters are available for DNS verification'
    }

    # AdvancedSecurity's opt-in IPv6 disable writes DisabledComponents=0xFF,
    # which suppresses effective IPv6 resolver state without changing the
    # adapter binding or the static NameServer shown by Windows Settings. The
    # effective resolver and UI-visible native DoH layers are verified as
    # distinct scopes; only the exact documented full-disable mask is honored.
    $ipv6StackEnabled = $true
    $tcpip6ParametersPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if (Test-Path -LiteralPath $tcpip6ParametersPath) {
        $tcpip6ParametersKey = Get-Item -LiteralPath $tcpip6ParametersPath -ErrorAction Stop
        try {
            if ($tcpip6ParametersKey.GetValueNames() -contains 'DisabledComponents' -and
                ((([long]$tcpip6ParametersKey.GetValue('DisabledComponents')) -band 0xFF) -eq 0xFF)) {
                $ipv6StackEnabled = $false
            }
        }
        finally {
            $tcpip6ParametersKey.Close()
        }
    }

    $adapterStates = @()
    foreach ($adapter in $adapters) {
        $interfaceGuid = [string]$adapter.InterfaceGuid
        if (-not $interfaceGuid.StartsWith('{')) { $interfaceGuid = "{$interfaceGuid}" }
        $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop)
        $ipv4Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 2 })
        $ipv6Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 23 })
        if ($ipv4Instance.Count -ne 1 -or $ipv6Instance.Count -ne 1) {
            throw "DNS address-family state is incomplete for adapter '$($adapter.Name)'"
        }

        $ipv6Binding = @($adapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop)
        if ($ipv6Binding.Count -ne 1) {
            throw "IPv6 binding state is ambiguous for adapter '$($adapter.Name)'"
        }
        $familyRegistryState = @{}
        foreach ($familyDefinition in @(
                [PSCustomObject]@{ Family = 2; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuid" },
                [PSCustomObject]@{ Family = 23; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$interfaceGuid" }
            )) {
            $registryAddresses = @()
            $valueExists = $false
            $valueType = $null
            if (Test-Path -LiteralPath $familyDefinition.Path) {
                $interfaceKey = Get-Item -LiteralPath $familyDefinition.Path -ErrorAction Stop
                $valueExists = $interfaceKey.GetValueNames() -contains 'NameServer'
                if ($valueExists) {
                    $valueType = $interfaceKey.GetValueKind('NameServer').ToString()
                    $nameServerValue = [string]$interfaceKey.GetValue(
                        'NameServer',
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    if (-not [string]::IsNullOrWhiteSpace($nameServerValue)) {
                        $registryAddresses = @([regex]::Split($nameServerValue.Trim(), '[,\s]+') | Where-Object { $_ })
                    }
                }
            }
            $familyRegistryState[[int]$familyDefinition.Family] = [PSCustomObject]@{
                Exists    = $valueExists
                Type      = $valueType
                Addresses = $registryAddresses
            }
        }
        $adapterStates += [PSCustomObject]@{
            Name         = [string]$adapter.Name
            InterfaceGuid = $interfaceGuid
            IPv4         = @($ipv4Instance[0].ServerAddresses)
            IPv6         = @($ipv6Instance[0].ServerAddresses)
            IPv6Managed  = ([bool]$ipv6Binding[0].Enabled -and $ipv6StackEnabled)
            IPv6DohManaged = [bool]$ipv6Binding[0].Enabled
            IPv4Registry = $familyRegistryState[2]
            IPv6Registry = $familyRegistryState[23]
        }
    }

    $providerCandidates = @($providerDefinitions | Where-Object {
            $candidate = $_
            $matchesAllAdapters = $true
            foreach ($adapterState in $adapterStates) {
                if (-not (& $orderedAddressesMatch $adapterState.IPv4 $candidate.IPv4)) {
                    $matchesAllAdapters = $false
                    break
                }
            }
            $matchesAllAdapters
        })
    $detectedProvider = if ($providerCandidates.Count -eq 1) { $providerCandidates[0] } else { $null }

    # The engine documents a no-takeover choice (interactive '[0] Skip' /
    # provider KEEP leaves the system resolver untouched). A public-resolver
    # DoH catalog entry is not evidence that Windows selected that resolver:
    # current Windows images can ship those dormant entries themselves. Only
    # adapter resolver state or an active managed DoH policy is a takeover
    # signature when no exact provider state can be resolved.
    $dnsChoicesAuthoritative = $appliedScopeRun -or $null -ne $dnsIntent
    $dnsKeepDeclared = $dnsChoicesAuthoritative -and (Test-DNSKeepDecision `
            -FrameworkConfig $frameworkConfig `
            -DnsIntent $dnsIntent)
    $intendedDnsProvider = if ($appliedScopeRun -and -not $dnsKeepDeclared) {
        [string]$frameworkConfig.modules.DNS.provider
    }
    elseif ($dnsIntent) { [string]$dnsIntent.provider }
    else { $null }
    $intendedDohMode = if ($appliedScopeRun -and -not $dnsKeepDeclared) {
        [string]$frameworkConfig.modules.DNS.dohMode
    }
    elseif ($dnsIntent) { [string]$dnsIntent.dohMode }
    else { $null }
    if ($dnsChoicesAuthoritative -and -not $dnsKeepDeclared -and
        ($intendedDnsProvider -notin @('Quad9', 'Cloudflare', 'AdGuard') -or $intendedDohMode -notin @('REQUIRE', 'ALLOW'))) {
        throw 'Authoritative DNS intent is incomplete or invalid'
    }
    $selectedProvider = if ($detectedProvider -and
        (-not $dnsChoicesAuthoritative -or
            (-not $dnsKeepDeclared -and [string]$detectedProvider.Token -ceq $intendedDnsProvider))) {
        $detectedProvider
    }
    else { $null }
    $dnsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $dnsPolicyValue = $null
    if (Test-Path -LiteralPath $dnsPolicyPath) {
        $dnsPolicyKey = Get-Item -LiteralPath $dnsPolicyPath -ErrorAction Stop
        if ($dnsPolicyKey.GetValueNames() -contains 'DoHPolicy' -and
            $dnsPolicyKey.GetValueKind('DoHPolicy').ToString() -eq 'DWord') {
            $dnsPolicyValue = [int]$dnsPolicyKey.GetValue('DoHPolicy')
        }
    }
    $managedDohPolicyPresent = [bool]($null -ne $dnsPolicyValue -and $dnsPolicyValue -in @(2, 3))
    $dnsTakeoverEvidence = $null -eq $selectedProvider -and
        (Test-DNSManagedTakeoverEvidence `
            -AdapterStates @($adapterStates) `
            -ProviderDefinitions @($providerDefinitions) `
            -ManagedDohPolicyPresent:$managedDohPolicyPresent)

    $dnsChecks = [System.Collections.Generic.List[object]]::new()

    $primaryIPv4Ok = $null -ne $selectedProvider
    $secondaryIPv4Ok = $null -ne $selectedProvider
    if ($selectedProvider) {
        foreach ($adapterState in $adapterStates) {
            $registryStateOk = $adapterState.IPv4Registry.Exists -and
                $adapterState.IPv4Registry.Type -in @('String', 'ExpandString') -and
                (& $orderedAddressesMatch $adapterState.IPv4Registry.Addresses $selectedProvider.IPv4)
            if (-not $registryStateOk) {
                $primaryIPv4Ok = $false
                $secondaryIPv4Ok = $false
            }
        }
    }
    $null = $dnsChecks.Add([PSCustomObject]@{
            Check = 'Primary IPv4 resolver'; Passed = $primaryIPv4Ok
            Expected = 'Selected provider primary IPv4 on every physical adapter with a static NameServer override'
            Actual = if ($selectedProvider -and $primaryIPv4Ok) { "$($selectedProvider.Name): $($selectedProvider.IPv4[0])" } else { 'No single exact provider/static adapter state' }
        })
    $null = $dnsChecks.Add([PSCustomObject]@{
            Check = 'Secondary IPv4 resolver'; Passed = $secondaryIPv4Ok
            Expected = 'Selected provider secondary IPv4 on every physical adapter in exact order'
            Actual = if ($selectedProvider -and $secondaryIPv4Ok) { "$($selectedProvider.Name): $($selectedProvider.IPv4[1])" } else { 'No single exact provider/static adapter state' }
        })

    $ipv6Ok = $null -ne $selectedProvider
    $managedIPv6Adapters = @($adapterStates | Where-Object { $_.IPv6Managed })
    $nativeIPv6Adapters = @($adapterStates | Where-Object { $_.IPv6DohManaged })
    if ($selectedProvider) {
        foreach ($adapterState in $nativeIPv6Adapters) {
            if (($adapterState.IPv6Managed -and
                    -not (& $orderedAddressesMatch $adapterState.IPv6 $selectedProvider.IPv6)) -or
                -not $adapterState.IPv6Registry.Exists -or
                $adapterState.IPv6Registry.Type -notin @('String', 'ExpandString') -or
                -not (& $orderedAddressesMatch $adapterState.IPv6Registry.Addresses $selectedProvider.IPv6)) {
                $ipv6Ok = $false
                break
            }
        }
    }
    $null = $dnsChecks.Add([PSCustomObject]@{
            Check = 'IPv6 resolver pair / sealed scope'; Passed = $ipv6Ok
            Expected = 'Exact provider IPv6 pair in every binding-enabled adapter registry; effective readback also required while the IPv6 stack is enabled'
            Actual = if ($ipv6Ok) { "$($nativeIPv6Adapters.Count) UI-visible and $($managedIPv6Adapters.Count) transport-enabled IPv6 adapter(s) exact" } else { 'Provider IPv6 state mismatch' }
        })

    $dohSettings = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
    $ownedDohEntries = @()
    $dohRegistrationsOk = $null -ne $selectedProvider
    if ($selectedProvider) {
        foreach ($address in @($selectedProvider.IPv4 + $selectedProvider.IPv6)) {
            $canonicalExpected = & $canonicalAddress $address
            $dohMatches = @($dohSettings | Where-Object {
                    (& $canonicalAddress ([string]$_.ServerAddress)) -eq $canonicalExpected
                })
            if ($dohMatches.Count -ne 1 -or
                [string]$dohMatches[0].DohTemplate -cne $selectedProvider.Template -or
                -not [bool]$dohMatches[0].AutoUpgrade) {
                $dohRegistrationsOk = $false
            }
            if ($dohMatches.Count -eq 1) { $ownedDohEntries += $dohMatches[0] }
        }
    }
    $null = $dnsChecks.Add([PSCustomObject]@{
            Check = 'DoH endpoint registrations'; Passed = $dohRegistrationsOk
            Expected = 'All four selected provider endpoints registered once with the exact HTTPS template and AutoUpgrade=true'
            Actual = if ($dohRegistrationsOk) { '4/4 exact registrations' } else { "$($ownedDohEntries.Count)/4 exact-or-present registrations" }
        })

    $policyOk = $false
    $policyText = 'Missing or invalid'
    if ($null -ne $dnsPolicyValue) {
        $policyValue = [int]$dnsPolicyValue
        $policyModeMatchesIntent = -not $dnsChoicesAuthoritative -or $dnsKeepDeclared -or
            ($intendedDohMode -eq 'ALLOW' -and $policyValue -eq 2) -or
            ($intendedDohMode -eq 'REQUIRE' -and $policyValue -eq 3)
        if ($policyValue -in @(2, 3) -and $policyModeMatchesIntent -and $dohRegistrationsOk -and $ownedDohEntries.Count -eq 4) {
            $expectedFallback = ($policyValue -eq 2)
            $fallbackMismatchCount = @($ownedDohEntries | Where-Object {
                    [bool]$_.AllowFallbackToUdp -ne $expectedFallback
                }).Count
            $interfaceDohMismatchCount = 0
            foreach ($adapterState in $adapterStates) {
                foreach ($interfaceFamily in @(
                        [PSCustomObject]@{ Family = 2; Servers = $selectedProvider.IPv4; Managed = $true },
                        [PSCustomObject]@{ Family = 23; Servers = $selectedProvider.IPv6; Managed = [bool]$adapterState.IPv6DohManaged }
                    ) | Where-Object { $_.Managed }) {
                    $expectedInterfaceDoh = ConvertTo-DnsInterfaceDohTargetState `
                        -AddressFamily ([int]$interfaceFamily.Family) `
                        -NameServers @($interfaceFamily.Servers) `
                        -DohTemplate ([string]$selectedProvider.Template) `
                        -AllowFallbackToUdp $expectedFallback
                    $actualInterfaceDoh = Get-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                        -AddressFamily ([int]$interfaceFamily.Family)
                    if (-not (Test-DnsInterfaceDohStateExact `
                            -Actual $actualInterfaceDoh -Expected $expectedInterfaceDoh)) {
                        $interfaceDohMismatchCount++
                    }
                }
            }
            $policyOk = $fallbackMismatchCount -eq 0 -and $interfaceDohMismatchCount -eq 0
            $modeText = if ($policyValue -eq 2) { 'ALLOW/fallback=true' } else { 'REQUIRE/fallback=false' }
            $interfaceFamilyCount = $adapterStates.Count + @($adapterStates | Where-Object IPv6DohManaged).Count
            $policyText = "$modeText; $(4 - $fallbackMismatchCount)/4 endpoint flags and $($interfaceFamilyCount - $interfaceDohMismatchCount)/$interfaceFamilyCount native adapter-family states matched"
        }
    }
    $null = $dnsChecks.Add([PSCustomObject]@{
            Check = 'DoH policy and fallback'; Passed = $policyOk
            Expected = $(if ($dnsChoicesAuthoritative -and -not $dnsKeepDeclared) { "$intendedDohMode mode on 4/4 endpoints and every managed native adapter-family DoH state" } else { 'DWORD 3/fallback=false or DWORD 2/fallback=true on 4/4 endpoints and every managed native adapter-family DoH state' })
            Actual = $policyText
        })

    if ($dnsChecks.Count -ne $results.DNSChecks) {
        throw "DNS verifier produced $($dnsChecks.Count) checks; expected $($results.DNSChecks)"
    }

    # Honor the documented no-takeover choice instead of reporting it as five
    # hard failures:
    #  - authoritative KEEP -> the checks become deliberate NotChecked
    #    placeholders regardless of the preserved live resolver state
    #  - zero signature without a KEEP declaration in a non-authoritative run
    #    -> plain NotChecked (open uncertainty, never silently green)
    #  - any partial provider signature -> the exact results above stand
    #    (drift, not a choice)
    $dnsNotChecked = @()
    if ($null -eq $selectedProvider -and $dnsKeepDeclared -and $dnsChoicesAuthoritative) {
        $dnsNotChecked = @($dnsChecks | ForEach-Object {
                [PSCustomObject]@{
                    Check = [string]$_.Check; Expected = [string]$_.Expected
                    Actual = 'Excluded by saved DNS choice: resolver takeover was skipped (provider KEEP)'
                    CheckState = 'NotChecked'
                    VerificationDisposition = 'ByChoice'
                    VerificationEvidenceSource = 'ApplyIntent'
                    VerificationReasonCode = 'DNS.TakeoverSkipped'
                    AffectedTargetCount = 1
                }
            })
    }
    elseif ($null -eq $selectedProvider -and -not $dnsChoicesAuthoritative -and -not $dnsTakeoverEvidence) {
        $dnsNotChecked = @($dnsChecks | ForEach-Object {
                [PSCustomObject]@{
                    Check = [string]$_.Check; Expected = [string]$_.Expected
                    Actual = 'No saved DNS choice; live state contains no exact NoID Privacy provider signature, so takeover is not inferred.'
                    CheckState = 'NotChecked'
                    VerificationDisposition = 'NoSavedChoice'
                    VerificationEvidenceSource = 'None'
                    VerificationReasonCode = 'DNS.NoSavedChoice'
                    AffectedTargetCount = 1
                }
            })
    }

    if ($dnsNotChecked.Count -gt 0) {
        $dnsNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
            -Details $dnsNotChecked -ExpectedCount $dnsNotChecked.Count `
            -Context 'DNS NotChecked evidence'
        $results.NotChecked += $dnsNotChecked.Count
        $results.AllSettings += [PSCustomObject]@{
            Category      = "DNS"
            Total         = $results.DNSChecks
            Passed        = 0
            Failed        = 0
            NotChecked    = $dnsNotChecked.Count
            NotCheckedDeliberate = $dnsNotCheckedAccounting.ByChoice
            NotCheckedNoSavedChoice = $dnsNotCheckedAccounting.NoSavedChoice
            NotCheckedCannotVerify = $dnsNotCheckedAccounting.CannotVerify
            NotApplicable = 0
            PassedDetails = @()
            FailedDetails = @()
            NotCheckedDetails = $dnsNotChecked
            NotApplicableDetails = @()
        }
        $dnsNotCheckedDeliberate = $dnsNotCheckedAccounting.ByChoice
        $dnsSummary = if ($dnsNotCheckedDeliberate -eq $dnsNotChecked.Count) {
            "DNS takeover deliberately skipped by saved Apply choice; $($dnsNotChecked.Count) intentional exclusions ($($results.DNSChecks) declared)."
        }
        else {
            "0 verified; 0 failed; $($dnsNotChecked.Count) unproven because the saved DNS selection is unavailable ($($results.DNSChecks) declared)."
        }
        $dnsPresentation = Get-VerificationModulePresentation `
            -Name 'DNS' -Total $results.DNSChecks -Passed 0 -Failed 0 `
            -NotChecked $dnsNotChecked.Count -NotCheckedDeliberate $dnsNotCheckedDeliberate `
            -NotApplicable 0 -Summary $dnsSummary
        Write-VerificationModulePresentation -Presentation $dnsPresentation
    }
    else {
        $dnsPassed = @($dnsChecks | Where-Object { $_.Passed })
        $dnsFailed = @($dnsChecks | Where-Object { -not $_.Passed })
        $results.Verified += $dnsPassed.Count
        $results.Failed += $dnsFailed.Count
        $results.AllSettings += [PSCustomObject]@{
            Category      = "DNS"
            Total         = $results.DNSChecks
            Passed        = $dnsPassed.Count
            Failed        = $dnsFailed.Count
            NotChecked    = 0
            NotApplicable = 0
            PassedDetails = $dnsPassed
            FailedDetails = $dnsFailed
            NotCheckedDetails = @()
            NotApplicableDetails = @()
        }

        if ($dnsFailed.Count -gt 0) {
            $results.FailedSettings += [PSCustomObject]@{
                Category = "DNS"
                Count    = $dnsFailed.Count
                Details  = $dnsFailed
            }
        }

        $dnsPresentation = Get-VerificationModulePresentation `
            -Name 'DNS' -Total $results.DNSChecks -Passed $dnsPassed.Count -Failed $dnsFailed.Count `
            -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
            -Summary "$($dnsPassed.Count)/$($results.DNSChecks) checks passed; $($dnsFailed.Count) failed."
        Write-VerificationModulePresentation -Presentation $dnsPresentation
    }
}
catch {
    $results.Failed += $results.DNSChecks
    $dnsFailureDetail = [PSCustomObject]@{
        Check = 'DNS verification scope'
        Expected = 'All canonical DNS checks executable'
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category = 'DNS'; Total = $results.DNSChecks; Passed = 0; Failed = $results.DNSChecks
        NotChecked = 0; NotApplicable = 0; PassedDetails = @(); FailedDetails = @($dnsFailureDetail)
        NotCheckedDetails = @(); NotApplicableDetails = @()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category = 'DNS'; Count = $results.DNSChecks; Details = @($dnsFailureDetail)
    }
    $dnsPresentation = Get-VerificationModulePresentation `
        -Name 'DNS' -Total $results.DNSChecks -Passed 0 -Failed $results.DNSChecks `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $dnsPresentation
}
}

# [ALWAYS] Privacy Compliance Checks (loaded dynamically from the active mode
# plus the always-applied OneDrive/Store target set). Destructive AppX removal
# is intentionally outside the exact BAVR framework and is not a compliance target.
if (Test-VerificationModuleSelected 'Privacy') {
$privacyVerifiedBefore = $results.Verified
$privacyFailedBefore = $results.Failed
$privacyNotCheckedBefore = $results.NotChecked
$privacyNotApplicableBefore = $results.NotApplicable
$privacyExpectedForRun = $EXPECTED_PRIVACY_COUNT
$privacyStepWritten = $false
$privacyIntentMissing = $false
try {
    $privacyFailed = @()
    $privacyPassed = @()
    $privacyNotChecked = @()
    $privacyNotApplicable = @()

    # ==========================================================================
    # LOAD REGISTRY CHECKS FROM Privacy-<Mode>.json (exact intent comparison)
    # ==========================================================================
    # Mode -> file mapping. A scoped run receives the exact Apply config; a
    # standalone run may use only the durable machine-local Apply intent. It
    # never infers a mode from a best-match ratio or from surviving backups.
    $privacyIntentForRun = if ($appliedScopeRun) { $frameworkConfig.modules.Privacy } else { $privacyIntent }
    $privacyChoicesAuthoritative = $null -ne $privacyIntentForRun

    # Establish the fail-closed magnitude HERE, before any fragile live query.
    # The seed above is the MSRecommended total (63); everything from the helper
    # loading below onwards can throw - Get-PrivacyApplicability itself queries
    # CIM and the registry and throws on unknown editions, and later steps
    # resolve the interactive Explorer user, load its hive, call Get-Service and
    # Get-ScheduledTask - and on a Paranoid machine (117 declared targets) the
    # catch then published "Privacy Total=63, Failed=63" and an HTML scope label
    # claiming the maximum scope had been used. Both halves were false. The mode
    # is readable from durable intent without touching Windows at all; only when
    # even that is unreadable do we fall back to the declared maximum, which is
    # the same fail-closed choice the later catch already makes.
    $privacyResolvedModeForScope = if ($privacyChoicesAuthoritative) {
        [string]$privacyIntentForRun.mode
    } else { '' }
    if ($privacyResolvedModeForScope -in @('MSRecommended', 'Strict', 'Paranoid')) {
        $privacyExpectedForRun = _GetPrivacyModeCount -Mode $privacyResolvedModeForScope
        # Name the mode the scope belongs to even if verification never completes,
        # so the report cannot describe a 117-target scope as an unproven profile.
        $results.PrivacyMode = $privacyResolvedModeForScope
    }
    else {
        $privacyExpectedForRun = _GetPrivacyModeCount -Mode 'Paranoid'
    }

    $privacyManagementHelper = Join-Path $rootPath 'Modules\Privacy\Private\Get-PrivacyManagementState.ps1'
    $privacyUcpdHelper = Join-Path $rootPath 'Modules\Privacy\Private\Get-PrivacyUcpdProtectionState.ps1'
    $privacyApplicabilityHelper = Join-Path $rootPath 'Modules\Privacy\Private\Get-PrivacyApplicability.ps1'
    $privacyTier1Helper = Join-Path $rootPath 'Modules\Privacy\Private\Get-PrivacyTier1PolicyDefinition.ps1'
    $privacyUserContextHelper = Join-Path $rootPath 'Modules\Privacy\Private\Get-PrivacyUserContext.ps1'
    $privacyWindowsSearchHelper = Join-Path $rootPath 'Modules\Privacy\Private\PrivacyWindowsSearch.ps1'
    foreach ($privacyHelper in @(
            $privacyManagementHelper, $privacyUcpdHelper, $privacyApplicabilityHelper,
            $privacyTier1Helper, $privacyUserContextHelper, $privacyWindowsSearchHelper
        )) {
        if (-not (Test-Path -LiteralPath $privacyHelper -PathType Leaf)) {
            throw "Privacy applicability helper is missing: $privacyHelper"
        }
        . $privacyHelper
    }
    $privacyApplicability = Get-PrivacyApplicability
    # A standalone run always measures all three profile scorecards from live
    # Windows state. The durable Apply intent labels the selected comparison;
    # it never suppresses or changes these measurements.
    if (-not $appliedScopeRun) {
        $privacyUser = Get-PrivacyUserContext -Refresh
        if (-not $privacyUser -or [string]$privacyUser.Sid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') {
            throw 'Privacy scorecards could not resolve the interactive Explorer user'
        }
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop
        }
        $privacyUserRootForScores = "HKU:\$([string]$privacyUser.Sid)"
        if (-not (Test-Path -LiteralPath $privacyUserRootForScores -PathType Container)) {
            throw 'Privacy scorecards require the interactive user hive to be loaded'
        }
        $searchStateForScores = Invoke-PrivacyWindowsSearchUserState -User $privacyUser -Operation Query
        if (-not [bool]$searchStateForScores.Success) {
            throw 'Privacy scorecards could not query effective Windows Search state'
        }
        $oneDriveScorePath = Join-Path $rootPath 'Modules\Privacy\Config\OneDrive.json'
        # Query each provider decisively once. A provider failure is uncertainty,
        # never evidence that every declared service/task is absent.
        $privacyScorecardServices = @(Get-Service -ErrorAction Stop)
        $privacyScorecardTasks = @(Get-ScheduledTask -ErrorAction Stop)
        $scorecards = @()
        foreach ($candidateMode in @('MSRecommended', 'Strict', 'Paranoid')) {
            $candidatePath = Join-Path $rootPath ("Modules\Privacy\Config\Privacy-{0}.json" -f $candidateMode)
            $candidateConfig = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $candidateChecks = @(Get-RegistryChecksFromJson -JsonPath $candidatePath) +
                @(Get-RegistryChecksFromJson -JsonPath $oneDriveScorePath)
            $matched = 0
            $mismatched = 0
            $notApplicable = 0
            $mismatchDetails = @()
            foreach ($candidateCheck in $candidateChecks) {
                $candidateApplicability = Get-PrivacyTargetApplicability `
                    -Path ([string]$candidateCheck.Path) `
                    -Name ([string]$candidateCheck.Name) `
                    -Applicability $privacyApplicability
                if (-not $candidateApplicability.Applicable) { $notApplicable++; continue }
                $candidateLivePath = if ([string]$candidateCheck.Path -like 'HKCU:\*') {
                    $privacyUserRootForScores + '\' + ([string]$candidateCheck.Path).Substring(6)
                } else { [string]$candidateCheck.Path }
                $candidatePassed = Test-RegistryValue `
                    -Path $candidateLivePath -Name ([string]$candidateCheck.Name) `
                    -ExpectedValue $candidateCheck.Value
                if ($candidatePassed) {
                    $candidateKey = Get-Item -LiteralPath $candidateLivePath -ErrorAction Stop
                    $candidatePassed = $candidateKey.GetValueKind([string]$candidateCheck.Name).ToString() -ceq [string]$candidateCheck.Type
                }
                if ($candidatePassed -and [string]$candidateCheck.Name -ceq 'BingSearchEnabled' -and
                    $candidateLivePath -match '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Search$') {
                    $candidatePassed = -not [bool]$searchStateForScores.WebResultsEnabled
                }
                if ($candidatePassed) { $matched++ }
                else {
                    $mismatched++
                    if ($mismatchDetails.Count -lt 12) {
                        $mismatchDetails += "$candidateLivePath\$([string]$candidateCheck.Name)"
                    }
                }
            }
            foreach ($candidateService in @($candidateConfig.Services)) {
                $serviceMatches = @($privacyScorecardServices | Where-Object {
                        [string]$_.Name -ceq [string]$candidateService.Name
                    })
                if ($serviceMatches.Count -eq 0) { $notApplicable++; continue }
                if ($serviceMatches.Count -gt 1) {
                    throw "Privacy scorecard service inventory is ambiguous: $([string]$candidateService.Name)"
                }
                $service = $serviceMatches[0]
                if ([string]$service.StartType -ceq [string]$candidateService.StartupType -and
                    [string]$service.Status -ceq 'Stopped') { $matched++ }
                else { $mismatched++; $mismatchDetails += "service:$([string]$candidateService.Name)" }
            }
            foreach ($candidateTaskPath in @($candidateConfig.ScheduledTasks)) {
                $taskLeaf = Split-Path ([string]$candidateTaskPath) -Leaf
                $taskFolder = ([string]$candidateTaskPath).Substring(0, ([string]$candidateTaskPath).Length - $taskLeaf.Length)
                $taskMatches = @($privacyScorecardTasks | Where-Object {
                        [string]$_.TaskPath -ceq $taskFolder -and [string]$_.TaskName -ceq $taskLeaf
                    })
                if ($taskMatches.Count -eq 0) { $notApplicable++; continue }
                if ($taskMatches.Count -gt 1) {
                    throw "Privacy scorecard scheduled-task inventory is ambiguous: $candidateTaskPath"
                }
                $task = $taskMatches[0]
                if ([string]$task.State -ceq 'Disabled') { $matched++ }
                else { $mismatched++; $mismatchDetails += "task:$candidateTaskPath" }
            }
            $scorecards += [PSCustomObject]@{
                Mode = $candidateMode
                Scope = 'Mode-specific base targets; shared 27-target Tier 1 app-policy opt-in excluded'
                Matched = $matched
                Mismatched = $mismatched
                NotApplicable = $notApplicable
                ApplicableTotal = $matched + $mismatched
                ExactMatch = ($mismatched -eq 0 -and $matched -gt 0)
                MismatchDetails = @($mismatchDetails | Select-Object -First 12)
            }
        }
        $results.PrivacyProfileScorecards = @($scorecards)
        if (-not $privacyChoicesAuthoritative) {
            $privacyIntentMissing = $true
            # Never let absence or drift in stronger controls silently shrink
            # the scope to a smaller profile. Keep the maximum declared Privacy
            # magnitude. The three live scorecards remain machine-readable
            # diagnostics only; competing profile comparisons are not printed
            # beside the one user-facing Privacy verdict.
            $privacyExpectedForRun = _GetPrivacyModeCount -Mode 'Paranoid'
            throw 'No valid Privacy Apply intent exists. Live scorecards were measured, but none is silently promoted to the user-selected profile.'
        }
    }
    $privacyMode = [string]$privacyIntentForRun.mode
    if ($privacyMode -notin @('MSRecommended', 'Strict', 'Paranoid')) {
        throw "Canonical Privacy mode is invalid: '$privacyMode'"
    }
    # Establish the fail-closed magnitude as soon as the configured mode is
    # known. Standalone detection may refine the mode below; authoritative GUI
    # runs retain this exact Apply-time choice.
    $privacyExpectedForRun = _GetPrivacyModeCount -Mode $privacyMode
    $disableCloudClipboardConfigured = $true
    if ($privacyIntentForRun.PSObject.Properties['disableCloudClipboard']) {
        if ($privacyIntentForRun.disableCloudClipboard -isnot [bool]) {
            throw 'Canonical Privacy disableCloudClipboard decision must be Boolean'
        }
        $disableCloudClipboardConfigured = [bool]$privacyIntentForRun.disableCloudClipboard
    }
    # Tier 1 remains in the declared scope for every decision. On a supported
    # host, false is NotChecked; on an unsupported/externally-managed host it is
    # NotApplicable. It never disappears from the published count.
    # Tier 2 classic bloatware removal is a best-effort, non-exact-BAVR action and
    # is intentionally outside this verifier's declared registry/service/task scope.
    $tier1PolicySelected = $false
    if ($privacyIntentForRun.PSObject.Properties['applyStorePackagePolicy']) {
        if ($privacyIntentForRun.applyStorePackagePolicy -isnot [bool]) {
            throw 'Canonical Privacy applyStorePackagePolicy decision must be Boolean'
        }
        $tier1PolicySelected = [bool]$privacyIntentForRun.applyStorePackagePolicy
    }

    $privacyModeSource = if ($appliedScopeRun) { 'exact transaction-bound Apply configuration' } else { 'durable Apply intent; state measured live' }

    # The progress heading, failure magnitude, final JSON and HTML report must
    # all describe the same active mode-dependent scope.
    $privacyExpectedForRun = _GetPrivacyModeCount -Mode $privacyMode
    Write-VerificationStep "Verifying Privacy - selected profile $privacyMode ($privacyExpectedForRun targets)..."
    $privacyStepWritten = $true
    Write-Host "  NOTE: Tier 2 best-effort app removal is outside this verifier's exact scope;" -ForegroundColor Gray
    Write-Host "  apps reinstalled by Store/Windows Update are not detected here." -ForegroundColor Gray

    $privacyJsonPath = Join-Path $rootPath ("Modules\Privacy\Config\Privacy-{0}.json" -f $privacyMode)
    if (-not (Test-Path -LiteralPath $privacyJsonPath -PathType Leaf)) {
        throw "Canonical Privacy mode configuration is missing: $privacyJsonPath"
    }
    Write-Host "  Selected Privacy profile: $privacyMode ($privacyModeSource)" -ForegroundColor Cyan
    # Recorded for the HTML report: the declared grand total moves with this
    # mode (63/88/117 Privacy targets), so the report names the mode next to
    # the total instead of letting a scope shift read like a counting error.
    $results.PrivacyMode = [string]$privacyMode
    $privacyConfigObject = Get-Content -LiteralPath $privacyJsonPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $oneDriveJsonPath = Join-Path $rootPath 'Modules\Privacy\Config\OneDrive.json'
    if (-not (Test-Path -LiteralPath $oneDriveJsonPath -PathType Leaf)) { throw "Privacy OneDrive.json not found" }
    $privacyChecks = @(Get-RegistryChecksFromJson -JsonPath $privacyJsonPath) + @(Get-RegistryChecksFromJson -JsonPath $oneDriveJsonPath)
    $tier1Definition = Get-PrivacyTier1PolicyDefinition
    $privacyChecks += @($tier1Definition.Targets | ForEach-Object {
            [PSCustomObject]@{ Path=$_.Path; Name=$_.Name; Type=$_.Type; Value=$_.Value; Desc=$_.Description }
        })

    $privacyDeclaredFromInventory = $privacyChecks.Count + @($privacyConfigObject.Services).Count +
        @($privacyConfigObject.ScheduledTasks).Count
    if ($privacyDeclaredFromInventory -ne $privacyExpectedForRun) {
        throw "Canonical Privacy mode count drift: mode=$privacyMode, inventory=$privacyDeclaredFromInventory, expected=$privacyExpectedForRun"
    }

    $privacySessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId
    $privacyInteractiveNames = @(Get-Process -Name explorer -IncludeUserName -ErrorAction Stop |
        Where-Object { $_.SessionId -eq $privacySessionId -and -not [string]::IsNullOrWhiteSpace($_.UserName) } |
        ForEach-Object { [string]$_.UserName } | Sort-Object -Unique)
    if ($privacyInteractiveNames.Count -ne 1) { throw 'Privacy verifier could not resolve exactly one interactive desktop user' }
    $privacySid = [string]([System.Security.Principal.NTAccount]::new($privacyInteractiveNames[0])).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($privacySid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') { throw 'Privacy verifier resolved an unsupported interactive-user SID' }
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) { $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop }
    $privacyUserRoot = "HKU:\$privacySid"
    if (-not (Test-Path -LiteralPath $privacyUserRoot -PathType Container)) { throw 'Privacy verifier requires the interactive user hive to be loaded' }
    $privacySearchUser = Get-PrivacyUserContext -Refresh
    if ([string]$privacySearchUser.Sid -cne $privacySid) {
        throw 'Privacy registry/API verifier resolved different interactive-user SIDs'
    }
    $privacySearchState = Invoke-PrivacyWindowsSearchUserState `
        -User $privacySearchUser -Operation Query
    if (-not [bool]$privacySearchState.Success) {
        throw 'Privacy effective WindowsSearch query did not report success'
    }
    $privacyEffectiveSearchChecks = 0

    # Verify each registry setting from JSON
    foreach ($check in $privacyChecks) {
        $regPath = if ([string]$check.Path -like 'HKCU:\*') {
            $privacyUserRoot + '\' + ([string]$check.Path).Substring(6)
        }
        else { [string]$check.Path }

        $targetApplicability = Get-PrivacyTargetApplicability `
            -Path $regPath `
            -Name ([string]$check.Name) `
            -Applicability $privacyApplicability
        if (-not $targetApplicability.Applicable) {
            $results.NotApplicable++
            $privacyNotApplicable += [PSCustomObject]@{
                Setting = $check.Desc; Path = "$regPath\$($check.Name)"
                Expected = "$($check.Type)/$($check.Value) on a supported edition"
                Actual = "Not applicable: $($targetApplicability.Reason)"
                CheckState = 'NotApplicable'
            }
            continue
        }

        $isTier1PolicyTarget = $regPath -match '(?i)^HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Appx\\RemoveDefaultMicrosoftStorePackages(?:\\|$)'
        if ($isTier1PolicyTarget -and -not $tier1PolicySelected) {
            $results.NotChecked++
            $privacyNotChecked += [PSCustomObject]@{
                Setting = $check.Desc; Path = "$regPath\$($check.Name)"
                Expected = "$($check.Type)/$($check.Value) only when Tier 1 is selected"
                Actual = 'Excluded by saved Privacy choice: policy-based app removal was not selected'
                CheckState = 'NotChecked'
                VerificationDisposition = 'ByChoice'
                VerificationEvidenceSource = 'ApplyIntent'
                VerificationReasonCode = 'Privacy.Tier1NotSelected'
                AffectedTargetCount = 1
            }
            continue
        }

        if ($privacyMode -eq 'MSRecommended' -and
            [string]$check.Name -eq 'AllowCrossDeviceClipboard' -and
            -not $disableCloudClipboardConfigured) {
            $results.NotChecked++
            $privacyNotChecked += [PSCustomObject]@{
                Setting = $check.Desc; Path = "$regPath\$($check.Name)"
                Expected = 'DWord/0 only when Cloud Clipboard disable is selected'
                Actual = 'Excluded by saved Privacy choice: preserve-current-state is selected'
                CheckState = 'NotChecked'
                VerificationDisposition = 'ByChoice'
                VerificationEvidenceSource = 'ApplyIntent'
                VerificationReasonCode = 'Privacy.PreserveCurrentState'
                AffectedTargetCount = 1
            }
            continue
        }

        $passed = Test-RegistryValue -Path $regPath -Name $check.Name -ExpectedValue $check.Value
        if ($passed) {
            $privacyKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
            $passed = $privacyKey.GetValueKind([string]$check.Name).ToString() -eq [string]$check.Type
        }

        $actual = Get-ActualRegistryValue -Path $regPath -Name $check.Name

        $isWebSearchPreference = (
            [string]$check.Name -ceq 'BingSearchEnabled' -and
            $regPath -match '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Search$'
        )
        if ($isWebSearchPreference) {
            $privacyEffectiveSearchChecks++
            $passed = ($passed -and -not [bool]$privacySearchState.WebResultsEnabled)
            $actual = "$actual; WindowsSearch API EnableWebResultsSetting=$([bool]$privacySearchState.WebResultsEnabled)"
        }

        if ($passed) {
            $results.Verified++
            $privacyPassed += [PSCustomObject]@{
                Setting  = $check.Desc
                Path     = "$regPath\$($check.Name)"
                Expected = if ($isWebSearchPreference) {
                    "$($check.Type)/$($check.Value); WindowsSearch API EnableWebResultsSetting=False"
                } else { "$($check.Type)/$($check.Value)" }
                Actual   = $actual
            }
        }
        else {
            $results.Failed++

            $privacyFailed += [PSCustomObject]@{
                Setting  = $check.Desc
                Path     = "$regPath\$($check.Name)"
                Expected = if ($isWebSearchPreference) {
                    "$($check.Value); WindowsSearch API EnableWebResultsSetting=False"
                } else { $check.Value }
                Actual   = $actual
            }
        }
    }
    if ($privacyEffectiveSearchChecks -ne 1) {
        throw "Privacy verifier expected one BingSearchEnabled effective-state binding, found $privacyEffectiveSearchChecks"
    }

    # One decisive inventory query per provider distinguishes proven absence
    # from an unreadable service/task subsystem.
    $allPrivacyServices = @(Get-Service -ErrorAction Stop)
    $allPrivacyTasks = @(Get-ScheduledTask -ErrorAction Stop)
    $privacyRuntimeCheckCount = 0
    foreach ($serviceDefinition in @($privacyConfigObject.Services)) {
        $serviceMatches = @($allPrivacyServices | Where-Object {
                [string]$_.Name -eq [string]$serviceDefinition.Name
            })
        $privacyRuntimeCheckCount++
        if ($serviceMatches.Count -eq 0) {
            $results.NotApplicable++
            $privacyNotApplicable += [PSCustomObject]@{
                Setting="Service: $($serviceDefinition.Name)"; Path='Service'; Expected='Disabled/Stopped'
                Actual='Not applicable: service is not installed'; CheckState='NotApplicable'
            }
        }
        elseif ($serviceMatches.Count -eq 1 -and
            $serviceMatches[0].StartType -eq 'Disabled' -and $serviceMatches[0].Status -eq 'Stopped') {
            $service = $serviceMatches[0]
            $privacyPassed += [PSCustomObject]@{ Setting="Service: $($serviceDefinition.Name)"; Path='Service'; Expected='Disabled/Stopped'; Actual="$($service.StartType)/$($service.Status)" }
            $results.Verified++
        }
        elseif ($serviceMatches.Count -gt 1) {
            throw "Privacy service inventory is ambiguous: $($serviceDefinition.Name)"
        }
        else {
            $service = $serviceMatches[0]
            $privacyFailed += [PSCustomObject]@{ Setting="Service: $($serviceDefinition.Name)"; Path='Service'; Expected='Disabled/Stopped'; Actual="$($service.StartType)/$($service.Status)" }
            $results.Failed++
        }
    }
    foreach ($taskPath in @($privacyConfigObject.ScheduledTasks)) {
        $taskName = Split-Path $taskPath -Leaf; $taskFolder = Split-Path $taskPath -Parent
        $taskFolderName = $taskFolder.Trim([char]'\')
        $taskFolder = if ([string]::IsNullOrWhiteSpace($taskFolderName)) { '\' } else { '\' + $taskFolderName + '\' }
        $taskMatches = @($allPrivacyTasks | Where-Object {
                [string]$_.TaskPath -eq $taskFolder -and [string]$_.TaskName -eq $taskName
            })
        $privacyRuntimeCheckCount++
        if ($taskMatches.Count -eq 0) {
            $results.NotApplicable++
            $privacyNotApplicable += [PSCustomObject]@{
                Setting="Task: $taskPath"; Path='ScheduledTask'; Expected='Disabled'
                Actual='Not applicable: task is not installed'; CheckState='NotApplicable'
            }
        }
        elseif ($taskMatches.Count -eq 1 -and [string]$taskMatches[0].State -eq 'Disabled') {
            $task = $taskMatches[0]
            $privacyPassed += [PSCustomObject]@{ Setting="Task: $taskPath"; Path='ScheduledTask'; Expected='Disabled'; Actual=[string]$task.State }
            $results.Verified++
        }
        elseif ($taskMatches.Count -gt 1) {
            throw "Privacy scheduled-task inventory is ambiguous: $taskPath"
        }
        else {
            $task = $taskMatches[0]
            $privacyFailed += [PSCustomObject]@{ Setting="Task: $taskPath"; Path='ScheduledTask'; Expected='Disabled'; Actual=[string]$task.State }
            $results.Failed++
        }
    }

    # Calculate totals
    $registryCheckCount = $privacyChecks.Count
    $actualPrivacyTotal = $registryCheckCount + $privacyRuntimeCheckCount
    if ($actualPrivacyTotal -ne $privacyExpectedForRun) {
        throw "Privacy declared-check reconciliation failed: expected $privacyExpectedForRun, produced $actualPrivacyTotal"
    }
    $privacyPassedCount = $privacyPassed.Count
    if (($privacyPassedCount + $privacyFailed.Count + $privacyNotChecked.Count + $privacyNotApplicable.Count) -ne $actualPrivacyTotal) {
        throw "Privacy result reconciliation failed: passed=$privacyPassedCount, failed=$($privacyFailed.Count), notChecked=$($privacyNotChecked.Count), notApplicable=$($privacyNotApplicable.Count), total=$actualPrivacyTotal"
    }
    $privacyNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
        -Details $privacyNotChecked -ExpectedCount $privacyNotChecked.Count `
        -Context 'Privacy NotChecked evidence'
    $privacyNotCheckedDeliberateCount = $privacyNotCheckedAccounting.ByChoice

    # Add to AllSettings for HTML report
    $results.AllSettings += [PSCustomObject]@{
        Category      = "Privacy"
        Total         = $actualPrivacyTotal
        Passed        = $privacyPassedCount
        Failed        = $privacyFailed.Count
        NotChecked    = $privacyNotChecked.Count
        NotCheckedDeliberate = $privacyNotCheckedDeliberateCount
        NotCheckedNoSavedChoice = $privacyNotCheckedAccounting.NoSavedChoice
        NotCheckedCannotVerify = $privacyNotCheckedAccounting.CannotVerify
        NotApplicable = $privacyNotApplicable.Count
        PassedDetails = $privacyPassed
        FailedDetails = $privacyFailed
        NotCheckedDetails = $privacyNotChecked
        NotApplicableDetails = $privacyNotApplicable
    }

    if ($privacyFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "Privacy"
            Count    = $privacyFailed.Count
            Details  = $privacyFailed
        }
    }

    $privacyPresentation = Get-PrivacyVerificationPresentation `
        -Mode $privacyMode `
        -Total $actualPrivacyTotal `
        -Passed $privacyPassedCount `
        -Failed $privacyFailed.Count `
        -NotChecked $privacyNotChecked.Count `
        -NotCheckedDeliberate $privacyNotCheckedDeliberateCount `
        -NotApplicable $privacyNotApplicable.Count
    $privacyDisplayStatus = [string]$privacyPresentation.Status
    $privacyModulePresentation = Get-VerificationModulePresentation `
        -Name 'Privacy' -Context $privacyMode -Total $privacyPresentation.Total `
        -Passed $privacyPresentation.Passed -Failed $privacyPresentation.Failed `
        -NotChecked $privacyPresentation.NotChecked `
        -NotCheckedDeliberate $privacyPresentation.NotCheckedDeliberate `
        -NotApplicable $privacyPresentation.NotApplicable `
        -Summary "$($privacyPresentation.Passed)/$($privacyPresentation.Evaluated) evaluated live targets passed; $($privacyPresentation.Failed) failed; $($privacyPresentation.NotCheckedDeliberate) intentional exclusion(s); $($privacyPresentation.NotCheckedUnresolved) unproven; $($privacyPresentation.NotApplicable) not applicable ($($privacyPresentation.Total) declared)."
    if ($privacyModulePresentation.Status -cne $privacyDisplayStatus) {
        throw "Privacy module status disagrees with selected-profile presentation: $($privacyModulePresentation.Status)/$privacyDisplayStatus"
    }
    Write-VerificationModulePresentation -Presentation $privacyModulePresentation

    # Update global results object with actual Privacy count
    $results.PrivacyChecks = $actualPrivacyTotal
}
catch {
    if (-not $privacyStepWritten) {
        Write-VerificationStep "Verifying Privacy ($privacyExpectedForRun targets)..."
    }
    $results.Verified = $privacyVerifiedBefore
    $results.NotApplicable = $privacyNotApplicableBefore
    $results.PrivacyChecks = $privacyExpectedForRun
    if ($privacyIntentMissing) {
        $privacyUnavailablePresentation = Get-PrivacyUnavailablePresentation -Total $privacyExpectedForRun
        $privacyModulePresentation = Get-VerificationModulePresentation `
            -Name 'Privacy' -Total $privacyExpectedForRun -Passed 0 -Failed 0 `
            -NotChecked $privacyExpectedForRun -NotCheckedDeliberate 0 -NotApplicable 0 `
            -Summary ([string]$privacyUnavailablePresentation.SummaryLine)
        Write-VerificationModulePresentation -Presentation $privacyModulePresentation
        $results.Failed = $privacyFailedBefore
        $results.NotChecked = $privacyNotCheckedBefore + $privacyExpectedForRun
        $privacyIntentDetail = [PSCustomObject]@{
            Setting='Selected Privacy profile comparison'; Expected='Durable engine Apply intent'
            Actual=[string]$privacyUnavailablePresentation.DetailActual
            CheckState='NotChecked'
            VerificationDisposition='NoSavedChoice'
            VerificationEvidenceSource='None'
            VerificationReasonCode='Privacy.NoSavedProfile'
            AffectedTargetCount=$privacyExpectedForRun
        }
        $privacyIntentAccounting = Get-VerificationNotCheckedAccounting `
            -Details @($privacyIntentDetail) -ExpectedCount $privacyExpectedForRun `
            -Context 'Privacy unavailable NotChecked evidence'
        $results.AllSettings += [PSCustomObject]@{
            Category='Privacy'; Total=$privacyExpectedForRun; Passed=0; Failed=0; NotChecked=$privacyExpectedForRun; NotCheckedDeliberate=0; NotApplicable=0
            NotCheckedNoSavedChoice=$privacyIntentAccounting.NoSavedChoice; NotCheckedCannotVerify=$privacyIntentAccounting.CannotVerify
            PassedDetails=@(); FailedDetails=@(); NotCheckedDetails=@($privacyIntentDetail); NotApplicableDetails=@()
        }
    }
    else {
        $results.Failed = $privacyFailedBefore + $privacyExpectedForRun
        $results.NotChecked = $privacyNotCheckedBefore
        $privacyFailureDetail = [PSCustomObject]@{
            Setting='Privacy verification scope'; Expected='All canonical Privacy targets executable'
            Actual="Verification failed closed: $($_.Exception.Message)"
        }
        $results.AllSettings += [PSCustomObject]@{
            Category='Privacy'; Total=$privacyExpectedForRun; Passed=0; Failed=$privacyExpectedForRun; NotChecked=0; NotCheckedDeliberate=0; NotApplicable=0
            PassedDetails=@(); FailedDetails=@($privacyFailureDetail); NotCheckedDetails=@(); NotApplicableDetails=@()
        }
        $results.FailedSettings += [PSCustomObject]@{
            Category='Privacy'; Count=$privacyExpectedForRun; Details=@($privacyFailureDetail)
        }
        $privacyModulePresentation = Get-VerificationModulePresentation `
            -Name 'Privacy' -Total $privacyExpectedForRun -Passed 0 -Failed $privacyExpectedForRun `
            -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
            -Summary "Verification failed closed: $($_.Exception.Message)"
        Write-VerificationModulePresentation -Presentation $privacyModulePresentation
    }
}
}

# [ALWAYS] AntiAI Policies (loaded dynamically from JSON)
# Source: AntiAI-Settings.json (Single Source of Truth)
if (Test-VerificationModuleSelected 'AntiAI') {
Write-VerificationStep "Verifying AntiAI Policies ($EXPECTED_ANTIAI_COUNT)..."

$antiAIVerifiedBefore = $results.Verified
$antiAIFailedBefore = $results.Failed
try {
    $antiAIFailed = @()
    $antiAIPassed = @()
    $antiAINotChecked = @()

    # ==========================================================================
    # LOAD REGISTRY CHECKS FROM AntiAI-Settings.json (Single Source of Truth)
    # ==========================================================================
    $antiAIJsonPath = Join-Path $rootPath "Modules\AntiAI\Config\AntiAI-Settings.json"
    $antiAIChecks = Get-RegistryChecksFromJson -JsonPath $antiAIJsonPath
    if (@($antiAIChecks).Count -ne 43 -or $EXPECTED_ANTIAI_COUNT -ne 47) {
        throw "AntiAI declared-scope drift: registry=$(@($antiAIChecks).Count), complete expected=$EXPECTED_ANTIAI_COUNT"
    }

    $antiAIModulePath = Join-Path $rootPath 'Modules\AntiAI\AntiAI.psd1'
    Import-Module -Name $antiAIModulePath -Force -ErrorAction Stop
    $antiAIUserRoot = [string]$verifierUserContext.Root
    $antiAIPlan = if ($appliedScopeRun) {
        Get-AntiAITargetPlan
    }
    elseif ($antiAIPlanIntentKnown) {
        Get-AntiAIIntentTargetPlan -Intent $antiAIIntent
    }
    else { $null }
    if ($antiAIPlan -and ([int]$antiAIPlan.DeclaredCount -ne 43 -or
        [int]$antiAIPlan.ApplicableCount + [int]$antiAIPlan.NotApplicableCount -ne 43)) {
        throw 'AntiAI intent/applicability plan does not reconcile to the declared registry scope'
    }
    $antiAINotApplicable = @($(if ($antiAIPlan) { $antiAIPlan.NotApplicableTargets } else { @() }) | ForEach-Object {
            [PSCustomObject]@{
                Policy = [string]$_.Name
                Path = "$($_.Path)\$($_.Name)"
                Expected = 'Not mutated'
                Actual = [string]$_.Reason
                CheckState = 'NotApplicable'
            }
        })

    # Verify each AntiAI registry setting from JSON
    # MultiString policies count as 1 check (consistent with Test-AntiAICompliance.ps1)
    $actualCheckCount = 0

    if (-not $antiAIPlan) {
        foreach ($check in @($antiAIChecks)) {
            $regPath = if ([string]$check.Path -like 'HKCU:\*') {
                $antiAIUserRoot + '\' + ([string]$check.Path).Substring(6)
            }
            else { [string]$check.Path }
            $actualCheckCount++
            $results.NotChecked++
            $antiAINotChecked += [PSCustomObject]@{
                Policy = [string]$check.Desc
                Path = "$regPath\$($check.Name)"
                Expected = 'Apply-time applicability intent'
                Actual = 'No saved AntiAI target plan; live applicability is not substituted.'
                CheckState = 'NotChecked'
                VerificationDisposition = 'NoSavedChoice'
                VerificationEvidenceSource = 'None'
                VerificationReasonCode = 'AntiAI.NoSavedTargetPlan'
                AffectedTargetCount = 1
            }
        }
    }

    foreach ($check in @($(if ($antiAIPlan) { $antiAIPlan.ApplicableTargets } else { @() }))) {
        $regPath = [string]$check.Path
        $actualCheckCount++

        if ($check.Value -is [array]) {
            # A MultiString target is exact owned state: registry kind, item count,
            # order, casing and content must all match; extras are a failure.
            $valueExists = $false
            $actualType = $null
            $actualArray = @()
            if (Test-Path -LiteralPath $regPath -PathType Container -ErrorAction Stop) {
                $registryKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                $valueExists = $registryKey.GetValueNames() -contains [string]$check.Name
                if ($valueExists) {
                    $actualType = $registryKey.GetValueKind([string]$check.Name).ToString()
                    $actualArray = @($registryKey.GetValue(
                        [string]$check.Name,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    ))
                }
            }
            $expectedArray = @($check.Value)
            $expectedJson = ConvertTo-Json -InputObject $expectedArray -Compress -Depth 20
            $actualJson = ConvertTo-Json -InputObject $actualArray -Compress -Depth 20
            $passed = ($valueExists -and $actualType -ceq [string]$check.Type -and $actualJson -ceq $expectedJson)

            if ($passed) {
                $results.Verified++
                $antiAIPassed += [PSCustomObject]@{
                    Policy   = $check.Description
                    Path     = "$regPath\$($check.Name)"
                    Expected = "$($check.Type)/$expectedJson"
                    Actual   = "$actualType/$actualJson"
                }
            }
            else {
                $results.Failed++
                $antiAIFailed += [PSCustomObject]@{
                    Policy   = $check.Description
                    Path     = "$regPath\$($check.Name)"
                    Expected = "$($check.Type)/$expectedJson"
                    Actual   = if ($valueExists) { "$actualType/$actualJson" } else { 'Missing' }
                }
            }
        }
        else {
            # Simple Registry-Policy (DWORD/String)
            $passed = Test-RegistryValue -Path $regPath -Name $check.Name -ExpectedValue $check.Value
            if ($passed) {
                $registryKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                $passed = $registryKey.GetValueKind([string]$check.Name).ToString() -eq [string]$check.Type
            }

            if ($passed) {
                $results.Verified++
                $antiAIPassed += [PSCustomObject]@{
                    Policy   = $check.Description
                    Path     = "$regPath\$($check.Name)"
                    Expected = $check.Value
                    Actual   = Get-ActualRegistryValue -Path $regPath -Name $check.Name
                }
            }
            else {
                $results.Failed++
                $actual = Get-ActualRegistryValue -Path $regPath -Name $check.Name
                $antiAIFailed += [PSCustomObject]@{
                    Policy   = $check.Description
                    Path     = "$regPath\$($check.Name)"
                    Expected = $check.Value
                    Actual   = $actual
                }
            }
        }
    }
    $actualCheckCount += $antiAINotApplicable.Count
    $results.NotApplicable += $antiAINotApplicable.Count

    # URI handler absence is owned state, not a prose-only side effect. Verify
    # both protocols in both real source hives and include all four in totals.
    foreach ($uriPath in @(
            'HKLM:\SOFTWARE\Classes\ms-copilot',
            'HKLM:\SOFTWARE\Classes\ms-edge-copilot',
            "$antiAIUserRoot\Software\Classes\ms-copilot",
            "$antiAIUserRoot\Software\Classes\ms-edge-copilot"
        )) {
        $actualCheckCount++
        if (-not (Test-Path -LiteralPath $uriPath)) {
            $results.Verified++
            $antiAIPassed += [PSCustomObject]@{
                Policy = 'Copilot URI source key absent'; Path = $uriPath
                Expected = 'Absent'; Actual = 'Absent'
            }
        }
        else {
            $results.Failed++
            $antiAIFailed += [PSCustomObject]@{
                Policy = 'Copilot URI source key absent'; Path = $uriPath
                Expected = 'Absent'; Actual = 'Present'
            }
        }
    }
    if ($actualCheckCount -ne $EXPECTED_ANTIAI_COUNT) {
        throw "AntiAI verifier produced $actualCheckCount checks; expected $EXPECTED_ANTIAI_COUNT"
    }

    # Update AntiAI-Total with actual check count (incl. MultiString individual checks)
    $results.AntiAIPolicies = $actualCheckCount

    # Add to AllSettings for HTML report
    $antiAIPassedCount = $antiAIPassed.Count
    $antiAINotCheckedAccounting = Get-VerificationNotCheckedAccounting `
        -Details $antiAINotChecked -ExpectedCount $antiAINotChecked.Count `
        -Context 'AntiAI NotChecked evidence'
    $results.AllSettings += [PSCustomObject]@{
        Category      = "AntiAI"
        Total         = $actualCheckCount
        Passed        = $antiAIPassedCount
        Failed        = $antiAIFailed.Count
        NotChecked    = $antiAINotChecked.Count
        NotCheckedDeliberate = $antiAINotCheckedAccounting.ByChoice
        NotCheckedNoSavedChoice = $antiAINotCheckedAccounting.NoSavedChoice
        NotCheckedCannotVerify = $antiAINotCheckedAccounting.CannotVerify
        NotApplicable = $antiAINotApplicable.Count
        PassedDetails = $antiAIPassed
        FailedDetails = $antiAIFailed
        NotCheckedDetails = $antiAINotChecked
        NotApplicableDetails = $antiAINotApplicable
    }

    if ($antiAIFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "AntiAI"
            Count    = $antiAIFailed.Count
            Details  = $antiAIFailed
        }
    }

    $antiAIPresentation = Get-VerificationModulePresentation `
        -Name 'AntiAI' -Total $actualCheckCount -Passed $antiAIPassedCount -Failed $antiAIFailed.Count `
        -NotChecked $antiAINotChecked.Count -NotCheckedDeliberate $antiAINotCheckedAccounting.ByChoice `
        -NotApplicable $antiAINotApplicable.Count `
        -Summary "$antiAIPassedCount verified; $($antiAIFailed.Count) failed; $($antiAINotChecked.Count) unproven; $($antiAINotApplicable.Count) not applicable ($actualCheckCount declared)."
    Write-VerificationModulePresentation -Presentation $antiAIPresentation
}
catch {
    $results.Verified = $antiAIVerifiedBefore
    $results.Failed = $antiAIFailedBefore + $EXPECTED_ANTIAI_COUNT
    $results.AntiAIPolicies = $EXPECTED_ANTIAI_COUNT
    $antiAIScopeFailure = [PSCustomObject]@{
        Policy = 'Complete AntiAI verification scope'; Path = 'AntiAI'
        Expected = "$EXPECTED_ANTIAI_COUNT executable checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category = 'AntiAI'; Total = $EXPECTED_ANTIAI_COUNT; Passed = 0; Failed = $EXPECTED_ANTIAI_COUNT
        NotChecked = 0; NotApplicable = 0; PassedDetails = @(); FailedDetails = @($antiAIScopeFailure)
        NotCheckedDetails = @(); NotApplicableDetails = @()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category = 'AntiAI'; Count = $EXPECTED_ANTIAI_COUNT; Details = @($antiAIScopeFailure)
    }
    $antiAIPresentation = Get-VerificationModulePresentation `
        -Name 'AntiAI' -Total $EXPECTED_ANTIAI_COUNT -Passed 0 -Failed $EXPECTED_ANTIAI_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $antiAIPresentation
}
}

# [ALWAYS] EdgeHardening canonical scope (26 managed values; metadata excluded)
if (Test-VerificationModuleSelected 'EdgeHardening') {
Write-VerificationStep "Verifying EdgeHardening Policies ($EXPECTED_EDGE_COUNT)..."

$edgeVerifiedBefore = $results.Verified
$edgeFailedBefore = $results.Failed
$edgeNotCheckedBefore = $results.NotChecked
$edgeNotApplicableBefore = $results.NotApplicable
try {
    $edgeFailed = @()
    $edgePassed = @()
    $edgeNotChecked = @()
    $edgeNotApplicable = @()
    $edgeTargetHelper = Join-Path $rootPath 'Modules\EdgeHardening\Private\Get-EdgePolicyTargets.ps1'
    $edgeApplicabilityHelper = Join-Path $rootPath 'Modules\EdgeHardening\Private\Get-EdgeRuntimeApplicability.ps1'
    $edgeInstallationHelper = Join-Path $rootPath 'Modules\EdgeHardening\Private\Get-EdgeInstallationStatus.ps1'
    foreach ($requiredHelper in @($edgeApplicabilityHelper, $edgeInstallationHelper, $edgeTargetHelper)) {
        if (-not (Test-Path -LiteralPath $requiredHelper -PathType Leaf)) {
            throw "Canonical Edge helper is missing: $requiredHelper"
        }
        . $requiredHelper
    }
    $edgeApplicability = Get-EdgeRuntimeApplicability
    $edgeInstallation = Get-EdgeInstallationStatus
    $edgeTargets = @(Get-EdgePolicyTargets -RuntimeApplicability $edgeApplicability `
            -EdgeInstallationStatus $edgeInstallation)
    if ($edgeTargets.Count -ne $EXPECTED_EDGE_COUNT) {
        throw "Edge target inventory produced $($edgeTargets.Count) managed values; expected $EXPECTED_EDGE_COUNT"
    }

    foreach ($target in $edgeTargets) {
        $isExtensionBlock = ([string]$target.Name -eq '1' -and
            [string]$target.Path -eq 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist')
        # List policies consist of numbered registry values, so the raw value
        # name "1" says nothing in a report. Label the block-all entry by intent.
        $edgePolicyLabel = if ($isExtensionBlock) { 'ExtensionInstallBlocklist entry "1" (block-all "*")' } else { [string]$target.Name }
        if (-not [bool]$target.Applicable) {
            $results.NotApplicable++
            # Report-only context: Microsoft documents these four SmartScreen
            # policies as managed-Windows-only; Edge ignores them on an
            # unmanaged device, so writing them would fake compliance and
            # trigger Edge's false "Managed by your organization" banner.
            # The sealed NotApplicableReason string itself must stay
            # unchanged -- it is part of the Assert-EdgePolicySnapshot
            # restore contract.
            $managedWindowsReason = ([bool]$target.RequiresManagedWindows -and
                [string]$target.NotApplicableReason -match 'AD domain join')
            $edgeNotApplicable += [PSCustomObject]@{
                Policy = $edgePolicyLabel; Path = $target.Path
                Expected = if ($managedWindowsReason) {
                    'AD domain join or eligible Pro/Enterprise MDM registration'
                }
                else {
                    "Microsoft Edge $([int]$target.MinimumEdgeMajor) or later"
                }
                Actual = if ($managedWindowsReason) {
                    "Not applicable: $($target.NotApplicableReason). Edge honors this policy only on managed Windows; writing it here would fake compliance. The same protection can be enabled manually: Edge > Settings > Privacy, search, and services (SmartScreen / block potentially unwanted apps)."
                }
                else {
                    "Not applicable: $($target.NotApplicableReason). The value remains untouched and is not reported as applied."
                }
                CheckState = 'NotApplicable'
            }
            continue
        }

        $keyExists = Test-Path -LiteralPath $target.Path -PathType Container -ErrorAction Stop
        $valueExists = $false
        $actualValue = $null
        $actualType = $null
        if ($keyExists) {
            $edgeKey = Get-Item -LiteralPath $target.Path -ErrorAction Stop
            $valueExists = $edgeKey.GetValueNames() -contains [string]$target.Name
            if ($valueExists) {
                $actualType = $edgeKey.GetValueKind([string]$target.Name).ToString()
                $actualValue = $edgeKey.GetValue(
                    [string]$target.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
            }
        }

        if ($isExtensionBlock) {
            if (-not $edgeExtensionDecisionKnown) {
                $results.NotChecked++
                $edgeNotChecked += [PSCustomObject]@{
                    Policy = $edgePolicyLabel; Path = $target.Path
                    Expected = 'Explicit allow/block extension intent'
                    Actual = if ($valueExists) {
                        "No saved Edge extension choice; observed blocklist state is $actualType/$actualValue."
                    }
                    else { 'No saved Edge extension choice; blocklist intent cannot be inferred (entry absent).' }
                    CheckState = 'NotChecked'
                    VerificationDisposition = 'NoSavedChoice'
                    VerificationEvidenceSource = 'None'
                    VerificationReasonCode = 'Edge.NoSavedExtensionChoice'
                    AffectedTargetCount = 1
                }
                continue
            }
            if ($edgeAllowExtensionsSelected) {
                if ($valueExists) {
                    $results.Failed++
                    $edgeFailed += [PSCustomObject]@{
                        Policy = $edgePolicyLabel; Path = $target.Path
                        Expected = 'Absent (allow-extensions intent requires no block-all entry)'
                        Actual = "$actualType/$actualValue (unexpected blocklist entry)"
                    }
                }
                else {
                    $results.NotChecked++
                    # The absent optional target is the only deliberate
                    # allow-extensions outcome. A surviving value contradicts
                    # current intent and must never be promoted as external.
                    $edgeNotChecked += [PSCustomObject]@{
                        Policy = $edgePolicyLabel; Path = $target.Path
                        Expected = 'Absent (allow-extensions profile leaves the blocklist unset)'
                        Actual = 'Excluded by saved Edge choice: allow extensions leaves the block-all entry absent'
                        CheckState = 'NotChecked'
                        VerificationDisposition = 'ByChoice'
                        VerificationEvidenceSource = 'ApplyIntent'
                        VerificationReasonCode = 'Edge.ExtensionBlocklistExcluded'
                        AffectedTargetCount = 1
                    }
                }
                continue
            }
        }

        $expectedJson = ConvertTo-Json -InputObject @($target.Value) -Compress -Depth 20
        $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
        $passed = ($valueExists -and $actualType -ceq [string]$target.Type -and $actualJson -ceq $expectedJson)
        $detail = [PSCustomObject]@{
            Policy = $edgePolicyLabel; Path = $target.Path
            Expected = "$($target.Type)/$expectedJson"
            Actual = if ($valueExists) { "$actualType/$actualJson" } else { 'Missing' }
        }
        if ($passed) {
            $results.Verified++
            $edgePassed += $detail
        }
        else {
            $results.Failed++
            $edgeFailed += $detail
        }
    }

    $edgeProduced = $edgePassed.Count + $edgeFailed.Count + $edgeNotChecked.Count + $edgeNotApplicable.Count
    if ($edgeProduced -ne $EXPECTED_EDGE_COUNT) {
        throw "Edge verifier produced $edgeProduced results; expected $EXPECTED_EDGE_COUNT"
    }
    $edgeNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
        -Details $edgeNotChecked -ExpectedCount $edgeNotChecked.Count `
        -Context 'EdgeHardening NotChecked evidence'
    $results.AllSettings += [PSCustomObject]@{
        Category = 'EdgeHardening'; Total = $EXPECTED_EDGE_COUNT
        Passed = $edgePassed.Count; Failed = $edgeFailed.Count; NotChecked = $edgeNotChecked.Count
        NotCheckedDeliberate = $edgeNotCheckedAccounting.ByChoice
        NotCheckedNoSavedChoice = $edgeNotCheckedAccounting.NoSavedChoice
        NotCheckedCannotVerify = $edgeNotCheckedAccounting.CannotVerify
        NotApplicable = $edgeNotApplicable.Count; PassedDetails = $edgePassed; FailedDetails = $edgeFailed
        NotCheckedDetails = $edgeNotChecked; NotApplicableDetails = $edgeNotApplicable
    }
    if ($edgeFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = 'EdgeHardening'; Count = $edgeFailed.Count; Details = $edgeFailed
        }
    }
    $edgeNotCheckedDeliberate = $edgeNotCheckedAccounting.ByChoice
    $edgePresentation = Get-VerificationModulePresentation `
        -Name 'EdgeHardening' -Total $EXPECTED_EDGE_COUNT -Passed $edgePassed.Count -Failed $edgeFailed.Count `
        -NotChecked $edgeNotChecked.Count -NotCheckedDeliberate $edgeNotCheckedDeliberate `
        -NotApplicable $edgeNotApplicable.Count `
        -Summary "$($edgePassed.Count) verified; $($edgeFailed.Count) failed; $edgeNotCheckedDeliberate intentional exclusion(s); $($edgeNotChecked.Count - $edgeNotCheckedDeliberate) unproven; $($edgeNotApplicable.Count) not applicable ($EXPECTED_EDGE_COUNT declared)."
    Write-VerificationModulePresentation -Presentation $edgePresentation
}
catch {
    $results.Verified = $edgeVerifiedBefore
    $results.Failed = $edgeFailedBefore + $EXPECTED_EDGE_COUNT
    $results.NotChecked = $edgeNotCheckedBefore
    $results.NotApplicable = $edgeNotApplicableBefore
    $edgeScopeFailure = [PSCustomObject]@{
        Policy = 'Complete EdgeHardening verification scope'; Path = 'EdgeHardening'
        Expected = "$EXPECTED_EDGE_COUNT executable managed-value checks"
        Actual = "Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category = 'EdgeHardening'; Total = $EXPECTED_EDGE_COUNT; Passed = 0; Failed = $EXPECTED_EDGE_COUNT; NotChecked = 0
        NotApplicable = 0; PassedDetails = @(); FailedDetails = @($edgeScopeFailure)
        NotCheckedDetails = @(); NotApplicableDetails = @()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category = 'EdgeHardening'; Count = $EXPECTED_EDGE_COUNT; Details = @($edgeScopeFailure)
    }
    $edgePresentation = Get-VerificationModulePresentation `
        -Name 'EdgeHardening' -Total $EXPECTED_EDGE_COUNT -Passed 0 -Failed $EXPECTED_EDGE_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $edgePresentation
}
}

# [ALWAYS] AdvancedSecurity Settings (policy-level checks)
if (Test-VerificationModuleSelected 'AdvancedSecurity') {
Write-VerificationStep "Verifying AdvancedSecurity Settings ($EXPECTED_ADVANCED_COUNT)..."

$advVerifiedBefore = $results.Verified
$advFailedBefore = $results.Failed
$advNotCheckedBefore = $results.NotChecked
$advNotApplicableBefore = $results.NotApplicable
try {
    $advFailed = @()
    $advPassed = @()
    function Get-AdvancedSecurityNotCheckedDetail {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Setting,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Expected,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Actual,
            [Parameter(Mandatory)][ValidateSet('ByChoice','NoSavedChoice','CannotVerify')][string]$Disposition,
            [Parameter(Mandatory)][ValidateSet('ApplyIntent','WindowsState','None','RuntimeQuery')][string]$EvidenceSource,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ReasonCode
        )

        return [PSCustomObject][ordered]@{
            Setting = $Setting
            Expected = $Expected
            Actual = $Actual
            CheckState = 'NotChecked'
            VerificationDisposition = $Disposition
            VerificationEvidenceSource = $EvidenceSource
            VerificationReasonCode = $ReasonCode
            AffectedTargetCount = 1
        }
    }
    function Get-AdvancedSecurityChoiceNotCheckedDetail {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Setting,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Expected,
            [Parameter(Mandatory)][bool]$ChoiceProven,
            [Parameter(Mandatory)][ValidateSet(
                'Discovery','Firewall','Rdp','OptionalControl',
                'AdminShares','Upnp','WirelessDisplay'
            )][string]$Topic,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProvenActual,
            [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UnprovenActual
        )

        $reasonCodes = switch ($Topic) {
            'Discovery' { @('AdvancedSecurity.DiscoveryNotSelected', 'AdvancedSecurity.NoSavedDiscoveryChoice') }
            'Firewall' { @('AdvancedSecurity.FirewallRuleNotSelected', 'AdvancedSecurity.NoSavedFirewallChoice') }
            'Rdp' { @('AdvancedSecurity.RdpPreserved', 'AdvancedSecurity.NoSavedRdpChoice') }
            'OptionalControl' { @('AdvancedSecurity.OptionalControlNotSelected', 'AdvancedSecurity.NoSavedOptionalControlChoice') }
            'AdminShares' { @('AdvancedSecurity.AdminSharesPreserved', 'AdvancedSecurity.NoSavedAdminSharesChoice') }
            'Upnp' { @('AdvancedSecurity.UpnpPreserved', 'AdvancedSecurity.NoSavedUpnpChoice') }
            'WirelessDisplay' { @('AdvancedSecurity.WirelessDisplayNotSelected', 'AdvancedSecurity.NoSavedWirelessDisplayChoice') }
        }
        if (@($reasonCodes).Count -ne 2) {
            throw "AdvancedSecurity choice reason mapping is incomplete: $Topic"
        }

        return Get-AdvancedSecurityNotCheckedDetail `
            -Setting $Setting -Expected $Expected `
            -Actual $(if ($ChoiceProven) { $ProvenActual } else { $UnprovenActual }) `
            -Disposition $(if ($ChoiceProven) { 'ByChoice' } else { 'NoSavedChoice' }) `
            -EvidenceSource $(if ($ChoiceProven) { 'ApplyIntent' } else { 'None' }) `
            -ReasonCode $(if ($ChoiceProven) { $reasonCodes[0] } else { $reasonCodes[1] })
    }
    $advancedFirewallHelper = Join-Path $rootPath 'Modules\AdvancedSecurity\Private\AdvancedSecurityFirewallRules.ps1'
    if (-not (Test-Path -LiteralPath $advancedFirewallHelper -PathType Leaf)) {
        throw "Canonical AdvancedSecurity firewall helper is missing: $advancedFirewallHelper"
    }
    . $advancedFirewallHelper
    $advancedApplicabilityHelper = Join-Path $rootPath 'Modules\AdvancedSecurity\Private\Get-AdvancedSecurityApplicability.ps1'
    if (-not (Test-Path -LiteralPath $advancedApplicabilityHelper -PathType Leaf)) {
        throw "AdvancedSecurity applicability helper is missing: $advancedApplicabilityHelper"
    }
    . $advancedApplicabilityHelper
    $advancedApplicability = Get-AdvancedSecurityApplicability
    $advancedWinInetHelper = Join-Path $rootPath 'Modules\AdvancedSecurity\Private\AdvancedSecurityWinInet.ps1'
    if (-not (Test-Path -LiteralPath $advancedWinInetHelper -PathType Leaf)) {
        throw "AdvancedSecurity WinINet helper is missing: $advancedWinInetHelper"
    }
    . $advancedWinInetHelper
    $advancedNetBIOSHelper = Join-Path $rootPath 'Modules\AdvancedSecurity\Private\AdvancedSecurityNetBIOS.ps1'
    if (-not (Test-Path -LiteralPath $advancedNetBIOSHelper -PathType Leaf)) {
        throw "AdvancedSecurity NetBIOS helper is missing: $advancedNetBIOSHelper"
    }
    . $advancedNetBIOSHelper

    # RDP Settings (3 checks). NLA and TLS are always owned in the exact GPO
    # path used by Apply. Complete disable is checked only when its decision is
    # authoritative; preserving the existing RDP state is never a positive pass.
    $rdpChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "SecurityLayer"; Expected = 2; Desc = "RDP Security Layer (TLS policy)"; Optional = $false; Applicable = [bool]$advancedApplicability.RdpHostSupported }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "UserAuthentication"; Expected = 1; Desc = "RDP NLA policy"; Optional = $false; Applicable = [bool]$advancedApplicability.RdpHostSupported }
    )
    $rdpDisableCheck = @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        Name = "fDenyTSConnections"
        Expected = 1
        Desc = "RDP complete disable"
    }

    # Admin-share policy is choice/domain-aware and owns both client/server values.
    $adminShareChecks = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "AutoShareWks"; Expected = 0; Desc = "Admin Shares: AutoShareWks" }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "AutoShareServer"; Expected = 0; Desc = "Admin Shares: AutoShareServer" }
    )

    # Risky Services (3 checks) - UPnP services (SSDPSRV, upnphost) areOPTIONAL (user decides), lmhosts is REQUIRED
    $riskyServices = @(
        @{ Name = "SSDPSRV"; Desc = "SSDP Discovery Service"; Optional = $true }
        @{ Name = "upnphost"; Desc = "UPnP Device Host"; Optional = $true }
        @{ Name = "lmhosts"; Desc = "TCP/IP NetBIOS Helper"; Optional = $false }
    )

    # TLS Settings (8 checks) - ALWAYS required (all profiles disable legacy TLS)
    # Check both Server AND Client to match what AdvancedSecurity applies
    # We validate both Enabled=0 and DisabledByDefault=1 per version/component
    $tlsChecks = @(
        # Enabled flags
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name = "Enabled"; Expected = 0; Desc = "TLS 1.0 Server Disabled"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Name = "Enabled"; Expected = 0; Desc = "TLS 1.0 Client Disabled"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name = "Enabled"; Expected = 0; Desc = "TLS 1.1 Server Disabled"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Name = "Enabled"; Expected = 0; Desc = "TLS 1.1 Client Disabled"; Optional = $false }
        # DisabledByDefault flags
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name = "DisabledByDefault"; Expected = 1; Desc = "TLS 1.0 Server DisabledByDefault"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Name = "DisabledByDefault"; Expected = 1; Desc = "TLS 1.0 Client DisabledByDefault"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name = "DisabledByDefault"; Expected = 1; Desc = "TLS 1.1 Server DisabledByDefault"; Optional = $false }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Name = "DisabledByDefault"; Expected = 1; Desc = "TLS 1.1 Client DisabledByDefault"; Optional = $false }
    )

    # WPAD has exactly two owned checks: Microsoft's documented WinHTTP value
    # here and the current Explorer user's documented WinINet AutoDetect bit
    # below. Undocumented scalar AutoDetect/WpadOverride values are not used.
    # Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features
    # Reference: https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags
    $wpadChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name = "DisableWpad"; Expected = 1; Desc = "WPAD Disabled (Official MS Key)"; Optional = $false }
    )

    # Legacy SRP root policy (2 checks). Registry state only; runtime
    # enforcement is outside this verifier and is not claimed.
    $srpRootChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "DefaultLevel"; Expected = 262144; Desc = "SRP DefaultLevel (Unrestricted)"; Optional = $false }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "TransparentEnabled"; Expected = 1; Desc = "SRP TransparentEnabled"; Optional = $false }
    )

    # Firewall Shields Up (1 check) - Maximum profile only, blocks ALL incoming on Public network
    # Optional = true because it's only applied for Maximum profile (user choice)
    $shieldsUpCheck = @{
        Path     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
        Name     = "DoNotAllowExceptions"
        Expected = 1
        Desc     = "Firewall Shields Up (Maximum only)"
        Optional = $true
    }

    # Discovery Protocols (WS-Discovery + mDNS) - Maximum profile only
    # Optional = true because only applied for Maximum profile (user choice)
    # Check 1: mDNS disabled via registry
    $discoveryMdnsCheck = @{
        Path     = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        Name     = "EnableMDNS"
        Expected = 0
        Desc     = "Discovery Protocols: mDNS Disabled (Maximum only)"
        Optional = $true
    }

    # Discovery Protocols: Firewall block rules (4 checks) - checked separately below
    # Also need to check services FDResPub and fdPHost are disabled

    # Exact 0xFF IPv6 component-disable registry state - Maximum profile only.
    # Optional = true because only applied for Maximum profile (user choice)
    $ipv6Check = @{
        Path     = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        Name     = "DisabledComponents"
        Expected = 255  # 0xFF = documented broad disable; internal IPv6 remains
        Desc     = "IPv6 component-disable state 0xFF (Maximum only; runtime completeness not asserted)"
        Optional = $true
    }

    # Windows Update (3 Checks) - ALWAYS required - matches AdvancedSecurity module Config/WindowsUpdate.json
    $wuChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "SetAllowOptionalContent"; Expected = 3; Desc = "WU: optional updates remain user-selected"; Optional = $false; Applicable = [bool]$advancedApplicability.ManagedPolicySupported }
        @{ Path = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name = "IsContinuousInnovationOptedIn"; Expected = 0; Desc = "WU: early non-security/feature rollout off (Windows re-asserts a stored manual Settings opt-in at boot and on Settings activity; to fix, manually turn OFF 'Get the latest updates as soon as they're available' under Settings > Windows Update)"; Optional = $false }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name = "DODownloadMode"; Expected = 0; Desc = "WU: P2P Delivery Optimization OFF"; Optional = $false; Applicable = [bool]$advancedApplicability.ManagedPolicySupported }
    )

    # Optional discovery services are counted individually. A non-selected
    # Maximum-profile option is NotChecked, never positive verification.
    $allAdvancedServices = @(Get-Service -ErrorAction Stop)
    function Get-UniqueAdvancedService {
        param([Parameter(Mandatory = $true)][string]$Name)
        $serviceMatches = @($allAdvancedServices | Where-Object { [string]$_.Name -eq $Name })
        if ($serviceMatches.Count -gt 1) { throw "AdvancedSecurity service identity is ambiguous: $Name" }
        if ($serviceMatches.Count -eq 1) { return $serviceMatches[0] }
        return $null
    }
    $discoveryServiceEvidence = $false
    foreach ($serviceName in @('FDResPub','fdPHost')) {
        $service = Get-UniqueAdvancedService -Name $serviceName
        if ($service -and $service.StartType -eq 'Disabled') { $discoveryServiceEvidence = $true }
    }
    $discoveryRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    $discoveryRegistryEvidence = $false
    if (Test-Path -LiteralPath $discoveryRegistryPath -PathType Container) {
        $discoveryRegistryEvidence = (Get-Item -LiteralPath $discoveryRegistryPath -ErrorAction Stop).GetValueNames() -contains 'EnableMDNS'
    }
    $discoverySelected = $advancedDiscoveryExpected -or
        (-not $advancedChoicesAuthoritative -and ($discoveryServiceEvidence -or $discoveryRegistryEvidence))
    foreach ($serviceName in @('FDResPub','fdPHost')) {
        $service = Get-UniqueAdvancedService -Name $serviceName
        if (-not $service) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting="Discovery service: $serviceName"; Expected='Disabled/Stopped'
                Actual='Not applicable: service is not installed'; CheckState='NotApplicable'
            }
        }
        elseif (-not $discoverySelected) {
            $results.NotChecked++
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting "Discovery service: $serviceName" -Expected 'Disabled/Stopped when selected' `
                -ChoiceProven $advancedChoicesAuthoritative -Topic Discovery `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: discovery hardening was not selected' `
                -UnprovenActual 'No saved discovery choice; selection cannot be inferred.'
        }
        elseif ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped') {
            $results.Verified++
            $advPassed += [PSCustomObject]@{ Setting="Discovery service: $serviceName"; Expected='Disabled/Stopped'; Actual="$($service.StartType)/$($service.Status)" }
        }
        else {
            $results.Failed++
            $advFailed += [PSCustomObject]@{ Setting="Discovery service: $serviceName"; Expected='Disabled/Stopped'; Actual="$($service.StartType)/$($service.Status)" }
        }
    }

    # Exact, stable module-owned firewall targets. The skip decision is
    # authoritative only from an explicit parameter or NonInteractive config;
    # otherwise missing rules remain NotChecked instead of being guessed as a
    # successful skip or a successful apply.
    Write-Host "  Verifying 16 firewall rules at filter level (port/address/program)..." -ForegroundColor DarkGray
    $allAdvancedFirewallRules = @(Get-NetFirewallRule -ErrorAction Stop)
    # Bulk filter snapshot: six store-wide enumerations for the whole loop
    # instead of seven CIM queries per rule (measured ~4s/rule -> ~2s total).
    # Built lazily so fully skipped firewall layers pay nothing. The store-wide
    # enumeration can be access-denied in constrained sessions where the
    # per-rule association queries still work, so a failed build falls back to
    # the slow-but-always-readable live path instead of failing the section.
    $advancedFirewallFilterCache = $null
    $advancedFirewallFilterCacheFailed = $false
    function Get-UniqueAdvancedFirewallRule {
        param([Parameter(Mandatory = $true)][string]$Name)
        $firewallMatches = @($allAdvancedFirewallRules | Where-Object { [string]$_.Name -ceq $Name })
        if ($firewallMatches.Count -gt 1) { throw "AdvancedSecurity firewall rule identity is ambiguous: $Name" }
        if ($firewallMatches.Count -eq 1) { return $firewallMatches[0] }
        return $null
    }
    $firewallDefinitions = @(Get-AdvancedSecurityFirewallDefinitions)
    if ($firewallDefinitions.Count -ne 16) {
        throw "Canonical AdvancedSecurity firewall definition count is $($firewallDefinitions.Count), expected 16"
    }
    # Invoke-AdvancedSecurity.ps1:523-526 forces UPnP blocking for every
    # non-Balanced profile. Reading the key raw let an Enterprise run that really
    # did disable SSDPSRV/upnphost and create the two block rules be attested as
    # "excluded by saved firewall choice" - applied hardening reported as skipped.
    $upnpConfigured = $advancedChoicesAuthoritative -and $(if ($appliedScopeRun) {
            $advancedConfiguredProfile -ne 'Balanced' -or
            [bool]$frameworkConfig.modules.AdvancedSecurity.disableUPnP
        } else { [bool]$advancedSecurityIntent.disableUPnP })
    $advancedComputer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    # Invoke-AdvancedSecurity.ps1:454 reads forceAdminShares only when the host is
    # domain-joined AND the profile is Balanced; outside that gate the switch stays
    # false and neither AutoShareWks nor AutoShareServer is written. Consuming the
    # key without the gate produced two false failures on a domain Enterprise host.
    $adminConfigured = $advancedChoicesAuthoritative -and $(if ($appliedScopeRun) {
            -not [bool]$advancedComputer.PartOfDomain -or
            ($advancedConfiguredProfile -eq 'Balanced' -and
                [bool]$frameworkConfig.modules.AdvancedSecurity.forceAdminShares) -or
            $advancedConfiguredProfile -eq 'Maximum'
        } else { [bool]$advancedSecurityIntent.adminSharesDisabled })
    foreach ($definition in $firewallDefinitions) {
        if ($definition.Group -eq 'Miracast' -and -not [bool]$advancedApplicability.WirelessDisplaySupported) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting="Firewall: $($definition.Name)"; Expected='Supported Wireless Display policy edition'
                Actual="Not applicable on $($advancedApplicability.EditionFamily)"; CheckState='NotApplicable'
            }
            continue
        }
        $rule = Get-UniqueAdvancedFirewallRule -Name ([string]$definition.Name)
        $selected = if ($advancedFirewallDecisionKnown -and $advancedSkipFirewallLayer) { $false }
        elseif ($advancedFirewallDecisionKnown) {
            switch ($definition.Group) {
                'UPnP' { if ($advancedChoicesAuthoritative) { $upnpConfigured } else { $null -ne $rule } }
                'AdminShares' { if ($advancedChoicesAuthoritative) { $adminConfigured } else { $null -ne $rule } }
                'Discovery' { if ($advancedChoicesAuthoritative) { $advancedDiscoveryExpected } else { $null -ne $rule } }
                'Miracast' { if ($advancedChoicesAuthoritative) { $advancedWirelessFullExpected } else { $null -ne $rule } }
                default { $true }
            }
        }
        else { $null -ne $rule }

        if (-not $selected) {
            $results.NotChecked++
            $firewallChoiceProven = $advancedChoicesAuthoritative -and $advancedFirewallDecisionKnown
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting "Firewall: $($definition.Name)" -Expected 'Selected exact block rule' `
                -ChoiceProven $firewallChoiceProven -Topic Firewall `
                -ProvenActual 'Excluded by saved AdvancedSecurity firewall choice.' `
                -UnprovenActual 'No saved firewall choice; rule selection cannot be inferred.'
            continue
        }
        if ($null -eq $advancedFirewallFilterCache -and -not $advancedFirewallFilterCacheFailed) {
            try {
                $advancedFirewallFilterCache = Get-AdvancedSecurityFirewallFilterCache
            }
            catch {
                $advancedFirewallFilterCacheFailed = $true
                Write-Host "  Store-wide filter enumeration unavailable; using per-rule queries (slower)..." -ForegroundColor DarkGray
            }
        }
        $verification = if ($null -ne $advancedFirewallFilterCache) {
            Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet $allAdvancedFirewallRules -FilterCache $advancedFirewallFilterCache
        }
        else {
            Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition
        }
        if ($verification.Compliant) {
            $results.Verified++
            $advPassed += [PSCustomObject]@{ Setting="Firewall: $($definition.Name)"; Expected="$($definition.Direction) $($definition.Protocol) $($definition.Port) $($definition.Profile) Block"; Actual='Exact rule and all filters verified' }
        }
        else {
            $results.Failed++
            $advFailed += [PSCustomObject]@{ Setting="Firewall: $($definition.Name)"; Expected="$($definition.Direction) $($definition.Protocol) $($definition.Port) $($definition.Profile) Block"; Actual=($verification.Mismatches -join '; ') }
        }
    }

    # Complete RDP disable is a separate, explicit choice. Evidence inference
    # for non-authoritative runs matches the other optional targets, but only
    # the exact module-owned disable state (DWord 1) counts as evidence: RDP
    # left enabled with an unknown decision stays NotChecked because it may be
    # a deliberate preserve choice and must not raise a false alarm.
    if (-not $advancedChoicesAuthoritative -and -not $advancedRdpDecisionKnown) {
        $rdpEvidenceKey = if (Test-Path -LiteralPath $rdpDisableCheck.Path -PathType Container) { Get-Item -LiteralPath $rdpDisableCheck.Path -ErrorAction Stop } else { $null }
        if ($rdpEvidenceKey -and $rdpEvidenceKey.GetValueNames() -contains $rdpDisableCheck.Name -and
            $rdpEvidenceKey.GetValueKind($rdpDisableCheck.Name).ToString() -eq 'DWord' -and
            [int]$rdpEvidenceKey.GetValue($rdpDisableCheck.Name) -eq [int]$rdpDisableCheck.Expected) {
            $advancedRdpDecisionKnown = $true
            $advancedDisableRdp = $true
        }
    }
    if (-not [bool]$advancedApplicability.RdpHostSupported) {
        $results.NotApplicable++
        $advPassed += [PSCustomObject]@{
            Setting=$rdpDisableCheck.Desc; Expected='RDP host-capable Windows edition'
            Actual="Not applicable on $($advancedApplicability.EditionFamily)"; CheckState='NotApplicable'
        }
    }
    elseif (-not $advancedRdpDecisionKnown -or -not $advancedDisableRdp) {
        $results.NotChecked++
        $rdpChoiceProven = $advancedChoicesAuthoritative -and $advancedRdpDecisionKnown
        $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
            -Setting $rdpDisableCheck.Desc -Expected 'DWord/1 when explicitly selected' `
            -ChoiceProven $rdpChoiceProven -Topic Rdp `
            -ProvenActual 'Excluded by saved AdvancedSecurity choice: current RDP state is preserved.' `
            -UnprovenActual 'No saved RDP choice; complete-disable selection cannot be inferred.'
    }
    else {
        $rdpDisableKey = if (Test-Path -LiteralPath $rdpDisableCheck.Path -PathType Container) {
            Get-Item -LiteralPath $rdpDisableCheck.Path -ErrorAction Stop
        } else { $null }
        $rdpDisableExists = $rdpDisableKey -and $rdpDisableKey.GetValueNames() -contains $rdpDisableCheck.Name
        $rdpDisableValue = if ($rdpDisableExists) { $rdpDisableKey.GetValue($rdpDisableCheck.Name) } else { $null }
        if ($rdpDisableExists -and $rdpDisableKey.GetValueKind($rdpDisableCheck.Name).ToString() -eq 'DWord' -and
            [int]$rdpDisableValue -eq 1) {
            $results.Verified++
            $advPassed += [PSCustomObject]@{ Setting=$rdpDisableCheck.Desc; Expected='DWord/1'; Actual='DWord/1' }
        }
        else {
            $results.Failed++
            $advFailed += [PSCustomObject]@{
                Setting=$rdpDisableCheck.Desc
                Expected='DWord/1'
                Actual=$(if ($rdpDisableExists) { "$($rdpDisableKey.GetValueKind($rdpDisableCheck.Name))/$rdpDisableValue" } else { 'Missing' })
            }
        }
    }

    # Choice-aware optional registry targets. Exact values only count when the
    # corresponding choice is selected; otherwise they are NotChecked.
    $optionalRegistryChecks = @(
        @{ Check=$shieldsUpCheck; Selected=($advancedFirewallDecisionKnown -and -not $advancedSkipFirewallLayer -and $advancedChoicesAuthoritative -and $advancedConfiguredProfile -eq 'Maximum') }
        @{ Check=$discoveryMdnsCheck; Selected=$discoverySelected }
        @{ Check=$ipv6Check; Selected=$advancedIPv6Expected }
    )
    foreach ($optionalDefinition in $optionalRegistryChecks) {
        $check = $optionalDefinition.Check
        $key = if (Test-Path -LiteralPath $check.Path -PathType Container) { Get-Item -LiteralPath $check.Path -ErrorAction Stop } else { $null }
        $exists = $key -and $key.GetValueNames() -contains [string]$check.Name
        $actual = if ($exists) { $key.GetValue([string]$check.Name) } else { $null }
        $selected = [bool]$optionalDefinition.Selected
        if (-not $advancedChoicesAuthoritative -and $exists) { $selected = $true }
        if (-not $selected) {
            $results.NotChecked++
            $optionalChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting $check.Desc -Expected "DWord/$($check.Expected) when selected" `
                -ChoiceProven $optionalChoiceProven -Topic OptionalControl `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: optional control was not selected.' `
                -UnprovenActual 'No saved optional-control choice; selection cannot be inferred.'
        }
        elseif ($exists -and $key.GetValueKind([string]$check.Name).ToString() -eq 'DWord' -and [int]$actual -eq [int]$check.Expected) {
            $results.Verified++; $advPassed += [PSCustomObject]@{ Setting=$check.Desc; Expected="DWord/$($check.Expected)"; Actual="DWord/$actual" }
        }
        else {
            $results.Failed++; $advFailed += [PSCustomObject]@{ Setting=$check.Desc; Expected="DWord/$($check.Expected)"; Actual=$(if ($exists) { "$($key.GetValueKind([string]$check.Name))/$actual" } else { 'Missing' }) }
        }
    }

    $adminKey = if (Test-Path -LiteralPath $adminShareChecks[0].Path -PathType Container) { Get-Item -LiteralPath $adminShareChecks[0].Path -ErrorAction Stop } else { $null }
    $adminEvidence = $adminKey -and @($adminShareChecks | Where-Object {
            $adminKey.GetValueNames() -contains $_.Name
        }).Count -gt 0
    $adminPolicySelected = $adminConfigured -or (-not $advancedChoicesAuthoritative -and $adminEvidence)
    foreach ($check in $adminShareChecks) {
        $exists = $adminKey -and $adminKey.GetValueNames() -contains $check.Name
        $actual = if ($exists) { $adminKey.GetValue($check.Name) } else { $null }
        if (-not $adminPolicySelected) {
            $results.NotChecked++
            $adminChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting $check.Desc -Expected 'DWord/0 when selected' `
                -ChoiceProven $adminChoiceProven -Topic AdminShares `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: administrative shares are preserved.' `
                -UnprovenActual 'No saved administrative-share choice; selection cannot be inferred.'
        }
        elseif ($exists -and $adminKey.GetValueKind($check.Name).ToString() -eq 'DWord' -and [int]$actual -eq 0) {
            $results.Verified++; $advPassed += [PSCustomObject]@{ Setting=$check.Desc; Expected='DWord/0'; Actual='DWord/0' }
        }
        else {
            $results.Failed++; $advFailed += [PSCustomObject]@{ Setting=$check.Desc; Expected='DWord/0'; Actual=$(if ($exists) { "$($adminKey.GetValueKind($check.Name))/$actual" } else { 'Missing' }) }
        }
    }

    # Check all always-owned registry settings. SRP path rules are verified separately.
    $allAdvChecks = $rdpChecks + $tlsChecks + $wuChecks + $wpadChecks + $srpRootChecks
    foreach ($check in $allAdvChecks) {
        if ($check.ContainsKey('Applicable') -and -not [bool]$check.Applicable) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting=$check.Desc; Expected='Supported Windows edition'
                Actual="Not applicable on $($advancedApplicability.EditionFamily)"; CheckState='NotApplicable'
            }
            continue
        }
        $actualValue = $null
        $actualType = $null
        if (Test-Path $check.Path) {
            $advancedKey = Get-Item -LiteralPath $check.Path -ErrorAction Stop
            if ($advancedKey.GetValueNames() -contains [string]$check.Name) {
                $actualValue = $advancedKey.GetValue([string]$check.Name)
                $actualType = $advancedKey.GetValueKind([string]$check.Name).ToString()
            }
        }
        $valueMatches = if ($check.ContainsKey('AllowedValues')) {
            $null -ne $actualValue -and [int]$actualValue -in @($check.AllowedValues)
        } else {
            $null -ne $actualValue -and $actualValue -eq $check.Expected
        }

        if ($valueMatches -and $actualType -eq 'DWord') {
            # Setting exists and matches expected value - SUCCESS
            $results.Verified++
            $advPassed += [PSCustomObject]@{
                Setting  = $check.Desc
                Expected = $check.Expected
                Actual   = $actualValue
            }
        }
        elseif ($check.Optional -eq $true) {
            # A non-selected optional setting is not positive verification.
            $results.NotChecked++
            $alwaysOptionalChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting $check.Desc -Expected ([string]$check.Expected) `
                -ChoiceProven $alwaysOptionalChoiceProven -Topic OptionalControl `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: optional control was not selected.' `
                -UnprovenActual "No saved optional-control choice; observed value/type is $actualValue/$actualType."
        }
        elseif ([string]$check.Name -ceq 'IsContinuousInnovationOptedIn' -and
            $actualType -eq 'DWord' -and $null -ne $actualValue -and [int]$actualValue -eq 1 -and
            (Test-Path -LiteralPath $check.Path -PathType Container) -and
            ((Get-Item -LiteralPath $check.Path -ErrorAction Stop).GetValueNames() -contains 'CIOptinModified')) {
            # Windows re-commits a stored manual Settings-toggle opt-in
            # (CIOptinModified stamp, proven via ETL - see Set-WindowsUpdate.ps1)
            # over this value at boot and on Settings activity. That is the
            # user's own preserved Windows choice, not hardening drift, and no
            # registry write can win against it. Reported as a deliberate
            # NotChecked naming the only durable fix instead of a permanent
            # false alarm. Value 1 WITHOUT the intent stamp stays a failure.
            $results.NotChecked++
            $advPassed += Get-AdvancedSecurityNotCheckedDetail `
                -Setting $check.Desc -Expected ([string]$check.Expected) `
                -Actual "Excluded by the authoritative Windows Settings choice marker (CIOptinModified); turn OFF 'Get the latest updates as soon as they're available' under Settings > Windows Update." `
                -Disposition 'ByChoice' -EvidenceSource 'WindowsState' `
                -ReasonCode 'AdvancedSecurity.WindowsUpdateUserOptIn'
        }
        else {
            # Setting is required but missing or wrong
            $results.Failed++
            $advFailed += [PSCustomObject]@{
                Setting  = $check.Desc
                Expected = $check.Expected
                Actual   = if ($null -eq $actualValue) { "Not set" } else { $actualValue }
            }
        }
    }

    # WinINet is per-user state and must be queried through the supported API in
    # the actual Explorer user's token. The helper's transient limited task is
    # identity-checked and removed after the query. Only the AutoDetect bit is
    # owned; all other proxy flags remain outside the NoID Privacy contract.
    Write-Host "  Querying per-user WinINet proxy state (transient task)..." -ForegroundColor DarkGray
    try {
        $winInetUser = Get-AdvancedSecurityInteractiveUser -AllowNone
        if ($null -eq $winInetUser) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting  = 'WPAD AutoDetect (interactive Explorer user)'
                Expected = 'WinINet PROXY_TYPE_AUTO_DETECT cleared'
                Actual   = 'Not applicable: no interactive Explorer user exists in this session'
                CheckState = 'NotApplicable'
            }
        }
        else {
            $winInetState = Invoke-AdvancedSecurityWinInetUserState -User $winInetUser -Operation Query
            if ([bool]$winInetState.AutoDetectEnabled) {
                $results.Failed++
                $advFailed += [PSCustomObject]@{
                    Setting  = 'WPAD AutoDetect (interactive Explorer user)'
                    Expected = 'PROXY_TYPE_AUTO_DETECT cleared'
                    Actual   = "Enabled (flags=$($winInetState.Flags), SID=$($winInetUser.Sid))"
                }
            }
            else {
                $results.Verified++
                $advPassed += [PSCustomObject]@{
                    Setting  = 'WPAD AutoDetect (interactive Explorer user)'
                    Expected = 'PROXY_TYPE_AUTO_DETECT cleared'
                    Actual   = "Disabled through WinINet state (flags=$($winInetState.Flags), SID=$($winInetUser.Sid))"
                }
            }
        }
    }
    catch {
        # A transient task/API failure is explicit uncertainty, never a pass.
        $results.NotChecked++
        $advPassed += Get-AdvancedSecurityNotCheckedDetail `
            -Setting 'WPAD AutoDetect (interactive Explorer user)' `
            -Expected 'WinINet PROXY_TYPE_AUTO_DETECT cleared' `
            -Actual "Could not verify WinINet state: $($_.Exception.Message)" `
            -Disposition 'CannotVerify' -EvidenceSource 'RuntimeQuery' `
            -ReasonCode 'AdvancedSecurity.WinInetQueryFailed'
    }

    # Check risky services. UPnP services are choice-aware; lmhosts is always owned.
    # Same profile precedence as the UPnP firewall definitions above.
    $upnpServicesExpected = $advancedChoicesAuthoritative -and $(if ($appliedScopeRun) {
            $advancedConfiguredProfile -ne 'Balanced' -or
            [bool]$frameworkConfig.modules.AdvancedSecurity.disableUPnP
        } else { [bool]$advancedSecurityIntent.disableUPnP })
    foreach ($svcDef in $riskyServices) {
        $service = Get-UniqueAdvancedService -Name ([string]$svcDef.Name)
        $serviceSelected = -not $svcDef.Optional -or $upnpServicesExpected -or
            (-not $advancedChoicesAuthoritative -and $service -and $service.StartType -eq 'Disabled')

        if (-not $service) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting  = "Service: $($svcDef.Desc)"
                Expected = "Disabled/Stopped"
                Actual   = 'Not applicable: service is not installed'
                CheckState = 'NotApplicable'
            }
        }
        elseif (-not $serviceSelected) {
            $results.NotChecked++
            $upnpChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting "Service: $($svcDef.Desc)" -Expected 'Disabled/Stopped when selected' `
                -ChoiceProven $upnpChoiceProven -Topic Upnp `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: UPnP services are preserved.' `
                -UnprovenActual 'No saved UPnP choice; service selection cannot be inferred.'
        }
        elseif ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped') {
            $results.Verified++
            $advPassed += [PSCustomObject]@{
                Setting  = "Service: $($svcDef.Desc)"
                Expected = "Disabled/Stopped"
                Actual   = "$($service.StartType)/$($service.Status)"
            }
        }
        else {
            # Service is required but not disabled
            $results.Failed++
            $advFailed += [PSCustomObject]@{
                Setting  = "Service: $($svcDef.Desc)"
                Expected = "Disabled/Stopped"
                Actual   = "$($service.StartType)/$($service.Status)"
            }
        }
    }

    # Stable SRP rules: verify all three owned values for both deterministic IDs.
    $srpConfigPath = Join-Path $rootPath 'Modules\AdvancedSecurity\Config\SRP-Rules.json'
    $srpConfig = Get-Content -LiteralPath $srpConfigPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($rule in @($srpConfig.PathRules | Where-Object { $_.Enabled })) {
        $rulePath = Join-Path ([string]$srpConfig.RegistryPaths.PathRules) ([string]$rule.Id)
        $ruleKey = if (Test-Path -LiteralPath $rulePath -PathType Container) { Get-Item -LiteralPath $rulePath -ErrorAction Stop } else { $null }
        foreach ($expectation in @(
                @{ Name='ItemData'; Type='ExpandString'; Value=[string]$rule.Path }
                @{ Name='Description'; Type='String'; Value=[string]$rule.Description }
                @{ Name='SaferFlags'; Type='DWord'; Value=[int]$rule.SaferFlags }
            )) {
            $exists = $ruleKey -and $ruleKey.GetValueNames() -contains $expectation.Name
            $actual = if ($exists) { $ruleKey.GetValue($expectation.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
            $actualJson = ConvertTo-Json -InputObject $actual -Compress
            $expectedJson = ConvertTo-Json -InputObject $expectation.Value -Compress
            $ok = $exists -and $ruleKey.GetValueKind($expectation.Name).ToString() -eq $expectation.Type -and $actualJson -ceq $expectedJson
            if ($ok) {
                $results.Verified++; $advPassed += [PSCustomObject]@{ Setting="SRP $($rule.Id) $($expectation.Name)"; Expected="$($expectation.Type)/$expectedJson"; Actual="$($expectation.Type)/$actualJson" }
            }
            else {
                $results.Failed++; $advFailed += [PSCustomObject]@{ Setting="SRP $($rule.Id) $($expectation.Name)"; Expected="$($expectation.Type)/$expectedJson"; Actual=$(if ($exists) { "$($ruleKey.GetValueKind($expectation.Name))/$actualJson" } else { 'Missing' }) }
            }
        }
    }
    # Risky Ports checks owned by AdvancedSecurity - individual firewall rule verification
    # Baseline-owned registry policies (EnableMulticast, NodeType, SMB1, AllowInsecureGuestAuth)
    # are verified in the SecurityBaseline/Registry section and are intentionally
    # NOT duplicated here to keep module ownership clean.

    # 1. Check NetBIOS disabled on all network adapters (aggregated policy check)
    try {
        $netbios = Test-AdvancedSecurityNetBIOSDisabled
        $totalAdapters = @($netbios.Adapters).Count
        $disabledCount = $totalAdapters - @($netbios.NonCompliant).Count
        $settingName = "NetBIOS Adapters (Aggregated)"

        if ([bool]$netbios.Compliant) {
            $results.Verified++
            $advPassed += [PSCustomObject]@{
                Setting  = $settingName
                Expected = "All active and physical adapters Disabled (DWORD/2)"
                Actual   = "$disabledCount/$totalAdapters disabled"
            }
        }
        else {
            $results.Failed++
            $actualDesc = "$disabledCount/$totalAdapters disabled"
            if (@($netbios.NonCompliant).Count -gt 0) {
                $actualDesc += " | Non-compliant: " + (@($netbios.NonCompliant | ForEach-Object {
                            "$($_.Description) (provider=$($_.ProviderValue), registry=$($_.RegistryValueType)/$($_.RegistryValue))"
                        }) -join '; ')
            }
            $advFailed += [PSCustomObject]@{
                Setting  = $settingName
                Expected = "All active and physical adapters Disabled (DWORD/2)"
                Actual   = $actualDesc
            }
        }
    }
    catch {
        $results.Failed++
        $advFailed += [PSCustomObject]@{
            Setting  = "NetBIOS Adapters (Aggregated)"
            Expected = "All active and physical adapters Disabled (DWORD/2)"
            Actual   = "Check failed: $($_.Exception.Message)"
        }
    }

    # Wireless Display base values are always owned. Complete-disable values,
    # service and adapters are checked only when that choice is authoritative
    # or there is concrete module-owned evidence that it was selected.
    if (-not [bool]$advancedApplicability.WirelessDisplaySupported) {
        foreach ($wirelessSetting in @(
                'Wireless Display: Block receiving projections',
                'Wireless Display: Always require PIN',
                'Wireless Display: Block sending projections',
                'Wireless Display: Block mDNS advertisement',
                'Wireless Display: Block mDNS discovery',
                'Wireless Display: Block infrastructure sending',
                'Wireless Display: Block infrastructure receiving',
                'WiFi Direct Service (WFDSConMgrSvc)',
                'Wi-Fi Direct adapters (aggregated)'
            )) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting=$wirelessSetting; Expected='Supported Wireless Display policy edition'
                Actual="Not applicable on $($advancedApplicability.EditionFamily)"; CheckState='NotApplicable'
            }
        }
    }
    else {
        $wirelessDisplayPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        $wirelessKey = if (Test-Path -LiteralPath $wirelessDisplayPath -PathType Container) { Get-Item -LiteralPath $wirelessDisplayPath -ErrorAction Stop } else { $null }
        $wirelessValueNames = if ($wirelessKey) { @($wirelessKey.GetValueNames()) } else { @() }
        $wirelessBaseChecks = @(
            @{ Name='AllowProjectionToPC'; Expected=0; Desc='Wireless Display: Block receiving projections' }
            @{ Name='RequirePinForPairing'; Expected=2; Desc='Wireless Display: Always require PIN' }
        )
        foreach ($check in $wirelessBaseChecks) {
            $exists = $wirelessValueNames -contains $check.Name
            $actual = if ($exists) { $wirelessKey.GetValue($check.Name) } else { $null }
            $ok = $exists -and $wirelessKey.GetValueKind($check.Name).ToString() -eq 'DWord' -and
                [int]$actual -eq [int]$check.Expected
            if ($ok) {
                $results.Verified++
                $advPassed += [PSCustomObject]@{ Setting=$check.Desc; Expected="DWord/$($check.Expected)"; Actual="DWord/$actual" }
            }
            else {
                $results.Failed++
                $advFailed += [PSCustomObject]@{ Setting=$check.Desc; Expected="DWord/$($check.Expected)"; Actual=$(if ($exists) { "$($wirelessKey.GetValueKind($check.Name))/$actual" } else { 'Missing' }) }
            }
        }

        $wirelessOptionalChecks = @(
            @{ Name='AllowProjectionFromPC'; Expected=0; Desc='Wireless Display: Block sending projections' }
            @{ Name='AllowMdnsAdvertisement'; Expected=0; Desc='Wireless Display: Block mDNS advertisement' }
            @{ Name='AllowMdnsDiscovery'; Expected=0; Desc='Wireless Display: Block mDNS discovery' }
            @{ Name='AllowProjectionFromPCOverInfrastructure'; Expected=0; Desc='Wireless Display: Block infrastructure sending' }
            @{ Name='AllowProjectionToPCOverInfrastructure'; Expected=0; Desc='Wireless Display: Block infrastructure receiving' }
        )
        $wirelessEvidence = @($wirelessOptionalChecks | Where-Object { $wirelessValueNames -contains $_.Name }).Count -gt 0 -or
            @($allAdvancedFirewallRules | Where-Object { $_.Name -like 'NoID-Block-Miracast-*' }).Count -gt 0
        $wirelessFullSelected = $advancedWirelessFullExpected -or (-not $advancedChoicesAuthoritative -and $wirelessEvidence)
        foreach ($check in $wirelessOptionalChecks) {
            if (-not $wirelessFullSelected) {
                $results.NotChecked++
                $wirelessChoiceProven = $advancedChoicesAuthoritative
                $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                    -Setting $check.Desc -Expected 'DWord/0 when selected' `
                    -ChoiceProven $wirelessChoiceProven -Topic WirelessDisplay `
                    -ProvenActual 'Excluded by saved AdvancedSecurity choice: complete Wireless Display disable was not selected.' `
                    -UnprovenActual 'No saved Wireless Display choice; complete-disable selection cannot be inferred.'
                continue
            }
            $exists = $wirelessValueNames -contains $check.Name
            $actual = if ($exists) { $wirelessKey.GetValue($check.Name) } else { $null }
            $ok = $exists -and $wirelessKey.GetValueKind($check.Name).ToString() -eq 'DWord' -and [int]$actual -eq 0
            if ($ok) {
                $results.Verified++
                $advPassed += [PSCustomObject]@{ Setting=$check.Desc; Expected='DWord/0'; Actual='DWord/0' }
            }
            else {
                $results.Failed++
                $advFailed += [PSCustomObject]@{ Setting=$check.Desc; Expected='DWord/0'; Actual=$(if ($exists) { "$($wirelessKey.GetValueKind($check.Name))/$actual" } else { 'Missing' }) }
            }
        }

        $wfdService = Get-UniqueAdvancedService -Name 'WFDSConMgrSvc'
        if (-not $wfdService) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting='WiFi Direct Service (WFDSConMgrSvc)'; Expected='Disabled/Stopped'
                Actual='Not applicable: service is not installed'; CheckState='NotApplicable'
            }
        }
        elseif (-not $wirelessFullSelected) {
            $results.NotChecked++
            $wirelessServiceChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting 'WiFi Direct Service (WFDSConMgrSvc)' -Expected 'Disabled/Stopped when selected' `
                -ChoiceProven $wirelessServiceChoiceProven -Topic WirelessDisplay `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: complete Wireless Display disable was not selected.' `
                -UnprovenActual 'No saved Wireless Display choice; Wi-Fi Direct service selection cannot be inferred.'
        }
        elseif ($wfdService.StartType -eq 'Disabled' -and $wfdService.Status -eq 'Stopped') {
            $results.Verified++
            $advPassed += [PSCustomObject]@{ Setting='WiFi Direct Service (WFDSConMgrSvc)'; Expected='Disabled/Stopped'; Actual="$($wfdService.StartType)/$($wfdService.Status)" }
        }
        else {
            $results.Failed++
            $advFailed += [PSCustomObject]@{ Setting='WiFi Direct Service (WFDSConMgrSvc)'; Expected='Disabled/Stopped'; Actual="$($wfdService.StartType)/$($wfdService.Status)" }
        }

        $wfdAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*' })
        if ($wfdAdapters.Count -eq 0) {
            $results.NotApplicable++
            $advPassed += [PSCustomObject]@{
                Setting='Wi-Fi Direct adapters (aggregated)'; Expected='All disabled'
                Actual='Not applicable: no Wi-Fi Direct adapter is installed'; CheckState='NotApplicable'
            }
        }
        elseif (-not $wirelessFullSelected) {
            $results.NotChecked++
            $wirelessAdapterChoiceProven = $advancedChoicesAuthoritative
            $advPassed += Get-AdvancedSecurityChoiceNotCheckedDetail `
                -Setting 'Wi-Fi Direct adapters (aggregated)' -Expected 'All disabled when selected' `
                -ChoiceProven $wirelessAdapterChoiceProven -Topic WirelessDisplay `
                -ProvenActual 'Excluded by saved AdvancedSecurity choice: complete Wireless Display disable was not selected.' `
                -UnprovenActual 'No saved Wireless Display choice; Wi-Fi Direct adapter selection cannot be inferred.'
        }
        else {
            $enabledWfdAdapters = @($wfdAdapters | Where-Object { [string]$_.Status -ne 'Disabled' })
            if ($enabledWfdAdapters.Count -eq 0) {
                $results.Verified++
                $advPassed += [PSCustomObject]@{ Setting='Wi-Fi Direct adapters (aggregated)'; Expected='All disabled'; Actual="$($wfdAdapters.Count) adapter(s), all disabled" }
            }
            else {
                $results.Failed++
                $advFailed += [PSCustomObject]@{ Setting='Wi-Fi Direct adapters (aggregated)'; Expected='All disabled'; Actual="$($enabledWfdAdapters.Count) remain enabled" }
            }
        }
    }

    # Add to AllSettings for HTML report
    # Use actual count of checks (policy-level, now deterministic)
    $advNotCheckedDetails = @($advPassed | Where-Object {
            $_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -eq 'NotChecked'
        })
    $advNotApplicableDetails = @($advPassed | Where-Object {
            $_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -eq 'NotApplicable'
        })
    $advVerifiedDetails = @($advPassed | Where-Object {
            -not ($_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -in @('NotChecked', 'NotApplicable'))
        })
    $advTotalChecks = $advPassed.Count + $advFailed.Count
    if ($advTotalChecks -ne $EXPECTED_ADVANCED_COUNT) {
        throw "AdvancedSecurity declared-check reconciliation failed: expected $EXPECTED_ADVANCED_COUNT, produced $advTotalChecks"
    }
    $advNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
        -Details $advNotCheckedDetails -ExpectedCount $advNotCheckedDetails.Count `
        -Context 'AdvancedSecurity NotChecked evidence'
    $results.AdvancedSecuritySettings = $advTotalChecks
    $results.AllSettings += [PSCustomObject]@{
        Category      = "AdvancedSecurity"
        Total         = $advTotalChecks
        Passed        = $advVerifiedDetails.Count
        Failed        = $advFailed.Count
        NotChecked    = $advNotCheckedDetails.Count
        NotCheckedDeliberate = $advNotCheckedAccounting.ByChoice
        NotCheckedNoSavedChoice = $advNotCheckedAccounting.NoSavedChoice
        NotCheckedCannotVerify = $advNotCheckedAccounting.CannotVerify
        NotApplicable = $advNotApplicableDetails.Count
        PassedDetails = $advVerifiedDetails
        NotCheckedDetails = $advNotCheckedDetails
        NotApplicableDetails = $advNotApplicableDetails
        FailedDetails = $advFailed
    }

    if ($advFailed.Count -gt 0) {
        $results.FailedSettings += [PSCustomObject]@{
            Category = "AdvancedSecurity"
            Count    = $advFailed.Count
            Details  = $advFailed
        }
    }

    $advNotCheckedDeliberateCount = $advNotCheckedAccounting.ByChoice
    $advancedPresentation = Get-VerificationModulePresentation `
        -Name 'AdvancedSecurity' -Total $advTotalChecks -Passed $advVerifiedDetails.Count -Failed $advFailed.Count `
        -NotChecked $advNotCheckedDetails.Count -NotCheckedDeliberate $advNotCheckedDeliberateCount `
        -NotApplicable $advNotApplicableDetails.Count `
        -Summary "$($advVerifiedDetails.Count) verified; $($advFailed.Count) failed; $advNotCheckedDeliberateCount intentional exclusion(s); $($advNotCheckedDetails.Count - $advNotCheckedDeliberateCount) unproven; $($advNotApplicableDetails.Count) not applicable ($advTotalChecks declared)."
    Write-VerificationModulePresentation -Presentation $advancedPresentation
}
catch {
    $results.Verified = $advVerifiedBefore
    $results.Failed = $advFailedBefore + $EXPECTED_ADVANCED_COUNT
    $results.NotChecked = $advNotCheckedBefore
    $results.NotApplicable = $advNotApplicableBefore
    $results.AdvancedSecuritySettings = $EXPECTED_ADVANCED_COUNT
    $advancedScopeFailure = [PSCustomObject]@{
        Setting='Complete AdvancedSecurity verification scope'; Path='AdvancedSecurity'
        Expected="$EXPECTED_ADVANCED_COUNT executable checks"
        Actual="Verification failed closed: $($_.Exception.Message)"
    }
    $results.AllSettings += [PSCustomObject]@{
        Category='AdvancedSecurity'; Total=$EXPECTED_ADVANCED_COUNT; Passed=0; Failed=$EXPECTED_ADVANCED_COUNT
        NotChecked=0; NotApplicable=0; PassedDetails=@(); FailedDetails=@($advancedScopeFailure)
        NotCheckedDetails=@(); NotApplicableDetails=@()
    }
    $results.FailedSettings += [PSCustomObject]@{
        Category='AdvancedSecurity'; Count=$EXPECTED_ADVANCED_COUNT; Details=@($advancedScopeFailure)
    }
    $advancedPresentation = Get-VerificationModulePresentation `
        -Name 'AdvancedSecurity' -Total $EXPECTED_ADVANCED_COUNT -Passed 0 -Failed $EXPECTED_ADVANCED_COUNT `
        -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 `
        -Summary "Verification failed closed: $($_.Exception.Message)"
    Write-VerificationModulePresentation -Presentation $advancedPresentation
}
}

# Prove that every declared verification category exists exactly once with its
# canonical active-run total before deriving global counters.
$expectedCategoryTotals = [ordered]@{}
if (Test-VerificationModuleSelected 'SecurityBaseline') {
    $expectedCategoryTotals.Registry = $EXPECTED_REGISTRY_COUNT
    $expectedCategoryTotals.AuditPolicies = $EXPECTED_AUDIT_COUNT
    $expectedCategoryTotals.SecurityTemplate = $EXPECTED_SECURITY_COUNT
}
if (Test-VerificationModuleSelected 'ASR') { $expectedCategoryTotals.ASR = $EXPECTED_ASR_COUNT }
if (Test-VerificationModuleSelected 'DNS') { $expectedCategoryTotals.DNS = $EXPECTED_DNS_COUNT }
if (Test-VerificationModuleSelected 'Privacy') { $expectedCategoryTotals.Privacy = $results.PrivacyChecks }
if (Test-VerificationModuleSelected 'AntiAI') { $expectedCategoryTotals.AntiAI = $EXPECTED_ANTIAI_COUNT }
if (Test-VerificationModuleSelected 'EdgeHardening') { $expectedCategoryTotals.EdgeHardening = $EXPECTED_EDGE_COUNT }
if (Test-VerificationModuleSelected 'AdvancedSecurity') { $expectedCategoryTotals.AdvancedSecurity = $EXPECTED_ADVANCED_COUNT }
foreach ($categoryName in $expectedCategoryTotals.Keys) {
    $categoryResults = @($results.AllSettings | Where-Object { [string]$_.Category -ceq $categoryName })
    if ($categoryResults.Count -ne 1) {
        throw "Verification category '$categoryName' occurred $($categoryResults.Count) times; expected exactly once"
    }
    $categoryResult = $categoryResults[0]
    if ([int]$categoryResult.Total -ne [int]$expectedCategoryTotals[$categoryName]) {
        throw "Verification category '$categoryName' total is $($categoryResult.Total); expected $($expectedCategoryTotals[$categoryName])"
    }
    foreach ($requiredProperty in @('Passed','Failed','NotChecked','NotApplicable','PassedDetails','FailedDetails','NotCheckedDetails','NotApplicableDetails')) {
        if (-not ($categoryResult.PSObject.Properties.Name -contains $requiredProperty)) {
            throw "Verification category '$categoryName' is missing result property '$requiredProperty'"
        }
    }
    $categoryStateTotal = [int]$categoryResult.Passed + [int]$categoryResult.Failed +
        [int]$categoryResult.NotChecked + [int]$categoryResult.NotApplicable
    if ($categoryStateTotal -ne [int]$categoryResult.Total) {
        throw "Verification category '$categoryName' does not reconcile: states=$categoryStateTotal, total=$($categoryResult.Total)"
    }

    # NotChecked detail rows can be weighted (for example one Privacy row can
    # represent an unknown 117-target profile). The weight sum is a hard
    # per-category invariant, not a best-effort presentation fallback.
    $categoryNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
        -Details @($categoryResult.NotCheckedDetails) `
        -ExpectedCount ([int]$categoryResult.NotChecked) `
        -Context "Verification category '$categoryName'"
    Add-Member -InputObject $categoryResult -MemberType NoteProperty `
        -Name NotCheckedDeliberate -Value ([int]$categoryNotCheckedAccounting.ByChoice) -Force
    Add-Member -InputObject $categoryResult -MemberType NoteProperty `
        -Name NotCheckedNoSavedChoice -Value ([int]$categoryNotCheckedAccounting.NoSavedChoice) -Force
    Add-Member -InputObject $categoryResult -MemberType NoteProperty `
        -Name NotCheckedCannotVerify -Value ([int]$categoryNotCheckedAccounting.CannotVerify) -Force
}
if ($results.AllSettings.Count -ne $expectedCategoryTotals.Count) {
    throw "Unexpected verification categories detected: actual=$($results.AllSettings.Count), expected=$($expectedCategoryTotals.Count)"
}

# STABLE DENOMINATOR CONTRACT: applied-scope (post-Apply) runs publish the
# same declared totals as standalone complete runs. Authoritatively selected or preserved
# optional state keeps its honest NotChecked classification in every count and
# is proven by authoritative intent or a Windows-owned preservation stamp via
# notCheckedDeliberate instead of being subtracted
# from the denominator. Historically the subtraction made the same machine
# publish the complete declared total from the Verify tab but a smaller total
# from post-Apply verification -- an unexplainable fluctuation for the user.
# The verdict below and both GUI gates treat
# "zero failures and every NotChecked authoritatively selected/preserved" as fully compliant,
# so removing the subtraction changes no compliance outcome, only the
# stability of the published numbers.

# Reconcile all global counters from the one canonical category result list.
# A target must be exactly one of Passed, Failed, NotChecked or NotApplicable.
$results.TotalSettings = ($results.AllSettings | Measure-Object -Property Total -Sum).Sum
$results.Verified = ($results.AllSettings | Measure-Object -Property Passed -Sum).Sum
$results.Failed = ($results.AllSettings | Measure-Object -Property Failed -Sum).Sum
$results.NotChecked = ($results.AllSettings | Measure-Object -Property NotChecked -Sum).Sum
$results.NotApplicable = ($results.AllSettings | Measure-Object -Property NotApplicable -Sum).Sum
if (($results.Verified + $results.Failed + $results.NotChecked + $results.NotApplicable) -ne $results.TotalSettings) {
    throw "Global verification reconciliation failed: total=$($results.TotalSettings), passed=$($results.Verified), failed=$($results.Failed), notChecked=$($results.NotChecked), notApplicable=$($results.NotApplicable)"
}
if ([int]$results.ProductTargetInventory -lt [int]$results.TotalSettings) {
    throw "Verification scope exceeds product inventory: scope=$($results.TotalSettings), inventory=$($results.ProductTargetInventory)"
}
# Aggregate the already validated structured dispositions. Human-facing text
# is intentionally not consulted here or by any downstream verdict consumer.
$results.NotCheckedDeliberate = [int](($results.AllSettings | Measure-Object -Property NotCheckedDeliberate -Sum).Sum)
$results.NotCheckedNoSavedChoice = [int](($results.AllSettings | Measure-Object -Property NotCheckedNoSavedChoice -Sum).Sum)
$results.NotCheckedCannotVerify = [int](($results.AllSettings | Measure-Object -Property NotCheckedCannotVerify -Sum).Sum)
if (($results.NotCheckedDeliberate + $results.NotCheckedNoSavedChoice + $results.NotCheckedCannotVerify) -ne $results.NotChecked) {
    throw "Global NotChecked disposition reconciliation failed: total=$($results.NotChecked), byChoice=$($results.NotCheckedDeliberate), noSavedChoice=$($results.NotCheckedNoSavedChoice), cannotVerify=$($results.NotCheckedCannotVerify)"
}
$unresolvedNotChecked = [int]$results.NotChecked - [int]$results.NotCheckedDeliberate
$verificationComplete = ($results.Failed -eq 0 -and $unresolvedNotChecked -eq 0)
$results.VerificationComplete = $verificationComplete

$results.Duration = (Get-Date) - $startTime

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verification Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Module evidence ($($selectedModuleNames.Count) selected):" -ForegroundColor Cyan
foreach ($selectedModuleName in $selectedModuleNames) {
    # Read every count from the reconciled result object (never the raw
    # declared constants): Privacy expands at runtime with the applied mode,
    # so only these values are guaranteed to sum to the Verification Scope
    # line below.
    $selectedModuleCount = switch ($selectedModuleName) {
        'SecurityBaseline' { [int]$results.RegistrySettings + [int]$results.SecurityTemplate + [int]$results.AuditPolicies }
        'ASR' { [int]$results.ASRRules }
        'DNS' { [int]$results.DNSChecks }
        'Privacy' { [int]$results.PrivacyChecks }
        'AntiAI' { [int]$results.AntiAIPolicies }
        'EdgeHardening' { [int]$results.EdgeHardeningPolicies }
        'AdvancedSecurity' { [int]$results.AdvancedSecuritySettings }
        default { throw "Unexpected selected module: $selectedModuleName" }
    }
    $selectedCategories = switch ($selectedModuleName) {
        'SecurityBaseline' { @('Registry', 'AuditPolicies', 'SecurityTemplate') }
        'ASR' { @('ASR') }
        'DNS' { @('DNS') }
        'Privacy' { @('Privacy') }
        'AntiAI' { @('AntiAI') }
        'EdgeHardening' { @('EdgeHardening') }
        'AdvancedSecurity' { @('AdvancedSecurity') }
        default { throw "Unexpected selected module: $selectedModuleName" }
    }
    $selectedRows = @($results.AllSettings | Where-Object {
            [string]$_.Category -in $selectedCategories
        })
    $moduleFailed = [int](($selectedRows | Measure-Object -Property Failed -Sum).Sum)
    $moduleNotChecked = [int](($selectedRows | Measure-Object -Property NotChecked -Sum).Sum)
    $moduleNotApplicable = [int](($selectedRows | Measure-Object -Property NotApplicable -Sum).Sum)
    $moduleNotCheckedDeliberate = [int](($selectedRows | Measure-Object -Property NotCheckedDeliberate -Sum).Sum)
    $moduleNoSavedChoice = [int](($selectedRows | Measure-Object -Property NotCheckedNoSavedChoice -Sum).Sum)
    $moduleCannotVerify = [int](($selectedRows | Measure-Object -Property NotCheckedCannotVerify -Sum).Sum)
    if (($moduleNotCheckedDeliberate + $moduleNoSavedChoice + $moduleCannotVerify) -ne $moduleNotChecked) {
        throw "Module '$selectedModuleName' NotChecked dispositions do not reconcile"
    }
    $moduleUnresolved = $moduleNotChecked - $moduleNotCheckedDeliberate
    if ($moduleFailed -gt 0) {
        $moduleVerdict = "FAILED: $moduleFailed mismatch(es)"
        $moduleColor = 'Red'
    }
    elseif ($moduleUnresolved -gt 0) {
        $moduleVerdict = "INCOMPLETE: $moduleUnresolved unproven"
        $moduleColor = 'Yellow'
    }
    elseif ($moduleNotCheckedDeliberate -gt 0) {
        $moduleVerdict = "VERIFIED: $moduleNotCheckedDeliberate intentional exclusion(s)"
        $moduleColor = 'Green'
    }
    elseif ($moduleNotApplicable -eq $selectedModuleCount) {
        $moduleVerdict = 'NOT APPLICABLE'
        $moduleColor = 'DarkGray'
    }
    else {
        $moduleVerdict = 'VERIFIED'
        $moduleColor = 'Green'
    }
    Write-Host "  - ${selectedModuleName}: [$moduleVerdict] ($selectedModuleCount targets)" -ForegroundColor $moduleColor
}
Write-Host ""

if ($results.Failed -gt 0) {
    Write-Host "Overall Result: FAILED" -ForegroundColor Red
}
elseif ($unresolvedNotChecked -gt 0) {
    Write-Host "Overall Result: INCOMPLETE" -ForegroundColor Yellow
}
else {
    Write-Host "Overall Result: VERIFIED" -ForegroundColor Green
}
Write-Host "Product Targets:    $($results.ProductTargetInventory)" -ForegroundColor White
$verificationScopeSuffix = if (Test-VerificationModuleSelected 'Privacy') {
    if (-not [string]::IsNullOrWhiteSpace([string]$results.PrivacyMode)) {
        " (Privacy: $($results.PrivacyMode))"
    }
    else { ' (Privacy profile unproven)' }
}
else { '' }
Write-Host "Verification Scope: $($results.TotalSettings)$verificationScopeSuffix" -ForegroundColor White
Write-Host "Verified:       $($results.Verified)" -ForegroundColor Green
Write-Host "Failed:         $($results.Failed)" -ForegroundColor $(if ($results.Failed -eq 0) { "Green" } else { "Red" })
if ($results.NotCheckedDeliberate -gt 0) {
    Write-Host "By Choice:      $($results.NotCheckedDeliberate)" -ForegroundColor Yellow
    Write-Host "                (authoritatively selected optional or preserved state)" -ForegroundColor DarkGray
}
if ($unresolvedNotChecked -gt 0) {
    Write-Host "Not Checked:    $unresolvedNotChecked" -ForegroundColor Yellow
    Write-Host "                (unresolved; each report row names the missing evidence)" -ForegroundColor DarkGray
}
if ($results.NotApplicable -gt 0) {
    Write-Host "Not Applicable: $($results.NotApplicable)" -ForegroundColor DarkGray
    Write-Host "                (declared target unsupported or component absent on this host)" -ForegroundColor DarkGray
}
# Report the same required-scope percentage used by the HTML result bar.
# NotApplicable and authoritatively deliberate exclusions are not required
# live checks; failed and unresolved targets remain in the denominator.
$verifiableTotal = [int]$results.Verified + [int]$results.Failed
Write-Host "Evaluated Live: $verifiableTotal ($($results.Verified) passed, $($results.Failed) failed)" -ForegroundColor $(if ($results.Failed -gt 0) { 'Red' } else { 'White' })
$requiredVerificationCount = [int]$results.Verified + [int]$results.Failed + $unresolvedNotChecked
$verificationPercent = if ($requiredVerificationCount -gt 0) {
    [math]::Round(([int]$results.Verified / $requiredVerificationCount) * 100, 2)
} else { 0 }
$verificationPercentText = $verificationPercent.ToString('0.##', [System.Globalization.CultureInfo]::InvariantCulture)
if ($results.Failed -gt 0) {
    $verificationSuffix = "$($results.Failed) failed"
    if ($unresolvedNotChecked -gt 0) { $verificationSuffix += ", $unresolvedNotChecked unproven" }
    Write-Host "Verification Result: $verificationPercentText% of $requiredVerificationCount required checks passed ($verificationSuffix)" -ForegroundColor Red
}
elseif ($unresolvedNotChecked -gt 0) {
    Write-Host "Verification Result: $verificationPercentText% of $requiredVerificationCount required checks proven ($unresolvedNotChecked unproven)" -ForegroundColor Yellow
}
elseif ($requiredVerificationCount -gt 0) {
    Write-Host "Verification Result: $verificationPercentText% of $requiredVerificationCount required checks passed" -ForegroundColor Green
}
else {
    Write-Host 'Verification Result: no applicable targets required verification' -ForegroundColor DarkGray
}
Write-Host "Duration:       $([math]::Round($results.Duration.TotalSeconds, 1)) seconds" -ForegroundColor White
Write-Host ""

if ($results.Failed -gt 0) {
    Write-Host "Failed Settings by Category:" -ForegroundColor Red
    Write-Host ""

    foreach ($category in $results.FailedSettings) {
        Write-Host "  $($category.Category): $($category.Count) failed" -ForegroundColor Red

        # Always show first 5 details
        foreach ($detail in ($category.Details | Select-Object -First 5)) {
            # Format based on category
            if ($category.Category -eq "Registry") {
                Write-Host "    - $($detail.Path)\$($detail.Name) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "SecurityTemplate") {
                Write-Host "    - [$($detail.Section)] $($detail.Setting) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "AuditPolicies") {
                Write-Host "    - $($detail.Policy) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "ASR") {
                Write-Host "    - $($detail.Rule) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "DNS") {
                Write-Host "    - $($detail.Check) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "Privacy") {
                Write-Host "    - $($detail.Setting) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "AntiAI") {
                Write-Host "    - $($detail.Policy) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "EdgeHardening") {
                Write-Host "    - $($detail.Policy) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
            elseif ($category.Category -eq "AdvancedSecurity") {
                Write-Host "    - $($detail.Setting) | Expected: $($detail.Expected) | Actual: $($detail.Actual)" -ForegroundColor Gray
            }
        }

        # Count the remaining rows from the actual detail list: on fail-closed
        # paths Count carries the declared magnitude while Details holds a
        # single synthetic scope-failure entry.
        $remainingDetailCount = @($category.Details).Count - 5
        if ($remainingDetailCount -gt 0) {
            Write-Host "    ... and $remainingDetailCount more" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

if ($ExportPath) {
    # Use .NET WriteAllText with UTF-8 NO-BOM so the exported report parses cleanly with
    # Python json / jq / Node JSON.parse without BOM-handling workarounds. PS 5.1's bare
    # `Out-File` defaults to ANSI (system codepage) -- worse than BOM in PS 7+.
    $resultsJson = $results | ConvertTo-Json -Depth 10
    $exportEncoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($ExportPath, $resultsJson, $exportEncoding)
    Write-Host "Results exported to: $ExportPath" -ForegroundColor Cyan
}

# ========================================
# GENERATE HTML COMPLIANCE REPORT
# ========================================
Write-Host ""
Write-Host "Generating HTML Compliance Report..." -ForegroundColor Cyan

try {
    # Determine project root (one level up from Tools folder)
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $reportsFolder = Join-Path $projectRoot "Reports"

    # Create Reports folder if it doesn't exist
    if (-not (Test-Path $reportsFolder)) {
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    }

    # Generate timestamped filename
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss-fff"
    $reportNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $reportPrefix = if (-not [bool]$results.AppliedScopeRun) { 'Complete-Hardening' } else { 'Applied-Scope' }
    $htmlFile = Join-Path $reportsFolder "${reportPrefix}_${timestamp}_$reportNonce.html"

    # Generate HTML report (extracted helper for testability -- VCH-INLINE-FUNCTION-DOTSOURCE-SCOPE)
    . (Join-Path $PSScriptRoot 'Private/New-HardeningHtmlReport.ps1')
    New-HardeningHtmlReport -Results $results -OutputFile $htmlFile -RedactComputerName:$RedactComputerName
    if (-not (Test-Path -LiteralPath $htmlFile -PathType Leaf)) {
        throw 'HTML report generator returned without creating the declared report file'
    }
    $reportGenerated = $true

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  HTML COMPLIANCE REPORT GENERATED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Report Location:" -ForegroundColor Cyan
    Write-Host "  $htmlFile" -ForegroundColor White
    Write-Host ""
    Write-Host "Open this file in your browser to view the detailed compliance report." -ForegroundColor Gray
    Write-Host "Result: $($results.Verified) verified, $($results.Failed) failed, $($results.NotChecked) not checked, $($results.NotApplicable) not applicable in a $($results.TotalSettings)-target verification scope ($($results.ProductTargetInventory) product targets)." -ForegroundColor Gray
    Write-Host ""
}
catch {
    $htmlFile = ''
    $reportGenerated = $false
    Write-Host "Warning: Failed to generate HTML report: $_" -ForegroundColor Yellow
}

# Schema 3 also binds the machine contract to the exact configuration bytes
# consumed during a scoped post-Apply run and exposes the intent provenance.
# A standalone live audit has no transaction configuration, so its config hash
# is deliberately empty instead of being guessed from repository defaults.
$guiVerificationResult = [ordered]@{
    schemaVersion = 3
    complete = [bool]$verificationComplete
    total = [int]$results.TotalSettings
    verified = [int]$results.Verified
    failed = [int]$results.Failed
    notChecked = [int]$results.NotChecked
    notCheckedDeliberate = [int]$results.NotCheckedDeliberate
    notApplicable = [int]$results.NotApplicable
    reportGenerated = [bool]$reportGenerated
    reportPath = [string]$htmlFile
    intentReference = [string]$standaloneIntentStatus
    configSha256 = [string]$verificationConfigSha256
}

# Bind report-history status to the same counters as the console/GUI contract.
# A bare HTML file is never success evidence: the adjacent result record pins
# its SHA-256 and verdict. Legacy reports remain readable but unclassified.
if ($reportGenerated) {
    try {
        $reportHash = (Get-FileHash -LiteralPath $htmlFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $reportResult = [ordered]@{
            schemaVersion = 1
            recordType = 'NoIDVerificationReportResult'
            reportFileName = [IO.Path]::GetFileName($htmlFile)
            reportSha256 = $reportHash
            generatedAt = (Get-Date).ToUniversalTime().ToString('o')
            complete = [bool]$guiVerificationResult.complete
            total = [int]$guiVerificationResult.total
            verified = [int]$guiVerificationResult.verified
            failed = [int]$guiVerificationResult.failed
            notChecked = [int]$guiVerificationResult.notChecked
            notCheckedDeliberate = [int]$guiVerificationResult.notCheckedDeliberate
            notApplicable = [int]$guiVerificationResult.notApplicable
        }
        $resultPath = [IO.Path]::ChangeExtension($htmlFile, '.result.json')
        $resultTempPath = "$resultPath.tmp-$([Guid]::NewGuid().ToString('N'))"
        $resultBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ($reportResult | ConvertTo-Json -Compress -Depth 3)
        )
        $resultStream = [IO.FileStream]::new(
            $resultTempPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $resultStream.Write($resultBytes, 0, $resultBytes.Length)
            $resultStream.Flush($true)
        }
        finally { $resultStream.Dispose() }
        [IO.File]::Move($resultTempPath, $resultPath)
    }
    catch {
        Write-Host "Warning: HTML was created, but its machine-readable result binding failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $reportGenerated = $false
        $htmlFile = ''
        $guiVerificationResult.reportGenerated = $false
        $guiVerificationResult.reportPath = ''
    }
}
Write-Output ("NOID_VERIFY_JSON=" + ($guiVerificationResult | ConvertTo-Json -Compress -Depth 3))

}
finally {
    # Measurement is over - completed or aborted - so mutations may proceed.
    # This must run on every exit path: an in-process caller survives a throw
    # and would otherwise keep holding the mutation mutex on its thread.
    if ($script:NoIDVerifierMutationMutexHeld) {
        try { $script:NoIDVerifierMutationMutex.ReleaseMutex() } catch { Write-Verbose "Mutation mutex release failed: $($_.Exception.Message)" }
        $script:NoIDVerifierMutationMutexHeld = $false
    }
    $script:NoIDVerifierMutationMutex.Dispose()
}

# Final status message. A zero-failure subset is not a successful verification
# when the declared scope still contains unresolved targets. Deliberate,
# authoritative exclusions retain their honest NotChecked classification but
# do not make the verdict incomplete.
if ($verificationComplete) {
    Write-Host "[+] VERIFIED: every applicable target has conclusive evidence." -ForegroundColor Green
}
elseif ($results.Failed -eq 0 -and $results.NotChecked -gt 0) {
    if ($unresolvedNotChecked -le 0) {
        Write-Host "[+] VERIFIED: every applicable target is proven or intentionally excluded." -ForegroundColor Green
            Write-Host "    $($results.NotChecked) optional or explicitly preserved target(s) are listed as BY CHOICE (see report)." -ForegroundColor Gray
    }
    else {
        Write-Host "[!] VERIFICATION INCOMPLETE: $unresolvedNotChecked target(s) remain unproven." -ForegroundColor Yellow
        Write-Host "    No mismatch was measured among the $verifiableTotal evaluated live checks, but no" -ForegroundColor Yellow
        Write-Host "    complete compliance verdict is possible without evidence for the remaining scope." -ForegroundColor Yellow
        if ($results.NotCheckedDeliberate -gt 0) {
                Write-Host "    $($results.NotCheckedDeliberate) optional or explicitly preserved target(s) are listed as BY CHOICE (see report)." -ForegroundColor Gray
        }
        Write-Host "    Each unresolved row in the report names the missing evidence." -ForegroundColor Yellow
    }
}
else {
    Write-Host "[-] VERIFICATION FAILED: $($results.Failed) target(s) differ from the required state." -ForegroundColor Red
}

# No exit code and no pipeline verdict here: the NOID_VERIFY_JSON line above is
# the machine contract. A returned boolean prints as a stray True/False line in
# every -File invocation (Pro GUI log panes, standalone console runs), and exit
# would cause output-buffer issues when called from the interactive shell.
