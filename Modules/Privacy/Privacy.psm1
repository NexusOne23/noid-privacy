#Requires -Version 5.1

<#
.SYNOPSIS
    Privacy & Telemetry hardening module loader

.DESCRIPTION
    Loads all Privacy module functions for Windows 11 telemetry control,
    personalization settings and OneDrive/Store configuration with exact BAVR.

    Supports 3 operating modes:
    - MSRecommended: Least-disruptive selected controls without relaxing stricter existing policy (default)
    - Strict: Strong privacy with per-target build/edition applicability; unsupported policies are NotApplicable
    - Paranoid: Hardcore mode (not recommended)

.NOTES
    Module: Privacy
    Version: 2.2.5
    Author: NexusOne23
#>

# Get module root path
$script:ModuleRoot = $PSScriptRoot
$script:PrivacyUserContext = $null

# Import the one canonical decision-bound backup/apply/restore path plus sealed
# service/task helpers. Legacy section setters are deliberately absent so no
# internal caller can bypass the decision-bound BAVR plan.
$privateFunctions = @(
    'Get-PrivacyUserContext',
    'Get-PrivacyTier1PolicyDefinition',
    'Get-PrivacyTier1RestorePolicyDefinitions',
    'Get-PrivacyManagementState',
    'Get-PrivacyRegistryTargets',
    'Get-PrivacyUcpdProtectionState',
    'Get-PrivacyApplicability',
    'Get-PrivacyTargetPlan',
    'Get-PrivacyRuntimeTargetPlan',
    'PrivacyAppxFirewall',
    'Assert-PrivacyRegistrySnapshot',
    'Assert-PrivacyPrestate',
    'PrivacyWindowsSearch',
    'PrivacySearchPolicyNotification',
    'Restore-PrivacyRegistryState',
    'Set-PrivacyRegistryTargets',
    'Backup-PrivacySettings',
    'Disable-TelemetryServices',
    'Disable-TelemetryTasks',
    'Get-PrivacyBloatwareConfig',
    'Get-PrivacyBloatwareInventoryFingerprint',
    'Get-PrivacyTier1AppCatalog',
    'Get-PrivacyTier1AppInventory',
    'Assert-PrivacyTier1AppInventory',
    'Get-PrivacyBloatwareActionLog',
    'Assert-PrivacyBloatwareActionLog',
    'PrivacyUserAppx',
    'Remove-BloatwareApps'
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path (Join-Path $ModuleRoot 'Private') "$function.ps1"
    if (-not (Test-Path -LiteralPath $functionPath -PathType Leaf)) { throw "Required Privacy private file is missing: $functionPath" }
    . $functionPath
}

# Import Test-PrivacyCompliance (located in module root)
$testCompliancePath = Join-Path $ModuleRoot "Test-PrivacyCompliance.ps1"
if (-not (Test-Path -LiteralPath $testCompliancePath -PathType Leaf)) { throw "Required Privacy compliance file is missing: $testCompliancePath" }
. $testCompliancePath

# Import public functions
$publicFunctions = @(
    'Invoke-PrivacyHardening',
    'Get-BloatwareRestoreAssessment',
    'Restore-BloatwareApps'
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path (Join-Path $ModuleRoot 'Public') "$function.ps1"
    if (-not (Test-Path -LiteralPath $functionPath -PathType Leaf)) { throw "Required Privacy public file is missing: $functionPath" }
    . $functionPath
}

# Export public functions + Test-PrivacyCompliance (needed for Invoke-PrivacyHardening verification)
Export-ModuleMember -Function @($publicFunctions + 'Test-PrivacyCompliance')

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-Privacy' -Value 'Invoke-PrivacyHardening' -Force
Export-ModuleMember -Alias 'Invoke-Privacy'
