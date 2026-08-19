#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AntiAI Module Loader

.DESCRIPTION
    Applies and exactly verifies the module's declared reversible Windows and
    Edge AI policy targets. Runtime effectiveness is reported separately for
    edition/build-limited policies; the current Copilot MSIX app is not claimed
    as blocked by the deprecated legacy Copilot policy.

.NOTES
    Module: AntiAI
    Version: 2.2.5
    Author: NexusOne23
#>

Set-StrictMode -Version Latest

# Get module root path
$script:ModuleRoot = $PSScriptRoot
$script:AntiAIUserContext = $null

# Import private functions
$privateFunctions = @(
    'Get-AntiAIUserContext'     # Interactive user's loaded hive, even after over-the-shoulder elevation
    'Get-AntiAIRegistryTargets' # Canonical config-derived registry target set
    'Get-AntiAIDeclaredPolicyCount'
    'Get-AntiAIApplicability'   # OS/edition/runtime scope, separate from registry success
    'Get-AntiAITargetPlan'      # Per-target build/edition/product applicability
    'Get-AntiAIIntentTargetPlan' # Apply-time identity partition without live scope substitution
    'Assert-AntiAIRegistrySnapshot'
    'Assert-AntiAIPrestate'
    'Set-AntiAIRegistryValue'   # Exact type/value writer with readback
    'Set-AntiAIRegistryTargets'
    'Restore-AntiAIRegistryState'
    'Test-AntiAICompliance'
    'Disable-CopilotURIHandlers'
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path (Join-Path $script:ModuleRoot 'Private') "$function.ps1"
    if (-not (Test-Path -LiteralPath $functionPath -PathType Leaf)) {
        throw "Required AntiAI function file is missing: $functionPath"
    }
    . $functionPath
}

# Import public functions
$publicFunctions = @(
    'Invoke-AntiAI'
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path (Join-Path $script:ModuleRoot 'Public') "$function.ps1"
    if (-not (Test-Path -LiteralPath $functionPath -PathType Leaf)) {
        throw "Required AntiAI public function file is missing: $functionPath"
    }
    . $functionPath
}

# Export public functions + Test-AntiAICompliance (needed for Invoke-AntiAI verification)
Export-ModuleMember -Function @(
    $publicFunctions + 'Test-AntiAICompliance' + 'Get-AntiAITargetPlan' + 'Get-AntiAIIntentTargetPlan'
)
