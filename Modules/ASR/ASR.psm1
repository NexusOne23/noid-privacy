<#
.SYNOPSIS
    Attack Surface Reduction (ASR) Module

.DESCRIPTION
    Declares 19 Microsoft Defender ASR rules, applies the 18 rules supported on
    Windows 11 clients, and reports the Exchange-server Webshell rule as
    NotApplicable.

    Target-scoped implementation:
    - Exact per-GUID Defender policy prestate for backup and restore
    - Native policy values for application; effective Defender state for verification

.NOTES
    Author: NexusOne23
    Version: 2.2.6
    Requires: PowerShell 5.1+, Administrator privileges, Windows Defender
#>

# Get the module root path
$ModuleRoot = $PSScriptRoot

# Shared race-free registry helpers (Core/Runtime.ps1). Loading them here keeps
# the module self-contained when a host imports it without the framework
# dependency bridge (standalone verifier, restore engine, unit tests).
. (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core') 'Runtime.ps1')
. (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core') 'AsrPolicyRuntime.ps1')

# Dot source all Private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
if (-not (Test-Path -LiteralPath $PrivatePath -PathType Container)) {
    throw "Required ASR Private directory is missing: $PrivatePath"
}
foreach ($import in @(Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -File -ErrorAction Stop)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required ASR private file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Dot source all Public functions
$PublicPath = Join-Path $ModuleRoot "Public"
if (-not (Test-Path -LiteralPath $PublicPath -PathType Container)) {
    throw "Required ASR Public directory is missing: $PublicPath"
}
foreach ($import in @(Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -File -ErrorAction Stop)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required ASR public file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Export the public entry point plus Test-ASRCompliance, which Invoke-ASRRules
# also uses for its post-apply check (the standalone verifier keeps its own checks)
Export-ModuleMember -Function @('Invoke-ASRRules', 'Test-ASRCompliance')

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-ASR' -Value 'Invoke-ASRRules' -Force
Export-ModuleMember -Alias 'Invoke-ASR'
