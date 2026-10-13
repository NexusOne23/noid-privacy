<#
.SYNOPSIS
    Microsoft Security Baseline for Windows 11 26H2

.DESCRIPTION
    Implements the repository's 425-target profile derived from the Microsoft
    Security Baseline, subject to documented NoID Privacy deviations:
    - 330 Computer Registry policies (native firewall format metadata excluded)
    - 5 User Registry policies
    - 67 Security Template settings
    - 23 Advanced Audit Policies

    Applies the same documented target profile on standalone and domain-joined
    systems; no implicit remote-administration compatibility adjustment is made.

.NOTES
    Author: NexusOne23
    Version: 2.2.6
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Get the module root path
$ModuleRoot = $PSScriptRoot

# Shared race-free registry helpers (Core/Runtime.ps1). Loading them here keeps
# the module self-contained when a host imports it without the framework
# dependency bridge (standalone verifier, restore engine, unit tests).
. (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core') 'Runtime.ps1')
. (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core') 'AsrPolicyRuntime.ps1')

$script:SecurityBaselineUserContext = $null

# Dot source all Private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
if (-not (Test-Path -LiteralPath $PrivatePath -PathType Container)) {
    throw "Required SecurityBaseline Private directory is missing: $PrivatePath"
}
foreach ($import in @(Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -File -ErrorAction Stop)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required SecurityBaseline private file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Dot source all Public functions
$PublicPath = Join-Path $ModuleRoot "Public"
if (-not (Test-Path -LiteralPath $PublicPath -PathType Container)) {
    throw "Required SecurityBaseline Public directory is missing: $PublicPath"
}
foreach ($import in @(Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -File -ErrorAction Stop)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required SecurityBaseline public file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Export only public functions
Export-ModuleMember -Function Invoke-SecurityBaseline, Restore-SecurityBaseline, Restore-RegistryPolicies
