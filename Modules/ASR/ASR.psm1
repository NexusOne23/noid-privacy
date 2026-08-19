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
    Version: 2.2.5
    Requires: PowerShell 5.1+, Administrator privileges, Windows Defender
#>

# Get the module root path
$ModuleRoot = $PSScriptRoot

# Dot source all Private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
if (-not (Test-Path -LiteralPath $PrivatePath -PathType Container)) {
    throw "Required ASR Private directory is missing: $PrivatePath"
}
Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -File -ErrorAction Stop | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        throw "Failed to import required ASR private file '$($_.FullName)': $($_.Exception.Message)"
    }
}

# Dot source all Public functions
$PublicPath = Join-Path $ModuleRoot "Public"
if (-not (Test-Path -LiteralPath $PublicPath -PathType Container)) {
    throw "Required ASR Public directory is missing: $PublicPath"
}
Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -File -ErrorAction Stop | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        throw "Failed to import required ASR public file '$($_.FullName)': $($_.Exception.Message)"
    }
}

# Export public functions + Test-ASRCompliance (stable standalone compliance surface;
# used internally by Invoke-ASRRules -- the Verify tool keeps its own inline checks)
Export-ModuleMember -Function @('Invoke-ASRRules', 'Test-ASRCompliance')

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-ASR' -Value 'Invoke-ASRRules' -Force
Export-ModuleMember -Alias 'Invoke-ASR'
