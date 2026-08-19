<#
.SYNOPSIS
    Microsoft Security Baseline for Windows 11 25H2

.DESCRIPTION
    Implements the repository's 425-target profile derived from the Microsoft
    Security Baseline, subject to documented NoID Privacy deviations:
    - 330 Computer Registry policies
    - 5 User Registry policies
    - 67 Security Template settings
    - 23 Advanced Audit Policies

    Auto-detects domain membership and applies appropriate adjustments.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Get the module root path
$ModuleRoot = $PSScriptRoot
$script:SecurityBaselineUserContext = $null

# Dot source all Private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
if (-not (Test-Path -LiteralPath $PrivatePath -PathType Container)) {
    throw "Required SecurityBaseline Private directory is missing: $PrivatePath"
}
Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -File -ErrorAction Stop | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        throw "Failed to import required SecurityBaseline private file '$($_.FullName)': $($_.Exception.Message)"
    }
}

# Dot source all Public functions
$PublicPath = Join-Path $ModuleRoot "Public"
if (-not (Test-Path -LiteralPath $PublicPath -PathType Container)) {
    throw "Required SecurityBaseline Public directory is missing: $PublicPath"
}
Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -File -ErrorAction Stop | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        throw "Failed to import required SecurityBaseline public file '$($_.FullName)': $($_.Exception.Message)"
    }
}

# Export only public functions
Export-ModuleMember -Function Invoke-SecurityBaseline, Restore-SecurityBaseline, Restore-RegistryPolicies
