#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    EdgeHardening Module Loader

.DESCRIPTION
    Loads all private and public functions for the EdgeHardening module.
    Applies the selected Microsoft Edge v139 baseline values plus explicitly
    identified NoID Privacy additions using native PowerShell.

    NO EXTERNAL DEPENDENCIES:
    - No LGPO.exe required
    - Native PowerShell Set-ItemProperty
    - Built-in Windows tools only

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Module variables
$script:ModuleName = "EdgeHardening"
$script:ModuleRoot = $PSScriptRoot

# Discover Private + Public functions dynamically, matching the dynamic loaders in
# SecurityBaseline / ASR / DNS / AdvancedSecurity -- new files are picked up automatically
# without touching the loader. (Privacy and AntiAI deliberately use explicit function
# lists instead; see the rationale in their psm1 loaders.)
$privatePath = Join-Path $PSScriptRoot 'Private'
$publicPath = Join-Path $PSScriptRoot 'Public'
if (-not (Test-Path -LiteralPath $privatePath -PathType Container)) { throw "Required EdgeHardening Private directory is missing: $privatePath" }
if (-not (Test-Path -LiteralPath $publicPath -PathType Container)) { throw "Required EdgeHardening Public directory is missing: $publicPath" }
$Private = @(Get-ChildItem -LiteralPath $privatePath -Filter "*.ps1" -File -ErrorAction Stop)
$Public  = @(Get-ChildItem -LiteralPath $publicPath -Filter "*.ps1" -File -ErrorAction Stop)

foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required EdgeHardening file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Export public functions explicitly (matches every other module's psm1). The psd1
# FunctionsToExport already restricts what Get-Module reports; Export-ModuleMember at the
# psm1 level prevents dot-sourced Private helpers from leaking into the surface.
Export-ModuleMember -Function 'Invoke-EdgeHardening', 'Test-EdgeHardening'

# Module loaded successfully
Write-Verbose "[$script:ModuleName] Module loaded successfully from: $PSScriptRoot"
