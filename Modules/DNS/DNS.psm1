#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Configuration Module for NoID Privacy

.DESCRIPTION
    Provides secure DNS configuration with DNS over HTTPS (DoH) support.
    Supports Cloudflare, Quad9, and AdGuard DNS providers with automatic
    backup and restore capabilities.

.NOTES
    Author: NexusOne23
    Version: 2.2.6
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Module-level variables
$script:ModuleName = "DNS"
$script:ModuleRoot = $PSScriptRoot

# Shared race-free registry helpers (Core/Runtime.ps1). Loading them here keeps
# the module self-contained when a host imports it without the framework
# dependency bridge (standalone verifier, restore engine, unit tests).
. (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core') 'Runtime.ps1')

$PrivatePath = Join-Path $PSScriptRoot 'Private'

# Get module functions
$PublicPath = Join-Path $PSScriptRoot 'Public'
if (-not (Test-Path -LiteralPath $PrivatePath -PathType Container)) { throw "Required DNS Private directory is missing: $PrivatePath" }
if (-not (Test-Path -LiteralPath $PublicPath -PathType Container)) { throw "Required DNS Public directory is missing: $PublicPath" }
$Private = @(Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -File -ErrorAction Stop)
$Public = @(Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -File -ErrorAction Stop)

# Dot source the functions
foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required DNS file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-DNS' -Value 'Invoke-DNSConfiguration' -Force
Export-ModuleMember -Alias 'Invoke-DNS'
