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
    Author: NoID Privacy
    Version: 2.2.1
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Module-level variables
$script:ModuleName = "DNS"
$script:ModuleRoot = $PSScriptRoot
$PrivatePath = "$PSScriptRoot\Private"

# Get module functions
$Private = @(Get-ChildItem -Path $PrivatePath -Filter "*.ps1" -ErrorAction SilentlyContinue)
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public" -Filter "*.ps1" -ErrorAction SilentlyContinue)

# Dot source the functions
foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Host "ERROR: Failed to import function $($import.FullName): $_" -ForegroundColor Red
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-DNS' -Value 'Invoke-DNSConfiguration' -Force
Export-ModuleMember -Alias 'Invoke-DNS'
