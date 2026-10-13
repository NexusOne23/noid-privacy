#Requires -Version 5.1
<#
.SYNOPSIS
    Read the current ASR, Windows edition and device-management prerequisites.
.DESCRIPTION
    Does not apply hardening, create backups, change policies or contact a server.
    CloudProtection describes configuration, not live cloud connectivity.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Core/Runtime.ps1')
Assert-NoIDPowerShellRuntime
function Write-Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Engine-local logging sink keeps the read-only JSON contract clean.')]
    [CmdletBinding()]
    param($Level, $Message, $Module)
    $null = $Level, $Message, $Module
}
. (Join-Path $PSScriptRoot 'Core/Readiness.ps1')
Get-NoIDHardeningReadiness | ConvertTo-Json -Depth 4 -Compress
