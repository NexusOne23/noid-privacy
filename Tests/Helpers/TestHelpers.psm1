#Requires -Version 5.1

<#
.SYNOPSIS
    Helper functions for Pester tests

.DESCRIPTION
    Common mocking functions and test utilities
#>

Set-StrictMode -Version Latest

function New-MockRegistry {
    <#
    .SYNOPSIS
        Creates a mock registry structure for testing
    #>
    param(
        [string]$Path,
        [hashtable]$Properties = @{}
    )
    
    $mockRegistry = [PSCustomObject]@{
        Path = $Path
        Properties = $Properties
    }
    
    return $mockRegistry
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if current session has Administrator privileges
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeTestPath {
    <#
    .SYNOPSIS
        Returns a safe temporary path for testing
    #>
    $tempPath = Join-Path $env:TEMP "NoIDPrivacy-Tests"
    if (-not (Test-Path $tempPath)) {
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
    }
    return $tempPath
}

Export-ModuleMember -Function *
