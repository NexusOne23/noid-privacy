<#
.SYNOPSIS
    Compatibility wrappers for module function calls

.DESCRIPTION
    Provides wrapper functions to ensure compatibility between module calls
    and core framework functions. Maps old function names to new names.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+
#>

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Wrapper for Test-IsAdministrator

    .DESCRIPTION
        Checks if the current PowerShell session has administrator privileges

    .OUTPUTS
        Boolean indicating administrator status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return Test-IsAdministrator
}

function Test-WindowsVersion {
    <#
    .SYNOPSIS
        Wrapper for Get-WindowsVersion with minimum build check

    .DESCRIPTION
        Checks if Windows version meets minimum requirements

    .PARAMETER MinimumBuild
        Minimum required build number (default: 26100 for Windows 11 24H2)

    .OUTPUTS
        Boolean indicating if version requirement is met
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MinimumBuild = 26100
    )

    $versionInfo = Get-WindowsVersion
    return ($versionInfo.IsSupported -and $versionInfo.BuildNumber -ge $MinimumBuild)
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
