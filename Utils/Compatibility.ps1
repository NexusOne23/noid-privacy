<#
.SYNOPSIS
    Compatibility wrappers for module function calls
    
.DESCRIPTION
    Provides wrapper functions to ensure compatibility between module calls
    and core framework functions. Maps old function names to new names.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
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
        Minimum required build number (default: 22000 for Windows 11)
        
    .OUTPUTS
        Boolean indicating if version requirement is met
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MinimumBuild = 22000
    )
    
    $versionInfo = Get-WindowsVersion
    return ($versionInfo.BuildNumber -ge $MinimumBuild)
}

function New-RegistryBackup {
    <#
    .SYNOPSIS
        Wrapper for Backup-RegistryKey
        
    .DESCRIPTION
        Creates a backup of a registry key before modification
        
    .PARAMETER Path
        Registry path to backup
        
    .PARAMETER BackupId
        Optional backup identifier
        
    .OUTPUTS
        PSCustomObject with backup results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupId
    )
    
    # Ensure a valid backup name is always passed to Backup-RegistryKey
    if (-not $BackupId) {
        $BackupId = "RegistryBackup_{0:yyyyMMdd_HHmmss}" -f (Get-Date)
    }

    return Backup-RegistryKey -KeyPath $Path -BackupName $BackupId
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
