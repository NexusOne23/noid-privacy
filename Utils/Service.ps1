<#
.SYNOPSIS
    Service management utilities for NoID Privacy
    
.DESCRIPTION
    Provides safe service manipulation functions with automatic
    backup and validation.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
#>

function Set-ServiceStartupType {
    <#
    .SYNOPSIS
        Safely change service startup type with backup
        
    .PARAMETER ServiceName
        Name of the service
        
    .PARAMETER StartupType
        Startup type (Automatic, Manual, Disabled)
        
    .PARAMETER BackupName
        Optional backup name
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Automatic", "Manual", "Disabled")]
        [string]$StartupType,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    try {
        # Verify service exists (throws if not found)
        $null = Get-Service -Name $ServiceName -ErrorAction Stop
        
        # Create backup if requested
        if ($BackupName) {
            Backup-ServiceConfiguration -ServiceName $ServiceName -BackupName $BackupName | Out-Null
        }
        
        # Set startup type
        Set-Service -Name $ServiceName -StartupType $StartupType -ErrorAction Stop
        
        Write-Log -Level SUCCESS -Message "Service '$ServiceName' startup type set to: $StartupType" -Module "Service"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set service startup type: $ServiceName" -Module "Service" -Exception $_
        return $false
    }
}

function Stop-ServiceSafely {
    <#
    .SYNOPSIS
        Safely stop a service
        
    .PARAMETER ServiceName
        Name of the service
        
    .PARAMETER Force
        Force stop even if dependent services exist
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        if ($service.Status -eq 'Stopped') {
            Write-Log -Level INFO -Message "Service '$ServiceName' is already stopped" -Module "Service"
            return $true
        }
        
        if ($Force) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        else {
            Stop-Service -Name $ServiceName -ErrorAction Stop
        }
        
        Write-Log -Level SUCCESS -Message "Service '$ServiceName' stopped" -Module "Service"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to stop service: $ServiceName" -Module "Service" -Exception $_
        return $false
    }
}

function Disable-ServiceSafely {
    <#
    .SYNOPSIS
        Safely disable a service (set to disabled and stop)
        
    .PARAMETER ServiceName
        Name of the service
        
    .PARAMETER BackupName
        Optional backup name
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    try {
        # Verify service exists
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        # Create backup if requested
        if ($BackupName) {
            Backup-ServiceConfiguration -ServiceName $ServiceName -BackupName $BackupName | Out-Null
        }
        
        # Stop service if running
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Log -Level INFO -Message "Service '$ServiceName' stopped" -Module "Service"
        }
        
        # Set to disabled
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
        
        Write-Log -Level SUCCESS -Message "Service '$ServiceName' disabled" -Module "Service"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable service: $ServiceName" -Module "Service" -Exception $_
        return $false
    }
}

function Test-ServiceExists {
    <#
    .SYNOPSIS
        Check if a service exists
        
    .PARAMETER ServiceName
        Name of the service
        
    .OUTPUTS
        Boolean indicating existence
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )
    
    try {
        $null = Get-Service -Name $ServiceName -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-ServiceStatus {
    <#
    .SYNOPSIS
        Get detailed service status information
        
    .PARAMETER ServiceName
        Name of the service
        
    .OUTPUTS
        PSCustomObject with service details or $null if not found
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $serviceWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        
        return [PSCustomObject]@{
            Name        = $service.Name
            DisplayName = $service.DisplayName
            Status      = $service.Status
            StartType   = $service.StartType
            StartMode   = $serviceWmi.StartMode
            PathName    = $serviceWmi.PathName
            Description = $serviceWmi.Description
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Service not found: $ServiceName" -Module "Service"
        return $null
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
