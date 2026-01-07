<#
.SYNOPSIS
    Dependency checking utilities for NoID Privacy
    
.DESCRIPTION
    Provides functions to check for required external tools and dependencies
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
#>

function Test-CommandExists {
    <#
    .SYNOPSIS
        Check if a command/executable exists
        
    .PARAMETER Command
        Command or executable name to check
        
    .OUTPUTS
        Boolean indicating existence
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-SecEditAvailable {
    <#
    .SYNOPSIS
        Check if secedit.exe is available
        
    .DESCRIPTION
        Verifies secedit.exe exists (required for Security Baseline module)
        
    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        Available = $false
        Path      = $null
        Version   = $null
        Error     = $null
    }
    
    try {
        # secedit.exe is typically in System32
        $seceditPath = Join-Path $env:SystemRoot "System32\secedit.exe"
        
        if (Test-Path $seceditPath) {
            $result.Available = $true
            $result.Path = $seceditPath
            
            # Try to get version
            try {
                $versionInfo = (Get-Item $seceditPath).VersionInfo
                $result.Version = $versionInfo.FileVersion
            }
            catch {
                $result.Version = "Unknown"
            }
        }
        else {
            $result.Error = "secedit.exe not found at expected location: $seceditPath"
        }
    }
    catch {
        $result.Error = "Failed to check for secedit.exe: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-AuditPolAvailable {
    <#
    .SYNOPSIS
        Check if auditpol.exe is available
        
    .DESCRIPTION
        Verifies auditpol.exe exists (required for Security Baseline module)
        
    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        Available = $false
        Path      = $null
        Version   = $null
        Error     = $null
    }
    
    try {
        # auditpol.exe is typically in System32
        $auditpolPath = Join-Path $env:SystemRoot "System32\auditpol.exe"
        
        if (Test-Path $auditpolPath) {
            $result.Available = $true
            $result.Path = $auditpolPath
            
            # Try to get version
            try {
                $versionInfo = (Get-Item $auditpolPath).VersionInfo
                $result.Version = $versionInfo.FileVersion
            }
            catch {
                $result.Version = "Unknown"
            }
        }
        else {
            $result.Error = "auditpol.exe not found at expected location: $auditpolPath"
        }
    }
    catch {
        $result.Error = "Failed to check for auditpol.exe: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-WindowsDefenderAvailable {
    <#
    .SYNOPSIS
        Check if Windows Defender is available and running
        
    .DESCRIPTION
        Verifies Windows Defender service status (required for ASR module)
        
    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        Available      = $false
        ServiceRunning = $false
        ServiceName    = "WinDefend"
        Error          = $null
    }
    
    try {
        $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        
        if ($defenderService) {
            $result.Available = $true
            $result.ServiceRunning = ($defenderService.Status -eq "Running")
            
            if (-not $result.ServiceRunning) {
                $result.Error = "Windows Defender service exists but is not running (Status: $($defenderService.Status))"
            }
        }
        else {
            $result.Error = "Windows Defender service (WinDefend) not found"
        }
    }
    catch {
        $result.Error = "Failed to check Windows Defender: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-AllDependencies {
    <#
    .SYNOPSIS
        Check all required dependencies for NoID Privacy
        
    .DESCRIPTION
        Performs comprehensive dependency check for all modules
        
    .OUTPUTS
        PSCustomObject with all dependency statuses
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        AllAvailable     = $true
        SecurityBaseline = @{
            secedit  = $null
            auditpol = $null
        }
        ASR              = @{
            defender = $null
        }
        MissingCritical  = @()
        MissingOptional  = @()
    }
    
    # Check secedit.exe (CRITICAL for SecurityBaseline)
    $result.SecurityBaseline.secedit = Test-SecEditAvailable
    if (-not $result.SecurityBaseline.secedit.Available) {
        $result.AllAvailable = $false
        $result.MissingCritical += "secedit.exe (required for Security Baseline)"
    }
    
    # Check auditpol.exe (CRITICAL for SecurityBaseline)
    $result.SecurityBaseline.auditpol = Test-AuditPolAvailable
    if (-not $result.SecurityBaseline.auditpol.Available) {
        $result.AllAvailable = $false
        $result.MissingCritical += "auditpol.exe (required for Security Baseline)"
    }
    
    # NOTE: LGPO.exe check removed - v2.0 SecurityBaseline is fully self-contained
    
    # Check Windows Defender (CRITICAL for ASR)
    $result.ASR.defender = Test-WindowsDefenderAvailable
    if (-not $result.ASR.defender.Available -or -not $result.ASR.defender.ServiceRunning) {
        $result.AllAvailable = $false
        $result.MissingCritical += "Windows Defender (required for ASR module)"
    }
    
    return $result
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
