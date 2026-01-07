<#
.SYNOPSIS
    Hardware capability detection for NoID Privacy
    
.DESCRIPTION
    Detects hardware features required for advanced security features
    like VBS, Credential Guard, TPM, etc.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
#>

function Test-VBSCapable {
    <#
    .SYNOPSIS
        Check if system is capable of Virtualization-Based Security
        
    .OUTPUTS
        PSCustomObject with capability details
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $requirements = @{
        UEFI           = Test-UEFIBoot
        SecureBoot     = Test-SecureBootEnabled
        TPM            = (Test-TPMAvailable).Present
        Virtualization = Test-VirtualizationEnabled
        Windows11      = (Get-WindowsVersion).IsWindows11
    }
    
    $allMet = $requirements.UEFI -and $requirements.SecureBoot -and `
        $requirements.TPM -and $requirements.Virtualization -and `
        $requirements.Windows11
    
    return [PSCustomObject]@{
        Capable        = $allMet
        UEFI           = $requirements.UEFI
        SecureBoot     = $requirements.SecureBoot
        TPM            = $requirements.TPM
        Virtualization = $requirements.Virtualization
        Windows11      = $requirements.Windows11
    }
}

function Test-UEFIBoot {
    <#
    .SYNOPSIS
        Check if system is booted in UEFI mode
        
    .OUTPUTS
        Boolean indicating UEFI boot mode
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $firmwareType = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType
        return $firmwareType -eq 'Uefi'
    }
    catch {
        # Fallback method
        try {
            $null = bcdedit /enum "{current}" | Select-String "path.*\\EFI\\"
            return $true
        }
        catch {
            return $false
        }
    }
}

function Get-CPUInfo {
    <#
    .SYNOPSIS
        Get CPU information
        
    .OUTPUTS
        PSCustomObject with CPU details
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        return [PSCustomObject]@{
            Name                  = $cpu.Name
            Manufacturer          = $cpu.Manufacturer
            Cores                 = $cpu.NumberOfCores
            LogicalProcessors     = $cpu.NumberOfLogicalProcessors
            MaxClockSpeed         = $cpu.MaxClockSpeed
            VirtualizationEnabled = $cpu.VirtualizationFirmwareEnabled
            Architecture          = $cpu.Architecture
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to get CPU information" -Module "Hardware" -Exception $_
        return $null
    }
}

function Get-MemoryInfo {
    <#
    .SYNOPSIS
        Get system memory information
        
    .OUTPUTS
        PSCustomObject with memory details
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        return [PSCustomObject]@{
            TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            FreePhysicalMemoryGB  = [math]::Round($os.FreePhysicalMemory / 1MB / 1024, 2)
            TotalVirtualMemoryGB  = [math]::Round($os.TotalVirtualMemorySize / 1MB / 1024, 2)
            FreeVirtualMemoryGB   = [math]::Round($os.FreeVirtualMemory / 1MB / 1024, 2)
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to get memory information" -Module "Hardware" -Exception $_
        return $null
    }
}

function Test-SSDDrive {
    <#
    .SYNOPSIS
        Check if system drive is SSD
        
    .OUTPUTS
        Boolean indicating SSD status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $systemDrive = $env:SystemDrive -replace ':', ''
        $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $systemDrive } | Select-Object -First 1
        
        if ($null -eq $partition) {
            return $false
        }
        
        $disk = Get-Disk -Number $partition.DiskNumber
        
        # MediaType: 3 = HDD, 4 = SSD, 5 = SCM (Storage Class Memory)
        return $disk.MediaType -in @('SSD', 'SCM', '4', '5')
    }
    catch {
        Write-Log -Level WARNING -Message "Unable to detect drive type" -Module "Hardware"
        return $false
    }
}

function Get-WindowsEditionInfo {
    <#
    .SYNOPSIS
        Get Windows edition information
        
    .OUTPUTS
        PSCustomObject with edition details
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        
        # Determine edition type
        $isHome = $os.Caption -match 'Home'
        $isPro = $os.Caption -match 'Pro' -and -not ($os.Caption -match 'Education')
        $isEnterprise = $os.Caption -match 'Enterprise'
        $isEducation = $os.Caption -match 'Education'
        
        # Check for specific features availability
        $supportsCredentialGuard = $isPro -or $isEnterprise -or $isEducation
        $supportsAppLocker = $isEnterprise -or $isEducation
        $supportsBitLocker = -not $isHome
        
        return [PSCustomObject]@{
            Caption                 = $os.Caption
            Version                 = $os.Version
            BuildNumber             = $os.BuildNumber
            IsHome                  = $isHome
            IsPro                   = $isPro
            IsEnterprise            = $isEnterprise
            IsEducation             = $isEducation
            SupportsCredentialGuard = $supportsCredentialGuard
            SupportsAppLocker       = $supportsAppLocker
            SupportsBitLocker       = $supportsBitLocker
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to get Windows edition" -Module "Hardware" -Exception $_
        return $null
    }
}

function Get-HardwareReport {
    <#
    .SYNOPSIS
        Generate comprehensive hardware capability report
        
    .OUTPUTS
        PSCustomObject with complete hardware details
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    return [PSCustomObject]@{
        OS             = Get-WindowsVersion
        Edition        = Get-WindowsEditionInfo
        CPU            = Get-CPUInfo
        Memory         = Get-MemoryInfo
        UEFI           = Test-UEFIBoot
        SecureBoot     = Test-SecureBootEnabled
        TPM            = Test-TPMAvailable
        Virtualization = Test-VirtualizationEnabled
        VBSCapable     = Test-VBSCapable
        SSD            = Test-SSDDrive
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
