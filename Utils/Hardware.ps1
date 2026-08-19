<#
.SYNOPSIS
    Hardware capability detection for NoID Privacy

.DESCRIPTION
    Detects hardware features required for advanced security features
    like VBS, Credential Guard, TPM, etc.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
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

    $secureBootStatus = Get-SecureBootStatus
    $tpmStatus = Test-TPMAvailable
    $virtualizationStatus = Get-VirtualizationStatus
    $requirements = @{
        UEFI           = Test-UEFIBoot
        SecureBoot     = $secureBootStatus.QuerySucceeded -and [bool]$secureBootStatus.Enabled
        TPM20          = $tpmStatus.QuerySucceeded -and $tpmStatus.SpecQuerySucceeded -and [bool]$tpmStatus.IsTpm20
        Virtualization = $virtualizationStatus.QuerySucceeded -and [bool]$virtualizationStatus.FirmwareEnabled
        VMExtensions   = $virtualizationStatus.QuerySucceeded -and [bool]$virtualizationStatus.VMMonitorModeExtensions
        SLAT           = $virtualizationStatus.QuerySucceeded -and [bool]$virtualizationStatus.SecondLevelAddressTranslation
        Windows11      = (Get-WindowsVersion).IsWindows11
    }

    # Complete modern Windows 11 VBS hardware profile for this framework,
    # not merely a claim that one individual VBS-backed feature can start.
    $allMet = $requirements.UEFI -and $requirements.SecureBoot -and `
        $requirements.TPM20 -and $requirements.Virtualization -and `
        $requirements.VMExtensions -and $requirements.SLAT -and `
        $requirements.Windows11

    return [PSCustomObject]@{
        Capable        = $allMet
        UEFI           = $requirements.UEFI
        SecureBoot     = $requirements.SecureBoot
        TPM20          = $requirements.TPM20
        Virtualization = $requirements.Virtualization
        VMExtensions   = $requirements.VMExtensions
        SLAT           = $requirements.SLAT
        Windows11      = $requirements.Windows11
        SecureBootStatus = $secureBootStatus
        TPMStatus      = $tpmStatus
        VirtualizationStatus = $virtualizationStatus
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
        # Locale-independent fallback: $env:firmware_type is set by Windows on boot to
        # "UEFI" or "Legacy" (or empty in containers). Avoids the previous bcdedit text
        # probe whose `path` label was localized on non-English Windows.
        try {
            if ($env:firmware_type) {
                return $env:firmware_type -eq 'UEFI'
            }
            # Secondary fallback: the SecureBoot\State key is only present on UEFI systems.
            return Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
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
        Write-Log -Level ERROR -Message "Failed to get CPU information" -Module "Hardware" -Exception $_.Exception
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
            # Win32_OperatingSystem reports these three values in KiB. Convert
            # units explicitly; dividing by 1MB and then by 1024 made the old
            # result 1024 times too small.
            FreePhysicalMemoryGB  = [math]::Round(([double]$os.FreePhysicalMemory * 1KB) / 1GB, 2)
            TotalVirtualMemoryGB  = [math]::Round(([double]$os.TotalVirtualMemorySize * 1KB) / 1GB, 2)
            FreeVirtualMemoryGB   = [math]::Round(([double]$os.FreeVirtualMemory * 1KB) / 1GB, 2)
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to get memory information" -Module "Hardware" -Exception $_.Exception
        return $null
    }
}

function Get-NoIDPartitionByDriveLetter {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [char]$DriveLetter
    )

    return @(Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop)
}

function Get-NoIDDiskForPartition {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Partition
    )

    return @(Get-Disk -Partition $Partition -ErrorAction Stop)
}

function Get-NoIDVirtualDisk {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @(Get-VirtualDisk -ErrorAction Stop)
}

function Get-NoIDDiskForVirtualDisk {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$VirtualDisk
    )

    return @(Get-Disk -VirtualDisk $VirtualDisk -ErrorAction Stop)
}

function Get-NoIDPhysicalDisk {
    <#
    .SYNOPSIS
        Isolate the Storage cmdlet boundary used by physical-media detection.

    .DESCRIPTION
        Pester cannot reliably generate proxies for the Storage CDXML cmdlets
        on every Windows build because their generated parameter types are not
        normal PowerShell type names. These wrappers keep the production calls
        explicit and independently mockable without changing semantics.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [object]$VirtualDisk
    )

    if ($PSBoundParameters.ContainsKey('VirtualDisk')) {
        return @(Get-PhysicalDisk -VirtualDisk $VirtualDisk -ErrorAction Stop)
    }
    return @(Get-PhysicalDisk -ErrorAction Stop)
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
        $partitions = @(Get-NoIDPartitionByDriveLetter -DriveLetter $systemDrive)

        if ($partitions.Count -ne 1) {
            Write-Log -Level WARNING -Message "System-drive partition lookup returned $($partitions.Count) results" -Module "Hardware"
            return $false
        }

        $disks = @(Get-NoIDDiskForPartition -Partition $partitions[0])
        if ($disks.Count -ne 1) {
            Write-Log -Level WARNING -Message "System-drive disk lookup returned $($disks.Count) results" -Module "Hardware"
            return $false
        }

        # MediaType belongs to MSFT_PhysicalDisk, not MSFT_Disk. Resolve the
        # physical backing media by VirtualDisk association for Storage Spaces,
        # otherwise by stable UniqueId with DeviceId as a last standard-disk
        # fallback. A mixed or unspecified backing set is not proven SSD.
        $disk = $disks[0]
        $physicalDisks = @()
        if ([int]$disk.BusType -eq 16) {
            foreach ($virtualDisk in @(Get-NoIDVirtualDisk)) {
                $associatedDisks = @(Get-NoIDDiskForVirtualDisk -VirtualDisk $virtualDisk)
                if (@($associatedDisks | Where-Object { [int]$_.Number -eq [int]$disk.Number }).Count -eq 1) {
                    $physicalDisks = @(Get-NoIDPhysicalDisk -VirtualDisk $virtualDisk)
                    break
                }
            }
        }
        else {
            $allPhysicalDisks = @(Get-NoIDPhysicalDisk)
            if (-not [string]::IsNullOrWhiteSpace([string]$disk.UniqueId)) {
                $physicalDisks = @($allPhysicalDisks | Where-Object {
                        -not [string]::IsNullOrWhiteSpace([string]$_.UniqueId) -and
                        ([string]$_.UniqueId).Trim().Equals(([string]$disk.UniqueId).Trim(), [StringComparison]::OrdinalIgnoreCase)
                    })
            }
            if ($physicalDisks.Count -eq 0) {
                $physicalDisks = @($allPhysicalDisks | Where-Object { [int]$_.DeviceId -eq [int]$disk.Number })
            }
        }

        if ($physicalDisks.Count -eq 0) {
            Write-Log -Level WARNING -Message 'System-drive physical backing media could not be resolved' -Module 'Hardware'
            return $false
        }
        $mediaTypes = @($physicalDisks | ForEach-Object { [int]$_.MediaType })
        return @($mediaTypes | Where-Object { $_ -notin @(4, 5) }).Count -eq 0
    }
    catch {
        Write-Log -Level WARNING -Message "Unable to detect drive type" -Module "Hardware" -Exception $_.Exception
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
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $windows = Get-WindowsVersion
        $sku = [int]$os.OperatingSystemSKU
        $editionId = [string]$windows.Edition

        # OperatingSystemSKU uses the documented GetProductInfo PRODUCT_* IDs
        # and is stable across display languages. EditionID is a non-localized
        # registry fallback for a future/unknown SKU; Caption is display only.
        $homeSkus = @(2, 3, 5, 26, 98, 99, 100, 101)
        $proSkus = @(6, 16, 48, 49, 103, 161, 162, 164)
        $enterpriseSkus = @(4, 27, 70, 72, 84, 125, 126, 129, 130, 175)
        $educationSkus = @(121, 122)
        $iotEnterpriseSkus = @(188, 191)

        $editionFamily = if ($sku -in $homeSkus) { 'Home' }
            elseif ($sku -in $proSkus) { 'Professional' }
            elseif ($sku -in $enterpriseSkus) { 'Enterprise' }
            elseif ($sku -in $educationSkus) { 'Education' }
            elseif ($sku -in $iotEnterpriseSkus) { 'IoTEnterprise' }
            elseif ($editionId -match '^Core') { 'Home' }
            elseif ($editionId -match '^Professional') { 'Professional' }
            elseif ($editionId -match '^Enterprise') { 'Enterprise' }
            elseif ($editionId -match '^Education') { 'Education' }
            elseif ($editionId -match '^IoTEnterprise') { 'IoTEnterprise' }
            else { 'Unknown' }

        $isHome = $editionFamily -eq 'Home'
        $isPro = $editionFamily -eq 'Professional'
        $isEnterprise = $editionFamily -eq 'Enterprise'
        $isEducation = $editionFamily -eq 'Education'
        $isIoTEnterprise = $editionFamily -eq 'IoTEnterprise'

        # Current Microsoft licensing: Credential Guard is licensed for
        # Enterprise/Education, not Pro/Pro Education. AppLocker enforcement is
        # technically supported on every Windows 11 edition after KB5024351,
        # while current licensing tables reserve the named AppLocker entitlement
        # for Enterprise/Education. Expose both facts instead of conflating them.
        $supportsCredentialGuard = $isEnterprise -or $isEducation
        $supportsAppLocker = [bool]$windows.IsWindows11
        $appLockerLicensed = $isEnterprise -or $isEducation
        $supportsBitLocker = $isPro -or $isEnterprise -or $isEducation -or $isIoTEnterprise

        return [PSCustomObject]@{
            Caption                 = $os.Caption
            Version                 = $os.Version
            BuildNumber             = $os.BuildNumber
            EditionID               = $editionId
            EditionFamily           = $editionFamily
            OperatingSystemSKU      = $sku
            IsHome                  = $isHome
            IsPro                   = $isPro
            IsEnterprise            = $isEnterprise
            IsEducation             = $isEducation
            IsIoTEnterprise         = $isIoTEnterprise
            SupportsCredentialGuard = $supportsCredentialGuard
            SupportsAppLocker       = $supportsAppLocker
            AppLockerLicensed       = $appLockerLicensed
            SupportsBitLocker       = $supportsBitLocker
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to get Windows edition" -Module "Hardware" -Exception $_.Exception
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
        SecureBoot     = Get-SecureBootStatus
        TPM            = Test-TPMAvailable
        Virtualization = Get-VirtualizationStatus
        VBSCapable     = Test-VBSCapable
        SSD            = Test-SSDDrive
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
