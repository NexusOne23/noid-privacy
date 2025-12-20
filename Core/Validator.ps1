<#
.SYNOPSIS
    System validation for NoID Privacy Framework
    
.DESCRIPTION
    Provides pre-execution validation checks and post-execution verification
    to ensure system safety and compliance.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.1
    Requires: PowerShell 5.1+
#>

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validate all system prerequisites before hardening
        
    .OUTPUTS
        PSCustomObject with validation results
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    Write-Log -Level INFO -Message "Starting prerequisite validation" -Module "Validator"
    
    $result = [PSCustomObject]@{
        Success = $true
        Errors = @()
        Warnings = @()
        SystemInfo = $null
    }
    
    # Check 1: Administrator privileges
    if (-not (Test-IsAdministrator)) {
        Write-Log -Level ERROR -Message "Administrator privileges required" -Module "Validator"
        $result.Success = $false
        $result.Errors += "Administrator privileges required"
    }
    else {
        Write-Log -Level SUCCESS -Message "Administrator check: PASSED" -Module "Validator"
    }
    
    # Check 2: Windows version
    $osInfo = Get-WindowsVersion
    if ($osInfo.IsSupported) {
        Write-Log -Level SUCCESS -Message "Windows version check: PASSED ($($osInfo.Version))" -Module "Validator"
    }
    else {
        Write-Log -Level ERROR -Message "Unsupported Windows version: $($osInfo.Version)" -Module "Validator"
        $result.Success = $false
        $result.Errors += "Unsupported Windows version: $($osInfo.Version)"
    }
    
    # Check 3: Disk space
    $diskSpace = Get-AvailableDiskSpace
    if ($diskSpace -gt 500MB) {
        Write-Log -Level SUCCESS -Message "Disk space check: PASSED ($([math]::Round($diskSpace/1MB, 2)) MB available)" -Module "Validator"
    }
    else {
        Write-Log -Level WARNING -Message "Low disk space: $([math]::Round($diskSpace/1MB, 2)) MB" -Module "Validator"
        $result.Warnings += "Low disk space: $([math]::Round($diskSpace/1MB, 2)) MB"
    }
    
    # Check 4: PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-Log -Level SUCCESS -Message "PowerShell version check: PASSED ($($PSVersionTable.PSVersion))" -Module "Validator"
    }
    else {
        Write-Log -Level ERROR -Message "PowerShell 5.1 or higher required" -Module "Validator"
        $result.Success = $false
        $result.Errors += "PowerShell 5.1 or higher required (found: $($PSVersionTable.PSVersion))"
    }
    
    # Get system info
    $result.SystemInfo = Get-SystemInfo
    
    if ($result.Success) {
        Write-Log -Level SUCCESS -Message "All prerequisite checks passed" -Module "Validator"
    }
    else {
        Write-Log -Level ERROR -Message "One or more prerequisite checks failed" -Module "Validator"
    }
    
    return $result
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Check if script is running with administrator privileges
        
    .OUTPUTS
        Boolean indicating administrator status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsVersion {
    <#
    .SYNOPSIS
        Get Windows version information
        
    .OUTPUTS
        PSCustomObject with version details and support status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = [int]$os.BuildNumber
    
    # Windows 11 build numbers
    # 22000 = 21H2, 22621 = 22H2, 22631 = 23H2, 26100 = 24H2, 26200 = 25H2
    $isWindows11 = $buildNumber -ge 22000
    $isSupported = $buildNumber -ge 26100  # 24H2 or newer required
    
    $versionName = switch ($buildNumber) {
        { $_ -ge 26200 } { "Windows 11 25H2"; break }
        { $_ -ge 26100 } { "Windows 11 24H2"; break }
        { $_ -ge 22631 } { "Windows 11 23H2"; break }
        { $_ -ge 22621 } { "Windows 11 22H2"; break }
        { $_ -ge 22000 } { "Windows 11 21H2"; break }
        default { "Windows $($os.Version)" }
    }
    
    return [PSCustomObject]@{
        Version = $versionName
        BuildNumber = $buildNumber
        IsWindows11 = $isWindows11
        IsSupported = $isSupported
        Edition = $os.Caption
        Architecture = $os.OSArchitecture
    }
}

function Get-AvailableDiskSpace {
    <#
    .SYNOPSIS
        Get available disk space on system drive
        
    .OUTPUTS
        Int64 representing available bytes
    #>
    [CmdletBinding()]
    [OutputType([Int64])]
    param()
    
    $systemDrive = $env:SystemDrive
    $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    
    return $drive.FreeSpace
}

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
        Test internet connectivity
        
    .OUTPUTS
        Boolean indicating connectivity status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '')]
    param()
    
    try {
        # Using Google DNS (8.8.8.8) - intentional for internet connectivity check
        $response = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction Stop
        return $response
    }
    catch {
        return $false
    }
}

function Test-TPMAvailable {
    <#
    .SYNOPSIS
        Check if TPM 2.0 is available
        
    .OUTPUTS
        PSCustomObject with TPM information
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        
        if ($null -eq $tpm) {
            return [PSCustomObject]@{
                Present = $false
                Version = "N/A"
                Enabled = $false
                Activated = $false
            }
        }
        
        return [PSCustomObject]@{
            Present = $tpm.TpmPresent
            Version = if ($tpm.ManufacturerVersion) { $tpm.ManufacturerVersion } else { "2.0" }
            Enabled = $tpm.TpmEnabled
            Activated = $tpm.TpmActivated
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Unable to check TPM status: $_" -Module "Validator"
        return [PSCustomObject]@{
            Present = $false
            Version = "Unknown"
            Enabled = $false
            Activated = $false
        }
    }
}

function Test-SecureBootEnabled {
    <#
    .SYNOPSIS
        Check if Secure Boot is enabled
        
    .OUTPUTS
        Boolean indicating Secure Boot status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        return $secureBoot
    }
    catch {
        Write-Log -Level WARNING -Message "Unable to check Secure Boot status (may not be UEFI): $_" -Module "Validator"
        return $false
    }
}

function Test-VirtualizationEnabled {
    <#
    .SYNOPSIS
        Check if CPU virtualization is enabled
        
    .OUTPUTS
        Boolean indicating virtualization status
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor
        
        # Check for Intel VT-x or AMD-V
        $vmxEnabled = $cpu.VirtualizationFirmwareEnabled
        
        return $vmxEnabled
    }
    catch {
        Write-Log -Level WARNING -Message "Unable to check virtualization status: $_" -Module "Validator"
        return $false
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Get comprehensive system information
        
    .OUTPUTS
        PSCustomObject with detailed system information
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $osInfo = Get-WindowsVersion
    $tpmInfo = Test-TPMAvailable
    $secureBoot = Test-SecureBootEnabled
    $virtualization = Test-VirtualizationEnabled
    $isAdmin = Test-IsAdministrator
    $diskSpace = Get-AvailableDiskSpace
    $internet = Test-InternetConnectivity
    
    return [PSCustomObject]@{
        OS = $osInfo
        TPM = $tpmInfo
        SecureBoot = $secureBoot
        Virtualization = $virtualization
        IsAdministrator = $isAdmin
        DiskSpaceAvailable = $diskSpace
        InternetConnected = $internet
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Test-DomainJoined {
    <#
    .SYNOPSIS
        Check if system is joined to an Active Directory domain
        
    .DESCRIPTION
        Detects if the system is domain-joined and warns about potential
        Group Policy conflicts with local hardening settings.
        
    .PARAMETER Interactive
        If set, prompts user to confirm continuation on domain-joined systems
        
    .OUTPUTS
        PSCustomObject with domain status information
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$Interactive
    )
    
    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $isDomainJoined = $computerSystem.PartOfDomain
        
        $result = [PSCustomObject]@{
            IsDomainJoined = $isDomainJoined
            DomainName = if ($isDomainJoined) { $computerSystem.Domain } else { "N/A" }
            Workgroup = if (-not $isDomainJoined) { $computerSystem.Workgroup } else { "N/A" }
            UserConfirmed = $false
        }
        
        if ($isDomainJoined) {
            Write-Log -Level WARNING -Message "System is domain-joined: $($computerSystem.Domain)" -Module "Validator"
            
            if ($Interactive) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  WARNING: DOMAIN-JOINED SYSTEM" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "This system is joined to domain: " -NoNewline -ForegroundColor White
                Write-Host "$($computerSystem.Domain)" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "IMPORTANT CONSIDERATIONS:" -ForegroundColor Red
                Write-Host "  - Domain Group Policies will override local policies" -ForegroundColor Yellow
                Write-Host "  - GPO refresh occurs every 90 minutes" -ForegroundColor Yellow
                Write-Host "  - Some hardening may be reset automatically" -ForegroundColor Yellow
                Write-Host "  - Coordinate with AD team before proceeding" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "RECOMMENDED FOR DOMAIN ENVIRONMENTS:" -ForegroundColor Cyan
                Write-Host "  - Integrate these settings into Domain GPOs instead" -ForegroundColor White
                Write-Host "  - Use this tool only for testing/standalone systems" -ForegroundColor White
                Write-Host ""
                
                $continue = Read-Host "Do you want to continue anyway? (yes/no)"
                
                if ($continue -ne "yes") {
                    Write-Log -Level INFO -Message "User cancelled due to domain-joined warning" -Module "Validator"
                    Write-Host ""
                    Write-Host "Operation cancelled by user." -ForegroundColor Gray
                    Write-Host ""
                    exit 1
                }
                
                $result.UserConfirmed = $true
                Write-Log -Level INFO -Message "User confirmed continuation on domain-joined system" -Module "Validator"
            }
        }
        else {
            Write-Log -Level INFO -Message "System is standalone (workgroup: $($computerSystem.Workgroup))" -Module "Validator"
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to check domain status: $_" -Module "Validator" -Exception $_.Exception
        return [PSCustomObject]@{
            IsDomainJoined = $false
            DomainName = "Error"
            Workgroup = "Error"
            UserConfirmed = $false
        }
    }
}

function Confirm-SystemBackup {
    <#
    .SYNOPSIS
        Non-interactive system backup recommendation
        
    .DESCRIPTION
        Historically this function displayed an interactive prompt asking the
        user to confirm that a full system backup exists before proceeding.
        For modern CLI and GUI workflows this interaction is removed to avoid
        blocking automation. The function now simply logs that a backup is
        recommended and returns a confirmation object.
        
    .PARAMETER Force
        Retained for backwards compatibility. No longer changes behaviour.
        
    .OUTPUTS
        PSCustomObject with backup confirmation status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Log -Level INFO -Message "Backup recommendation: non-interactive confirmation (no prompt shown)" -Module "Validator"

    $result = [PSCustomObject]@{
        UserConfirmed    = $true
        BackupRecommended = $true
    }

    return $result
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
