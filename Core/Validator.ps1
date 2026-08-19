<#
.SYNOPSIS
    System validation for NoID Privacy Framework

.DESCRIPTION
    Provides pre-execution validation checks and post-execution verification
    to ensure system safety and compliance.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
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
        Success    = $true
        Errors     = @()
        Warnings   = @()
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
        if ($osInfo.SupportLevel -eq 'Experimental') {
            $previewWarning = "$($osInfo.Version) is recognized only as an Experimental Preview and is currently not runtime-validated or release-approved; preview policies and behavior can change"
            Write-Log -Level WARNING -Message $previewWarning -Module 'Validator'
            $result.Warnings += $previewWarning
        }
    }
    else {
        Write-Log -Level ERROR -Message "Unsupported Windows version: $($osInfo.Version)" -Module "Validator"
        $result.Success = $false
        $result.Errors += "Unsupported Windows version: $($osInfo.Version)"
    }

    # Check 3: Disk space
    $diskSpace = Get-AvailableDiskSpace
    if ($diskSpace -gt 500MB) {
        Write-Log -Level SUCCESS -Message "Disk space check: PASSED ($([math]::Round($diskSpace/1GB, 1)) GB available)" -Module "Validator"
    }
    else {
        Write-Log -Level WARNING -Message "Low disk space: $([math]::Round($diskSpace/1MB, 2)) MB" -Module "Validator"
        $result.Warnings += "Low disk space: $([math]::Round($diskSpace/1MB, 2)) MB"
    }

    # Check 4: PowerShell version
    if ($PSVersionTable.PSVersion -ge [version]'5.1') {
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

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    if ($processors.Count -eq 0) {
        throw 'Win32_Processor returned no instances while validating the native platform architecture'
    }
    $nativeArchitectures = @($processors | ForEach-Object {
            if ($null -eq $_.Architecture) {
                throw 'Win32_Processor did not report Architecture for every processor'
            }
            [int]$_.Architecture
        } | Sort-Object -Unique)
    $nativeArchitecture = if ($nativeArchitectures.Count -eq 1) { [int]$nativeArchitectures[0] } else { -1 }
    $nativeArchitectureName = switch ($nativeArchitecture) {
        9 { 'x64 (AMD64/x86-64)' }
        12 { 'ARM64' }
        0 { 'x86' }
        default { "Unsupported or mixed architecture ($($nativeArchitectures -join ','))" }
    }
    $isX64Platform = ($nativeArchitecture -eq 9)
    $currentVersionPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $currentVersionKey = Get-Item -LiteralPath $currentVersionPath -ErrorAction Stop
    $getRegistryValue = {
        param([string]$Name, $Fallback)
        if ($currentVersionKey.GetValueNames() -contains $Name) {
            return $currentVersionKey.GetValue($Name)
        }
        return $Fallback
    }

    $buildNumber = [int](& $getRegistryValue 'CurrentBuildNumber' $os.BuildNumber)
    $updateBuildRevision = [int](& $getRegistryValue 'UBR' 0)
    $displayVersion = [string](& $getRegistryValue 'DisplayVersion' '')
    $editionId = [string](& $getRegistryValue 'EditionID' '')
    $installationType = [string](& $getRegistryValue 'InstallationType' '')
    $productType = [int]$os.ProductType
    $operatingSystemSku = [int]$os.OperatingSystemSKU
    $isClient = ($productType -eq 1 -and $installationType -notmatch '(?i)Server')
    $isWindows11 = ($isClient -and $buildNumber -ge 22000)

    $release = 'Unknown'
    $supportProfile = 'Unsupported'
    $supportLevel = 'Unsupported'
    $supportReason = 'Build family is not supported by this framework'

    if (-not $isClient) {
        $supportReason = 'Windows Server and domain-controller SKUs are not supported'
    }
    elseif ($displayVersion -eq '26H2' -and $buildNumber -ge 26300 -and $buildNumber -lt 28000) {
        $release = '26H2'
        $supportProfile = 'Windows11-26H2-Experimental'
        $supportLevel = 'Experimental'
        $supportReason = 'Recognized 26H2 Experimental Preview on the 24H2/25H2 servicing branch; currently not runtime-validated or release-approved'
    }
    elseif ($displayVersion -eq '26H1' -or ($buildNumber -ge 28000 -and $buildNumber -lt 29000)) {
        $release = '26H1'
        $supportProfile = 'Windows11-26H1-UnsupportedCore'
        $supportReason = '26H1 uses a different Windows core and is not a supported upgrade target for this framework'
    }
    elseif ($displayVersion -eq '25H2' -and $buildNumber -ge 26200 -and $buildNumber -lt 26300) {
        $release = '25H2'
        $supportProfile = 'Windows11-25H2'
        $supportLevel = 'Stable'
        $supportReason = 'Supported Windows 11 25H2 release'
    }
    elseif ($displayVersion -eq '24H2' -and $buildNumber -ge 26100 -and $buildNumber -lt 26200) {
        $release = '24H2'
        $supportProfile = 'Windows11-24H2'
        $supportLevel = 'Stable'
        $supportReason = 'Supported Windows 11 24H2 release'
    }
    elseif ([string]::IsNullOrWhiteSpace($displayVersion) -and $buildNumber -ge 26300 -and $buildNumber -lt 28000) {
        $release = 'UnidentifiedPreview'
        $supportProfile = 'Windows11-UnidentifiedPreview-Unsupported'
        $supportReason = 'Build 26300-27999 is accepted only when Windows explicitly reports the official 26H2 DisplayVersion'
    }
    elseif ([string]::IsNullOrWhiteSpace($displayVersion) -and $buildNumber -ge 26200 -and $buildNumber -lt 26300) {
        $release = '25H2'
        $supportProfile = 'Windows11-25H2'
        $supportLevel = 'Stable'
        $supportReason = '25H2 build family inferred because DisplayVersion is unavailable'
    }
    elseif ([string]::IsNullOrWhiteSpace($displayVersion) -and $buildNumber -ge 26100 -and $buildNumber -lt 26200) {
        $release = '24H2'
        $supportProfile = 'Windows11-24H2'
        $supportLevel = 'Stable'
        $supportReason = '24H2 build family inferred because DisplayVersion is unavailable'
    }
    elseif ($buildNumber -ge 29600) {
        $release = 'FuturePlatform'
        $supportProfile = 'Windows11-FuturePlatform-Unsupported'
        $supportReason = 'Future-platform/Canary build families are outside the explicitly recognized 26H2 Experimental Preview boundary'
    }

    if (-not $isX64Platform) {
        $supportProfile = 'Windows11-UnsupportedArchitecture'
        $supportLevel = 'Unsupported'
        $supportReason = "NoID Privacy supports Windows 11 x64 (AMD64/x86-64) only; Windows on Arm (ARM64) and other processor architectures are not supported (detected: $nativeArchitectureName)"
    }

    $isSupported = $isWindows11 -and $isX64Platform -and $supportLevel -in @('Stable', 'Experimental')
    $versionName = if ($isWindows11) {
        if ($supportLevel -eq 'Experimental') { "Windows 11 $release (Experimental Preview - not runtime-validated or release-approved)" }
        elseif ($release -ne 'Unknown') { "Windows 11 $release" }
        else { "Windows 11 build $buildNumber" }
    }
    elseif ($isClient) {
        "Windows client build $buildNumber"
    }
    else {
        "Unsupported Windows Server build $buildNumber"
    }

    return [PSCustomObject]@{
        Version             = $versionName
        Release             = $release
        DisplayVersion      = $displayVersion
        BuildNumber         = $buildNumber
        UpdateBuildRevision = $updateBuildRevision
        FullBuild           = "$buildNumber.$updateBuildRevision"
        ProductType         = $productType
        IsClient            = $isClient
        IsWindows11         = $isWindows11
        IsSupported         = $isSupported
        SupportProfile      = $supportProfile
        SupportLevel        = $supportLevel
        SupportReason       = $supportReason
        Edition             = $editionId
        OperatingSystemSKU  = $operatingSystemSku
        InstallationType    = $installationType
        Architecture        = $os.OSArchitecture
        NativeArchitecture  = $nativeArchitectureName
        NativeArchitectureId = $nativeArchitecture
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
        $tpm = Get-Tpm -ErrorAction Stop
        if ($null -eq $tpm) {
            throw 'Get-Tpm returned no result'
        }

        $present = [bool]$tpm.TpmPresent
        $specVersion = if ($present) { 'Unknown' } else { 'N/A' }
        $manufacturerVersion = if ([string]::IsNullOrWhiteSpace([string]$tpm.ManufacturerVersion)) {
            'Unknown'
        }
        else {
            [string]$tpm.ManufacturerVersion
        }
        $specQuerySucceeded = $null
        $isTpm20 = if ($present) { $null } else { $false }

        if ($present) {
            try {
                $providerResults = @(Get-CimInstance -Namespace 'Root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop)
                if ($providerResults.Count -ne 1) {
                    throw "Win32_Tpm returned $($providerResults.Count) instances"
                }
                $specVersion = [string]$providerResults[0].SpecVersion
                if ([string]::IsNullOrWhiteSpace($specVersion) -or $specVersion -eq 'Not Supported') {
                    throw 'Win32_Tpm returned no usable SpecVersion'
                }
                $specQuerySucceeded = $true
                $isTpm20 = $specVersion -match '^\s*2\.0(?:\s*,|\s*$)'
            }
            catch {
                $specQuerySucceeded = $false
                Write-Log -Level WARNING -Message "Unable to query TPM specification version: $($_.Exception.Message)" -Module 'Validator'
            }
        }

        return [PSCustomObject]@{
            QuerySucceeded       = $true
            Present              = $present
            Ready                = [bool]$tpm.TpmReady
            Version              = $specVersion
            SpecVersion          = $specVersion
            SpecQuerySucceeded   = $specQuerySucceeded
            IsTpm20              = $isTpm20
            ManufacturerVersion  = $manufacturerVersion
            Enabled              = [bool]$tpm.TpmEnabled
            Activated            = [bool]$tpm.TpmActivated
            Error                = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Level WARNING -Message "Unable to check TPM status: $errorMessage" -Module "Validator"
        return [PSCustomObject]@{
            QuerySucceeded       = $false
            Present              = $null
            Ready                = $null
            Version              = 'Unknown'
            SpecVersion          = 'Unknown'
            SpecQuerySucceeded   = $false
            IsTpm20              = $null
            ManufacturerVersion  = 'Unknown'
            Enabled              = $null
            Activated            = $null
            Error                = $errorMessage
        }
    }
}

function Get-SecureBootStatus {
    <#
    .SYNOPSIS
        Query Secure Boot without conflating a query failure with Disabled
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        $enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        return [PSCustomObject]@{
            QuerySucceeded = $true
            Enabled        = $enabled
            Error          = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Level WARNING -Message "Unable to check Secure Boot status: $errorMessage" -Module 'Validator'
        return [PSCustomObject]@{
            QuerySucceeded = $false
            Enabled        = $null
            Error          = $errorMessage
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

    $status = Get-SecureBootStatus
    return $status.QuerySucceeded -and [bool]$status.Enabled
}

function Get-VirtualizationStatus {
    <#
    .SYNOPSIS
        Query firmware virtualization, VM-monitor extensions and SLAT on every CPU socket
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
        if ($processors.Count -eq 0) {
            throw 'Win32_Processor returned no instances'
        }

        foreach ($propertyName in @(
                'VirtualizationFirmwareEnabled',
                'VMMonitorModeExtensions',
                'SecondLevelAddressTranslationExtensions'
            )) {
            if (@($processors | Where-Object { $null -eq $_.$propertyName }).Count -gt 0) {
                throw "Win32_Processor did not report '$propertyName' for every processor"
            }
        }

        return [PSCustomObject]@{
            QuerySucceeded                 = $true
            ProcessorCount                 = $processors.Count
            FirmwareEnabled                = @($processors | Where-Object { -not [bool]$_.VirtualizationFirmwareEnabled }).Count -eq 0
            VMMonitorModeExtensions        = @($processors | Where-Object { -not [bool]$_.VMMonitorModeExtensions }).Count -eq 0
            SecondLevelAddressTranslation  = @($processors | Where-Object { -not [bool]$_.SecondLevelAddressTranslationExtensions }).Count -eq 0
            Error                          = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Level WARNING -Message "Unable to check virtualization status: $errorMessage" -Module 'Validator'
        return [PSCustomObject]@{
            QuerySucceeded                 = $false
            ProcessorCount                 = 0
            FirmwareEnabled                = $null
            VMMonitorModeExtensions        = $null
            SecondLevelAddressTranslation  = $null
            Error                          = $errorMessage
        }
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

    $status = Get-VirtualizationStatus
    return $status.QuerySucceeded -and [bool]$status.FirmwareEnabled
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
    $secureBoot = Get-SecureBootStatus
    $virtualization = Get-VirtualizationStatus
    $isAdmin = Test-IsAdministrator
    $diskSpace = Get-AvailableDiskSpace
    return [PSCustomObject]@{
        OS                 = $osInfo
        TPM                = $tpmInfo
        SecureBoot         = $secureBoot
        Virtualization     = $virtualization
        IsAdministrator    = $isAdmin
        DiskSpaceAvailable = $diskSpace
        # Deliberately NotChecked: prerequisites must not create an unsolicited
        # outbound request merely to label connectivity.
        InternetConnected  = $null
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
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
            QuerySucceeded  = $true
            IsDomainJoined = $isDomainJoined
            DomainName     = if ($isDomainJoined) { $computerSystem.Domain } else { "N/A" }
            Workgroup      = if (-not $isDomainJoined) { $computerSystem.Workgroup } else { "N/A" }
            UserConfirmed  = $false
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
                Write-Host "  - Overlapping Domain Group Policies can override local effective values" -ForegroundColor Yellow
                Write-Host "  - Refresh can occur at startup, sign-in, manually, or in the background" -ForegroundColor Yellow
                Write-Host "  - Some hardening may be reset automatically" -ForegroundColor Yellow
                Write-Host "  - Coordinate with AD team before proceeding" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "RECOMMENDED FOR DOMAIN ENVIRONMENTS:" -ForegroundColor Cyan
                Write-Host "  - Integrate these settings into Domain GPOs instead" -ForegroundColor White
                Write-Host "  - Use this tool only for testing/standalone systems" -ForegroundColor White
                Write-Host ""

                Write-Host "Do you want to continue anyway?" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  [N] NO - Cancel (default)" -ForegroundColor Green
                Write-Host "      - No changes are made to this domain-joined system" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Continue anyway" -ForegroundColor Cyan
                Write-Host "      - Domain Group Policies may override or reset local hardening" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
                    $continue = Read-Host
                    if ([string]::IsNullOrWhiteSpace($continue)) { $continue = "N" }
                    $continue = $continue.Trim().ToUpperInvariant()
                    # Tolerate the documented word answers as well.
                    if ($continue -eq 'YES') { $continue = 'Y' }
                    elseif ($continue -eq 'NO') { $continue = 'N' }

                    if ($continue -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($continue -notin @('Y', 'N'))

                if ($continue -ne 'Y') {
                    Write-Log -Level INFO -Message "User cancelled due to domain-joined warning" -Module "Validator"
                    Write-Host ""
                    Write-Host "Operation cancelled by user." -ForegroundColor Gray
                    Write-Host ""
                    # Return result with UserConfirmed=$false so caller decides flow (do not exit from utility function)
                    return $result
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
            QuerySucceeded = $false
            IsDomainJoined = $false
            DomainName     = "Error"
            Workgroup      = "Error"
            UserConfirmed  = $false
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

    Write-Log -Level INFO -Message "Backup recommendation acknowledged automatically; a session backup is created before any change" -Module "Validator"

    $result = [PSCustomObject]@{
        UserConfirmed     = $true
        BackupRecommended = $true
    }

    return $result
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
