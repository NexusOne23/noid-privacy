#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for stable Windows SKU and hardware-unit detection.
#>

BeforeAll {
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function global:Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Namespace) $null = $ClassName, $Namespace; throw 'Get-CimInstance test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
        function global:Get-Tpm { [CmdletBinding()] param() throw 'Get-Tpm test placeholder was not mocked' }
    }
    if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        function global:Confirm-SecureBootUEFI { [CmdletBinding()] param() throw 'Confirm-SecureBootUEFI test placeholder was not mocked' }
    }
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Core/Validator.ps1')
    . (Join-Path $script:RepoRoot 'Utils/Hardware.ps1')
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    . (Join-Path $script:RepoRoot 'Core/Config.ps1')
    function Get-FakeCurrentVersionKey {
        param([hashtable]$Values)
        $key = [PSCustomObject]@{ Values = $Values }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
            return @($this.Values.Keys)
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
            param($name, $fallback)
            if ($this.Values.ContainsKey($name)) { return $this.Values[$name] }
            return $fallback
        }
        return $key
    }
}

Describe 'Exact runtime configuration schema' {
    BeforeEach {
        $script:Config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Mock Write-Log { }
    }

    It 'accepts the shipped complete decision schema' {
        Test-ConfigValid | Should -BeTrue
    }

    It 'rejects a string that looks like a Boolean decision' {
        $script:Config.modules.ASR.allowNewSoftware = 'false'
        Test-ConfigValid | Should -BeFalse
    }

    It 'rejects Weather Widget removal unless Tier 2 is selected' {
        $script:Config.modules.Privacy.removeWeatherWidget = $true
        Test-ConfigValid | Should -BeFalse

        $script:Config.modules.Privacy.removeBloatwareApps = 'standard'
        Test-ConfigValid | Should -BeTrue
    }

    It 'rejects unknown module properties instead of ignoring typos' {
        $script:Config.modules.DNS | Add-Member -NotePropertyName dohMod -NotePropertyValue 'REQUIRE'
        Test-ConfigValid | Should -BeFalse
    }

    It 'rejects dead or unknown global options' {
        $script:Config.options | Add-Member -NotePropertyName autoReboot -NotePropertyValue $false
        Test-ConfigValid | Should -BeFalse
    }

    It 'rejects unknown root properties instead of ignoring them' {
        $script:Config | Add-Member -NotePropertyName unexpectedRoot -NotePropertyValue $true
        Test-ConfigValid | Should -BeFalse
    }

    It 'rejects case variants of every closed enum value' {
        $cases = @(
            @{ Module = 'SecurityBaseline'; Property = 'standardUserElevationMode'; Value = 'strict' }
            @{ Module = 'DNS'; Property = 'provider'; Value = 'quad9' }
            @{ Module = 'DNS'; Property = 'dohMode'; Value = 'require' }
            @{ Module = 'Privacy'; Property = 'mode'; Value = 'msrecommended' }
            @{ Module = 'Privacy'; Property = 'removeBloatwareApps'; Value = 'None' }
            @{ Module = 'AdvancedSecurity'; Property = 'securityProfile'; Value = 'balanced' }
            @{ Module = $null; Property = 'sessionType'; Value = 'Wizard' }
        )
        foreach ($case in $cases) {
            $script:Config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 |
                ConvertFrom-Json
            if ($null -eq $case.Module) {
                $script:Config.options | Add-Member -NotePropertyName $case.Property -NotePropertyValue $case.Value
            }
            else {
                $script:Config.modules.($case.Module).($case.Property) = $case.Value
            }
            Test-ConfigValid | Should -BeFalse -Because "$($case.Property) values are case-exact"
        }
    }

    It 'rejects duplicate JSON property names before object conversion' {
        $baseRaw = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8
        $samples = @(
            ($baseRaw -replace '"version"\s*:\s*"2\.2\.5"\s*,', '"version":"0.0.0","version":"2.2.5",')
            ($baseRaw -replace '"version"\s*:\s*"2\.2\.5"\s*,', '"Version":"0.0.0","version":"2.2.5",')
            ($baseRaw -replace '"enabled"\s*:\s*true\s*,', '"enabled":false,"enabled":true,')
        )
        for ($index = 0; $index -lt $samples.Count; $index++) {
            $path = Join-Path $TestDrive "duplicate-$index.json"
            [System.IO.File]::WriteAllText($path, [string]$samples[$index], [System.Text.UTF8Encoding]::new($false))
            { Initialize-Config -ConfigPath $path -CreateDefault $false } |
                Should -Throw '*Duplicate JSON property name*'
        }
    }

    It 'never creates a missing explicitly selected configuration by default' {
        $missing = Join-Path $TestDrive 'caller-selected-missing.json'
        { Initialize-Config -ConfigPath $missing } |
            Should -Throw '*Configuration file not found*'
        $missing | Should -Not -Exist
    }

    It 'accepts a valid GUI session identity and rejects an unknown one' {
        $script:Config.options | Add-Member -NotePropertyName sessionType -NotePropertyValue 'wizard'
        Test-ConfigValid | Should -BeTrue

        $script:Config.options.sessionType = 'gui'
        Test-ConfigValid | Should -BeFalse
    }

    It 'generates a default configuration that validates against its own current schema' {
        $generatedPath = Join-Path $TestDrive 'generated-default.json'
        New-DefaultConfig -Path $generatedPath -Confirm:$false
        $script:Config = Get-Content -LiteralPath $generatedPath -Raw -Encoding UTF8 | ConvertFrom-Json

        Test-ConfigValid | Should -BeTrue
    }

    It 'rejects missing modules and version drift' {
        $script:Config.modules.PSObject.Properties.Remove('AntiAI')
        Test-ConfigValid | Should -BeFalse

        $script:Config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:Config.version = '0.0.0'
        Test-ConfigValid | Should -BeFalse
    }

    It 'routes every one of the 128 enabled-module subsets exactly once in priority order' {
        Mock Test-ModuleAvailability { $true }
        $moduleNames = @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')

        foreach ($mask in 0..127) {
            $script:Config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 |
                ConvertFrom-Json
            $expected = @()
            for ($index = 0; $index -lt $moduleNames.Count; $index++) {
                $enabled = [bool]($mask -band (1 -shl $index))
                $script:Config.modules.($moduleNames[$index]).enabled = $enabled
                if ($enabled) { $expected += $moduleNames[$index] }
            }

            $actual = @(Get-EnabledModules)
            ($actual -join '|') | Should -BeExactly ($expected -join '|') -Because "module mask $mask must preserve the exact enabled subset and priority order"
            @($actual | Group-Object | Where-Object Count -ne 1).Count | Should -Be 0 -Because "module mask $mask must never route a module more than once"
        }

        Assert-MockCalled Test-ModuleAvailability -Exactly 448 -Scope It
    }
}

Describe 'Hardware unit conversion' {
    It 'converts Win32_OperatingSystem KiB values to GiB exactly once' {
        Mock Get-CimInstance {
            param($ClassName)
            if ($ClassName -eq 'Win32_ComputerSystem') {
                return [PSCustomObject]@{ TotalPhysicalMemory = [uint64](16GB) }
            }
            if ($ClassName -eq 'Win32_OperatingSystem') {
                return [PSCustomObject]@{
                    FreePhysicalMemory   = [uint64]8388608
                    TotalVirtualMemorySize = [uint64]25165824
                    FreeVirtualMemory    = [uint64]12582912
                }
            }
            throw "Unexpected class $ClassName"
        }

        $memory = Get-MemoryInfo
        $memory.TotalPhysicalMemoryGB | Should -Be 16
        $memory.FreePhysicalMemoryGB | Should -Be 8
        $memory.TotalVirtualMemoryGB | Should -Be 24
        $memory.FreeVirtualMemoryGB | Should -Be 12
    }
}

Describe 'Hardware security query semantics' {
    BeforeEach {
        Mock Write-Log { }
    }

    It 'reports the TPM specification separately from manufacturer firmware' {
        Mock Get-Tpm {
            [PSCustomObject]@{
                TpmPresent = $true; TpmReady = $true; TpmEnabled = $true
                TpmActivated = $true; ManufacturerVersion = '7.63.3353.0'
            }
        }
        Mock Get-CimInstance {
            [PSCustomObject]@{ SpecVersion = '2.0, 0, 1.59' }
        } -ParameterFilter { $Namespace -eq 'Root\CIMV2\Security\MicrosoftTpm' -and $ClassName -eq 'Win32_Tpm' }

        $result = Test-TPMAvailable
        $result.QuerySucceeded | Should -BeTrue
        $result.SpecQuerySucceeded | Should -BeTrue
        $result.SpecVersion | Should -Be '2.0, 0, 1.59'
        $result.Version | Should -Be '2.0, 0, 1.59'
        $result.ManufacturerVersion | Should -Be '7.63.3353.0'
        $result.IsTpm20 | Should -BeTrue
    }

    It 'keeps TPM query failure unknown instead of claiming absence' {
        Mock Get-Tpm { throw 'TPM provider unavailable' }

        $result = Test-TPMAvailable
        $result.QuerySucceeded | Should -BeFalse
        $result.Present | Should -BeNullOrEmpty
        $result.IsTpm20 | Should -BeNullOrEmpty
        $result.Error | Should -Match 'provider unavailable'
    }

    It 'requires firmware virtualization on every reported CPU socket' {
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    VirtualizationFirmwareEnabled = $true
                    VMMonitorModeExtensions = $true
                    SecondLevelAddressTranslationExtensions = $true
                }
                [PSCustomObject]@{
                    VirtualizationFirmwareEnabled = $false
                    VMMonitorModeExtensions = $true
                    SecondLevelAddressTranslationExtensions = $true
                }
            )
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }

        $result = Get-VirtualizationStatus
        $result.QuerySucceeded | Should -BeTrue
        $result.ProcessorCount | Should -Be 2
        $result.FirmwareEnabled | Should -BeFalse
        Test-VirtualizationEnabled | Should -BeFalse
    }

    It 'keeps Secure Boot query failure distinct from Disabled' {
        Mock Confirm-SecureBootUEFI { throw 'not supported on this platform' }

        $result = Get-SecureBootStatus
        $result.QuerySucceeded | Should -BeFalse
        $result.Enabled | Should -BeNullOrEmpty
        Test-SecureBootEnabled | Should -BeFalse
    }
}

Describe 'Stable Windows edition classification' {
    It 'classifies Home without granting managed enterprise capabilities' {
        Mock Get-CimInstance { [PSCustomObject]@{ OperatingSystemSKU = 101; Caption = 'Localized'; Version = '10.0.26100'; BuildNumber = '26100' } }
        Mock Get-WindowsVersion { [PSCustomObject]@{ Edition = 'Core'; IsWindows11 = $true } }

        $edition = Get-WindowsEditionInfo
        $edition.EditionFamily | Should -Be 'Home'
        $edition.SupportsCredentialGuard | Should -BeFalse
        $edition.AppLockerLicensed | Should -BeFalse
    }

    It 'classifies Pro by OperatingSystemSKU independent of localized Caption' {
        Mock Get-CimInstance { [PSCustomObject]@{ OperatingSystemSKU = 48; Caption = 'Beliebige lokalisierte Anzeige'; Version = '10.0.26100'; BuildNumber = '26100' } }
        Mock Get-WindowsVersion { [PSCustomObject]@{ Edition = 'Professional'; IsWindows11 = $true } }

        $edition = Get-WindowsEditionInfo
        $edition.EditionFamily | Should -Be 'Professional'
        $edition.IsPro | Should -BeTrue
        $edition.SupportsCredentialGuard | Should -BeFalse
        $edition.SupportsAppLocker | Should -BeTrue
        $edition.AppLockerLicensed | Should -BeFalse
        $edition.SupportsBitLocker | Should -BeTrue
    }

    It 'classifies Education by OperatingSystemSKU and exposes current licensing' {
        Mock Get-CimInstance { [PSCustomObject]@{ OperatingSystemSKU = 121; Caption = 'Localized'; Version = '10.0.26200'; BuildNumber = '26200' } }
        Mock Get-WindowsVersion { [PSCustomObject]@{ Edition = 'Education'; IsWindows11 = $true } }

        $edition = Get-WindowsEditionInfo
        $edition.EditionFamily | Should -Be 'Education'
        $edition.IsEducation | Should -BeTrue
        $edition.SupportsCredentialGuard | Should -BeTrue
        $edition.AppLockerLicensed | Should -BeTrue
        $edition.SupportsBitLocker | Should -BeTrue
    }

    It 'classifies Enterprise by OperatingSystemSKU independent of EditionID fallback' {
        Mock Get-CimInstance { [PSCustomObject]@{ OperatingSystemSKU = 4; Caption = 'Localized'; Version = '10.0.26200'; BuildNumber = '26200' } }
        Mock Get-WindowsVersion { [PSCustomObject]@{ Edition = 'UnexpectedFallback'; IsWindows11 = $true } }

        $edition = Get-WindowsEditionInfo
        $edition.EditionFamily | Should -Be 'Enterprise'
        $edition.SupportsCredentialGuard | Should -BeTrue
        $edition.AppLockerLicensed | Should -BeTrue
    }
}

Describe 'Windows 11 servicing-profile matrix' {
    BeforeEach {
        $script:versionValues = @{}
        $script:versionOs = [PSCustomObject]@{
            BuildNumber = '26100'; ProductType = 1; OperatingSystemSKU = 48
            OSArchitecture = '64-bit'
        }
        $script:versionProcessor = [PSCustomObject]@{ Architecture = 9 }
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_OperatingSystem') { return $script:versionOs }
            if ($ClassName -eq 'Win32_Processor') { return $script:versionProcessor }
            throw "Unexpected CIM class in servicing-profile test: $ClassName"
        }
        Mock Get-Item { Get-FakeCurrentVersionKey -Values $script:versionValues }
    }

    It '<Label>' -TestCases @(
        @{ Label='24H2 stable'; Display='24H2'; Build=26100; ExpectedProfile='Windows11-24H2'; ExpectedLevel='Stable'; Supported=$true }
        @{ Label='25H2 stable'; Display='25H2'; Build=26200; ExpectedProfile='Windows11-25H2'; ExpectedLevel='Stable'; Supported=$true }
        @{ Label='26H2 official Experimental'; Display='26H2'; Build=26300; ExpectedProfile='Windows11-26H2-Experimental'; ExpectedLevel='Experimental'; Supported=$true }
        @{ Label='26H2-range without explicit version'; Display=''; Build=26300; ExpectedProfile='Windows11-UnidentifiedPreview-Unsupported'; ExpectedLevel='Unsupported'; Supported=$false }
        @{ Label='separate 26H1 core'; Display='26H1'; Build=28000; ExpectedProfile='Windows11-26H1-UnsupportedCore'; ExpectedLevel='Unsupported'; Supported=$false }
        @{ Label='future platform'; Display=''; Build=29600; ExpectedProfile='Windows11-FuturePlatform-Unsupported'; ExpectedLevel='Unsupported'; Supported=$false }
    ) {
        param($Display, $Build, $ExpectedProfile, $ExpectedLevel, $Supported)
        $script:versionValues = @{
            CurrentBuildNumber = [string]$Build; UBR = 1; DisplayVersion = $Display
            EditionID = 'Professional'; InstallationType = 'Client'
        }
        $script:versionOs.BuildNumber = [string]$Build

        $result = Get-WindowsVersion
        $result.SupportProfile | Should -Be $ExpectedProfile
        $result.SupportLevel | Should -Be $ExpectedLevel
        $result.IsSupported | Should -Be $Supported
    }

    It 'rejects Windows Server even when its build resembles a supported client' {
        $script:versionValues = @{
            CurrentBuildNumber = '26100'; UBR = 1; DisplayVersion = '24H2'
            EditionID = 'ServerStandard'; InstallationType = 'Server'
        }
        $script:versionOs.ProductType = 3

        $result = Get-WindowsVersion
        $result.IsClient | Should -BeFalse
        $result.IsSupported | Should -BeFalse
        $result.SupportReason | Should -Match 'Server'
    }

    It 'rejects Windows on Arm even when its release and build are otherwise supported' {
        $script:versionValues = @{
            CurrentBuildNumber = '26200'; UBR = 1; DisplayVersion = '25H2'
            EditionID = 'Professional'; InstallationType = 'Client'
        }
        $script:versionOs.BuildNumber = '26200'
        $script:versionProcessor.Architecture = 12

        $result = Get-WindowsVersion
        $result.IsSupported | Should -BeFalse
        $result.SupportProfile | Should -Be 'Windows11-UnsupportedArchitecture'
        $result.NativeArchitecture | Should -Be 'ARM64'
        $result.SupportReason | Should -Match 'Windows on Arm'
    }
}

Describe 'Domain-membership detection is fail closed' {
    BeforeEach {
        Mock Write-Log { }
    }

    It 'reports successful standalone and domain queries explicitly' {
        Mock Get-CimInstance {
            [PSCustomObject]@{ PartOfDomain = $false; Domain = ''; Workgroup = 'WORKGROUP' }
        }
        $standalone = Test-DomainJoined
        $standalone.QuerySucceeded | Should -BeTrue
        $standalone.IsDomainJoined | Should -BeFalse

        Mock Get-CimInstance {
            [PSCustomObject]@{ PartOfDomain = $true; Domain = 'example.invalid'; Workgroup = '' }
        }
        $domain = Test-DomainJoined
        $domain.QuerySucceeded | Should -BeTrue
        $domain.IsDomainJoined | Should -BeTrue
    }

    It 'marks a CIM failure unknown and the framework preflight rejects it' {
        Mock Get-CimInstance { throw 'CIM unavailable' }
        $unknown = Test-DomainJoined
        $unknown.QuerySucceeded | Should -BeFalse
        $unknown.IsDomainJoined | Should -BeFalse

        $framework = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $framework | Should -Match 'if \(-not \$domainCheck\.QuerySucceeded\)'
        $framework | Should -Match 'refusing to assume a standalone workstation'
    }
}

Describe 'Physical media detection' {
    BeforeEach {
        $env:SystemDrive = 'C:'
        Mock Get-NoIDPartitionByDriveLetter { [PSCustomObject]@{ DriveLetter = 'C'; DiskNumber = 0 } }
        Mock Get-NoIDDiskForPartition { [PSCustomObject]@{ Number = 0; BusType = 17; UniqueId = 'stable-disk-id' } }
        Mock Get-NoIDVirtualDisk { @() }
    }

    It 'recognizes MSFT_PhysicalDisk SSD media type 4' {
        Mock Get-NoIDPhysicalDisk { [PSCustomObject]@{ DeviceId = '0'; UniqueId = 'stable-disk-id'; MediaType = 4 } }
        Test-SSDDrive | Should -BeTrue
    }

    It 'does not report MSFT_PhysicalDisk HDD media type 3 as SSD' {
        Mock Get-NoIDPhysicalDisk { [PSCustomObject]@{ DeviceId = '0'; UniqueId = 'stable-disk-id'; MediaType = 3 } }
        Test-SSDDrive | Should -BeFalse
    }
}
