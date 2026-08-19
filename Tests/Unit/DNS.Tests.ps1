#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for DNS module

.DESCRIPTION
    Pester v5 tests for the DNS module functionality.
    Tests return values, DryRun behavior, provider configuration, and backup creation.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0
#>

BeforeAll {
    # Module entry points prompt through Read-Host unless non-interactive mode
    # is set; the 'Interactive'-tagged smoke tests below run through
    # Invoke-UnitNonInteractive so they cannot block on a real desktop.
    . (Join-Path $PSScriptRoot '_NonInteractive.ps1')
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/DNS.psm1"

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }
    . (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Tools/Private/Test-DNSKeepDecision.ps1')
    . (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Tools/Private/Test-DNSManagedTakeoverEvidence.ps1')

    # Import Core modules for testing
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1", "NonInteractive.ps1")
    $corePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }

    foreach ($functionName in @(
            'Write-Log', 'Write-ErrorLog', 'Initialize-Logger',
            'Initialize-BackupSystem', 'Start-ModuleBackup',
            'Complete-ModuleBackup', 'Save-IncompleteModuleBackup',
            'Test-NonInteractiveMode', 'Get-NonInteractiveValue',
            'Write-NonInteractiveDecision', 'Get-ConfigValue'
        )) {
        if (Test-Path "function:$functionName") {
            Set-Item -Path "function:global:$functionName" -Value (Get-Item "function:$functionName").ScriptBlock
        }
    }
    if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
        function global:Get-NetAdapter { [CmdletBinding()] param([switch]$Physical) $null = $Physical; @() }
    }
    if (-not (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue)) {
        function global:Get-VpnConnection { [CmdletBinding()] param([switch]$AllUserConnection) $null = $AllUserConnection; @() }
    }
    if (-not (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        function global:Get-DnsClientDohServerAddress { [CmdletBinding()] param([string]$ServerAddress) $null = $ServerAddress; @() }
    }
    if (-not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        function global:Add-DnsClientDohServerAddress {
            [CmdletBinding()]
            param([string]$ServerAddress, [string]$DohTemplate, [bool]$AllowFallbackToUdp, [bool]$AutoUpgrade)
            $null = $ServerAddress, $DohTemplate, $AllowFallbackToUdp, $AutoUpgrade
        }
    }
    if (-not (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        function global:Set-DnsClientDohServerAddress {
            [CmdletBinding()]
            param([string]$ServerAddress, [string]$DohTemplate, [bool]$AllowFallbackToUdp, [bool]$AutoUpgrade)
            $null = $ServerAddress, $DohTemplate, $AllowFallbackToUdp, $AutoUpgrade
        }
    }
    Import-Module $modulePath -Force

    # Initialize logging (silent for tests)
    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }

    # Initialize config
    if (Get-Command Initialize-Config -ErrorAction SilentlyContinue) {
        $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "config.json"
        Initialize-Config -ConfigPath $configPath
    }

    # Initialize backup system
    if (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue) {
        Initialize-BackupSystem
    }
}

Describe "DNS Module" {

    Context "Module Structure" {

        It "Should export Invoke-DNSConfiguration function" {
            $command = Get-Command -Name Invoke-DNSConfiguration -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export Get-DNSStatus function" {
            $command = Get-Command -Name Get-DNSStatus -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have Provider parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('Provider') | Should -Be $true
        }

        It "Provider parameter should accept specific values" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $validateSet = $command.Parameters['Provider'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'Cloudflare'
            $validateSet.ValidValues | Should -Contain 'Quad9'
            $validateSet.ValidValues | Should -Contain 'AdGuard'
        }

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }

    Context "DNS Providers Configuration" {

        It "Should load DNS providers from JSON" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            $providersPath | Should -Exist
        }

        It "Providers file should be valid JSON" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            { Get-Content $providersPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Should have Cloudflare provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'cloudflare'
        }

        It "Should have Quad9 provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'quad9'
        }

        It "Should have AdGuard provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'adguard'
        }

        It "Cloudflare should have DoH template" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/DNS/Config/Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.cloudflare.doh.template | Should -Not -BeNullOrEmpty
        }
    }

    Context "Function Execution - DryRun Mode" {
        # These tests require network adapters and admin rights - skipped on CI

        It "Should execute without errors in DryRun mode with provider" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun } } | Should -Not -Throw
        }
    }

    Context "Return Object Structure" {
        It "Should report KEEP as a successful explicit no-mutation decision" {
            $result = Invoke-UnitNonInteractive {
                Invoke-DNSConfiguration -Provider 'KEEP'
            }
            $result.Success | Should -BeTrue
            $result.Status | Should -Be 'Success'
            $result.Provider | Should -BeExactly 'KEEP'
            $result.DoHMode | Should -BeExactly 'KEEP'
            $result.VerificationPassed | Should -BeNullOrEmpty
            $result.ChecksSkipped | Should -Be 5
            $result.AdaptersConfigured | Should -Be 0
        }

        It 'Should advise before provider selection and fail closed before a mutating provider path' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw
            $resolverProbes = @([regex]::Matches(
                    $source,
                    '\$currentDnsUsesLanResolver\s*=\s*Test-CurrentDnsUsesLanResolver'))
            $resolverProbes.Count | Should -Be 2
            $providerMenu = $source.IndexOf('DNS PROVIDER SELECTION')
            $providerChoice = $source.IndexOf('Select provider [1-3, 0=Skip]')
            $keepBranch = $source.IndexOf("if (`$Provider -eq 'KEEP')")
            $advisoryProbe = $resolverProbes[0].Index
            $mutationGateProbe = $resolverProbes[1].Index
            $providerMenu | Should -BeGreaterThan -1
            $advisoryProbe | Should -BeGreaterThan $providerMenu
            $providerChoice | Should -BeGreaterThan $advisoryProbe -Because 'the live router/LAN evidence must be visible before the user chooses KEEP or replacement'
            $keepBranch | Should -BeGreaterThan -1
            $mutationGateProbe | Should -BeGreaterThan $keepBranch -Because 'KEEP returns without requiring a successful probe; a selected replacement must fail closed when the advisory read was unavailable'
            $source | Should -Match 'Decision ''LAN resolver note'''
            $source | Should -Match 'This selection replaces router/LAN DNS; choosing KEEP preserves that resolver unchanged\.'
            $source | Should -Not -Match 'Current DNS uses a LAN resolver; Skip preserves it unchanged\.'
            $source | Should -Not -Match 'private IP.*custom|custom.*private IP'
        }
    }

    Context "DoH Policy Settings" {

        It "Should add a custom DoH endpoint that is absent from the system list" {
            $script:TestDohEndpointAdded = $false
            Mock -ModuleName DNS Get-DnsClientDohServerAddress {
                param($ServerAddress)
                $null = $ServerAddress
                if (-not $script:TestDohEndpointAdded) {
                    return @()
                }
                return [PSCustomObject]@{
                    ServerAddress = '192.0.2.53'
                    DohTemplate = 'https://dns.example.test/dns-query'
                    AllowFallbackToUdp = $false
                    AutoUpgrade = $true
                }
            }
            Mock -ModuleName DNS Add-DnsClientDohServerAddress {
                $script:TestDohEndpointAdded = $true
            }
            Mock -ModuleName DNS Set-DnsClientDohServerAddress

            $result = & (Get-Module DNS) {
                $script:DoHMode = 'REQUIRE'
                Enable-DoH `
                    -ServerAddress '192.0.2.53' `
                    -DohTemplate 'https://dns.example.test/dns-query' `
                    -Confirm:$false
            }

            $result | Should -BeTrue
            Should -Invoke -ModuleName DNS Get-DnsClientDohServerAddress -Times 2 -Exactly `
                -ParameterFilter { [string]::IsNullOrWhiteSpace([string]$ServerAddress) }
            Should -Invoke -ModuleName DNS Add-DnsClientDohServerAddress -Times 1 -Exactly `
                -ParameterFilter {
                    $ServerAddress -ceq '192.0.2.53' -and
                    $DohTemplate -ceq 'https://dns.example.test/dns-query' -and
                    -not $AllowFallbackToUdp -and $AutoUpgrade
                }
            Should -Invoke -ModuleName DNS Set-DnsClientDohServerAddress -Times 0 -Exactly
        }

        It "Set-DoHPolicy writes DoHPolicy=<Expected> as DWord for <Mode>" -TestCases @(
            @{ Mode = 'REQUIRE'; Expected = 3 }
            @{ Mode = 'ALLOW'; Expected = 2 }
        ) {
            param($Mode, $Expected)
            # The previous test matched "DoHPolicy = 3" against a COMMENT in the
            # source file, so inverting the actual mode-to-value mapping (REQUIRE
            # writing 2, silently allowing unencrypted fallback the operator
            # explicitly refused) failed nothing. Exercise the function and
            # assert the write it performs.
            # Hoisted into the It scope: the analyzer's unused-parameter rule
            # does not traverse the nested Mock script blocks that consume it.
            $expectedDoHValue = $Expected
            Mock -ModuleName DNS Test-Path { $true }
            Mock -ModuleName DNS New-ItemProperty {}
            Mock -ModuleName DNS Get-Item {
                $key = [PSCustomObject]@{}
                $expectedValue = $expectedDoHValue
                # The value-name argument these shims receive binds to $args;
                # neither result depends on it.
                $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                    $expectedValue
                }.GetNewClosure()
                $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
                    [Microsoft.Win32.RegistryValueKind]::DWord
                }
                $key
            }

            $result = & (Get-Module DNS) {
                param($testMode)
                $script:DoHMode = $testMode
                Set-DoHPolicy -Confirm:$false
            } $Mode

            $result | Should -BeTrue
            Should -Invoke -ModuleName DNS New-ItemProperty -Times 1 -Exactly `
                -ParameterFilter {
                    $LiteralPath -ceq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -and
                    $Name -ceq 'DoHPolicy' -and
                    [string]$PropertyType -ceq 'DWord' -and
                    [int]$Value -eq $Expected
                }
        }

        It "Set-DoHPolicy fails when the readback does not match what it wrote" {
            Mock -ModuleName DNS Test-Path { $true }
            Mock -ModuleName DNS New-ItemProperty {}
            Mock -ModuleName DNS Get-Item {
                $key = [PSCustomObject]@{}
                # The value-name argument binds to $args; the readback is fixed.
                $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { 2 }
                $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
                    [Microsoft.Win32.RegistryValueKind]::DWord
                }
                $key
            }
            Mock -ModuleName DNS Write-ErrorLog {}

            $result = & (Get-Module DNS) {
                $script:DoHMode = 'REQUIRE'
                Set-DoHPolicy -Confirm:$false
            }

            $result | Should -BeFalse
        }
    }

    Context "Canonical provider endpoint contract" {
        It "pins every shipped resolver address and DoH template as literals" {
            # No test pinned any endpoint, and the verifier reads the same
            # Providers.json the module ships - so a wrong resolver address was
            # invisible end to end: Apply would configure it, Verify would
            # confirm it, and every machine's DNS would go to the wrong place.
            # These literals are the only authority outside that file.
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Config/Providers.json'
            $providers = (Get-Content -LiteralPath $providersPath -Raw -Encoding UTF8 | ConvertFrom-Json).providers

            $expected = @{
                quad9 = @{
                    IntentToken = 'Quad9'
                    Ipv4 = @('9.9.9.9', '149.112.112.112')
                    Ipv6 = @('2620:fe::fe', '2620:fe::9')
                    Template = 'https://dns.quad9.net/dns-query'
                }
                cloudflare = @{
                    IntentToken = 'Cloudflare'
                    Ipv4 = @('1.1.1.1', '1.0.0.1')
                    Ipv6 = @('2606:4700:4700::1111', '2606:4700:4700::1001')
                    Template = 'https://cloudflare-dns.com/dns-query'
                }
                adguard = @{
                    IntentToken = 'AdGuard'
                    Ipv4 = @('94.140.14.14', '94.140.15.15')
                    Ipv6 = @('2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff')
                    Template = 'https://dns.adguard-dns.com/dns-query'
                }
            }

            foreach ($key in $expected.Keys) {
                $declared = $providers.$key
                $declared | Should -Not -BeNullOrEmpty -Because "provider '$key' must be shipped"
                [string]$declared.intentToken | Should -BeExactly $expected[$key].IntentToken
                [string]$declared.ipv4.primary | Should -BeExactly $expected[$key].Ipv4[0]
                [string]$declared.ipv4.secondary | Should -BeExactly $expected[$key].Ipv4[1]
                [string]$declared.ipv6.primary | Should -BeExactly $expected[$key].Ipv6[0]
                [string]$declared.ipv6.secondary | Should -BeExactly $expected[$key].Ipv6[1]
                [string]$declared.doh.template | Should -BeExactly $expected[$key].Template
                [bool]$declared.doh.supported | Should -BeTrue
            }

            # The interactive menu advertises addresses inline; they must be the
            # same addresses the provider table configures.
            $menuSource = Get-Content (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw
            $menuSource | Should -Match '\[1\] Quad9 \(9\.9\.9\.9\)'
            $menuSource | Should -Match '\[2\] Cloudflare \(1\.1\.1\.1\)'
            $menuSource | Should -Match '\[3\] AdGuard DNS \(94\.140\.14\.14\)'
        }

        It "maps interactive selection <Selection> to <Expected>" -TestCases @(
            @{ Selection = ''; Expected = 'Quad9' }
            @{ Selection = '1'; Expected = 'Quad9' }
            @{ Selection = '2'; Expected = 'Cloudflare' }
            @{ Selection = '3'; Expected = 'AdGuard' }
        ) {
            param($Selection, $Expected)
            # The number the user types after reading the menu MUST select the
            # provider the menu names for that number. Swapping two switch arms
            # in the old inline mapping sent "[3] AdGuard - RECOMMENDED FOR
            # AD-BLOCKING" to Cloudflare's unfiltered resolver with no failing
            # test and no visible error.
            InModuleScope DNS -Parameters @{ Selection = $Selection; Expected = $Expected } {
                Resolve-DnsProviderSelection -Selection $Selection | Should -BeExactly $Expected
            }
        }

        It "maps selection 0 to the KEEP decision and rejects everything else" {
            InModuleScope DNS {
                Resolve-DnsProviderSelection -Selection '0' | Should -BeNullOrEmpty
                { Resolve-DnsProviderSelection -Selection '4' } | Should -Throw '*Unsupported DNS provider selection*'
                { Resolve-DnsProviderSelection -Selection 'x' } | Should -Throw '*Unsupported DNS provider selection*'
            }
        }
    }

    Context "Sealed DNS backup contract" {
        BeforeAll {
            function Get-TestDnsSnapshot {
                [PSCustomObject]@{
                    SchemaVersion = 5
                    Policy = [PSCustomObject]@{
                        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                        Name = 'DoHPolicy'
                        KeyExisted = $false
                        Exists = $false
                        Type = $null
                        Value = $null
                    }
                    DohEntries = @(
                        [PSCustomObject]@{
                            ServerAddress = '2620:fe::9'
                            Exists = $false
                            DohTemplate = $null
                            AllowFallbackToUdp = $null
                            AutoUpgrade = $null
                        }
                    )
                    Adapters = @(
                        [PSCustomObject]@{
                            InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'
                            InterfaceDescription = 'Test Ethernet'
                            Families = @(
                                [PSCustomObject]@{
                                    AddressFamily = 2
                                    Managed = $true
                                    InterfaceDohManaged = $true
                                    ServerAddresses = @('192.168.1.1')
                                    InterfaceDoh = [PSCustomObject]@{
                                        AddressFamily = 2
                                        NameServers = @()
                                        Properties = @()
                                    }
                                    RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{11111111-2222-3333-4444-555555555555}'
                                    RegistryKeyExisted = $true
                                    NameServerExisted = $false
                                    NameServerType = $null
                                    NameServerValue = $null
                                },
                                [PSCustomObject]@{
                                    AddressFamily = 23
                                    Managed = $false
                                    InterfaceDohManaged = $true
                                    ServerAddresses = @()
                                    InterfaceDoh = [PSCustomObject]@{
                                        AddressFamily = 23
                                        NameServers = @('2620:fe::fe', '2620:fe::9')
                                        Properties = @()
                                    }
                                    RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{11111111-2222-3333-4444-555555555555}'
                                    RegistryKeyExisted = $true
                                    NameServerExisted = $true
                                    NameServerType = 'String'
                                    NameServerValue = '2620:fe::fe,2620:fe::9'
                                }
                            )
                        }
                    )
                }
            }
        }

        It "Should accept a complete internally consistent snapshot" {
            $snapshot = Get-TestDnsSnapshot
            $result = & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot
            $result | Should -BeTrue
        }

        It 'accepts an already-absent baseline-owned DNS policy key on a repeated layered restore' {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.Policy.KeyExisted = $true
            $baselinePath = Join-Path $TestDrive 'dns-baseline-prestate.json'
            [PSCustomObject]@{
                SchemaVersion = 4
                Computer = @(
                    [PSCustomObject]@{
                        KeyName = '[Software\Policies\Microsoft\Windows NT\DNSClient'
                        ValueName = 'EnableMulticast'
                        KeyExisted = $false
                        Exists = $false
                    }
                )
                ComputerClearKeys = @()
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselinePath -Encoding UTF8

            InModuleScope DNS -Parameters @{
                Snapshot = $snapshot
                BaselinePath = $baselinePath
            } {
                param($Snapshot, $BaselinePath)

                Mock Test-Path { $LiteralPath -ceq $BaselinePath }

                Test-DNSCombinedSessionPolicyKeyAbsence `
                    -DNSSnapshot $Snapshot `
                    -SecurityBaselineRegistryBackupPath $BaselinePath |
                    Should -BeTrue
            }
        }

        It 'does not accept a later DNS policy key as the combined session prestate' {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.Policy.KeyExisted = $true
            $baselinePath = Join-Path $TestDrive 'dns-baseline-foreign-state.json'
            [PSCustomObject]@{
                SchemaVersion = 4
                Computer = @(
                    [PSCustomObject]@{
                        KeyName = '[Software\Policies\Microsoft\Windows NT\DNSClient'
                        ValueName = 'EnableMulticast'
                        KeyExisted = $false
                        Exists = $false
                    }
                )
                ComputerClearKeys = @()
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselinePath -Encoding UTF8

            InModuleScope DNS -Parameters @{
                Snapshot = $snapshot
                BaselinePath = $baselinePath
            } {
                param($Snapshot, $BaselinePath)

                Mock Test-Path { $true }

                Test-DNSCombinedSessionPolicyKeyAbsence `
                    -DNSSnapshot $Snapshot `
                    -SecurityBaselineRegistryBackupPath $BaselinePath |
                    Should -BeFalse
            }
        }

        It "Should reject a duplicate managed DoH target" {
            $snapshot = Get-TestDnsSnapshot
            $duplicate = [PSCustomObject]@{
                ServerAddress = '2620:00fe:0000:0000:0000:0000:0000:0009'
                Exists = $false
                DohTemplate = $null
                AllowFallbackToUdp = $null
                AutoUpgrade = $null
            }
            $snapshot.DohEntries = @($snapshot.DohEntries[0], $duplicate)
            { & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot } |
                Should -Throw '*duplicate DoH address*'
        }

        It "Should reject a resolver address stored under the wrong family" {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.Adapters[0].Families[0].ServerAddresses = @('2620:fe::fe')
            { & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot } |
                Should -Throw '*wrong family*'
        }

        It 'Should reject malformed native per-interface DoH state' {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.Adapters[0].Families[0].InterfaceDoh = [PSCustomObject]@{
                AddressFamily = 2
                NameServers = @('9.9.9.9')
                Properties = @([PSCustomObject]@{
                        Version = 1; ServerIndex = 0; Type = 1
                        Flags = [uint64]3; Template = $null; Port = 0
                    })
            }
            { & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot } |
                Should -Throw '*native interface secure-DNS enable flags are invalid*'
        }

        It 'Should retain compatibility with sealed schema-3 DNS artifacts' {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.SchemaVersion = 3
            foreach ($family in @($snapshot.Adapters[0].Families)) {
                $family.PSObject.Properties.Remove('InterfaceDoh')
                $family.PSObject.Properties.Remove('InterfaceDohManaged')
            }
            & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot |
                Should -BeTrue
        }

        It "Should accept an unmanaged IPv6 family whose static NameServer has no effective servers" {
            # Live-proven re-apply state: the first Apply sealed IPv6 servers,
            # AdvancedSecurity later disabled the stack (DisabledComponents=0xFF),
            # so the registry value persists while the DNS client reports none.
            $snapshot = Get-TestDnsSnapshot
            $result = & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot
            $result | Should -BeTrue
        }

        It 'seals UI-visible IPv6 DoH independently when DisabledComponents suppresses transport' {
            $snapshot = Get-TestDnsSnapshot
            $ipv6 = $snapshot.Adapters[0].Families[1]
            $ipv6.Managed | Should -BeFalse
            $ipv6.InterfaceDohManaged | Should -BeTrue
            @($ipv6.ServerAddresses).Count | Should -Be 0
            @($ipv6.InterfaceDoh.NameServers) | Should -Be @('2620:fe::fe', '2620:fe::9')
            { & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot } |
                Should -Not -Throw
        }

        It 'retains compatibility with sealed schema-4 DNS artifacts' {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.SchemaVersion = 4
            foreach ($family in @($snapshot.Adapters[0].Families)) {
                $family.PSObject.Properties.Remove('InterfaceDohManaged')
            }
            $snapshot.Adapters[0].Families[1].InterfaceDoh = $null
            & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot |
                Should -BeTrue
        }

        It "Should still reject a managed family whose static NameServer has no effective servers" {
            $snapshot = Get-TestDnsSnapshot
            $snapshot.Adapters[0].Families[0].ServerAddresses = @()
            $snapshot.Adapters[0].Families[0].NameServerExisted = $true
            $snapshot.Adapters[0].Families[0].NameServerType = 'String'
            $snapshot.Adapters[0].Families[0].NameServerValue = '9.9.9.9'
            { & (Get-Module DNS) { param($InputSnapshot) Assert-DNSBackupSnapshot -Snapshot $InputSnapshot } $snapshot } |
                Should -Throw '*no effective server addresses*'
        }

        It "Should validate the full canonical provider file" {
            $configuration = & (Get-Module DNS) { Get-DnsProviderConfiguration }
            @($configuration.providers.PSObject.Properties).Count | Should -Be 3
            $configuration.default_provider | Should -Be 'quad9'
        }
    }

    Context "BAVR and verification structure" {
        It "Should preflight the complete snapshot before the first restore mutation" {
            $restorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Restore-DNSSettings.ps1'
            $content = Get-Content -LiteralPath $restorePath -Raw
            $content.IndexOf('Assert-DNSBackupSnapshot -Snapshot $snapshot') |
                Should -BeLessThan $content.IndexOf('# Restore the sole DNS policy value owned by this module.')
        }

        It "Should verify managed address families independently and in order" {
            $invokePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1'
            $content = Get-Content -LiteralPath $invokePath -Raw
            $content | Should -Match 'familyExpectations'
            $content | Should -Match 'DNS server order/readback verification failed'
            $content | Should -Not -Match 'Compare-Object -ReferenceObject \(\$adapterExpectedAddresses'
        }

        It 'Should live-validate IPv4 while proving IPv6 by family parsing and exact readback' {
            $setterPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Private/Set-DNSServers.ps1'
            $content = Get-Content -LiteralPath $setterPath -Raw
            $content | Should -Match '\$Validate -and \$target\.Label -eq ''IPv4'''
            $content | Should -Match '\[System\.Net\.IPAddress\]::TryParse'
            $content | Should -Match 'DNS server order/readback does not match the requested list'
        }

        It 'Should not repeat Windows live validation after the exact resolver pre-check already passed' {
            $invokePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1'
            $content = Get-Content -LiteralPath $invokePath -Raw
            $content | Should -Match '\$resolverConnectivityProven\s*=\s*\$false'
            $content | Should -Match '\$resolverConnectivityProven\s*=\s*\$true'
            $content | Should -Match '-Validate:\(-not \$Force -and -not \$resolverConnectivityProven\)'
            $content.IndexOf('$resolverConnectivityProven = $true') |
                Should -BeLessThan $content.IndexOf('-Validate:(-not $Force -and -not $resolverConnectivityProven)')
        }

        It 'Should avoid redundant DoH writes and use writable registry-provider mutations during restore' {
            $restorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Restore-DNSSettings.ps1'
            $content = Get-Content -LiteralPath $restorePath -Raw
            $content | Should -Match '\$alreadyExact'
            $content | Should -Match 'if \(\$alreadyExact\) \{[\s\S]*?continue'
            $content | Should -Match 'New-ItemProperty -LiteralPath \$familyState\.RegistryPath'
            $content | Should -Match '\$currentValue -cne \[string\]\$familyState\.NameServerValue'
            $content | Should -Match 'elseif \(\$registryKey\.GetValueNames\(\) -contains ''NameServer''\) \{\s*Remove-ItemProperty'
            $automaticPhase = $content.IndexOf('Where-Object { -not $_.HasStaticOverride }')
            $staticPhase = $content.IndexOf('Where-Object { $_.HasStaticOverride }', $automaticPhase)
            $registryPhase = $content.IndexOf('# Reinstate exact registry existence/type/data', $staticPhase)
            $automaticPhase | Should -BeGreaterThan -1
            $automaticPhase | Should -BeLessThan $staticPhase
            $staticPhase | Should -BeLessThan $registryPhase
            $content | Should -Not -Match '\.DeleteValue\('
            $content | Should -Not -Match '\.SetValue\('
        }

        It 'Should restore exact shared-key existence and refuse later unowned DNS state' {
            $restorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Restore-DNSSettings.ps1'
            $content = Get-Content -LiteralPath $restorePath -Raw
            $content | Should -Match 'Originally absent DNS policy key contains later unowned state'
            $content | Should -Match 'Originally absent DNS family key contains later unowned state'
            $content | Should -Match 'DNS family key acquired unowned state during restore; refusing destructive cleanup'
            $content | Should -Match '\$actualRegistryKeyExists -ne \[bool\]\$familyState\.RegistryKeyExisted'
        }

        It 'Should bind adapter identity and verify only owned static resolver order exactly' {
            $restorePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/DNS/Public/Restore-DNSSettings.ps1'
            $content = Get-Content -LiteralPath $restorePath -Raw
            $content | Should -Match 'InterfaceDescription -cne \[string\]\$adapterState\.InterfaceDescription'
            $content | Should -Match '\$hadStaticOverride = \[bool\]\$familyState\.NameServerExisted'
            $staticGuard = $content.IndexOf('if ($hadStaticOverride)')
            $addressComparison = $content.IndexOf('$expectedAddresses = @($familyState.ServerAddresses)', $staticGuard)
            $staticGuard | Should -BeGreaterThan -1
            $addressComparison | Should -BeGreaterThan $staticGuard
            $content | Should -Match '\$expectedAddresses = @\(\$familyState\.ServerAddresses\)'
            $content | Should -Match 'DNS effective static server list count verification failed'
            $content | Should -Match 'DNS effective static server order/readback verification failed'
            $content | Should -Match 'DHCP-supplied resolver addresses are observations, not'
        }

        It "Core manifest preflight should invoke the same DNS snapshot validator" {
            $rollbackPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core/Rollback.ps1'
            $content = Get-Content -LiteralPath $rollbackPath -Raw
            $content | Should -Match 'Assert-DNSBackupSnapshot -Snapshot \$json'
            $content | Should -Match 'ConvertTo-DnsCanonicalAddress\.ps1'
            $content | Should -Match 'DnsInterfaceDoh\.ps1'
            $content | Should -Match 'Restore-DNSSettings\.ps1'
            $content | Should -Match 'Restore-DNSSettings -BackupFilePath \$dnsBackupFilePath -Confirm:\$false'
            $content | Should -Not -Match 'Import-Module \$dnsModulePath'
        }

        It 'Should reconcile policy, DoH, adapter, family and NameServer prestate on both sides of sealing' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $guard = Get-Content -LiteralPath (Join-Path $repo 'Modules/DNS/Private/Assert-DNSPrestate.ps1') -Raw
            $invoke = Get-Content -LiteralPath (Join-Path $repo 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw
            $guard | Should -Match 'DoHPolicy value/type/data changed'
            $guard | Should -Match 'DoH registration changed'
            $guard | Should -Match 'DNS server order/state changed'
            $guard | Should -Match 'DNS NameServer prestate changed'
            $guard | Should -Match 'Native interface DoH state changed after DNS backup'
            ([regex]::Matches($invoke, 'Assert-DNSPrestate -Snapshot \$dnsBackupState')).Count | Should -Be 2
            $firstGuard = $invoke.IndexOf('Assert-DNSPrestate -Snapshot $dnsBackupState')
            $seal = $invoke.IndexOf('Complete-ModuleBackup', $firstGuard)
            $secondGuard = $invoke.IndexOf('Assert-DNSPrestate -Snapshot $dnsBackupState', $seal)
            $apply = $invoke.IndexOf('# Get physical adapters', $secondGuard)
            $firstGuard | Should -BeLessThan $seal
            $seal | Should -BeLessThan $secondGuard
            $secondGuard | Should -BeLessThan $apply
        }

        It "Complete verifier should use the exact five-check DNS contract without legacy fallbacks" {
            $verifierPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Tools/Verify-Complete-Hardening.ps1'
            $content = Get-Content -LiteralPath $verifierPath -Raw
            $dnsStart = $content.IndexOf('# [ALWAYS] DNS Configuration (5 checks)')
            $dnsEnd = $content.IndexOf('# [ALWAYS] Privacy Compliance Checks', $dnsStart)
            $dnsSection = $content.Substring($dnsStart, $dnsEnd - $dnsStart)
            $dnsSection | Should -Match 'Primary IPv4 resolver'
            $dnsSection | Should -Match 'Secondary IPv4 resolver'
            $dnsSection | Should -Match 'IPv6 resolver pair / sealed scope'
            $dnsSection | Should -Match 'All four selected provider endpoints registered once'
            $dnsSection | Should -Match 'Test-DNSKeepDecision'
            $dnsSection | Should -Not -Match 'ErrorAction SilentlyContinue'
            $dnsSection | Should -Match 'Get-DnsInterfaceDohState'
            $dnsSection | Should -Match 'IPv6DohManaged'
            $dnsSection | Should -Not -Match 'DohInterfaceSettings'
            $dnsSection | Should -Not -Match 'Test-Connection'
            $dnsSection | Should -Not -Match 'AddressOrigin'
        }

        It 'Should distinguish config KEEP semantics from canonical durable KEEP intent' {
            $configKeepRequire = [PSCustomObject]@{
                modules = [PSCustomObject]@{
                    DNS = [PSCustomObject]@{ provider='KEEP'; dohMode='REQUIRE' }
                }
            }
            $configKeepAllow = [PSCustomObject]@{
                modules = [PSCustomObject]@{
                    DNS = [PSCustomObject]@{ provider='KEEP'; dohMode='ALLOW' }
                }
            }
            $configTakeover = [PSCustomObject]@{
                modules = [PSCustomObject]@{
                    DNS = [PSCustomObject]@{ provider='Quad9'; dohMode='REQUIRE' }
                }
            }

            (Test-DNSKeepDecision -FrameworkConfig $configKeepRequire -DnsIntent $null) | Should -BeTrue
            (Test-DNSKeepDecision -FrameworkConfig $configKeepAllow -DnsIntent $null) | Should -BeTrue
            (Test-DNSKeepDecision -FrameworkConfig $configTakeover -DnsIntent $null) | Should -BeFalse
            (Test-DNSKeepDecision -FrameworkConfig $null -DnsIntent ([PSCustomObject]@{
                        provider='KEEP'; dohMode='KEEP'
                    })) | Should -BeTrue
            (Test-DNSKeepDecision -FrameworkConfig $null -DnsIntent ([PSCustomObject]@{
                        provider='KEEP'; dohMode='REQUIRE'
                    })) | Should -BeFalse
            (Test-DNSKeepDecision -FrameworkConfig $null -DnsIntent ([PSCustomObject]@{
                        provider='keep'; dohMode='KEEP'
                    })) | Should -BeFalse
        }

        It 'Should not treat dormant Windows DoH catalog entries as DNS takeover evidence' {
            $providers = @([PSCustomObject]@{
                    IPv4=@('9.9.9.9','149.112.112.112')
                    IPv6=@('2620:fe::fe','2620:fe::9')
                })
            $freshAdapter = [PSCustomObject]@{
                IPv4=@('10.0.2.3'); IPv6=@()
                IPv4Registry=[PSCustomObject]@{ Addresses=@() }
                IPv6Registry=[PSCustomObject]@{ Addresses=@() }
            }

            (Test-DNSManagedTakeoverEvidence -AdapterStates @($freshAdapter) `
                    -ProviderDefinitions $providers -ManagedDohPolicyPresent:$false) |
                Should -BeFalse
        }

        It 'Should detect active, persisted, and policy DNS takeover signatures' {
            $providers = @([PSCustomObject]@{
                    IPv4=@('9.9.9.9','149.112.112.112')
                    IPv6=@('2620:fe::fe','2620:fe::9')
                })
            $activeAdapter = [PSCustomObject]@{
                IPv4=@('9.9.9.9'); IPv6=@()
                IPv4Registry=[PSCustomObject]@{ Addresses=@() }
                IPv6Registry=[PSCustomObject]@{ Addresses=@() }
            }
            $persistedAdapter = [PSCustomObject]@{
                IPv4=@('10.0.2.3'); IPv6=@()
                IPv4Registry=[PSCustomObject]@{ Addresses=@('149.112.112.112') }
                IPv6Registry=[PSCustomObject]@{ Addresses=@() }
            }
            $plainAdapter = [PSCustomObject]@{
                IPv4=@('10.0.2.3'); IPv6=@()
                IPv4Registry=[PSCustomObject]@{ Addresses=@() }
                IPv6Registry=[PSCustomObject]@{ Addresses=@() }
            }

            (Test-DNSManagedTakeoverEvidence -AdapterStates @($activeAdapter) `
                    -ProviderDefinitions $providers) | Should -BeTrue
            (Test-DNSManagedTakeoverEvidence -AdapterStates @($persistedAdapter) `
                    -ProviderDefinitions $providers) | Should -BeTrue
            (Test-DNSManagedTakeoverEvidence -AdapterStates @($plainAdapter) `
                    -ProviderDefinitions $providers -ManagedDohPolicyPresent:$true) |
                Should -BeTrue
        }

        It 'Should use Microsoft native interface DNS APIs without raw DoH registry writes' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $native = Get-Content -LiteralPath (Join-Path $repo 'Modules/DNS/Private/DnsInterfaceDoh.ps1') -Raw
            $invoke = Get-Content -LiteralPath (Join-Path $repo 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw
            $restore = Get-Content -LiteralPath (Join-Path $repo 'Modules/DNS/Public/Restore-DNSSettings.ps1') -Raw
            $native | Should -Match 'GetInterfaceDnsSettings'
            $native | Should -Match 'SetInterfaceDnsSettings'
            $native | Should -Match 'FreeInterfaceDnsSettings'
            $native | Should -Match '0x1000UL'
            $native | Should -Not -Match 'DNS_DOT|0x10000UL'
            $native | Should -Not -Match 'DohInterfaceSettings|DohFlags|EnableAutoDoh'
            $invoke | Should -Match 'ConvertTo-DnsInterfaceDohTargetState'
            $invoke | Should -Match 'Set-DnsInterfaceDohState'
            $restore | Should -Match 'Set-DnsInterfaceDohState'
            $restore | Should -Match 'Clear-DnsInterfaceDohPropertiesForResolverReset'
            $restore | Should -Match 'Repeat restore: this family already holds the sealed'
            $restore | Should -Match '@\(\$currentInterfaceDoh\.Properties\)\.Count -eq 0'
            $native | Should -Match 'live Windows 11 behavior can clear the interface NameServer field'
            $restore | Should -Match 'Native interface DoH post-restore verification failed'
        }
    }
}

Describe "DNS Helper Functions" {

    Context "Get-PhysicalAdapters VPN inspection authority" {
        It 'keeps read-only inventory available but makes a missing VPN probe visible' {
            InModuleScope DNS {
                Mock Get-NetAdapter {
                    [PSCustomObject]@{
                        Name = 'Ethernet'; InterfaceAlias = 'Ethernet'
                        InterfaceDescription = 'Physical Ethernet'; Status = 'Up'
                        InterfaceType = 6; MediaType = '802.3'
                    }
                }
                Mock Get-VpnConnection { throw 'RasMan unavailable' }
                $script:adapterWarnings = @()
                Set-Item -Path function:Write-Log -Value {
                    param($Level, $Message, $Module)
                    $null = $Module
                    if ([string]$Level -eq 'WARNING') { $script:adapterWarnings += [string]$Message }
                }
                Set-Item -Path function:Write-ErrorLog -Value {
                    param($Message, $Module, $ErrorRecord)
                    $null = $Message, $Module, $ErrorRecord
                }
                try {
                    @(Get-PhysicalAdapters).Count | Should -Be 1
                    @($script:adapterWarnings | Where-Object { $_ -like '*read-only adapter inspection*' }).Count |
                        Should -Be 1
                }
                finally {
                    # Keep minimal module-local sinks for the remaining tests.
                    # Removing these names here can also remove the dynamically
                    # resolved Core logger commands from the imported module's
                    # session state, making later tests order-dependent.
                    Set-Item -Path function:Write-Log -Value {
                        param($Level, $Message, $Module)
                        $null = $Level, $Message, $Module
                    }
                    Set-Item -Path function:Write-ErrorLog -Value {
                        param($Message, $Module, $ErrorRecord)
                        $null = $Message, $Module, $ErrorRecord
                    }
                }
            }
        }

        It 'fails closed when VPN exclusion is part of a mutation scope' {
            InModuleScope DNS {
                Mock Get-NetAdapter { @() }
                Mock Get-VpnConnection { throw 'RasMan unavailable' }
                Set-Item -Path function:Write-Log -Value {
                    param($Level, $Message, $Module)
                    $null = $Level, $Message, $Module
                }
                Set-Item -Path function:Write-ErrorLog -Value {
                    param($Message, $Module, $ErrorRecord)
                    $null = $Message, $Module, $ErrorRecord
                }
                try {
                    { Get-PhysicalAdapters -RequireVpnInspection } |
                        Should -Throw '*Native VPN connection lookup was unavailable*'
                }
                finally {
                    Set-Item -Path function:Write-Log -Value {
                        param($Level, $Message, $Module)
                        $null = $Level, $Message, $Module
                    }
                    Set-Item -Path function:Write-ErrorLog -Value {
                        param($Message, $Module, $ErrorRecord)
                        $null = $Message, $Module, $ErrorRecord
                    }
                }
            }
        }
    }

    Context 'Interactive DNS decision ordering' {
        It 'shows router or LAN resolver evidence before asking which provider to select' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (
                Join-Path $repo 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw
            $menuStart = $source.IndexOf('DNS PROVIDER SELECTION', [StringComparison]::Ordinal)
            $probe = $source.IndexOf('Test-CurrentDnsUsesLanResolver', $menuStart, [StringComparison]::Ordinal)
            $choice = $source.IndexOf('Select provider [1-3, 0=Skip]', $menuStart, [StringComparison]::Ordinal)

            $menuStart | Should -BeGreaterOrEqual 0
            $probe | Should -BeGreaterThan $menuStart
            $choice | Should -BeGreaterThan $probe
            $source | Should -Match 'KEEP remains safe; selecting a replacement will repeat this check and fail closed'
        }
    }

    Context "Get-DNSStatus" {
        # Requires network environment - skipped on CI

        It "Should execute without errors" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Get-DNSStatus } } | Should -Not -Throw
        }

        It 'reports persisted IPv6 encryption without claiming disabled IPv6 transport' {
            InModuleScope DNS {
                Mock Get-DnsProviderConfiguration {
                    Get-Content (Join-Path $script:ModuleRoot 'Config\Providers.json') -Raw -Encoding UTF8 |
                        ConvertFrom-Json
                }
                Mock Get-PhysicalAdapters {
                    [PSCustomObject]@{
                        Name = 'Ethernet'; InterfaceDescription = 'Test Adapter'; Status = 'Up'
                        InterfaceIndex = 7
                        InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'
                    }
                }
                Mock Test-DNSIPv6StackEnabled { $false }
                Mock Get-NetAdapterBinding { [PSCustomObject]@{ Enabled = $true } }
                Mock Get-DnsClientServerAddress {
                    @(
                        [PSCustomObject]@{ AddressFamily = 2; ServerAddresses = @('9.9.9.9', '149.112.112.112') },
                        [PSCustomObject]@{ AddressFamily = 23; ServerAddresses = @() }
                    )
                }
                Mock Get-DnsClientDohServerAddress {
                    @('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9') |
                        ForEach-Object {
                            [PSCustomObject]@{
                                ServerAddress = $_
                                DohTemplate = 'https://dns.quad9.net/dns-query'
                                AllowFallbackToUdp = $false
                                AutoUpgrade = $true
                            }
                        }
                }
                Mock Get-DnsInterfaceDohState {
                    param($InterfaceGuid, $AddressFamily)
                    $null = $InterfaceGuid
                    $servers = if ([int]$AddressFamily -eq 2) {
                        @('9.9.9.9', '149.112.112.112')
                    }
                    else { @('2620:fe::fe', '2620:fe::9') }
                    ConvertTo-DnsInterfaceDohTargetState `
                        -AddressFamily ([int]$AddressFamily) `
                        -NameServers $servers `
                        -DohTemplate 'https://dns.quad9.net/dns-query' `
                        -AllowFallbackToUdp $false
                }
                Mock Test-Path {
                    $LiteralPath -ceq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                }
                $policyKey = [PSCustomObject]@{}
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
                    @('DoHPolicy')
                }
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
                    param($Name)
                    $null = $Name
                    [Microsoft.Win32.RegistryValueKind]::DWord
                }
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                    param($Name)
                    $null = $Name
                    3
                }
                Mock Get-Item { $policyKey }
                # A Pester proxy generated from the production logger copies
                # its module-local [LogLevel] parameter type. That type is not
                # resolvable from this imported module scope, so use a minimal
                # test-local sink instead of exercising the logger proxy.
                Set-Item -Path function:Write-Log -Value {
                    param($Level, $Message, $Module)
                    $null = $Level, $Message, $Module
                }
                Set-Item -Path function:Write-ErrorLog -Value {
                    param($Message, $Module, $ErrorRecord)
                    $null = $Message, $Module
                    throw $ErrorRecord
                }

                $status = @(Get-DNSStatus -Detailed)

                $status.Count | Should -Be 1
                $status[0].DetectedProvider | Should -BeExactly 'Quad9'
                $status[0].IPv6BindingEnabled | Should -BeTrue
                $status[0].IPv6TransportEnabled | Should -BeFalse
                $status[0].NativeIPv4Encrypted | Should -BeTrue
                $status[0].NativeIPv6Encrypted | Should -BeTrue
                $status[0].DoHConfigured | Should -BeTrue
                @($status[0].IPv6Addresses).Count | Should -Be 0
                @($status[0].NativeIPv6Addresses) | Should -Be @('2620:fe::fe', '2620:fe::9')
            }
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module DNS -Force -ErrorAction SilentlyContinue
}
