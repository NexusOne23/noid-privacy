#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:FrameworkRoot = $script:RepoRoot
    . (Join-Path $script:RepoRoot 'Core\Rollback.ps1')
    . (Join-Path $script:RepoRoot 'Core\QuickActions.ps1')
    . (Join-Path $script:RepoRoot 'Core\IntentState.ps1')

    Set-Item -Path Function:global:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    Set-Item -Path Function:global:Write-ErrorLog -Value {
        param($Message, $Module, $ErrorRecord)
        $null = $Message, $Module, $ErrorRecord
    }
    Set-Item -Path Function:global:Get-FrameworkVersion -Value { '2.2.5' }

    # Pester can mock Windows-only commands only when a command surface exists.
    # Keep the suite independently runnable on non-Windows development hosts;
    # the real Windows cmdlets always win when they are installed.
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function global:Get-CimInstance { param($ClassName) throw "Get-CimInstance is unavailable: $ClassName" }
    }
    if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
        function global:Get-NetAdapter {
            param([switch]$Physical, [switch]$IncludeHidden)
            $null = $Physical, $IncludeHidden
            throw 'Get-NetAdapter is unavailable'
        }
    }
    if (-not (Get-Command Get-NetAdapterBinding -ErrorAction SilentlyContinue)) {
        function global:Get-NetAdapterBinding {
            param($InputObject, $ComponentID)
            $null = $InputObject, $ComponentID
            throw 'Get-NetAdapterBinding is unavailable'
        }
    }
    if (-not (Get-Command Get-NetRoute -ErrorAction SilentlyContinue)) {
        function global:Get-NetRoute {
            param($DestinationPrefix, $AddressFamily)
            $null = $DestinationPrefix, $AddressFamily
            throw 'Get-NetRoute is unavailable'
        }
    }
    if (-not (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
        function global:Get-DnsClientServerAddress {
            param($InterfaceIndex)
            $null = $InterfaceIndex
            throw 'Get-DnsClientServerAddress is unavailable'
        }
    }
    if (-not (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        function global:Get-DnsClientDohServerAddress {
            param($ServerAddress)
            $null = $ServerAddress
            throw 'Get-DnsClientDohServerAddress is unavailable'
        }
    }
    if (-not (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        function global:Set-DnsClientDohServerAddress {
            param($ServerAddress, $DohTemplate, $AllowFallbackToUdp, $AutoUpgrade)
            $null = $ServerAddress, $DohTemplate, $AllowFallbackToUdp, $AutoUpgrade
            throw 'Set-DnsClientDohServerAddress is unavailable'
        }
    }
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        function global:Get-NetFirewallRule {
            param($Name)
            $null = $Name
            throw 'Get-NetFirewallRule is unavailable'
        }
    }

    function Get-TestQuickActionState {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet('Allow', 'Block')]
            [string]$State,

            [Parameter(Mandatory = $true)]
            [string]$Marker,

            # Overridable so a test can present a post-state whose unrelated
            # Defender rules CHANGED - the exact situation the guard exists for.
            [Parameter(Mandatory = $false)]
            [string]$UnrelatedFingerprint = ('a' * 64)
        )

        $payload = [ordered]@{
            actionId = 'ManagementTools'
            owningModule = 'ASR'
            state = $State
            actionable = $true
            reason = ''
            targetIds = @('registry:hklm:test:managementtools')
            targets = [ordered]@{
                marker = $Marker
                # ManagementTools/NewSoftware must prove that their shared ASR
                # mutation left every unrelated effective rule unchanged. Keep
                # the fixture contract-complete under production StrictMode.
                unrelatedEffectiveRules = [ordered]@{
                    fingerprint = $UnrelatedFingerprint
                }
            }
        }
        return [PSCustomObject][ordered]@{
            schemaVersion = 1
            actionId = $payload.actionId
            owningModule = $payload.owningModule
            state = $payload.state
            actionable = $payload.actionable
            reason = $payload.reason
            targetIds = $payload.targetIds
            targets = $payload.targets
            fingerprint = Get-QuickActionObjectSha256 -InputObject $payload
        }
    }
}

Describe 'Physical adapter helper action scope contract' {
    It 'loads the complete encrypted-DNS helper surface through the production Quick Action boundary' {
        foreach ($name in @(
                'ConvertTo-DnsCanonicalAddress',
                'ConvertTo-DnsInterfaceDohTargetState',
                'Get-DnsInterfaceDohState',
                'Get-PhysicalAdapters',
                'Set-DnsInterfaceDohState',
                'Test-DnsInterfaceDohStateExact',
                'Test-DNSIPv6StackEnabled'
            )) {
            Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because "$name must outlive the DNS state-query function scope"
        }
    }

    It 'loads the shared physical-adapter helper without a DNS module script scope' {
        Remove-Variable -Name ModuleName -Scope Script -ErrorAction SilentlyContinue
        Mock Write-Log { }
        Mock Write-ErrorLog { }
        Mock Get-NetAdapter { @() }
        @(Get-PhysicalAdapters).Count | Should -Be 0
        Should -Invoke Get-NetAdapter -Times 1 -Exactly
    }
}

Describe 'Encrypted DNS Quick Action native adapter contract' {
    BeforeEach {
        $script:TestDnsFallback = $true
        Mock Get-CimInstance {
            [PSCustomObject]@{ PartOfDomain = $false }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock Get-NetRoute {
            [PSCustomObject]@{
                DestinationPrefix = '0.0.0.0/0'; State = 'Alive'
                RouteMetric = 0; InterfaceMetric = 0; InterfaceIndex = 7
            }
        }
        Mock Get-PhysicalAdapters {
            [PSCustomObject]@{
                Name = 'Ethernet'
                InterfaceIndex = 7
                InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'
            }
        }
        Mock Get-NetAdapterBinding { [PSCustomObject]@{ Enabled = $true } }
        Mock Test-DNSIPv6StackEnabled { $true }
        Mock Get-DnsClientServerAddress {
            param([uint32[]]$InterfaceIndex)
            $null = $InterfaceIndex
            @(
                [PSCustomObject]@{
                    AddressFamily = 2
                    ServerAddresses = @('9.9.9.9', '149.112.112.112')
                },
                [PSCustomObject]@{
                    AddressFamily = 23
                    ServerAddresses = @('2620:fe::fe', '2620:fe::9')
                }
            )
        }
        Mock Get-DnsClientDohServerAddress {
            @(
                '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'
            ) | ForEach-Object {
                [PSCustomObject]@{
                    ServerAddress = $_
                    DohTemplate = 'https://dns.quad9.net/dns-query'
                    AutoUpgrade = $true
                    AllowFallbackToUdp = $script:TestDnsFallback
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
                -AllowFallbackToUdp $script:TestDnsFallback
        }
        Mock Get-QuickActionRegistryValueState {
            param($Path, $Name)
            [PSCustomObject][ordered]@{
                kind = 'RegistryValue'; path = $Path; name = $Name
                keyExisted = $true; valueExisted = $true
                originalName = $Name; type = 'DWord'; value = 2
                absentAncestorKeys = @()
            }
        }
    }

    It 'seals policy, endpoint fallback and both native address-family states' {
        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)

        $state.state | Should -BeExactly 'Allow'
        $state.actionable | Should -BeTrue
        $state.targets.resolverEvidence.providerId | Should -BeExactly 'Quad9'
        @($state.targets.resolverEvidence.interfaceDohStates).Count | Should -Be 2
        @($state.targetIds | Where-Object { $_ -like 'dns-interface:*' }) | Should -Be @(
            'dns-interface:11111111-2222-3333-4444-555555555555:2',
            'dns-interface:11111111-2222-3333-4444-555555555555:23'
        )
        { Assert-QuickActionStateArtifact -State $state } | Should -Not -Throw
    }

    It 'keeps UI-visible IPv6 in the sealed native scope when transport is disabled' {
        Mock Test-DNSIPv6StackEnabled { $false }
        Mock Get-DnsClientServerAddress {
            @(
                [PSCustomObject]@{
                    AddressFamily = 2
                    ServerAddresses = @('9.9.9.9', '149.112.112.112')
                },
                [PSCustomObject]@{
                    AddressFamily = 23
                    ServerAddresses = @()
                }
            )
        }

        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)

        $state.state | Should -BeExactly 'Allow'
        $state.actionable | Should -BeTrue
        $state.targets.resolverEvidence.activeAddresses | Should -Be @(
            '149.112.112.112', '9.9.9.9'
        )
        $state.targets.resolverEvidence.addresses | Should -Be @(
            '149.112.112.112', '9.9.9.9'
        )
        $state.targets.resolverEvidence.interfaceDohScopeVersion | Should -Be 2
        @($state.targets.resolverEvidence.interfaceDohStates).Count | Should -Be 2
        @($state.targetIds | Where-Object { $_ -like 'dns-interface:*' }) | Should -Be @(
            'dns-interface:11111111-2222-3333-4444-555555555555:2',
            'dns-interface:11111111-2222-3333-4444-555555555555:23'
        )
        { Assert-QuickActionStateArtifact -State $state } | Should -Not -Throw
    }

    It 'projects pre-split native sessions onto their exact historic family scope' {
        Mock Test-DNSIPv6StackEnabled { $false }
        Mock Get-DnsClientServerAddress {
            @(
                [PSCustomObject]@{
                    AddressFamily = 2
                    ServerAddresses = @('9.9.9.9', '149.112.112.112')
                },
                [PSCustomObject]@{ AddressFamily = 23; ServerAddresses = @() }
            )
        }
        $live = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)
        $resolver = $live.targets.resolverEvidence
        $historicInterfaces = @($resolver.interfaceDohStates | Where-Object {
                [int]$_.addressFamily -eq 2
            })
        $historic = Complete-QuickActionState `
            -ActionId EncryptedDNS `
            -OwningModule DNS `
            -State Allow `
            -Actionable:$true `
            -TargetIds @($live.targetIds | Where-Object {
                    [string]$_ -notlike 'dns-interface:*:23'
                }) `
            -Targets ([PSCustomObject][ordered]@{
                policyValue = $live.targets.policyValue
                resolverEvidence = [PSCustomObject][ordered]@{
                    kind = $resolver.kind
                    supported = $resolver.supported
                    reason = $resolver.reason
                    domainJoined = $resolver.domainJoined
                    providerId = $resolver.providerId
                    adapters = @($resolver.adapters)
                    addresses = [string[]]@($resolver.addresses)
                    activeAddresses = [string[]]@($resolver.activeAddresses)
                    managedAddresses = [string[]]@($resolver.managedAddresses)
                    registrations = @($resolver.registrations)
                    dohTemplate = $resolver.dohTemplate
                    interfaceDohStates = @($historicInterfaces)
                }
            })

        $comparable = Get-QuickActionSessionComparableState `
            -LiveState $live -SealedState $historic

        $comparable.fingerprint | Should -BeExactly $historic.fingerprint
        @($comparable.targets.resolverEvidence.interfaceDohStates).Count | Should -Be 1
        [int]$comparable.targets.resolverEvidence.interfaceDohStates[0].addressFamily |
            Should -Be 2
    }

    It 'owns a disconnected physical adapter so a later connection cannot retain stale fallback' {
        Mock Get-PhysicalAdapters {
            @(
                [PSCustomObject]@{
                    Name = 'Ethernet'
                    InterfaceIndex = 7
                    InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'
                },
                [PSCustomObject]@{
                    Name = 'Wi-Fi'
                    InterfaceIndex = 8
                    InterfaceGuid = '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
                }
            )
        }
        Mock Get-DnsClientServerAddress {
            param([uint32[]]$InterfaceIndex)
            @(
                [PSCustomObject]@{
                    AddressFamily = 2
                    ServerAddresses = @('9.9.9.9', '149.112.112.112')
                },
                [PSCustomObject]@{
                    AddressFamily = 23
                    ServerAddresses = @('2620:fe::fe', '2620:fe::9')
                }
            )
            if ([int]$InterfaceIndex[0] -lt 1) {
                throw 'Test adapter identity must remain positive'
            }
        }

        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)

        $state.actionable | Should -BeTrue
        @($state.targets.resolverEvidence.adapters).Count | Should -Be 2
        @($state.targets.resolverEvidence.adapters | Where-Object activeDefaultRoute).Count |
            Should -Be 1
        @($state.targets.resolverEvidence.interfaceDohStates).Count | Should -Be 4
        @($state.targetIds | Where-Object { $_ -like 'dns-interface:*' }).Count |
            Should -Be 4
    }

    It 'fails closed instead of attaching a provider template to an unrelated inactive resolver' {
        Mock Get-PhysicalAdapters {
            @(
                [PSCustomObject]@{
                    Name = 'Ethernet'
                    InterfaceIndex = 7
                    InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'
                },
                [PSCustomObject]@{
                    Name = 'Wi-Fi'
                    InterfaceIndex = 8
                    InterfaceGuid = '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
                }
            )
        }
        Mock Get-DnsClientServerAddress {
            param([uint32[]]$InterfaceIndex)
            if ([int]$InterfaceIndex[0] -eq 8) {
                @(
                    [PSCustomObject]@{ AddressFamily = 2; ServerAddresses = @('192.0.2.53') },
                    [PSCustomObject]@{ AddressFamily = 23; ServerAddresses = @('2001:db8::53') }
                )
            }
            else {
                @(
                    [PSCustomObject]@{
                        AddressFamily = 2
                        ServerAddresses = @('9.9.9.9', '149.112.112.112')
                    },
                    [PSCustomObject]@{
                        AddressFamily = 23
                        ServerAddresses = @('2620:fe::fe', '2620:fe::9')
                    }
                )
            }
        }

        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)

        $state.state | Should -BeExactly 'Unknown'
        $state.actionable | Should -BeFalse
        $state.reason | Should -Match 'outside the active embedded provider'
    }

    It 'fails closed when policy, endpoint fallback and Windows UI state disagree' {
        Mock Get-DnsClientDohServerAddress {
            @(
                '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'
            ) | ForEach-Object {
                [PSCustomObject]@{
                    ServerAddress = $_
                    DohTemplate = 'https://dns.quad9.net/dns-query'
                    AutoUpgrade = $true
                    AllowFallbackToUdp = $false
                }
            }
        }
        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)

        $state.state | Should -BeExactly 'Unknown'
        $state.actionable | Should -BeFalse
        $state.reason | Should -Match 'inconsistent; reapply the DNS module'
    }

    It 'applies and restores endpoint plus native adapter fallback inside the sealed scope' {
        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)
        Mock Set-DnsClientDohServerAddress { }
        Mock Set-DnsInterfaceDohState { $true }
        Mock Set-QuickActionRegistryValue { }
        Mock Restore-QuickActionRegistryValue { }

        Invoke-QuickActionScopeApply -PreState $state -DesiredState Require -Confirm:$false
        Should -Invoke Set-DnsClientDohServerAddress -Times 4 -Exactly `
            -ParameterFilter { $AllowFallbackToUdp -eq $false -and $AutoUpgrade -eq $true }
        Should -Invoke Set-DnsInterfaceDohState -Times 2 -Exactly `
            -ParameterFilter { @($Properties | Where-Object { [uint64]$_.Flags -ne 2 }).Count -eq 0 }
        Should -Invoke Set-QuickActionRegistryValue -Times 1 -Exactly `
            -ParameterFilter { [int]$Value -eq 3 }

        Restore-QuickActionScopeState -State $state -Confirm:$false
        Should -Invoke Set-DnsClientDohServerAddress -Times 4 -Exactly `
            -ParameterFilter { $AllowFallbackToUdp -eq $true -and $AutoUpgrade -eq $true }
        Should -Invoke Set-DnsInterfaceDohState -Times 2 -Exactly `
            -ParameterFilter { @($Properties | Where-Object { [uint64]$_.Flags -ne 6 }).Count -eq 0 }
        Should -Invoke Restore-QuickActionRegistryValue -Times 1 -Exactly
    }

    It 'keeps previous 2.2.5 policy-only sealed sessions comparable and restore-scoped' {
        $state = Get-QuickActionEncryptedDnsState `
            -Definition (Get-QuickActionDefinition -ActionId EncryptedDNS)
        $resolver = $state.targets.resolverEvidence
        $legacy = Complete-QuickActionState `
            -ActionId EncryptedDNS `
            -OwningModule DNS `
            -State Allow `
            -Actionable:$true `
            -TargetIds @($state.targetIds | Where-Object { $_ -notlike 'dns-interface:*' }) `
            -Targets ([PSCustomObject][ordered]@{
                policyValue = $state.targets.policyValue
                resolverEvidence = [PSCustomObject][ordered]@{
                    kind = $resolver.kind; supported = $resolver.supported
                    reason = $resolver.reason; domainJoined = $resolver.domainJoined
                    providerId = $resolver.providerId
                    adapters = @($resolver.adapters | Where-Object activeDefaultRoute |
                        ForEach-Object {
                            [PSCustomObject][ordered]@{
                                interfaceIndex = [int]$_.interfaceIndex
                                serverAddresses = [string[]]@($_.serverAddresses)
                            }
                        })
                    addresses = [string[]]@($resolver.activeAddresses)
                    registrations = @($resolver.registrations | Where-Object {
                            [string]$_.serverAddress -in [string[]]@($resolver.activeAddresses)
                        })
                }
            })

        $comparable = Get-QuickActionSessionComparableState `
            -LiveState $state `
            -SealedState $legacy
        $comparable.fingerprint | Should -BeExactly $legacy.fingerprint

        Mock Set-DnsClientDohServerAddress { throw 'Legacy restore must not own endpoint state.' }
        Mock Set-DnsInterfaceDohState { throw 'Legacy restore must not own adapter state.' }
        Mock Restore-QuickActionRegistryValue { }
        Restore-QuickActionScopeState -State $legacy -Confirm:$false
        Should -Invoke Set-DnsClientDohServerAddress -Times 0 -Exactly
        Should -Invoke Set-DnsInterfaceDohState -Times 0 -Exactly
        Should -Invoke Restore-QuickActionRegistryValue -Times 1 -Exactly
    }
}

Describe 'Quick Action closed product contract' {
    It 'defines exactly the nine owner-approved action identities and module owners' {
        $definitions = @(Get-QuickActionDefinitions)
        $definitions.Count | Should -Be 9
        @($definitions.Id) | Should -Be @(
            'ManagementTools',
            'NewSoftware',
            'EncryptedDNS',
            'BitLockerUSB',
            'RDP',
            'UPnP',
            'WirelessDisplay',
            'EdgeExtensions',
            'SmartScreen'
        )
        @($definitions.OwningModule) | Should -Be @(
            'ASR',
            'ASR',
            'DNS',
            'SecurityBaseline',
            'AdvancedSecurity',
            'AdvancedSecurity',
            'AdvancedSecurity',
            'EdgeHardening',
            'SecurityBaseline'
        )
    }

    It 'fingerprints unrelated ASR rules from the live Defender state, not from a constant' {
        # Core/QuickActions.ps1 refuses to seal a ManagementTools/NewSoftware
        # session whose post-state fingerprint of the OTHER 18 Defender rules
        # differs from the pre-state - the only thing stopping a Quick Action
        # from silently resetting LSASS credential-theft protection and friends.
        # The fixtures pin that comparison against a constant 'aaaa...' string,
        # so inverting the guard failed nothing. Prove the fingerprint really
        # moves with the unrelated rules and really ignores the acted-on rule.
        $managementToolsRule = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        $lsassRule = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        $officeRule = '3b576869-a4ec-4529-8536-b80a7769e899'
        $definition = Get-QuickActionDefinition -ActionId ManagementTools

        Mock Get-QuickActionRegistryValueState {
            [PSCustomObject][ordered]@{
                kind = 'RegistryValue'; path = [string]$Path; name = [string]$Name
                keyExisted = $false; valueExisted = $false; type = $null; value = $null
            }
        }

        function Get-TestAsrState {
            param($RuleActionPairs)
            $script:QuickActionBatchMpPreference = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids = @($RuleActionPairs.Keys)
                AttackSurfaceReductionRules_Actions = @($RuleActionPairs.Keys | ForEach-Object { $RuleActionPairs[$_] })
            }
            try {
                Get-QuickActionAsrState -Definition $definition
            }
            finally {
                $script:QuickActionBatchMpPreference = $null
            }
        }

        $baseline = Get-TestAsrState -RuleActionPairs ([ordered]@{
            $managementToolsRule = 1; $lsassRule = 1; $officeRule = 1
        })
        $lsassReset = Get-TestAsrState -RuleActionPairs ([ordered]@{
            $managementToolsRule = 1; $lsassRule = 0; $officeRule = 1
        })
        $ownRuleChanged = Get-TestAsrState -RuleActionPairs ([ordered]@{
            $managementToolsRule = 2; $lsassRule = 1; $officeRule = 1
        })

        # An unrelated rule changing MUST change the fingerprint...
        [string]$lsassReset.targets.unrelatedEffectiveRules.fingerprint |
            Should -Not -BeExactly ([string]$baseline.targets.unrelatedEffectiveRules.fingerprint) `
            -Because 'resetting LSASS protection must be visible in the unrelated-rules fingerprint'
        # ...and the acted-on rule changing must NOT, or every legitimate toggle
        # would trip its own guard.
        [string]$ownRuleChanged.targets.unrelatedEffectiveRules.fingerprint |
            Should -BeExactly ([string]$baseline.targets.unrelatedEffectiveRules.fingerprint)
        [int]$baseline.targets.unrelatedEffectiveRules.count | Should -Be 2
    }

    It 'SmartScreen state fails closed per missing policy half and reads the level behaviourally' {
        # The SmartScreen Quick Action had no behavioural test at all - only
        # regexes over the source. Drive Get-QuickActionSmartScreenState through
        # every gate with per-name mocked registry reads.
        $definition = Get-QuickActionDefinition -ActionId SmartScreen

        function Get-TestSmartScreenState {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSReviewUnusedParameter',
                '',
                Justification = 'All four parameters are consumed inside the nested Mock script block, which the rule does not traverse.'
            )]
            param($EnableValue, $EnableType, $LevelValue, $LevelType)
            Mock Get-QuickActionRegistryValueState {
                if ($Name -ceq 'EnableSmartScreen') {
                    [PSCustomObject][ordered]@{
                        kind = 'RegistryValue'; path = [string]$Path; name = [string]$Name
                        keyExisted = ($null -ne $EnableValue); valueExisted = ($null -ne $EnableValue)
                        type = $EnableType; value = $EnableValue
                    }
                }
                else {
                    [PSCustomObject][ordered]@{
                        kind = 'RegistryValue'; path = [string]$Path; name = [string]$Name
                        keyExisted = ($null -ne $LevelValue); valueExisted = ($null -ne $LevelValue)
                        type = $LevelType; value = $LevelValue
                    }
                }
            }
            Get-QuickActionSmartScreenState -Definition $definition
        }

        # EnableSmartScreen absent, wrong value, or wrong type -> not actionable,
        # with the reason that names the missing baseline.
        foreach ($broken in @(
            @{ EnableValue = $null; EnableType = $null },
            @{ EnableValue = 0; EnableType = 'DWord' },
            @{ EnableValue = 1; EnableType = 'String' }
        )) {
            $state = Get-TestSmartScreenState @broken -LevelValue 'Block' -LevelType 'String'
            [bool]$state.actionable | Should -BeFalse
            [string]$state.reason | Should -Match 'EnableSmartScreen'
            [string]$state.state | Should -BeExactly 'Unknown'
        }

        # Level absent, non-string, or outside Block/Warn -> not actionable with
        # the level reason.
        foreach ($broken in @(
            @{ LevelValue = $null; LevelType = $null },
            @{ LevelValue = 'Block'; LevelType = 'DWord' },
            @{ LevelValue = 'Off'; LevelType = 'String' }
        )) {
            $state = Get-TestSmartScreenState -EnableValue 1 -EnableType 'DWord' @broken
            [bool]$state.actionable | Should -BeFalse
            [string]$state.reason | Should -Match 'ShellSmartScreenLevel'
        }

        # Both halves valid -> the state IS the level.
        foreach ($level in @('Block', 'Warn')) {
            $state = Get-TestSmartScreenState -EnableValue 1 -EnableType 'DWord' -LevelValue $level -LevelType 'String'
            [bool]$state.actionable | Should -BeTrue
            [string]$state.state | Should -BeExactly $level
            [string]$state.reason | Should -BeNullOrEmpty
        }
    }

    It 'keeps the SmartScreen action scoped to the level value and fails closed without the policy pair' {
        $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core\QuickActions.ps1') -Raw -Encoding UTF8
        $definition = Get-QuickActionDefinition -ActionId SmartScreen
        [string]$definition.RegistryPath | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        [string]$definition.RegistryName | Should -Be 'ShellSmartScreenLevel'
        @($definition.States) | Should -Be @('Warn', 'Block')
        # Apply changes only the level; EnableSmartScreen is captured evidence.
        $source | Should -Match "'SmartScreen' \{[\s\S]*?\`$level = if \(\`$DesiredState -eq 'Block'\) \{ 'Block' \} else \{ 'Warn' \}"
        $source | Should -Match 'The EnableSmartScreen policy is not applied; apply the SecurityBaseline module first\.'
        $source | Should -Match 'ShellSmartScreenLevel is absent or has an unsupported type or value\.'
        # Restore covers the complete sealed scope, both values.
        $source | Should -Match "Restore-QuickActionRegistryValue -State \`$State\.targets\.enableValue -Confirm:\`$false"
    }

    It 'keeps the privileged backend out of the Shell menu and contains no full-module fallback' {
        $quickActions = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core\QuickActions.ps1') -Raw -Encoding UTF8
        $cli = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $framework = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core\Framework.ps1') -Raw -Encoding UTF8
        $rollback = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core\Rollback.ps1') -Raw -Encoding UTF8

        $quickActions | Should -Not -Match '\bInvoke-Hardening\b'
        $quickActions | Should -Not -Match '\bInvoke-(?:ASRRules|DNSConfiguration|SecurityBaseline|AdvancedSecurity|EdgeHardening)\b'
        $cli | Should -Not -Match '(?i)quick[\s-]?actions?|schnellaktionen?'
        $framework | Should -Match 'Core\\QuickActions\.ps1'
        $quickActions | Should -Match 'Global\\NoIDPrivacyMutationV1'
        $framework | Should -Match '\$script:NoIDMutationMutexName'
        $rollback | Should -Match '\$script:NoIDMutationMutexName'
        $rollback | Should -Match 'Restore-QuickActionSession'
        $rollback | Should -Match 'Assert-NoNewerQuickActionOverlapForModuleRestore'
    }

    It 'keeps the shipped Windows release gate on the action-scoped contract' {
        $releaseGate = Get-Content -LiteralPath (
            Join-Path $script:RepoRoot 'Docs\WINDOWS-VM-RELEASE-GATE.md'
        ) -Raw -Encoding UTF8

        $releaseGate | Should -Match 'changes only its declared target IDs'
        $releaseGate | Should -Match 'ignore that snapshot'
        $releaseGate | Should -Not -Match 'executes the complete owning BAVR module'
        $releaseGate | Should -Not -Match 'RDP/UPnP shortcuts must be unavailable'
    }

    It 'uses the same ordinal target-ID order as the GUI trust parser' {
        $state = Complete-QuickActionState `
            -ActionId EdgeExtensions `
            -OwningModule EdgeHardening `
            -State Allow `
            -Actionable:$true `
            -TargetIds @(
                'registry:HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist::1',
                'registry-value-names:HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            ) `
            -Targets ([PSCustomObject][ordered]@{ marker = 'ordinal-contract' })

        @($state.targetIds) | Should -Be @(
            'registry-value-names:HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist',
            'registry:HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist::1'
        )
        { Assert-QuickActionStateArtifact -State $state } | Should -Not -Throw
    }
}

Describe 'RDP Quick Action service-side-effect contract' {
    BeforeEach {
        Mock Get-QuickActionRegistryValueState {
            param($Path, $Name)
            [PSCustomObject][ordered]@{
                kind = 'RegistryValue'
                path = $Path
                name = $Name
                keyExisted = $true
                valueExisted = $false
                originalName = $null
                type = $null
                value = $null
                absentAncestorKeys = @()
            }
        }
        Mock Get-QuickActionFirewallGroupState {
            [PSCustomObject][ordered]@{
                kind = 'FirewallGroup'
                group = '@FirewallAPI.dll,-28752'
                rules = @(
                    [PSCustomObject][ordered]@{ name = 'RemoteDesktop-Shadow-In-TCP'; enabled = 'False' },
                    [PSCustomObject][ordered]@{ name = 'RemoteDesktop-UserMode-In-TCP'; enabled = 'False' },
                    [PSCustomObject][ordered]@{ name = 'RemoteDesktop-UserMode-In-UDP'; enabled = 'False' }
                )
            }
        }
        Mock Get-QuickActionServiceState {
            param($Name)
            [PSCustomObject][ordered]@{
                kind = 'Service'
                name = $Name
                exists = $true
                status = 'Stopped'
                startType = 'Manual'
                delayedAutoStartExists = $false
                delayedAutoStart = $null
            }
        }
    }

    It 'seals the three services Windows starts for RDP and preserves a strict v2.2.5 projection' {
        $state = Get-QuickActionRdpState -Definition (Get-QuickActionDefinition -ActionId RDP)

        $state.state | Should -Be 'Disable'
        $state.actionable | Should -BeTrue
        @($state.targets.rdpServices.name) | Should -Be @('TermService', 'SessionEnv', 'UmRdpService')
        @($state.targetIds | Where-Object { $_ -like 'service:*' }) | Should -Be @(
            'service:SessionEnv',
            'service:TermService',
            'service:UmRdpService'
        )
        { Assert-QuickActionStateArtifact -State $state } | Should -Not -Throw

        $legacy = ConvertTo-QuickActionRdpLegacyState -State $state
        @($legacy.targetIds | Where-Object { $_ -like 'service:*' }).Count | Should -Be 0
        @($legacy.targets.PSObject.Properties.Name) | Should -Not -Contain 'rdpServices'
        { Assert-QuickActionStateArtifact -State $legacy } | Should -Not -Throw
        $comparable = Get-QuickActionSessionComparableState -LiveState $state -SealedState $legacy
        $comparable.fingerprint | Should -BeExactly $legacy.fingerprint

        Mock Get-QuickActionServiceState {
            param($Name)
            [PSCustomObject][ordered]@{
                kind = 'Service'
                name = $Name
                exists = $true
                status = 'Stopped'
                startType = 'Disabled'
                delayedAutoStartExists = $false
                delayedAutoStart = $null
            }
        }
        $serviceDrift = Get-QuickActionRdpState -Definition (Get-QuickActionDefinition -ActionId RDP)
        $serviceDrift.actionable | Should -BeFalse
        $serviceDrift.state | Should -Be 'Unknown'
        $legacyComparable = Get-QuickActionSessionComparableState `
            -LiveState $serviceDrift `
            -SealedState $legacy
        $legacyComparable.fingerprint | Should -BeExactly $legacy.fingerprint `
            -Because 'v2.2.5 did not seal or own RDP service state'
        (Get-QuickActionSessionComparableState -LiveState $serviceDrift -SealedState $state).fingerprint |
            Should -Not -BeExactly $state.fingerprint `
            -Because 'new sessions must remain bound to their complete service scope'
    }

    It 'starts and stops the complete declared RDP service scope in dependency-safe order' {
        $state = Get-QuickActionRdpState -Definition (Get-QuickActionDefinition -ActionId RDP)
        Mock Set-QuickActionRegistryValue { }
        Mock Set-QuickActionFirewallGroupEnabled { }
        $script:rdpServiceRuntimeCalls = [System.Collections.Generic.List[string]]::new()
        Mock Set-QuickActionServiceRuntime {
            param($Name, $Running)
            $script:rdpServiceRuntimeCalls.Add("$Name/$Running")
        }

        Invoke-QuickActionScopeApply -PreState $state -DesiredState Enable -Confirm:$false
        Should -Invoke Set-QuickActionServiceRuntime -Times 3 -Exactly -ParameterFilter { $Running -eq $true }
        @($script:rdpServiceRuntimeCalls) | Should -Be @(
            'TermService/True', 'SessionEnv/True', 'UmRdpService/True'
        )

        $script:rdpServiceRuntimeCalls.Clear()
        Invoke-QuickActionScopeApply -PreState $state -DesiredState Disable -Confirm:$false
        Should -Invoke Set-QuickActionServiceRuntime -Times 3 -Exactly -ParameterFilter { $Running -eq $false }
        @($script:rdpServiceRuntimeCalls) | Should -Be @(
            'SessionEnv/False', 'UmRdpService/False', 'TermService/False'
        )
    }

    It 'restores all new RDP service evidence while leaving legacy session scope unchanged' {
        $state = Get-QuickActionRdpState -Definition (Get-QuickActionDefinition -ActionId RDP)
        $legacy = ConvertTo-QuickActionRdpLegacyState -State $state
        Mock Set-QuickActionRegistryValue { }
        Mock Restore-QuickActionRegistryValue { }
        Mock Restore-QuickActionFirewallGroupState { }
        Mock Restore-QuickActionServiceState { }

        Restore-QuickActionScopeState -State $state -Confirm:$false
        Should -Invoke Restore-QuickActionServiceState -Times 3 -Exactly

        Restore-QuickActionScopeState -State $legacy -Confirm:$false
        Should -Invoke Restore-QuickActionServiceState -Times 3 -Exactly
    }
}

Describe 'Quick Action batched named-firewall snapshot' {
    It 'produces byte-identical named-firewall states from the real snapshot builder' {
        # The 2.2.5 firewall-cache lesson: exercise the REAL builder against
        # the live per-name path and compare complete canonical values, under
        # StrictMode, so a silent null-append or unwrapped one-element list
        # can never hide again.
        Set-StrictMode -Version Latest
        try {
            # Decide "can this session read the firewall store at all?" ONCE, with a
            # single guarded probe, and skip only on that. The exercise below must
            # not sit in a catch that skips: a null append or an unwrapped
            # one-element list in the builder - precisely the 2.2.5 regression this
            # test exists to catch - raises under StrictMode, and skipping on it
            # turned the only behavioural proof of the snapshot into a green skip.
            try {
                $null = Get-NetFirewallRule -ErrorAction Stop | Select-Object -First 1
            }
            catch {
                Set-ItResult -Skipped -Because "live firewall queries are unavailable here: $($_.Exception.Message)"
                return
            }

            $script:QuickActionBatchNamedFirewallRules = $null
            try {
                $live = @(
                    Get-QuickActionNamedFirewallState -SetName UPnP
                    Get-QuickActionNamedFirewallState -SetName WirelessDisplay
                )
                $script:QuickActionBatchNamedFirewallRules = Get-QuickActionNamedFirewallRuleSnapshot
                $batched = @(
                    Get-QuickActionNamedFirewallState -SetName UPnP
                    Get-QuickActionNamedFirewallState -SetName WirelessDisplay
                )
            }
            finally {
                $script:QuickActionBatchNamedFirewallRules = $null
            }

            (ConvertTo-QuickActionCanonicalJson -InputObject $batched) |
                Should -BeExactly (ConvertTo-QuickActionCanonicalJson -InputObject $live)
        }
        finally {
            Set-StrictMode -Off
        }
    }

    It 'consumes the snapshot without any live per-name query and keeps the ambiguity guard' {
        Mock Get-NetFirewallRule { throw 'The batched read must not query live rules.' }
        try {
            $script:QuickActionBatchNamedFirewallRules =
                [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)

            $state = Get-QuickActionNamedFirewallState -SetName UPnP
            @($state.rules).Count | Should -Be 2
            @($state.rules | Where-Object { [bool]$_.exists }).Count | Should -Be 0

            $script:QuickActionBatchNamedFirewallRules['NoID-Block-SSDP-UDP-1900'] = @(
                [PSCustomObject]@{ Name = 'NoID-Block-SSDP-UDP-1900' },
                [PSCustomObject]@{ Name = 'NoID-Block-SSDP-UDP-1900' }
            )
            { Get-QuickActionNamedFirewallState -SetName UPnP } |
                Should -Throw '*ambiguous*'
            Should -Invoke Get-NetFirewallRule -Times 0 -Exactly
        }
        finally {
            $script:QuickActionBatchNamedFirewallRules = $null
        }
    }

    It 'keeps the firewall snapshot batch-scoped exactly like the Defender snapshot' {
        $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core\QuickActions.ps1') -Raw -Encoding UTF8

        ([regex]::Matches(
            $source,
            '\$script:QuickActionBatchNamedFirewallRules\s*=\s*Get-QuickActionNamedFirewallRuleSnapshot'
        )).Count | Should -Be 1
        # Cleared in the batch finally block alongside the Defender snapshot.
        $source | Should -Match '(?s)finally \{\s*\$script:QuickActionBatchMpPreference = \$null\s*\$script:QuickActionBatchMpPreferenceError = \$null\s*\$script:QuickActionBatchNamedFirewallRules = \$null\s*\}\s*return @\(\$results\.ToArray\(\)\)'
    }
}

Describe 'Quick Action optimistic concurrency and no-op behavior' {
    BeforeEach {
        $script:CurrentQuickActionState = Get-TestQuickActionState -State Allow -Marker current
        Mock Get-QuickActionState { $script:CurrentQuickActionState }
        Mock Update-NoIDQuickActionIntentState { $true }
        Mock New-QuickActionPreparedSession { throw 'Backup must not be created in this test' }
        Mock Invoke-QuickActionScopeApply { throw 'Mutation must not start in this test' }
    }

    It 'fails closed on a stale displayed fingerprint before Backup or mutation' {
        $result = Invoke-QuickAction `
            -ActionId ManagementTools `
            -DesiredState Block `
            -ExpectedFingerprint ('b' * 64) `
            -Confirm:$false

        $result.success | Should -BeFalse
        $result.mutated | Should -BeFalse
        $result.verified | Should -BeFalse
        $result.backupPath | Should -Be ''
        $result.error | Should -Match 'state changed after it was displayed'
        Should -Invoke New-QuickActionPreparedSession -Times 0 -Exactly
        Should -Invoke Invoke-QuickActionScopeApply -Times 0 -Exactly
    }

    It 'returns a verified no-op without creating a backup' {
        $result = Invoke-QuickAction `
            -ActionId ManagementTools `
            -DesiredState Allow `
            -ExpectedFingerprint $script:CurrentQuickActionState.fingerprint `
            -Confirm:$false

        $result.success | Should -BeTrue
        $result.status | Should -Be 'NoChange'
        $result.mutated | Should -BeFalse
        $result.verified | Should -BeTrue
        $result.backupPath | Should -Be ''
        $result.preFingerprint | Should -Be $result.postFingerprint
        Should -Invoke New-QuickActionPreparedSession -Times 0 -Exactly
        Should -Invoke Invoke-QuickActionScopeApply -Times 0 -Exactly
    }

    It 'does not mutate an unknown or non-actionable state' {
        $script:CurrentQuickActionState.actionable = $false
        $script:CurrentQuickActionState.reason = 'Resolver support is not proven.'

        $result = Invoke-QuickAction `
            -ActionId ManagementTools `
            -DesiredState Block `
            -ExpectedFingerprint $script:CurrentQuickActionState.fingerprint `
            -Confirm:$false

        $result.success | Should -BeFalse
        $result.mutated | Should -BeFalse
        $result.error | Should -Match 'not actionable'
        Should -Invoke New-QuickActionPreparedSession -Times 0 -Exactly
        Should -Invoke Invoke-QuickActionScopeApply -Times 0 -Exactly
    }

    It 'fails the Apply and compensates when the mutation changed unrelated ASR rules' {
        # The one thing standing between a ManagementTools/NewSoftware toggle and
        # a silent reset of the other 18 Defender rules is the fingerprint guard
        # after Wait-QuickActionState. Every other fixture in this file keeps the
        # fingerprints equal, so inverting or deleting that guard failed nothing.
        Mock New-QuickActionPreparedSession {
            [PSCustomObject]@{ SessionPath = Join-Path $TestDrive 'Session_unrelated_mutated' }
        }
        Mock Invoke-QuickActionScopeApply {
            # Reaches the requested state, but the unrelated-rules fingerprint
            # moved: the mutation touched rules it does not own.
            $script:CurrentQuickActionState = Get-TestQuickActionState `
                -State Block -Marker post -UnrelatedFingerprint ('c' * 64)
        }
        Mock Wait-QuickActionState { $script:CurrentQuickActionState }
        Mock Complete-QuickActionSession { throw 'a session that mutated unrelated rules must never be sealed as Applied' }
        Mock Restore-QuickActionScopeState {
            $script:CurrentQuickActionState = Get-TestQuickActionState -State Allow -Marker current
        }
        Mock Set-QuickActionFailedSessionStatus { }

        $preFingerprint = $script:CurrentQuickActionState.fingerprint
        $result = Invoke-QuickAction `
            -ActionId ManagementTools `
            -DesiredState Block `
            -ExpectedFingerprint $preFingerprint `
            -Confirm:$false

        $result.success | Should -BeFalse
        $result.error | Should -Match 'unrelated effective ASR rules'
        $result.mutated | Should -BeTrue
        $result.status | Should -BeExactly 'ApplyFailedRolledBack'
        Should -Invoke Restore-QuickActionScopeState -Times 1 -Exactly
        Should -Invoke Set-QuickActionFailedSessionStatus -Times 1 -Exactly -ParameterFilter {
            $Status -ceq 'ApplyFailedRolledBack'
        }
    }

    It 'keeps a verified Apply successful when optional intent maintenance fails' {
        Mock New-QuickActionPreparedSession {
            [PSCustomObject]@{ SessionPath = Join-Path $TestDrive 'Session_apply_verified' }
        }
        Mock Invoke-QuickActionScopeApply {
            $script:CurrentQuickActionState = Get-TestQuickActionState -State Block -Marker post
        }
        Mock Wait-QuickActionState { $script:CurrentQuickActionState }
        Mock Complete-QuickActionSession { $true }
        Mock Get-QuickActionSessionDocument { [PSCustomObject]@{} }
        Mock Update-NoIDQuickActionIntentState { throw 'intent store unavailable' }
        Mock Restore-QuickActionScopeState { throw 'verified Apply must not be compensated' }
        Mock Set-QuickActionFailedSessionStatus { }

        $result = Invoke-QuickAction `
            -ActionId ManagementTools `
            -DesiredState Block `
            -ExpectedFingerprint $script:CurrentQuickActionState.fingerprint `
            -Confirm:$false

        $result.success | Should -BeTrue -Because $result.error
        $result.status | Should -BeExactly 'Applied'
        $result.mutated | Should -BeTrue
        $result.verified | Should -BeTrue
        Should -Invoke Complete-QuickActionSession -Times 1 -Exactly
        Should -Invoke Update-NoIDQuickActionIntentState -Times 1 -Exactly
        Should -Invoke Restore-QuickActionScopeState -Times 0 -Exactly
        Should -Invoke Set-QuickActionFailedSessionStatus -Times 0 -Exactly
    }
}

Describe 'Quick Action sealed session listing and receipt binding' {
    It 'writes receipt scopes in the GUI validator ordinal order' {
        $backupRoot = Join-Path $TestDrive 'OrdinalReceipt'
        $pre = Get-TestQuickActionState -State Allow -Marker pre
        $post = Get-TestQuickActionState -State Block -Marker post
        $prepared = New-QuickActionPreparedSession `
            -PreState $pre `
            -DesiredState Block `
            -BackupDirectory $backupRoot `
            -Confirm:$false
        $manifest = Complete-QuickActionSession `
            -PreparedSession $prepared `
            -PostState $post `
            -Confirm:$false

        $receipt = Write-SessionRestoreReceipt `
            -SessionPath $prepared.SessionPath `
            -Manifest $manifest `
            -Scopes @(
                'module:AntiAI'
                'module:AdvancedSecurity'
                'module:ASR'
                'module:AntiAI'
            ) `
            -Confirm:$false

        @($receipt.restoredScopes).Count | Should -Be 3
        [string]$receipt.restoredScopes[0] | Should -BeExactly 'module:ASR'
        [string]$receipt.restoredScopes[1] | Should -BeExactly 'module:AdvancedSecurity'
        [string]$receipt.restoredScopes[2] | Should -BeExactly 'module:AntiAI'
    }

    It 'lists an applied action as restorable and its exact receipt as completed' {
        $backupRoot = Join-Path $TestDrive 'Backups'
        $pre = Get-TestQuickActionState -State Allow -Marker pre
        $post = Get-TestQuickActionState -State Block -Marker post
        $prepared = New-QuickActionPreparedSession `
            -PreState $pre `
            -DesiredState Block `
            -BackupDirectory $backupRoot `
            -Confirm:$false
        $manifest = Complete-QuickActionSession `
            -PreparedSession $prepared `
            -PostState $post `
            -Confirm:$false
        Mock Get-QuickActionState { $post }

        $before = @(Get-BackupSessions -BackupDirectory $backupRoot)
        $before.Count | Should -Be 1
        $before[0].SessionType | Should -Be 'quickAction'
        $before[0].Restorable | Should -BeTrue
        $before[0].RetentionKind | Should -Be 'QuickActionSealed'
        $before[0].Modules[0].actionId | Should -Be 'ManagementTools'

        $null = Write-SessionRestoreReceipt `
            -SessionPath $prepared.SessionPath `
            -Manifest $manifest `
            -Scopes @('action:ManagementTools') `
            -Confirm:$false

        $after = @(Get-BackupSessions -BackupDirectory $backupRoot)
        $after.Count | Should -Be 1
        $after[0].Restorable | Should -BeFalse
        $after[0].ValidationStatus | Should -Be 'RestoredAndValidated'
        $after[0].RetentionKind | Should -Be 'QuickActionRestored'
        $after[0].ValidationError | Should -Match 'already been restored'
    }

    It 'rejects a receipt whose valid generic syntax names the wrong scope type' {
        $backupRoot = Join-Path $TestDrive 'WrongScope'
        $pre = Get-TestQuickActionState -State Allow -Marker pre
        $post = Get-TestQuickActionState -State Block -Marker post
        $prepared = New-QuickActionPreparedSession `
            -PreState $pre `
            -DesiredState Block `
            -BackupDirectory $backupRoot `
            -Confirm:$false
        $manifest = Complete-QuickActionSession `
            -PreparedSession $prepared `
            -PostState $post `
            -Confirm:$false
        $null = Write-SessionRestoreReceipt `
            -SessionPath $prepared.SessionPath `
            -Manifest $manifest `
            -Scopes @('module:ASR') `
            -Confirm:$false

        { Get-QuickActionSessionDocument -SessionPath $prepared.SessionPath } |
            Should -Throw '*one exact action scope*'

        $listed = @(Get-BackupSessions -BackupDirectory $backupRoot)
        $listed.Count | Should -Be 1
        $listed[0].Restorable | Should -BeFalse
        $listed[0].RetentionKind | Should -Be 'QuickActionInvalidOrUnsealed'
    }

    It 'retains a failed prepared action as visible but non-restorable' {
        $backupRoot = Join-Path $TestDrive 'Failed'
        $pre = Get-TestQuickActionState -State Allow -Marker pre
        $prepared = New-QuickActionPreparedSession `
            -PreState $pre `
            -DesiredState Block `
            -BackupDirectory $backupRoot `
            -Confirm:$false
        Set-QuickActionFailedSessionStatus `
            -PreparedSession $prepared `
            -Status ApplyFailedRolledBack `
            -Confirm:$false

        $listed = @(Get-BackupSessions -BackupDirectory $backupRoot)
        $listed.Count | Should -Be 1
        $listed[0].DisplayName | Should -Be 'Quick Action: ManagementTools -> Block'
        $listed[0].SessionType | Should -Be 'quickAction'
        $listed[0].Restorable | Should -BeFalse
        $listed[0].RetentionKind | Should -Be 'QuickActionInvalidOrUnsealed'
        $listed[0].Modules[0].status | Should -Be 'ApplyFailedRolledBack'
    }
}

Describe 'Quick Action restore fail-closed guards' {
    BeforeEach {
        $preState = Get-TestQuickActionState -State Allow -Marker pre
        $postState = Get-TestQuickActionState -State Block -Marker post
        $script:RestoreDocument = [PSCustomObject]@{
            SessionPath = Join-Path $TestDrive 'Session_test_QuickAction_ManagementTools'
            Manifest = [PSCustomObject]@{
                sessionId = 'Session_test_QuickAction_ManagementTools'
                actionId = 'ManagementTools'
            }
            PreState = $preState
            PostState = $postState
        }
        $script:LiveRestoreState = $postState
        Mock Get-QuickActionSessionDocument { $script:RestoreDocument }
        Mock Get-SessionRestoreReceipt { $null }
        Mock Assert-NoNewerOverlapForQuickActionRestore { }
        Mock Get-QuickActionState { $script:LiveRestoreState }
        Mock Restore-QuickActionScopeState {
            param($State)
            $script:LiveRestoreState = $State
        }
        Mock Write-SessionRestoreReceipt { }
        Mock Update-NoIDQuickActionIntentState { $true }
    }

    It 'refuses current-state drift before restoring any target' {
        $script:LiveRestoreState = Get-TestQuickActionState -State Allow -Marker foreign
        Restore-QuickActionSession -SessionPath $script:RestoreDocument.SessionPath -Confirm:$false |
            Should -BeFalse

        Should -Invoke Restore-QuickActionScopeState -Times 0 -Exactly
        Should -Invoke Write-SessionRestoreReceipt -Times 0 -Exactly
    }

    It 'treats an already receipted action restore as idempotent success before reading live state' {
        Mock Get-SessionRestoreReceipt {
            [PSCustomObject]@{ restoredScopes = @('action:ManagementTools') }
        }

        Restore-QuickActionSession -SessionPath $script:RestoreDocument.SessionPath -Confirm:$false |
            Should -BeTrue

        Should -Invoke Get-QuickActionState -Times 0 -Exactly
        Should -Invoke Restore-QuickActionScopeState -Times 0 -Exactly
        Should -Invoke Update-NoIDQuickActionIntentState -Times 0 -Exactly
    }

    It 'removes an unproven receipt candidate before compensating to the sealed poststate' {
        Mock Write-SessionRestoreReceipt { throw 'receipt publication failed' }

        Restore-QuickActionSession -SessionPath $script:RestoreDocument.SessionPath -Confirm:$false |
            Should -BeFalse

        $script:LiveRestoreState.fingerprint | Should -Be $script:RestoreDocument.PostState.fingerprint
        Should -Invoke Restore-QuickActionScopeState -Times 2 -Exactly
        Should -Invoke Write-SessionRestoreReceipt -Times 1 -Exactly
    }

    It 'never compensates when a failed receipt candidate cannot be removed safely' {
        Mock Write-SessionRestoreReceipt { throw 'receipt publication failed' }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*restore-receipt.json' }
        Mock Remove-Item { throw 'receipt locked' }

        Restore-QuickActionSession -SessionPath $script:RestoreDocument.SessionPath -Confirm:$false |
            Should -BeFalse

        $script:LiveRestoreState.fingerprint | Should -Be $script:RestoreDocument.PreState.fingerprint
        Should -Invoke Restore-QuickActionScopeState -Times 1 -Exactly
    }

    It 'does not rewrite a valid restore receipt from historical intent evidence' {
        Mock Get-SessionRestoreReceipt {
            [PSCustomObject]@{ restoredScopes = @('action:ManagementTools') }
        }
        Mock Update-NoIDQuickActionIntentState { throw 'intent store unavailable' }

        Restore-QuickActionSession -SessionPath $script:RestoreDocument.SessionPath -Confirm:$false |
            Should -BeTrue

        Should -Invoke Get-QuickActionState -Times 0 -Exactly
        Should -Invoke Restore-QuickActionScopeState -Times 0 -Exactly
        Should -Invoke Update-NoIDQuickActionIntentState -Times 0 -Exactly
    }

    It 'maps cross-owned ASR targets to the SecurityBaseline restore scope' {
        @(Get-QuickActionModuleRestoreScopes -ActionId ManagementTools) |
            Should -Be @('ASR', 'SecurityBaseline')
        @(Get-QuickActionModuleRestoreScopes -ActionId NewSoftware) |
            Should -Be @('ASR', 'SecurityBaseline')
        @(Get-QuickActionModuleRestoreScopes -ActionId RDP) |
            Should -Be @('AdvancedSecurity')
    }
}

Describe 'Quick Action newer-overlap receipt validation' {
    It 'blocks a restore when a relevant newer session has invalid receipt evidence' {
        $backupRoot = Join-Path $TestDrive 'overlap-root'
        $selectedPath = Join-Path $backupRoot 'Session_20260815_120000_000_11111111'
        $newerPath = Join-Path $backupRoot 'Session_20260815_120100_000_22222222'
        $null = New-Item -ItemType Directory -Path $selectedPath, $newerPath -Force
        $candidate = [ordered]@{
            schemaVersion = 3
            recordType = 'QuickActionSession'
            sessionId = 'Session_20260815_120100_000_22222222'
            timestamp = '2026-08-15T12:01:00.0000000Z'
            actionId = 'ManagementTools'
            owningModule = 'ASR'
            restorable = $true
            targetIds = @('registry:hklm:test:managementtools')
        }
        $candidate | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $newerPath 'manifest.json') -Encoding UTF8
        $selected = [PSCustomObject]@{
            SessionPath = $selectedPath
            Manifest = [PSCustomObject]@{
                schemaVersion = 3
                recordType = 'QuickActionSession'
                sessionId = 'Session_20260815_120000_000_11111111'
                timestamp = '2026-08-15T12:00:00.0000000Z'
                actionId = 'ManagementTools'
                owningModule = 'ASR'
                restorable = $true
                targetIds = @('registry:hklm:test:managementtools')
            }
        }
        Mock Get-SessionRestoreReceipt { throw 'receipt hash mismatch' }

        { Assert-NoNewerOverlapForQuickActionRestore -SelectedDocument $selected } |
            Should -Throw '*newer overlapping Quick Action has invalid restore evidence*'
    }
}
