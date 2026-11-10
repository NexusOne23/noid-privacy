#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $helperPath = Join-Path $repoRoot 'Modules/AdvancedSecurity/Private/AdvancedSecurityNetBIOS.ps1'

    # Non-Windows parser/unit runners do not expose the Windows NetAdapter
    # cmdlet. Define only the command surface Pester must mock, then remove it.
    $script:AddedGetNetAdapterStub = -not [bool](Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)
    if ($script:AddedGetNetAdapterStub) {
        function global:Get-NetAdapter {
            [CmdletBinding()]
            param([switch]$IncludeHidden)
            $null = $IncludeHidden
            throw 'Get-NetAdapter test stub was not mocked'
        }
    }

    . (Join-Path (Join-Path $repoRoot 'Core') 'Runtime.ps1')
    . $helperPath

    function Get-NetBIOSTestRegistryKey {
        param(
            [Parameter(Mandatory = $true)][bool]$ValueExists,
            [Parameter(Mandatory = $false)][string]$Type = 'DWord',
            [Parameter(Mandatory = $false)]$Value = 0
        )
        $key = [PSCustomObject]@{
            HasValue = $ValueExists
            Kind = $Type
            Data = $Value
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
            if ($this.HasValue) { return @('NetbiosOptions') }
            return @()
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
            param($Name)
            if ($Name -cne 'NetbiosOptions' -or -not $this.HasValue) { throw 'missing test value' }
            return $this.Kind
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
            param($Name, $DefaultValue, $Options)
            $null = $Options
            if ($Name -cne 'NetbiosOptions' -or -not $this.HasValue) { return $DefaultValue }
            return $this.Data
        }
        return $key
    }
}

Describe 'AdvancedSecurity offline NetBIOS targeting' {
    BeforeEach {
        $script:NetBIOSTestKey = Get-NetBIOSTestRegistryKey -ValueExists $true -Type DWord -Value 0
        $script:PhysicalGuid = '{11111111-1111-1111-1111-111111111111}'
        $script:VirtualGuid = '{22222222-2222-2222-2222-222222222222}'

        Mock Get-NetAdapter {
            @([PSCustomObject]@{
                    Name = 'Ethernet'
                    InterfaceGuid = $script:PhysicalGuid
                    InterfaceDescription = 'Physical test NIC'
                    HardwareInterface = $true
                    Status = 'Disconnected'
                })
        }
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    Description = 'Physical test NIC'; Index = 1; InterfaceIndex = 10
                    SettingID = $script:PhysicalGuid; IPEnabled = $false; TcpipNetbiosOptions = $null
                },
                [PSCustomObject]@{
                    Description = 'Active virtual test NIC'; Index = 2; InterfaceIndex = 20
                    SettingID = $script:VirtualGuid; IPEnabled = $true; TcpipNetbiosOptions = 1
                }
            )
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*NetBT*Tcpip_*' }
        Mock Test-NoIDRegistryKey { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*NetBT*Tcpip_*' }
        Mock Get-Item { $script:NetBIOSTestKey } -ParameterFilter { $LiteralPath -like 'HKLM:*NetBT*Tcpip_*' }
    }

    It 'includes a link-down physical adapter in addition to active configurations' {
        $state = Get-AdvancedSecurityNetBIOSState

        $state.SchemaVersion | Should -Be 2
        @($state.Adapters).Count | Should -Be 2
        $physical = @($state.Adapters | Where-Object SettingID -eq $script:PhysicalGuid)[0]
        $physical.PhysicalAdapter | Should -BeTrue
        $physical.IPEnabled | Should -BeFalse
        $physical.PhysicalAdapterStatus | Should -Be 'Disconnected'
        $physical.RegistryValueExists | Should -BeTrue
        $physical.RegistryValueType | Should -Be 'DWord'
        $physical.RegistryValue | Should -Be 0
    }

    It 'seals a non-DWORD prestate without pretending it is already compliant' {
        $script:NetBIOSTestKey = Get-NetBIOSTestRegistryKey `
            -ValueExists $true -Type String -Value 'owner-prestate'

        $state = Get-AdvancedSecurityNetBIOSState

        { Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $state } | Should -Not -Throw
        @($state.Adapters | Where-Object RegistryValueType -eq 'String').Count | Should -Be 2
        (Test-AdvancedSecurityNetBIOSDisabled).Compliant | Should -BeFalse
    }

    It 'records a not-present physical adapter without a configuration as a registry-only target' {
        # Field values from a real report: an HP 5G modem's mobile-broadband
        # interfaces stay listed as not present and have no
        # Win32_NetworkAdapterConfiguration. 2.2.6 and 2.2.7 aborted here.
        $script:GhostGuid = '{F4722628-BB61-45E8-93E1-BE039309D62F}'
        Mock Get-NetAdapter {
            @(
                [PSCustomObject]@{
                    Name = 'Mobilfunk 7'; InterfaceGuid = $script:GhostGuid
                    InterfaceDescription = 'HP 5G Sub-6 Cat19'; InterfaceIndex = 33
                    HardwareInterface = $true; Status = 'Not Present'; InterfaceOperationalStatus = 6
                },
                [PSCustomObject]@{
                    Name = 'Ethernet'; InterfaceGuid = $script:PhysicalGuid
                    InterfaceDescription = 'Physical test NIC'; InterfaceIndex = 10
                    HardwareInterface = $true; Status = 'Disconnected'; InterfaceOperationalStatus = 2
                }
            )
        }

        $state = Get-AdvancedSecurityNetBIOSState

        @($state.Adapters).Count | Should -Be 3
        $ghost = @($state.Adapters | Where-Object SettingID -eq $script:GhostGuid)[0]
        $ghost.PhysicalAdapter | Should -BeTrue
        $ghost.IPEnabled | Should -BeFalse
        $ghost.Index | Should -BeNullOrEmpty
        $ghost.InterfaceIndex | Should -Be 33
        $ghost.Description | Should -BeExactly 'HP 5G Sub-6 Cat19'
        $ghost.PhysicalAdapterName | Should -BeExactly 'Mobilfunk 7'
        $ghost.PhysicalAdapterStatus | Should -BeExactly 'Not Present'
        $ghost.TcpipNetbiosOptions | Should -BeNullOrEmpty
        $ghost.RegistryPath | Should -BeLike "*\Tcpip_$script:GhostGuid"
        { Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $state } | Should -Not -Throw
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $state -Candidate $state | Should -BeTrue

        # A reconnect between backup and Apply changes link status, IP binding
        # and indexes. The backup-window checks compare adapter identities and
        # the owned NetBT values only; a changed value is still drift.
        $reconnected = $state | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $moved = @($reconnected.Adapters | Where-Object SettingID -eq $script:GhostGuid)[0]
        $moved.PhysicalAdapterStatus = 'Up'
        $moved.InterfaceIndex = 34
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $state -Candidate $reconnected | Should -BeFalse
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $state -Candidate $reconnected -ConfigurationOnly | Should -BeTrue
        $owned = @($reconnected.Adapters | Where-Object { [bool]$_.RegistryValueExists })[0]
        $owned | Should -Not -BeNullOrEmpty
        $owned.RegistryValue = [int]$owned.RegistryValue + 1
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $state -Candidate $reconnected -ConfigurationOnly | Should -BeFalse

        $canonical = ConvertFrom-Json (ConvertTo-AdvancedSecurityNetBIOSCanonicalJson -Snapshot $state)
        @($canonical | Where-Object SettingID -eq $script:GhostGuid)[0].Index | Should -BeNullOrEmpty

        $verification = Test-AdvancedSecurityNetBIOSDisabled
        $verification.Compliant | Should -BeFalse
        @($verification.NonCompliant | Where-Object SettingID -eq $script:GhostGuid).Count | Should -Be 1
        $script:NetBIOSTestKey = Get-NetBIOSTestRegistryKey -ValueExists $true -Type DWord -Value 2
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    Description = 'Physical test NIC'; Index = 1; InterfaceIndex = 10
                    SettingID = $script:PhysicalGuid; IPEnabled = $false; TcpipNetbiosOptions = 2
                },
                [PSCustomObject]@{
                    Description = 'Active virtual test NIC'; Index = 2; InterfaceIndex = 20
                    SettingID = $script:VirtualGuid; IPEnabled = $true; TcpipNetbiosOptions = 2
                }
            )
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        (Test-AdvancedSecurityNetBIOSDisabled).Compliant | Should -BeTrue
    }

    It 'still rejects a physical adapter without a stable identity' {
        Mock Get-NetAdapter {
            @([PSCustomObject]@{
                    Name = 'Broken'; InterfaceGuid = ''; InterfaceDescription = 'No identity'
                    HardwareInterface = $true; Status = 'Not Present'; InterfaceOperationalStatus = 6
                })
        }

        { Get-AdvancedSecurityNetBIOSState } | Should -Throw '*has no stable InterfaceGuid*'
    }
}

AfterAll {
    if ($script:AddedGetNetAdapterStub) {
        Remove-Item Function:\Get-NetAdapter -Force -ErrorAction SilentlyContinue
    }
}
