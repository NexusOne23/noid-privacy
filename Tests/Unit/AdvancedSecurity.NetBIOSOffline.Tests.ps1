#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $helperPath = Join-Path $repoRoot 'Modules/AdvancedSecurity/Private/AdvancedSecurityNetBIOS.ps1'

    # Fedora-based parser/unit runners do not expose the Windows NetAdapter
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

    It 'fails closed when a present physical adapter has no matching configuration identity' {
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                    Description = 'Different adapter'; Index = 2; InterfaceIndex = 20
                    SettingID = $script:VirtualGuid; IPEnabled = $true; TcpipNetbiosOptions = 1
                })
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }

        { Get-AdvancedSecurityNetBIOSState } |
            Should -Throw '*has no matching Win32_NetworkAdapterConfiguration*'
    }
}

AfterAll {
    if ($script:AddedGetNetAdapterStub) {
        Remove-Item Function:\Get-NetAdapter -Force -ErrorAction SilentlyContinue
    }
}
