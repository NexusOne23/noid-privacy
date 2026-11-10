#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityNetBIOS.ps1')
    function Write-Log {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
        [CmdletBinding()] param($Level,$Message,$Module) $null=$Level,$Message,$Module
    }
    function Get-PresenceTestValue {
        param([Parameter(Mandatory = $true)][string]$Guid)
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PresenceSubkey + '\Tcpip_' + $Guid)
        if ($null -eq $key) { return 'no key' }
        try {
            if ($key.GetValueNames() -notcontains 'NetbiosOptions') { return 'no value' }
            return '{0}:{1}' -f $key.GetValueKind('NetbiosOptions'), $key.GetValue('NetbiosOptions')
        }
        finally { $key.Dispose() }
    }
}

Describe 'NetBIOS exact typed registry restore' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        # Real registry values, isolated from every network adapter. Only the
        # adapter discovery transport is mocked; Apply/Restore use the provider.
        $script:TypedNetBiosSubkey = 'Software\NoID-NetBIOS-Test-' + [Guid]::NewGuid().ToString('N')
        $script:TypedNetBiosRootHandle = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:TypedNetBiosSubkey)
        $script:AdvancedSecurityNetBIOSRegistryRoot = 'HKCU:\' + $script:TypedNetBiosSubkey
        $script:TypedNetBiosGuid = '{11111111-1111-1111-1111-111111111111}'
        $script:TypedNetBiosHandle = $script:TypedNetBiosRootHandle.CreateSubKey('Tcpip_' + $script:TypedNetBiosGuid)
        Mock Get-CimInstance {
            [pscustomobject]@{
                Description = 'Isolated fixture adapter'; Index = 1; InterfaceIndex = 1
                SettingID = $script:TypedNetBiosGuid; IPEnabled = $false; TcpipNetbiosOptions = $null
            }
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        Mock Get-NetAdapter {
            [pscustomobject]@{
                Name = 'Fixture'; InterfaceGuid = $script:TypedNetBiosGuid
                HardwareInterface = $true; Status = 'Disconnected'
            }
        }
        Mock Invoke-CimMethod { throw 'The isolated offline fixture must never call a live adapter method' }
    }

    AfterEach {
        if ($script:TypedNetBiosHandle) { $script:TypedNetBiosHandle.Dispose() }
        if ($script:TypedNetBiosRootHandle) {
            $script:TypedNetBiosRootHandle.Dispose()
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:TypedNetBiosSubkey, $false)
        }
    }

    It 'restores <Label> from an unchanged schema-2 JSON snapshot' -TestCases @(
        @{ Label = 'DWORD zero'; Kind = 'DWord'; Data = [int]0 },
        @{ Label = 'DWORD high bit'; Kind = 'DWord'; Data = [int]-1 },
        @{ Label = 'QWORD high bit'; Kind = 'QWord'; Data = [long]::MinValue },
        @{ Label = 'literal expandable string'; Kind = 'ExpandString'; Data = '%USERPROFILE%\owner-value' },
        @{ Label = 'empty string'; Kind = 'String'; Data = '' },
        @{ Label = 'ordinary string'; Kind = 'String'; Data = 'owner-value' },
        @{ Label = 'empty binary'; Kind = 'Binary'; Data = [byte[]]@() },
        @{ Label = 'one binary byte'; Kind = 'Binary'; Data = [byte[]]@(0) },
        @{ Label = 'binary byte array'; Kind = 'Binary'; Data = [byte[]]@(0, 128, 255) },
        @{ Label = 'empty multi-string'; Kind = 'MultiString'; Data = [string[]]@() },
        @{ Label = 'one multi-string item'; Kind = 'MultiString'; Data = [string[]]@('one') },
        @{ Label = 'multiple multi-string items'; Kind = 'MultiString'; Data = [string[]]@('one', 'two') }
    ) {
        param($Label, $Kind, $Data)
        $null = $Label
        $script:TypedNetBiosHandle.SetValue('NetbiosOptions', $Data, [Microsoft.Win32.RegistryValueKind]$Kind)
        $before = Get-AdvancedSecurityNetBIOSState
        $backupPath = Join-Path $TestDrive ('netbios-' + [Guid]::NewGuid().ToString('N') + '.json')
        $before | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $backupPath -Encoding UTF8
        $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash
        $saved = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $saved

        $applied = Invoke-AdvancedSecurityNetBIOSDisable
        $applied.Adapters[0].RegistryValueType | Should -BeExactly 'DWord'
        $applied.Adapters[0].RegistryValue | Should -Be 2
        $restored = Restore-AdvancedSecurityNetBIOSState -Snapshot $saved
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $before -Candidate $restored | Should -BeTrue

        $actual = $script:TypedNetBiosHandle.GetValue('NetbiosOptions', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $script:TypedNetBiosHandle.GetValueKind('NetbiosOptions').ToString() | Should -BeExactly $Kind
        (ConvertTo-Json -InputObject $actual -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $Data -Compress)
        (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash | Should -BeExactly $backupHash
        Should -Invoke Invoke-CimMethod -Times 0 -Exactly
    }

    It 'restores DWORD <Value> when adapter observation changes: <Change>' -TestCases @(
        foreach ($value in @(0, 1, 2)) {
            foreach ($change in @('ConnectedAfterBackup', 'DisconnectedAfterBackup', 'Renamed', 'Reindexed')) {
                @{ Value = $value; Change = $change }
            }
        }
    ) {
        param($Value, $Change)
        $script:NetBiosConnected = $Change -ne 'ConnectedAfterBackup'
        $script:NetBiosProviderValue = $Value
        $script:NetBiosObservationName = 'Fixture'
        $script:NetBiosObservationIndex = 1
        Mock Get-CimInstance {
            $fixture = New-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ClientOnly -Property @{
                Description = $script:NetBiosObservationName
                Index = $script:NetBiosObservationIndex
                InterfaceIndex = $script:NetBiosObservationIndex
                SettingID = $script:TypedNetBiosGuid
                IPEnabled = $script:NetBiosConnected
            }
            $providerValue = if ($script:NetBiosConnected) { [uint32]$script:NetBiosProviderValue } else { $null }
            $fixture.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create(
                    'TcpipNetbiosOptions', $providerValue, [Microsoft.Management.Infrastructure.CimType]::UInt32,
                    [Microsoft.Management.Infrastructure.CimFlags]::None))
            $fixture
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        Mock Get-NetAdapter {
            [pscustomobject]@{
                Name = $script:NetBiosObservationName; InterfaceGuid = $script:TypedNetBiosGuid
                HardwareInterface = $true
                Status = $(if ($script:NetBiosConnected) { 'Up' } else { 'Disconnected' })
            }
        }
        Mock Invoke-CimMethod {
            $script:NetBiosProviderValue = [int]$Arguments.TcpipNetbiosOptions
            $script:TypedNetBiosHandle.SetValue('NetbiosOptions', $script:NetBiosProviderValue,
                [Microsoft.Win32.RegistryValueKind]::DWord)
            [pscustomobject]@{ ReturnValue = 0 }
        }
        $script:TypedNetBiosHandle.SetValue('NetbiosOptions', [int]$Value, [Microsoft.Win32.RegistryValueKind]::DWord)
        $snapshotPath = Join-Path $TestDrive 'connection-prestate.json'
        Get-AdvancedSecurityNetBIOSState | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $snapshotPath -Encoding UTF8
        $savedHash = (Get-FileHash $snapshotPath).Hash
        $saved = Get-Content $snapshotPath -Raw | ConvertFrom-Json
        $script:TypedNetBiosHandle.SetValue('NetbiosOptions', [int]2, [Microsoft.Win32.RegistryValueKind]::DWord)
        $script:NetBiosProviderValue = 2
        switch ($Change) {
            'ConnectedAfterBackup' { $script:NetBiosConnected = $true }
            'DisconnectedAfterBackup' { $script:NetBiosConnected = $false }
            'Renamed' { $script:NetBiosObservationName = 'Renamed fixture' }
            'Reindexed' { $script:NetBiosObservationIndex = 9 }
        }

        $restored = Restore-AdvancedSecurityNetBIOSState -Snapshot $saved
        $restored.Adapters[0].RegistryValueType | Should -BeExactly 'DWord'
        $restored.Adapters[0].RegistryValue | Should -Be $Value
        $restored.Adapters[0].IPEnabled | Should -Be $script:NetBiosConnected
        if ($script:NetBiosConnected) {
            $restored.Adapters[0].TcpipNetbiosOptions | Should -Be $Value
            Should -Invoke Invoke-CimMethod -Times 1 -Exactly -ParameterFilter {
                $MethodName -eq 'SetTcpipNetbios' -and [int]$Arguments.TcpipNetbiosOptions -eq $Value
            }
        }
        else { Should -Invoke Invoke-CimMethod -Times 0 -Exactly }
        (Get-FileHash $snapshotPath).Hash | Should -BeExactly $savedHash
        # Backup sealing still detects changes between its own consecutive
        # captures. Only Restore may accept independent connection metadata.
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $saved -Candidate $restored | Should -BeFalse
    }

    It 'rejects an active provider that reports success without restoring the captured value' {
        $script:TypedNetBiosHandle.SetValue('NetbiosOptions', [int]0, [Microsoft.Win32.RegistryValueKind]::DWord)
        Mock Get-CimInstance {
            New-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ClientOnly -Property @{
                Description = 'Isolated fixture adapter'; Index = 1; InterfaceIndex = 1
                SettingID = $script:TypedNetBiosGuid; IPEnabled = $true; TcpipNetbiosOptions = $script:NetBiosProviderValue
            }
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        $script:NetBiosProviderValue = 0
        $saved = Get-AdvancedSecurityNetBIOSState
        $script:TypedNetBiosHandle.SetValue('NetbiosOptions', [int]2, [Microsoft.Win32.RegistryValueKind]::DWord)
        $script:NetBiosProviderValue = 2
        Mock Invoke-CimMethod { [pscustomobject]@{ ReturnValue = 0 } }
        { Restore-AdvancedSecurityNetBIOSState -Snapshot $saved } | Should -Throw '*NetBIOS *state did not return*'
        Should -Invoke Invoke-CimMethod -Times 1 -Exactly
    }
}

Describe 'NetBIOS adapter presence changes' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        # Real registry values under HKCU; only adapter discovery is mocked.
        $script:PresenceSubkey = 'Software\NoID-NetBIOS-Presence-' + [Guid]::NewGuid().ToString('N')
        $script:PresenceRootHandle = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:PresenceSubkey)
        $script:AdvancedSecurityNetBIOSRegistryRoot = 'HKCU:\' + $script:PresenceSubkey
        $script:WiredGuid = '{33333333-3333-3333-3333-333333333333}'
        $script:ModemGuid = '{F4722628-BB61-45E8-93E1-BE039309D62F}'
        $script:AddedGuid = '{44444444-4444-4444-4444-444444444444}'
        $wiredKey = $script:PresenceRootHandle.CreateSubKey('Tcpip_' + $script:WiredGuid)
        $wiredKey.SetValue('NetbiosOptions', [int]0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $wiredKey.Dispose()
        $script:WiredListed = $true
        $script:WiredConfigured = $true
        $script:AddedPresent = $false
        Mock Get-CimInstance {
            # Windows keeps the configuration of an unplugged PnP adapter.
            if ($script:WiredConfigured) {
                [pscustomobject]@{
                    Description = 'USB test NIC'; Index = 3; InterfaceIndex = 12
                    SettingID = $script:WiredGuid; IPEnabled = $false; TcpipNetbiosOptions = $null
                }
            }
            if ($script:AddedPresent) {
                [pscustomobject]@{
                    Description = 'Dock test NIC'; Index = 4; InterfaceIndex = 14
                    SettingID = $script:AddedGuid; IPEnabled = $false; TcpipNetbiosOptions = $null
                }
            }
        } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
        Mock Get-NetAdapter {
            if ($script:WiredListed) {
                [pscustomobject]@{
                    Name = 'Lan-Verbindung'; InterfaceGuid = $script:WiredGuid; InterfaceDescription = 'USB test NIC'
                    InterfaceIndex = 12; HardwareInterface = $true; Status = 'Disconnected'; InterfaceOperationalStatus = 2
                }
            }
            # A mobile-broadband interface without a configuration stays
            # listed while its modem is not present.
            [pscustomobject]@{
                Name = 'Mobilfunk 7'; InterfaceGuid = $script:ModemGuid; InterfaceDescription = 'HP 5G Sub-6 Cat19'
                InterfaceIndex = 33; HardwareInterface = $true; Status = 'Not Present'; InterfaceOperationalStatus = 6
            }
            if ($script:AddedPresent) {
                [pscustomobject]@{
                    Name = 'Ethernet 3'; InterfaceGuid = $script:AddedGuid; InterfaceDescription = 'Dock test NIC'
                    InterfaceIndex = 14; HardwareInterface = $true; Status = 'Disconnected'; InterfaceOperationalStatus = 2
                }
            }
        }
        Mock Invoke-CimMethod { throw 'Offline fixtures must never call a live adapter method' }
        Mock Write-Log { }
        $snapshotPath = Join-Path $TestDrive ('presence-' + [Guid]::NewGuid().ToString('N') + '.json')
        Get-AdvancedSecurityNetBIOSState | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
        $script:PresenceSaved = Get-Content -LiteralPath $snapshotPath -Raw | ConvertFrom-Json
    }

    AfterEach {
        if ($script:PresenceRootHandle) {
            $script:PresenceRootHandle.Dispose()
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:PresenceSubkey, $false)
        }
    }

    It 'disables and restores a not-present adapter that has no configuration' {
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'

        $null = Invoke-AdvancedSecurityNetBIOSDisable -SealedSnapshot $script:PresenceSaved
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'DWord:2'
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'DWord:2'
        (Test-AdvancedSecurityNetBIOSDisabled).Compliant | Should -BeTrue

        $null = Restore-AdvancedSecurityNetBIOSState -Snapshot $script:PresenceSaved
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'DWord:0'
        Test-AdvancedSecurityNetBIOSStateEqual -Reference $script:PresenceSaved `
            -Candidate (Get-AdvancedSecurityNetBIOSState) | Should -BeTrue
        Should -Invoke Invoke-CimMethod -Times 0 -Exactly
    }

    It 'restores an adapter that was unplugged after Apply' {
        $null = Invoke-AdvancedSecurityNetBIOSDisable -SealedSnapshot $script:PresenceSaved
        $script:WiredListed = $false

        { Restore-AdvancedSecurityNetBIOSState -Snapshot $script:PresenceSaved } | Should -Not -Throw
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'DWord:0'
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'
        Should -Invoke Write-Log -ParameterFilter { $Message -like "*$($script:WiredGuid) is not connected*" }
    }

    It 'leaves an adapter added after the backup untouched' {
        $null = Invoke-AdvancedSecurityNetBIOSDisable -SealedSnapshot $script:PresenceSaved
        $script:AddedPresent = $true
        $addedKey = $script:PresenceRootHandle.CreateSubKey('Tcpip_' + $script:AddedGuid)
        $addedKey.SetValue('NetbiosOptions', [int]1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $addedKey.Dispose()

        $null = Restore-AdvancedSecurityNetBIOSState -Snapshot $script:PresenceSaved
        Get-PresenceTestValue -Guid $script:AddedGuid | Should -BeExactly 'DWord:1'
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'DWord:0'
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'
    }

    It 'does not recreate an adapter Windows removed together with its NetBT key' {
        $null = Invoke-AdvancedSecurityNetBIOSDisable -SealedSnapshot $script:PresenceSaved
        $script:WiredListed = $false
        $script:WiredConfigured = $false
        $script:PresenceRootHandle.DeleteSubKeyTree('Tcpip_' + $script:WiredGuid)

        { Restore-AdvancedSecurityNetBIOSState -Snapshot $script:PresenceSaved } | Should -Not -Throw
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'no key'
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'
        Should -Invoke Write-Log -ParameterFilter { $Message -like "*$($script:WiredGuid) and its NetBT key were removed*" }
    }

    It 'rejects Apply when the adapter inventory changed after the sealed backup' {
        $script:AddedPresent = $true

        { Invoke-AdvancedSecurityNetBIOSDisable -SealedSnapshot $script:PresenceSaved } |
            Should -Throw '*changed after the sealed backup*'
        Get-PresenceTestValue -Guid $script:WiredGuid | Should -BeExactly 'DWord:0'
        Get-PresenceTestValue -Guid $script:ModemGuid | Should -BeExactly 'no key'
    }
}
