#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Public/Restore-AdvancedSecuritySettings.ps1')
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    # Non-Windows runners have no NetAdapter commands; Pester mocks need one.
    foreach ($commandName in @('Get-NetAdapter', 'Enable-NetAdapter', 'Disable-NetAdapter')) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            Set-Item -Path "Function:global:$commandName" -Value {
                param($InputObject, $Name, [switch]$IncludeHidden)
                $null = $InputObject, $Name, $IncludeHidden
                throw 'NetAdapter commands are unavailable'
            }
        }
    }
}

Describe 'Wi-Fi Direct adapter restore from a sealed backup' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $script:WfdGuid = '{8D7F1F8A-658B-412F-8AF8-7E3F631DBB73}'
        # State after Apply: the adapter is disabled. Enable/Disable-NetAdapter
        # bind -InputObject as CimInstance[], so the fixture is a CIM instance.
        $script:Wfd = New-CimInstance -ClassName NoIDTest_NetAdapter -Namespace root/noidtest -ClientOnly -Property @{
            Name = 'LAN-Verbindung* 1'; InterfaceGuid = $script:WfdGuid
            InterfaceDescription = 'Microsoft Wi-Fi Direct Virtual Adapter'
            AdminStatus = 'Down'; Status = 'Disabled'; InterfaceOperationalStatus = [uint32]2
        }
        $script:Wfd.PSObject.TypeNames.Insert(0, 'Microsoft.Management.Infrastructure.CimInstance#MSFT_NetAdapter')
        Mock Get-NetAdapter { @($script:Wfd) }
        Mock Enable-NetAdapter { $script:Wfd.CimInstanceProperties['AdminStatus'].Value = 'Up' } -RemoveParameterType InputObject
        Mock Disable-NetAdapter { $script:Wfd.CimInstanceProperties['AdminStatus'].Value = 'Down' } -RemoveParameterType InputObject
        Mock Write-Log { }
        Mock Wait-NoIDWiFiDirectAdapterSettle { }
    }

    It 'enables an adapter that was enabled before Apply' {
        # Backup records the NET_IF_ADMIN_STATUS name; a JSON round trip keeps it.
        $backup = ConvertFrom-Json (@{
                Adapters = @(@{
                        Name = 'LAN-Verbindung* 1'; InterfaceGuid = $script:WfdGuid
                        InterfaceDescription = 'Microsoft Wi-Fi Direct Virtual Adapter'
                        Status = 'Disconnected'; AdminStatus = 'Up'
                    })
            } | ConvertTo-Json -Depth 5)

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -BeTrue
        Should -Invoke Enable-NetAdapter -Times 1 -Exactly -ParameterFilter {
            [string]$InputObject.InterfaceGuid -eq $script:WfdGuid -and
                -not $PesterBoundParameters.ContainsKey('Name')
        }
        Should -Invoke Disable-NetAdapter -Times 0 -Exactly
        [string]$script:Wfd.AdminStatus | Should -BeExactly 'Up'
    }

    It 'keeps an adapter disabled that was disabled before Apply' {
        $backup = [PSCustomObject]@{ Adapters = @([PSCustomObject]@{
                    InterfaceGuid = $script:WfdGuid; AdminStatus = 'Down'; Status = 'Disabled' }) }

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -BeTrue
        # Already in the saved state: verified, not changed again.
        Should -Invoke Disable-NetAdapter -Times 0 -Exactly
        Should -Invoke Enable-NetAdapter -Times 0 -Exactly
    }

    It 'fails closed on an AdminStatus other than Up or Down: <Saved>' -TestCases @(
        @{ Saved = 1 }, @{ Saved = 'Testing' }, @{ Saved = 'up' }
    ) {
        param($Saved)
        $backup = [PSCustomObject]@{ Adapters = @([PSCustomObject]@{
                    InterfaceGuid = $script:WfdGuid; AdminStatus = $Saved; Status = 'Disconnected' }) }

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -BeFalse
        Should -Invoke Enable-NetAdapter -Times 0 -Exactly
        Should -Invoke Disable-NetAdapter -Times 0 -Exactly
    }

    It 'reports a listed adapter that is not present when its saved state differs' {
        $backup = [PSCustomObject]@{ Adapters = @([PSCustomObject]@{
                    InterfaceGuid = $script:WfdGuid; AdminStatus = 'Up'; Status = 'Disconnected' }) }
        $script:Wfd.CimInstanceProperties['InterfaceOperationalStatus'].Value = [uint32]6
        $script:Wfd.CimInstanceProperties['Status'].Value = 'Not Present'

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -BeFalse
        Should -Invoke Write-Log -ParameterFilter { $Message -like '*is not present, so its saved state cannot be applied now*' }
        Should -Invoke Enable-NetAdapter -Times 0 -Exactly
    }

    It 'judges an absent adapter by its persisted device state: saved <Saved>, disabled <Disabled>' -TestCases @(
        # Windows removed a role adapter it had created on demand; its device
        # was never disabled, so it returns enabled.
        @{ Saved = 'Up'; Disabled = $false; Expected = $true },
        # The adapter's Wi-Fi hardware is unplugged and Apply disabled it.
        @{ Saved = 'Up'; Disabled = $true; Expected = $false },
        @{ Saved = 'Down'; Disabled = $true; Expected = $true },
        @{ Saved = 'Down'; Disabled = $false; Expected = $false },
        # Windows uninstalled the device.
        @{ Saved = 'Up'; Disabled = $null; Expected = $true }
    ) {
        param($Saved, $Disabled, $Expected)
        $script:FlagValue = $Disabled
        Mock Get-NetAdapter { @() }
        Mock Get-NoIDNetAdapterDeviceDisabled { $script:FlagValue }
        $backup = [PSCustomObject]@{ Adapters = @([PSCustomObject]@{
                    InterfaceGuid = $script:WfdGuid; AdminStatus = $Saved; Status = 'Disconnected' }) }

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -Be $Expected
        Should -Invoke Get-NoIDNetAdapterDeviceDisabled -Times 1 -Exactly -ParameterFilter { $InterfaceGuid -eq $script:WfdGuid }
        Should -Invoke Enable-NetAdapter -Times 0 -Exactly
        Should -Invoke Disable-NetAdapter -Times 0 -Exactly
        if (-not $Expected) {
            Should -Invoke Write-Log -ParameterFilter { $Message -like '*reconnect its Wi-Fi adapter and run Restore again*' }
        }
    }

    It 'enables the oldest adapter first and judges a role adapter Windows has not recreated by its device state' {
        $script:Role = New-CimInstance -ClassName NoIDTest_NetAdapter -Namespace root/noidtest -ClientOnly -Property @{
            Name = 'LAN-Verbindung* 10'; InterfaceGuid = '{06FE2DB1-D11B-4DA7-AAF4-64343D6D10AA}'
            InterfaceDescription = 'Microsoft Wi-Fi Direct Virtual Adapter #2'
            AdminStatus = 'Up'; Status = 'Disconnected'; InterfaceOperationalStatus = [uint32]2
        }
        # Apply disabled the first adapter; Windows removed the role adapter.
        Mock Get-NetAdapter { @($script:Wfd) }
        Mock Get-NoIDNetAdapterDeviceDisabled { $false }
        $backup = [PSCustomObject]@{ Adapters = @(
                [PSCustomObject]@{ InterfaceGuid = '{06FE2DB1-D11B-4DA7-AAF4-64343D6D10AA}'; AdminStatus = 'Up'
                    InterfaceDescription = 'Microsoft Wi-Fi Direct Virtual Adapter #2'; Status = 'Disconnected' },
                [PSCustomObject]@{ InterfaceGuid = $script:WfdGuid; AdminStatus = 'Up'
                    InterfaceDescription = 'Microsoft Wi-Fi Direct Virtual Adapter'; Status = 'Disconnected' }
            ) }

        Restore-WiFiDirectAdapters -BackupData $backup -Confirm:$false | Should -BeTrue
        Should -Invoke Enable-NetAdapter -Times 1 -Exactly -ParameterFilter { [string]$InputObject.InterfaceGuid -eq $script:WfdGuid }
        Should -Invoke Get-NoIDNetAdapterDeviceDisabled -Times 1 -Exactly -ParameterFilter {
            $InterfaceGuid -eq '{06FE2DB1-D11B-4DA7-AAF4-64343D6D10AA}'
        }
        Should -Invoke Write-Log -ParameterFilter { $Message -like '*keeps the saved Up state for when Windows creates it again*' }
    }
}
