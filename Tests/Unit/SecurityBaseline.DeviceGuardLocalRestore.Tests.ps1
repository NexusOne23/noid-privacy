#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $private = Join-Path $repo 'Modules/SecurityBaseline/Private'
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    . (Join-Path $private 'Get-SecurityBaselineDeviceGuardPlan.ps1')
    . (Join-Path $private 'Restore-RegistryPolicies.ps1')
    function Mount-UserRegistryHiveForRestore { param($Sid) throw "Unexpected user mount: $Sid" }
    function Dismount-UserRegistryHiveAfterRestore { param($Mount) throw "Unexpected user dismount: $Mount" }
    # RegistryKey returns a CLR array, including a genuinely empty array.
    # ScriptMethod results can retain PowerShell wrappers instead.
    if (-not ('NoIDLocalRecoveryTestKey' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Collections.Generic;
public sealed class NoIDLocalRecoveryTestKey {
    public string Name;
    public int SubKeyCount;
    public Dictionary<string, int> Values = new Dictionary<string, int>();
    public string[] GetValueNames() { return new List<string>(Values.Keys).ToArray(); }
}
'@
    }
    function Get-LocalRecoveryFixture {
        $rows = @(foreach ($target in @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)) {
                [pscustomobject]@{
                    KeyName = $target.KeyName; ValueName = $target.ValueName
                    KeyExisted = $false; Exists = $false; Type = 'REG_DWORD'
                    OriginalValue = $null; OriginalValueName = $null
                }
            })
        $rows += [pscustomobject]@{
            KeyName = '[SOFTWARE\NoIDUnrelated'; ValueName = 'Enabled'
            KeyExisted = $false; Exists = $false; Type = 'REG_DWORD'
            OriginalValue = $null; OriginalValueName = $null
        }
        [pscustomobject]@{
            SchemaVersion = 4; UserRegistryRoot = 'HKU:\S-1-5-21-101-202-303-1001'
            Computer = $rows; User = @(); ComputerClearKeys = @(); UserClearKeys = @()
            AbsentAncestorKeys = @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios', 'HKLM:\SOFTWARE\NoIDUnrelatedParent')
            DirectiveCount = $rows.Count
        }
    }
}

Describe 'Recorded local Device Guard recovery scope' {
    It 'selects twenty existing records without changing their data or the source snapshot' {
        $source = Get-LocalRecoveryFixture
        $source.Computer[0].KeyExisted = $true
        $source.Computer[0].Exists = $true
        $source.Computer[0].Type = 'REG_EXPAND_SZ'
        $source.Computer[0].OriginalValue = '%RECORDED_LITERAL%'
        $source.Computer[0].OriginalValueName = $source.Computer[0].ValueName.ToUpperInvariant()
        $before = $source | ConvertTo-Json -Depth 12 -Compress
        $selected = Select-SecurityBaselineDeviceGuardLocalRestoreSnapshot -RegistrySnapshot $source
        $selected.DirectiveCount | Should -Be 20
        $selected.Computer.Count | Should -Be 20
        @($selected.User).Count | Should -Be 0
        @($selected.ComputerClearKeys).Count | Should -Be 0
        @($selected.UserClearKeys).Count | Should -Be 0
        @($selected.AbsentAncestorKeys).Count | Should -Be 1
        $selected.AbsentAncestorKeys[0] | Should -BeExactly 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
        ($selected.Computer | ConvertTo-Json -Depth 12 -Compress) |
            Should -BeExactly ($source.Computer[0..19] | ConvertTo-Json -Depth 12 -Compress)
        ($source | ConvertTo-Json -Depth 12 -Compress) | Should -BeExactly $before
        $selected.Computer[0].OriginalValue = 'changed view'
        ($source | ConvertTo-Json -Depth 12 -Compress) | Should -BeExactly $before
    }

    It 'rejects <Fault> instead of supplying missing prestate' -ForEach @(
        @{ Fault = 'historical inventory' }, @{ Fault = 'duplicate target' },
        @{ Fault = 'same name in another key' }, @{ Fault = 'wrong schema' },
        @{ Fault = 'wrong directive count' }, @{ Fault = 'malformed ancestor' },
        @{ Fault = 'string boolean' }, @{ Fault = 'invented absent value' },
        @{ Fault = 'missing original value field' }, @{ Fault = 'coerced integer' }
    ) {
        $source = Get-LocalRecoveryFixture
        switch ($Fault) {
            'historical inventory' { $source.Computer = @($source.Computer[-1]); $source.DirectiveCount = 1 }
            'duplicate target' { $source.Computer += $source.Computer[0].PSObject.Copy(); $source.DirectiveCount++ }
            'same name in another key' { $source.Computer[0].KeyName = '[SOFTWARE\NoIDLookalike' }
            'wrong schema' { $source.SchemaVersion = 3 }
            'wrong directive count' { $source.DirectiveCount++ }
            'malformed ancestor' { $source.AbsentAncestorKeys = @($null) }
            'string boolean' { $source.Computer[0].Exists = 'false' }
            'invented absent value' { $source.Computer[0].OriginalValue = 0 }
            'missing original value field' { $source.Computer[0].PSObject.Properties.Remove('OriginalValue') }
            'coerced integer' {
                $source.Computer[0].KeyExisted = $true; $source.Computer[0].Exists = $true
                $source.Computer[0].OriginalValueName = $source.Computer[0].ValueName
                $source.Computer[0].OriginalValue = '1'
            }
        }
        $before = $source | ConvertTo-Json -Depth 12 -Compress
        { Select-SecurityBaselineDeviceGuardLocalRestoreSnapshot -RegistrySnapshot $source } | Should -Throw
        ($source | ConvertTo-Json -Depth 12 -Compress) | Should -BeExactly $before
    }

    It 'restores the selected local state while preserving an unrelated setting and the backup bytes' {
        $source = Get-LocalRecoveryFixture
        $path = Join-Path $TestDrive 'RegistryPolicies.json'
        $source | ConvertTo-Json -Depth 12 | Set-Content $path -Encoding UTF8
        $hash = (Get-FileHash $path).Hash
        $script:localPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        $script:localPresent = $true
        $script:localKey = [NoIDLocalRecoveryTestKey]::new()
        $script:localKey.Name = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        $script:localKey.Values.Add('Locked', 1)
        $script:unrelatedPath = 'HKLM:\SOFTWARE\NoIDUnrelated'
        $script:unrelatedPresent = $true
        $script:unrelatedKey = [NoIDLocalRecoveryTestKey]::new()
        $script:unrelatedKey.Name = 'HKEY_LOCAL_MACHINE\SOFTWARE\NoIDUnrelated'
        $script:unrelatedKey.Values.Add('Enabled', 99)
        Mock Mount-UserRegistryHiveForRestore { throw 'A machine-only recovery must not mount the user hive' }
        Mock Test-Path {
            if ($LiteralPath -eq $script:localPath) { return $script:localPresent }
            if ($LiteralPath -eq $script:unrelatedPath) { return $script:unrelatedPresent }
            if ($LiteralPath -like 'HKLM:*' -or $LiteralPath -like 'HKU:*') { return $false }
            [IO.File]::Exists($LiteralPath)
        }
        Mock Test-NoIDRegistryKey {
            if ($LiteralPath -eq $script:localPath) { return $script:localPresent }
            if ($LiteralPath -eq $script:unrelatedPath) { return $script:unrelatedPresent }
            return $false
        }
        Mock New-NoIDRegistryKey { throw 'No originally absent key should be created in this fixture' }
        Mock Get-Item { $script:localKey } -ParameterFilter { $LiteralPath -eq $script:localPath }
        Mock Get-Item { $script:unrelatedKey } -ParameterFilter { $LiteralPath -eq $script:unrelatedPath }
        Mock Get-ChildItem { @() } -ParameterFilter { $LiteralPath -eq $script:localPath }
        Mock New-ItemProperty { throw 'No originally present value should be created in this fixture' }
        Mock Remove-ItemProperty {
            if ($LiteralPath -ne $script:localPath -or $Name -cne 'Locked') { throw 'Unrelated registry deletion' }
            $null = $script:localKey.Values.Remove($Name)
        }
        Mock Remove-Item {
            if ($LiteralPath -ne $script:localPath -or $script:localKey.Values.Count -ne 0) { throw 'Unrelated or nonempty key deletion' }
            $script:localPresent = $false
        }
        foreach ($attempt in 1..2) {
            $result = Restore-RegistryPolicies -BackupPath $path -DeviceGuardLocalOnly -Confirm:$false
            $result.Errors.Count | Should -Be 0 -Because ($result.Errors -join '; ')
            $result.Success | Should -BeTrue
            $result.ItemsVerified | Should -Be 20
            $script:localPresent | Should -BeFalse
            $script:unrelatedPresent | Should -BeTrue
            $script:unrelatedKey.Values.Enabled | Should -Be 99
            (Get-FileHash $path).Hash | Should -BeExactly $hash
        }
        Should -Invoke Mount-UserRegistryHiveForRestore -Times 0 -Exactly
        Should -Invoke Remove-ItemProperty -Times 1 -Exactly
        Should -Invoke Remove-Item -Times 1 -Exactly
    }

    It 'rejects an old inventory before native registry access or a user-hive mount' {
        $source = Get-LocalRecoveryFixture
        $source.Computer = @($source.Computer[-1]); $source.DirectiveCount = 1
        $path = Join-Path $TestDrive 'HistoricalRegistryPolicies.json'
        $source | ConvertTo-Json -Depth 12 | Set-Content $path -Encoding UTF8
        $hash = (Get-FileHash $path).Hash
        Mock Mount-UserRegistryHiveForRestore { throw 'Unexpected mount' }
        Mock Get-Item { throw 'Unexpected native access' }
        Mock New-ItemProperty { throw 'Unexpected native write' }
        $result = Restore-RegistryPolicies -BackupPath $path -DeviceGuardLocalOnly -Confirm:$false
        $result.Success | Should -BeFalse
        $result.Errors[0] | Should -Match 'missing or duplicated'
        Should -Invoke Get-Item -Times 0 -Exactly
        Should -Invoke New-ItemProperty -Times 0 -Exactly
        Should -Invoke Mount-UserRegistryHiveForRestore -Times 0 -Exactly
        (Get-FileHash $path).Hash | Should -BeExactly $hash
    }

    It 'validates the selected contract without accessing Windows or claiming live verification' {
        $path = Join-Path $TestDrive 'ValidationOnly.json'
        Get-LocalRecoveryFixture | ConvertTo-Json -Depth 12 | Set-Content $path -Encoding UTF8
        Mock Mount-UserRegistryHiveForRestore { throw 'Unexpected mount' }
        Mock Get-Item { throw 'Unexpected registry access' }
        Mock New-Item { throw 'Unexpected registry write' }
        Mock New-NoIDRegistryKey { throw 'Unexpected registry write' }
        $result = Restore-RegistryPolicies -BackupPath $path -DeviceGuardLocalOnly -ValidateOnly
        $result.Success | Should -BeTrue
        $result.ItemsRestored | Should -Be 0
        $result.ItemsVerified | Should -Be 0
        Should -Invoke Get-Item -Times 0 -Exactly
        Should -Invoke New-Item -Times 0 -Exactly
        Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
        Should -Invoke Mount-UserRegistryHiveForRestore -Times 0 -Exactly
    }
}
