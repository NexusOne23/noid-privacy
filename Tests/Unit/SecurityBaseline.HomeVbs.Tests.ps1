#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $private = Join-Path $script:RepoRoot 'Modules/SecurityBaseline/Private'
    . (Join-Path (Join-Path $script:RepoRoot 'Core') 'Runtime.ps1')
    foreach ($file in @('Get-RecoverableSecurityBaselinePolicies.ps1', 'Get-SecurityBaselineDeviceGuardPlan.ps1',
            'ConvertTo-RegistryTypeString.ps1', 'Set-SecurityBaselineHomeVbs.ps1')) {
        . (Join-Path $private $file)
    }
    $source = Get-Content (Join-Path $private '../ParsedSettings/Computer-RegistryPolicies.json') -Raw | ConvertFrom-Json
    $script:Policies = @(Get-RecoverableSecurityBaselinePolicies -Policies $source)
    if (-not ('NoIDHomeVbsTestKey' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using Microsoft.Win32;
public sealed class NoIDHomeVbsTestKey {
    public readonly Dictionary<string, object> Values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, RegistryValueKind> Kinds = new Dictionary<string, RegistryValueKind>(StringComparer.OrdinalIgnoreCase);
    public string[] GetValueNames() { var names = new string[Values.Count]; Values.Keys.CopyTo(names, 0); return names; }
    public RegistryValueKind GetValueKind(string name) { return Kinds[name]; }
    public object GetValue(string name) { return Values.ContainsKey(name) ? Values[name] : null; }
    public object GetValue(string name, object fallback, RegistryValueOptions options) { return Values.ContainsKey(name) ? Values[name] : fallback; }
}
'@
    }
}

Describe 'Home VBS activation stays within the reviewed baseline and recorded boundary' {
    It 'selects documented local activation for Home SKU <Sku>' -TestCases @(
        @{ Sku = 98 }, @{ Sku = 99 }, @{ Sku = 100 }, @{ Sku = 101 }
    ) {
        param($Sku)
        $targets = @(Get-SecurityBaselineHomeVbsTargets -OperatingSystemSku $Sku -Policies $script:Policies)
        $targets.Count | Should -Be 6
        $targets.Data | Should -Not -Contain 2
        ($targets | Where-Object ValueName -ceq HVCIMATRequired).Data | Should -Be 1
        @($targets | Where-Object ValueName -ceq Locked | Where-Object Data -ne 0).Count | Should -Be 0
        $owned = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets | ForEach-Object { "$($_.KeyName)`0$($_.ValueName)" })
        @($targets | Where-Object { "$($_.KeyName)`0$($_.ValueName)" -notin $owned }).Count | Should -Be 0
    }

    It 'does not replace native processing on non-Home SKU <Sku>' -TestCases @(
        @{ Sku = 48 }, @{ Sku = 49 }, @{ Sku = 4 }, @{ Sku = 72 }, @{ Sku = 121 }, @{ Sku = 97 }
    ) {
        param($Sku)
        @(Get-SecurityBaselineHomeVbsTargets -OperatingSystemSku $Sku -Policies $script:Policies).Count | Should -Be 0
    }

    It 'does not guess Home from invalid edition evidence <Sku>' -TestCases @(
        @{ Sku = '101' }, @{ Sku = $true }, @{ Sku = 101.5 }, @{ Sku = 0 }, @{ Sku = -1 }
    ) {
        param($Sku)
        $request = @{ OperatingSystemSku = $Sku; Policies = $script:Policies }
        { Get-SecurityBaselineHomeVbsTargets @request } | Should -Throw '*edition evidence*'
    }

    It 'rejects a weakened or incomplete Device Guard policy plan before producing local targets' -TestCases @(
        @{ Fault = 'MAT disabled' }, @{ Fault = 'CG omitted' }
    ) {
        param($Fault)
        $policies = $script:Policies | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        if ($Fault -eq 'MAT disabled') { ($policies | Where-Object ValueName -ceq HVCIMATRequired).Data = 0 }
        else { $policies = @($policies | Where-Object ValueName -cne LsaCfgFlags) }
        { Get-SecurityBaselineHomeVbsTargets -OperatingSystemSku 101 -Policies $policies } | Should -Throw '*Device Guard*'
    }
}

Describe 'Home local activation uses exact captured prestate' {
    BeforeEach {
        $script:Parent = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        $script:Hvci = "$script:Parent\Scenarios\HypervisorEnforcedCodeIntegrity"
        $script:Keys = @{}
        $script:Keys[$script:Parent] = [NoIDHomeVbsTestKey]::new()
        $script:Writes = [Collections.Generic.List[string]]::new()
        $script:CorruptReadback = $false
        $script:Snapshot = [pscustomobject]@{
            SchemaVersion = 4; UserRegistryRoot = 'HKU:\S-1-5-21-101-202-303-1001'
            DirectiveCount = 20; AbsentAncestorKeys = @(); User = @(); ComputerClearKeys = @(); UserClearKeys = @()
            Computer = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets | ForEach-Object {
                    [pscustomobject]@{
                        KeyName = $_.KeyName; ValueName = $_.ValueName; Type = 'REG_DWORD'
                        KeyExisted = ($_.KeyName -ceq '[SYSTEM\CurrentControlSet\Control\DeviceGuard')
                        Exists = $false; OriginalValue = $null; OriginalValueName = $null
                    }
                })
        }
        Mock Test-NoIDRegistryKey { param($LiteralPath) $script:Keys.ContainsKey([string]$LiteralPath) }
        Mock Get-Item { param($LiteralPath) $script:Keys[[string]$LiteralPath] }
        Mock New-NoIDRegistryKey { param($LiteralPath) $script:Keys[[string]$LiteralPath] = [NoIDHomeVbsTestKey]::new() }
        Mock New-ItemProperty {
            param($LiteralPath, $Name, $Value, $PropertyType)
            $script:Writes.Add("$LiteralPath`0$Name")
            $key = $script:Keys[[string]$LiteralPath]
            $key.Values[$Name] = if ($script:CorruptReadback) { 9 } else { $Value }
            $key.Kinds[$Name] = [Microsoft.Win32.RegistryValueKind]$PropertyType
        }
    }

    It 'writes and verifies only the six captured controls without changing the backup' {
        $before = $script:Snapshot | ConvertTo-Json -Depth 10 -Compress
        Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false | Should -BeTrue
        $script:Writes.Count | Should -Be 6
        $script:Keys[$script:Parent].Values['EnableVirtualizationBasedSecurity'] | Should -Be 1
        $script:Keys[$script:Hvci].Values['Enabled'] | Should -Be 1
        $script:Keys[$script:Hvci].Values['HVCIMATRequired'] | Should -Be 1
        $script:Keys[$script:Parent].Values['Locked'] | Should -Be 0
        $script:Keys[$script:Hvci].Values['Locked'] | Should -Be 0
        ($script:Snapshot | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
    }

    It 'refuses activation with <Scope> lock <Kind>/<Value> and enablement <EnabledState> before any write' -TestCases @(
        @{ Scope = 'Parent'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 'Absent' }
        @{ Scope = 'Hvci'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 'Absent' }
        @{ Scope = 'Parent'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 0 }
        @{ Scope = 'Hvci'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 0 }
        @{ Scope = 'Parent'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 1 }
        @{ Scope = 'Hvci'; Kind = 'DWord'; Value = 1; Type = 'REG_DWORD'; EnabledState = 1 }
        @{ Scope = 'Parent'; Kind = 'DWord'; Value = 7; Type = 'REG_DWORD'; EnabledState = 'Absent' }
        @{ Scope = 'Hvci'; Kind = 'DWord'; Value = 7; Type = 'REG_DWORD'; EnabledState = 'Absent' }
        @{ Scope = 'Parent'; Kind = 'Binary'; Value = [byte[]]@(0); Type = 'REG_BINARY'; EnabledState = 'Absent' }
        @{ Scope = 'Hvci'; Kind = 'Binary'; Value = [byte[]]@(0); Type = 'REG_BINARY'; EnabledState = 'Absent' }
    ) {
        param($Scope, $Kind, $Value, $Type, $EnabledState)
        $path = if ($Scope -ceq 'Parent') { $script:Parent } else { $script:Hvci }
        $keyName = '[' + $path.Substring(6)
        if (-not $script:Keys.ContainsKey($path)) { $script:Keys[$path] = [NoIDHomeVbsTestKey]::new() }
        foreach ($row in @($script:Snapshot.Computer | Where-Object KeyName -ceq $keyName)) { $row.KeyExisted = $true }
        $script:Keys[$path].Values['LOCKED'] = $Value
        $script:Keys[$path].Kinds['LOCKED'] = [Microsoft.Win32.RegistryValueKind]$Kind
        $entry = @($script:Snapshot.Computer | Where-Object { $_.KeyName -ceq $keyName -and $_.ValueName -ceq 'Locked' })[0]
        $entry.Exists = $true; $entry.OriginalValueName = 'LOCKED'; $entry.OriginalValue = $Value; $entry.Type = $Type
        if ($EnabledState -cne 'Absent') {
            $enabledName = if ($Scope -ceq 'Parent') { 'EnableVirtualizationBasedSecurity' } else { 'Enabled' }
            $script:Keys[$path].Values[$enabledName] = [int]$EnabledState
            $script:Keys[$path].Kinds[$enabledName] = [Microsoft.Win32.RegistryValueKind]::DWord
            $enabledEntry = @($script:Snapshot.Computer | Where-Object { $_.KeyName -ceq $keyName -and $_.ValueName -ceq $enabledName })[0]
            $enabledEntry.Exists = $true; $enabledEntry.OriginalValueName = $enabledName; $enabledEntry.OriginalValue = [int]$EnabledState
        }
        $before = $script:Snapshot | ConvertTo-Json -Depth 10 -Compress
        { Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false } |
            Should -Throw '*existing local UEFI-lock configuration*'
        $script:Writes.Count | Should -Be 0
        Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
        ($script:Snapshot | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
        $script:Keys[$path].GetValueNames() | Should -Contain 'LOCKED'
        $script:Keys[$path].GetValueKind('LOCKED').ToString() | Should -BeExactly $Kind
        (ConvertTo-Json -InputObject @($script:Keys[$path].GetValue('LOCKED')) -Compress) |
            Should -BeExactly (ConvertTo-Json -InputObject @($Value) -Compress)
    }

    It 'preserves a documented zero lock at <Scope> without rewriting its name' -TestCases @(
        @{ Scope = 'Parent' }, @{ Scope = 'Hvci' }
    ) {
        param($Scope)
        $path = if ($Scope -ceq 'Parent') { $script:Parent } else { $script:Hvci }
        $keyName = '[' + $path.Substring(6)
        if (-not $script:Keys.ContainsKey($path)) { $script:Keys[$path] = [NoIDHomeVbsTestKey]::new() }
        foreach ($row in @($script:Snapshot.Computer | Where-Object KeyName -ceq $keyName)) { $row.KeyExisted = $true }
        $script:Keys[$path].Values['LOCKED'] = 0
        $script:Keys[$path].Kinds['LOCKED'] = [Microsoft.Win32.RegistryValueKind]::DWord
        $entry = @($script:Snapshot.Computer | Where-Object { $_.KeyName -ceq $keyName -and $_.ValueName -ceq 'Locked' })[0]
        $entry.Exists = $true; $entry.OriginalValueName = 'LOCKED'; $entry.OriginalValue = 0
        Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false | Should -BeTrue
        $script:Writes.Count | Should -Be 5
        $script:Writes | Should -Not -Contain "$path`0Locked"
        $script:Keys[$path].GetValueNames() | Should -Contain 'LOCKED'
        $script:Keys[$path].GetValueKind('LOCKED').ToString() | Should -BeExactly 'DWord'
        $script:Keys[$path].GetValue('LOCKED') | Should -Be 0
    }

    It 'rejects incomplete historical prestate instead of inventing missing records' {
        $script:Snapshot.Computer = @($script:Snapshot.Computer | Where-Object ValueName -cne HVCIMATRequired)
        $script:Snapshot.DirectiveCount = 19
        { Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false } | Should -Throw '*missing or duplicated*'
        $script:Writes.Count | Should -Be 0
    }

    It 'detects a late control change before making any writes' {
        $script:Keys[$script:Hvci] = [NoIDHomeVbsTestKey]::new()
        $script:Keys[$script:Hvci].Values['Enabled'] = 1
        $script:Keys[$script:Hvci].Kinds['Enabled'] = [Microsoft.Win32.RegistryValueKind]::DWord
        { Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false } | Should -Throw '*changed after backup*'
        $script:Writes.Count | Should -Be 0
    }

    It 'does not accept a write that fails native readback' {
        $script:CorruptReadback = $true
        { Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false } | Should -Throw '*verification failed*'
        $script:Writes.Count | Should -Be 1
    }

    It 'leaves native state untouched under WhatIf' {
        Set-SecurityBaselineHomeVbs -OperatingSystemSku 101 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -WhatIf | Should -BeFalse
        $script:Writes.Count | Should -Be 0
        Should -Invoke Test-NoIDRegistryKey -Times 0 -Exactly
    }

    It 'never reads or writes local controls for Pro' {
        Set-SecurityBaselineHomeVbs -OperatingSystemSku 48 -Policies $script:Policies -RegistrySnapshot $script:Snapshot -Confirm:$false | Should -BeFalse
        $script:Writes.Count | Should -Be 0
        Should -Invoke Test-NoIDRegistryKey -Times 0 -Exactly
    }
}
