#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $private = Join-Path $script:RepoRoot 'Modules/SecurityBaseline/Private'
    . (Join-Path (Join-Path $script:RepoRoot 'Core') 'Runtime.ps1')
    . (Join-Path $private 'Get-RecoverableSecurityBaselinePolicies.ps1')
    . (Join-Path $private 'Get-SecurityBaselineDeviceGuardPlan.ps1')
    . (Join-Path $private 'Backup-RegistryPolicies.ps1')
    . (Join-Path $private 'ConvertTo-RegistryTypeString.ps1')
    function Get-RegistryHierarchyPrestate { param($TargetPath, $BoundaryPath) $null = $TargetPath, $BoundaryPath }
    function Get-ExactRegistryValueName { param($Key, $Name) @($Key.GetValueNames() | Where-Object { $_ -ieq $Name })[0] }
    Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module) $null = $Level, $Message, $Module }
    function Get-TestDeviceGuardPlan {
        $source = Get-Content (Join-Path $script:RepoRoot 'Modules/SecurityBaseline/ParsedSettings/Computer-RegistryPolicies.json') -Raw | ConvertFrom-Json
        @(Get-RecoverableSecurityBaselinePolicies -Policies $source)
    }
    # Use a CLR method like RegistryKey.GetValue. A ScriptMethod wraps array
    # results with PSObject metadata on Windows PowerShell 5.1, unlike the real
    # registry API; that would test the dummy's serialization instead of BAVR.
    if (-not ('NoIDDeviceGuardTestRegistryKey' -as [type])) {
        Add-Type -TypeDefinition @'
using Microsoft.Win32;
public sealed class NoIDDeviceGuardTestRegistryKey {
    public RegistryValueKind Kind;
    public object Value;
    public string[] GetValueNames() { return new string[] { "LOCKED" }; }
    public RegistryValueKind GetValueKind(string name) { return Kind; }
    public object GetValue(string name, object defaultValue, RegistryValueOptions options) { return Value; }
}
'@
    }
}

Describe 'SecurityBaseline complete Device Guard processing plan' {
    BeforeEach { $script:Policies = Get-TestDeviceGuardPlan }

    It 'retains all eight Microsoft options with the existing no-new-lock decision' {
        $before = $script:Policies | ConvertTo-Json -Depth 10 -Compress
        $plan = Get-SecurityBaselineDeviceGuardPlan -Policies $script:Policies
        $plan.PolicyKey | Should -BeExactly 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        $plan.Policies.Count | Should -Be 8
        ($plan.Policies | Where-Object ValueName -eq HVCIMATRequired).Data | Should -Be 1
        ($plan.Policies | Where-Object ValueName -eq MachineIdentityIsolation).Data | Should -Be 3
        @($plan.Policies | Where-Object ValueName -in @('HypervisorEnforcedCodeIntegrity', 'LsaCfgFlags') | Where-Object Data -eq 2).Count | Should -Be 2
        $plan.LocalBackupTargets.Count | Should -Be 20
        @($plan.LocalBackupTargets.KeyName | Sort-Object -Unique).Count | Should -Be 6
        @($plan.LocalBackupTargets | Where-Object { $_.PSObject.Properties['Data'] }).Count | Should -Be 0
        ($script:Policies | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
        $plan.Policies[0].Data = 0
        ($script:Policies | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
    }

    It 'rejects <Fault> atomically instead of reducing or changing the baseline' -TestCases @(
        @{ Fault = 'missing' }, @{ Fault = 'duplicate' }, @{ Fault = 'foreign extra' },
        @{ Fault = 'new firmware lock' }, @{ Fault = 'relaxed MAT' },
        @{ Fault = 'wrong type' }, @{ Fault = 'string data' }, @{ Fault = 'boolean data' },
        @{ Fault = 'changed identity' }
    ) {
        param($Fault)
        $hvci = @($script:Policies | Where-Object ValueName -ceq HypervisorEnforcedCodeIntegrity)[0]
        switch ($Fault) {
            'missing' { $script:Policies = @($script:Policies | Where-Object { $_ -ne $hvci }) }
            'duplicate' { $script:Policies += $hvci.PSObject.Copy() }
            'foreign extra' { $extra = $hvci.PSObject.Copy(); $extra.ValueName = 'FutureOption'; $script:Policies += $extra }
            'new firmware lock' { $hvci.Data = 1 }
            'relaxed MAT' { ($script:Policies | Where-Object ValueName -ceq HVCIMATRequired).Data = 0 }
            'wrong type' { $hvci.Type = 'REG_SZ' }
            'string data' { $hvci.Data = '2' }
            'boolean data' { $hvci.Data = $true }
            'changed identity' { $hvci.ValueName = 'FutureOption' }
        }
        $before = $script:Policies | ConvertTo-Json -Depth 10 -Compress
        $received = [Collections.Generic.List[object]]::new()
        { Get-SecurityBaselineDeviceGuardPlan -Policies $script:Policies | ForEach-Object { $received.Add($_) } } | Should -Throw '*Device Guard*'
        $received.Count | Should -Be 0
        ($script:Policies | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
    }

    It 'does not confuse a same-named foreign value with a Device Guard directive' {
        $script:Policies += [PSCustomObject]@{ KeyName = '[SOFTWARE\NoIDTest'; ValueName = 'HVCIMATRequired'; Type = 'REG_DWORD'; Data = 0 }
        $plan = Get-SecurityBaselineDeviceGuardPlan -Policies $script:Policies
        $plan.Policies.Count | Should -Be 8
        ($plan.Policies | Where-Object ValueName -ceq HVCIMATRequired).Data | Should -Be 1
    }
}

Describe 'Additional Device Guard prestate uses the existing typed registry snapshot' {
    BeforeEach {
        $script:SourcePath = Join-Path $TestDrive 'source.json'
        $script:BackupPath = Join-Path $TestDrive ("RegistryPolicies-$([Guid]::NewGuid().ToString('N')).json")
        $script:UserRoot = 'HKU:\S-1-5-21-101-202-303-1001'
        $script:ExistingTarget = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        $script:OriginalType = [Microsoft.Win32.RegistryValueKind]::DWord
        $script:OriginalData = 7
        $script:ExistingKey = [NoIDDeviceGuardTestRegistryKey]::new()
        $script:ExistingKey.Kind = $script:OriginalType
        $script:ExistingKey.Value = $script:OriginalData
        @([PSCustomObject]@{ KeyName = '[SOFTWARE\NoIDTest'; ValueName = 'Enabled'; Type = 'REG_DWORD'; Data = 1 }) |
            ConvertTo-Json | Set-Content -LiteralPath $script:SourcePath
        Mock Test-Path {
            param($LiteralPath)
            if ($LiteralPath -eq $script:UserRoot -or $LiteralPath -eq $script:ExistingTarget) { return $true }
            if ($LiteralPath -like 'HKLM:*' -or $LiteralPath -like 'HKU:*') { return $false }
            [IO.File]::Exists($LiteralPath)
        }
        Mock Test-NoIDRegistryKey {
            param($LiteralPath)
            $LiteralPath -eq $script:UserRoot -or $LiteralPath -eq $script:ExistingTarget
        }
        Mock Get-Item { $script:ExistingKey } -ParameterFilter { $LiteralPath -eq $script:ExistingTarget }
    }

    It 'preserves the old caller inventory and schema when no additional targets are supplied' {
        $result = Backup-RegistryPolicies -ComputerPoliciesPath $script:SourcePath -UserRegistryRoot $script:UserRoot -BackupPath $script:BackupPath -Confirm:$false
        $result.Success | Should -BeTrue
        $snapshot = Get-Content -LiteralPath $script:BackupPath -Raw | ConvertFrom-Json
        $snapshot.SchemaVersion | Should -Be 4
        $snapshot.DirectiveCount | Should -Be 1
        @($snapshot.Computer).Count | Should -Be 1
    }

    It 'captures every entry of a JSON policy array in the <Scope> scope' -TestCases @(
        @{ Scope = 'Computer' }, @{ Scope = 'User' }
    ) {
        param($Scope)
        $policies = @(
            [PSCustomObject]@{ KeyName = '[SOFTWARE\NoIDTest'; ValueName = 'First'; Type = 'REG_DWORD'; Data = 1 }
            [PSCustomObject]@{ KeyName = '[SOFTWARE\NoIDTest'; ValueName = 'Second'; Type = 'REG_DWORD'; Data = 1 }
        )
        ConvertTo-Json -InputObject $policies | Set-Content -LiteralPath $script:SourcePath
        $arguments = @{ UserRegistryRoot = $script:UserRoot; BackupPath = $script:BackupPath; Confirm = $false }
        $arguments[$Scope + 'PoliciesPath'] = $script:SourcePath
        $result = Backup-RegistryPolicies @arguments
        $result.Success | Should -BeTrue
        $result.ItemsBackedUp | Should -Be 2
        $snapshot = Get-Content -LiteralPath $script:BackupPath -Raw | ConvertFrom-Json
        $snapshot.DirectiveCount | Should -Be 2
        @($snapshot.$Scope).Count | Should -Be 2
        (@($snapshot.$Scope.ValueName) -join ',') | Should -BeExactly 'First,Second'
    }

    It 'captures all 20 additional values including original absence without applying defaults' {
        $targets = (Get-SecurityBaselineDeviceGuardPlan -Policies (Get-TestDeviceGuardPlan)).LocalBackupTargets
        $result = Backup-RegistryPolicies -ComputerPoliciesPath $script:SourcePath -AdditionalComputerTargets $targets -UserRegistryRoot $script:UserRoot -BackupPath $script:BackupPath -Confirm:$false
        $result.Success | Should -BeTrue
        $snapshot = Get-Content -LiteralPath $script:BackupPath -Raw | ConvertFrom-Json
        $snapshot.SchemaVersion | Should -Be 4
        $snapshot.DirectiveCount | Should -Be 21
        @($snapshot.Computer).Count | Should -Be 21
        $locked = @($snapshot.Computer | Where-Object { $_.KeyName -ceq '[SYSTEM\CurrentControlSet\Control\DeviceGuard' -and $_.ValueName -ceq 'Locked' })[0]
        $locked.OriginalValueName | Should -BeExactly 'LOCKED'
        $locked.OriginalValue | Should -Be 7
        $locked.Type | Should -BeExactly 'REG_DWORD'
        $absent = @($snapshot.Computer | Where-Object { $_.KeyName -like '*KernelShadowStacks' -and $_.ValueName -eq 'AuditModeEnabled' })[0]
        $absent.KeyExisted | Should -BeFalse
        $absent.Exists | Should -BeFalse
        $absent.OriginalValue | Should -BeNullOrEmpty
        $absent.OriginalValueName | Should -BeNullOrEmpty
    }

    It 'retains an original non-DWORD type and data: <Kind>' -TestCases @(
        @{ Kind = 'String'; Value = 'original value' },
        @{ Kind = 'ExpandString'; Value = '%ORIGINAL_VALUE%' },
        @{ Kind = 'MultiString'; Value = @('first', '', 'last') },
        @{ Kind = 'Binary'; Value = [byte[]]@(0, 127, 255) },
        @{ Kind = 'QWord'; Value = [long]::MaxValue }
    ) {
        param($Kind, $Value)
        $script:OriginalType = [Microsoft.Win32.RegistryValueKind]$Kind
        $script:OriginalData = $Value
        $script:ExistingKey.Kind = $script:OriginalType
        $script:ExistingKey.Value = $script:OriginalData
        $target = [PSCustomObject]@{ KeyName = '[SYSTEM\CurrentControlSet\Control\DeviceGuard'; ValueName = 'Locked'; Type = 'REG_DWORD' }
        $result = Backup-RegistryPolicies -AdditionalComputerTargets @($target) -UserRegistryRoot $script:UserRoot -BackupPath $script:BackupPath -Confirm:$false
        $result.Success | Should -BeTrue
        $snapshot = Get-Content -LiteralPath $script:BackupPath -Raw | ConvertFrom-Json
        @($snapshot.Computer).Count | Should -Be 1
        $snapshot.Computer[0].Type | Should -BeExactly (ConvertTo-RegistryTypeString -Kind $script:OriginalType)
        (ConvertTo-Json -InputObject @($snapshot.Computer[0].OriginalValue) -Compress) | Should -BeExactly (ConvertTo-Json -InputObject @($Value) -Compress)
        $snapshot.Computer[0].OriginalValueName | Should -BeExactly 'LOCKED'
    }

    It 'rejects <Fault> without creating a partial backup' -TestCases @(
        @{ Fault = 'duplicate additional target' }, @{ Fault = 'duplicate policy target' },
        @{ Fault = 'wrong root' }, @{ Fault = 'clear-key directive' },
        @{ Fault = 'wrong declared type' }, @{ Fault = 'empty name' }
    ) {
        param($Fault)
        $target = [PSCustomObject]@{ KeyName = '[SYSTEM\CurrentControlSet\Control\DeviceGuard'; ValueName = 'Locked'; Type = 'REG_DWORD' }
        $targets = @($target)
        switch ($Fault) {
            'duplicate additional target' { $targets += $target.PSObject.Copy() }
            'duplicate policy target' { @($target) | ConvertTo-Json | Set-Content -LiteralPath $script:SourcePath }
            'wrong root' { $target.KeyName = '[SOFTWARE\NoIDTest' }
            'clear-key directive' { $target.ValueName = '**delvals.' }
            'wrong declared type' { $target.Type = 'REG_SZ' }
            'empty name' { $target.ValueName = '' }
        }
        $result = Backup-RegistryPolicies -ComputerPoliciesPath $script:SourcePath -AdditionalComputerTargets $targets -UserRegistryRoot $script:UserRoot -BackupPath $script:BackupPath -Confirm:$false
        $result.Success | Should -BeFalse
        [IO.File]::Exists($script:BackupPath) | Should -BeFalse

        # Rejection must also leave an existing backup byte-for-byte intact.
        [IO.File]::WriteAllText($script:BackupPath, 'existing backup sentinel')
        $before = (Get-FileHash -LiteralPath $script:BackupPath).Hash
        $result = Backup-RegistryPolicies -ComputerPoliciesPath $script:SourcePath -AdditionalComputerTargets $targets -UserRegistryRoot $script:UserRoot -BackupPath $script:BackupPath -Confirm:$false
        $result.Success | Should -BeFalse
        (Get-FileHash -LiteralPath $script:BackupPath).Hash | Should -BeExactly $before
    }
}
