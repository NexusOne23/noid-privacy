#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $private = Join-Path $repoRoot 'Modules/SecurityBaseline/Private'
    . (Join-Path (Join-Path $repoRoot 'Core') 'Runtime.ps1')
    . (Join-Path $private 'Restore-RegistryPolicies.ps1')
    . (Join-Path $private 'Set-RegistryPolicies.ps1')
    . (Join-Path $repoRoot 'Core/Logger.ps1')
    function Mount-UserRegistryHiveForRestore { param($Sid) [pscustomobject]@{ Sid = $Sid } }
    function Dismount-UserRegistryHiveAfterRestore { param($Mount) $Mount.Sid -ceq $script:userRoot.Substring(5) }
    $script:userRoot = 'HKU:\S-1-5-21-111-222-333-1001'
    $script:keyName = 'SOFTWARE\NoIDRegistryClearTest'
}

Describe 'SecurityBaseline exact clear-key registry names and types' {
    BeforeEach {
        # Model the native RegistryKey contract, not the provider's default-name
        # alias. The Windows compatibility run also exercises real registry keys.
        $script:key = [pscustomobject]@{
            Values = @{ Applied = @{ Value = 1; Kind = [Microsoft.Win32.RegistryValueKind]::DWord } }
            Opens = 0; Disposals = 0; Deletes = 0; Writes = 0
        }
        $script:key | Add-Member ScriptMethod GetValueNames { return [string[]]@($this.Values.Keys) }
        $script:key | Add-Member ScriptMethod OpenSubKey {
            param($name, $writable)
            if ($name -cne '' -or $writable -ne $true) { throw 'Expected writable current key' }
            $this.Opens++; return $this
        }
        $script:key | Add-Member ScriptMethod Dispose { $this.Disposals++ }
        $script:key | Add-Member ScriptMethod DeleteValue {
            param($name, $throwOnMissing)
            if (-not $this.Values.ContainsKey($name) -and $throwOnMissing) { throw 'Missing native name' }
            $this.Values.Remove($name); $this.Deletes++
        }
        $script:key | Add-Member ScriptMethod SetValue {
            param($name, $value, $kind)
            if (($kind -eq [Microsoft.Win32.RegistryValueKind]::Binary -and $value -isnot [byte[]]) -or
                ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString -and $value -isnot [string[]])) {
                throw 'Native array type required'
            }
            $this.Values[$name] = @{ Value = $value; Kind = $kind }; $this.Writes++
        }
        $script:key | Add-Member ScriptMethod GetValue {
            param($name, $defaultValue, $options)
            if ($options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { throw 'Literal registry read required' }
            if (-not $this.Values.ContainsKey($name)) { return $defaultValue }
            return ,$this.Values[$name].Value
        }
        $script:key | Add-Member ScriptMethod GetValueKind { param($name) return $this.Values[$name].Kind }
        Mock Test-Path { $true } -ParameterFilter {
            $LiteralPath -like 'HKU:*' -or $LiteralPath -like 'HKLM:*' -or $Path -like 'HKU:*' -or $Path -like 'HKLM:*'
        }
        Mock Test-NoIDRegistryKey { $true } -ParameterFilter {
            $LiteralPath -like 'HKU:*' -or $LiteralPath -like 'HKLM:*'
        }
        Mock New-NoIDRegistryKey { throw 'Unexpected key creation in clear-key restore' }
        Mock Get-Item { $script:key } -ParameterFilter { $LiteralPath -like 'HKU:*' -or $LiteralPath -like 'HKLM:*' }
        Mock New-ItemProperty { throw 'Unexpected provider write in clear-key restore' }
        Mock Remove-ItemProperty { throw 'Unexpected provider deletion in clear-key restore' }
        Mock Write-Log {}
        $script:backup = [ordered]@{
            SchemaVersion = 4; UserRegistryRoot = $script:userRoot; AbsentAncestorKeys = @(); DirectiveCount = 2
            Computer = @(); ComputerClearKeys = @()
            User = @(@{ KeyName = $script:keyName; ValueName = 'Applied'; Type = 'REG_DWORD'; OriginalValue = $null; OriginalValueName = $null; KeyExisted = $true; Exists = $false })
            UserClearKeys = @(@{ KeyName = $script:keyName; KeyExisted = $true; Values = @() })
        }
        $script:backupPath = Join-Path $TestDrive 'RegistryPolicies.json'
    }

    It 'restores <Case> twice with schema <Schema> without rewriting the artifact' -ForEach @(
        foreach ($schema in 3, 4) {
            foreach ($valueCase in @(
                @{ Case = 'both default names and whitespace'; Values = @(@{ Name = ''; Type = 'REG_SZ'; Value = 'unnamed' }, @{ Name = '(default)'; Type = 'REG_SZ'; Value = 'literal' }, @{ Name = ' '; Type = 'REG_SZ'; Value = 'space' }) }
                @{ Case = 'literal wildcard name'; Values = @(@{ Name = 'a[*]?'; Type = 'REG_SZ'; Value = 'wildcard' }) }
                @{ Case = 'empty binary'; Values = @(@{ Name = 'Binary'; Type = 'REG_BINARY'; Value = [byte[]]@() }) }
                @{ Case = 'single binary'; Values = @(@{ Name = 'Binary'; Type = 'REG_BINARY'; Value = [byte[]]@(231) }) }
                @{ Case = 'multiple binary'; Values = @(@{ Name = 'Binary'; Type = 'REG_BINARY'; Value = [byte[]]@(0, 231) }) }
                @{ Case = 'empty multistring'; Values = @(@{ Name = 'Multi'; Type = 'REG_MULTI_SZ'; Value = [string[]]@() }) }
                @{ Case = 'single multistring'; Values = @(@{ Name = 'Multi'; Type = 'REG_MULTI_SZ'; Value = [string[]]@('alpha') }) }
                @{ Case = 'multiple multistring'; Values = @(@{ Name = 'Multi'; Type = 'REG_MULTI_SZ'; Value = [string[]]@('alpha', 'beta') }) }
                @{ Case = 'literal expansion'; Values = @(@{ Name = 'Expand'; Type = 'REG_EXPAND_SZ'; Value = '%TEMP%\NoID' }) }
                @{ Case = 'signed DWORD'; Values = @(@{ Name = 'Integer'; Type = 'REG_DWORD'; Value = -1 }) }
                @{ Case = 'signed QWORD'; Values = @(@{ Name = 'Integer'; Type = 'REG_QWORD'; Value = [long]-1 }) }
            )) { @{ Schema = $schema; Case = $valueCase.Case; Values = $valueCase.Values } }
        }
    ) {
        $script:backup.SchemaVersion = $Schema
        $script:backup.UserClearKeys[0].Values = $Values
        $script:backup | ConvertTo-Json -Depth 12 | Set-Content $script:backupPath -Encoding UTF8
        $hash = (Get-FileHash $script:backupPath).Hash
        foreach ($attempt in 1..2) {
            $result = Restore-RegistryPolicies -BackupPath $script:backupPath -Confirm:$false
            $result.Errors.Count | Should -Be 0
            $result.Success | Should -BeTrue
            $script:key.Values.Count | Should -Be $Values.Count
            foreach ($value in $Values) {
                $script:key.Values.ContainsKey($value.Name) | Should -BeTrue
                (ConvertTo-Json -InputObject @($script:key.Values[$value.Name].Value) -Compress) |
                    Should -BeExactly (ConvertTo-Json -InputObject @($value.Value) -Compress)
            }
            (Get-FileHash $script:backupPath).Hash | Should -BeExactly $hash
            $script:key.Disposals | Should -Be $attempt
        }
    }

    It 'rejects a <Case> clear-key name before any write' -ForEach @(
        @{ Case = 'missing'; Entry = @{ Type = 'REG_SZ'; Value = 'data' } }
        @{ Case = 'null'; Entry = @{ Name = $null; Type = 'REG_SZ'; Value = 'data' } }
        @{ Case = 'numeric'; Entry = @{ Name = 1; Type = 'REG_SZ'; Value = 'data' } }
    ) {
        $script:backup.UserClearKeys[0].Values = @($Entry)
        $script:backup | ConvertTo-Json -Depth 12 | Set-Content $script:backupPath -Encoding UTF8
        $result = Restore-RegistryPolicies -BackupPath $script:backupPath -Confirm:$false
        $result.Success | Should -BeFalse
        $result.Errors[0] | Should -Match 'Invalid value name'
        $script:key.Opens | Should -Be 0
        $script:key.Values.Applied.Value | Should -Be 1
    }

    It 'clears native names exactly in the <Scope> policy scope' -ForEach @(@{ Scope = 'Computer' }, @{ Scope = 'User' }) {
        foreach ($name in @('', '(default)', ' ', 'a[*]?')) {
            $script:key.Values[$name] = @{ Value = $name; Kind = [Microsoft.Win32.RegistryValueKind]::String }
        }
        $policiesPath = Join-Path $TestDrive 'Policies.json'
        ConvertTo-Json -InputObject @(@{ KeyName = $script:keyName; ValueName = '**delvals.'; Type = 'REG_SZ'; Data = '' }) |
            Set-Content $policiesPath -Encoding UTF8
        $parameters = @{ UserRegistryRoot = $script:userRoot }
        $parameters["${Scope}PoliciesPath"] = $policiesPath
        $result = Set-RegistryPolicies @parameters -Confirm:$false
        $result.Errors.Count | Should -Be 0
        $result.Success | Should -BeTrue
        $result.Applied | Should -Be 1
        $script:key.Values.Count | Should -Be 0
        $script:key.Deletes | Should -Be 5
        $script:key.Disposals | Should -Be 1
    }

    It 'reports a native <Operation> failure and closes the writable key' -ForEach @(
        @{ Operation = 'DeleteValue' }, @{ Operation = 'SetValue' }
    ) {
        $script:key | Add-Member ScriptMethod $Operation { throw 'Injected native write failure' } -Force
        $script:backup.UserClearKeys[0].Values = @(@{ Name = ''; Type = 'REG_SZ'; Value = 'original' })
        $script:backup | ConvertTo-Json -Depth 12 | Set-Content $script:backupPath -Encoding UTF8
        $hash = (Get-FileHash $script:backupPath).Hash
        $result = Restore-RegistryPolicies -BackupPath $script:backupPath -Confirm:$false
        $result.Success | Should -BeFalse
        $result.Errors[0] | Should -Match 'Injected native write failure'
        $script:key.Disposals | Should -Be 1
        (Get-FileHash $script:backupPath).Hash | Should -BeExactly $hash
    }

    It 'still rejects an ordinary directive with a <Case> name before mutation' -ForEach @(
        @{ Case = 'default'; Name = '' }, @{ Case = 'whitespace'; Name = ' ' }
    ) {
        $script:backup.User[0].ValueName = $Name
        $script:backup | ConvertTo-Json -Depth 12 | Set-Content $script:backupPath -Encoding UTF8
        $result = Restore-RegistryPolicies -BackupPath $script:backupPath -Confirm:$false
        $result.Success | Should -BeFalse
        $result.Errors[0] | Should -Match 'empty value name'
        $script:key.Opens | Should -Be 0
    }
}

Describe 'SecurityBaseline Windows-protected policy key' {
    BeforeAll {
        function Write-ProtectedBackup {
            param([bool]$Exists, $OriginalValue)
            [ordered]@{
                SchemaVersion = 4; UserRegistryRoot = $script:userRoot; AbsentAncestorKeys = @(); DirectiveCount = 1
                Computer = @(@{
                        KeyName = $script:protectedKeyName; ValueName = $script:protectedValue; Type = 'REG_DWORD'
                        OriginalValue = $OriginalValue
                        OriginalValueName = $(if ($Exists) { $script:protectedValue } else { $null })
                        KeyExisted = $true; Exists = $Exists
                    })
                ComputerClearKeys = @(); User = @(); UserClearKeys = @()
            } | ConvertTo-Json -Depth 12 | Set-Content $script:protectedBackupPath -Encoding UTF8
        }
    }

    BeforeEach {
        # Windows owns DriverRanking with a DACL that lets Administrators read only;
        # the provider must never write there.
        $script:protectedKeyName = '[SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'
        $script:protectedValue = 'UseWindowsReadyPrintDriverRankingGroupPolicy'
        $script:key = [pscustomobject]@{
            Values = @{ UseWindowsReadyPrintDriverRanking = @{ Value = 1; Kind = [Microsoft.Win32.RegistryValueKind]::DWord } }
        }
        $script:key | Add-Member ScriptMethod GetValueNames { return [string[]]@($this.Values.Keys) }
        $script:key | Add-Member ScriptMethod GetValueKind { param($name) return $this.Values[$name].Kind }
        $script:key | Add-Member ScriptMethod GetValue {
            param($name, $defaultValue, $options)
            $null = $options
            if (-not $this.Values.ContainsKey($name)) { return $defaultValue }
            return $this.Values[$name].Value
        }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' }
        Mock Test-NoIDRegistryKey { $true } -ParameterFilter { $LiteralPath -like 'HK*' }
        Mock New-NoIDRegistryKey { throw 'Unexpected key creation' }
        Mock Get-Item { $script:key } -ParameterFilter { $LiteralPath -like 'HK*' }
        Mock New-ItemProperty { throw 'Unexpected provider write on a protected key' }
        Mock Remove-ItemProperty { throw 'Unexpected provider deletion on a protected key' }
        Mock Set-NoIDProtectedPolicyRegistryValue {
            $script:key.Values[$Name] = @{ Value = $Value; Kind = $Kind }
        }
        Mock Remove-NoIDProtectedPolicyRegistryValue { $script:key.Values.Remove($Name) }
        Mock Write-Log {}
        $script:protectedBackupPath = Join-Path $TestDrive 'ProtectedRegistryPolicies.json'
    }

    It 'applies the baseline value through the privileged runtime helper' {
        $policiesPath = Join-Path $TestDrive 'ProtectedPolicies.json'
        ConvertTo-Json -InputObject @(@{
                GPO = 'MSFT Windows 11 26H2 - Computer'; KeyName = $script:protectedKeyName
                ValueName = $script:protectedValue; Type = 'REG_DWORD'; Data = 1
            }) | Set-Content $policiesPath -Encoding UTF8
        $result = Set-RegistryPolicies -ComputerPoliciesPath $policiesPath -UserRegistryRoot $script:userRoot -Confirm:$false
        $result.Errors.Count | Should -Be 0
        $result.Success | Should -BeTrue
        $result.Applied | Should -Be 1
        Should -Invoke Set-NoIDProtectedPolicyRegistryValue -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking' -and
            $Name -ceq 'UseWindowsReadyPrintDriverRankingGroupPolicy' -and $Value -eq 1 -and $Kind -eq 'DWord'
        }
        $script:key.Values.UseWindowsReadyPrintDriverRanking.Value | Should -Be 1
    }

    It 'restores an originally absent value by deleting it through the runtime helper' {
        $script:key.Values[$script:protectedValue] = @{ Value = 1; Kind = [Microsoft.Win32.RegistryValueKind]::DWord }
        Write-ProtectedBackup -Exists $false -OriginalValue $null
        $result = Restore-RegistryPolicies -BackupPath $script:protectedBackupPath -Confirm:$false
        $result.Errors.Count | Should -Be 0
        $result.Success | Should -BeTrue
        $script:key.Values.ContainsKey($script:protectedValue) | Should -BeFalse
        $script:key.Values.ContainsKey('UseWindowsReadyPrintDriverRanking') | Should -BeTrue
        Should -Invoke Remove-NoIDProtectedPolicyRegistryValue -Times 1 -Exactly
    }

    It 'restores an original value exactly through the runtime helper' {
        $script:key.Values[$script:protectedValue] = @{ Value = 1; Kind = [Microsoft.Win32.RegistryValueKind]::DWord }
        Write-ProtectedBackup -Exists $true -OriginalValue 0
        $result = Restore-RegistryPolicies -BackupPath $script:protectedBackupPath -Confirm:$false
        $result.Errors.Count | Should -Be 0
        $result.Success | Should -BeTrue
        $script:key.Values[$script:protectedValue].Value | Should -Be 0
        [string]$script:key.Values[$script:protectedValue].Kind | Should -BeExactly 'DWord'
        Should -Invoke Set-NoIDProtectedPolicyRegistryValue -Times 1 -Exactly
    }
}
