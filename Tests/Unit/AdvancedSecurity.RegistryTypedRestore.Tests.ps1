#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    foreach ($helper in @('Get-AdvancedSecuritySchema5RegistryTargets', 'Get-AdvancedSecuritySchema6RegistryTargets',
            'Get-AdvancedSecurityRegistryTargets',
            'Assert-AdvancedSecurityRegistrySnapshot', 'Restore-AdvancedSecurityRegistryState',
            'Backup-AdvancedSecuritySettings', 'AdvancedSecurityNetBIOS')) {
        . (Join-Path $repo "Modules/AdvancedSecurity/Private/$helper.ps1")
    }
    function Get-AdvancedSecurityInteractiveUser {
        param([switch]$AllowNone)
        $null = $AllowNone
        throw 'Interactive-user fixture was not mocked'
    }
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    Set-Item -Path function:Start-ModuleBackup -Value {
        param($ModuleName)
        $null = $ModuleName
        throw 'Backup-session fixture was not mocked'
    }
    function Register-Backup {
        param($Type, $Data, $Name)
        $null = $Type, $Data, $Name
        throw 'Backup-registration fixture was not mocked'
    }

    function Save-TypedRegistryFixture {
        param([string]$Kind, [AllowNull()]$Data)
        $script:TypedRegistryHandle.SetValue('Canary', 41, [Microsoft.Win32.RegistryValueKind]::DWord)
        $script:TypedRegistryHandle.SetValue('SavedValue', $Data, [Microsoft.Win32.RegistryValueKind]$Kind)
        $backup = Backup-AdvancedSecuritySettings -SkipFirewallLayer -Confirm:$false
        $backup.Success | Should -BeTrue -Because ($backup.Failures -join '; ')
        foreach ($name in @('Canary', 'SavedValue')) {
            $script:TypedRegistryHandle.SetValue($name, 99, [Microsoft.Win32.RegistryValueKind]::DWord)
        }
    }
}

Describe 'AdvancedSecurity exact typed registry restore' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        # Isolate registry targets and unrelated service/network bookkeeping.
        # Backup's native registry capture, snapshot validation, JSON transport
        # and every registry restore/readback operation are real.
        $script:TypedRegistryHadIndex = Test-Path variable:global:BackupIndex
        $script:TypedRegistryOriginalIndex = Get-Variable BackupIndex -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $global:BackupIndex = @()
        $script:TypedRegistrySubkey = 'Software\NoID-Registry-Test-' + [Guid]::NewGuid().ToString('N')
        $script:TypedRegistryPath = 'HKCU:\' + $script:TypedRegistrySubkey
        $script:TypedRegistryHandle = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:TypedRegistrySubkey)
        # New backups are schema 6; Restore validates them against the frozen
        # schema-6 list, so both the live and the frozen list name the fixture.
        Mock Get-AdvancedSecuritySchema6RegistryTargets {
            [pscustomobject]@{Path=$script:TypedRegistryPath;Name='';KeyOnly=$true}
            [pscustomobject]@{Path=$script:TypedRegistryPath;Name='Canary';KeyOnly=$false}
            [pscustomobject]@{Path=$script:TypedRegistryPath;Name='SavedValue';KeyOnly=$false}
        }
        Mock Get-AdvancedSecurityInteractiveUser { $null }
        Mock Get-AdvancedSecurityRegistryTargets { Get-AdvancedSecuritySchema6RegistryTargets }
        Mock Start-ModuleBackup { $TestDrive }
        Mock Get-Service { [pscustomobject]@{Name='UnrelatedFixtureService'} }
        Mock Get-AdvancedSecurityNetBIOSState { [pscustomobject]@{Fixture='unchanged'} }
        Mock Assert-AdvancedSecurityNetBIOSSnapshot { $true }
        Mock Test-AdvancedSecurityNetBIOSStateEqual { $true }
        Mock Register-Backup {
            $path = Join-Path $TestDrive "$Name.json"
            $Data | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
            $global:BackupIndex += [pscustomobject]@{Module='AdvancedSecurity';Type=$Type;Name=$Name;BackupFile=$path}
            if ($Name -eq 'AdvancedSecurity_PreState') {
                $script:TypedRegistryBackup = $path
                $script:TypedRegistrySnapshot = $Data
            }
            $path
        }
    }

    AfterEach {
        if ($script:TypedRegistryHandle) {
            $script:TypedRegistryHandle.Dispose()
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:TypedRegistrySubkey, $false)
        }
        if ($script:TypedRegistryHadIndex) { $global:BackupIndex = $script:TypedRegistryOriginalIndex }
        else { Remove-Variable BackupIndex -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'restores and repeats <Label> without changing the schema-6 artifact' -TestCases @(
        @{Label='DWORD zero';Kind='DWord';Data=[int]0},
        @{Label='DWORD high bit';Kind='DWord';Data=[int]-1},
        @{Label='QWORD high bit';Kind='QWord';Data=[long]::MinValue},
        @{Label='literal expandable string';Kind='ExpandString';Data='%USERPROFILE%\owner-value'},
        @{Label='empty string';Kind='String';Data=''},
        @{Label='ordinary string';Kind='String';Data='owner-value'},
        @{Label='empty binary';Kind='Binary';Data=[byte[]]@()},
        @{Label='one binary byte';Kind='Binary';Data=[byte[]]@(0)},
        @{Label='binary byte array';Kind='Binary';Data=[byte[]]@(0,128,255)},
        @{Label='empty multi-string';Kind='MultiString';Data=[string[]]@()},
        @{Label='one multi-string item';Kind='MultiString';Data=[string[]]@('one')},
        @{Label='multiple multi-string items';Kind='MultiString';Data=[string[]]@('one','two')}
    ) {
        param($Label, $Kind, $Data)
        $null = $Label
        Save-TypedRegistryFixture -Kind $Kind -Data $Data
        $hash = (Get-FileHash -LiteralPath $script:TypedRegistryBackup -Algorithm SHA256).Hash
        foreach ($attempt in 1..2) {
            $script:TypedRegistryHandle.SetValue('Canary', 99 + $attempt, [Microsoft.Win32.RegistryValueKind]::DWord)
            $result = Restore-AdvancedSecurityRegistryState -BackupPath $script:TypedRegistryBackup -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
            $result.Verified | Should -Be 3
            $script:TypedRegistryHandle.GetValue('Canary') | Should -Be 41
            $script:TypedRegistryHandle.GetValueKind('SavedValue').ToString() | Should -BeExactly $Kind
            $actual = $script:TypedRegistryHandle.GetValue('SavedValue', $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            (ConvertTo-Json -InputObject $actual -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $Data -Compress)
            (Get-FileHash -LiteralPath $script:TypedRegistryBackup -Algorithm SHA256).Hash | Should -BeExactly $hash
        }
    }

    It 'rejects <Label> before restoring an earlier valid canary' -TestCases @(
        @{Label='overflowing DWORD';Kind='DWord';Data=[long]2147483648},
        @{Label='overflowing QWORD';Kind='QWord';Data='9223372036854775808'},
        @{Label='string-encoded DWORD';Kind='DWord';Data='7'},
        @{Label='Boolean DWORD';Kind='DWord';Data=$true},
        @{Label='null DWORD';Kind='DWord';Data=$null},
        @{Label='Boolean QWORD';Kind='QWord';Data=$true},
        @{Label='array-valued string';Kind='String';Data=@('one','two')},
        @{Label='null string';Kind='String';Data=$null},
        @{Label='numeric multi-string';Kind='MultiString';Data=@(1,2)},
        @{Label='null binary';Kind='Binary';Data=$null},
        @{Label='negative binary byte';Kind='Binary';Data=@(-1)},
        @{Label='oversized binary byte';Kind='Binary';Data=@(256)}
    ) {
        param($Label, $Kind, $Data)
        $null = $Label
        Save-TypedRegistryFixture -Kind DWord -Data 7
        $entry = $script:TypedRegistrySnapshot.Entries[2]
        $entry.Type = $Kind
        $entry.Value = $Data
        $script:TypedRegistrySnapshot | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $script:TypedRegistryBackup -Encoding UTF8
        $hash = (Get-FileHash -LiteralPath $script:TypedRegistryBackup -Algorithm SHA256).Hash
        $result = Restore-AdvancedSecurityRegistryState -BackupPath $script:TypedRegistryBackup -Confirm:$false
        $result.Success | Should -BeFalse
        ($result.Errors -join '; ') | Should -Not -Match 'invalid or duplicate target' -Because 'the fixture targets must be accepted so that only the value is rejected'
        $script:TypedRegistryHandle.GetValue('Canary') | Should -Be 99 -Because 'all saved values must be validated before the first restore write'
        $result.Restored | Should -Be 0
        { Assert-AdvancedSecurityRegistrySnapshot -Snapshot $script:TypedRegistrySnapshot -RestoreOnly } | Should -Throw
        (Get-FileHash -LiteralPath $script:TypedRegistryBackup -Algorithm SHA256).Hash | Should -BeExactly $hash
    }
}
