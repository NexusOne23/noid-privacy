#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    foreach ($helper in @(
            'Get-AdvancedSecurityRegistryTargets',
            'Get-AdvancedSecuritySchema5RegistryTargets',
            'Assert-AdvancedSecurityRegistrySnapshot',
            'Restore-AdvancedSecurityRegistryState',
            'Backup-AdvancedSecuritySettings'
        )) {
        . (Join-Path $repo "Modules/AdvancedSecurity/Private/$helper.ps1")
    }
    Set-Item -Path function:Get-AdvancedSecurityInteractiveUser -Value {
        param([switch]$AllowNone)
        $null = $AllowNone
        throw 'Interactive-user fixture was not mocked'
    }
    Set-Item -Path function:Invoke-AdvancedSecurityWinInetUserState -Value {
        param($User, [string]$Operation)
        $null = $User, $Operation
        throw 'WinINet fixture was not mocked'
    }
    Set-Item -Path function:Write-Log -Value {
        [CmdletBinding()]
        param([string]$Level, [string]$Message, [string]$Module, [Exception]$Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    Set-Item -Path function:Start-ModuleBackup -Value {
        param([string]$ModuleName)
        $null = $ModuleName
        throw 'Backup-session fixture was not mocked'
    }
    Set-Item -Path function:Register-Backup -Value {
        param([string]$Type, $Data, [string]$Name)
        $null = $Type, $Data, $Name
        throw 'Backup-registration fixture was not mocked'
    }
    Set-Item -Path function:Get-AdvancedSecurityNetBIOSState -Value { throw 'NetBIOS fixture was not mocked' }
    Set-Item -Path function:Assert-AdvancedSecurityNetBIOSSnapshot -Value {
        param($Snapshot)
        $null = $Snapshot
        throw 'NetBIOS validation fixture was not mocked'
    }
    Set-Item -Path function:Test-AdvancedSecurityNetBIOSStateEqual -Value {
        param($Reference, $Candidate)
        $null = $Reference, $Candidate
        throw 'NetBIOS comparison fixture was not mocked'
    }
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        Set-Item -Path function:Get-Service -Value { [CmdletBinding()]param() throw 'Service fixture was not mocked' }
    }
}

Describe 'AdvancedSecurity sealed registry evidence' {
    BeforeEach {
        $script:AdvancedEvidenceHadIndex = Test-Path variable:global:BackupIndex
        $script:AdvancedEvidenceOriginalIndex = Get-Variable -Name BackupIndex -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $global:BackupIndex = @()
        $targets = @(Get-AdvancedSecuritySchema5RegistryTargets -SkipFirewallLayer)
        $script:AdvancedEvidenceSnapshot = [pscustomobject]@{
            SchemaVersion=5; CapturedAt=[DateTime]::UtcNow.ToString('o')
            EditionFamily='Professional'; RdpHostSupported=$true
            ManagedPolicySupported=$true; WirelessDisplaySupported=$true
            SkipFirewallLayer=$true; DisableRDP=$false; AdminSharesDisabled=$false
            DisableUPnP=$false; DisableWirelessDisplayCompletely=$false
            DisableDiscoveryProtocolsCompletely=$false; DisableIPv6Completely=$false
            EnableFirewallShieldsUp=$false; WinInetUsers=@(); TargetCount=$targets.Count
            Entries=@($targets | ForEach-Object {
                    [pscustomobject]@{
                        Path=$_.Path; Name=$_.Name; KeyOnly=$_.KeyOnly
                        KeyExisted=$false; Exists=$false; Type=$null; Value=$null
                    }
                })
        }
        $script:AdvancedEvidenceBackup = Join-Path $TestDrive 'prestate.json'
        $script:AdvancedEvidenceSnapshot | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $script:AdvancedEvidenceBackup -Encoding UTF8
        Mock Get-AdvancedSecurityInteractiveUser { $null }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like 'HKLM:\*' }
        Mock Test-NoIDRegistryKey { $false } -ParameterFilter { $LiteralPath -like 'HKLM:\*' }
        Mock New-Item { throw 'Registry creation must not be reached' } -ParameterFilter { $Path -like 'HKLM:\*' }
        Mock New-NoIDRegistryKey { throw 'Registry creation must not be reached' }
        Mock New-ItemProperty { throw 'Registry mutation must not be reached' }
        $script:AdvancedEvidenceRegistrations = 0
        Mock Start-ModuleBackup { $TestDrive }
        Mock Get-Service { @() }
        Mock Get-AdvancedSecurityNetBIOSState { [pscustomobject]@{Fixture='unchanged'} }
        Mock Assert-AdvancedSecurityNetBIOSSnapshot { $true }
        Mock Test-AdvancedSecurityNetBIOSStateEqual { $true }
        Mock Register-Backup {
            $global:BackupIndex += [pscustomobject]@{Module='AdvancedSecurity';Type=$Type;Name=$Name}
            if ($Name -eq 'AdvancedSecurity_PreState') {
                $script:AdvancedEvidenceRegistrations++
                $null = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $Data
            }
            $script:AdvancedEvidenceBackup
        }
    }

    AfterEach {
        if ($script:AdvancedEvidenceHadIndex) { $global:BackupIndex = $script:AdvancedEvidenceOriginalIndex }
        else { Remove-Variable -Name BackupIndex -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'accepts a complete frozen schema-5 snapshot and verifies its absent values' {
        $validation = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $script:AdvancedEvidenceSnapshot -RestoreOnly
        $validation.TargetCount | Should -Be $script:AdvancedEvidenceSnapshot.TargetCount
        $result = Restore-AdvancedSecurityRegistryState -BackupPath $script:AdvancedEvidenceBackup -Confirm:$false
        $result.Success | Should -BeTrue
        $result.Verified | Should -Be $validation.TargetCount
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }

    It 'fails restore when registry existence queries fail' {
        $ErrorActionPreference = 'Continue'
        Mock Test-Path { Write-Error 'Registry evidence unavailable'; $false } -ParameterFilter {
            $LiteralPath -like 'HKLM:\*'
        }
        Mock Test-NoIDRegistryKey { throw 'Registry evidence unavailable' } -ParameterFilter {
            $LiteralPath -like 'HKLM:\*'
        }
        $result = Restore-AdvancedSecurityRegistryState -BackupPath $script:AdvancedEvidenceBackup -Confirm:$false 2>$null
        $result.Success | Should -BeFalse
        $result.Verified | Should -Be 0
        $result.Errors -join '; ' | Should -Match 'Registry evidence unavailable'
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }

    It 'captures a complete schema-5 registry inventory when absence is readable' {
        $result = Backup-AdvancedSecuritySettings -SkipFirewallLayer -Confirm:$false
        $result.Success | Should -BeTrue
        $script:AdvancedEvidenceRegistrations | Should -Be 1
    }

    It 'reports a failed user-state capture once, without follow-on reconciliation failures' {
        Mock Get-AdvancedSecurityInteractiveUser {
            [pscustomobject]@{Account='PC\user'; Sid='S-1-5-21-1-2-3-1001'; SessionId=1; HiveRoot='HKU:\S-1-5-21-1-2-3-1001'}
        }
        Mock Invoke-AdvancedSecurityWinInetUserState { throw 'Original-user worker fixture failed' }
        $result = Backup-AdvancedSecuritySettings -SkipFirewallLayer -Confirm:$false
        $result.Success | Should -BeFalse
        $failures = $result.Failures -join '; '
        $failures | Should -Match 'Targeted AdvancedSecurity pre-state failed: Original-user worker fixture failed'
        $failures | Should -Not -Match 'Pre-seal live-state reconciliation|Interactive Explorer user changed'
        $script:AdvancedEvidenceRegistrations | Should -Be 0
        # The prestate asks once; a skipped reconciliation never asks again.
        Should -Invoke Get-AdvancedSecurityInteractiveUser -Times 1 -Exactly
    }

    It 'does not register unreadable registry state as an absent prestate' {
        $ErrorActionPreference = 'Continue'
        Mock Test-Path { Write-Error 'Registry evidence unavailable'; $false } -ParameterFilter {
            $LiteralPath -like 'HKLM:\*'
        }
        Mock Test-NoIDRegistryKey { throw 'Registry evidence unavailable' } -ParameterFilter {
            $LiteralPath -like 'HKLM:\*'
        }
        $result = Backup-AdvancedSecuritySettings -SkipFirewallLayer -Confirm:$false 2>$null
        $result.Success | Should -BeFalse
        $script:AdvancedEvidenceRegistrations | Should -Be 0
        $result.Failures -join '; ' | Should -Match 'Registry evidence unavailable'
    }
}
