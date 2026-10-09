#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    foreach ($helper in @(
        'Get-PrivacyTier1PolicyDefinition', 'Get-PrivacyTier1RestorePolicyDefinitions',
        'Assert-PrivacyRegistrySnapshot', 'Backup-PrivacySettings',
        'Assert-PrivacyPrestate', 'Restore-PrivacyRegistryState',
        'Get-PrivacyApplicability', 'Get-PrivacyRuntimeTargetPlan', 'Set-PrivacyRegistryTargets',
        'PrivacyAppxFirewall'
    )) {
        . (Join-Path $repo "Modules/Privacy/Private/$helper.ps1")
    }
    function Send-PrivacySearchPolicyChangeNotification {
        param($Entries)
        $null = $Entries
        throw 'Unmocked Search notification'
    }
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:Get-Service -Value { [CmdletBinding()] param() throw 'Unmocked service query' }
    }
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module)
        $null = $Level, $Message, $Module
    }
}

Describe 'Privacy AppX firewall registry evidence' {
    BeforeEach {
        $ErrorActionPreference = 'Continue'
        Mock Test-NoIDRegistryKey { throw 'Firewall registry existence query failed' } -ParameterFilter {
            $LiteralPath -eq $script:PrivacyAppxFirewallRegistryPath
        }
    }

    It 'rejects an unreadable firewall key with <Label>' -TestCases @(
        @{ Label = 'no selected families'; Families = @() },
        @{ Label = 'a selected family'; Families = @('Test.App_testpub') }
    ) {
        param($Label, $Families)
        $null = $Label
        $script:FirewallEvidenceFamilies = $Families
        { Get-PrivacyAppxFirewallState -PackageFamilyNames @($script:FirewallEvidenceFamilies) 2>$null } |
            Should -Throw '*Firewall registry existence query failed*'
    }

    It 'rejects an unverified firewall restore even when the sealed original key was absent' {
        $state = [pscustomobject]@{
            SchemaVersion = 1
            RegistryPath = $script:PrivacyAppxFirewallRegistryPath
            KeyExisted = $false
            PackageFamilyNames = @()
            EntryCount = 0
            Entries = @()
            StateSha256 = ''
        }
        $state.StateSha256 = Get-PrivacyAppxFirewallStateHash -State $state
        Assert-PrivacyAppxFirewallState -State $state | Should -BeTrue
        { Restore-PrivacyAppxFirewallState -State $state 2>$null } |
            Should -Throw '*Firewall registry existence query failed*'
    }

    It 'preserves a successfully queried absent empty firewall state' {
        Mock Test-NoIDRegistryKey { $false } -ParameterFilter {
            $LiteralPath -eq $script:PrivacyAppxFirewallRegistryPath
        }
        $state = Get-PrivacyAppxFirewallState -PackageFamilyNames @()
        $state.KeyExisted | Should -BeFalse
        $state.EntryCount | Should -Be 0
        $result = Restore-PrivacyAppxFirewallState -State $state
        $result.Success | Should -BeTrue
        $result.Restored | Should -Be 0
        $result.Removed | Should -Be 0
    }
}

Describe 'Privacy registry absence requires a successful query' {
    BeforeEach {
        $ErrorActionPreference = 'Continue'
        $script:RegistryEvidencePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        $script:RegistryEvidenceSnapshot = [pscustomobject]@{
            SchemaVersion = 3
            Mode = 'MSRecommended'
            InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
            EditionFamily = 'Professional'
            BuildNumber = 26100
            DeclaredRegistryTargetCount = 1
            TargetCount = 1
            Entries = @([pscustomobject]@{
                Path = $script:RegistryEvidencePath
                Name = 'AllowTelemetry'
                ApplyType = 'DWord'
                ApplyValue = 1
                KeyExisted = $false
                Exists = $false
                Type = $null
                Value = $null
            })
            NotApplicableRegistryTargets = @()
            DeclaredServiceNames = @()
            ApplicableServiceNames = @()
            DeclaredScheduledTaskPaths = @()
            ApplicableScheduledTaskPaths = @()
        }
        $script:RegistryEvidenceBackup = Join-Path $TestDrive 'privacy-prestate.json'
        $script:RegistryEvidenceSnapshot | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $script:RegistryEvidenceBackup -Encoding UTF8
        # Use the actual frozen reader and a valid legacy snapshot. An unrelated
        # schema failure cannot stand in for detecting the injected read error.
        Assert-PrivacyRegistrySnapshot -Snapshot $script:RegistryEvidenceSnapshot -RestoreOnly |
            Should -BeTrue
        Mock Send-PrivacySearchPolicyChangeNotification { $true }
        Mock Get-Service { @() }
        Mock Get-PrivacyApplicability {
            [pscustomobject]@{ EditionFamily = 'Professional'; BuildNumber = 26100 }
        }
        Mock Get-PrivacyRuntimeTargetPlan {
            [pscustomobject]@{
                RegistryPlan = [pscustomobject]@{
                    ApplicableTargets = @([pscustomobject]@{
                        Path = $script:RegistryEvidencePath
                        Name = 'AllowTelemetry'; Type = 'DWord'; Value = 1
                    })
                }
            }
        }
        Mock Get-PrivacyAppxFirewallState { throw 'Backup advanced past an unreadable registry prestate' }
        Mock Test-NoIDRegistryKey { $true } -ParameterFilter { $LiteralPath -like 'HKLM:\*' }
        Mock Test-NoIDRegistryKey { throw 'Registry existence query failed' } -ParameterFilter {
            $LiteralPath -eq $script:RegistryEvidencePath
        }
    }

    It 'stops backup collection before registering an unreadable target as absent' {
        $result = Backup-PrivacySettings -Config ([pscustomobject]@{ Mode = 'MSRecommended' }) -Confirm:$false 2>$null
        $result.Success | Should -BeFalse
        $result.Count | Should -Be 0
        ($result.Failures -join '; ') | Should -BeLike '*Registry existence query failed*'
        Should -Invoke Get-PrivacyAppxFirewallState -Times 0 -Exactly
    }

    It 'rejects the pre-Apply gate when original absence cannot be rechecked' {
        $artifacts = @([pscustomobject]@{
            Type = 'Privacy'; Name = 'Privacy_PreState'; BackupFile = $script:RegistryEvidenceBackup
        })
        { Assert-PrivacyPrestate -SnapshotPath $script:RegistryEvidenceBackup -Artifacts $artifacts 2>$null } |
            Should -Throw '*Registry existence query failed*'
    }

    It 'never reports a verified restore when registry queries failed' {
        $beforeHash = (Get-FileHash -LiteralPath $script:RegistryEvidenceBackup).Hash
        $result = Restore-PrivacyRegistryState -BackupPath $script:RegistryEvidenceBackup 2>$null
        $result.Success | Should -BeFalse
        $result.Verified | Should -Be 0
        ($result.Errors -join '; ') | Should -BeLike '*Registry existence query failed*'
        (Get-FileHash -LiteralPath $script:RegistryEvidenceBackup).Hash | Should -BeExactly $beforeHash
        Should -Invoke Send-PrivacySearchPolicyChangeNotification -Times 0 -Exactly
    }

    It 'does not create a registry key after an Apply-time existence query failed' {
        Mock Assert-PrivacyRegistrySnapshot { $true }
        Mock New-Item { throw 'Apply attempted a mutation after an unreadable target' }
        Mock New-NoIDRegistryKey { throw 'Apply attempted a mutation after an unreadable target' }
        $applySnapshot = $script:RegistryEvidenceSnapshot.PSObject.Copy()
        $applySnapshot.SchemaVersion = 7
        { Set-PrivacyRegistryTargets -Snapshot $applySnapshot -Confirm:$false 2>$null } |
            Should -Throw '*Registry existence query failed*'
        Should -Invoke New-Item -Times 0 -Exactly
        Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
    }

    It 'still verifies proven absence on repeated legacy restores without modifying backup bytes' {
        Mock Test-NoIDRegistryKey { $false } -ParameterFilter { $LiteralPath -eq $script:RegistryEvidencePath }
        $beforeHash = (Get-FileHash -LiteralPath $script:RegistryEvidenceBackup).Hash
        foreach ($attempt in 1..2) {
            $result = Restore-PrivacyRegistryState -BackupPath $script:RegistryEvidenceBackup
            $result.Success | Should -BeTrue -Because "restore attempt $attempt"
            $result.Verified | Should -Be 1
            @($result.Errors).Count | Should -Be 0
            (Get-FileHash -LiteralPath $script:RegistryEvidenceBackup).Hash | Should -BeExactly $beforeHash
        }
    }
}
