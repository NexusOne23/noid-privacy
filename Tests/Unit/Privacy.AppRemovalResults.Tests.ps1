#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/Privacy/Private/PrivacyUserAppx.ps1')
    function Get-AppRemovalFixture {
        param([int]$Count = 1)
        [pscustomobject]@{
            TargetPackages=$Count;Removed=$Count;Failed=0;Success=$true;Error=$null
            Entries=@(1..$Count | ForEach-Object {
                [pscustomobject]@{AppName="Fixture.App$_";PackageFullName="Fixture.App$($_)_1_x64__fixture";Removed=$true;Error=''}
            })
        }
    }
}

Describe 'Authoritative per-app removal results' {
    BeforeEach { Mock Get-AppxPackage { @() } }

    It 'retains fourteen verified removals when one app was registered again' {
        Mock Get-AppxPackage { [pscustomobject]@{PackageUserInformation=@()} } -ParameterFilter { $Name -eq 'Fixture.App15' }
        $result = Confirm-PrivacyAppxRemovalResult -Record (Get-AppRemovalFixture -Count 15) -UserSid 'S-1-5-21-1-2-3-1001'
        $result.Success | Should -BeFalse
        $result.Removed | Should -Be 14
        $result.Failed | Should -Be 1
        $result.Entries[14].Error | Should -Match 'registered again by Windows'
        Should -Invoke Get-AppxPackage -Exactly -Times 30
    }

    It 'rejects pending registration even when the per-user query appears empty' {
        Mock Get-AppxPackage {
            [pscustomobject]@{PackageUserInformation=@(
                [pscustomobject]@{UserSecurityId=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001'};InstallState='Installed'}
            )}
        } -ParameterFilter { $AllUsers }
        $result = Confirm-PrivacyAppxRemovalResult -Record (Get-AppRemovalFixture) -UserSid 'S-1-5-21-1-2-3-1001'
        $result.Success | Should -BeFalse
        $result.Removed | Should -Be 0
        $result.Failed | Should -Be 1
    }

    It 'does not mistake another user registration for the target user' {
        Mock Get-AppxPackage {
            [pscustomobject]@{PackageUserInformation=@(
                [pscustomobject]@{UserSecurityId=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1002'};InstallState='Installed'}
            )}
        } -ParameterFilter { $AllUsers }
        (Confirm-PrivacyAppxRemovalResult -Record (Get-AppRemovalFixture) -UserSid 'S-1-5-21-1-2-3-1001').Success | Should -BeTrue
    }

    It 'keeps an unreadable app unverified while checking the remaining apps' {
        Mock Get-AppxPackage { throw 'fixture provider failure' } -ParameterFilter { $Name -eq 'Fixture.App1' }
        $result = Confirm-PrivacyAppxRemovalResult -Record (Get-AppRemovalFixture -Count 2) -UserSid 'S-1-5-21-1-2-3-1001'
        $result.Success | Should -BeFalse
        $result.Removed | Should -Be 1
        $result.Failed | Should -Be 1
        $result.Entries[0].Error | Should -Match 'Could not verify.*fixture provider failure'
    }

    It 'accepts independently verified absence after a worker removal error' {
        $record = Get-AppRemovalFixture
        $record.Entries[0].Removed=$false
        $record.Entries[0].Error='Concurrent removal'
        $record.Removed=0; $record.Failed=1; $record.Success=$false
        $result = Confirm-PrivacyAppxRemovalResult -Record $record -UserSid 'S-1-5-21-1-2-3-1001'
        $result.Success | Should -BeTrue
        $result.Removed | Should -Be 1
        $result.Failed | Should -Be 0
    }
}

Describe 'Sealed app identity preflight' {
    It 'accepts an already absent package without trying to remove it' {
        Mock Get-AppxPackage { @() }
        { Assert-PrivacyAppxRemovalInventory -Entries (Get-AppRemovalFixture).Entries } | Should -Not -Throw
    }

    It 'rejects a new version outside the sealed inventory' {
        Mock Get-AppxPackage { [pscustomobject]@{PackageFullName='Fixture.App1_2_x64__fixture';IsBundle=$false} }
        { Assert-PrivacyAppxRemovalInventory -Entries (Get-AppRemovalFixture).Entries } | Should -Throw '*identity drifted*'
    }

    It 'rejects duplicate live identities before mutation' {
        Mock Get-AppxPackage { 1..2 | ForEach-Object { [pscustomobject]@{PackageFullName='Fixture.App1_1_x64__fixture';IsBundle=$false} } }
        { Assert-PrivacyAppxRemovalInventory -Entries (Get-AppRemovalFixture).Entries } | Should -Throw '*identity drifted*'
    }

    It 'does not turn an inventory query failure into already absent' {
        Mock Get-AppxPackage { throw 'fixture enumeration failure' }
        { Assert-PrivacyAppxRemovalInventory -Entries (Get-AppRemovalFixture).Entries } | Should -Throw '*fixture enumeration failure*'
    }
}
