#Requires -Version 5.1

BeforeDiscovery {
    $script:TransientOwnershipElevated = $false
    if ($env:OS -eq 'Windows_NT') {
        $script:TransientOwnershipElevated = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($helper in @('Get-PrivacyUserContext', 'PrivacyAppxFirewall', 'PrivacyUserAppx', 'PrivacyWindowsSearch')) {
        . (Join-Path $repo "Modules/Privacy/Private/$helper.ps1")
    }
    function Invoke-TransientOwnershipFixture {
        param([string]$Worker)
        if ($Worker -eq 'Search') {
            Invoke-PrivacyWindowsSearchUserState -User $script:TransientOwnershipUser -Operation Query
        }
        else {
            Invoke-PrivacyUserAppxRemoval -User $script:TransientOwnershipUser -Entries @(
                [pscustomobject]@{AppName='Fixture.App';PackageFullName='Fixture.App_1';PackageFamilyName='Fixture.App_fixture'}
            )
        }
    }
}

Describe 'Privacy transient directory ownership: <Worker>' -ForEach @(
    @{Worker='Search'}, @{Worker='Appx'}
) -Skip:(-not $script:TransientOwnershipElevated) {
    BeforeEach {
        $script:TransientOwnershipOriginalProgramData = $env:ProgramData
        $env:ProgramData = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($env:ProgramData)
        $script:TransientOwnershipUser = [pscustomobject]@{
            Account='FixtureUser'; Sid='S-1-5-21-1-2-3-1001'; SessionId=1
        }
        $script:TransientOwnershipDirectory = $null
        Mock Get-PrivacyUserContext { $script:TransientOwnershipUser }
        Mock Get-PrivacyAppxFirewallState { [pscustomobject]@{Entries=@()} }
        Mock New-ScheduledTaskAction { throw 'fixture failure after directory creation' }
        Mock Register-ScheduledTask { throw 'fixture must not register a task' }
    }

    AfterEach {
        $env:ProgramData = $script:TransientOwnershipOriginalProgramData
    }

    It 'preserves a foreign directory when exclusive creation fails' {
        Mock New-Item {
            $script:TransientOwnershipDirectory = $Path
            $null = [IO.Directory]::CreateDirectory($Path)
            [IO.File]::WriteAllText((Join-Path $Path 'foreign.txt'), 'preserve me')
            throw 'fixture directory already exists'
        } -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like "$env:ProgramData\NoID-*" }

        { Invoke-TransientOwnershipFixture -Worker $Worker } | Should -Throw '*fixture directory already exists*'
        $script:TransientOwnershipDirectory | Should -Not -BeNullOrEmpty
        $sentinel = Join-Path $script:TransientOwnershipDirectory 'foreign.txt'
        Test-Path -LiteralPath $sentinel | Should -BeTrue
        Get-Content -LiteralPath $sentinel -Raw | Should -BeExactly 'preserve me'
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }

    It 'cleans its own directory after a later failure' {
        Mock New-Item {
            $script:TransientOwnershipDirectory = $Path
            [IO.Directory]::CreateDirectory($Path)
        } -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like "$env:ProgramData\NoID-*" }

        { Invoke-TransientOwnershipFixture -Worker $Worker } | Should -Throw '*fixture failure after directory creation*'
        $script:TransientOwnershipDirectory | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $script:TransientOwnershipDirectory | Should -BeFalse
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }
}
