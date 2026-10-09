#Requires -Version 5.1

BeforeDiscovery {
    $script:AdvancedTransientElevated = $false
    if ($env:OS -eq 'Windows_NT') {
        $script:AdvancedTransientElevated = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityWinInet.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallPolicyState.ps1')
    function Invoke-AdvancedTransientFixture {
        param([string]$Worker)
        if ($Worker -eq 'WinInet') {
            Invoke-AdvancedSecurityWinInetUserState -User $script:AdvancedTransientUser -Operation Query
        }
        else {
            Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $script:AdvancedTransientPolicy
        }
    }
}

Describe 'AdvancedSecurity transient directory ownership: <Worker>' -ForEach @(
    @{ Worker = 'WinInet' }, @{ Worker = 'FirewallHive' }
) -Skip:(-not $script:AdvancedTransientElevated) {
    BeforeEach {
        $script:AdvancedTransientOriginalProgramData = $env:ProgramData
        $env:ProgramData = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($env:ProgramData)
        $script:AdvancedTransientUser = [pscustomobject]@{
            Account = 'FixtureUser'; Sid = 'S-1-5-21-1-2-3-1001'; SessionId = 1
        }
        $script:AdvancedTransientPolicy = Join-Path $TestDrive 'source.wfw'
        [IO.File]::WriteAllText($script:AdvancedTransientPolicy, 'fixture; never mounted')
        $script:AdvancedTransientDirectory = $null
        Mock Get-AdvancedSecurityInteractiveUser { $script:AdvancedTransientUser }
        Mock New-ScheduledTaskAction { throw 'fixture failure after directory creation' }
        Mock Register-ScheduledTask { throw 'fixture must not register a task' }
        Mock Invoke-AdvancedSecurityRegistryTool { throw 'fixture failure after directory creation' }
    }

    AfterEach {
        $env:ProgramData = $script:AdvancedTransientOriginalProgramData
        # The failed-creation fixture deliberately leaves its own sentinel.
        # Remove only this exact directory, whose creation the test recorded.
        if ($script:AdvancedTransientDirectory -and [IO.Directory]::Exists($script:AdvancedTransientDirectory)) {
            [IO.Directory]::Delete($script:AdvancedTransientDirectory, $true)
        }
    }

    It 'preserves a foreign directory when exclusive creation fails' {
        Mock New-Item {
            $script:AdvancedTransientDirectory = $Path
            $null = [IO.Directory]::CreateDirectory($Path)
            [IO.File]::WriteAllText((Join-Path $Path 'foreign.txt'), 'preserve me')
            throw 'fixture directory already exists'
        } -ParameterFilter { $ItemType -eq 'Directory' -and ($Path -like '*NoID-WinInet-*' -or $Path -like '*NoIDFirewall_*') }

        { Invoke-AdvancedTransientFixture -Worker $Worker } | Should -Throw '*fixture directory already exists*'
        $script:AdvancedTransientDirectory | Should -Not -BeNullOrEmpty
        $sentinel = Join-Path $script:AdvancedTransientDirectory 'foreign.txt'
        Test-Path -LiteralPath $sentinel | Should -BeTrue
        Get-Content -LiteralPath $sentinel -Raw | Should -BeExactly 'preserve me'
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
        Should -Invoke Invoke-AdvancedSecurityRegistryTool -Times 0 -Exactly
    }

    It 'cleans its own directory after a later failure' {
        Mock New-Item {
            $script:AdvancedTransientDirectory = $Path
            [IO.Directory]::CreateDirectory($Path)
        } -ParameterFilter { $ItemType -eq 'Directory' -and ($Path -like '*NoID-WinInet-*' -or $Path -like '*NoIDFirewall_*') }

        { Invoke-AdvancedTransientFixture -Worker $Worker } | Should -Throw '*fixture failure after directory creation*'
        $script:AdvancedTransientDirectory | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $script:AdvancedTransientDirectory | Should -BeFalse
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }

    It 'never merges into a pre-existing exchange directory with Force' {
        Mock New-Item {
            $script:AdvancedTransientDirectory = $Path
            $directory = [IO.Directory]::CreateDirectory($Path)
            [IO.File]::WriteAllText((Join-Path $Path 'foreign.txt'), 'preserve me')
            if ($Force) { return $directory }
            throw 'fixture directory already exists'
        } -ParameterFilter { $ItemType -eq 'Directory' -and ($Path -like '*NoID-WinInet-*' -or $Path -like '*NoIDFirewall_*') }

        { Invoke-AdvancedTransientFixture -Worker $Worker } | Should -Throw '*fixture directory already exists*'
        Test-Path -LiteralPath (Join-Path $script:AdvancedTransientDirectory 'foreign.txt') | Should -BeTrue
        Should -Invoke Invoke-AdvancedSecurityRegistryTool -Times 0 -Exactly
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }
}

Describe 'AdvancedSecurity WinINet exchange cleanup never recurses' -Skip:(-not $script:AdvancedTransientElevated) {
    BeforeEach {
        $script:AdvancedTransientOriginalProgramData = $env:ProgramData
        $env:ProgramData = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($env:ProgramData)
        $script:AdvancedTransientUser = [pscustomobject]@{
            Account = 'FixtureUser'; Sid = 'S-1-5-21-1-2-3-1001'; SessionId = 1
        }
        $script:AdvancedTransientDirectory = $null
        Mock Get-AdvancedSecurityInteractiveUser { $script:AdvancedTransientUser }
        Mock New-ScheduledTaskAction { throw 'fixture failure after directory creation' }
        Mock Register-ScheduledTask { throw 'fixture must not register a task' }
    }

    AfterEach {
        $env:ProgramData = $script:AdvancedTransientOriginalProgramData
        if ($script:AdvancedTransientDirectory -and [IO.Directory]::Exists($script:AdvancedTransientDirectory)) {
            [IO.Directory]::Delete($script:AdvancedTransientDirectory, $true)
        }
    }

    It 'keeps content planted inside the user-writable exchange directory' {
        # The interactive user may write into the exchange directory; the
        # privileged cleanup must fail instead of deleting unexpected content.
        Mock New-Item {
            $script:AdvancedTransientDirectory = $Path
            $directory = [IO.Directory]::CreateDirectory($Path)
            $planted = [IO.Directory]::CreateDirectory((Join-Path $Path 'planted'))
            [IO.File]::WriteAllText((Join-Path $planted.FullName 'keep.txt'), 'preserve me')
            $directory
        } -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like '*NoID-WinInet-*' }

        { Invoke-AdvancedSecurityWinInetUserState -User $script:AdvancedTransientUser -Operation Query } | Should -Throw
        $script:AdvancedTransientDirectory | Should -Not -BeNullOrEmpty
        Get-Content -LiteralPath (Join-Path $script:AdvancedTransientDirectory 'planted\keep.txt') -Raw |
            Should -BeExactly 'preserve me'
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }
}
