#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/PrivacyWindowsSearch.ps1')
    function Get-SearchStateTestKey {
        param([string]$Path)
        $key = [pscustomobject]@{
            PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\' + $Path.Substring(6)
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { return @() }
        return $key
    }
}

Describe 'Exact Windows Search registry observation' {
    BeforeEach {
        $script:SearchStateRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
        $script:SearchStateKeys = @()
        Mock Test-NoIDRegistryKey { $LiteralPath -in $script:SearchStateKeys } -ParameterFilter {
            $LiteralPath -like 'HKCU:\*'
        }
        Mock Get-Item { Get-SearchStateTestKey -Path $LiteralPath } -ParameterFilter {
            $LiteralPath -like 'HKCU:\*'
        }
        Mock Get-ChildItem {
            $parentPath = [string]@($LiteralPath)[0]
            foreach ($path in $script:SearchStateKeys) {
                if ($path.StartsWith($parentPath + '\', [StringComparison]::Ordinal)) {
                    Get-SearchStateTestKey -Path $path
                }
            }
        } -ParameterFilter { $LiteralPath -like 'HKCU:\*' }
    }

    It 'detects creation and deletion of an empty root' {
        $absent = @(Get-PrivacyWindowsSearchRegistryState)
        $script:SearchStateKeys = @($script:SearchStateRoot)
        $present = @(Get-PrivacyWindowsSearchRegistryState)
        Test-PrivacyWindowsSearchExactState -Expected $absent -Actual $present | Should -BeFalse
        Test-PrivacyWindowsSearchExactState -Expected $present -Actual $absent | Should -BeFalse
    }

    It 'detects an empty descendant even when the root already existed' {
        $script:SearchStateKeys = @($script:SearchStateRoot)
        $before = @(Get-PrivacyWindowsSearchRegistryState)
        $script:SearchStateKeys += $script:SearchStateRoot + '\EmptyChild'
        $after = @(Get-PrivacyWindowsSearchRegistryState)
        Test-PrivacyWindowsSearchExactState -Expected $before -Actual $after | Should -BeFalse
    }

    It 'accepts an unchanged empty tree' {
        $script:SearchStateKeys = @($script:SearchStateRoot, ($script:SearchStateRoot + '\EmptyChild'))
        $before = @(Get-PrivacyWindowsSearchRegistryState)
        $after = @(Get-PrivacyWindowsSearchRegistryState)
        Test-PrivacyWindowsSearchExactState -Expected $before -Actual $after | Should -BeTrue
    }

    It 'rejects unreadable roots instead of observing an empty tree' {
        $ErrorActionPreference = 'Continue'
        Mock Test-NoIDRegistryKey { throw 'Search registry query failed' } -ParameterFilter {
            $LiteralPath -like 'HKCU:\*'
        }
        { Get-PrivacyWindowsSearchRegistryState 2>$null } | Should -Throw '*Search registry query failed*'
    }
}

Describe 'Windows Search user worker deadline' {
    It 'allows the measured slow first provider call and keeps the AppX worker bound' {
        $command = Get-Command Invoke-PrivacyWindowsSearchUserState
        $timeout = $command.Parameters['TimeoutSeconds']
        $range = @($timeout.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] })
        $range.Count | Should -Be 1
        [int]$range[0].MaxRange | Should -Be 300
        $source = Get-Content (Join-Path $repo 'Modules/Privacy/Private/PrivacyWindowsSearch.ps1') -Raw
        $source | Should -Match '\[int\]\$TimeoutSeconds = 300'
        $source | Should -Match '-ExecutionTimeLimit \(New-TimeSpan -Seconds \(\[int\]\$TimeoutSeconds \+ 5\)\)'
    }
}
