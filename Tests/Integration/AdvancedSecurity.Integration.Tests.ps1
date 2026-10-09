#Requires -Version 5.1

Describe "AdvancedSecurity Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'AdvancedSecurity'
        $script:ManifestPath = Join-Path $script:ModulePath 'AdvancedSecurity.psd1'
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:SettingsCounts = Get-Content (Join-Path $repoRoot 'Config/SettingsCounts.json') -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-AdvancedSecurity function" {
            $module = Get-Module AdvancedSecurity
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-AdvancedSecurity"
        }

        It "Should export Test-AdvancedSecurity function" {
            $module = Get-Module AdvancedSecurity
            $module.ExportedFunctions.Keys | Should -Contain "Test-AdvancedSecurity"
        }
    }

    Context "Configuration Files" {
        It "Should no longer ship the legacy SRP-Rules.json" {
            $configPath = Join-Path $script:ModulePath "Config/SRP-Rules.json"
            Test-Path $configPath | Should -Be $false
        }

        It "Should have WindowsUpdate.json" {
            $configPath = Join-Path $script:ModulePath "Config/WindowsUpdate.json"
            Test-Path $configPath | Should -Be $true
        }

        It "WindowsUpdate.json should be valid" {
            $configPath = Join-Path $script:ModulePath "Config/WindowsUpdate.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured Invoke-AdvancedSecurity DryRun result" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            # GitHub-hosted CI is Windows Server; the self-hosted Windows 11 release gate must execute these tests.
            $result = @(Invoke-IntegrationNonInteractive { Invoke-AdvancedSecurity -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'AdvancedSecurity default DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].Status | Should -Be 'DryRun'
            $result[0].SettingsDeclared | Should -Be ([int]$script:SettingsCounts.modules.AdvancedSecurity.settings)
            ($result[0].SettingsPreviewed + $result[0].SettingsSkipped + $result[0].SettingsNotApplicable + $result[0].SettingsNotSelected) |
                Should -Be $result[0].SettingsDeclared
            $result[0].SettingsApplied | Should -Be 0
            $result[0].ChangesMade | Should -Be 0
        }

        It "Should return one structured Balanced DryRun result" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            $result = @(Invoke-IntegrationNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Balanced" -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'AdvancedSecurity Balanced DryRun'
        }

        It "Should return one structured Enterprise DryRun result" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            $result = @(Invoke-IntegrationNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Enterprise" -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'AdvancedSecurity Enterprise DryRun'
        }

        It "Should return one structured Maximum DryRun result" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            $result = @(Invoke-IntegrationNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Maximum" -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'AdvancedSecurity Maximum DryRun'
        }

        It "Should return the complete AdvancedSecurity verification inventory" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            $result = Test-AdvancedSecurity -SecurityProfile Balanced -DisableRDP $true `
                    -AdminSharesDisabled $true -DisableUPnP $true `
                    -DisableWirelessDisplayCompletely $false `
                    -DisableDiscoveryProtocolsCompletely $false `
                    -DisableIPv6Completely $false -SkipFirewallLayer:$false `
                    -ErrorAction Stop
            $result | Should -Not -BeNullOrEmpty
            $result.Results.Count | Should -Be 12
            ($result.TotalChecks + $result.NotCheckedCount + $result.NotApplicableCount) | Should -Be 12
        }
    }

    AfterAll {
        Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
    }
}
