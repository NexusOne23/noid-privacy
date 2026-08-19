#Requires -Version 5.1

Describe "SecurityBaseline Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'SecurityBaseline'
        $script:ManifestPath = Join-Path $script:ModulePath 'SecurityBaseline.psd1'
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

        It "Should export Invoke-SecurityBaseline function" {
            $module = Get-Module SecurityBaseline
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-SecurityBaseline"
        }

        It "Should export Restore-SecurityBaseline function" {
            $module = Get-Module SecurityBaseline
            $module.ExportedFunctions.Keys | Should -Contain "Restore-SecurityBaseline"
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured DryRun result" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires admin rights and registry access
            $result = @(Invoke-IntegrationNonInteractive { Invoke-SecurityBaseline -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'SecurityBaseline DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].SettingsDeclared | Should -Be ([int]$script:SettingsCounts.modules.SecurityBaseline.subtotal)
            $result[0].SettingsApplied | Should -Be 0
            ($result[0].SettingsPreviewed + $result[0].SettingsNotApplicable) |
                Should -Be $result[0].SettingsDeclared
            $result[0].BackupCreated | Should -BeFalse
            $result[0].VerificationPassed | Should -BeNullOrEmpty
            $result[0].RequiresReboot | Should -BeFalse
        }
    }

    AfterAll {
        Remove-Module SecurityBaseline -ErrorAction SilentlyContinue
    }
}
