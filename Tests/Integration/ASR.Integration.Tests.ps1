#Requires -Version 5.1

Describe "ASR Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'ASR'
        $script:ManifestPath = Join-Path $script:ModulePath 'ASR.psd1'
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-ASRRules function" {
            $module = Get-Module ASR
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-ASRRules"
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured DryRun result" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires Windows Defender and admin rights
            $result = @(Invoke-IntegrationNonInteractive { Invoke-ASRRules -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'ASR DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].Status | Should -Be 'DryRun'
            $result[0].RulesApplied | Should -Be 0
            $result[0].RulesPreviewed | Should -Be $result[0].Details.Applicable
            $result[0].RulesNotApplicable | Should -Be $result[0].Details.NotApplicable
            $result[0].BackupCreated | Should -BeFalse
            $result[0].VerificationPassed | Should -BeNullOrEmpty
            ($result[0].Details.BlockMode + $result[0].Details.AuditMode + $result[0].Details.DisabledMode + $result[0].Details.NotApplicable) |
                Should -Be $result[0].Details.TotalRules
        }
    }

    AfterAll {
        Remove-Module ASR -ErrorAction SilentlyContinue
    }
}
