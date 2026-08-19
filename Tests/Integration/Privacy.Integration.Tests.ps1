#Requires -Version 5.1

Describe "Privacy Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'Privacy'
        $script:ManifestPath = Join-Path $script:ModulePath 'Privacy.psd1'
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-PrivacyHardening function" {
            $module = Get-Module Privacy
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-PrivacyHardening"
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured DryRun result with MSRecommended mode" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires admin rights and registry access
            $result = @(Invoke-IntegrationNonInteractive { Invoke-PrivacyHardening -Mode "MSRecommended" -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'Privacy DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].Status | Should -Be 'DryRun'
            $result[0].DeclaredChecks | Should -BeGreaterThan 0
            ($result[0].Previewed + $result[0].NotChecked + $result[0].NotApplicable) |
                Should -Be $result[0].DeclaredChecks
            $result[0].ChangesMade | Should -Be 0
            $result[0].VerificationPassed | Should -BeNullOrEmpty
        }
    }

    AfterAll {
        Remove-Module Privacy -ErrorAction SilentlyContinue
    }
}
