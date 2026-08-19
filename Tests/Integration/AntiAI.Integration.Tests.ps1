#Requires -Version 5.1

Describe "AntiAI Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'AntiAI'
        $script:ManifestPath = Join-Path $script:ModulePath 'AntiAI.psd1'
        $script:ComplianceScript = Join-Path $script:ModulePath 'Private' | Join-Path -ChildPath 'Test-AntiAICompliance.ps1'
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should have compliance test script" {
            Test-Path $script:ComplianceScript | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-AntiAI function" {
            $module = Get-Module AntiAI
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-AntiAI"
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured DryRun result" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires admin rights and registry access
            $result = @(Invoke-IntegrationNonInteractive { Invoke-AntiAI -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'AntiAI DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].AppliedPolicyTargets | Should -Be 0
            ($result[0].PreviewedPolicyTargets + $result[0].NotApplicablePolicyTargets) |
                Should -Be $result[0].DeclaredPolicyTargets
            $result[0].VerificationPassed | Should -BeNullOrEmpty
            $result[0].RequiresReboot | Should -BeFalse
        }
    }

    Context "Compliance Check" {
        It "Should run compliance test without errors" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires admin rights and registry access
            { & $script:ComplianceScript -ErrorAction Stop } | Should -Not -Throw
        }
    }

    AfterAll {
        Remove-Module AntiAI -ErrorAction SilentlyContinue
    }
}
