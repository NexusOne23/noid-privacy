#Requires -Version 5.1

Describe "AntiAI Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'AntiAI'
        $script:ManifestPath = Join-Path $script:ModulePath 'AntiAI.psd1'
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
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
        It "Should return one structured DryRun result" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            # GitHub-hosted CI is Windows Server; the self-hosted Windows 11 release gate must execute this test.
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
        It "Should execute all checks for an explicit AntiAI test plan" -Skip:($env:OS -ne 'Windows_NT' -or ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -ne 'self-hosted')) {
            # GitHub-hosted CI is Windows Server; the self-hosted Windows 11 release gate must execute this test.
            # This is a read-only integration fixture, not evidence of a prior
            # Apply. Execute the function, not merely its definition file.
            $result = @(& (Get-Module AntiAI) {
                    $plan = Get-AntiAITargetPlan -Targets @(Get-AntiAIRegistryTargets) -Applicability (Get-AntiAIApplicability)
                    Test-AntiAICompliance -ApplicableTargets @($plan.ApplicableTargets) -NotApplicableTargets @($plan.NotApplicableTargets)
                })
            $result.Count | Should -Be 1
            $result[0].TotalPolicies | Should -Be 50
            $result[0].UriChecks | Should -Be 4
            $result[0].TotalChecks | Should -Be 54
            $result[0].Details.Count | Should -Be 54
            ($result[0].Passed + $result[0].Failed + $result[0].NotApplicable) | Should -Be 54
        }
    }

    AfterAll {
        Remove-Module AntiAI -ErrorAction SilentlyContinue
    }
}
