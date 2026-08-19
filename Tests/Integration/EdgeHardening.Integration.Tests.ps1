#Requires -Version 5.1

Describe "EdgeHardening Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'EdgeHardening'
        $script:ManifestPath = Join-Path $script:ModulePath 'EdgeHardening.psd1'
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-EdgeHardening function" {
            $module = Get-Module EdgeHardening
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-EdgeHardening"
        }

        It "Should export Test-EdgeHardening function" {
            $module = Get-Module EdgeHardening
            $module.ExportedFunctions.Keys | Should -Contain "Test-EdgeHardening"
        }
    }

    Context "Configuration Files" {
        It "Should have EdgePolicies.json" {
            $configPath = Join-Path $script:ModulePath "Config/EdgePolicies.json"
            Test-Path $configPath | Should -Be $true
        }

        It "EdgePolicies.json should be valid" {
            $configPath = Join-Path $script:ModulePath "Config/EdgePolicies.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "DryRun Execution" {
        It "Should enforce the installed Edge version contract in one structured DryRun result" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires admin rights and registry access
            $module = Import-Module $script:ManifestPath -Force -PassThru -ErrorAction Stop
            $installation = & $module { Get-EdgeInstallationStatus }
            $result = @(Invoke-IntegrationNonInteractive { Invoke-EdgeHardening -DryRun -ErrorAction Stop })
            Assert-SingleStructuredModuleResult -Result $result -Context 'EdgeHardening DryRun'
            $result[0].PoliciesApplied | Should -Be 0
            $result[0].BackupCreated | Should -BeFalse
            $result[0].ComplianceVerified | Should -BeNullOrEmpty
            $result[0].RuntimePolicyVerified | Should -BeNullOrEmpty

            if ($installation.Installed -and [int]$installation.Major -lt 139) {
                $result[0].Success | Should -BeFalse
                $result[0].Status | Should -Be 'Failed'
                $result[0].EdgeVersion | Should -Be ([string]$installation.Version)
                $result[0].PoliciesPreviewed | Should -Be 0
                @($result[0].Errors).Count | Should -Be 1
                $result[0].Errors[0] | Should -Be (
                    "Edge hardening failed: Installed Microsoft Edge $($installation.Version) is older than the v139 baseline contract"
                )
            }
            else {
                $result[0].Success | Should -BeTrue
                $result[0].Status | Should -Be 'DryRun'
                ($result[0].PoliciesPreviewed + $result[0].PoliciesNotApplicable) |
                    Should -Be $result[0].PoliciesSelected
            }
        }

        It "Should run Test-EdgeHardening without errors" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            { Test-EdgeHardening -ErrorAction Stop } | Should -Not -Throw
        }
    }

    AfterAll {
        Remove-Module EdgeHardening -ErrorAction SilentlyContinue
    }
}
