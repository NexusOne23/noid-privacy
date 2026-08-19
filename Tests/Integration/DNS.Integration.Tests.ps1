#Requires -Version 5.1

Describe "DNS Integration Tests" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_Common.ps1')
        Initialize-IntegrationTestEnvironment
        $script:ModulePath = Get-IntegrationModulePath -Module 'DNS'
        $script:ManifestPath = Join-Path $script:ModulePath 'DNS.psd1'
    }

    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }

        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should export Invoke-DNSConfiguration function" {
            $module = Get-Module DNS
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-DNSConfiguration"
        }

        It "Should export Get-DNSStatus function" {
            $module = Get-Module DNS
            $module.ExportedFunctions.Keys | Should -Contain "Get-DNSStatus"
        }
    }

    Context "DryRun Execution" {
        It "Should return one structured DryRun result with provider specified" -Skip:($env:GITHUB_ACTIONS -eq 'true' -or $env:OS -ne 'Windows_NT') {
            # Skip on CI - requires network adapters and admin rights
            $result = @(Invoke-IntegrationNonInteractive {
                    Invoke-DNSConfiguration -Provider "Quad9" -DryRun -ErrorAction Stop
                })
            Assert-SingleStructuredModuleResult -Result $result -Context 'DNS DryRun'
            $result[0].Success | Should -BeTrue
            $result[0].Status | Should -Be 'DryRun'
            $result[0].AdaptersConfigured | Should -Be 0
            $result[0].AdaptersPreviewed | Should -BeGreaterThan 0
            $result[0].BackupCreated | Should -BeFalse
            $result[0].VerificationPassed | Should -BeNullOrEmpty
        }
    }

    AfterAll {
        Remove-Module DNS -ErrorAction SilentlyContinue
    }
}
