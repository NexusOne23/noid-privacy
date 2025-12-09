Describe "AntiAI Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\AntiAI"
        $script:ManifestPath = Join-Path $script:ModulePath "AntiAI.psd1"
        $script:ComplianceScript = Join-Path $script:ModulePath "Private\Test-AntiAICompliance.ps1"
        $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
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
        It "Should run in DryRun mode without errors" -Skip:$script:IsCI {
            # Skip on CI - requires admin rights and registry access
            { Invoke-AntiAI -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "Compliance Check" {
        It "Should run compliance test without errors" -Skip:$script:IsCI {
            # Skip on CI - requires admin rights and registry access
            { & $script:ComplianceScript -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module AntiAI -ErrorAction SilentlyContinue
    }
}
