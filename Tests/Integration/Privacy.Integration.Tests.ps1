Describe "Privacy Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\Privacy"
        $script:ManifestPath = Join-Path $script:ModulePath "Privacy.psd1"
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
        It "Should run in DryRun mode with MSRecommended mode without errors" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            # Skip on CI - requires admin rights and registry access
            { Invoke-PrivacyHardening -Mode "MSRecommended" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module Privacy -ErrorAction SilentlyContinue
    }
}
