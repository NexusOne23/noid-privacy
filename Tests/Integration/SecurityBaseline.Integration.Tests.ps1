Describe "SecurityBaseline Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\SecurityBaseline"
        $script:ManifestPath = Join-Path $script:ModulePath "SecurityBaseline.psd1"
        $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
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
        It "Should run in DryRun mode without errors" -Skip:$script:IsCI {
            # Skip on CI - requires admin rights and registry access
            { Invoke-SecurityBaseline -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module SecurityBaseline -ErrorAction SilentlyContinue
    }
}
