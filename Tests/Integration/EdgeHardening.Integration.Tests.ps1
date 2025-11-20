Describe "EdgeHardening Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\EdgeHardening"
        $script:ManifestPath = Join-Path $script:ModulePath "EdgeHardening.psd1"
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
            $configPath = Join-Path $script:ModulePath "Config\EdgePolicies.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "EdgePolicies.json should be valid" {
            $configPath = Join-Path $script:ModulePath "Config\EdgePolicies.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "DryRun Execution" {
        It "Should run Invoke-EdgeHardening in DryRun mode without errors" {
            { Invoke-EdgeHardening -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should run Test-EdgeHardening without errors" {
            { Test-EdgeHardening -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module EdgeHardening -ErrorAction SilentlyContinue
    }
}
