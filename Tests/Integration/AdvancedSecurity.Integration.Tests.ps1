Describe "AdvancedSecurity Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\AdvancedSecurity"
        $script:ManifestPath = Join-Path $script:ModulePath "AdvancedSecurity.psd1"
        $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
    }
    
    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }
        
        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should export Invoke-AdvancedSecurity function" {
            $module = Get-Module AdvancedSecurity
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-AdvancedSecurity"
        }
        
        It "Should export Test-AdvancedSecurity function" {
            $module = Get-Module AdvancedSecurity
            $module.ExportedFunctions.Keys | Should -Contain "Test-AdvancedSecurity"
        }
    }
    
    Context "Configuration Files" {
        It "Should have SRP-Rules.json" {
            $configPath = Join-Path $script:ModulePath "Config\SRP-Rules.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "SRP-Rules.json should be valid" {
            $configPath = Join-Path $script:ModulePath "Config\SRP-Rules.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should have WindowsUpdate.json" {
            $configPath = Join-Path $script:ModulePath "Config\WindowsUpdate.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "WindowsUpdate.json should be valid" {
            $configPath = Join-Path $script:ModulePath "Config\WindowsUpdate.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "DryRun Execution" {
        It "Should run Invoke-AdvancedSecurity in DryRun mode without errors" -Skip:$script:IsCI {
            # Skip on CI - requires admin rights and registry access
            { Invoke-AdvancedSecurity -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should run with Balanced profile in DryRun mode" -Skip:$script:IsCI {
            { Invoke-AdvancedSecurity -SecurityProfile "Balanced" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should run with Enterprise profile in DryRun mode" -Skip:$script:IsCI {
            { Invoke-AdvancedSecurity -SecurityProfile "Enterprise" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should run with Maximum profile in DryRun mode" -Skip:$script:IsCI {
            { Invoke-AdvancedSecurity -SecurityProfile "Maximum" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should run Test-AdvancedSecurity without errors" -Skip:$script:IsCI {
            { Test-AdvancedSecurity -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
    }
}
