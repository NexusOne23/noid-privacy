Describe "ASR Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\ASR"
        $script:ManifestPath = Join-Path $script:ModulePath "ASR.psd1"
        $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
    }
    
    Context "Module Structure" {
        It "Should have module manifest" {
            Test-Path $script:ManifestPath | Should -Be $true
        }
        
        It "Should load module without errors" {
            { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should export Invoke-ASRRules function" {
            $module = Get-Module ASR
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-ASRRules"
        }
    }
    
    Context "DryRun Execution" {
        It "Should run in DryRun mode without errors" -Skip:$script:IsCI {
            # Skip on CI - requires Windows Defender and admin rights
            { Invoke-ASRRules -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module ASR -ErrorAction SilentlyContinue
    }
}
