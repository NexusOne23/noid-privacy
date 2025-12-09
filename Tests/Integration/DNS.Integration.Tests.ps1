Describe "DNS Integration Tests" {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot "..\..\Modules\DNS"
        $script:ManifestPath = Join-Path $script:ModulePath "DNS.psd1"
        $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
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
        It "Should run in DryRun mode with provider specified without errors" -Skip:$script:IsCI {
            # Skip on CI - requires network adapters and admin rights
            { Invoke-DNSConfiguration -Provider "Quad9" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    AfterAll {
        Remove-Module DNS -ErrorAction SilentlyContinue
    }
}
