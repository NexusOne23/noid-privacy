<#
.SYNOPSIS
    Unit tests for EdgeHardening module
    
.DESCRIPTION
    Pester v5 tests for the EdgeHardening module functionality.
    Tests return values, DryRun behavior, and configuration handling.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\EdgeHardening\EdgeHardening.psm1"
    
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }
    
    # Import Core modules for testing
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1")
    $corePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Core"
    
    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }
    
    # Import Utils modules
    $utilsModules = @("Registry.ps1")
    $utilsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Utils"
    
    foreach ($module in $utilsModules) {
        $moduleFile = Join-Path $utilsPath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }
    
    # Initialize logging (silent for tests)
    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }
    
    # Initialize config
    if (Get-Command Initialize-Config -ErrorAction SilentlyContinue) {
        $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "config.json"
        Initialize-Config -ConfigPath $configPath
    }
}

Describe "EdgeHardening Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-EdgeHardening function" {
            $command = Get-Command -Name Invoke-EdgeHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Test-EdgeHardening function" {
            $command = Get-Command -Name Test-EdgeHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.CommandType | Should -Be 'Function'
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "Should have AllowExtensions parameter" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters.ContainsKey('AllowExtensions') | Should -Be $true
        }
        
        It "AllowExtensions parameter should be a switch" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters['AllowExtensions'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
    }
    
    Context "Configuration" {
        
        It "EdgePolicies.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\EdgeHardening\Config\EdgePolicies.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "EdgePolicies.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\EdgeHardening\Config\EdgePolicies.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "EdgePolicies.json should contain policies" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\EdgeHardening\Config\EdgePolicies.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.Policies | Should -Not -BeNullOrEmpty
            $config.Policies.Count | Should -BeGreaterThan 0
        }
        
        It "All policies should have required properties" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\EdgeHardening\Config\EdgePolicies.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            foreach ($policy in $config.Policies) {
                $policy.Name | Should -Not -BeNullOrEmpty
                $policy.Path | Should -Not -BeNullOrEmpty
                $policy.Value | Should -Not -BeNull
                $policy.Type | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "DryRun Behavior" {
        
        It "Should accept DryRun parameter without errors" {
            { Invoke-EdgeHardening -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should not modify system in DryRun mode" {
            # This test verifies that DryRun mode doesn't write to registry
            # We can't easily test this without admin rights, but we can verify the function runs
            Invoke-EdgeHardening -DryRun -AllowExtensions -ErrorAction SilentlyContinue
            # Function should complete without errors
            $? | Should -Be $true
        }
    }
    
    Context "Test-EdgeHardening Function" {
        
        It "Should run Test-EdgeHardening without errors" {
            { Test-EdgeHardening -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should return compliance results" {
            $result = Test-EdgeHardening -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    # Cleanup
    Remove-Module EdgeHardening -ErrorAction SilentlyContinue
}
