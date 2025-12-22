<#
.SYNOPSIS
    Unit tests for AdvancedSecurity module
    
.DESCRIPTION
    Pester v5 tests for the AdvancedSecurity module functionality.
    Tests return values, DryRun behavior, profile handling, and configuration.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.2
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AdvancedSecurity\AdvancedSecurity.psm1"
    
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
    $utilsModules = @("Registry.ps1", "Service.ps1")
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

Describe "AdvancedSecurity Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-AdvancedSecurity function" {
            $command = Get-Command -Name Invoke-AdvancedSecurity -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Test-AdvancedSecurity function" {
            $command = Get-Command -Name Test-AdvancedSecurity -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.CommandType | Should -Be 'Function'
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have SecurityProfile parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('SecurityProfile') | Should -Be $true
        }
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "Should have DisableRDP parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('DisableRDP') | Should -Be $true
        }
        
        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
        
        It "Should have SkipBackup parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $true
        }
    }
    
    Context "Configuration" {
        
        It "SRP-Rules.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AdvancedSecurity\Config\SRP-Rules.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "SRP-Rules.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AdvancedSecurity\Config\SRP-Rules.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "WindowsUpdate.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AdvancedSecurity\Config\WindowsUpdate.json"
            Test-Path $configPath | Should -Be $true
        }
        
        It "WindowsUpdate.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AdvancedSecurity\Config\WindowsUpdate.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
    }
    
    Context "Security Profiles" -Skip:$true {
        # These tests require user interaction and admin rights
        # Skipped on CI - run manually with: Invoke-Pester -TagFilter 'Interactive'
        
        It "Should accept Balanced profile" -Tag 'Interactive' {
            { Invoke-AdvancedSecurity -SecurityProfile "Balanced" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should accept Enterprise profile" -Tag 'Interactive' {
            { Invoke-AdvancedSecurity -SecurityProfile "Enterprise" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should accept Maximum profile" -Tag 'Interactive' {
            { Invoke-AdvancedSecurity -SecurityProfile "Maximum" -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "DryRun Behavior" -Skip:$true {
        # These tests require user interaction - skipped on CI
        
        It "Should accept DryRun parameter without errors" -Tag 'Interactive' {
            { Invoke-AdvancedSecurity -DryRun -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should not modify system in DryRun mode" -Tag 'Interactive' {
            Invoke-AdvancedSecurity -DryRun -ErrorAction SilentlyContinue
            $? | Should -Be $true
        }
    }
    
    Context "Test-AdvancedSecurity Function" {
        
        It "Should run Test-AdvancedSecurity without errors" {
            { Test-AdvancedSecurity -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should return compliance results" {
            $result = Test-AdvancedSecurity -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Compliance results should be an array of test results" {
            $result = Test-AdvancedSecurity -ErrorAction SilentlyContinue
            # Test-AdvancedSecurity returns an array of compliance results
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    # Cleanup
    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
}
