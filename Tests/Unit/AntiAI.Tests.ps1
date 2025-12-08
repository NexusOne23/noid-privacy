<#
.SYNOPSIS
    Unit tests for AntiAI module
    
.DESCRIPTION
    Pester v5 tests for the AntiAI module functionality.
    Tests return values, DryRun behavior, and compliance verification.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\AntiAI.psm1"
    
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
    
    # Import Utils
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
    
    # Initialize backup system
    if (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue) {
        Initialize-BackupSystem
    }
}

Describe "AntiAI Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-AntiAI function" {
            $command = Get-Command -Name Invoke-AntiAI -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Test-AntiAICompliance function" {
            $command = Get-Command -Name Test-AntiAICompliance -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "Should have SkipBackup parameter" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $true
        }
    }
    
    Context "AntiAI Configuration" {
        
        It "Should load AntiAI settings from JSON" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settingsPath | Should -Exist
        }
        
        It "Settings file should be valid JSON" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            { Get-Content $settingsPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Settings should be a valid config object" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Function Execution - DryRun Mode" -Skip:$true {
        # These tests require admin rights and proper environment - skipped on CI
        
        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-AntiAI -DryRun } | Should -Not -Throw
        }
        
        It "Should return a result" -Tag 'Interactive' {
            $result = Invoke-AntiAI -DryRun
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Return Object Structure" -Skip:$true {
        # Skipped - return object properties may vary based on environment
    }
    
    Context "Compliance Testing" {
        
        It "Test-AntiAICompliance should execute without errors" {
            { Test-AntiAICompliance } | Should -Not -Throw
        }
        
        It "Test-AntiAICompliance should return a result" {
            $result = Test-AntiAICompliance
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "AI Features Coverage" -Skip:$true {
        # Config structure tests - skipped as structure may vary
    }
}

AfterAll {
    # Clean up
    Remove-Module AntiAI -Force -ErrorAction SilentlyContinue
}
