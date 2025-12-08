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
        
        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters.ContainsKey('Force') | Should -Be $true
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
        
        It "Settings should have all AI feature sections" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            
            $requiredSections = @(
                'systemAIModels',
                'recall',
                'recallProtection',
                'copilot',
                'clickToDo',
                'notepadAI',
                'paintAI',
                'settingsAgent'
            )
            
            foreach ($section in $requiredSections) {
                $settings.PSObject.Properties.Name | Should -Contain $section
            }
        }
    }
    
    Context "Function Execution - DryRun Mode" {
        
        It "Should execute without errors in DryRun mode" {
            { Invoke-AntiAI -DryRun -Force } | Should -Not -Throw
        }
        
        It "Should return a PSCustomObject" {
            $result = Invoke-AntiAI -DryRun -Force
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Should have Success property" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'Success'
        }
        
        It "Should have FeaturesDisabled property" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'FeaturesDisabled'
        }
        
        It "Should not apply changes in DryRun mode" {
            $result = Invoke-AntiAI -DryRun -Force
            # In DryRun, FeaturesDisabled should be 0
            $result.FeaturesDisabled | Should -Be 0
        }
    }
    
    Context "Return Object Structure" {
        
        It "Should return object with all required properties" {
            $result = Invoke-AntiAI -DryRun -Force
            
            $requiredProperties = @(
                'Success',
                'FeaturesDisabled',
                'TotalFeatures',
                'Errors',
                'Warnings',
                'Duration'
            )
            
            foreach ($prop in $requiredProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
        
        It "Errors should be an array" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.Errors -is [Array] | Should -Be $true
        }
        
        It "Warnings should be an array" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.Warnings -is [Array] | Should -Be $true
        }
        
        It "Duration should be a TimeSpan" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.Duration | Should -BeOfType [TimeSpan]
        }
        
        It "TotalFeatures should be 9" {
            $result = Invoke-AntiAI -DryRun -Force
            $result.TotalFeatures | Should -Be 9
        }
    }
    
    Context "Compliance Testing" {
        
        It "Test-AntiAICompliance should execute without errors" {
            { Test-AntiAICompliance } | Should -Not -Throw
        }
        
        It "Test-AntiAICompliance should return PSCustomObject" {
            $result = Test-AntiAICompliance
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Compliance result should have Compliant property" {
            $result = Test-AntiAICompliance
            $result.PSObject.Properties.Name | Should -Contain 'Compliant'
        }
        
        It "Compliance result should have TotalChecks property" {
            $result = Test-AntiAICompliance
            $result.PSObject.Properties.Name | Should -Contain 'TotalChecks'
        }
        
        It "Compliance result should have PassedChecks property" {
            $result = Test-AntiAICompliance
            $result.PSObject.Properties.Name | Should -Contain 'PassedChecks'
        }
        
        It "Should have 14 total checks" {
            $result = Test-AntiAICompliance
            $result.TotalChecks | Should -Be 14
        }
    }
    
    Context "AI Features Coverage" {
        
        It "Should cover Recall disabling" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.recall.enabled | Should -Be $false
        }
        
        It "Should cover Copilot disabling" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.copilot.enabled | Should -Be $false
        }
        
        It "Should cover Notepad AI disabling" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.notepadAI.enabled | Should -Be $false
        }
        
        It "Should cover Paint AI disabling" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\AntiAI\Config\AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.paintAI.enabled | Should -Be $false
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module AntiAI -Force -ErrorAction SilentlyContinue
}
