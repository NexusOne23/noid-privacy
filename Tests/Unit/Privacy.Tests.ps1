<#
.SYNOPSIS
    Unit tests for Privacy module
    
.DESCRIPTION
    Pester v5 tests for the Privacy module functionality.
    Tests return values, DryRun behavior, mode selection, and compliance.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Privacy.psm1"
    
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

Describe "Privacy Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-PrivacyHardening function" {
            $command = Get-Command -Name Invoke-PrivacyHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Test-PrivacyCompliance function" {
            $command = Get-Command -Name Test-PrivacyCompliance -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have Mode parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('Mode') | Should -Be $true
        }
        
        It "Mode parameter should accept specific values" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $validateSet = $command.Parameters['Mode'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'MSRecommended'
            $validateSet.ValidValues | Should -Contain 'Strict'
            $validateSet.ValidValues | Should -Contain 'Paranoid'
        }
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }
    
    Context "Privacy Mode Configurations" {
        
        It "Should load MSRecommended config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-MSRecommended.json"
            $configPath | Should -Exist
        }
        
        It "Should load Strict config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-Strict.json"
            $configPath | Should -Exist
        }
        
        It "Should load Paranoid config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-Paranoid.json"
            $configPath | Should -Exist
        }
        
        It "MSRecommended config should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-MSRecommended.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "MSRecommended should have AllowTelemetry = 1" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-MSRecommended.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.telemetry.AllowTelemetry | Should -Be 1
        }
        
        It "Strict should have AllowTelemetry = 0" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Privacy-Strict.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.telemetry.AllowTelemetry | Should -Be 0
        }
    }
    
    Context "Bloatware Configuration" {
        
        It "Should load Bloatware config from JSON" {
            $bloatwarePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Bloatware.json"
            $bloatwarePath | Should -Exist
        }
        
        It "Bloatware config should be valid JSON" {
            $bloatwarePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Bloatware.json"
            { Get-Content $bloatwarePath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should have both removal and protected lists" {
            $bloatwarePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\Privacy\Config\Bloatware.json"
            $config = Get-Content $bloatwarePath -Raw | ConvertFrom-Json
            $config.PSObject.Properties.Name | Should -Contain 'appsToRemove'
            $config.PSObject.Properties.Name | Should -Contain 'protectedApps'
        }
    }
    
    Context "Function Execution - DryRun Mode" {
        
        It "Should execute without errors in DryRun mode with MSRecommended" {
            { Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force } | Should -Not -Throw
        }
        
        It "Should return a PSCustomObject" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Should have Success property" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'Success'
        }
        
        It "Should have Mode property" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'Mode'
        }
        
        It "Mode property should match requested mode" {
            $result = Invoke-PrivacyHardening -Mode 'Strict' -DryRun -Force
            $result.Mode | Should -Be 'Strict'
        }
    }
    
    Context "Return Object Structure" {
        
        It "Should return object with all required properties" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            
            $requiredProperties = @(
                'Success',
                'Mode',
                'Errors',
                'Warnings',
                'Duration'
            )
            
            foreach ($prop in $requiredProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
        
        It "Errors should be an array" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            $result.Errors -is [Array] | Should -Be $true
        }
        
        It "Warnings should be an array" {
            $result = Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun -Force
            $result.Warnings -is [Array] | Should -Be $true
        }
    }
    
    Context "Compliance Testing" {
        
        It "Test-PrivacyCompliance should execute without errors" {
            { Test-PrivacyCompliance -Mode 'MSRecommended' } | Should -Not -Throw
        }
        
        It "Test-PrivacyCompliance should return PSCustomObject" {
            $result = Test-PrivacyCompliance -Mode 'MSRecommended'
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Compliance result should have Compliant property" {
            $result = Test-PrivacyCompliance -Mode 'MSRecommended'
            $result.PSObject.Properties.Name | Should -Contain 'Compliant'
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module Privacy -Force -ErrorAction SilentlyContinue
}
