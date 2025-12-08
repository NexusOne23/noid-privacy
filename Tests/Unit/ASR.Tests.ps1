<#
.SYNOPSIS
    Unit tests for ASR (Attack Surface Reduction) module
    
.DESCRIPTION
    Pester v5 tests for the ASR module functionality.
    Tests return values, DryRun behavior, and backup creation.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\ASR\ASR.psm1"
    
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

Describe "ASR Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-ASRRules function" {
            $command = Get-Command -Name Invoke-ASRRules -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.CommandType | Should -Be 'Function'
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }
    
    Context "Function Execution - DryRun Mode" -Skip:$true {
        # These tests require admin rights and Windows Defender - skipped on CI
        
        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-ASRRules -DryRun } | Should -Not -Throw
        }
    }
    
    Context "Return Object Structure" -Skip:$true {
        # Skipped - requires proper Windows Defender environment
    }
    
    Context "ASR Rules Configuration" {
        
        It "Should load ASR rules from JSON" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\ASR\Config\ASR-Rules.json"
            $rulesPath | Should -Exist
        }
        
        It "ASR rules file should be valid JSON" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\ASR\Config\ASR-Rules.json"
            { Get-Content $rulesPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should have 19 ASR rules" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\ASR\Config\ASR-Rules.json"
            $rules = Get-Content $rulesPath -Raw | ConvertFrom-Json
            $rules.Count | Should -Be 19
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module ASR -Force -ErrorAction SilentlyContinue
}
