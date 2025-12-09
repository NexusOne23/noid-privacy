<#
.SYNOPSIS
    Unit tests for ModuleTemplate module
    
.DESCRIPTION
    Pester v5 tests demonstrating module testing best practices.
    All test files must end with .Tests.ps1
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\_ModuleTemplate\ModuleTemplate.psm1"
    
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
    $utilsModules = @("Registry.ps1", "Service.ps1", "Hardware.ps1", "GPO.ps1")
    $utilsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Utils"
    
    foreach ($module in $utilsModules) {
        $moduleFile = Join-Path $utilsPath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }
}

Describe "ModuleTemplate Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-ModuleTemplate function" {
            $command = Get-Command -Name Invoke-ModuleTemplate -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.CommandType | Should -Be 'Function'
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "Should have SkipBackup parameter" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $true
        }
        
        It "Should have SkipVerify parameter" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters.ContainsKey('SkipVerify') | Should -Be $true
        }
    }
    
    Context "Function Execution - DryRun Mode" {
        
        BeforeAll {
            # Initialize required systems for testing
            if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
                Initialize-Logger -EnableConsole $false
            }
            $script:IsCI = $env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true'
        }
        
        It "Should execute without errors in DryRun mode" -Skip:$script:IsCI {
            # Skip on CI - requires initialized environment
            { Invoke-ModuleTemplate -DryRun } | Should -Not -Throw
        }
        
        It "Should return a PSCustomObject" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Should have ModuleName property" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.ModuleName | Should -Be "ModuleTemplate"
        }
        
        It "Should have Success property" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.PSObject.Properties.Name | Should -Contain 'Success'
        }
        
        It "Should have ChangesApplied property" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.PSObject.Properties.Name | Should -Contain 'ChangesApplied'
        }
        
        It "Should not apply changes in DryRun mode" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.ChangesApplied | Should -Be 0
        }
    }
    
    Context "Return Object Structure" {
        
        It "Should return object with all required properties" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            
            $requiredProperties = @(
                'ModuleName',
                'Success',
                'ChangesApplied',
                'Errors',
                'Warnings',
                'BackupCreated',
                'VerificationPassed'
            )
            
            foreach ($prop in $requiredProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
        
        It "Errors should be an array" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.Errors | Should -BeOfType [System.Object[]]
        }
        
        It "Warnings should be an array" -Skip:$script:IsCI {
            $result = Invoke-ModuleTemplate -DryRun
            $result.Warnings | Should -BeOfType [System.Object[]]
        }
    }
}

Describe "ModuleTemplate Helper Functions" {
    
    Context "Private Functions" {
        
        It "Private functions should not be exported" {
            $exportedCommands = Get-Command -Module ModuleTemplate
            $exportedCommands.Name | Should -Not -Contain 'Test-TemplateRequirements'
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module ModuleTemplate -Force -ErrorAction SilentlyContinue
}
