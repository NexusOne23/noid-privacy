#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for ModuleTemplate module

.DESCRIPTION
    Pester v5 tests demonstrating module testing best practices.
    All test files must end with .Tests.ps1

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0
#>

BeforeAll {
    # Production load order: Core dependencies FIRST. See AdvancedSecurity.Tests.ps1
    # for the global-promotion rationale (Import-Module isolates session state, so
    # we lift Write-Log + co. into global function-table for the imported module).
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1")
    $corePath = Join-Path $repoRoot "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }

    foreach ($fn in 'Write-Log','Write-ErrorLog','Initialize-Logger','Get-LogFilePath','Get-ErrorContext','Test-NonInteractiveMode') {
        if (Test-Path "function:$fn") {
            Set-Item -Path "function:global:$fn" -Value (Get-Item "function:$fn").ScriptBlock
        }
    }

    $modulePath = Join-Path $repoRoot "Modules" | Join-Path -ChildPath "_ModuleTemplate" | Join-Path -ChildPath "ModuleTemplate.psm1"

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }

    # Import the read-only hardware helpers used by the template tests.
    $utilsModules = @("Hardware.ps1")
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

        It 'Should fail closed when required loader directories or files cannot be discovered' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $loader = Get-Content (Join-Path $repo 'Modules/_ModuleTemplate/ModuleTemplate.psm1') -Raw
            $loader | Should -Match 'Required module directory is missing'
            $loader | Should -Match 'Get-ChildItem -LiteralPath \$publicPath.*-ErrorAction Stop'
            $loader | Should -Match 'Get-ChildItem -LiteralPath \$privatePath.*-ErrorAction Stop'
            $loader | Should -Not -Match 'Get-ChildItem[^\r\n]+SilentlyContinue'
            $loader | Should -Not -Match 'Write-Error "Failed to load function'
        }

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

        It "Should not expose a SkipBackup parameter" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $false
        }

        It "Should not expose a SkipVerify parameter" {
            $command = Get-Command -Name Invoke-ModuleTemplate
            $command.Parameters.ContainsKey('SkipVerify') | Should -Be $false
        }
    }

    Context "Function Execution - DryRun Mode" {

        BeforeAll {
            # Initialize required systems for testing
            if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
                Initialize-Logger -EnableConsole $false
            }
        }

        It "Should execute without errors in DryRun mode" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            # Skip on CI - requires initialized environment
            { Invoke-ModuleTemplate -DryRun } | Should -Not -Throw
        }

        It "Should return a PSCustomObject" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result | Should -BeOfType [PSCustomObject]
        }

        It "Should have ModuleName property" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result.ModuleName | Should -Be "ModuleTemplate"
        }

        It "Should have Success property" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result.PSObject.Properties.Name | Should -Contain 'Success'
        }

        It "Should have ChangesApplied property" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result.PSObject.Properties.Name | Should -Contain 'ChangesApplied'
        }

        It "Should not apply changes in DryRun mode" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result.ChangesApplied | Should -Be 0
        }

        It "Should identify itself as a dry-run scaffold" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            $result.Success | Should -BeTrue
            $result.Status | Should -Be 'DryRun'
            $result.BackupCreated | Should -BeFalse
            $result.VerificationPassed | Should -BeNullOrEmpty
        }

    }

    Context "Live execution safety" {

        It "Should refuse live execution without any mutation" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate
            $result.Success | Should -BeFalse
            $result.Status | Should -Be 'ScaffoldOnly'
            $result.ChangesApplied | Should -Be 0
            $result.BackupCreated | Should -BeFalse
            $result.VerificationPassed | Should -BeNullOrEmpty
            $result.Errors.Count | Should -Be 1
        }

        It "Should contain no obsolete warning-and-continue backup example" {
            $source = Get-Content -LiteralPath (Join-Path $repoRoot 'Modules/_ModuleTemplate/Public/Invoke-ModuleTemplate.ps1') -Raw -Encoding UTF8
            $source | Should -Not -Match 'Backup creation failed.+Warnings'
            $source | Should -Not -Match 'Set-RegistryValue|Set-ServiceStartupType'
            $source | Should -Match 'non-executable scaffold'
        }
    }

    Context "Return Object Structure" {

        It "Should return object with all required properties" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
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

        It "Errors should be an array" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            # Comma-prefix prevents Pester's pipeline-unrolling on empty arrays
            # (Should -BeOfType operates on stream items; an empty @() streams nothing).
            ,$result.Errors | Should -BeOfType ([Object[]])
        }

        It "Warnings should be an array" -Skip:($env:GITHUB_ACTIONS -eq 'true') {
            $result = Invoke-ModuleTemplate -DryRun
            ,$result.Warnings | Should -BeOfType ([Object[]])
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
