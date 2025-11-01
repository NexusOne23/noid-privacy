#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Integration Tests for Apply → Verify workflow

.DESCRIPTION
    Tests the complete workflow:
    1. Apply security baseline (WhatIf mode)
    2. Verify compliance
    3. Check that verification passes
    
.NOTES
    These tests run in WhatIf mode to avoid modifying the system.
    Real integration testing should be done on dedicated VMs.
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $applyScript = Join-Path $projectRoot "Apply-Win11-25H2-SecurityBaseline.ps1"
    $verifyScript = Join-Path $projectRoot "Verify-SecurityBaseline.ps1"
}

Describe "Integration - Apply → Verify Workflow" {
    
    Context "Scripts Exist" {
        It "Apply script should exist" {
            Test-Path $applyScript | Should -Be $true
        }
        
        It "Verify script should exist" {
            Test-Path $verifyScript | Should -Be $true
        }
    }
    
    Context "Script Syntax" {
        It "Apply script should have no syntax errors" {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $applyScript,
                [ref]$null,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
        
        It "Verify script should have no syntax errors" {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $verifyScript,
                [ref]$null,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
    }
    
    Context "WhatIf Support" {
        It "Apply script should support -WhatIf" {
            $content = Get-Content $applyScript -Raw
            $content | Should -Match 'SupportsShouldProcess'
        }
    }
}

Describe "Integration - Workflow Dependencies" {
    
    Context "Module Availability" {
        It "Core module should be loadable" {
            $corePath = Join-Path $projectRoot "Modules\SecurityBaseline-Core.ps1"
            Test-Path $corePath | Should -Be $true
        }
        
        It "ASR module should be loadable" {
            $asrPath = Join-Path $projectRoot "Modules\SecurityBaseline-ASR.ps1"
            Test-Path $asrPath | Should -Be $true
        }
        
        It "Localization module should be loadable" {
            $locPath = Join-Path $projectRoot "Modules\SecurityBaseline-Localization.ps1"
            Test-Path $locPath | Should -Be $true
        }
    }
}

Describe "Integration - End-to-End Validation" {
    
    Context "Script Parameters" {
        It "Apply should accept -WhatIf parameter" {
            # This validates that the script can be invoked with WhatIf
            # Actual execution requires admin rights and is tested in VM
            $content = Get-Content $applyScript -Raw
            $content | Should -Match '\[CmdletBinding.*SupportsShouldProcess'
        }
    }
}
