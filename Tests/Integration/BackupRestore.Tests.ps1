#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Integration Tests for Backup -> Restore workflow

.DESCRIPTION
    Tests the complete backup and restore workflow:
    1. Backup current settings
    2. Validate backup file
    3. Restore from backup
    4. Verify restoration
    
.NOTES
    These tests validate structure and syntax, not actual execution.
    Real backup/restore testing requires admin rights and is done on VMs.
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $backupScript = Join-Path $projectRoot "Backup-SecurityBaseline.ps1"
    $restoreScript = Join-Path $projectRoot "Restore-SecurityBaseline.ps1"
}

Describe "Integration - Backup -> Restore Workflow" {
    
    Context "Scripts Exist" {
        It "Backup script should exist" {
            Test-Path $backupScript | Should -Be $true
        }
        
        It "Restore script should exist" {
            Test-Path $restoreScript | Should -Be $true
        }
    }
    
    Context "Script Compatibility" {
        It "Backup should create JSON output" {
            $content = Get-Content $backupScript -Raw
            $content | Should -Match 'ConvertTo-Json'
        }
        
        It "Restore should accept JSON input" {
            $content = Get-Content $restoreScript -Raw
            $content | Should -Match 'ConvertFrom-Json'
        }
    }
}

Describe "Integration - Backup Validation" {
    
    Context "Backup Structure" {
        It "Should backup registry keys" {
            $content = Get-Content $backupScript -Raw
            $content | Should -Match 'RegistryChanges'
        }
        
        It "Should create backup directory" {
            $content = Get-Content $backupScript -Raw
            $content | Should -Match 'New-Item.*Directory'
        }
        
        It "Should generate timestamp" {
            $content = Get-Content $backupScript -Raw
            $content | Should -Match 'Get-Date'
        }
    }
}

Describe "Integration - Restore Validation" {
    
    Context "Restore Safety" {
        It "Should validate backup file exists" {
            $content = Get-Content $restoreScript -Raw
            $content | Should -Match 'Test-Path'
        }
        
        It "Should ask for confirmation" {
            $content = Get-Content $restoreScript -Raw
            $content | Should -Match 'Read-Host'
        }
        
        It "Should handle errors gracefully" {
            $content = Get-Content $restoreScript -Raw
            $tryCount = ([regex]::Matches($content, '\btry\b')).Count
            $catchCount = ([regex]::Matches($content, '\bcatch\b')).Count
            
            $tryCount | Should -BeGreaterThan 5
            $catchCount | Should -BeGreaterThan 5
        }
    }
}

Describe "Integration - Workflow Dependencies" {
    
    Context "Shared Modules" {
        It "Both scripts should use same RegistryBackup module" {
            $backupContent = Get-Content $backupScript -Raw
            $restoreContent = Get-Content $restoreScript -Raw
            
            $backupContent | Should -Match 'RegistryBackup-Optimized'
            $restoreContent | Should -Match 'RegistryBackup-Optimized'
        }
        
        It "Both scripts should use Localization module" {
            $backupContent = Get-Content $backupScript -Raw
            $restoreContent = Get-Content $restoreScript -Raw
            
            $backupContent | Should -Match 'Localization'
            $restoreContent | Should -Match 'Localization'
        }
    }
}

Describe "Integration - Data Integrity" {
    
    Context "Backup Format" {
        It "Should use consistent JSON structure" {
            $backupContent = Get-Content $backupScript -Raw
            $restoreContent = Get-Content $restoreScript -Raw
            
            # Both should reference Settings structure
            $backupContent | Should -Match 'Settings'
            $restoreContent | Should -Match 'Settings'
        }
    }
}
