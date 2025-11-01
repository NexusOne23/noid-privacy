#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Unit Tests for Backup-SecurityBaseline.ps1

.DESCRIPTION
    Tests for Backup script functionality:
    - Registry backup
    - Service backup
    - JSON export
    - Error handling
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $scriptPath = Join-Path $projectRoot "Backup-SecurityBaseline.ps1"
    
    # Note: We test structure, not execution (needs admin)
}

Describe "Backup Script - Basic Validation" {
    
    Context "Script Structure" {
        It "Should exist" {
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have #Requires statements" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '#Requires -Version'
            $content | Should -Match '#Requires -RunAsAdministrator'
        }
        
        It "Should have Set-StrictMode" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Set-StrictMode'
        }
        
        It "Should initialize script:RegistryChanges" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '\$script:RegistryChanges\s*='
        }
    }
    
    Context "Syntax Validation" {
        It "Should have no syntax errors" {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $scriptPath,
                [ref]$null,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
    }
}

Describe "Backup Script - Parameter Validation" {
    
    Context "Parameters" {
        It "Should have BackupPath parameter" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'param\s*\('
            $content | Should -Match '\$BackupPath'
        }
    }
}

Describe "Backup Script - Module Loading" {
    
    Context "Dependencies" {
        It "Should load Localization module" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecurityBaseline-Localization\.ps1'
        }
        
        It "Should load RegistryChanges-Definition" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'RegistryChanges-Definition\.ps1'
        }
        
        It "Should load RegistryBackup-Optimized" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecurityBaseline-RegistryBackup-Optimized\.ps1'
        }
    }
}

Describe "Backup Script - Error Handling" {
    
    Context "Try-Catch Blocks" {
        It "Should have try-catch blocks" {
            $content = Get-Content $scriptPath -Raw
            $tryCount = ([regex]::Matches($content, '\btry\b')).Count
            $catchCount = ([regex]::Matches($content, '\bcatch\b')).Count
            
            $tryCount | Should -BeGreaterThan 5
            $catchCount | Should -BeGreaterThan 5
        }
    }
    
    Context "Admin Check" {
        It "Should check for Administrator privileges" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Administrator'
        }
    }
}

Describe "Backup Script - Logging" {
    
    Context "Transcript" {
        It "Should have Start-Transcript" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Start-Transcript'
        }
        
        It "Should have Stop-Transcript" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Stop-Transcript'
        }
    }
    
    Context "Log Messages" {
        It "Should use Write-Verbose" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Write-Verbose'
        }
        
        It "Should use Write-Host for user messages" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Write-Host'
        }
    }
}

Describe "Backup Script - JSON Export" {
    
    Context "JSON Operations" {
        It "Should export to JSON" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'ConvertTo-Json'
        }
        
        It "Should create backup directory" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'New-Item.*Directory'
        }
    }
}

Describe "Backup Script - Backup Functions" {
    
    Context "Function Calls" {
        It "Should call Backup-SpecificRegistryKeys" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Backup-SpecificRegistryKeys'
        }
    }
}
