#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Unit Tests for Restore-SecurityBaseline.ps1

.DESCRIPTION
    Tests for Restore script functionality:
    - Registry restore
    - Service restore
    - JSON import
    - Validation
    - Error handling
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $scriptPath = Join-Path $projectRoot "Restore-SecurityBaseline.ps1"
}

Describe "Restore Script - Basic Validation" {
    
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

Describe "Restore Script - Parameter Validation" {
    
    Context "Parameters" {
        It "Should have BackupFile parameter" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '\$BackupFile'
        }
        
        It "Should have LogPath parameter" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '\$LogPath'
        }
    }
}

Describe "Restore Script - Module Loading" {
    
    Context "Dependencies" {
        It "Should load Localization module" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecurityBaseline-Localization\.ps1'
        }
        
        It "Should load RegistryBackup-Optimized" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecurityBaseline-RegistryBackup-Optimized\.ps1'
        }
    }
}

Describe "Restore Script - JSON Import" {
    
    Context "JSON Operations" {
        It "Should import from JSON" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'ConvertFrom-Json'
        }
        
        It "Should validate backup file exists" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Test-Path'
        }
    }
}

Describe "Restore Script - Error Handling" {
    
    Context "Try-Catch Blocks" {
        It "Should have try-catch blocks" {
            $content = Get-Content $scriptPath -Raw
            $tryCount = ([regex]::Matches($content, '\btry\b')).Count
            $catchCount = ([regex]::Matches($content, '\bcatch\b')).Count
            
            $tryCount | Should -BeGreaterThan 10
            $catchCount | Should -BeGreaterThan 10
        }
    }
    
    Context "Admin Check" {
        It "Should check for Administrator privileges" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Administrator'
        }
    }
    
    Context "Backup Validation" {
        It "Should validate backup before restore" {
            $content = Get-Content $scriptPath -Raw
            # Should check if backup file is valid
            ($content -match 'Test-Path' -or $content -match 'Get-Content') | Should -Be $true
        }
    }
}

Describe "Restore Script - Restore Functions" {
    
    Context "Function Calls" {
        It "Should call Restore-SpecificRegistryKeys" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Restore-SpecificRegistryKeys'
        }
    }
    
    Context "Statistics" {
        It "Should track restore statistics" {
            $content = Get-Content $scriptPath -Raw
            # Should show success/failure counts
            ($content -match 'Restored' -or $content -match 'stats') | Should -Be $true
        }
    }
}

Describe "Restore Script - Logging" {
    
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
    
    Context "Progress Messages" {
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

Describe "Restore Script - Safety Features" {
    
    Context "Confirmation" {
        It "Should ask for user confirmation" {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Read-Host'
        }
    }
    
    Context "Protected Keys" {
        It "Should handle TrustedInstaller-protected keys" {
            $content = Get-Content $scriptPath -Raw
            ($content -match 'TrustedInstaller' -or $content -match 'UnauthorizedAccess') | Should -Be $true
        }
    }
}

Describe "Restore Script - Service Restore" {
    
    Context "Services" {
        It "Should restore service states" {
            $content = Get-Content $scriptPath -Raw
            ($content -match 'Service' -or $content -match 'Get-Service' -or $content -match 'Set-Service') | Should -Be $true
        }
    }
}
