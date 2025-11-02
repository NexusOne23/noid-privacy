#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Unit Tests for SecurityBaseline-Advanced.ps1

.DESCRIPTION
    Tests for Advanced Security module:
    - Windows LAPS
    - Virtualization-Based Security (VBS)
    - Credential Guard
    - HVCI (Hypervisor Code Integrity)
    - LSA Protection
    - AutoPlay/AutoRun
    - SmartScreen
    - Exploit Protection
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    
    # Load dependencies first (Advanced module needs these)
    $commonPath = Join-Path $projectRoot "Modules\SecurityBaseline-Common.ps1"
    $localizationPath = Join-Path $projectRoot "Modules\SecurityBaseline-Localization.ps1"
    $modulePath = Join-Path $projectRoot "Modules\SecurityBaseline-Advanced.ps1"
    
    # Dot-source dependencies
    . $commonPath
    . $localizationPath
    
    # Dot-source the module under test
    . $modulePath
}

Describe "Advanced Module - Basic Validation" {
    
    Context "Module Loading" {
        It "Should load without errors" {
            { . $modulePath } | Should -Not -Throw
        }
        
        It "Should have #Requires statements" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '#Requires -Version'
            $content | Should -Match '#Requires -RunAsAdministrator'
        }
        
        It "Should have Set-StrictMode" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Set-StrictMode'
        }
    }
}

Describe "Advanced Module - LAPS Functions" {
    
    Context "Windows LAPS" {
        It "Should have Enable-WindowsLAPS function" {
            Get-Command Enable-WindowsLAPS -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have CmdletBinding" {
            $cmd = Get-Command Enable-WindowsLAPS
            $cmd.CmdletBinding | Should -Be $true
        }
        
        It "Should have comment-based help" {
            $help = Get-Help Enable-WindowsLAPS
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Advanced Module - VBS & Credential Guard" {
    
    Context "Virtualization-Based Security" {
        It "Should have Enable-VirtualizationBasedSecurity function" {
            Get-Command Enable-VirtualizationBasedSecurity -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should reference Credential Guard" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Credential.*Guard'
        }
        
        It "Should reference HVCI" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'HVCI'
        }
    }
}

Describe "Advanced Module - LSA Protection" {
    
    Context "LSA Protection" {
        It "Should have Enable-LSAProtection function" {
            Get-Command Enable-LSAProtection -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should reference RunAsPPL" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'RunAsPPL'
        }
    }
}

Describe "Advanced Module - AutoPlay & SmartScreen" {
    
    Context "AutoPlay" {
        It "Should have Disable-AutoPlay function" {
            Get-Command Disable-AutoPlay -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "SmartScreen" {
        It "Should have Set-SmartScreenExtended function" {
            Get-Command Set-SmartScreenExtended -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Advanced Module - Exploit Protection" {
    
    Context "Exploit Protection" {
        It "Should have Set-ExploitProtection function" {
            Get-Command Set-ExploitProtection -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should reference DEP (Data Execution Prevention)" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '\bDEP\b'
        }
        
        It "Should reference SEHOP" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'SEHOP'
        }
        
        It "Should reference ASLR" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'ASLR'
        }
    }
}

Describe "Advanced Module - Code Quality" {
    
    Context "Error Handling" {
        It "Should have try-catch blocks" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '\btry\b'
            $content | Should -Match '\bcatch\b'
        }
        
        It "Should use Write-Verbose" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Write-Verbose'
        }
    }
    
    Context "Syntax Validation" {
        It "Should have no syntax errors" {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $modulePath,
                [ref]$null,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
    }
}

Describe "Advanced Module - Registry Operations" {
    
    Context "Registry Safety" {
        It "Should use Set-RegistryValue function" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Set-RegistryValue'
        }
    }
}
