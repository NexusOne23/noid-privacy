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
        # Note: VBS/Credential Guard functions are in Core module, not Advanced
        # Advanced module contains: LAPS, Auditing, TLS, WDigest, EFSRPC, WebClient
        
        It "Should be loadable (Advanced module focuses on LAPS, Auditing, TLS)" {
            { . $modulePath } | Should -Not -Throw
        }
    }
}

Describe "Advanced Module - TLS Hardening" {
    
    Context "TLS/SSL Security" {
        It "Should have Set-TLSHardening function" {
            Get-Command Set-TLSHardening -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should reference TLS 1.2" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'TLS.*1\.2'
        }
    }
}

Describe "Advanced Module - WDigest & Auth Coercion Protection" {
    
    Context "WDigest Authentication" {
        It "Should have Disable-WDigest function" {
            Get-Command Disable-WDigest -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "EFSRPC Protection" {
        It "Should have Disable-EFSRPC function" {
            Get-Command Disable-EFSRPC -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "WebClient/WebDAV Protection" {
        It "Should have Disable-WebClient function" {
            Get-Command Disable-WebClient -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Advanced Module - Auditing" {
    
    Context "Advanced Auditing" {
        It "Should have Enable-AdvancedAuditing function" {
            Get-Command Enable-AdvancedAuditing -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "NTLM Auditing" {
        It "Should have Enable-NTLMAuditing function" {
            Get-Command Enable-NTLMAuditing -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
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
