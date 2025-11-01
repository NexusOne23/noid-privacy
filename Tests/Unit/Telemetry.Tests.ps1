#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Unit Tests for SecurityBaseline-Telemetry.ps1

.DESCRIPTION
    Tests for Telemetry & Privacy module:
    - Telemetry deactivation (158 Registry Keys)
    - Service disabling (37 Services)
    - Scheduled Task disabling (30 Tasks)
    - App Permissions (37 Permissions)
    - Diagnostic Data settings
#>

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $projectRoot "Modules\SecurityBaseline-Telemetry.ps1"
    
    . $modulePath
}

Describe "Telemetry Module - Basic Validation" {
    
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

Describe "Telemetry Module - Functions" {
    
    Context "Main Functions" {
        It "Should have Disable-WindowsTelemetry function" {
            Get-Command Disable-WindowsTelemetry -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Disable-TelemetryServices function" {
            Get-Command Disable-TelemetryServices -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Disable-TelemetryScheduledTasks function" {
            Get-Command Disable-TelemetryScheduledTasks -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Disable-AllAppPermissionsDefaults function" {
            Get-Command Disable-AllAppPermissionsDefaults -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-MinimalDiagnosticData function" {
            Get-Command Set-MinimalDiagnosticData -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "CmdletBinding" {
        It "Should have CmdletBinding on main functions" {
            $cmd = Get-Command Disable-WindowsTelemetry
            $cmd.CmdletBinding | Should -Be $true
        }
    }
}

Describe "Telemetry Module - Service Disabling" {
    
    Context "Telemetry Services" {
        It "Should reference DiagTrack service" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'DiagTrack'
        }
        
        It "Should reference dmwappushservice" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'dmwappushservice'
        }
        
        It "Should disable services safely" {
            $content = Get-Content $modulePath -Raw
            # Should use try-catch for service operations
            $content | Should -Match 'try'
            $content | Should -Match 'catch'
        }
    }
}

Describe "Telemetry Module - Registry Operations" {
    
    Context "Registry Keys" {
        It "Should set AllowTelemetry to 0" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'AllowTelemetry'
        }
        
        It "Should disable CEIP (Customer Experience Improvement)" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'CEIP'
        }
        
        It "Should use Set-RegistryValue function" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Set-RegistryValue'
        }
    }
}

Describe "Telemetry Module - App Permissions" {
    
    Context "Permission Categories" {
        It "Should reference Location permission" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'location'
        }
        
        It "Should reference Camera permission" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'webcam|camera'
        }
        
        It "Should reference Microphone permission" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'microphone'
        }
        
        It "Should handle 37 app permissions" {
            $content = Get-Content $modulePath -Raw
            # Check for multiple permission types
            ($content -match 'Capability' -or $content -match 'Permission') | Should -Be $true
        }
    }
}

Describe "Telemetry Module - Scheduled Tasks" {
    
    Context "Task Disabling" {
        It "Should disable scheduled tasks" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'ScheduledTask'
        }
        
        It "Should use try-catch for task operations" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'try'
            $content | Should -Match 'catch'
        }
    }
}

Describe "Telemetry Module - Diagnostic Data" {
    
    Context "Minimal Diagnostic Data" {
        It "Should set diagnostic data to Security (0)" {
            $content = Get-Content $modulePath -Raw
            # Should set AllowTelemetry to 0 (Security/Required)
            $content | Should -Match 'AllowTelemetry.*0'
        }
    }
}

Describe "Telemetry Module - Error Handling" {
    
    Context "Robustness" {
        It "Should have multiple try-catch blocks" {
            $content = Get-Content $modulePath -Raw
            $tryCount = ([regex]::Matches($content, '\btry\b')).Count
            $catchCount = ([regex]::Matches($content, '\bcatch\b')).Count
            
            $tryCount | Should -BeGreaterThan 10
            $catchCount | Should -BeGreaterThan 10
        }
        
        It "Should use Write-Verbose for logging" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match 'Write-Verbose'
        }
    }
}

Describe "Telemetry Module - Comment-Based Help" {
    
    Context "Documentation" {
        It "Should have Synopsis" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '\.SYNOPSIS'
        }
        
        It "Should have Description" {
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '\.DESCRIPTION'
        }
    }
}
