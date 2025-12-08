<#
.SYNOPSIS
    Unit tests for DNS module
    
.DESCRIPTION
    Pester v5 tests for the DNS module functionality.
    Tests return values, DryRun behavior, provider configuration, and backup creation.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: Pester 5.0+
#>

BeforeAll {
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\DNS.psm1"
    
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
    
    # Initialize backup system
    if (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue) {
        Initialize-BackupSystem
    }
}

Describe "DNS Module" {
    
    Context "Module Structure" {
        
        It "Should export Invoke-DNSConfiguration function" {
            $command = Get-Command -Name Invoke-DNSConfiguration -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Get-DNSStatus function" {
            $command = Get-Command -Name Get-DNSStatus -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.CmdletBinding | Should -Be $true
        }
    }
    
    Context "Function Parameters" {
        
        It "Should have Provider parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('Provider') | Should -Be $true
        }
        
        It "Provider parameter should accept specific values" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $validateSet = $command.Parameters['Provider'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'Cloudflare'
            $validateSet.ValidValues | Should -Contain 'Quad9'
            $validateSet.ValidValues | Should -Contain 'AdGuard'
        }
        
        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }
        
        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-DNSConfiguration
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }
    
    Context "DNS Providers Configuration" {
        
        It "Should load DNS providers from JSON" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            $providersPath | Should -Exist
        }
        
        It "Providers file should be valid JSON" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            { Get-Content $providersPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should have Cloudflare provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'cloudflare'
        }
        
        It "Should have Quad9 provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'quad9'
        }
        
        It "Should have AdGuard provider" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.PSObject.Properties.Name | Should -Contain 'adguard'
        }
        
        It "Cloudflare should have DoH template" {
            $providersPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Config\Providers.json"
            $providersData = Get-Content $providersPath -Raw | ConvertFrom-Json
            $providersData.providers.cloudflare.doh.template | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Function Execution - DryRun Mode" {
        
        It "Should execute without errors in DryRun mode with provider" {
            { Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force } | Should -Not -Throw
        }
        
        It "Should return a PSCustomObject" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            $result | Should -BeOfType [PSCustomObject]
        }
        
        It "Should have Success property" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'Success'
        }
        
        It "Should have Provider property" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            $result.PSObject.Properties.Name | Should -Contain 'Provider'
        }
        
        It "Provider property should match requested provider" {
            $result = Invoke-DNSConfiguration -Provider 'Quad9' -DryRun -Force
            $result.Provider | Should -Be 'Quad9'
        }
    }
    
    Context "Return Object Structure" {
        
        It "Should return object with all required properties" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            
            $requiredProperties = @(
                'Success',
                'Provider',
                'AdaptersConfigured',
                'Errors',
                'Warnings',
                'Duration'
            )
            
            foreach ($prop in $requiredProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
        
        It "Errors should be an array" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            $result.Errors -is [Array] | Should -Be $true
        }
        
        It "Warnings should be an array" {
            $result = Invoke-DNSConfiguration -Provider 'Cloudflare' -DryRun -Force
            $result.Warnings -is [Array] | Should -Be $true
        }
    }
    
    Context "DoH Policy Settings" {
        
        It "Set-DoHPolicy should use correct registry values" {
            # This is a mock test - actual policy setting requires admin rights
            # We're just checking the function exists and has correct documentation
            $functionContent = Get-Content (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules\DNS\Private\Set-DoHPolicy.ps1") -Raw
            $functionContent | Should -Match "DoHPolicy = 3"
            $functionContent | Should -Match "REQUIRE"
        }
    }
}

Describe "DNS Helper Functions" {
    
    Context "Get-DNSStatus" {
        
        It "Should execute without errors" {
            { Get-DNSStatus } | Should -Not -Throw
        }
        
        It "Should return a PSCustomObject" {
            $result = Get-DNSStatus
            $result | Should -BeOfType [PSCustomObject]
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module DNS -Force -ErrorAction SilentlyContinue
}
