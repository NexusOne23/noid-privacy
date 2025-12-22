#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    EdgeHardening Module Loader
    
.DESCRIPTION
    Loads all private and public functions for the EdgeHardening module.
    Applies Microsoft Edge v139+ Security Baseline using native PowerShell.
    
    NO EXTERNAL DEPENDENCIES:
    - No LGPO.exe required
    - Native PowerShell Set-ItemProperty
    - Built-in Windows tools only
    
.NOTES
    Author: NexusOne23
    Version: 2.2.2
    Requires: PowerShell 5.1+, Administrator privileges
#>

# Module variables
$script:ModuleName = "EdgeHardening"
$script:ModuleRoot = $PSScriptRoot

# Load Private functions
$privateFunctions = @(
    'Set-EdgePolicies.ps1',
    'Test-EdgePolicies.ps1',
    'Backup-EdgePolicies.ps1',
    'Restore-EdgePolicies.ps1'
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path $PSScriptRoot "Private\$function"
    if (Test-Path $functionPath) {
        . $functionPath
    }
    else {
        Write-Host "WARNING: [$script:ModuleName] Private function not found: $function" -ForegroundColor Yellow
    }
}

# Load Public functions
$publicFunctions = @(
    'Invoke-EdgeHardening.ps1',
    'Test-EdgeHardening.ps1'
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path $PSScriptRoot "Public\$function"
    if (Test-Path $functionPath) {
        . $functionPath
    }
    else {
        Write-Host "WARNING: [$script:ModuleName] Public function not found: $function" -ForegroundColor Yellow
    }
}

# Module loaded successfully
Write-Verbose "[$script:ModuleName] Module loaded successfully from: $PSScriptRoot"
