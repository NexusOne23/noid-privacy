#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Privacy & Telemetry hardening module loader

.DESCRIPTION
    Loads all Privacy module functions for Windows 11 telemetry control,
    personalization settings, bloatware removal, and OneDrive configuration.
    
    Supports 3 operating modes:
    - MSRecommended: Fully supported by Microsoft (default)
    - Strict: Maximum privacy (AllowTelemetry=0 only on Enterprise/Education, other settings work everywhere)
    - Paranoid: Hardcore mode (not recommended)

.NOTES
    Module: Privacy
    Version: 2.2.2
    Author: NoID Privacy
#>

# Get module root path
$script:ModuleRoot = $PSScriptRoot

# Import private functions
$privateFunctions = @(
    'Backup-PrivacySettings',
    'Set-TelemetrySettings',
    'Set-PersonalizationSettings',
    'Set-AppPrivacySettings',
    'Set-OneDriveSettings',
    'Set-PolicyBasedAppRemoval',
    'Disable-TelemetryServices',
    'Disable-TelemetryTasks',
    'Remove-Bloatware'
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path $ModuleRoot "Private\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Import Test-PrivacyCompliance (located in module root)
$testCompliancePath = Join-Path $ModuleRoot "Test-PrivacyCompliance.ps1"
if (Test-Path $testCompliancePath) {
    . $testCompliancePath
}

# Import public functions
$publicFunctions = @(
    'Invoke-PrivacyHardening',
    'Restore-Bloatware'
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path $ModuleRoot "Public\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Export public functions + Test-PrivacyCompliance (needed for Invoke-PrivacyHardening verification)
Export-ModuleMember -Function @($publicFunctions + 'Test-PrivacyCompliance')

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-Privacy' -Value 'Invoke-PrivacyHardening' -Force
Export-ModuleMember -Alias 'Invoke-Privacy'
