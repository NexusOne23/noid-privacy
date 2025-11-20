#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AntiAI Module Loader
    
.DESCRIPTION
    Disables all Windows 11 AI features using official Microsoft policies.
    Includes Recall, Copilot, Paint AI, Notepad AI, Click to Do, and Settings Agent.
    
.NOTES
    Module: AntiAI
    Version: 2.1.0
    Author: NoID Privacy Pro
#>

Set-StrictMode -Version Latest

# Get module root path
$script:ModuleRoot = $PSScriptRoot

# Import private functions
$privateFunctions = @(
    'Backup-AntiAISettings'
    'Restore-AntiAISettings'
    'Test-AntiAICompliance'
    'Set-SystemAIModels'
    'Disable-Recall'
    'Set-RecallProtection'
    'Disable-Copilot'
    'Disable-ClickToDo'
    'Disable-SettingsAgent'
    'Disable-NotepadAI'
    'Disable-PaintAI'
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path $ModuleRoot "Private\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Import public functions
$publicFunctions = @(
    'Invoke-AntiAI'
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path $ModuleRoot "Public\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Export public functions + Test-AntiAICompliance (needed for Invoke-AntiAI verification)
Export-ModuleMember -Function @($publicFunctions + 'Test-AntiAICompliance')
