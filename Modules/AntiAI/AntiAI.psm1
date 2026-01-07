#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AntiAI Module Loader
    
.DESCRIPTION
    Disables all Windows 11 AI features using official Microsoft policies.
    Includes Recall, Copilot, Paint AI, Notepad AI, Click to Do, Settings Agent, and Explorer AI Actions.
    
.NOTES
    Module: AntiAI
    Version: 2.2.3
    Author: NoID Privacy
#>

Set-StrictMode -Version Latest

# Get module root path
$script:ModuleRoot = $PSScriptRoot

# Import private functions
$privateFunctions = @(
    'Test-AntiAICompliance'
    'Set-SystemAIModels'
    'Disable-Recall'
    'Set-RecallProtection'
    'Disable-Copilot'
    'Disable-CopilotAdvanced'  # NEW v2.2.3: URI handlers, Edge sidebar, Recall export
    'Disable-ClickToDo'
    'Disable-SettingsAgent'
    'Disable-ExplorerAI'       # NEW: File Explorer AI Actions menu
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
