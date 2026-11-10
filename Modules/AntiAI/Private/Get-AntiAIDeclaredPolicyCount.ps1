#Requires -Version 5.1

function Get-AntiAIDeclaredPolicyCount {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $settingsPath = Join-Path $script:ModuleRoot '..\..\Config\SettingsCounts.json'
    $moduleConfigPath = Join-Path $script:ModuleRoot 'Config\AntiAI-Settings.json'
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $moduleConfig = Get-Content -LiteralPath $moduleConfigPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $declared = [int]$settings.modules.AntiAI.policies
    $configured = [int]$moduleConfig.TotalPolicies
    $derived = @(Get-AntiAIRegistryTargets).Count
    if ($declared -lt 1 -or $declared -ne $configured -or $declared -ne $derived) {
        throw "AntiAI policy count drift: SettingsCounts=$declared, config=$configured, derived=$derived"
    }
    return $declared
}
