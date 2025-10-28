# ============================================================================
# SecurityBaseline-AI.ps1
# Windows AI Features Lockdown (Copilot, Recall, Click to Do, etc.)
# ============================================================================

Set-StrictMode -Version Latest

function Disable-WindowsRecall {
    <#
    .SYNOPSIS
        Completely disables Windows Recall (PRIVACY CRITICAL!)
    .DESCRIPTION
        Recall takes screenshots of EVERYTHING incl. passwords, banking, etc.
        MUST be disabled for privacy!
        
        Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
        Policy: DisableAIDataAnalysis = 1
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AIRecallTitle')"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    
    # CRITICAL: Turn off Recall completely
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableAIDataAnalysis" -Value 1 -Type DWord `
        -Description "Windows Recall deaktivieren (KEINE Screenshots!)"
    
    # Policy Manager Path (additional protection)
    $policyManagerPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableAIDataAnalysis"
    Set-RegistryValue -Path $policyManagerPath -Name "value" -Value 1 -Type DWord `
        -Description "Recall Policy Manager: DISABLED"
    
    Write-Success "$(Get-LocalizedString 'AIRecallDisabled')"
    Write-Warning "$(Get-LocalizedString 'AIRecallNightmare')"
    Write-Info "$(Get-LocalizedString 'AIRecallSnapshotsDeleted')"
}

function Disable-WindowsCopilot {
    <#
    .SYNOPSIS
        Completely disables Windows Copilot (Multi-Layer Blocking!)
    .DESCRIPTION
        Blocks Copilot on ALL levels:
        1. TurnOffWindowsCopilot Policy
        2. ShowCopilotButton = 0 (Taskbar)
        3. Copilot App Registry Keys
        
        Microsoft constantly changes the paths - therefore Multi-Layer!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AICopilotTitle')"
    
    # Layer 1: TurnOffWindowsCopilot (HKLM - not official but works)
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 1 - Main Policy (HKLM)"
    
    # Layer 2: WindowsCopilot Path (old method, still use!)
    $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    Set-RegistryValue -Path $copilotPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 2 - Legacy Policy Path"
    
    # Layer 3: Hide Taskbar Button
    Set-RegistryValue -Path $copilotPath -Name "ShowCopilotButton" -Value 0 -Type DWord `
        -Description "Copilot: Layer 3 - Hide Taskbar Button"
    
    # Layer 4: Disable Copilot altogether
    $explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-RegistryValue -Path $explorerPath -Name "DisableWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 4 - Explorer Disable"
    
    Write-Success "$(Get-LocalizedString 'AICopilotBlocked')"
    Write-Info "$(Get-LocalizedString 'AICopilot4Layers')"
    Write-Info "$(Get-LocalizedString 'AICopilotIconRemoved')"
}

function Disable-ClickToDo {
    <#
    .SYNOPSIS
        Disables Click to Do (AI Screenshot Analysis)
    .DESCRIPTION
        Click to Do takes screenshots + AI Analysis
        Privacy-invasive, should be disabled
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AIClickToDoTitle')"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableClickToDo" -Value 1 -Type DWord `
        -Description "Click to Do deaktivieren (AI Screenshot Analysis)"
    
    Write-Success "$(Get-LocalizedString 'AIClickToDoDisabled')"
    Write-Info "$(Get-LocalizedString 'AIClickToDoNoAnalysis')"
}

function Disable-PaintAIFeatures {
    <#
    .SYNOPSIS
        Disables AI Features in Paint (Cocreator, Generative Fill, Image Creator)
    .DESCRIPTION
        Microsoft has integrated AI into Paint
        All AI Features will be disabled
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AIPaintTitle')"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    
    # Cocreator (AI Image Generation)
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableCocreator" -Value 1 -Type DWord `
        -Description "Paint Cocreator deaktivieren (AI Image Gen)"
    
    # Generative Fill (AI Editing)
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableGenerativeFill" -Value 1 -Type DWord `
        -Description "Paint Generative Fill deaktivieren (AI Edit)"
    
    # Image Creator (AI Art)
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableImageCreator" -Value 1 -Type DWord `
        -Description "Paint Image Creator deaktivieren (AI Art)"
    
    Write-Success "$(Get-LocalizedString 'AIPaintDisabled')"
    Write-Info "$(Get-LocalizedString 'AIPaintFeatures')"
}

function Disable-SettingsAgent {
    <#
    .SYNOPSIS
        Disables Settings Agent (AI in Settings Menu)
    .DESCRIPTION
        Windows has integrated AI into Settings Menu
        Will be disabled
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AISettingsAgentTitle')"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableSettingsAgent" -Value 1 -Type DWord `
        -Description "Settings Agent deaktivieren (AI in Settings)"
    
    Write-Success "$(Get-LocalizedString 'AISettingsAgentDisabled')"
}

function Disable-CopilotProactive {
    <#
    .SYNOPSIS
        Disables Copilot Proactive Features
    .DESCRIPTION
        Prevents Copilot from making unsolicited suggestions
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AICopilotProactiveTitle')"
    
    # Disable Copilot Proactive
    $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    Set-RegistryValue -Path $copilotPath -Name "DisableCopilotProactive" -Value 1 -Type DWord `
        -Description "Copilot Proactive deaktivieren (keine ungewollten Vorschlaege)"
    
    Write-Success "$(Get-LocalizedString 'AICopilotProactiveDisabled')"
}

function Set-RecallMaximumStorage {
    <#
    .SYNOPSIS
        Sets Recall Storage to minimum (if Recall should be enabled)
    .DESCRIPTION
        Fallback if Recall is reactivated by user
        Limits storage space to minimum
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "$(Get-LocalizedString 'AIRecallStorageTitle')"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    
    # Maximum Storage auf 10GB (Minimum)
    Set-RegistryValue -Path $aiPolicyPath -Name "SetMaximumStorageSpaceForRecallSnapshots" -Value 10 -Type DWord `
        -Description "Recall: Max Storage = 10GB (Minimum, falls reaktiviert)"
    
    # Maximum Duration auf 1 Tag (Minimum)
    Set-RegistryValue -Path $aiPolicyPath -Name "SetMaximumStorageDurationForRecallSnapshots" -Value 1 -Type DWord `
        -Description "Recall: Max Duration = 1 Tag (Minimum, falls reaktiviert)"
    
    Write-Success "$(Get-LocalizedString 'AIRecallStorageMinimum')"
    Write-Info "$(Get-LocalizedString 'AIRecallStorageFallback')"
}

function Show-AILockdownReport {
    <#
    .SYNOPSIS
        Shows AI blocking summary
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "$(Get-LocalizedString 'AILockdownSummary')" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AIDisabled')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AIRecallScreenshots')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AICopilotMultiLayer')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AIClickToDoAnalysis')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AIPaintAI')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AISettingsAgent')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AICopilotProactive')" -ForegroundColor Green
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AIFallback'):" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'AIRecallMinimum')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AIStatus'):" -ForegroundColor Cyan
    Write-Host "$(Get-LocalizedString 'AISystemWideBlocked')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AIAllUsers')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AIMultiLayerBlocking')" -ForegroundColor Green
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AINote'):" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'AIMicrosoftChanges')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'AIFutureProof')" -ForegroundColor Yellow
    Write-Host ""
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
