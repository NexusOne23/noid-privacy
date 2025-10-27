# ============================================================================
# SecurityBaseline-AI.ps1
# Windows AI Features Lockdown (Copilot, Recall, Click to Do, etc.)
# ============================================================================

Set-StrictMode -Version Latest

function Disable-WindowsRecall {
    <#
    .SYNOPSIS
        Deaktiviert Windows Recall komplett (PRIVACY KRITISCH!)
    .DESCRIPTION
        Recall macht Screenshots von ALLEM inkl. Passwoertern, Banking, etc.
        MUSS deaktiviert werden fuer Privacy!
        
        Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
        Policy: DisableAIDataAnalysis = 1
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Windows Recall - KOMPLETT DEAKTIVIEREN"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    
    # KRITISCH: Recall komplett ausschalten
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableAIDataAnalysis" -Value 1 -Type DWord `
        -Description "Windows Recall deaktivieren (KEINE Screenshots!)"
    
    # Policy Manager Path (zusaetzlicher Schutz)
    $policyManagerPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableAIDataAnalysis"
    Set-RegistryValue -Path $policyManagerPath -Name "value" -Value 1 -Type DWord `
        -Description "Recall Policy Manager: DISABLED"
    
    Write-Success "Windows Recall: KOMPLETT DEAKTIVIERT"
    Write-Warning "Recall war ein PRIVACY NIGHTMARE - Screenshots von Passwoertern, Banking, etc.!"
    Write-Info "Alle vorhandenen Snapshots werden beim naechsten Login geloescht"
}

function Disable-WindowsCopilot {
    <#
    .SYNOPSIS
        Deaktiviert Windows Copilot komplett (Multi-Layer Blocking!)
    .DESCRIPTION
        Blockiert Copilot auf ALLEN Ebenen:
        1. TurnOffWindowsCopilot Policy
        2. ShowCopilotButton = 0 (Taskbar)
        3. Copilot App Registry Keys
        
        Microsoft aendert staendig die Pfade - daher Multi-Layer!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Windows Copilot - MULTI-LAYER BLOCKING"
    
    # Layer 1: TurnOffWindowsCopilot (HKLM - nicht offiziell aber funktioniert)
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 1 - Main Policy (HKLM)"
    
    # Layer 2: WindowsCopilot Path (alte Methode, noch verwenden!)
    $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    Set-RegistryValue -Path $copilotPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 2 - Legacy Policy Path"
    
    # Layer 3: Taskbar Button verstecken
    Set-RegistryValue -Path $copilotPath -Name "ShowCopilotButton" -Value 0 -Type DWord `
        -Description "Copilot: Layer 3 - Hide Taskbar Button"
    
    # Layer 4: Disable Copilot altogether
    $explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-RegistryValue -Path $explorerPath -Name "DisableWindowsCopilot" -Value 1 -Type DWord `
        -Description "Copilot: Layer 4 - Explorer Disable"
    
    Write-Success "Windows Copilot: MULTI-LAYER BLOCKIERT"
    Write-Info "Blockiert auf 4 Ebenen (Microsoft aendert staendig die Pfade!)"
    Write-Info "Copilot Icon wird von Taskbar entfernt"
}

function Disable-ClickToDo {
    <#
    .SYNOPSIS
        Deaktiviert Click to Do (AI Screenshot Analysis)
    .DESCRIPTION
        Click to Do macht Screenshots + AI Analysis
        Privacy-invasiv, sollte deaktiviert werden
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Click to Do - DEAKTIVIEREN"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableClickToDo" -Value 1 -Type DWord `
        -Description "Click to Do deaktivieren (AI Screenshot Analysis)"
    
    Write-Success "Click to Do: DEAKTIVIERT"
    Write-Info "Keine AI-basierten Screenshot-Analysen mehr"
}

function Disable-PaintAIFeatures {
    <#
    .SYNOPSIS
        Deaktiviert AI Features in Paint (Cocreator, Generative Fill, Image Creator)
    .DESCRIPTION
        Microsoft hat AI in Paint integriert
        Alle AI Features werden deaktiviert
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Paint AI Features - DEAKTIVIEREN"
    
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
    
    Write-Success "Paint AI Features: ALLE DEAKTIVIERT"
    Write-Info "Cocreator, Generative Fill, Image Creator = AUS"
}

function Disable-SettingsAgent {
    <#
    .SYNOPSIS
        Deaktiviert Settings Agent (AI im Settings Menu)
    .DESCRIPTION
        Windows hat AI im Settings Menu integriert
        Wird deaktiviert
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Settings Agent - DEAKTIVIEREN"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue -Path $aiPolicyPath -Name "DisableSettingsAgent" -Value 1 -Type DWord `
        -Description "Settings Agent deaktivieren (AI in Settings)"
    
    Write-Success "Settings Agent: DEAKTIVIERT"
}

function Disable-CopilotProactive {
    <#
    .SYNOPSIS
        Deaktiviert Copilot Proactive Features
    .DESCRIPTION
        Verhindert dass Copilot ungefragt Vorschlaege macht
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Copilot Best Practice 25H2 - DEAKTIVIEREN"
    
    # Disable Copilot Proactive
    $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    Set-RegistryValue -Path $copilotPath -Name "DisableCopilotProactive" -Value 1 -Type DWord `
        -Description "Copilot Proactive deaktivieren (keine ungewollten Vorschlaege)"
    
    Write-Success "Copilot Proactive: DEAKTIVIERT"
}

function Set-RecallMaximumStorage {
    <#
    .SYNOPSIS
        Setzt Recall Storage auf Minimum (falls Recall aktiviert sein sollte)
    .DESCRIPTION
        Fallback falls Recall durch User reaktiviert wird
        Limitiert Speicherplatz auf Minimum
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Recall Storage Limits - MINIMUM"
    
    $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    
    # Maximum Storage auf 10GB (Minimum)
    Set-RegistryValue -Path $aiPolicyPath -Name "SetMaximumStorageSpaceForRecallSnapshots" -Value 10 -Type DWord `
        -Description "Recall: Max Storage = 10GB (Minimum, falls reaktiviert)"
    
    # Maximum Duration auf 1 Tag (Minimum)
    Set-RegistryValue -Path $aiPolicyPath -Name "SetMaximumStorageDurationForRecallSnapshots" -Value 1 -Type DWord `
        -Description "Recall: Max Duration = 1 Tag (Minimum, falls reaktiviert)"
    
    Write-Success "Recall Storage Limits: AUF MINIMUM gesetzt"
    Write-Info "Fallback falls Recall reaktiviert wird: Nur 10GB fuer 1 Tag"
}

function Show-AILockdownReport {
    <#
    .SYNOPSIS
        Zeigt Zusammenfassung der AI-Blockierung
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  AI LOCKDOWN - ZUSAMMENFASSUNG" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DEAKTIVIERT:" -ForegroundColor Green
    Write-Host "  [X] Windows Recall (Screenshots)" -ForegroundColor Green
    Write-Host "  [X] Windows Copilot (Multi-Layer)" -ForegroundColor Green
    Write-Host "  [X] Click to Do (AI Analysis)" -ForegroundColor Green
    Write-Host "  [X] Paint AI (Cocreator, Gen Fill, Image Creator)" -ForegroundColor Green
    Write-Host "  [X] Settings Agent (AI in Settings)" -ForegroundColor Green
    Write-Host "  [X] Copilot Proactive Features" -ForegroundColor Green
    Write-Host ""
    Write-Host "FALLBACK:" -ForegroundColor Yellow
    Write-Host "  [!] Recall Storage auf Minimum (10GB, 1 Tag)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "STATUS:" -ForegroundColor Cyan
    Write-Host "  [OK] Alle AI Features system-weit blockiert (HKLM)" -ForegroundColor Green
    Write-Host "  [OK] Gilt fuer ALLE User" -ForegroundColor Green
    Write-Host "  [OK] Multi-Layer Blocking (mehrere Registry Pfade)" -ForegroundColor Green
    Write-Host ""
    Write-Host "HINWEIS:" -ForegroundColor Yellow
    Write-Host "  Microsoft aendert staendig AI-Implementierung!" -ForegroundColor Yellow
    Write-Host "  Wir blockieren auf mehreren Ebenen fuer Zukunftssicherheit." -ForegroundColor Yellow
    Write-Host ""
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
