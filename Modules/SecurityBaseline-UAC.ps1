# ============================================================================
# SecurityBaseline-UAC.ps1
# User Account Control Enhanced Settings - Windows 11 25H2
# ============================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Set-MaximumUAC {
    <#
    .SYNOPSIS
        Sets UAC to Maximum (Always notify)
    .DESCRIPTION
        Configures UAC to highest security:
        - Slider Position: Top (Always notify)
        - ConsentPromptBehaviorAdmin = 2 (Prompt for credentials on secure desktop)
        - PromptOnSecureDesktop = 1 (Secure Desktop active)
        - EnableLUA = 1 (UAC enabled)
    .EXAMPLE
        Set-MaximumUAC
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "UAC Maximum Security (Immer benachrichtigen)"
    
    $securityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # Enable UAC
    Set-RegistryValue -Path $securityPath -Name "EnableLUA" -Value 1 -Type DWord `
        -Description "Enable UAC"
    
    # CRITICAL: ConsentPromptBehaviorAdmin = 2 for "Always notify" (Slider at top!)
    # Values: 0=No prompt, 1=Prompt credentials (no secure desktop), 2=Prompt credentials (secure desktop),
    #         5=Prompt for consent (DEFAULT - Slider Position 2)
    Set-RegistryValue -Path $securityPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord `
        -Description "UAC: Always notify (Slider at top) - Prompt for credentials on secure desktop"
    
    # Enable Secure Desktop for UAC prompts
    Set-RegistryValue -Path $securityPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord `
        -Description "UAC: Enable Secure Desktop (Anti-Malware Protection)"
    
    # ConsentPromptBehaviorUser: Standard users prompt behavior
    # Value: 1 = Prompt for credentials (allows user to elevate with admin password)
    Set-RegistryValue -Path $securityPath -Name "ConsentPromptBehaviorUser" -Value 1 -Type DWord `
        -Description "UAC: Standard User Prompt for credentials"
    
    # ValidateAdminCodeSignatures: Don't require signed executables (too restrictive for most environments)
    # Value: 0 = Don't require (default), 1 = Require digital signature
    Set-RegistryValue -Path $securityPath -Name "ValidateAdminCodeSignatures" -Value 0 -Type DWord `
        -Description "UAC: No signature check (too restrictive for normal environments)"
    
    # EnableSecureUIAPaths: Only allow UIAccess applications that are in secure locations
    Set-RegistryValue -Path $securityPath -Name "EnableSecureUIAPaths" -Value 1 -Type DWord `
        -Description "UAC: Only allow secure UIAccess paths"
    
    Write-Success "UAC auf MAXIMUM gesetzt (Immer benachrichtigen)"
    Write-Info "Slider Position: Ganz oben (Position 1 von 4)"
    Write-Info "Jede Admin-Aktion erfordert Bestaetigung auf Secure Desktop!"
    Write-Warning "Dies ist die sicherste Einstellung - aber kann laestig sein bei vielen Admin-Tasks!"
}

function Enable-EnhancedPrivilegeProtectionMode {
    <#
    .SYNOPSIS
        Enables Enhanced Privilege Protection Mode (EPP) for UAC
    .DESCRIPTION
        Microsoft Security Baseline 25H2: Enhanced Privilege Protection Mode.
        IMPORTANT: This feature is visible in Windows 11 25H2 but NOT YET FUNCTIONAL!
        Settings will be applied, feature will come in later Windows 11 updates.
    .EXAMPLE
        Enable-EnhancedPrivilegeProtectionMode
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "UAC Enhanced Privilege Protection Mode"
    
    Write-Warning-Custom "HINWEIS: Enhanced Privilege Protection ist ein KOMMENDES Feature!"
    Write-Info "Microsoft hat diese Settings in der Baseline 25H2 angekuendigt,"
    Write-Info "aber das Feature ist noch NICHT aktiv in Windows 11 25H2."
    Write-Info "Mehr Info: https://techcommunity.microsoft.com/blog/windows-itpro-blog/administrator-protection-on-windows-11/4303482"
    Write-Host ""
    Write-Info "Wir setzen die Registry-Keys TROTZDEM (fuer zukuenftige Windows Updates)..."
    
    # Security Options: Enhanced Privilege Protection Mode
    # Behavior of the elevation prompt for administrators in Enhanced Privilege Protection Mode
    # Value: 2 = Prompt for credentials on secure desktop
    $securityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    Set-RegistryValue -Path $securityPath -Name "ConsentPromptBehaviorAdminInEPPMode" -Value 2 -Type DWord `
        -Description "UAC EPP: Prompt for credentials on secure desktop"
    
    # Configure type of Admin Approval Mode
    # Value: 1 = Admin Approval Mode with enhanced privilege protection
    Set-RegistryValue -Path $securityPath -Name "AdminApprovalModeType" -Value 1 -Type DWord `
        -Description "UAC: Admin Approval Mode with Enhanced Privilege Protection"
    
    Write-Success "Enhanced Privilege Protection Mode Settings gesetzt"
    Write-Warning-Custom "WICHTIG: Feature ist NOCH NICHT aktiv - wird in zukuenftigen Updates aktiviert!"
    Write-Info "Diese Settings sind 'Future-Proof' - bereit fuer kommende Windows Updates"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
