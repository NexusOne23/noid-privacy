# =======================================================================================
# SecurityBaseline-OneDrive.ps1 - OneDrive Privacy Hardening
# =======================================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Set-OneDrivePrivacyHardening {
    <#
    .SYNOPSIS
        OneDrive Privacy Hardening (without Breaking Changes)
    .DESCRIPTION
        Hardens OneDrive for maximum privacy with full functionality:
        - Disables Tutorial and Feedback (Privacy)
        - Prevents Network Traffic before User-Login (CRITICAL!)
        - Blocks Known Folder Move / Auto-Upload (Privacy!)
        - Keeps OneDrive functionality (User can continue using)
        
        IMPORTANT: Optional Diagnostic Data Popup is ALREADY disabled by Telemetry module!
        -> AllowTelemetry = 0 (Security Level) blocks OneDrive telemetry
        
        Best Practice October 2025: Privacy-First without Breaking Changes
    .NOTES
        NO Breaking Changes:
        - OneDrive continues to work
        - User can manually upload files (Drag and Drop)
        - Personal OneDrive stays active (not Enterprise-Only)
        
        Breaking for:
        - NOBODY! (Safe for all users)
        
        Auto-Upload (KFM) is blocked:
        - Desktop/Documents/Pictures will NOT be automatically uploaded
        - User must manually move files to OneDrive folder
        - Privacy-First: User has CONTROL over what gets uploaded
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "OneDrive Privacy Hardening"
    
    Write-Info "$(Get-LocalizedString 'OneDriveHardeningStart')"
    Write-Info "$(Get-LocalizedString 'OneDriveFunctionalityPreserved')"
    
    # CRITICAL FIX v1.7.6: Set BOTH paths (HKCU + HKLM) for maximum coverage!
    # HKCU = Current User (takes effect immediately)
    # HKLM = Default for NEW Users (future profiles)
    $oneDrivePathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
    $oneDrivePathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # 1. Disable Tutorial (Privacy: less tracking on first start)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveTutorialDisabled')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveTutorialDisabledDefault')"
    
    # 2. Disable Feedback (Privacy: prevents data leaks via bug reports)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveFeedbackDisabled')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveFeedbackDisabledDefault')"
    
    # 3. BLOCK Network Traffic before User-Login (CRITICAL!)
    # OneDrive must NOT phone home without user consent!
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveNoConnectWithoutConsent')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveNoConnectWithoutConsentDefault')"
    
    # 4. BLOCK Known Folder Move (prevent Auto-Upload!)
    # Prevents automatic upload of Desktop/Documents/Pictures
    # User has CONTROL over what gets uploaded (Privacy-First!)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveBlockAutoUpload')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveBlockAutoUploadDefault')"
    
    # 5. Do NOT block Personal OneDrive!
    # DisablePersonalSync would break Home users - only for Enterprise!
    # We keep Personal OneDrive active (no breaking change)
    
    Write-Success "$(Get-LocalizedString 'OneDriveHardeningDone')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'OneDrivePrivacyStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveTutorialStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveFeedbackStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveNetworkStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveKFMStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveDiagnosticStatus')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'OneDriveFunctionality')"
    Write-Info "$(Get-LocalizedString 'OneDriveWorksNormally')"
    Write-Info "$(Get-LocalizedString 'OneDrivePersonalActive')"
    Write-Info "$(Get-LocalizedString 'OneDriveKFMOff')"
    Write-Info "$(Get-LocalizedString 'OneDriveUserControl')"
}
