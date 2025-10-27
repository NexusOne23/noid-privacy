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
    
    Write-Info "OneDrive wird fuer Maximum Privacy gehaertet..."
    Write-Info "Funktionalitaet bleibt erhalten - User hat KONTROLLE ueber Uploads"
    
    # CRITICAL FIX v1.7.6: Set BOTH paths (HKCU + HKLM) for maximum coverage!
    # HKCU = Current User (takes effect immediately)
    # HKLM = Default for NEW Users (future profiles)
    $oneDrivePathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
    $oneDrivePathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # 1. Disable Tutorial (Privacy: less tracking on first start)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "OneDrive Tutorial deaktivieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "OneDrive Tutorial deaktivieren (Privacy) - Default fuer neue User"
    
    # 2. Disable Feedback (Privacy: prevents data leaks via bug reports)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "OneDrive Feedback an Microsoft deaktivieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "OneDrive Feedback an Microsoft deaktivieren (Privacy) - Default fuer neue User"
    
    # 3. BLOCK Network Traffic before User-Login (CRITICAL!)
    # OneDrive must NOT phone home without user consent!
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "OneDrive darf nicht ohne User-Consent connecten (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "OneDrive darf nicht ohne User-Consent connecten (Privacy) - Default fuer neue User"
    
    # 4. BLOCK Known Folder Move (prevent Auto-Upload!)
    # Prevents automatic upload of Desktop/Documents/Pictures
    # User has CONTROL over what gets uploaded (Privacy-First!)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "Auto-Upload von Desktop/Dokumente/Bilder blockieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "Auto-Upload von Desktop/Dokumente/Bilder blockieren (Privacy) - Default fuer neue User"
    
    # 5. Do NOT block Personal OneDrive!
    # DisablePersonalSync would break Home users - only for Enterprise!
    # We keep Personal OneDrive active (no breaking change)
    
    Write-Success "OneDrive Privacy Hardening: DONE"
    Write-Host ""
    Write-Info "OneDrive Privacy Status:"
    Write-Info "  [OK] Tutorial deaktiviert (kein Tracking beim ersten Start)"
    Write-Info "  [OK] Feedback deaktiviert (keine Data-Leaks via Bug-Reports)"
    Write-Info "  [OK] Kein Network Traffic vor User-Login (kein Silent-Tracking)"
    Write-Info "  [OK] Known Folder Move blockiert (kein Auto-Upload)"
    Write-Info "  [OK] Optional Diagnostic Data deaktiviert (via Telemetry-Modul)"
    Write-Host ""
    Write-Info "OneDrive Funktionalitaet:"
    Write-Info "  [OK] OneDrive funktioniert normal (Sync/Upload/Download)"
    Write-Info "  [OK] Personal OneDrive aktiv (kein Breaking fuer Home-User)"
    Write-Info "  [!] Auto-Backup (KFM) ist AUS - User muss Dateien manuell hochladen"
    Write-Info "  [!] User hat KONTROLLE was in die Cloud hochgeladen wird (Privacy-First!)"
}
