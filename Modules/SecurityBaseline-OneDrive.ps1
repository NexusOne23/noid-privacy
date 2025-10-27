# =======================================================================================
# SecurityBaseline-OneDrive.ps1 - OneDrive Privacy Hardening
# =======================================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Set-OneDrivePrivacyHardening {
    <#
    .SYNOPSIS
        OneDrive Privacy Hardening (ohne Breaking Changes)
    .DESCRIPTION
        Haertet OneDrive fuer Maximum Privacy bei voller Funktionalitaet:
        - Deaktiviert Tutorial und Feedback (Privacy)
        - Verhindert Network Traffic vor User-Login (KRITISCH!)
        - Blockiert Known Folder Move / Auto-Upload (Privacy!)
        - Behaelt OneDrive-Funktionalitaet (User kann weiter nutzen)
        
        WICHTIG: Optional Diagnostic Data Popup wird BEREITS vom Telemetry-Modul deaktiviert!
        -> AllowTelemetry = 0 (Security Level) blockiert OneDrive-Telemetrie
        
        Best Practice October 2025: Privacy-First ohne Breaking Changes
    .NOTES
        KEINE Breaking Changes:
        - OneDrive funktioniert weiter
        - User kann manuell Dateien hochladen (Drag and Drop)
        - Personal OneDrive bleibt aktiv (kein Enterprise-Only)
        
        Breaking fuer:
        - NIEMANDEN! (Safe fuer alle User)
        
        Auto-Upload (KFM) wird blockiert:
        - Desktop/Dokumente/Bilder werden NICHT automatisch hochgeladen
        - User muss Dateien manuell in OneDrive-Ordner verschieben
        - Privacy-First: User hat KONTROLLE was hochgeladen wird
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "OneDrive Privacy Hardening"
    
    Write-Info "OneDrive wird fuer Maximum Privacy gehaertet..."
    Write-Info "Funktionalitaet bleibt erhalten - User hat KONTROLLE ueber Uploads"
    
    # CRITICAL FIX v1.7.6: Setze BEIDE Pfade (HKCU + HKLM) fuer Maximum Coverage!
    # HKCU = Aktueller User (wirkt sofort)
    # HKLM = Default fuer NEUE User (zukuenftige Profile)
    $oneDrivePathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
    $oneDrivePathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # 1. Tutorial deaktivieren (Privacy: weniger Tracking beim ersten Start)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "OneDrive Tutorial deaktivieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "OneDrive Tutorial deaktivieren (Privacy) - Default fuer neue User"
    
    # 2. Feedback deaktivieren (Privacy: verhindert Data-Leaks via Bug-Reports)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "OneDrive Feedback an Microsoft deaktivieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "OneDrive Feedback an Microsoft deaktivieren (Privacy) - Default fuer neue User"
    
    # 3. Network Traffic BLOCKIEREN vor User-Login (KRITISCH!)
    # OneDrive darf NICHT ohne User-Consent nach Hause telefonieren!
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "OneDrive darf nicht ohne User-Consent connecten (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "OneDrive darf nicht ohne User-Consent connecten (Privacy) - Default fuer neue User"
    
    # 4. Known Folder Move BLOCKIEREN (Auto-Upload verhindern!)
    # Verhindert automatisches Hochladen von Desktop/Dokumente/Bilder
    # User hat KONTROLLE was hochgeladen wird (Privacy-First!)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "Auto-Upload von Desktop/Dokumente/Bilder blockieren (Privacy)"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "Auto-Upload von Desktop/Dokumente/Bilder blockieren (Privacy) - Default fuer neue User"
    
    # 5. Personal OneDrive NICHT blockieren!
    # DisablePersonalSync wuerde Home-User brechen - nur fuer Enterprise!
    # Wir lassen Personal OneDrive aktiv (kein Breaking Change)
    
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
