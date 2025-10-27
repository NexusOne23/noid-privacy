# ============================================================================
# SecurityBaseline-WindowsUpdate.ps1
# Windows Update GUI Settings (KEINE Policies, nur Defaults setzen!)
# ============================================================================

Set-StrictMode -Version Latest

function Set-WindowsUpdateDefaults {
    <#
    .SYNOPSIS
        Setzt Windows Update GUI-Toggles auf empfohlene Defaults (HYBRID)
    .DESCRIPTION
        HYBRID-LÖSUNG für Windows Update Settings:
        
        1. Setzt User-Preferences (UX\Settings) - funktioniert gut mit Toggles
        2. Setzt ZUSÄTZLICH Policies wo verfügbar (für Garantie)
        
        = Beste Balance zwischen Sicherheit und User-Kontrolle!
        
        Settings:
        1. Updates für andere Microsoft-Produkte -> EIN
        2. Sich auf den aktuellen Stand bringen lassen -> EIN
        3. Updates über getaktete Verbindungen -> EIN (Security First!)
        4. Benachrichtigung bei Neustart -> EIN
        5. Erhalten Sie die neuesten Updates -> EIN
        
        WICHTIG: Alle Toggles auf EIN = Maximum Security Updates!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Windows Update - Empfohlene Defaults (HYBRID)"
    
    # HYBRID APPROACH:
    # 1. Setze User Preferences (funktioniert mit Toggles)
    $wuPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    
    Set-RegistryValue -Path $wuPath -Name "AllowMUUpdateService" -Value 1 -Type DWord `
        -Description "Updates für andere MS-Produkte: EIN"
    
    Set-RegistryValue -Path $wuPath -Name "IsContinuousInnovationOptedIn" -Value 1 -Type DWord `
        -Description "Sich auf den aktuellen Stand bringen: EIN"
    
    Set-RegistryValue -Path $wuPath -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Value 1 -Type DWord `
        -Description "Updates über getaktete Verbindungen: AN (Security First!)"
    
    Set-RegistryValue -Path $wuPath -Name "RestartNotificationsAllowed2" -Value 1 -Type DWord `
        -Description "Neustart-Benachrichtigungen: EIN"
    
    Set-RegistryValue -Path $wuPath -Name "IsExpedited" -Value 1 -Type DWord `
        -Description "Neueste Updates sofort erhalten: EIN"
    
    # 2. Setze ZUSÄTZLICH Policies (für kritische Settings)
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    
    # Verhindere Insider/Preview Builds (kritisch für Stabilität!)
    Set-RegistryValue -Path $policyPath -Name "ManagePreviewBuilds" -Value 1 -Type DWord `
        -Description "Preview Builds Policy: Verwaltet"
    
    Set-RegistryValue -Path $policyPath -Name "ManagePreviewBuildsPolicyValue" -Value 0 -Type DWord `
        -Description "Preview Builds Policy: KEINE Preview Builds (garantiert!)"
    
    Write-Success "Windows Update Defaults gesetzt (HYBRID)"
    Write-Info "Konfiguration:"
    Write-Info "  [+] Updates fuer andere MS-Produkte: EIN (User kann aendern)"
    Write-Info "  [+] Sich auf aktuellen Stand bringen: EIN (User kann aendern)"
    Write-Info "  [+] Updates ueber getaktete Verbindungen: EIN (Security First!)"
    Write-Info "  [+] Neustart-Benachrichtigungen: EIN (User kann aendern)"
    Write-Info "  [+] Neueste Updates sofort: EIN (User kann aendern)"
    Write-Info "  [!] Preview Builds: AUS (Policy = GARANTIERT!)"
    Write-Host ""
    Write-Host "HYBRID-MODUS:" -ForegroundColor Cyan
    Write-Info "  [OK] User-Preferences = Toggle funktionieren!"
    Write-Info "  [OK] Policies fuer kritische Settings (Preview Builds)"
    Write-Info "  [OK] Best of Both Worlds!"
}

function Set-DeliveryOptimizationDefaults {
    <#
    .SYNOPSIS
        Setzt Delivery Optimization auf HTTP-Only (HYBRID: Policy + Config!)
    .DESCRIPTION
        HYBRID-LÖSUNG für maximale Sicherheit + User-Kontrolle:
        
        1. Setzt Policy (GARANTIERT dass Setting greift)
        2. Setzt auch User-Config (für Toggle-Funktionalität)
        
        User kann ändern durch:
        - Settings Toggle nutzen (entfernt Policy automatisch bei Änderung)
        - Oder Policy manuell entfernen via Registry
        
        = Best of Both Worlds: Garantiert SICHER + User kann ändern!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Delivery Optimization - HTTP-Only (HYBRID)"
    
    # HYBRID APPROACH:
    # 1. Setze Policy (garantiert dass es greift)
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-RegistryValue -Path $policyPath -Name "DODownloadMode" -Value 0 -Type DWord `
        -Description "Delivery Optimization Policy: HTTP-Only (garantiert!)"
    
    # 2. Setze auch User-Config (Fallback + Toggle-Support)
    $configPath = "HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config"
    Set-RegistryValue -Path $configPath -Name "DODownloadMode" -Value 0 -Type DWord `
        -Description "Delivery Optimization Config: HTTP-Only (Fallback)"
    
    Write-Success "Delivery Optimization: HTTP-Only Mode (HYBRID)"
    Write-Info "GARANTIERT: Updates kommen NUR von Microsoft-Servern (HTTP)"
    Write-Info "KEIN P2P-Sharing, KEIN LAN-Scanning"
    Write-Host ""
    Write-Host "HYBRID-MODUS:" -ForegroundColor Cyan
    Write-Info "  [OK] Policy gesetzt = GARANTIERT dass Setting greift"
    Write-Info "  [OK] Config gesetzt = Toggle-Unterstuetzung"
    Write-Host ""
    Write-Host "User kann aendern durch:" -ForegroundColor Yellow
    Write-Info "  1. In Settings Toggle aendern (entfernt Policy automatisch)"
    Write-Info "  2. Oder Policy manuell loeschen via Registry:"
    Write-Info "     Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Name DODownloadMode"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
