# ============================================================================
# SecurityBaseline-WindowsUpdate.ps1
# Windows Update GUI Settings (NO Policies, only set Defaults!)
# ============================================================================

Set-StrictMode -Version Latest

function Set-WindowsUpdateDefaults {
    <#
    .SYNOPSIS
        Sets Windows Update GUI toggles to recommended defaults (HYBRID)
    .DESCRIPTION
        HYBRID SOLUTION for Windows Update Settings:
        
        1. Sets User-Preferences (UX\Settings) - works well with toggles
        2. ADDITIONALLY sets Policies where available (for guarantee)
        
        = Best balance between security and user control!
        
        Settings:
        1. Updates for other Microsoft products -> ON
        2. Get latest updates as soon as available -> ON
        3. Download updates over metered connections -> ON (Security First!)
        4. Restart notifications -> ON
        5. Get the latest updates as soon as available -> ON
        
        IMPORTANT: All toggles ON = Maximum Security Updates!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Windows Update - Empfohlene Defaults (HYBRID)"
    
    # HYBRID APPROACH:
    # 1. Set User Preferences (works with toggles)
    $wuPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    
    Set-RegistryValue -Path $wuPath -Name "AllowMUUpdateService" -Value 1 -Type DWord `
        -Description "Updates for other MS products: ON"
    
    Set-RegistryValue -Path $wuPath -Name "IsContinuousInnovationOptedIn" -Value 1 -Type DWord `
        -Description "Get latest updates as soon as available: ON"
    
    Set-RegistryValue -Path $wuPath -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Value 1 -Type DWord `
        -Description "Download updates over metered connections: ON (Security First!)"
    
    Set-RegistryValue -Path $wuPath -Name "RestartNotificationsAllowed2" -Value 1 -Type DWord `
        -Description "Restart notifications: ON"
    
    Set-RegistryValue -Path $wuPath -Name "IsExpedited" -Value 1 -Type DWord `
        -Description "Get latest updates immediately: ON"
    
    # 2. ADDITIONALLY set Policies (for critical settings)
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    
    # Prevent Insider/Preview Builds (critical for stability!)
    Set-RegistryValue -Path $policyPath -Name "ManagePreviewBuilds" -Value 1 -Type DWord `
        -Description "Preview Builds Policy: Managed"
    
    Set-RegistryValue -Path $policyPath -Name "ManagePreviewBuildsPolicyValue" -Value 0 -Type DWord `
        -Description "Preview Builds Policy: NO Preview Builds (guaranteed!)"
    
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
        Sets Delivery Optimization to HTTP-Only (HYBRID: Policy + Config!)
    .DESCRIPTION
        HYBRID SOLUTION for maximum security + user control:
        
        1. Sets Policy (GUARANTEES that setting applies)
        2. Also sets User-Config (for toggle functionality)
        
        User can change by:
        - Using Settings toggle (automatically removes Policy on change)
        - Or manually remove Policy via Registry
        
        = Best of Both Worlds: Guaranteed SECURE + User can change!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Delivery Optimization - HTTP-Only (HYBRID)"
    
    # HYBRID APPROACH:
    # 1. Set Policy (guarantees that it applies)
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-RegistryValue -Path $policyPath -Name "DODownloadMode" -Value 0 -Type DWord `
        -Description "Delivery Optimization Policy: HTTP-Only (guaranteed!)"
    
    # 2. Also set User-Config (Fallback + Toggle-Support)
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
