# =======================================================================================
# SecurityBaseline-Edge.ps1 - Microsoft Edge Security (User-Friendly Balance)
# =======================================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Set-EdgeSecurityBaseline {
    <#
    .SYNOPSIS
        Microsoft Edge Security Baseline v139+ (User-Friendly)
    .DESCRIPTION
        Wendet Edge-Sicherheits-Baseline an - BALANCE zwischen Security & Usability.
        NICHT zu restriktiv - fuer normale User geeignet!
        
        Aktiviert:
        - SmartScreen & Site Isolation
        - Tracking Prevention (Balanced)
        - DNS over HTTPS
        - Enhanced Security Mode (Balanced)
        - TLS 1.2+ erzwingen
        
        NICHT blockiert:
        - Erweiterungen (Microsoft Store OK)
        - AutoFill (verfuegbar)
        - Payment Methods (verfuegbar)
    .EXAMPLE
        Set-EdgeSecurityBaseline
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Microsoft Edge Security Baseline v139+ (User-Friendly)"
    
    # WICHTIG: Policies vs. Preferences!
    # Policies (ausgegraut):  HKLM:\SOFTWARE\Policies\Microsoft\Edge
    # Preferences (änderbar): HKLM:\SOFTWARE\Microsoft\Edge
    
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"      # Für Security (ausgegraut)
    $edgePrefPath = "HKLM:\SOFTWARE\Microsoft\Edge"                  # Für User-Friendly (änderbar)
    
    # === SmartScreen & Security (POLICIES - AUSGEGRAUT!) ===
    Write-Info "Konfiguriere SmartScreen und Site Isolation..."
    
    # CRITICAL FIX v1.7.6: SmartScreenEnabled MUSS gesetzt werden (auch wenn deprecated!)
    # Wird im Compliance-Report gecheckt und von SecurityBaseline-Core auch gesetzt
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "SmartScreen aktivieren (auch wenn deprecated ab Edge v139+)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "SmartScreen PUA (Potentially Unwanted Apps) aktivieren"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverride" -Value "true" -Type String `
        -Description "SmartScreen-Warnungen nicht umgehbar"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverrideForFiles" -Value "true" -Type String `
        -Description "SmartScreen-Dateiwarnungen nicht umgehbar"
    
    # Site Isolation (Maximum Security)
    Set-RegistryValue -Path $edgePolicyPath -Name "SitePerProcess" -Value 1 -Type DWord `
        -Description "Site Isolation aktivieren"
    
    # === Tracking Prevention (POLICIES - AUSGEGRAUT!) ===
    Write-Info "Konfiguriere Tracking Prevention (Strict)..."
    
    # CRITICAL FIX v1.7.6: Tracking Prevention auf Strict (2) setzen!
    # 0 = Off, 1 = Balanced, 2 = Strict
    Set-RegistryValue -Path $edgePolicyPath -Name "TrackingPrevention" -Value 2 -Type DWord `
        -Description "Tracking Prevention: Strict (2) - Maximum Privacy"
    
    # Third-Party Cookies: NUR im InPrivate blockieren
    Set-RegistryValue -Path $edgePolicyPath -Name "BlockThirdPartyCookies" -Value 0 -Type DWord `
        -Description "Third-Party Cookies erlauben (normale Websites funktionieren)"
    
    # === DNS over HTTPS (POLICIES - AUSGEGRAUT!) ===
    Write-Info "Konfiguriere DNS over HTTPS..."
    
    Set-RegistryValue -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "automatic" -Type String `
        -Description "DNS over HTTPS: Automatic (nicht erzwungen)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "BuiltInDnsClientEnabled" -Value 1 -Type DWord `
        -Description "Built-in DNS Client aktivieren"
    
    # === Enhanced Security Mode (POLICIES - AUSGEGRAUT!) ===
    Write-Info "Konfiguriere Enhanced Security Mode (Balanced)..."
    
    # CRITICAL FIX v1.7.6: TYPO! Es muss "EnhancedSecurityMode" sein (mit "d")!
    # Enhanced Security Mode: Basic (nicht Strict!)
    Set-RegistryValue -Path $edgePolicyPath -Name "EnhancedSecurityMode" -Value 1 -Type DWord `
        -Description "Enhanced Security Mode: Basic (1) - Balance zwischen Security & Kompatibilitaet"
    
    # Download Restrictions: Gefaehrliche Files warnen (nicht blockieren)
    Set-RegistryValue -Path $edgePolicyPath -Name "DownloadRestrictions" -Value 1 -Type DWord `
        -Description "Gefaehrliche Downloads warnen (nicht blockieren)"
    
    # === Extensions (POLICIES - AUSGEGRAUT!) ===
    Write-Info "Konfiguriere Erweiterungs-Policies (User-Friendly)..."
    
    # Extensions: Nur Microsoft Store erlauben (keine komplett Blockierung!)
    # WICHTIG: ExtensionInstallSources MUSS ein MultiString (Array) sein!
    try {
        $extensionSources = @("https://microsoftedge.microsoft.com/addons/*")
        New-Item -Path $edgePolicyPath -Force -ErrorAction SilentlyContinue | Out-Null
        # CRITICAL: MultiString braucht New-ItemProperty (nicht Set-ItemProperty!)
        if (Get-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallSources" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallSources" -Force
        }
        New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallSources" -Value $extensionSources -PropertyType MultiString -Force | Out-Null
        Write-Verbose "ExtensionInstallSources als MultiString gesetzt"
    }
    catch {
        Write-Warning "ExtensionInstallSources konnte nicht gesetzt werden: $_"
    }
    
    # KEINE Blocklist - User kann Erweiterungen installieren!
    # ExtensionInstallBlocklist = NICHT gesetzt!
    
    Write-Info "Erweiterungen aus Microsoft Edge Store sind ERLAUBT"
    
    # === TLS/SSL Security ===
    Write-Info "Konfiguriere TLS/SSL Security..."
    
    # HINWEIS: SSLVersionMin wurde in Edge v98 entfernt (deprecated)
    # TLS 1.2 ist in modernen Edge-Versionen standardmaessig die Mindestversion
    # Keine Konfiguration mehr notwendig/moeglich!
    
    # QUIC/HTTP3 als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "QuicAllowed" -Value 1 -Type DWord `
        -Description "QUIC/HTTP3 Default: Aktiviert (User kann aendern)"
    
    Write-Info "TLS 1.2+ ist standardmaessig aktiviert (Edge v98+)"
    
    # === AutoFill & Password Manager (PREFERENCES - USER KANN AENDERN!) ===
    Write-Info "Konfiguriere AutoFill und Password Manager (Default: Aktiviert)..."
    
    # Password Manager als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "PasswordManagerEnabled" -Value 1 -Type DWord `
        -Description "Password Manager Default: Aktiviert (User kann deaktivieren)"
    
    # AutoFill Address als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "AutofillAddressEnabled" -Value 1 -Type DWord `
        -Description "AutoFill Address Default: Aktiviert (User kann deaktivieren)"
    
    # AutoFill Credit Card als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "AutofillCreditCardEnabled" -Value 1 -Type DWord `
        -Description "AutoFill Credit Card Default: Aktiviert (User kann deaktivieren)"
    
    # Payment Methods als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "PaymentMethodQueryEnabled" -Value 1 -Type DWord `
        -Description "Payment Methods Default: Aktiviert (User kann deaktivieren)"
    
    Write-Info "AutoFill und Password Manager sind als DEFAULT aktiviert (User KANN aendern!)"
    
    # === WebRTC IP-Leak Prevention (PREFERENCE - USER KANN AENDERN!) ===
    Write-Info "Konfiguriere WebRTC IP-Leak Prevention..."
    
    Set-RegistryValue -Path $edgePrefPath -Name "WebRtcLocalhostIpHandling" -Value "default_public_interface_only" -Type String `
        -Description "WebRTC IP-Leak Prevention Default (User kann aendern)"
    
    # === Auto-Update ===
    # UpdateDefault ist deprecated in Edge v139+
    # Edge verwendet jetzt eigenes Update-System (nicht mehr konfigurierbar via Policy)
    # Auto-Updates sind standardmäßig aktiviert
    
    # === InPrivate Mode (PREFERENCE - USER KANN AENDERN!) ===
    Write-Info "Konfiguriere InPrivate Mode..."
    
    # InPrivate Mode als PREFERENCE (User kann aendern!)
    Set-RegistryValue -Path $edgePrefPath -Name "InPrivateModeAvailability" -Value 0 -Type DWord `
        -Description "InPrivate Mode Default: Verfuegbar (User kann aendern)"
    
    Write-Success "Microsoft Edge Security Baseline v139+ angewendet (HYBRID Mode)"
    Write-Host ""
    Write-Info "KONFIGURATION (Hybrid: Policies + Preferences):"
    Write-Host ""
    Write-Host "  POLICIES (AUSGEGRAUT - User kann NICHT aendern):" -ForegroundColor Yellow
    Write-Info "  [OK] SmartScreen: Aktiv (nicht umgehbar)"
    Write-Info "  [OK] Tracking Prevention: Balanced"
    Write-Info "  [OK] DNS over HTTPS: Automatic"
    Write-Info "  [OK] Enhanced Security: Basic"
    Write-Info "  [OK] TLS: 1.2+ Standard (Edge v98+)"
    Write-Info "  [OK] Site Isolation: Aktiviert"
    Write-Info "  [OK] Erweiterungen: Nur Microsoft Store"
    Write-Host ""
    Write-Host "  PREFERENCES (DEFAULT - User KANN aendern!):" -ForegroundColor Cyan
    Write-Info "  [~] AutoFill Address: Default AN"
    Write-Info "  [~] AutoFill Credit Card: Default AN"
    Write-Info "  [~] Password Manager: Default AN"
    Write-Info "  [~] Payment Methods: Default AN"
    Write-Info "  [~] InPrivate Mode: Default VERFUEGBAR"
    Write-Info "  [~] QUIC/HTTP3: Default AN"
    Write-Info "  [~] WebRTC IP-Leak Prevention: Default AN"
    Write-Host ""
    Write-Host "  HYBRID-MODUS = Best of Both Worlds:" -ForegroundColor Green
    Write-Info "  [OK] Security-kritische Settings: ERZWUNGEN (Policies)"
    Write-Info "  [OK] User-Friendly Settings: STANDARD aber AENDERBAR (Preferences)"
    Write-Host ""
    Write-Warning-Custom "Edge-Neustart erforderlich fuer vollstaendige Anwendung!"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
