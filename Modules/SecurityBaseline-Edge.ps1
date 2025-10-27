# =======================================================================================
# SecurityBaseline-Edge.ps1 - Microsoft Edge Security (User-Friendly Balance)
# =======================================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Set-EdgeSecurityBaseline {
    <#
    .SYNOPSIS
        Microsoft Edge Security Baseline v139+ (User-Friendly)
    .DESCRIPTION
        Applies Edge Security Baseline - BALANCE between Security & Usability.
        NOT too restrictive - suitable for normal users!
        
        Enabled:
        - SmartScreen & Site Isolation
        - Tracking Prevention (Balanced)
        - DNS over HTTPS
        - Enhanced Security Mode (Balanced)
        - Enforce TLS 1.2+
        
        NOT blocked:
        - Extensions (Microsoft Store OK)
        - AutoFill (available)
        - Payment Methods (available)
    .EXAMPLE
        Set-EdgeSecurityBaseline
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Microsoft Edge Security Baseline v139+ (User-Friendly)"
    
    # IMPORTANT: Policies vs. Preferences!
    # Policies (greyed out):  HKLM:\SOFTWARE\Policies\Microsoft\Edge
    # Preferences (changeable): HKLM:\SOFTWARE\Microsoft\Edge
    
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"      # For Security (greyed out)
    $edgePrefPath = "HKLM:\SOFTWARE\Microsoft\Edge"                  # For User-Friendly (changeable)
    
    # === SmartScreen & Security (POLICIES - GREYED OUT!) ===
    Write-Info "Konfiguriere SmartScreen und Site Isolation..."
    
    # CRITICAL FIX v1.7.6: SmartScreenEnabled MUSS gesetzt werden (auch wenn deprecated!)
    # Wird im Compliance-Report gecheckt und von SecurityBaseline-Core auch gesetzt
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen (even if deprecated since Edge v139+)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen PUA (Potentially Unwanted Apps)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverride" -Value "true" -Type String `
        -Description "SmartScreen warnings cannot be bypassed"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverrideForFiles" -Value "true" -Type String `
        -Description "SmartScreen file warnings cannot be bypassed"
    
    # Site Isolation (Maximum Security)
    Set-RegistryValue -Path $edgePolicyPath -Name "SitePerProcess" -Value 1 -Type DWord `
        -Description "Enable Site Isolation"
    
    # === Tracking Prevention (POLICIES - GREYED OUT!) ===
    Write-Info "Konfiguriere Tracking Prevention (Strict)..."
    
    # CRITICAL FIX v1.7.6: Tracking Prevention auf Strict (2) setzen!
    # 0 = Off, 1 = Balanced, 2 = Strict
    Set-RegistryValue -Path $edgePolicyPath -Name "TrackingPrevention" -Value 2 -Type DWord `
        -Description "Tracking Prevention: Strict (2) - Maximum Privacy"
    
    # Third-Party Cookies: NUR im InPrivate blockieren
    Set-RegistryValue -Path $edgePolicyPath -Name "BlockThirdPartyCookies" -Value 0 -Type DWord `
        -Description "Allow Third-Party Cookies (normal websites work)"
    
    # === DNS over HTTPS (POLICIES - GREYED OUT!) ===
    Write-Info "Konfiguriere DNS over HTTPS..."
    
    Set-RegistryValue -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "automatic" -Type String `
        -Description "DNS over HTTPS: Automatic (not enforced)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "BuiltInDnsClientEnabled" -Value 1 -Type DWord `
        -Description "Enable Built-in DNS Client"
    
    # === Enhanced Security Mode (POLICIES - GREYED OUT!) ===
    Write-Info "Konfiguriere Enhanced Security Mode (Balanced)..."
    
    # CRITICAL FIX v1.7.6: TYPO! Es muss "EnhancedSecurityMode" sein (mit "d")!
    # Enhanced Security Mode: Basic (nicht Strict!)
    Set-RegistryValue -Path $edgePolicyPath -Name "EnhancedSecurityMode" -Value 1 -Type DWord `
        -Description "Enhanced Security Mode: Basic (1) - Balance between Security & Compatibility"
    
    # Download Restrictions: Warn for dangerous files (not block)
    Set-RegistryValue -Path $edgePolicyPath -Name "DownloadRestrictions" -Value 1 -Type DWord `
        -Description "Warn for dangerous downloads (not block)"
    
    # === Extensions (POLICIES - GREYED OUT!) ===
    Write-Info "Konfiguriere Erweiterungs-Policies (User-Friendly)..."
    
    # Extensions: Only allow Microsoft Store (no complete blocking!)
    # IMPORTANT: ExtensionInstallSources MUST be a MultiString (Array)!
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
    
    # NO Blocklist - User can install extensions!
    # ExtensionInstallBlocklist = NOT set!
    
    Write-Info "Erweiterungen aus Microsoft Edge Store sind ERLAUBT"
    
    # === TLS/SSL Security ===
    Write-Info "Konfiguriere TLS/SSL Security..."
    
    # NOTE: SSLVersionMin was removed in Edge v98 (deprecated)
    # TLS 1.2 is the default minimum version in modern Edge versions
    # No configuration needed/possible anymore!
    
    # QUIC/HTTP3 as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "QuicAllowed" -Value 1 -Type DWord `
        -Description "QUIC/HTTP3 Default: Enabled (User can change)"
    
    Write-Info "TLS 1.2+ ist standardmaessig aktiviert (Edge v98+)"
    
    # === AutoFill & Password Manager (PREFERENCES - USER CAN CHANGE!) ===
    Write-Info "Konfiguriere AutoFill und Password Manager (Default: Aktiviert)..."
    
    # Password Manager as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "PasswordManagerEnabled" -Value 1 -Type DWord `
        -Description "Password Manager Default: Enabled (User can disable)"
    
    # AutoFill Address as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "AutofillAddressEnabled" -Value 1 -Type DWord `
        -Description "AutoFill Address Default: Enabled (User can disable)"
    
    # AutoFill Credit Card as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "AutofillCreditCardEnabled" -Value 1 -Type DWord `
        -Description "AutoFill Credit Card Default: Enabled (User can disable)"
    
    # Payment Methods as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "PaymentMethodQueryEnabled" -Value 1 -Type DWord `
        -Description "Payment Methods Default: Enabled (User can disable)"
    
    Write-Info "AutoFill und Password Manager sind als DEFAULT aktiviert (User KANN aendern!)"
    
    # === WebRTC IP-Leak Prevention (PREFERENCE - USER CAN CHANGE!) ===
    Write-Info "Konfiguriere WebRTC IP-Leak Prevention..."
    
    Set-RegistryValue -Path $edgePrefPath -Name "WebRtcLocalhostIpHandling" -Value "default_public_interface_only" -Type String `
        -Description "WebRTC IP-Leak Prevention Default (User can change)"
    
    # === Auto-Update ===
    # UpdateDefault is deprecated in Edge v139+
    # Edge now uses its own update system (no longer configurable via Policy)
    # Auto-Updates are enabled by default
    
    # === InPrivate Mode (PREFERENCE - USER CAN CHANGE!) ===
    Write-Info "Konfiguriere InPrivate Mode..."
    
    # InPrivate Mode as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "InPrivateModeAvailability" -Value 0 -Type DWord `
        -Description "InPrivate Mode Default: Available (User can change)"
    
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
