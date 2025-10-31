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
    
    Write-Section "$(Get-LocalizedString 'EdgeBaselineTitle')"
    
    # IMPORTANT: Policies vs. Preferences!
    # Policies (greyed out):  HKLM:\SOFTWARE\Policies\Microsoft\Edge
    # Preferences (changeable): HKLM:\SOFTWARE\Microsoft\Edge
    
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"      # For Security (greyed out)
    $edgePrefPath = "HKLM:\SOFTWARE\Microsoft\Edge"                  # For User-Friendly (changeable)
    
    # === SmartScreen & Security (POLICIES - GREYED OUT!) ===
    Write-Info "$(Get-LocalizedString 'EdgeSmartScreenConfig')"
    
    # CRITICAL FIX v1.7.6: SmartScreenEnabled MUST be set (even if deprecated!)
    # Is checked in Compliance-Report and also set by SecurityBaseline-Core
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen (even if deprecated since Edge v139+)"
    
    # IMPORTANT: SmartScreenPuaEnabled controls "Block downloads" checkbox in Windows Security GUI
    # NOTE: Edge browser MUST be restarted for this to show in Windows Security GUI!
    # This is separate from Defender PUA "Block apps" checkbox (configured in Core module)
    
    # CRITICAL: Set in HKLM (Policy)
    Set-RegistryValue -Path $edgePolicyPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen PUA (Blocks downloads of potentially unwanted apps)"
    
    # CRITICAL FIX v1.7.13: Windows Security GUI checks HKCU, not HKLM!
    # Must set in CURRENT USER in BOTH paths for checkbox to appear in Windows Security GUI
    $edgeUserPath = "HKCU:\SOFTWARE\Microsoft\Edge"
    Set-RegistryValue -Path $edgeUserPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen PUA for current user (Windows Security GUI)"
    
    # CRITICAL FIX v1.7.13: Also set in HKCU Policy path (required for GUI checkbox!)
    # BOTH SmartScreenEnabled AND SmartScreenPuaEnabled needed in HKCU for Windows Security GUI!
    $edgeUserPolicyPath = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    Set-RegistryValue -Path $edgeUserPolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen for current user - Policy path (Windows Security GUI)"
    Set-RegistryValue -Path $edgeUserPolicyPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Enable SmartScreen PUA for current user - Policy path (Windows Security GUI)"
    
    # CRITICAL FIX v1.7.13: Set for ALL loaded user profiles (HKEY_USERS)
    # This ensures all logged-in users see the checkbox in Windows Security
    try {
        $loadedProfiles = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | 
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d\-]+$' }
        
        foreach ($userProfile in $loadedProfiles) {
            # Set in both paths for each user
            $userEdgePath = "Registry::HKEY_USERS\$($userProfile.PSChildName)\SOFTWARE\Microsoft\Edge"
            $userEdgePolicyPath = "Registry::HKEY_USERS\$($userProfile.PSChildName)\SOFTWARE\Policies\Microsoft\Edge"
            
            if (-not (Test-Path $userEdgePath)) {
                New-Item -Path $userEdgePath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (-not (Test-Path $userEdgePolicyPath)) {
                New-Item -Path $userEdgePolicyPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            Set-ItemProperty -Path $userEdgePath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $userEdgePolicyPath -Name "SmartScreenEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $userEdgePolicyPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
        Write-Verbose "SmartScreenPuaEnabled set for $($loadedProfiles.Count) loaded user profile(s)"
    }
    catch {
        Write-Verbose "Could not set SmartScreenPuaEnabled for all users: $_"
    }
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverride" -Value "true" -Type String `
        -Description "SmartScreen warnings cannot be bypassed"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "PreventSmartScreenPromptOverrideForFiles" -Value "true" -Type String `
        -Description "SmartScreen file warnings cannot be bypassed"
    
    # Site Isolation (Maximum Security)
    Set-RegistryValue -Path $edgePolicyPath -Name "SitePerProcess" -Value 1 -Type DWord `
        -Description "Enable Site Isolation"
    
    # === Tracking Prevention (POLICIES - GREYED OUT!) ===
    Write-Info "$(Get-LocalizedString 'EdgeTrackingConfig')"
    
    # CRITICAL FIX v1.7.6: Set Tracking Prevention to Strict (2)!
    # 0 = Off, 1 = Balanced, 2 = Strict
    Set-RegistryValue -Path $edgePolicyPath -Name "TrackingPrevention" -Value 2 -Type DWord `
        -Description "Tracking Prevention: Strict (2) - Maximum Privacy"
    
    # Third-Party Cookies: Block ONLY in InPrivate
    Set-RegistryValue -Path $edgePolicyPath -Name "BlockThirdPartyCookies" -Value 0 -Type DWord `
        -Description "Allow Third-Party Cookies (normal websites work)"
    
    # === DNS over HTTPS (POLICIES - GREYED OUT!) ===
    Write-Info "$(Get-LocalizedString 'EdgeDNSConfig')"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "automatic" -Type String `
        -Description "DNS over HTTPS: Automatic (not enforced)"
    
    Set-RegistryValue -Path $edgePolicyPath -Name "BuiltInDnsClientEnabled" -Value 1 -Type DWord `
        -Description "Enable Built-in DNS Client"
    
    # === Enhanced Security Mode (POLICIES - GREYED OUT!) ===
    Write-Info "$(Get-LocalizedString 'EdgeEnhancedSecurityConfig')"
    
    # CRITICAL FIX v1.7.6: TYPO! It must be "EnhancedSecurityMode" (with "d")!
    # Enhanced Security Mode: Basic (not Strict!)
    Set-RegistryValue -Path $edgePolicyPath -Name "EnhancedSecurityMode" -Value 1 -Type DWord `
        -Description "Enhanced Security Mode: Basic (1) - Balance between Security & Compatibility"
    
    # Download Restrictions: Warn for dangerous files (not block)
    Set-RegistryValue -Path $edgePolicyPath -Name "DownloadRestrictions" -Value 1 -Type DWord `
        -Description "Warn for dangerous downloads (not block)"
    
    # === Extensions (POLICIES - GREYED OUT!) ===
    Write-Info "$(Get-LocalizedString 'EdgeExtensionsConfig')"
    
    # Extensions: Only allow Microsoft Store (no complete blocking!)
    # IMPORTANT: ExtensionInstallSources MUST be a MultiString (Array)!
    try {
        $extensionSources = @("https://microsoftedge.microsoft.com/addons/*")
        New-Item -Path $edgePolicyPath -Force -ErrorAction SilentlyContinue | Out-Null
        # CRITICAL: MultiString needs New-ItemProperty (not Set-ItemProperty!)
        # Safe property check - no error records created
        $item = Get-ItemProperty -Path $edgePolicyPath -ErrorAction SilentlyContinue
        if ($item -and ($item.PSObject.Properties.Name -contains "ExtensionInstallSources")) {
            Remove-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallSources" -Force
        }
        New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallSources" -Value $extensionSources -PropertyType MultiString -Force | Out-Null
        Write-Verbose "ExtensionInstallSources set as MultiString"
    }
    catch {
        Write-Warning "ExtensionInstallSources could not be set: $_"
    }
    
    # NO Blocklist - User can install extensions!
    # ExtensionInstallBlocklist = NOT set!
    
    Write-Info "$(Get-LocalizedString 'EdgeExtensionsAllowed')"
    
    # === TLS/SSL Security ===
    Write-Info "$(Get-LocalizedString 'EdgeTLSConfig')"
    
    # NOTE: SSLVersionMin was removed in Edge v98 (deprecated)
    # TLS 1.2 is the default minimum version in modern Edge versions
    # No configuration needed/possible anymore!
    
    # QUIC/HTTP3 as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "QuicAllowed" -Value 1 -Type DWord `
        -Description "QUIC/HTTP3 Default: Enabled (User can change)"
    
    Write-Info "$(Get-LocalizedString 'EdgeTLSDefault')"
    
    # === AutoFill & Password Manager (PREFERENCES - USER CAN CHANGE!) ===
    Write-Info "$(Get-LocalizedString 'EdgeAutoFillConfig')"
    
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
    
    Write-Info "$(Get-LocalizedString 'EdgeAutoFillDefault')"
    
    # === WebRTC IP-Leak Prevention (PREFERENCE - USER CAN CHANGE!) ===
    Write-Info "$(Get-LocalizedString 'EdgeWebRTCConfig')"
    
    Set-RegistryValue -Path $edgePrefPath -Name "WebRtcLocalhostIpHandling" -Value "default_public_interface_only" -Type String `
        -Description "WebRTC IP-Leak Prevention Default (User can change)"
    
    # === Auto-Update ===
    # UpdateDefault is deprecated in Edge v139+
    # Edge now uses its own update system (no longer configurable via Policy)
    # Auto-Updates are enabled by default
    
    # === InPrivate Mode (PREFERENCE - USER CAN CHANGE!) ===
    Write-Info "$(Get-LocalizedString 'EdgeInPrivateConfig')"
    
    # InPrivate Mode as PREFERENCE (User can change!)
    Set-RegistryValue -Path $edgePrefPath -Name "InPrivateModeAvailability" -Value 0 -Type DWord `
        -Description "InPrivate Mode Default: Available (User can change)"
    
    Write-Success "$(Get-LocalizedString 'EdgeBaselineApplied')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'EdgeConfiguration')"
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'EdgePoliciesGreyed')" -ForegroundColor Yellow
    Write-Info "$(Get-LocalizedString 'EdgeSmartScreenActive')"
    Write-Info "$(Get-LocalizedString 'EdgeTrackingBalanced')"
    Write-Info "$(Get-LocalizedString 'EdgeDNSAutomatic')"
    Write-Info "$(Get-LocalizedString 'EdgeSecurityBasic')"
    Write-Info "$(Get-LocalizedString 'EdgeTLSStandard')"
    Write-Info "$(Get-LocalizedString 'EdgeSiteIsolation')"
    Write-Info "$(Get-LocalizedString 'EdgeExtensionsMSOnly')"
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'EdgePreferencesChangeable')" -ForegroundColor Cyan
    Write-Info "$(Get-LocalizedString 'EdgeAutoFillAddress')"
    Write-Info "$(Get-LocalizedString 'EdgeAutoFillCard')"
    Write-Info "$(Get-LocalizedString 'EdgePasswordManager')"
    Write-Info "$(Get-LocalizedString 'EdgePaymentMethods')"
    Write-Info "$(Get-LocalizedString 'EdgeInPrivateAvailable')"
    Write-Info "$(Get-LocalizedString 'EdgeQUIC')"
    Write-Info "$(Get-LocalizedString 'EdgeWebRTCDefault')"
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'EdgeHybridMode')" -ForegroundColor Green
    Write-Info "$(Get-LocalizedString 'EdgeSecurityEnforced')"
    Write-Info "$(Get-LocalizedString 'EdgeUserFriendly')"
    Write-Host ""
    Write-Warning-Custom "$(Get-LocalizedString 'EdgeRestartRequired')"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
