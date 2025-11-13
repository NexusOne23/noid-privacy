# ============================================================================
# SecurityBaseline-UAC.ps1
# User Account Control Enhanced Settings - Windows 11 25H2
# ============================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

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
    
    Write-Section "$(Get-LocalizedString 'UACMaximumSecurityTitle')"
    
    $securityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # Enable UAC
    Set-RegistryValue -Path $securityPath -Name "EnableLUA" -Value 1 -Type DWord `
        -Description "Enable UAC"
    
    # CRITICAL: ConsentPromptBehaviorAdmin = 5 for FULL UAC prompt (with details!)
    # Combined with PromptOnSecureDesktop = 1 → Secure Desktop + Full Prompt Size!
    # Values: 0=No prompt, 1=Prompt credentials (no secure desktop), 2=Consent (minimal prompt),
    #         5=Prompt for consent for non-Windows binaries (FULL PROMPT - shows Publisher, etc.)
    # WHY Value 5: Gives FULL-SIZE prompt with app details, STILL on Secure Desktop!
    Set-RegistryValue -Path $securityPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord `
        -Description "UAC: Prompt for consent on Secure Desktop"
    
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
    
    # ===========================
    # ADDITIONAL SECURITY SETTINGS (Microsoft Baseline 25H2)
    # ===========================
    
    # MS Security Guide: Apply UAC restrictions to local accounts on network logons
    # Prevents Pass-the-Hash attacks using local accounts
    Set-RegistryValue -Path $securityPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord `
        -Description "UAC: Prevent remote UAC bypass for local accounts (anti-PtH)"
    
    # Credential UI: Enumerate administrator accounts on elevation (MS Baseline 25H2)
    # Prevents enumeration of admin accounts on UAC prompt (security hardening)
    $credUIPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    Set-RegistryValue -Path $credUIPath -Name "EnumerateAdministrators" -Value 0 -Type DWord `
        -Description "UAC: Don't enumerate admin accounts on elevation prompt"
    
    # Interactive logon: Machine inactivity limit (15 minutes = 900 seconds)
    # Automatically locks screen after inactivity
    Set-RegistryValue -Path $securityPath -Name "InactivityTimeoutSecs" -Value 900 -Type DWord `
        -Description "Auto-lock after 15 minutes (900 sec) inactivity"
    
    # Microsoft Account Optional (MS Baseline 25H2 - Phase 3)
    # Makes Microsoft Account optional instead of required during OOBE
    Set-RegistryValue -Path $securityPath -Name "MSAOptional" -Value 1 -Type DWord `
        -Description "Microsoft Account optional (not forced in OOBE)"
    
    # Multiple Provider Router - Legacy (MS Baseline 25H2 - 100% Compliance)
    # Windows NT 4.0 legacy feature (Novell NetWare support)
    # Value 0 = Disabled (modern systems don't need this)
    # Set explicitly for documentation and compliance (even though default = 0)
    Set-RegistryValue -Path $securityPath -Name "EnableMPR" -Value 0 -Type DWord `
        -Description "Multiple Provider Router disabled (legacy - NT 4.0 feature)"
    
    # UAC: Detect application installations and prompt for elevation (MS Baseline 25H2)
    # Value: 1 = Enabled (UAC automatically detects installers and prompts)
    Set-RegistryValue -Path $securityPath -Name "EnableInstallerDetection" -Value 1 -Type DWord `
        -Description "UAC: Detect installers automatically (heuristic detection)"
    
    # UAC: Admin Approval Mode for the built-in Administrator account (MS Baseline 25H2)
    # Value: 1 = Enabled (built-in Admin account uses UAC like other admins)
    Set-RegistryValue -Path $securityPath -Name "FilterAdministratorToken" -Value 1 -Type DWord `
        -Description "UAC: Built-in Administrator account uses UAC (not full token by default)"
    
    # ===========================
    # CRITICAL FIX v1.8.3: Windows 11 25H2 NEW KEY!
    # ===========================
    # ConsentPromptBehaviorEnhancedAdmin: NEW in Windows 11 25H2!
    # Controls UAC behavior in Enhanced Admin Approval Mode
    # MUST be set to 5 (same as ConsentPromptBehaviorAdmin) to ensure:
    # - Prompts stay on Secure Desktop (anti-malware protection)
    # - FULL-SIZE prompt with app details (not minimal!)
    # IMPORTANT: ConsentPromptBehaviorEnhancedAdmin for Administrator Protection Mode
    # In TypeOfAdminApprovalMode = 2, prompt is compact by design (more secure!)
    Set-RegistryValue -Path $securityPath -Name "ConsentPromptBehaviorEnhancedAdmin" -Value 2 -Type DWord `
        -Description "UAC Enhanced: Administrator Protection Mode (Windows 11 25H2)"
    
    # TypeOfAdminApprovalMode: Controls Admin Approval Mode type
    # Value: 2 = Enhanced Admin Approval Mode (Windows 11 25H2)
    Set-RegistryValue -Path $securityPath -Name "TypeOfAdminApprovalMode" -Value 2 -Type DWord `
        -Description "UAC: Enhanced Admin Approval Mode (Windows 11 25H2)"
    
    Write-Success "$(Get-LocalizedString 'UACMaximumSet')"
    Write-Info "  - EnableInstallerDetection: UAC detects installers automatically"
    Write-Info "  - FilterAdministratorToken: Built-in Admin account uses UAC"
    Write-Info "$(Get-LocalizedString 'UACSliderPosition')"
    Write-Info "$(Get-LocalizedString 'UACEveryActionRequires')"
    Write-Warning "$(Get-LocalizedString 'UACMostSecureSetting')"
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
    
    Write-Warning-Custom "$(Get-LocalizedString 'UACEPPUpcomingFeature')"
    Write-Info "$(Get-LocalizedString 'UACEPPAnnouncedBaseline')"
    Write-Info "$(Get-LocalizedString 'UACEPPNotYetActive')"
    Write-Info "More info: https://techcommunity.microsoft.com/blog/windows-itpro-blog/administrator-protection-on-windows-11/4303482"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'UACEPPSettingAnyway')"
    
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
    
    Write-Success "$(Get-LocalizedString 'UACEPPSettingsSet')"
    Write-Warning-Custom "$(Get-LocalizedString 'UACEPPNotActiveYet')"
    Write-Info "$(Get-LocalizedString 'UACEPPFutureProof')"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
