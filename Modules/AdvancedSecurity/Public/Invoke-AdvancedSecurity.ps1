function Invoke-AdvancedSecurity {
    <#
    .SYNOPSIS
        Apply Advanced Security hardening based on selected profile
    
    .DESCRIPTION
        Applies advanced security hardening settings beyond Microsoft Security Baseline.
        
        Features 3 profiles:
        - Balanced: Safe defaults for home users and workstations
        - Enterprise: Conservative approach with domain-safety checks
        - Maximum: Maximum hardening for air-gapped/high-security environments
        
        Features implemented (v2.2.0):
        - RDP NLA enforcement + optional complete disable
        - WDigest credential protection
        - Administrative shares disable (domain-aware)
        - Risky firewall ports closure (LLMNR, NetBIOS, UPnP/SSDP)
        - Risky network services stop
        - Legacy TLS 1.0/1.1 disable
        - WPAD auto-discovery disable
        - PowerShell v2 removal
    
    .PARAMETER SecurityProfile
        Security profile to apply:
        - Balanced: Safe for home users and workstations (default)
        - Enterprise: Safe for corporate environments
        - Maximum: Maximum hardening for air-gapped systems
    
    .PARAMETER DisableRDP
        Completely disable Remote Desktop Protocol (bypasses interactive prompt for Home profile, AirGapped always disables)
    
    .PARAMETER Force
        Force operations that are normally skipped (e.g., admin shares on domain-joined systems)
    
    .PARAMETER WhatIf
        Show what would be changed without actually applying changes
    
    .PARAMETER SkipBackup
        Skip backup creation (NOT RECOMMENDED!)
    
    .PARAMETER DryRun
        Preview changes without applying them (alias for WhatIf)
    
    .EXAMPLE
        Invoke-AdvancedSecurity -SecurityProfile Balanced
        Applies safe hardening for home users
    
    .EXAMPLE
        Invoke-AdvancedSecurity -SecurityProfile Enterprise -WhatIf
        Preview changes for enterprise environment
    
    .EXAMPLE
        Invoke-AdvancedSecurity -SecurityProfile Maximum -DisableRDP -Force
        Maximum hardening with RDP disable for air-gapped system
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Balanced', 'Enterprise', 'Maximum')]
        [string]$SecurityProfile = 'Balanced',
        
        [Parameter(Mandatory = $false)]
        [switch]$DisableRDP,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup
    )
    
    try {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  ADVANCED SECURITY MODULE" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host "ERROR: Administrator rights required!" -ForegroundColor Red
            Write-Host "Please run this script as Administrator." -ForegroundColor Yellow
            Write-Host ""
            return [PSCustomObject]@{
                Success      = $false
                ErrorMessage = "Administrator rights required"
            }
        }
        
        # Detect Domain membership EARLY for better recommendations
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain
        
        # Profile Selection - NonInteractive or Interactive
        if (-not $PSBoundParameters.ContainsKey('SecurityProfile')) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $SecurityProfile = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "securityProfile" -Default "Balanced"
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Security Profile" -Value $SecurityProfile
            }
            else {
                # Interactive mode
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  SECURITY PROFILE SELECTION" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                
                # Show domain status if applicable
                if ($isDomainJoined) {
                    Write-Host "SYSTEM STATUS: Domain-joined" -ForegroundColor Yellow
                    Write-Host "Domain: $($computerSystem.Domain)" -ForegroundColor Gray
                    Write-Host ""
                }
                
                Write-Host "Choose your security profile:" -ForegroundColor White
                Write-Host ""
                Write-Host "  [1] Balanced" -ForegroundColor $(if (-not $isDomainJoined) { "Cyan" } else { "White" })
                Write-Host "      - For: Home users, standalone workstations" -ForegroundColor Gray
                Write-Host "      - All security features enabled" -ForegroundColor Gray
                Write-Host "      - Domain-aware admin shares (asks on domain systems)" -ForegroundColor Gray
                if (-not $isDomainJoined) {
                    Write-Host "      (Recommended for your system)" -ForegroundColor Cyan
                }
                Write-Host ""
                Write-Host "  [2] Enterprise" -ForegroundColor $(if ($isDomainJoined) { "Cyan" } else { "White" })
                Write-Host "      - For: Corporate/managed environments" -ForegroundColor Gray
                Write-Host "      - Keeps admin shares on domain (for IT management)" -ForegroundColor Gray
                Write-Host "      - Safe for business networks" -ForegroundColor Gray
                if ($isDomainJoined) {
                    Write-Host "      (Recommended for your domain system)" -ForegroundColor Cyan
                }
                Write-Host ""
                Write-Host "  [3] Maximum" -ForegroundColor White
                Write-Host "      - For: High-security environments" -ForegroundColor Gray
                Write-Host "      - Maximum hardening, no compromises" -ForegroundColor Gray
                Write-Host "      - RDP always disabled, Shields Up enabled" -ForegroundColor Gray
                Write-Host ""
                
                $defaultChoice = if ($isDomainJoined) { '2' } else { '1' }
                
                do {
                    $profileChoice = Read-Host "Select profile [1-3] (default: $defaultChoice)"
                    if ([string]::IsNullOrWhiteSpace($profileChoice)) { $profileChoice = $defaultChoice }
                    
                    if ($profileChoice -notin @('1', '2', '3')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter 1, 2, or 3." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($profileChoice -notin @('1', '2', '3'))
                
                switch ($profileChoice) {
                    '2' { $SecurityProfile = 'Enterprise'; Write-Host ""; Write-Host "  Selected: Enterprise" -ForegroundColor Green }
                    '3' { $SecurityProfile = 'Maximum'; Write-Host ""; Write-Host "  Selected: Maximum" -ForegroundColor Green }
                    default { $SecurityProfile = 'Balanced'; Write-Host ""; Write-Host "  Selected: Balanced" -ForegroundColor Cyan }
                }
                Write-Log -Level DEBUG -Message "User selected AdvancedSecurity profile: $SecurityProfile" -Module "AdvancedSecurity"
                Write-Host ""
            }
        }
        
        Write-Host "Profile: $SecurityProfile" -ForegroundColor White
        Write-Host ""
        
        # Display profile info
        switch ($SecurityProfile) {
            'Balanced' {
                Write-Host "For: Home users, workstations" -ForegroundColor White
                Write-Host "  - RDP disable recommended (asks user, default: disable)" -ForegroundColor Gray
                Write-Host "  - UPnP/SSDP block recommended (asks user, default: block)" -ForegroundColor Gray
                Write-Host "  - WDigest, Admin Shares (domain-aware), Legacy TLS, PSv2" -ForegroundColor Gray
            }
            'Enterprise' {
                Write-Host "For: Corporate environments" -ForegroundColor White
                Write-Host "  - RDP hardening only (no disable), UPnP blocked" -ForegroundColor Gray
                Write-Host "  - Admin Shares kept on domain (for IT management)" -ForegroundColor Gray
                Write-Host "  - WDigest, LLMNR/NetBIOS, Legacy TLS, PSv2" -ForegroundColor Gray
            }
            'Maximum' {
                Write-Host "For: Air-gapped, high-security systems" -ForegroundColor White
                Write-Host "  - RDP always disabled (no remote access)" -ForegroundColor Gray
                Write-Host "  - Admin Shares forced, UPnP blocked, all protocols disabled" -ForegroundColor Gray
                Write-Host "  - Firewall Shields Up: Block ALL incoming on Public network" -ForegroundColor Gray
                Write-Host "  - WDigest, LLMNR/NetBIOS, Legacy TLS, PSv2" -ForegroundColor Gray
            }
        }
        Write-Host ""
        
        # WARNING PROMPT: Inform about breaking changes
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  IMPORTANT NOTICES" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "This module will apply the following changes:" -ForegroundColor White
        Write-Host ""
        Write-Host "  Security Hardening:" -ForegroundColor Green
        Write-Host "  + RDP hardening (NLA + SSL/TLS enforcement)" -ForegroundColor Gray
        Write-Host "  + WDigest protection (credential security)" -ForegroundColor Gray
        
        # Profile-specific protocol blocking info
        if ($SecurityProfile -eq 'Balanced') {
            Write-Host "  + Risky protocols: LLMNR, NetBIOS blocked | UPnP/SSDP (asks user)" -ForegroundColor Gray
        }
        else {
            Write-Host "  + Risky protocols blocked (LLMNR, NetBIOS, UPnP/SSDP)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "  Potential Breaking Changes:" -ForegroundColor Red
        Write-Host "  ! PowerShell v2 removal (REBOOT REQUIRED after completion)" -ForegroundColor Yellow
        Write-Host "  ! Legacy TLS 1.0/1.1 disabled (old devices may fail)" -ForegroundColor Yellow
        
        # Profile-specific UPnP warning
        if ($SecurityProfile -eq 'Balanced') {
            Write-Host "  ! UPnP/SSDP may be blocked (you will be asked for DLNA compatibility)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  ! UPnP/SSDP blocked (DLNA media streaming will not work)" -ForegroundColor Yellow
        }
        
        Write-Host "  ! NetBIOS blocked (\\HOSTNAME\ requires DNS or .local suffix)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Devices that will still work:" -ForegroundColor Cyan
        Write-Host "  + Network printers (via IP or vendor software)" -ForegroundColor Gray
        Write-Host "  + NAS devices (via \\IP\ or manual mapping)" -ForegroundColor Gray
        Write-Host "  + Smart home devices (modern apps use mDNS/Cloud)" -ForegroundColor Gray
        Write-Host "  + Streaming services (Netflix, YouTube, Spotify, etc.)" -ForegroundColor Gray
        Write-Host ""
        
        # Continue confirmation - auto-confirm in NonInteractive mode
        if (-not (Test-NonInteractiveMode)) {
            do {
                $continueChoice = Read-Host "Continue with hardening? [Y/N] (default: Y)"
                if ([string]::IsNullOrWhiteSpace($continueChoice)) { $continueChoice = "Y" }
                $continueChoice = $continueChoice.ToUpper()
                
                if ($continueChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($continueChoice -notin @('Y', 'N'))
            
            if ($continueChoice -eq 'N') {
                Write-Host ""
                Write-Host "Hardening cancelled by user." -ForegroundColor Yellow
                Write-Host ""
                Write-Log -Level WARNING -Message "User cancelled AdvancedSecurity hardening at confirmation prompt" -Module "AdvancedSecurity"
                return [PSCustomObject]@{
                    Success      = $false
                    ErrorMessage = "Cancelled by user"
                }
            }
        }
        
        Write-Host ""
        Write-Host "Proceeding with security hardening..." -ForegroundColor Green
        Write-Host ""
        
        # Maximum: RDP is ALWAYS disabled (no prompt - air-gapped means no network!)
        if (-not $PSBoundParameters.ContainsKey('DisableRDP') -and $SecurityProfile -eq 'Maximum') {
            $DisableRDP = $true
            Write-Log -Level INFO -Message "Profile 'Maximum': RDP will be completely disabled automatically" -Module "AdvancedSecurity"
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "  REMOTE DESKTOP (RDP)" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  RDP will be COMPLETELY DISABLED (Air-gapped system)" -ForegroundColor Red
            Write-Host "  - No remote access on offline systems" -ForegroundColor Gray
            Write-Host "  - Hardening applied before disable" -ForegroundColor Gray
            Write-Host ""
        }
        
        # RDP Complete Disable - NonInteractive or Interactive (Home profile only for interactive)
        # NOTE: RDP is ALWAYS hardened (NLA + SSL/TLS), this prompt is only for complete disable
        # NonInteractive: ALWAYS read config value (respects user choice in any profile)
        # Interactive: Only prompt for Home profile (Enterprise/AirGapped have fixed behavior)
        if (-not $PSBoundParameters.ContainsKey('DisableRDP')) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - ALWAYS read config value (even for Enterprise)
                # This respects explicit user choice in config.json
                $configDisableRDP = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableRDP" -Default ($SecurityProfile -eq 'Balanced')
                $DisableRDP = $configDisableRDP
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "RDP" -Value $(if ($DisableRDP) { "Disabled" } else { "Hardened only" })
            }
            elseif ($SecurityProfile -eq 'Balanced') {
                # Interactive mode
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  REMOTE DESKTOP (RDP) CONFIGURATION" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "RDP is a common target for ransomware and cyber attacks." -ForegroundColor White
                Write-Host ""
                Write-Host "Do you want to COMPLETELY DISABLE Remote Desktop (until you manually re-enable it in Settings)?" -ForegroundColor White
                Write-Host ""
                Write-Host "  [Y] YES - Completely disable RDP (Recommended for security)" -ForegroundColor Cyan
                Write-Host "      - Maximum security - no RDP attack surface" -ForegroundColor Gray
                Write-Host "      - Recommended for home users who don't use remote access" -ForegroundColor Gray
                Write-Host "      - Can be re-enabled later if needed" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [N] NO - Keep RDP hardened and enabled (For remote access)" -ForegroundColor White
                Write-Host "      - RDP remains usable with strong security" -ForegroundColor Gray
                Write-Host "      - Network Level Authentication + SSL/TLS enforced" -ForegroundColor Gray
                Write-Host "      - Useful if you need remote desktop access" -ForegroundColor Gray
                Write-Host ""
                
                do {
                    $rdpChoice = Read-Host "Disable RDP completely? [Y/N] (default: Y)"
                    if ([string]::IsNullOrWhiteSpace($rdpChoice)) { $rdpChoice = "Y" }
                    $rdpChoice = $rdpChoice.ToUpper()
                    
                    if ($rdpChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($rdpChoice -notin @('Y', 'N'))
                
                if ($rdpChoice -eq 'N') {
                    $DisableRDP = $false
                    Write-Host ""
                    Write-Host "  RDP will be HARDENED and kept enabled" -ForegroundColor Cyan
                    Write-Log -Level INFO -Message "User decision: RDP will be hardened and kept enabled" -Module "AdvancedSecurity"
                }
                else {
                    $DisableRDP = $true
                    Write-Host ""
                    Write-Host "  RDP will be HARDENED and then DISABLED (you can re-enable it later in Settings)" -ForegroundColor Green
                    Write-Log -Level INFO -Message "User decision: RDP will be hardened then completely disabled" -Module "AdvancedSecurity"
                }
                Write-Host ""
            }
        }
        
        # Admin Shares Force (only on domain-joined systems with Home profile) - NonInteractive or Interactive
        # Enterprise profile automatically keeps admin shares on domain (no prompt)
        if (-not $PSBoundParameters.ContainsKey('Force') -and $isDomainJoined -and $SecurityProfile -eq 'Balanced') {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $Force = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "forceAdminShares" -Default $false
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Admin Shares on domain" -Value $(if ($Force) { "Disabled (forced)" } else { "Kept" })
            }
            else {
                # Interactive mode
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  ADMIN SHARES CONFIGURATION" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "WARNING: This system is DOMAIN-JOINED!" -ForegroundColor Red
                Write-Host ""
                Write-Host "Domain: $($computerSystem.Domain)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Admin Shares (C$, ADMIN$, IPC$) are often used by IT management tools." -ForegroundColor White
                Write-Host ""
                Write-Host "Do you want to DISABLE admin shares anyway?" -ForegroundColor White
                Write-Host ""
                Write-Host "  [N] NO - Keep admin shares (Recommended for domain)" -ForegroundColor Cyan
                Write-Host "      - IT can still manage this computer remotely" -ForegroundColor Gray
                Write-Host "      - SCCM, PDQ Deploy, PowerShell Remoting work" -ForegroundColor Gray
                Write-Host "      - Other security features still applied" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Disable admin shares anyway" -ForegroundColor White
                Write-Host "      - Maximum security but may break management tools" -ForegroundColor Gray
                Write-Host "      - IT cannot access C$, ADMIN$ remotely" -ForegroundColor Gray
                Write-Host "      - May require manual intervention from IT" -ForegroundColor Gray
                Write-Host ""
                
                do {
                    $adminShareChoice = Read-Host "Disable admin shares on domain system? [Y/N] (default: N)"
                    if ([string]::IsNullOrWhiteSpace($adminShareChoice)) { $adminShareChoice = "N" }
                    $adminShareChoice = $adminShareChoice.ToUpper()
                    
                    if ($adminShareChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($adminShareChoice -notin @('Y', 'N'))
                
                if ($adminShareChoice -eq 'Y') {
                    $Force = $true
                    Write-Host ""
                    Write-Host "  Admin Shares will be DISABLED (may break IT tools)" -ForegroundColor Red
                    Write-Log -Level INFO -Message "User decision: Admin shares will be DISABLED on domain system" -Module "AdvancedSecurity"
                }
                else {
                    $Force = $false
                    Write-Host ""
                    Write-Host "  Admin Shares will be KEPT (safe for domain)" -ForegroundColor Cyan
                    Write-Log -Level INFO -Message "User decision: Admin shares will be KEPT on domain system" -Module "AdvancedSecurity"
                }
                Write-Host ""
            }
        }
        
        # UPnP/SSDP Configuration - NonInteractive or Interactive (Home profile only for interactive)
        # NonInteractive: ALWAYS read config value (respects user choice in any profile)
        # Interactive: Only prompt for Home profile (Enterprise/AirGapped always block)
        $DisableUPnP = $true  # Default for all profiles
        
        if (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - ALWAYS read config value (even for Enterprise/AirGapped)
            # This respects explicit user choice in config.json
            $DisableUPnP = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableUPnP" -Default $true
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "UPnP/SSDP" -Value $(if ($DisableUPnP) { "Blocked" } else { "Allowed" })
        }
        elseif ($SecurityProfile -eq 'Balanced') {
            # Interactive mode
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "  UPnP/SSDP CONFIGURATION" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "UPnP (Universal Plug and Play) is used by some devices for auto-discovery." -ForegroundColor White
            Write-Host ""
            Write-Host "SECURITY RISK:" -ForegroundColor Red
            Write-Host "  - Port forwarding vulnerabilities (NAT-PMP attacks)" -ForegroundColor Gray
            Write-Host "  - DDoS amplification attacks" -ForegroundColor Gray
            Write-Host "  - Network enumeration by attackers" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT BREAKS:" -ForegroundColor Yellow
            Write-Host "  ! DLNA Media Streaming (legacy local network discovery)" -ForegroundColor Gray
            Write-Host "  ! Windows Media Player to TV/receiver" -ForegroundColor Gray
            Write-Host "  ! Some gaming console auto-discovery features" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT STILL WORKS:" -ForegroundColor Cyan
            Write-Host "  + Network printers (use mDNS, not UPnP)" -ForegroundColor Gray
            Write-Host "  + Media streaming apps (Netflix, YouTube, Spotify, etc.)" -ForegroundColor Gray
            Write-Host "  + Modern media servers (use app-based access, not DLNA)" -ForegroundColor Gray
            Write-Host "  + Smart Home apps (Hue, Google, Alexa use mDNS/Cloud)" -ForegroundColor Gray
            Write-Host "  + Manual IP configuration for any device" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to BLOCK UPnP/SSDP for security?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [Y] YES - Block UPnP/SSDP (Recommended for security)" -ForegroundColor Cyan
            Write-Host "      - Prevents port forwarding attacks" -ForegroundColor Gray
            Write-Host "      - Blocks DDoS amplification" -ForegroundColor Gray
            Write-Host "      - DLNA streaming will not work (use modern apps instead)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [N] NO - Keep UPnP/SSDP enabled" -ForegroundColor White
            Write-Host "      - DLNA streaming works" -ForegroundColor Gray
            Write-Host "      - Gaming console auto-discovery works" -ForegroundColor Gray
            Write-Host "      - Accepts security risk" -ForegroundColor Gray
            Write-Host ""
            
            do {
                $upnpChoice = Read-Host "Block UPnP/SSDP? [Y/N] (default: Y)"
                if ([string]::IsNullOrWhiteSpace($upnpChoice)) { $upnpChoice = "Y" }
                $upnpChoice = $upnpChoice.ToUpper()
                
                if ($upnpChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($upnpChoice -notin @('Y', 'N'))
            
            if ($upnpChoice -eq 'N') {
                $DisableUPnP = $false
                Write-Host ""
                Write-Host "  UPnP/SSDP will be KEPT enabled (DLNA works)" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "User decision: UPnP/SSDP will be KEPT enabled" -Module "AdvancedSecurity"
            }
            else {
                $DisableUPnP = $true
                Write-Host ""
                Write-Host "  UPnP/SSDP will be BLOCKED (security hardening)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: UPnP/SSDP will be BLOCKED" -Module "AdvancedSecurity"
            }
            Write-Host ""
        }

        # Wireless Display Configuration - Optional complete disable
        # Default for ALL profiles: Block receiving + Require PIN (always applied)
        # Optional: Complete disable (user choice like UPnP)
        $DisableWirelessDisplayCompletely = $false  # Default: only harden, allow sending
        
        if (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - use config value
            $DisableWirelessDisplayCompletely = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableWirelessDisplay" -Default $false
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Wireless Display" -Value $(if ($DisableWirelessDisplayCompletely) { "Completely Disabled" } else { "Hardened (sending allowed)" })
        }
        else {
            # Interactive mode
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "  WIRELESS DISPLAY (MIRACAST) SECURITY" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Wireless Display allows screen mirroring to TVs/projectors." -ForegroundColor White
            Write-Host ""
            Write-Host "DEFAULT HARDENING (always applied):" -ForegroundColor Cyan
            Write-Host "  + Block receiving projections (PC can't be used as display)" -ForegroundColor Gray
            Write-Host "  + Require PIN for all pairing (prevents rogue connections)" -ForegroundColor Gray
            Write-Host "  + Sending to displays STILL WORKS (presentations, TV mirroring)" -ForegroundColor Green
            Write-Host ""
            Write-Host "SECURITY RISK if not completely disabled:" -ForegroundColor Red
            Write-Host "  - Attacker in network can set up fake display to capture your screen" -ForegroundColor Gray
            Write-Host "  - Man-in-the-middle attacks on Miracast traffic (WPS PIN cracking)" -ForegroundColor Gray
            Write-Host "  - mDNS spoofing for rogue receiver discovery" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT BREAKS if completely disabled:" -ForegroundColor Yellow
            Write-Host "  ! Cannot mirror screen to TV/projector via Miracast" -ForegroundColor Gray
            Write-Host "  ! Windows + K shortcut won't find wireless displays" -ForegroundColor Gray
            Write-Host "  ! (HDMI/USB-C cables still work)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to COMPLETELY DISABLE Wireless Display?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [Y] YES - Complete disable (Maximum security)" -ForegroundColor Cyan
            Write-Host "      - All Miracast functionality blocked" -ForegroundColor Gray
            Write-Host "      - Ports 7236/7250 blocked" -ForegroundColor Gray
            Write-Host "      - Use HDMI/USB-C for presentations" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [N] NO - Keep hardened only (Default, Recommended)" -ForegroundColor Green
            Write-Host "      - Can still send to TVs/projectors" -ForegroundColor Gray
            Write-Host "      - PC cannot receive/be misused as display" -ForegroundColor Gray
            Write-Host "      - PIN always required" -ForegroundColor Gray
            Write-Host ""
            
            do {
                $wirelessChoice = Read-Host "Completely disable Wireless Display? [Y/N] (default: N)"
                if ([string]::IsNullOrWhiteSpace($wirelessChoice)) { $wirelessChoice = "N" }
                $wirelessChoice = $wirelessChoice.ToUpper()
                
                if ($wirelessChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($wirelessChoice -notin @('Y', 'N'))
            
            if ($wirelessChoice -eq 'Y') {
                $DisableWirelessDisplayCompletely = $true
                Write-Host ""
                Write-Host "  Wireless Display will be COMPLETELY DISABLED" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "User decision: Wireless Display completely disabled" -Module "AdvancedSecurity"
            }
            else {
                $DisableWirelessDisplayCompletely = $false
                Write-Host ""
                Write-Host "  Wireless Display will be HARDENED (sending still works)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: Wireless Display hardened only" -Module "AdvancedSecurity"
            }
            Write-Host ""
        }
        
        # Discovery Protocols (WS-Discovery + mDNS) Configuration - Maximum profile only
        # This controls OS-level mDNS resolver and WS-Discovery service+firewall block.
        $DisableDiscoveryProtocolsCompletely = $false

        if (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - use config value; effective only for Maximum profile
            $DisableDiscoveryProtocolsCompletely = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableDiscoveryProtocols" -Default ($SecurityProfile -eq 'Maximum')
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Discovery Protocols (WS-Discovery/mDNS, Maximum only)" -Value $(if ($DisableDiscoveryProtocolsCompletely) { "Completely Disabled" } else { "Default (Windows behavior)" })
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            # Interactive prompt only for Maximum profile
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "  DISCOVERY PROTOCOLS (WS-Discovery + mDNS)" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "WS-Discovery and mDNS are used for automatic device discovery (printers, TVs, scanners)." -ForegroundColor White
            Write-Host "On high-security / air-gapped systems, these discovery protocols should be COMPLETELY DISABLED." -ForegroundColor White
            Write-Host "" 
            Write-Host "SECURITY RISK:" -ForegroundColor Red
            Write-Host "  - Network mapping and lateral movement via WS-Discovery" -ForegroundColor Gray
            Write-Host "  - mDNS spoofing and fake devices on the local network" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "WHAT BREAKS IF DISABLED:" -ForegroundColor Yellow
            Write-Host "  ! Automatic discovery of network printers/TVs/scanners" -ForegroundColor Gray
            Write-Host "  ! Some legacy media streaming / casting workflows" -ForegroundColor Gray
            Write-Host "  ! Miracast display discovery (even if Miracast allowed above)" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "WHAT STILL WORKS:" -ForegroundColor Cyan
            Write-Host "  + Direct access via IP address (\\192.168.x.x or http://IP)" -ForegroundColor Gray
            Write-Host "  + Modern cloud-based apps (e.g. vendor apps, browser UIs)" -ForegroundColor Gray
            Write-Host "  + All outbound web traffic (browsing, streaming, etc.)" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "Do you want to COMPLETELY DISABLE WS-Discovery and mDNS on this system?" -ForegroundColor White
            Write-Host "" 
            Write-Host "  [Y] YES - Maximum security (Recommended for air-gapped / Maximum profile)" -ForegroundColor Cyan
            Write-Host "      - Disables OS mDNS resolver" -ForegroundColor Gray
            Write-Host "      - Disables WS-Discovery services" -ForegroundColor Gray
            Write-Host "      - Blocks WS-Discovery and mDNS ports in the firewall" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "  [N] NO - Keep default discovery behavior" -ForegroundColor White
            Write-Host "      - Device discovery continues to work" -ForegroundColor Gray
            Write-Host "      - Higher attack surface (not recommended for Maximum profile)" -ForegroundColor Gray
            Write-Host "" 

            do {
                $discoveryChoice = Read-Host "Completely disable WS-Discovery and mDNS? [Y/N] (default: N)"
                if ([string]::IsNullOrWhiteSpace($discoveryChoice)) { $discoveryChoice = "N" }
                $discoveryChoice = $discoveryChoice.ToUpper()
                
                if ($discoveryChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($discoveryChoice -notin @('Y', 'N'))

            if ($discoveryChoice -eq 'Y') {
                $DisableDiscoveryProtocolsCompletely = $true
                Write-Host "" 
                Write-Host "  Discovery protocols (WS-Discovery + mDNS) will be COMPLETELY DISABLED" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "User decision: Discovery protocols (WS-Discovery/mDNS) completely disabled on Maximum profile" -Module "AdvancedSecurity"
            }
            else {
                $DisableDiscoveryProtocolsCompletely = $false
                Write-Host "" 
                Write-Host "  Discovery protocols will be KEPT enabled (device discovery works)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: Discovery protocols (WS-Discovery/mDNS) kept enabled on Maximum profile" -Module "AdvancedSecurity"
            }
            Write-Host "" 
        }
        
        # IPv6 Disable Configuration - Maximum profile only (mitm6 attack mitigation)
        $DisableIPv6Completely = $false
        
        if (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - use config value; effective only for Maximum profile
            $DisableIPv6Completely = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableIPv6" -Default $false
            if ($DisableIPv6Completely) {
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "IPv6 (mitm6 protection)" -Value "Completely Disabled"
            }
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            # Interactive prompt only for Maximum profile
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "  IPv6 SECURITY (mitm6 Attack Mitigation)" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Windows sends DHCPv6 requests even when IPv6 is not configured." -ForegroundColor White
            Write-Host "Attackers can exploit this to perform DNS takeover and credential theft." -ForegroundColor White
            Write-Host "" 
            Write-Host "ATTACK SCENARIO (mitm6):" -ForegroundColor Red
            Write-Host "  1. Attacker responds to DHCPv6 requests as fake server" -ForegroundColor Gray
            Write-Host "  2. Attacker becomes DNS server for victim" -ForegroundColor Gray
            Write-Host "  3. Combined with WPAD -> NTLM credentials stolen" -ForegroundColor Gray
            Write-Host "  4. -> Domain compromise possible!" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "NOTE: WPAD is already disabled by this framework." -ForegroundColor Cyan
            Write-Host "      Disabling IPv6 provides additional defense-in-depth." -ForegroundColor Cyan
            Write-Host "" 
            Write-Host "WHAT BREAKS IF IPv6 DISABLED:" -ForegroundColor Yellow
            Write-Host "  ! Exchange Server communication (if using IPv6)" -ForegroundColor Gray
            Write-Host "  ! Some Active Directory features" -ForegroundColor Gray
            Write-Host "  ! IPv6-only services and websites" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "RECOMMENDED FOR:" -ForegroundColor Cyan
            Write-Host "  + Air-gapped systems" -ForegroundColor Gray
            Write-Host "  + Standalone workstations (no Exchange/AD)" -ForegroundColor Gray
            Write-Host "  + High-security environments" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "Do you want to COMPLETELY DISABLE IPv6?" -ForegroundColor White
            Write-Host "" 
            Write-Host "  [Y] YES - Disable IPv6 (Maximum security)" -ForegroundColor Cyan
            Write-Host "      - Prevents mitm6 attacks completely" -ForegroundColor Gray
            Write-Host "      - REBOOT REQUIRED" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "  [N] NO - Keep IPv6 enabled (Default)" -ForegroundColor Green
            Write-Host "      - WPAD already disabled (partial mitigation)" -ForegroundColor Gray
            Write-Host "      - IPv6 functionality preserved" -ForegroundColor Gray
            Write-Host "" 
            
            do {
                $ipv6Choice = Read-Host "Completely disable IPv6? [Y/N] (default: N)"
                if ([string]::IsNullOrWhiteSpace($ipv6Choice)) { $ipv6Choice = "N" }
                $ipv6Choice = $ipv6Choice.ToUpper()
                
                if ($ipv6Choice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($ipv6Choice -notin @('Y', 'N'))
            
            if ($ipv6Choice -eq 'Y') {
                $DisableIPv6Completely = $true
                Write-Host "" 
                Write-Host "  IPv6 will be COMPLETELY DISABLED (REBOOT REQUIRED)" -ForegroundColor Yellow
                Write-Log -Level INFO -Message "User decision: IPv6 completely disabled (mitm6 mitigation)" -Module "AdvancedSecurity"
            }
            else {
                $DisableIPv6Completely = $false
                Write-Host "" 
                Write-Host "  IPv6 will be KEPT enabled (WPAD already disabled for partial protection)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: IPv6 kept enabled (WPAD disabled provides partial mitm6 protection)" -Module "AdvancedSecurity"
            }
            Write-Host "" 
        }
        
        # Handle DryRun parameter (convert to WhatIf for ShouldProcess)
        if ($DryRun) {
            $WhatIfPreference = $true
        }
        
        # WhatIf mode
        if ($PSCmdlet.ShouldProcess("Advanced Security", "Apply $SecurityProfile hardening")) {
            
            # PHASE 1: BACKUP
            Write-Host "[1/4] BACKUP - Creating restore point..." -ForegroundColor Cyan
            
            if (-not $SkipBackup) {
                Write-Log -Level INFO -Message "Initializing backup system..." -Module "AdvancedSecurity"
                $backupInit = Initialize-BackupSystem
                
                if (-not $backupInit) {
                    Write-Log -Level ERROR -Message "Failed to initialize backup system!" -Module "AdvancedSecurity"
                    Write-Host "  ERROR: Backup system initialization failed!" -ForegroundColor Red
                    Write-Host "  Use -SkipBackup to proceed without backup (NOT RECOMMENDED)" -ForegroundColor Yellow
                    Write-Host ""
                    return [PSCustomObject]@{
                        Success      = $false
                        ErrorMessage = "Backup system initialization failed"
                    }
                }
                
                $backupResult = Backup-AdvancedSecuritySettings
                
                if ($backupResult) {
                    # Register backup in session manifest
                    Complete-ModuleBackup -ItemsBackedUp $backupResult -Status "Success"
                    
                    Write-Log -Level SUCCESS -Message "Backup completed: $backupResult items" -Module "AdvancedSecurity"
                    Write-Host "  Backup completed ($backupResult items)" -ForegroundColor Green
                }
                else {
                    Write-Log -Level WARNING -Message "Backup may have failed - proceeding anyway" -Module "AdvancedSecurity"
                    Write-Host "  WARNING: Backup may have issues" -ForegroundColor Yellow
                }
            }
            else {
                Write-Log -Level WARNING -Message "Backup SKIPPED by user request!" -Module "AdvancedSecurity"
                Write-Host "  Skipped (SkipBackup flag)" -ForegroundColor Yellow
            }
            Write-Host ""
            
            # PHASE 2: APPLY
            Write-Host "[2/4] APPLY - Applying security hardening..." -ForegroundColor Cyan
            Write-Host ""
            
            $appliedFeatures = @()
            $failedFeatures = @()
            
            # Feature 1: RDP Hardening
            Write-Host "  RDP Security Hardening..." -ForegroundColor White -NoNewline
            
            try {
                $rdpDisable = $false
                
                if ($SecurityProfile -eq 'Maximum' -and $DisableRDP) {
                    $rdpDisable = $true
                }
                elseif ($DisableRDP) {
                    Write-Log -Level INFO -Message "User explicitly requested full RDP disable in profile '$SecurityProfile' - applying complete disable with Force override" -Module "AdvancedSecurity"
                    $rdpDisable = $true
                }
                
                $rdpResult = Enable-RdpNLA -DisableRDP:$rdpDisable -Force:$Force
                
                if ($rdpResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "RDP Hardening"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "RDP Hardening"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "RDP Hardening"
                Write-Log -Level ERROR -Message "RDP hardening failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 2: WDigest Protection
            Write-Host "  WDigest Protection..." -ForegroundColor White -NoNewline
            
            try {
                $wdigestResult = Set-WDigestProtection
                
                if ($wdigestResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "WDigest Protection"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "WDigest Protection"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "WDigest Protection"
                Write-Log -Level ERROR -Message "WDigest protection failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 3: Administrative Shares
            Write-Host "  Admin Shares Disable..." -ForegroundColor White -NoNewline
            
            try {
                # Enterprise profile: Auto-skip on domain (for IT management)
                if ($SecurityProfile -eq 'Enterprise' -and $isDomainJoined -and -not $Force) {
                    Write-Host " SKIPPED (Enterprise + Domain)" -ForegroundColor Yellow
                    Write-Log -Level INFO -Message "Admin shares kept on domain (Enterprise profile)" -Module "AdvancedSecurity"
                }
                else {
                    $adminSharesForce = $false
                    
                    if ($SecurityProfile -eq 'Maximum') {
                        $adminSharesForce = $true
                    }
                    elseif ($Force) {
                        $adminSharesForce = $true
                    }
                    
                    $adminSharesResult = Disable-AdminShares -Force:$adminSharesForce
                    
                    if ($adminSharesResult) {
                        Write-Host " OK" -ForegroundColor Green
                        $appliedFeatures += "Admin Shares Disable"
                    }
                    else {
                        Write-Host " SKIPPED" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Admin Shares Disable"
                Write-Log -Level ERROR -Message "Admin shares disable failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 4: Risky Firewall Ports
            Write-Host "  Risky Ports Hardening..." -ForegroundColor White -NoNewline
            
            try {
                # Pass SkipUPnP if user chose to keep UPnP enabled
                $riskyPortsResult = Disable-RiskyPorts -SkipUPnP:(-not $DisableUPnP)
                
                if ($riskyPortsResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Risky Firewall Ports"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Risky Firewall Ports"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Risky Firewall Ports"
                Write-Log -Level ERROR -Message "Risky ports closure failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 5: Risky Network Services
            Write-Host "  Risky Services Stop..." -ForegroundColor White -NoNewline
            
            try {
                $riskyServicesResult = Stop-RiskyServices
                
                if ($riskyServicesResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Risky Network Services"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Risky Network Services"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Risky Network Services"
                Write-Log -Level ERROR -Message "Risky services stop failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 6: WPAD Disable
            Write-Host "  WPAD Disable..." -ForegroundColor White -NoNewline
            
            try {
                $wpadResult = Disable-WPAD
                
                if ($wpadResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "WPAD Disable"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "WPAD Disable"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "WPAD Disable"
                Write-Log -Level ERROR -Message "WPAD disable failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 7: Legacy TLS Disable
            Write-Host "  Legacy TLS 1.0/1.1 Disable..." -ForegroundColor White -NoNewline
            
            try {
                $tlsResult = Disable-LegacyTLS
                
                if ($tlsResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Legacy TLS Disable"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Legacy TLS Disable"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Legacy TLS Disable"
                Write-Log -Level ERROR -Message "Legacy TLS disable failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 8: PowerShell v2 Removal
            Write-Host "  PowerShell v2 Removal..." -ForegroundColor White -NoNewline
            
            $psv2Changed = $false
            try {
                $psv2Result = Remove-PowerShellV2
                
                if ($psv2Result -and $psv2Result.Success) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "PowerShell v2 Removal"
                    if ($psv2Result.Changed) {
                        $psv2Changed = $true
                    }
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "PowerShell v2 Removal"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "PowerShell v2 Removal"
                Write-Log -Level ERROR -Message "PowerShell v2 removal failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 9: Finger Protocol
            Write-Host "  Finger Protocol Block..." -ForegroundColor White -NoNewline
            
            try {
                $fingerResult = Block-FingerProtocol -DryRun:$DryRun
                
                if ($fingerResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Finger Protocol Block"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Finger Protocol Block"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Finger Protocol Block"
                Write-Log -Level ERROR -Message "Finger protocol block failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 10: SRP Rules (CVE-2025-9491)
            Write-Host "  SRP .lnk Protection (CVE-2025-9491)..." -ForegroundColor White -NoNewline
            
            try {
                $srpResult = Set-SRPRules -DryRun:$DryRun
                
                if ($srpResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "SRP .lnk Protection (CVE-2025-9491)"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "SRP .lnk Protection"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "SRP .lnk Protection"
                Write-Log -Level ERROR -Message "SRP configuration failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 11: Windows Update
            Write-Host "  Windows Update Config..." -ForegroundColor White -NoNewline
            
            try {
                $wuResult = Set-WindowsUpdate -DryRun:$DryRun
                
                if ($wuResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Windows Update (3 GUI settings)"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Windows Update"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Windows Update"
                Write-Log -Level ERROR -Message "Windows Update configuration failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }
            
            # Feature 12: Wireless Display Security
            Write-Host "  Wireless Display Security..." -ForegroundColor White -NoNewline
            
            try {
                $wirelessDisplayResult = Set-WirelessDisplaySecurity -DisableCompletely:$DisableWirelessDisplayCompletely
                
                if ($wirelessDisplayResult) {
                    if ($DisableWirelessDisplayCompletely) {
                        Write-Host " OK (Fully Disabled)" -ForegroundColor Green
                        $appliedFeatures += "Wireless Display (Fully Disabled)"
                    }
                    else {
                        Write-Host " OK (Hardened)" -ForegroundColor Green
                        $appliedFeatures += "Wireless Display (Hardened)"
                    }
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Wireless Display Security"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Wireless Display Security"
                Write-Log -Level ERROR -Message "Wireless Display security failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }

            # Feature 13: Discovery Protocols (WS-Discovery + mDNS) - Maximum only
            if ($SecurityProfile -eq 'Maximum') {
                Write-Host "  Discovery Protocols (WS-Discovery + mDNS)..." -ForegroundColor White -NoNewline

                try {
                    if ($DisableDiscoveryProtocolsCompletely) {
                        $discoveryResult = Set-DiscoveryProtocolsSecurity -DisableCompletely

                        if ($discoveryResult) {
                            Write-Host " OK (Disabled)" -ForegroundColor Green
                            $appliedFeatures += "Discovery Protocols (WS-Discovery + mDNS Disabled)"
                        }
                        else {
                            Write-Host " FAILED" -ForegroundColor Red
                            $failedFeatures += "Discovery Protocols (WS-Discovery + mDNS)"
                        }
                    }
                    else {
                        Write-Host " SKIPPED" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Discovery Protocols (WS-Discovery + mDNS)"
                    Write-Log -Level ERROR -Message "Discovery protocol security failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
                }
            }
            
            # Feature 14: Firewall Shields Up (Maximum only)
            # Blocks ALL incoming connections on Public network, including allowed apps
            if ($SecurityProfile -eq 'Maximum') {
                Write-Host "  Firewall Shields Up (Public)..." -ForegroundColor White -NoNewline
                
                try {
                    $shieldsUpResult = Set-FirewallShieldsUp -Enable
                    
                    if ($shieldsUpResult) {
                        Write-Host " OK" -ForegroundColor Green
                        $appliedFeatures += "Firewall Shields Up (Block ALL incoming on Public)"
                    }
                    else {
                        Write-Host " FAILED" -ForegroundColor Red
                        $failedFeatures += "Firewall Shields Up"
                    }
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Firewall Shields Up"
                    Write-Log -Level ERROR -Message "Firewall Shields Up failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
                }
            }
            
            # Feature 15: IPv6 Disable (Maximum only, optional)
            # Prevents mitm6 attacks (DHCPv6 spoofing → DNS takeover → NTLM relay)
            if ($SecurityProfile -eq 'Maximum' -and $DisableIPv6Completely) {
                Write-Host "  IPv6 Disable (mitm6 mitigation)..." -ForegroundColor White -NoNewline
                
                try {
                    $ipv6Result = Set-IPv6Security -DisableCompletely
                    
                    if ($ipv6Result) {
                        Write-Host " OK (REBOOT REQUIRED)" -ForegroundColor Green
                        $appliedFeatures += "IPv6 Disabled (mitm6 attack mitigation)"
                    }
                    else {
                        Write-Host " FAILED" -ForegroundColor Red
                        $failedFeatures += "IPv6 Disable"
                    }
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "IPv6 Disable"
                    Write-Log -Level ERROR -Message "IPv6 disable failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
                }
            }
            
            Write-Host ""
            
            # PHASE 3: VERIFY
            Write-Host "[3/4] VERIFY - Checking compliance..." -ForegroundColor Cyan
            Write-Host ""
            
            if ($appliedFeatures.Count -gt 0) {
                try {
                    $verifyResult = Test-AdvancedSecurity
                    
                    # Test-AdvancedSecurity now outputs full table + returns structured object
                    # No need to print summary here - it's already shown above
                    if ($verifyResult -and $verifyResult.Compliance -lt 100) {
                        # Log details to file for troubleshooting
                        Write-Log -Level WARNING -Message "Advanced Security Compliance: $($verifyResult.CompliantCount)/$($verifyResult.TotalChecks) passed ($($verifyResult.Compliance)%)" -Module "AdvancedSecurity"
                        
                        if ($verifyResult.Results) {
                            foreach ($test in $verifyResult.Results) {
                                if (-not $test.Compliant) {
                                    Write-Log -Level WARNING -Message "  [NON-COMPLIANT] $($test.Feature): $($test.Status) - $($test.Details)" -Module "AdvancedSecurity"
                                }
                            }
                        }
                        
                        Write-Host ""
                        Write-Host "  Note: $($verifyResult.TotalChecks - $verifyResult.CompliantCount) check(s) non-compliant" -ForegroundColor Yellow
                        Write-Host "  This may require reboot or additional configuration" -ForegroundColor Gray
                    }
                    elseif ($verifyResult) {
                        Write-Log -Level SUCCESS -Message "Advanced Security Compliance: 100% passed" -Module "AdvancedSecurity"
                    }
                }
                catch {
                    Write-Host "  Verification skipped (error occurred)" -ForegroundColor Gray
                }
            }
            else {
                Write-Host "  Skipped (no features applied)" -ForegroundColor Gray
            }
            Write-Host ""
            
            # PHASE 4: COMPLETE
            Write-Host "[4/4] COMPLETE - Advanced security finished!" -ForegroundColor Green
            Write-Host ""
            
            Write-Host "Profile:       $SecurityProfile" -ForegroundColor White
            Write-Host "Features:      $($appliedFeatures.Count)/15 applied" -ForegroundColor $(if ($failedFeatures.Count -eq 0) { 'Green' } else { 'Yellow' })
            
            if ($failedFeatures.Count -gt 0) {
                Write-Host "Failed:        $($failedFeatures.Count)" -ForegroundColor Red
            }
            
            Write-Host ""
            if ($psv2Changed) {
                Write-Host "REBOOT REQUIRED for some changes (Admin Shares, PowerShell v2)" -ForegroundColor Yellow
            }
            else {
                Write-Host "REBOOT REQUIRED for some changes (Admin Shares)" -ForegroundColor Yellow
            }
            Write-Host ""
            
            Write-Log -Level SUCCESS -Message "Advanced Security hardening completed: $($appliedFeatures.Count) features applied" -Module "AdvancedSecurity"
            
            # GUI parsing marker for settings count (50 advanced settings incl. Wireless Display + Discovery Protocols + IPv6)
            Write-Log -Level SUCCESS -Message "Applied 50 settings" -Module "AdvancedSecurity"
            
            # Return structured result object
            $hasFailures = $failedFeatures.Count -gt 0
            return [PSCustomObject]@{
                Success         = -not $hasFailures
                SecurityProfile = $SecurityProfile
                FeaturesApplied = $appliedFeatures
                FeaturesFailed  = $failedFeatures
                TotalFeatures   = $appliedFeatures.Count + $failedFeatures.Count
                Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                RebootRequired  = $true
            }
        }
        else {
            Write-Host "WhatIf mode - no changes applied" -ForegroundColor Yellow
            Write-Host ""
            return [PSCustomObject]@{
                Success         = $true
                SecurityProfile = $SecurityProfile
                Mode            = "WhatIf"
                Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Advanced Security hardening failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        Write-Host ""
        Write-Host "ERROR: Hardening failed!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Gray
        Write-Host ""
        
        # Return structured error object
        return [PSCustomObject]@{
            Success         = $false
            SecurityProfile = $SecurityProfile
            ErrorMessage    = $_.Exception.Message
            Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}
