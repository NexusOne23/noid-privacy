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

        Features implemented (v2.2.6, 13 components per Docs/FEATURES.md Module 7):
        - RDP NLA enforcement + optional complete disable
        - Administrative shares disable (domain-aware)
        - Risky firewall ports closure (LLMNR, NetBIOS, UPnP/SSDP)
        - NetBIOS adapter hardening (per-adapter TCP/IP NetBIOS disable)
        - Risky network services stop
        - Legacy TLS 1.0/1.1 disable
        - WPAD auto-discovery disable
        - Finger protocol block
        - Stable Windows Update configuration
        - Wireless Display/Miracast security
        - Discovery protocols security (WS-Discovery, mDNS; Maximum profile)
        - Firewall Shields Up (Maximum profile)
        - IPv6 component disable (0xFF, Maximum profile, optional)

    .PARAMETER SecurityProfile
        Security profile to apply:
        - Balanced: Safe for home users and workstations (default)
        - Enterprise: Safe for corporate environments
        - Maximum: Maximum hardening for air-gapped systems

    .PARAMETER DisableRDP
        Completely disable Remote Desktop Protocol (bypasses the Balanced-profile prompt; Maximum disables on RDP-host-capable editions)

    .PARAMETER Force
        Force operations that are normally skipped (e.g., admin shares on domain-joined systems)

    .PARAMETER WhatIf
        Show what would be changed without actually applying changes

    .PARAMETER SkipFirewallLayer
        Explicitly skips all Windows Firewall changes made by this module. A
        small third-party-controller detection list only prefills the prompt;
        it never silently decides for the user.

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
        [bool]$SkipFirewallLayer = $false
    )

    try {
        Write-NoIDDetail ""

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
        $computerSystem = Get-AdvancedSecurityComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain
        # Capture the validated configuration before Backup. Apply and Verify
        # use these same objects even if the JSON files change during the run.
        $windowsUpdateConfiguration = Get-AdvancedSecurityConfig -Name WindowsUpdate
        $applicability = Get-AdvancedSecurityApplicability
        $rdpHostSupported = [bool]$applicability.RdpHostSupported
        $managedPolicySupported = [bool]$applicability.ManagedPolicySupported
        $wirelessDisplaySupported = [bool]$applicability.WirelessDisplaySupported
        Write-Log -Level INFO -Message "Edition applicability: $($applicability.EditionFamily); RDP host=$rdpHostSupported; managed policy CSPs=$managedPolicySupported; Wireless Display policies=$wirelessDisplaySupported" -Module 'AdvancedSecurity'
        # Home applies the firewall layer as local rules. A configured local-rule
        # merge ban (SecurityBaseline sets it for the Public profile and runs
        # first) makes that layer unverifiable, so it must be skipped there.
        $localRuleBlockedProfiles = @(Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $managedPolicySupported)
        $localRuleBlockedText = $localRuleBlockedProfiles -join ', '

        # Profile Selection - NonInteractive or Interactive
        if (-not $PSBoundParameters.ContainsKey('SecurityProfile')) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $SecurityProfile = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "securityProfile" -Required
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Security Profile" -Value $SecurityProfile
            }
            else {
                # Interactive mode
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  SECURITY PROFILE SELECTION" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""

                # Show domain status if applicable
                if ($isDomainJoined) {
                    Write-Host "SYSTEM STATUS: Domain-joined" -ForegroundColor Cyan
                    Write-Host "Domain: $($computerSystem.Domain)" -ForegroundColor Gray
                    Write-Host ""
                }

                Write-Host "Choose your security profile:" -ForegroundColor White
                Write-Host ""
                if (-not $isDomainJoined) {
                    Write-Host "  [1] Balanced (Recommended)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [1] Balanced" -ForegroundColor Cyan
                }
                Write-Host "      - For: Home users, standalone workstations" -ForegroundColor Gray
                Write-Host "      - All edition-applicable default security features enabled" -ForegroundColor Gray
                Write-Host "      - Domain-aware admin shares (asks on domain systems)" -ForegroundColor Gray
                Write-Host ""
                if ($isDomainJoined) {
                    Write-Host "  [2] Enterprise (Recommended)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [2] Enterprise" -ForegroundColor Cyan
                }
                Write-Host "      - For: Corporate/managed environments" -ForegroundColor Gray
                Write-Host "      - Keeps admin shares on domain (for IT management)" -ForegroundColor Gray
                Write-Host "      - Safe for business networks" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [3] Maximum" -ForegroundColor Cyan
                Write-Host "      - For: High-security / air-gapped systems" -ForegroundColor Gray
                Write-Host "      - Broadest profile; compatibility testing and rollback evidence required" -ForegroundColor Gray
                Write-Host "      - RDP disabled where host-capable; Shields Up enabled" -ForegroundColor Gray
                Write-Host ""

                $defaultChoice = if ($isDomainJoined) { '2' } else { '1' }

                do {
                    Write-Host "Select profile [1-3] (default: $defaultChoice): " -ForegroundColor White -NoNewline
                    $profileChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($profileChoice)) { $profileChoice = $defaultChoice }

                    if ($profileChoice -notin @('1', '2', '3')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter 1, 2, or 3." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($profileChoice -notin @('1', '2', '3'))

                switch ($profileChoice) {
                    '2' { $SecurityProfile = 'Enterprise' }
                    '3' { $SecurityProfile = 'Maximum' }
                    default { $SecurityProfile = 'Balanced' }
                }
                Write-Log -Level DEBUG -Message "User selected AdvancedSecurity profile: $SecurityProfile" -Module "AdvancedSecurity"
                Write-Host ""
            }
        }

        Write-Host "Profile: $SecurityProfile" -ForegroundColor Green
        Write-Host ""

        # Display profile info
        switch ($SecurityProfile) {
            'Balanced' {
                Write-Host "For: Home users, workstations" -ForegroundColor White
                Write-Host "  - RDP disable recommended (asks user, default: disable)" -ForegroundColor Gray
                Write-Host "  - UPnP/SSDP block recommended (asks user, default: block)" -ForegroundColor Gray
                Write-Host "  - Admin Shares (domain-aware) disabled; Legacy TLS disabled" -ForegroundColor Gray
            }
            'Enterprise' {
                Write-Host "For: Corporate environments" -ForegroundColor White
                Write-Host "  - RDP hardening only (no disable), UPnP blocked" -ForegroundColor Gray
                Write-Host "  - Admin Shares kept on domain (for IT management)" -ForegroundColor Gray
                Write-Host "  - LLMNR/NetBIOS blocked; Legacy TLS disabled" -ForegroundColor Gray
            }
            'Maximum' {
                Write-Host "For: High-security / air-gapped systems" -ForegroundColor White
                Write-Host "  - RDP disabled on host-capable editions (no remote access)" -ForegroundColor Gray
                Write-Host "  - Admin Shares forced off, UPnP blocked; discovery/IPv6 follow explicit choices" -ForegroundColor Gray
                Write-Host "  - Firewall Shields Up: Block unsolicited inbound traffic on Public network" -ForegroundColor Gray
                Write-Host "  - LLMNR/NetBIOS blocked; Legacy TLS disabled" -ForegroundColor Gray
            }
        }

        # Firewall 3-layer decision model:
        # 1) small detection list supplies only the prompt default,
        # 2) explicit CLI/config/user choice is authoritative,
        # 3) every later module/test run repeats detection and warns about conflicts.
        $firewallControllerStatus = Get-FirewallControllerStatus
        $detectedFirewallProducts = if ($firewallControllerStatus.Detected) {
            $firewallControllerStatus.Products -join ', '
        }
        else {
            'None detected'
        }

        if (-not $PSBoundParameters.ContainsKey('SkipFirewallLayer')) {
            if (Test-NonInteractiveMode) {
                $SkipFirewallLayer = [bool](Get-NonInteractiveValue -Module 'AdvancedSecurity' -Key 'skipFirewallLayer' -Required)
                Write-NonInteractiveDecision -Module 'AdvancedSecurity' -Decision 'Windows Firewall layer' -Value $(if ($SkipFirewallLayer) { 'Skipped' } else { 'Applied' })
                Write-Log -Level INFO -Message "Firewall controller detection (advisory only): $detectedFirewallProducts" -Module 'AdvancedSecurity'
            }
            else {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  WINDOWS FIREWALL LAYER" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Third-party firewall controllers: $detectedFirewallProducts" -ForegroundColor $(if ($firewallControllerStatus.Detected) { 'Yellow' } else { 'Gray' })
                Write-Host "Detection only chooses the suggested default; it never decides for you." -ForegroundColor Gray
                Write-Host "Applying keeps Windows Firewall active and adds NoID Privacy's exact rules." -ForegroundColor Gray
                Write-Host "Skip only if another product is actually controlling Windows Firewall rules." -ForegroundColor Gray
                Write-Host ""
                Write-Host "Skip NoID Privacy's Windows Firewall changes?" -ForegroundColor White
                Write-Host ""

                $firewallDefault = if ($firewallControllerStatus.Detected -or $localRuleBlockedProfiles.Count -gt 0) { 'Y' } else { 'N' }
                if ($localRuleBlockedProfiles.Count -gt 0) {
                    Write-Host "  [Y] YES - Skip all $(if ($wirelessDisplaySupported) { 17 } else { 13 }) firewall settings (Recommended)" -ForegroundColor Green
                    Write-Host "      - Windows $($applicability.EditionFamily) applies this layer as local firewall rules" -ForegroundColor Gray
                    Write-Host "      - Configured policy disables local rules on the $localRuleBlockedText profile" -ForegroundColor Gray
                    Write-Host "        (for example SecurityBaseline), so they cannot take effect there" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [N] NO - Not possible here: AdvancedSecurity stops before any change" -ForegroundColor Cyan
                }
                elseif ($firewallDefault -eq 'N') {
                    Write-Host "  [N] NO - Apply and verify NoID Privacy's firewall settings (Recommended)" -ForegroundColor Green
                    Write-Host "      - All applicable firewall settings are applied and verified" -ForegroundColor Gray
                    Write-Host "      - Existing firewall rules not owned by NoID Privacy are preserved" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [Y] YES - Skip all $(if ($wirelessDisplaySupported) { 17 } else { 13 }) firewall settings" -ForegroundColor Cyan
                    Write-Host "      - Reported as Skipped/NotChecked" -ForegroundColor Gray
                }
                else {
                    Write-Host "  [Y] YES - Skip all $(if ($wirelessDisplaySupported) { 17 } else { 13 }) firewall settings (Recommended)" -ForegroundColor Green
                    Write-Host "      - Reported as Skipped/NotChecked" -ForegroundColor Gray
                    Write-Host "      - Leaves firewall control to the detected third-party controller" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [N] NO - Apply and verify NoID Privacy's firewall settings" -ForegroundColor Cyan
                    Write-Host "      - May conflict if the detected product controls Windows Firewall rules" -ForegroundColor Gray
                }
                Write-Host ""

                do {
                    Write-Host "Skip Windows Firewall layer? [Y/N] (default: $firewallDefault): " -ForegroundColor White -NoNewline
                    $firewallChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($firewallChoice)) { $firewallChoice = $firewallDefault }
                    $firewallChoice = $firewallChoice.ToUpperInvariant()
                    if ($firewallChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($firewallChoice -notin @('Y', 'N'))

                $SkipFirewallLayer = ($firewallChoice -eq 'Y')
                Write-Log -Level INFO -Message "User decision: Windows Firewall layer = $(if ($SkipFirewallLayer) { 'Skipped' } else { 'Applied' }); advisory detection = $detectedFirewallProducts" -Module 'AdvancedSecurity'
                Write-Host ""
                if ($SkipFirewallLayer) {
                    Write-Host "Windows Firewall layer skipped by your choice" -ForegroundColor Cyan
                }
                else {
                    Write-Host "NoID Privacy's firewall settings will be applied and verified" -ForegroundColor Green
                }
            }
        }
        else {
            Write-Log -Level INFO -Message "Explicit parameter decision: Windows Firewall layer = $(if ($SkipFirewallLayer) { 'Skipped' } else { 'Applied' }); advisory detection = $detectedFirewallProducts" -Module 'AdvancedSecurity'
        }

        $null = Write-FirewallControllerRuntimeWarning -FirewallLayerSkipped $SkipFirewallLayer -Detection $firewallControllerStatus

        if (-not $SkipFirewallLayer -and $localRuleBlockedProfiles.Count -gt 0) {
            $blockedMessage = "The Windows Firewall layer cannot take effect: Windows $($applicability.EditionFamily) applies it as local rules, " +
                "and configured policy (AllowLocalPolicyMerge, for example from SecurityBaseline) disables local firewall rules on the $localRuleBlockedText profile. " +
                "Skip the firewall layer (skipFirewallLayer=true) to apply the rest of AdvancedSecurity. No AdvancedSecurity change was made."
            Write-Log -Level ERROR -Message $blockedMessage -Module 'AdvancedSecurity'
            Write-Host ""
            Write-Host "ERROR: $blockedMessage" -ForegroundColor Red
            Write-Host ""
            return [PSCustomObject]@{
                Success      = $false
                ErrorMessage = $blockedMessage
            }
        }

        # WARNING PROMPT: Inform about breaking changes
        Write-Host ""
        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host "  IMPORTANT NOTICES" -ForegroundColor Cyan
        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "This module will apply the following changes:" -ForegroundColor White
        Write-Host ""
        Write-Host "  Security Hardening:" -ForegroundColor Green
        Write-Host "  + RDP hardening (NLA + SSL/TLS enforcement)" -ForegroundColor Gray

        # Profile-specific protocol blocking info
        if ($SecurityProfile -eq 'Balanced') {
            Write-Host "  + Risky protocols: LLMNR, NetBIOS blocked | UPnP/SSDP (asks user)" -ForegroundColor Gray
        }
        else {
            Write-Host "  + Risky protocols blocked (LLMNR, NetBIOS, UPnP/SSDP)" -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "  Potential Breaking Changes:" -ForegroundColor Yellow
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
            Write-Host "Continue with hardening?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [Y] YES - Continue with hardening (default)" -ForegroundColor Green
            Write-Host "      - Applies the changes listed above" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [N] NO - Cancel" -ForegroundColor Cyan
            Write-Host "      - No changes are made" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Your choice [Y/N] (default: Y): " -ForegroundColor White -NoNewline
                $continueChoice = Read-Host
                if ([string]::IsNullOrWhiteSpace($continueChoice)) { $continueChoice = "Y" }
                $continueChoice = $continueChoice.ToUpperInvariant()

                if ($continueChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($continueChoice -notin @('Y', 'N'))

            if ($continueChoice -eq 'N') {
                Write-Host ""
                Write-Host "AdvancedSecurity skipped by your choice; nothing was changed." -ForegroundColor Cyan
                Write-Host ""
                Write-Log -Level INFO -Message "User declined AdvancedSecurity hardening at the confirmation prompt; nothing was changed" -Module "AdvancedSecurity"
                return [PSCustomObject]@{
                    Success         = $false
                    Status          = 'Skipped'
                    SkippedByChoice = $true
                    ErrorMessage    = "Skipped by the user's choice"
                }
            }
        }

        Write-Host ""
        Write-Host "Proceeding with security hardening..." -ForegroundColor Green
        Write-Host ""

        # Maximum has a fixed complete-disable contract. Selecting this profile
        # is the explicit authority; a false switch binding must not silently
        # contradict the profile summary and BAVR decision record.
        if (-not $rdpHostSupported) {
            $DisableRDP = $false
            Write-Host "RDP host hardening: NOT APPLICABLE on Windows $($applicability.EditionFamily)" -ForegroundColor Gray
            Write-Log -Level INFO -Message "RDP host targets are NotApplicable because edition $($applicability.EditionFamily) cannot host Remote Desktop" -Module 'AdvancedSecurity'
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            $DisableRDP = $true
            Write-Log -Level INFO -Message "Profile 'Maximum': RDP will be completely disabled automatically" -Module "AdvancedSecurity"
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  REMOTE DESKTOP (RDP)" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  RDP will be COMPLETELY DISABLED (Maximum profile)" -ForegroundColor Cyan
            Write-Host "  - No inbound Remote Desktop hosting" -ForegroundColor Gray
            Write-Host "  - Hardening applied before disable" -ForegroundColor Gray
        }

        # RDP Complete Disable - NonInteractive or Interactive (Balanced profile only for interactive)
        # NOTE: RDP is ALWAYS hardened (NLA + SSL/TLS), this prompt is only for complete disable
        # NonInteractive: ALWAYS read config value (respects user choice in any profile)
        # Interactive: Only prompt for Balanced profile (Enterprise/Maximum have fixed behavior)
        if ($rdpHostSupported -and -not $PSBoundParameters.ContainsKey('DisableRDP')) {
            if (Test-NonInteractiveMode) {
                # The GUI disables this choice outside Balanced, so the runtime
                # contract must not let a stale hidden value contradict the profile.
                $DisableRDP = switch ($SecurityProfile) {
                    'Maximum' { $true }
                    'Enterprise' { $false }
                    default { [bool](Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableRDP" -Required) }
                }
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "RDP" -Value $(if ($DisableRDP) { "Disabled" } else { "Current enable/disable state preserved; NLA/TLS hardened" })
            }
            elseif ($SecurityProfile -eq 'Balanced') {
                # Interactive mode
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  REMOTE DESKTOP (RDP) CONFIGURATION" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "RDP is a common target for ransomware and cyber attacks." -ForegroundColor White
                Write-Host ""
                Write-Host "Do you want to COMPLETELY DISABLE Remote Desktop (until you manually re-enable it in Settings)?" -ForegroundColor White
                Write-Host ""
                Write-Host "  [Y] YES - Completely disable RDP (Recommended for security)" -ForegroundColor Green
                Write-Host "      - Disables inbound Remote Desktop hosting through the declared policy" -ForegroundColor Gray
                Write-Host "      - Recommended for home users who don't use remote access" -ForegroundColor Gray
                Write-Host "      - Can be re-enabled later if needed" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [N] NO - Preserve the current RDP enable/disable state" -ForegroundColor Cyan
                Write-Host "      - NoID Privacy will not enable Remote Desktop" -ForegroundColor Gray
                Write-Host "      - Network Level Authentication + SSL/TLS enforced" -ForegroundColor Gray
                Write-Host "      - If RDP is already enabled, it remains usable with stronger security" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Disable RDP completely? [Y/N] (default: Y): " -ForegroundColor White -NoNewline
                    $rdpChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($rdpChoice)) { $rdpChoice = "Y" }
                    $rdpChoice = $rdpChoice.ToUpperInvariant()

                    if ($rdpChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($rdpChoice -notin @('Y', 'N'))

                if ($rdpChoice -eq 'N') {
                    $DisableRDP = $false
                    Write-Host ""
                    Write-Host "RDP state will be PRESERVED; NLA/TLS will be hardened" -ForegroundColor Cyan
                    Write-Log -Level INFO -Message "User decision: preserve current RDP enable/disable state and harden NLA/TLS" -Module "AdvancedSecurity"
                }
                else {
                    $DisableRDP = $true
                    Write-Host ""
                    Write-Host "RDP will be HARDENED and then DISABLED (you can re-enable it later in Settings)" -ForegroundColor Green
                    Write-Log -Level INFO -Message "User decision: RDP will be hardened then completely disabled" -Module "AdvancedSecurity"
                }
                Write-Host ""
            }
        }

        # Admin Shares Force (only on domain-joined systems with Balanced profile) - NonInteractive or Interactive
        # Enterprise profile automatically keeps admin shares on domain (no prompt)
        if (-not $PSBoundParameters.ContainsKey('Force') -and $isDomainJoined -and $SecurityProfile -eq 'Balanced') {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config value
                $Force = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "forceAdminShares" -Required
                Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Admin Shares on domain" -Value $(if ($Force) { "Disabled (forced)" } else { "Kept" })
            }
            else {
                # Interactive mode
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  ADMIN SHARES CONFIGURATION" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Note: This system is domain-joined." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Domain: $($computerSystem.Domain)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Admin Shares (C$, ADMIN$) are often used by IT management tools; IPC$ is not changed." -ForegroundColor White
                Write-Host ""
                Write-Host "Do you want to DISABLE admin shares anyway?" -ForegroundColor White
                Write-Host ""
                Write-Host "  [N] NO - Keep admin shares (Recommended for domain)" -ForegroundColor Green
                Write-Host "      - IT can still manage this computer remotely" -ForegroundColor Gray
                Write-Host "      - SCCM, PDQ Deploy, PowerShell Remoting work" -ForegroundColor Gray
                Write-Host "      - Other security features still applied" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  [Y] YES - Disable admin shares anyway" -ForegroundColor Cyan
                Write-Host "      - Maximum security but may break management tools" -ForegroundColor Gray
                Write-Host "      - IT cannot access C$, ADMIN$ remotely" -ForegroundColor Gray
                Write-Host "      - May require manual intervention from IT" -ForegroundColor Gray
                Write-Host ""

                do {
                    Write-Host "Disable admin shares on domain system? [Y/N] (default: N): " -ForegroundColor White -NoNewline
                    $adminShareChoice = Read-Host
                    if ([string]::IsNullOrWhiteSpace($adminShareChoice)) { $adminShareChoice = "N" }
                    $adminShareChoice = $adminShareChoice.ToUpperInvariant()

                    if ($adminShareChoice -notin @('Y', 'N')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($adminShareChoice -notin @('Y', 'N'))

                if ($adminShareChoice -eq 'Y') {
                    $Force = $true
                    Write-Host ""
                    Write-Host "Admin Shares will be DISABLED (may break IT tools)" -ForegroundColor Yellow
                    Write-Log -Level INFO -Message "User decision: Admin shares will be DISABLED on domain system" -Module "AdvancedSecurity"
                }
                else {
                    $Force = $false
                    Write-Host ""
                    Write-Host "Admin Shares will be KEPT (safe for domain)" -ForegroundColor Cyan
                    Write-Log -Level INFO -Message "User decision: Admin shares will be KEPT on domain system" -Module "AdvancedSecurity"
                }
                Write-Host ""
            }
        }

        # UPnP/SSDP Configuration - NonInteractive or Interactive (Balanced profile only for interactive)
        # NonInteractive: ALWAYS read config value (respects user choice in any profile)
        # Interactive: Only prompt for Balanced profile (Enterprise/Maximum always block)
        $DisableUPnP = $true  # Default for all profiles

        if (Test-NonInteractiveMode) {
            # Enterprise/Maximum expose UPnP as a fixed blocked profile decision;
            # only Balanced presents an authoritative toggle.
            $DisableUPnP = if ($SecurityProfile -eq 'Balanced') {
                [bool](Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableUPnP" -Required)
            }
            else { $true }
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "UPnP/SSDP" -Value $(if ($DisableUPnP) { "Blocked" } else { "Allowed" })
        }
        elseif ($SecurityProfile -eq 'Balanced') {
            # Interactive mode
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  UPnP/SSDP CONFIGURATION" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "UPnP (Universal Plug and Play) is used by some devices for auto-discovery." -ForegroundColor White
            Write-Host ""
            Write-Host "SECURITY SCOPE:" -ForegroundColor Cyan
            Write-Host "  - Disabling the selected Windows UPnP/SSDP services reduces local discovery exposure" -ForegroundColor Gray
            Write-Host "  - This does not configure the router or cover unrelated NAT-PMP/UPnP implementations" -ForegroundColor Gray
            Write-Host ""
            Write-Host "POTENTIAL COMPATIBILITY IMPACT:" -ForegroundColor Yellow
            Write-Host "  ! DLNA Media Streaming (legacy local network discovery)" -ForegroundColor Gray
            Write-Host "  ! Windows Media Player to TV/receiver" -ForegroundColor Gray
            Write-Host "  ! Some gaming console auto-discovery features" -ForegroundColor Gray
            Write-Host ""
            Write-Host "OUTSIDE THIS CHANGE:" -ForegroundColor Cyan
            Write-Host "  + Ordinary web traffic is not directly targeted" -ForegroundColor Gray
            Write-Host "  + Other discovery protocols and router-side UPnP/NAT-PMP are not certified by this option" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to BLOCK UPnP/SSDP for security?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [Y] YES - Block UPnP/SSDP (Recommended for security)" -ForegroundColor Green
            Write-Host "      - Disables selected Windows services and module-owned rules" -ForegroundColor Gray
            Write-Host "      - DLNA/auto-discovery workflows may stop" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [N] NO - Keep UPnP/SSDP enabled" -ForegroundColor Cyan
            Write-Host "      - DLNA streaming works" -ForegroundColor Gray
            Write-Host "      - Gaming console auto-discovery works" -ForegroundColor Gray
            Write-Host "      - Accepts security risk" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Block UPnP/SSDP? [Y/N] (default: Y): " -ForegroundColor White -NoNewline
                $upnpChoice = Read-Host
                if ([string]::IsNullOrWhiteSpace($upnpChoice)) { $upnpChoice = "Y" }
                $upnpChoice = $upnpChoice.ToUpperInvariant()

                if ($upnpChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($upnpChoice -notin @('Y', 'N'))

            if ($upnpChoice -eq 'N') {
                $DisableUPnP = $false
                Write-Host ""
                Write-Host "UPnP/SSDP will be KEPT enabled (DLNA works)" -ForegroundColor Cyan
                Write-Log -Level INFO -Message "User decision: UPnP/SSDP will be KEPT enabled" -Module "AdvancedSecurity"
            }
            else {
                $DisableUPnP = $true
                Write-Host ""
                Write-Host "UPnP/SSDP will be BLOCKED (security hardening)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: UPnP/SSDP will be BLOCKED" -Module "AdvancedSecurity"
            }
            Write-Host ""
        }

        # Wireless Display Configuration - Optional complete disable
        # Default for ALL profiles: Block receiving + Require PIN (always applied)
        # Optional: Complete disable (user choice like UPnP)
        $DisableWirelessDisplayCompletely = $false  # Default: block receiving; preserve sending settings

        if (-not $wirelessDisplaySupported) {
            Write-Host "Wireless Display policy hardening: NOT APPLICABLE on Windows $($applicability.EditionFamily)" -ForegroundColor Gray
            Write-Log -Level INFO -Message "Wireless Display policy and complete-disable targets are NotApplicable on edition $($applicability.EditionFamily)" -Module 'AdvancedSecurity'
        }
        elseif (Test-NonInteractiveMode) {
            # NonInteractive mode (GUI) - use config value
            $DisableWirelessDisplayCompletely = Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableWirelessDisplay" -Required
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Wireless Display" -Value $(if ($DisableWirelessDisplayCompletely) { "Completely Disabled" } else { "Receiving blocked; sending settings unchanged" })
        }
        else {
            # Interactive mode
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  WIRELESS DISPLAY (MIRACAST) SECURITY" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Wireless Display allows screen mirroring to TVs/projectors." -ForegroundColor White
            Write-Host ""
            Write-Host "DEFAULT HARDENING (always applied):" -ForegroundColor Cyan
            Write-Host "  + Block receiving projections (PC can't be used as display)" -ForegroundColor Gray
            Write-Host "  + Require PIN policy for pairing" -ForegroundColor Gray
            Write-Host "  + Sending settings stay unchanged; earlier blocks are not removed" -ForegroundColor Green
            Write-Host ""
            Write-Host "REMAINING SCOPE if not completely disabled:" -ForegroundColor Cyan
            Write-Host "  - Sending/discovery settings are left as they are" -ForegroundColor Gray
            Write-Host "  - PIN/readback does not prove resistance to every Miracast or network attack" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT BREAKS if completely disabled:" -ForegroundColor Yellow
            Write-Host "  ! Cannot mirror screen to TV/projector via Miracast" -ForegroundColor Gray
            Write-Host "  ! Windows + K shortcut won't find wireless displays" -ForegroundColor Gray
            Write-Host "  ! (HDMI/USB-C cables still work)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to COMPLETELY DISABLE Wireless Display?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [N] NO - Keep hardened only (Default, Recommended)" -ForegroundColor Green
            Write-Host "      - Sending settings unchanged; does not re-enable earlier blocks" -ForegroundColor Gray
            Write-Host "      - Receive policy is disabled" -ForegroundColor Gray
            Write-Host "      - Pairing PIN policy is required" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [Y] YES - Complete disable (Maximum security)" -ForegroundColor Cyan
            Write-Host "      - Applies the module's full policy/service/adapter target set" -ForegroundColor Gray
            Write-Host "      - Module-owned TCP/UDP 7236/7250 rules enabled when firewall layer is selected" -ForegroundColor Gray
            Write-Host "      - Use HDMI/USB-C for presentations" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Completely disable Wireless Display? [Y/N] (default: N): " -ForegroundColor White -NoNewline
                $wirelessChoice = Read-Host
                if ([string]::IsNullOrWhiteSpace($wirelessChoice)) { $wirelessChoice = "N" }
                $wirelessChoice = $wirelessChoice.ToUpperInvariant()

                if ($wirelessChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($wirelessChoice -notin @('Y', 'N'))

            if ($wirelessChoice -eq 'Y') {
                $DisableWirelessDisplayCompletely = $true
                Write-Host ""
                Write-Host "Wireless Display will be COMPLETELY DISABLED" -ForegroundColor Cyan
                Write-Log -Level INFO -Message "User decision: Wireless Display completely disabled" -Module "AdvancedSecurity"
            }
            else {
                $DisableWirelessDisplayCompletely = $false
                Write-Host ""
                Write-Host "Wireless Display: receiving blocked; sending settings unchanged" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: Wireless Display hardened only" -Module "AdvancedSecurity"
            }
        }

        # Discovery Protocols (WS-Discovery + mDNS) Configuration - Maximum profile only
        # This controls OS-level mDNS resolver and WS-Discovery service+firewall block.
        $DisableDiscoveryProtocolsCompletely = $false

        if (Test-NonInteractiveMode) {
            # Clamp to the profile before recording, as for RDP and UPnP above.
            # A stale true from an earlier Maximum configuration must not make
            # the decision record claim that WS-Discovery and mDNS were disabled
            # when this profile never applies that change.
            $DisableDiscoveryProtocolsCompletely = ($SecurityProfile -eq 'Maximum') -and
                [bool](Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableDiscoveryProtocols" -Required)
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "Discovery Protocols (WS-Discovery/mDNS, Maximum only)" -Value $(if ($DisableDiscoveryProtocolsCompletely) { "Windows discovery restricted" } else { "Unchanged" })
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            # Interactive prompt only for Maximum profile
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  DISCOVERY PROTOCOLS (WS-Discovery + mDNS)" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "WS-Discovery and mDNS are used for automatic device discovery (printers, TVs, scanners)." -ForegroundColor White
            Write-Host "On a high-security/air-gapped profile, disabling these discovery targets is an explicit user choice." -ForegroundColor White
            Write-Host ""
            Write-Host "SECURITY SCOPE:" -ForegroundColor Cyan
            Write-Host "  - Disables selected Windows discovery policy/services and module-owned firewall paths" -ForegroundColor Gray
            Write-Host "  - Does not prove that every discovery or lateral-movement technique is blocked" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT BREAKS IF DISABLED:" -ForegroundColor Yellow
            Write-Host "  ! Automatic discovery of network printers/TVs/scanners" -ForegroundColor Gray
            Write-Host "  ! Some legacy media streaming / casting workflows" -ForegroundColor Gray
            Write-Host "  ! Miracast display discovery (even if Miracast allowed above)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "OUTSIDE THIS CHANGE:" -ForegroundColor Cyan
            Write-Host "  + The module does not deliberately block ordinary outbound web ports" -ForegroundColor Gray
            Write-Host "  + Direct-IP/vendor-app compatibility still depends on the device and application" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to restrict Windows device discovery (WS-Discovery and mDNS)?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [N] NO - Leave discovery settings unchanged (Recommended)" -ForegroundColor Green
            Write-Host "      - Existing restrictions stay in place" -ForegroundColor Gray
            Write-Host "      - Higher attack surface on a Maximum-profile system" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [Y] YES - Maximum security (air-gapped / Maximum profile)" -ForegroundColor Cyan
            Write-Host "      - Disables OS mDNS resolver" -ForegroundColor Gray
            Write-Host "      - Disables WS-Discovery services" -ForegroundColor Gray
            Write-Host "      - Blocks inbound WS-Discovery and mDNS ports when the firewall layer is selected" -ForegroundColor Gray
            Write-Host "      - Apps with their own discovery may still send requests" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Restrict Windows device discovery? [Y/N] (default: N): " -ForegroundColor White -NoNewline
                $discoveryChoice = Read-Host
                if ([string]::IsNullOrWhiteSpace($discoveryChoice)) { $discoveryChoice = "N" }
                $discoveryChoice = $discoveryChoice.ToUpperInvariant()

                if ($discoveryChoice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($discoveryChoice -notin @('Y', 'N'))

            if ($discoveryChoice -eq 'Y') {
                $DisableDiscoveryProtocolsCompletely = $true
                Write-Host ""
                Write-Host "Windows discovery services and selected inbound ports will be restricted" -ForegroundColor Cyan
                Write-Log -Level INFO -Message "User decision: Windows discovery hardening selected on Maximum profile" -Module "AdvancedSecurity"
            }
            else {
                $DisableDiscoveryProtocolsCompletely = $false
                Write-Host ""
                Write-Host "Discovery settings will remain unchanged" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: Discovery protocols (WS-Discovery/mDNS) left unchanged on Maximum profile" -Module "AdvancedSecurity"
            }
        }

        # Optional IPv6 component-disable state - Maximum profile only.
        $DisableIPv6Completely = $false

        if (Test-NonInteractiveMode) {
            # Same profile clamp as RDP/UPnP/discovery above. The decision is
            # recorded in both cases: "IPv6 unchanged" is a decision the operator
            # must be able to read back, not the absence of one.
            $DisableIPv6Completely = ($SecurityProfile -eq 'Maximum') -and
                [bool](Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableIPv6" -Required)
            Write-NonInteractiveDecision -Module "AdvancedSecurity" -Decision "IPv6 component state" -Value $(if ($DisableIPv6Completely) { "DisabledComponents=0xFF (broad disable; internal IPv6 remains)" } else { "Unchanged (Windows default IPv6 stack)" })
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            # Interactive prompt only for Maximum profile
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  OPTIONAL IPv6 COMPONENT DISABLE (0xFF)" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Untrusted DHCPv6/Router Advertisement responses can create DNS and relay attack paths." -ForegroundColor White
            Write-Host ""
            Write-Host "ATTACK SCENARIO (mitm6):" -ForegroundColor Cyan
            Write-Host "  1. Attacker responds to DHCPv6 requests as fake server" -ForegroundColor Gray
            Write-Host "  2. Attacker becomes DNS server for victim" -ForegroundColor Gray
            Write-Host "  3. Combined with WPAD -> NTLM credentials stolen" -ForegroundColor Gray
            Write-Host "  4. In vulnerable environments this can contribute to domain compromise" -ForegroundColor Gray
            Write-Host ""
            Write-Host "IMPORTANT MICROSOFT GUIDANCE:" -ForegroundColor Yellow
            Write-Host "  - IPv6 is a mandatory Windows component; Microsoft does not recommend disabling it" -ForegroundColor Gray
            Write-Host "  - 0xFF reduces network-facing IPv6 components after reboot, but internal/loopback IPv6 remains" -ForegroundColor Gray
            Write-Host "  - This state does not by itself guarantee complete mitm6 prevention" -ForegroundColor Gray
            Write-Host "  - For ordinary compatibility, keep IPv6 enabled (recommended default)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "WHAT MAY BREAK WITH 0xFF:" -ForegroundColor Yellow
            Write-Host "  ! Exchange Server communication (if using IPv6)" -ForegroundColor Gray
            Write-Host "  ! Some Active Directory features" -ForegroundColor Gray
            Write-Host "  ! IPv6-only services and websites" -ForegroundColor Gray
            Write-Host ""
            Write-Host "ONLY CONSIDER FOR:" -ForegroundColor Cyan
            Write-Host "  + A specifically tested environment with a documented need" -ForegroundColor Gray
            Write-Host "  + A rollback plan and acceptance of Windows compatibility risk" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Do you want to apply DisabledComponents=0xFF?" -ForegroundColor White
            Write-Host ""
            Write-Host "  [N] NO - Keep IPv6 enabled (Microsoft-recommended default)" -ForegroundColor Green
            Write-Host "      - Other framework controls still reduce WPAD/LLMNR/NetBIOS exposure" -ForegroundColor Gray
            Write-Host "      - IPv6 functionality preserved" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [Y] YES - Broadly disable IPv6 components (advanced opt-in)" -ForegroundColor Cyan
            Write-Host "      - Reduces network-facing IPv6 attack surface; no absolute guarantee" -ForegroundColor Gray
            Write-Host "      - REBOOT REQUIRED" -ForegroundColor Gray
            Write-Host ""

            do {
                Write-Host "Apply IPv6 DisabledComponents=0xFF? [Y/N] (default: N): " -ForegroundColor White -NoNewline
                $ipv6Choice = Read-Host
                if ([string]::IsNullOrWhiteSpace($ipv6Choice)) { $ipv6Choice = "N" }
                $ipv6Choice = $ipv6Choice.ToUpperInvariant()

                if ($ipv6Choice -notin @('Y', 'N')) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                    Write-Host ""
                }
            } while ($ipv6Choice -notin @('Y', 'N'))

            if ($ipv6Choice -eq 'Y') {
                $DisableIPv6Completely = $true
                Write-Host ""
                Write-Host "IPv6 component-disable value 0xFF will be applied (REBOOT REQUIRED)" -ForegroundColor Cyan
                Write-Log -Level INFO -Message "User decision: apply IPv6 DisabledComponents=0xFF; internal IPv6 remains and total mitm6 prevention is not claimed" -Module "AdvancedSecurity"
            }
            else {
                $DisableIPv6Completely = $false
                Write-Host ""
                Write-Host "IPv6 will be KEPT enabled (Microsoft-recommended default)" -ForegroundColor Green
                Write-Log -Level INFO -Message "User decision: IPv6 kept enabled; other selected network hardening remains active" -Module "AdvancedSecurity"
            }
            Write-Host ""
        }

        # Freeze the effective decision set before Backup. BAVR owns only state
        # that this exact run can mutate; unselected optional values/services are
        # neither captured nor later overwritten by Restore.
        $adminSharesSelected = -not ($isDomainJoined -and -not $Force -and $SecurityProfile -ne 'Maximum')
        $effectiveDiscoveryDisable = ($SecurityProfile -eq 'Maximum' -and $DisableDiscoveryProtocolsCompletely)
        $effectiveIPv6Disable = ($SecurityProfile -eq 'Maximum' -and $DisableIPv6Completely)
        $enableFirewallShieldsUp = ($SecurityProfile -eq 'Maximum' -and -not $SkipFirewallLayer)

        $countsPath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'Config\SettingsCounts.json'
        if (-not (Test-Path -LiteralPath $countsPath -PathType Leaf)) {
            throw "Canonical SettingsCounts.json is missing: $countsPath"
        }
        $counts = Get-Content -LiteralPath $countsPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $expectedCount = [int]$counts.modules.AdvancedSecurity.settings
        $firewallSettingsCount = [int]$counts.modules.AdvancedSecurity.firewall
        $runtimeApplicability = Get-AdvancedSecurityRuntimeApplicability
        $decisionAccounting = Get-AdvancedSecurityDecisionAccounting `
            -SecurityProfile $SecurityProfile `
            -SkipFirewallLayer ([bool]$SkipFirewallLayer) `
            -DisableRDP ([bool]$DisableRDP) `
            -AdminSharesSelected ([bool]$adminSharesSelected) `
            -DisableUPnP ([bool]$DisableUPnP) `
            -DisableWirelessDisplayCompletely ([bool]$DisableWirelessDisplayCompletely) `
            -DisableDiscoveryProtocolsCompletely ([bool]$effectiveDiscoveryDisable) `
            -DisableIPv6Completely ([bool]$effectiveIPv6Disable) `
            -RdpHostSupported ([bool]$rdpHostSupported) `
            -ManagedPolicySupported ([bool]$managedPolicySupported) `
            -WirelessDisplaySupported ([bool]$wirelessDisplaySupported) `
            -DeclaredCount $expectedCount `
            -FirewallDeclaredCount $firewallSettingsCount `
            -LmhostsPresent ([bool]$runtimeApplicability.LmhostsPresent) `
            -SsdpSrvPresent ([bool]$runtimeApplicability.SsdpSrvPresent) `
            -UpnpHostPresent ([bool]$runtimeApplicability.UpnpHostPresent) `
            -FdResPubPresent ([bool]$runtimeApplicability.FdResPubPresent) `
            -FdPHostPresent ([bool]$runtimeApplicability.FdPHostPresent) `
            -WfdServicePresent ([bool]$runtimeApplicability.WfdServicePresent) `
            -WfdAdapterPresent ([bool]$runtimeApplicability.WfdAdapterPresent) `
            -WinInetUserPresent ([bool]$runtimeApplicability.WinInetUserPresent)

        if ($DryRun -or $WhatIfPreference) {
            $previewRegistryTargets = @(Get-AdvancedSecurityRegistryTargets `
                -SkipFirewallLayer:$SkipFirewallLayer `
                -DisableRDP:$DisableRDP `
                -AdminSharesDisabled:$adminSharesSelected `
                -DisableDiscoveryProtocolsCompletely:$effectiveDiscoveryDisable `
                -DisableIPv6Completely:$effectiveIPv6Disable `
                -EnableFirewallShieldsUp:$enableFirewallShieldsUp `
                -RdpHostSupported:$rdpHostSupported `
                -ManagedPolicySupported:$managedPolicySupported `
                -WirelessDisplaySupported:$wirelessDisplaySupported)
            if ($previewRegistryTargets.Count -lt 1 -or
                @($previewRegistryTargets | Group-Object {
                        (([string]$_.Path) + '::' + ([string]$_.Name)).ToLowerInvariant()
                    } | Where-Object Count -gt 1).Count -gt 0) {
                throw 'AdvancedSecurity DryRun registry target plan is empty or ambiguous'
            }
            $canonicalFirewallDefinitions = @(Get-AdvancedSecurityFirewallDefinitions)
            if ($canonicalFirewallDefinitions.Count + 1 -ne $firewallSettingsCount) {
                throw "AdvancedSecurity firewall inventory drift: rules=$($canonicalFirewallDefinitions.Count), ShieldsUp=1, declared=$firewallSettingsCount"
            }
        }

        # Handle DryRun parameter (convert to WhatIf for ShouldProcess)
        if ($DryRun) {
            $WhatIfPreference = $true
        }

        # WhatIf mode
        if ($PSCmdlet.ShouldProcess("Advanced Security", "Apply $SecurityProfile hardening")) {

            # PHASE 1: BACKUP
            # No system restore point is created; the sealed BAVR backup below
            # is the restore mechanism.
            Write-Host "[1/4] Saving the current settings..." -ForegroundColor Cyan

            Write-Log -Level INFO -Message "Initializing backup system..." -Module "AdvancedSecurity"
            $backupInit = Initialize-BackupSystem

            if (-not $backupInit) {
                Write-Log -Level ERROR -Message "Failed to initialize backup system!" -Module "AdvancedSecurity"
                Write-Host "  ERROR: Backup system initialization failed!" -ForegroundColor Red
                Write-Host "  No changes were applied." -ForegroundColor Yellow
                Write-Host ""
                return [PSCustomObject]@{
                    Success      = $false
                    ErrorMessage = "Backup system initialization failed"
                }
            }

            $backupResult = Backup-AdvancedSecuritySettings `
                -SkipFirewallLayer:$SkipFirewallLayer `
                -DisableRDP:$DisableRDP `
                -AdminSharesDisabled:$adminSharesSelected `
                -DisableUPnP:$DisableUPnP `
                -DisableWirelessDisplayCompletely:$DisableWirelessDisplayCompletely `
                -DisableDiscoveryProtocolsCompletely:$effectiveDiscoveryDisable `
                -DisableIPv6Completely:$effectiveIPv6Disable `
                -EnableFirewallShieldsUp:$enableFirewallShieldsUp `
                -RdpHostSupported:$rdpHostSupported `
                -ManagedPolicySupported:$managedPolicySupported `
                -WirelessDisplaySupported:$wirelessDisplaySupported `
                -EditionFamily $applicability.EditionFamily

            if ($backupResult -and $backupResult.Success) {
                # The classification used for reporting must describe the
                # exact inventory protected by the sealed prestate. Abort if
                # optional features/services/adapters changed during Backup.
                $runtimeApplicabilityBeforeApply = Get-AdvancedSecurityRuntimeApplicability
                foreach ($propertyName in $runtimeApplicability.PSObject.Properties.Name) {
                    if ([bool]$runtimeApplicability.$propertyName -ne [bool]$runtimeApplicabilityBeforeApply.$propertyName) {
                        throw "AdvancedSecurity runtime applicability changed during backup: $propertyName"
                    }
                }

                $null = Assert-AdvancedSecurityPrestate
                # Seal the exact artifact set registered for this module.
                $registeredArtifacts = @($global:BackupIndex | Where-Object { $_.Module -eq 'AdvancedSecurity' })
                $backupCompleted = Complete-ModuleBackup -ItemsBackedUp $registeredArtifacts.Count -Status "Success"
                if (-not $backupCompleted) {
                    Write-Log -Level ERROR -Message "Backup manifest completion failed - aborting Apply" -Module "AdvancedSecurity"
                    $null = Save-IncompleteModuleBackup -ModuleName 'AdvancedSecurity' -Confirm:$false
                    return [PSCustomObject]@{ Success = $false; ErrorMessage = 'Backup manifest completion failed' }
                }
                # Live policy has just been reconciled before sealing. From
                # this point the backup is immutable: validate its full manifest
                # and hashes, rather than rejecting later Windows app servicing.
                $sealedManifest = Get-SessionManifest -SessionPath $global:BackupBasePath
                $null = Assert-SessionManifest -SessionPath $global:BackupBasePath -Manifest $sealedManifest

                $preStateArtifacts = @($registeredArtifacts | Where-Object {
                        [string]$_.Type -eq 'AdvancedSecurity' -and
                        [string]$_.Name -eq 'AdvancedSecurity_PreState'
                    })
                if ($preStateArtifacts.Count -ne 1) {
                    throw "Expected one sealed AdvancedSecurity prestate; found $($preStateArtifacts.Count)"
                }
                $advancedSecurityPreState = Get-Content -LiteralPath $preStateArtifacts[0].BackupFile `
                    -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                Write-Log -Level SUCCESS -Message "Backup completed: $($registeredArtifacts.Count) validated artifacts" -Module "AdvancedSecurity"
                Write-NoIDDetail "  Saved" -ForegroundColor Green
            }
            else {
                Write-Log -Level ERROR -Message "Backup is incomplete - aborting Apply" -Module "AdvancedSecurity"
                Write-Host "  ERROR: Backup is incomplete; no changes were applied" -ForegroundColor Red
                $null = Save-IncompleteModuleBackup -ModuleName 'AdvancedSecurity' -Confirm:$false
                return [PSCustomObject]@{ Success = $false; ErrorMessage = 'AdvancedSecurity backup incomplete' }
            }
            Write-Host ""

            # PHASE 2: APPLY
            Write-Host "[2/4] Applying..." -ForegroundColor Cyan

            $appliedFeatures = @()
            $failedFeatures = @()
            $skippedFeatures = @()
            if ($SkipFirewallLayer) {
                $skippedFeatures += "Windows Firewall Layer ($(if ($wirelessDisplaySupported) { 17 } else { 13 }) applicable targets)"
            }

            # Feature 1: RDP Hardening
            Write-Host "  RDP Security Hardening..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)
            if (-not $rdpHostSupported) {
                Write-Host " NOT APPLICABLE (edition cannot host RDP)" -ForegroundColor Gray
                $skippedFeatures += 'RDP Hardening (NotApplicable)'
            }
            else {
                try {
                    $rdpDisable = $false

                    if ($SecurityProfile -eq 'Maximum' -and $DisableRDP) {
                        $rdpDisable = $true
                    }
                    elseif ($DisableRDP) {
                        Write-Log -Level INFO -Message "User explicitly requested full RDP disable in profile '$SecurityProfile' - applying complete disable with Force override" -Module "AdvancedSecurity"
                        $rdpDisable = $true
                    }

                    # Reaching this point with DisableRDP=true is itself an explicit
                    # user/config/CLI decision. Do not let the unrelated admin-share
                    # Force choice silently override that RDP decision on a domain PC.
                    $rdpResult = Enable-RdpNLA -DisableRDP:$rdpDisable -Force:$rdpDisable

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
            }

            # Feature 2: Administrative Shares
            Write-Host "  Admin Shares Disable..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            try {
                # Domain safety applies consistently to Balanced and Enterprise;
                # Maximum or an explicit Force decision opts into the breakage.
                if ($isDomainJoined -and -not $Force -and $SecurityProfile -ne 'Maximum') {
                    Write-Host " SKIPPED (domain safety)" -ForegroundColor Cyan
                    $skippedFeatures += 'Admin Shares Disable (domain safety)'
                    Write-Log -Level INFO -Message "Admin shares kept on domain by explicit/default domain-safety decision" -Module "AdvancedSecurity"
                }
                else {
                    $adminSharesForce = $false

                    if ($SecurityProfile -eq 'Maximum') {
                        $adminSharesForce = $true
                    }
                    elseif ($Force) {
                        $adminSharesForce = $true
                    }

                    $adminSharesResult = Disable-AdminShares -Force:$adminSharesForce -SkipFirewallChanges:$SkipFirewallLayer

                    if ($adminSharesResult) {
                        Write-Host " OK" -ForegroundColor Green
                        $appliedFeatures += "Admin Shares Disable"
                    }
                    else {
                        Write-Host " FAILED" -ForegroundColor Red
                        $failedFeatures += 'Admin Shares Disable'
                    }
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Admin Shares Disable"
                Write-Log -Level ERROR -Message "Admin shares disable failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }

            # Feature 3: Risky Ports + NetBIOS adapter hardening
            Write-Host "  Risky Ports Hardening..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            try {
                $riskyPortsResult = Disable-RiskyPorts `
                    -SkipUPnP:(-not $DisableUPnP) `
                    -SkipFirewallChanges:$SkipFirewallLayer

                if ($riskyPortsResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Risky Ports and NetBIOS"
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Risky Ports and NetBIOS"
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                $failedFeatures += "Risky Ports and NetBIOS"
                Write-Log -Level ERROR -Message "Risky ports/NetBIOS hardening failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
            }

            # Feature 4: Risky Network Services
            Write-Host "  Risky Services Stop..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            try {
                $riskyServicesResult = Stop-RiskyServices -SkipUPnP:(-not $DisableUPnP)

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

            # Feature 5: WPAD Disable
            Write-Host "  WPAD Disable..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            try {
                $wpadResult = Disable-WPAD -WinInetUsers @($advancedSecurityPreState.WinInetUsers)

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

            # Feature 6: Legacy TLS Disable
            Write-Host "  Legacy TLS 1.0/1.1 Disable..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

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

            # Feature 7: Finger Protocol
            Write-Host "  Finger Protocol Block..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            if ($SkipFirewallLayer) {
                Write-Host " SKIPPED" -ForegroundColor Cyan
                Write-Log -Level INFO -Message "Finger Protocol firewall rule skipped by explicit firewall-layer choice" -Module 'AdvancedSecurity'
            }
            else {
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
            }

            # Feature 9: Windows Update
            Write-Host "  Windows Update Config..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

            try {
                $wuResult = Set-WindowsUpdate -DryRun:$DryRun -ManagedPoliciesSupported:$managedPolicySupported -Configuration $windowsUpdateConfiguration

                if ($wuResult) {
                    Write-Host " OK" -ForegroundColor Green
                    $appliedFeatures += "Windows Update ($(if ($managedPolicySupported) { 3 } else { 1 }) applicable values)"
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

            # Feature 10: Wireless Display Security
            Write-Host "  Wireless Display Security..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)
            if (-not $wirelessDisplaySupported) {
                Write-Host " NOT APPLICABLE (edition)" -ForegroundColor Gray
                $skippedFeatures += 'Wireless Display Security (NotApplicable)'
            }
            else {
                try {
                    $wirelessDisplayResult = Set-WirelessDisplaySecurity -DisableCompletely:$DisableWirelessDisplayCompletely -SkipFirewallChanges:$SkipFirewallLayer

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
            }

            # Feature 11: Discovery Protocols (WS-Discovery + mDNS) - Maximum only
            if ($SecurityProfile -eq 'Maximum') {
                Write-Host "  Discovery Protocols (WS-Discovery + mDNS)..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

                try {
                    if ($DisableDiscoveryProtocolsCompletely) {
                        $discoveryResult = Set-DiscoveryProtocolsSecurity -DisableCompletely -SkipFirewallChanges:$SkipFirewallLayer

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
                        Write-Host " SKIPPED" -ForegroundColor Cyan
                    }
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    $failedFeatures += "Discovery Protocols (WS-Discovery + mDNS)"
                    Write-Log -Level ERROR -Message "Discovery protocol security failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
                }
            }

            # Feature 12: Firewall Shields Up (Maximum only)
            # Blocks unsolicited Public-profile inbound traffic, ignoring app exceptions.
            if ($SecurityProfile -eq 'Maximum') {
                Write-Host "  Firewall Shields Up (Public)..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

                if ($SkipFirewallLayer) {
                    Write-Host " SKIPPED" -ForegroundColor Cyan
                    Write-Log -Level INFO -Message "Firewall Shields Up skipped by explicit firewall-layer choice" -Module 'AdvancedSecurity'
                }
                else {
                    try {
                        $shieldsUpResult = Set-FirewallShieldsUp -Enable

                        if ($shieldsUpResult) {
                            Write-Host " OK" -ForegroundColor Green
                            $appliedFeatures += "Firewall Shields Up (Block unsolicited inbound traffic on Public)"
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
            }

            # Feature 13: IPv6 component-disable state (Maximum only, optional)
            if ($SecurityProfile -eq 'Maximum' -and $DisableIPv6Completely) {
                Write-Host "  IPv6 component disable (0xFF)..." -ForegroundColor White -NoNewline:(Test-NoIDPlainConsole)

                try {
                    $ipv6Result = Set-IPv6Security -DisableCompletely

                    if ($ipv6Result) {
                        Write-Host " OK (REBOOT REQUIRED)" -ForegroundColor Green
                        $appliedFeatures += "IPv6 component-disable state (0xFF)"
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
            Write-Host "[3/4] Checking..." -ForegroundColor Cyan

            $verificationSucceeded = $false
            $verifyResult = $null
            $settingsRuntimeNotChecked = 0
            if ($appliedFeatures.Count -gt 0) {
                try {
                    if (-not $SkipFirewallLayer) {
                        # Each firewall setter reconciles only its selected
                        # pair. Check the whole recoverable inventory once at
                        # the module boundary before accepting Apply.
                        $null = Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized
                    }
                    # One authoritative decision feeds target planning,
                    # accounting, verification, result export and durable
                    # intent. Never recompute it later from parallel logic.
                    $adminSharesDisabled = [bool]$adminSharesSelected
                    $verifyResult = Test-AdvancedSecurity `
                        -SecurityProfile $SecurityProfile `
                        -DisableRDP ([bool]$DisableRDP) `
                        -AdminSharesDisabled $adminSharesDisabled `
                        -DisableUPnP $DisableUPnP `
                        -DisableWirelessDisplayCompletely $DisableWirelessDisplayCompletely `
                        -DisableDiscoveryProtocolsCompletely $effectiveDiscoveryDisable `
                        -DisableIPv6Completely $effectiveIPv6Disable `
                        -SkipFirewallLayer:$SkipFirewallLayer `
                        -RdpHostSupported:$rdpHostSupported `
                        -ManagedPolicySupported:$managedPolicySupported `
                        -WirelessDisplaySupported:$wirelessDisplaySupported `
                        -WinInetUsers @($advancedSecurityPreState.WinInetUsers) `
                        -WindowsUpdateConfiguration $windowsUpdateConfiguration

                    $windowsUpdateVerification = @($verifyResult.Results | Where-Object {
                            [string]$_.Feature -eq 'Windows Update'
                        })
                    if ($windowsUpdateVerification.Count -ne 1) {
                        throw "AdvancedSecurity verification returned $($windowsUpdateVerification.Count) Windows Update result(s)"
                    }
                    if ($windowsUpdateVerification[0].PSObject.Properties['NotCheckedCount']) {
                        $settingsRuntimeNotChecked = [int]$windowsUpdateVerification[0].NotCheckedCount
                    }
                    if ($settingsRuntimeNotChecked -notin @(0, 1)) {
                        throw "AdvancedSecurity Windows Update NotChecked count is invalid: $settingsRuntimeNotChecked"
                    }

                    # Test-AdvancedSecurity prints the full result table and returns
                    # a structured object, so no second summary is printed here.
                    if ($verifyResult -and $verifyResult.Compliance -lt 100) {
                        # Log details to file for troubleshooting
                        Write-Log -Level WARNING -Message "Advanced Security Compliance: $($verifyResult.CompliantCount)/$($verifyResult.TotalChecks) passed ($($verifyResult.Compliance)%)" -Module "AdvancedSecurity"

                        if ($verifyResult.Results) {
                            foreach ($test in $verifyResult.Results) {
                                $isNotChecked = $test.PSObject.Properties.Name -contains 'CheckState' -and $test.CheckState -eq 'NotChecked'
                                if (-not $isNotChecked -and -not $test.Compliant) {
                                    Write-Log -Level WARNING -Message "  [NON-COMPLIANT] $($test.Feature): $($test.Status) - $($test.Details)" -Module "AdvancedSecurity"
                                }
                            }
                        }

                        Write-Host ""
                        Write-Host "  Note: $($verifyResult.TotalChecks - $verifyResult.CompliantCount) check(s) failed" -ForegroundColor Yellow
                        Write-Host "  Module result is FAILED until these checks pass" -ForegroundColor Red
                        $failedFeatures += 'Compliance Verification'
                    }
                    elseif ($verifyResult) {
                        Write-Log -Level SUCCESS -Message "All applicable selected AdvancedSecurity checks passed" -Module "AdvancedSecurity"
                        if (Test-NoIDPlainConsole) {
                            Write-Host "  $($verifyResult.CompliantCount) passed, 0 failed" -ForegroundColor Green
                        }
                        $verificationSucceeded = $true
                    }
                    else {
                        Write-Log -Level ERROR -Message "Advanced Security verification returned no result" -Module "AdvancedSecurity"
                        $failedFeatures += 'Compliance Verification'
                    }
                }
                catch {
                    Write-Host "  Verification FAILED: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level ERROR -Message "Advanced Security verification failed: $_" -Module 'AdvancedSecurity' -Exception $_.Exception
                    $failedFeatures += 'Compliance Verification'
                }
            }
            else {
                Write-Host "  FAILED (no features were applied)" -ForegroundColor Red
                $failedFeatures += 'Compliance Verification'
            }

            # Repeat controller detection at runtime. This catches a controller
            # installed or started after the initial selection and also runs on
            # every future Test-AdvancedSecurity invocation.
            $null = Write-FirewallControllerRuntimeWarning -FirewallLayerSkipped $SkipFirewallLayer
            Write-Host ""

            # PHASE 4: COMPLETE
            Write-Host "[4/4] Done" -ForegroundColor Cyan
            Write-NoIDDetail ""

            # The framework prints the module result line; the feature tally is log detail.
            Write-NoIDDetail "Profile:       $SecurityProfile" -ForegroundColor White
            # Denominator = applied + failed, so the ratio reflects features actually attempted in this profile
            # (Maximum-only options aren't counted against Balanced/Enterprise runs).
            $featuresAttempted = $appliedFeatures.Count + $failedFeatures.Count
            Write-NoIDDetail "Features:      $($appliedFeatures.Count)/$featuresAttempted applied" -ForegroundColor $(if ($failedFeatures.Count -eq 0) { 'Green' } else { 'Yellow' })

            if ($failedFeatures.Count -gt 0) {
                Write-Host "  Failed:  $($failedFeatures.Count) ($($failedFeatures -join ', '))" -ForegroundColor Red
            }
            if ($skippedFeatures.Count -gt 0) {
                Write-Host "  Skipped: $($skippedFeatures.Count) ($($skippedFeatures -join ', '))" -ForegroundColor Cyan
            }

            Write-NoIDDetail ""
            # Only claim a reboot for changes that were actually applied this run
            # (Admin Shares can be skipped by domain safety; IPv6 0xFF is Maximum-only).
            # SChannel protocol changes reach processes that already hold TLS
            # credential handles only after they restart (Microsoft TLS registry
            # settings documentation), so a restart is the reliable activation.
            $rebootReasons = @()
            if ($appliedFeatures -contains 'Admin Shares Disable') { $rebootReasons += 'Admin Shares' }
            if ($appliedFeatures -contains 'Legacy TLS Disable') { $rebootReasons += 'Legacy TLS' }
            if ($appliedFeatures -contains 'IPv6 component-disable state (0xFF)') { $rebootReasons += 'IPv6 component disable' }
            if ($rebootReasons.Count -gt 0) {
                Write-Host "  Restart Windows to complete: $($rebootReasons -join ', ')" -ForegroundColor Cyan
            }
            Write-Host ""

            $hasFailures = ($failedFeatures.Count -gt 0) -or (-not $verificationSucceeded)
            if ($hasFailures) {
                Write-Log -Level ERROR -Message "Advanced Security hardening did not complete successfully: $($failedFeatures.Count) failed feature/check(s)" -Module "AdvancedSecurity"
            }
            else {
                Write-Log -Level SUCCESS -Message "Advanced Security hardening completed: $($appliedFeatures.Count) features applied" -Module "AdvancedSecurity"
            }

            # GUI parsing marker -- count derived from Config/SettingsCounts.json (single source of truth).
            $settingsAttempted = [int]$decisionAccounting.Attempted
            $settingsSkipped = [int]$decisionAccounting.Skipped
            $settingsNotApplicable = [int]$decisionAccounting.NotApplicable
            $settingsNotSelected = [int]$decisionAccounting.NotSelected
            $settingsRuntimeNotApplicable = [int]$decisionAccounting.RuntimeNotApplicable
            $settingsApplied = if ($hasFailures) { 0 } else { $settingsAttempted - $settingsRuntimeNotChecked }
            if (-not $hasFailures -and
                ($settingsApplied -lt 0 -or
                    ($settingsApplied + $settingsRuntimeNotChecked + $settingsSkipped +
                        $settingsNotApplicable + $settingsNotSelected) -ne $expectedCount)) {
                throw "AdvancedSecurity final setting accounting does not reconcile: applied=$settingsApplied, notChecked=$settingsRuntimeNotChecked, skipped=$settingsSkipped, notApplicable=$settingsNotApplicable, notSelected=$settingsNotSelected, declared=$expectedCount"
            }
            if ($hasFailures) {
                Write-Log -Level ERROR -Message "Applied-settings count not asserted because AdvancedSecurity apply/verification failed; attempted=$settingsAttempted, firewallSkipped=$settingsSkipped, notApplicable=$settingsNotApplicable, notSelected=$settingsNotSelected" -Module 'AdvancedSecurity'
            }
            else {
                Write-Log -Level SUCCESS -Message "Applied $settingsApplied settings" -Module "AdvancedSecurity"
            }
            if ($settingsSkipped -gt 0) {
                Write-Log -Level INFO -Message "Windows Firewall layer skipped by your choice: $settingsSkipped settings left unchanged" -Module 'AdvancedSecurity'
            }
            # $settingsNotApplicable is the COMBINED total that the result object
            # exports; only the edition-sourced share belongs on this line.
            $settingsEditionNotApplicable = [int]$decisionAccounting.EditionNotApplicable
            if ($settingsEditionNotApplicable -gt 0) {
                Write-Log -Level INFO -Message "Not applicable on Windows $($applicability.EditionFamily): $settingsEditionNotApplicable settings" -Module 'AdvancedSecurity'
            }
            if ($settingsRuntimeNotApplicable -gt 0) {
                Write-Log -Level INFO -Message "Not applicable on this PC (the Windows feature is not present): $settingsRuntimeNotApplicable settings" -Module 'AdvancedSecurity'
            }
            if ($settingsNotSelected -gt 0) {
                Write-Log -Level INFO -Message "Not part of the chosen profile: $settingsNotSelected settings" -Module 'AdvancedSecurity'
            }
            if ($settingsRuntimeNotChecked -gt 0) {
                Write-Log -Level INFO -Message "Kept $settingsRuntimeNotChecked of your own Windows Settings choices unchanged" -Module 'AdvancedSecurity'
            }

            # Return structured result object
            return [PSCustomObject]@{
                Success         = -not $hasFailures
                SecurityProfile = $SecurityProfile
                SkipFirewallLayer = [bool]$SkipFirewallLayer
                DisableRDP = [bool]$DisableRDP
                AdminSharesDisabled = [bool]$adminSharesSelected
                DisableUPnP = [bool]$DisableUPnP
                DisableWirelessDisplayCompletely = [bool]$DisableWirelessDisplayCompletely
                DisableDiscoveryProtocolsCompletely = [bool]$effectiveDiscoveryDisable
                DisableIPv6Completely = [bool]$effectiveIPv6Disable
                EnableFirewallShieldsUp = [bool]$enableFirewallShieldsUp
                FeaturesApplied = $appliedFeatures
                FeaturesFailed  = $failedFeatures
                FeaturesSkipped = $skippedFeatures
                TotalFeatures   = $appliedFeatures.Count + $failedFeatures.Count + $skippedFeatures.Count
                FirewallLayer   = $(if ($SkipFirewallLayer) { 'Skipped' } else { 'Applied' })
                SettingsApplied = $settingsApplied
                SettingsSkipped = $settingsSkipped
                SettingsNotApplicable = $settingsNotApplicable
                SettingsRuntimeNotApplicable = $settingsRuntimeNotApplicable
                SettingsNotChecked = $settingsRuntimeNotChecked
                SettingsNotSelected = $settingsNotSelected
                SettingsAttempted = $settingsAttempted
                Verification    = $verifyResult
                Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                # A later failure does not undo a completed restart-dependent
                # change. Keep this result consistent with the console notice.
                RebootRequired  = ($rebootReasons.Count -gt 0)
            }
        }
        else {
            Write-Host "WhatIf mode - no changes applied" -ForegroundColor Cyan
            Write-Host ""
            return [PSCustomObject]@{
                Success         = [bool]$DryRun
                Status          = $(if ($DryRun) { 'DryRun' } else { 'NotConfirmed' })
                SecurityProfile = $SecurityProfile
                SkipFirewallLayer = [bool]$SkipFirewallLayer
                DisableRDP = [bool]$DisableRDP
                AdminSharesDisabled = [bool]$adminSharesSelected
                DisableUPnP = [bool]$DisableUPnP
                DisableWirelessDisplayCompletely = [bool]$DisableWirelessDisplayCompletely
                DisableDiscoveryProtocolsCompletely = [bool]$effectiveDiscoveryDisable
                DisableIPv6Completely = [bool]$effectiveIPv6Disable
                EnableFirewallShieldsUp = [bool]$enableFirewallShieldsUp
                FirewallLayer   = $(if ($SkipFirewallLayer) { 'Skipped' } else { 'WouldApply' })
                Mode            = 'WhatIf'
                SettingsDeclared = [int]$decisionAccounting.Declared
                SettingsApplied = 0
                SettingsPreviewed = [int]$decisionAccounting.Attempted
                SettingsSkipped = [int]$decisionAccounting.Skipped
                SettingsNotApplicable = [int]$decisionAccounting.NotApplicable
                SettingsRuntimeNotApplicable = [int]$decisionAccounting.RuntimeNotApplicable
                SettingsNotSelected = [int]$decisionAccounting.NotSelected
                RegistryTargetsPreviewed = $previewRegistryTargets.Count
                ChangesMade     = 0
                Verification    = $null
                RebootRequired  = $false
                Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Advanced Security hardening failed: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        if (-not $DryRun -and [string]$global:CurrentModule -eq 'AdvancedSecurity') {
            try {
                if (-not (Save-IncompleteModuleBackup -ModuleName 'AdvancedSecurity' -Confirm:$false)) {
                    Write-Log -Level ERROR -Message 'Failed to retain/classify the incomplete AdvancedSecurity backup' -Module 'AdvancedSecurity'
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Incomplete AdvancedSecurity backup retention failed: $($_.Exception.Message)" -Module 'AdvancedSecurity'
            }
        }
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
