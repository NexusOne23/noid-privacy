function Disable-AdminShares {
    <#
    .SYNOPSIS
        Disable administrative shares (C$, ADMIN$, etc.) to prevent lateral movement

    .DESCRIPTION
        Disables automatic creation of administrative shares after reboot.
        Existing system-managed shares are intentionally left untouched so exact
        BAVR never attempts to reconstruct their special Windows state.
        Administrative shares (C$, D$, ADMIN$) are used by attackers for:
        - Lateral movement (WannaCry, NotPetya propagation)
        - Remote file access with stolen credentials
        - Pass-the-Hash attacks
        - Automated malware propagation

        CRITICAL: Includes domain-safety check. On domain-joined systems, admin shares
        are often required for Group Policy, SCCM, and remote management tools.

        REQUIRES REBOOT to prevent share recreation.

    .PARAMETER Force
        Force disable even on domain-joined systems (NOT RECOMMENDED for enterprise!)

    .PARAMETER SkipFirewallChanges
        Applies the registry/share hardening but does not create or modify the
        Windows Firewall rule. Used only after an explicit firewall-layer skip.

    .EXAMPLE
        Disable-AdminShares
        Disables admin shares with domain-safety check

    .EXAMPLE
        Disable-AdminShares -Force
        Forces disable even on domain-joined systems (DANGEROUS!)

    .NOTES
        Impact:
        - Home/Workgroup: Highly recommended
        - Enterprise Domain: May break management tools - TEST FIRST!
        - IPC$ is not targeted (required by Windows)

        System-managed drive/ADMIN$ shares are suppressed after reboot while
        the policy values remain 0.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$SkipFirewallChanges
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable AdminShares')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Configuring administrative shares disable..." -Module "AdvancedSecurity"

        # CRITICAL: Check if system is domain-joined
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        if ($computerSystem.PartOfDomain -and -not $Force) {
            Write-Log -Level WARNING -Message "Domain-joined system detected. Admin shares disable SKIPPED." -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "Admin shares are often required for:" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - Group Policy management" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - SCCM/Management tools" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - Remote administration" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "Use -Force to override (NOT RECOMMENDED!)" -Module "AdvancedSecurity"

            Write-Host ""
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host "  DOMAIN-JOINED SYSTEM DETECTED" -ForegroundColor Yellow
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Administrative shares are often required for:" -ForegroundColor White
            Write-Host "  - Group Policy remote management" -ForegroundColor Gray
            Write-Host "  - SCCM and other management tools" -ForegroundColor Gray
            Write-Host "  - Remote administration via WMI/PowerShell" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Skipping admin shares disable to prevent breakage." -ForegroundColor Green
            Write-Host "Use -DisableAdminShares -Force to override (NOT RECOMMENDED)." -ForegroundColor Red
            Write-Host ""

            return $false  # Caller must report this as skipped, never applied.
        }

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

        # Disable automatic creation
        Write-Log -Level INFO -Message "Disabling automatic administrative share creation..." -Module "AdvancedSecurity"

        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }

        # Disable for Workstation (Home/Pro)
        Remove-ItemProperty -LiteralPath $regPath -Name 'AutoShareWks' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $regPath -Name 'AutoShareWks' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level SUCCESS -Message "Disabled AutoShareWks (Workstation shares)" -Module "AdvancedSecurity"

        # Disable for Server editions
        Remove-ItemProperty -LiteralPath $regPath -Name 'AutoShareServer' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $regPath -Name 'AutoShareServer' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level SUCCESS -Message "Disabled AutoShareServer (Server edition shares)" -Module "AdvancedSecurity"

        # Do not remove live administrative shares. Recreating C$/ADMIN$ with
        # New-SmbShare cannot reproduce their system-managed security descriptor
        # and special semantics exactly. The policy takes effect after reboot;
        # until then verification reports Pending Reboot. This keeps BAVR exact.
        Write-Log -Level INFO -Message 'Live administrative shares were left untouched; automatic-share policy takes effect after reboot' -Module 'AdvancedSecurity'

        if ($SkipFirewallChanges) {
            Write-Log -Level INFO -Message "SMB Public-profile firewall rule skipped by explicit firewall-layer choice" -Module "AdvancedSecurity"
        }
        else {
            # Add firewall protection for Public networks.
            Write-Log -Level INFO -Message "Adding firewall protection for SMB on Public networks..." -Module "AdvancedSecurity"

            $adminFirewallDefinition = @(Get-AdvancedSecurityFirewallDefinitions -Feature AdminShares)
            if ($adminFirewallDefinition.Count -ne 1) {
                throw "Expected one canonical admin-share firewall rule, found $($adminFirewallDefinition.Count)"
            }
            $null = Set-AdvancedSecurityFirewallRuleDefinition -Definition $adminFirewallDefinition[0]

            Write-Log -Level SUCCESS -Message "Firewall rule verified: Block SMB (port 445) on Public networks" -Module "AdvancedSecurity"
        }

        $lanmanKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
        foreach ($name in @('AutoShareWks', 'AutoShareServer')) {
            if ($lanmanKey.GetValueKind($name).ToString() -ne 'DWord' -or [int]$lanmanKey.GetValue($name) -ne 0) {
                throw "Admin-share registry post-apply mismatch: $name"
            }
        }

        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  ADMINISTRATIVE SHARES DISABLED" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Registry settings:" -ForegroundColor White
        Write-Host "  AutoShareWks:    0 (Disabled)" -ForegroundColor Gray
        Write-Host "  AutoShareServer: 0 (Disabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Live shares:     Unchanged until reboot (exact BAVR boundary)" -ForegroundColor White
        if ($SkipFirewallChanges) {
            Write-Host "Firewall:        Skipped by explicit choice" -ForegroundColor Yellow
        }
        else {
            Write-Host "Firewall:        SMB blocked on Public networks" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "IMPORTANT: REBOOT REQUIRED" -ForegroundColor Yellow

        Write-Host "Automatically managed C$/ADMIN$ shares will not be recreated after reboot." -ForegroundColor Green
        Write-Host ""
        Write-Host "Note: IPC$ cannot be removed (required by Windows)" -ForegroundColor Gray
        Write-Host "Note: Explicit file shares will still work" -ForegroundColor Gray
        Write-Host ""

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable administrative shares: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
