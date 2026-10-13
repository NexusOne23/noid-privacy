function Disable-RiskyPorts {
    <#
    .SYNOPSIS
        Enforces explicit inbound block rules for risky Windows 11 ports.

    .DESCRIPTION
        Creates or normalizes stable, module-owned block rules for LLMNR and
        NetBIOS. UPnP/SSDP rules are included only when the user selected that
        hardening. Existing Windows/vendor allow rules are not broadly disabled;
        Windows Firewall gives an explicit matching block rule precedence, and
        the complete firewall policy is covered by the sealed BAVR artifact.

    .PARAMETER SkipUPnP
        Preserve UPnP/SSDP firewall behavior for DLNA/device-discovery use.

    .PARAMETER SkipFirewallChanges
        Preserve all Windows Firewall state while still disabling NetBIOS over
        TCP/IP on every active configuration and present physical adapter.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$SkipUPnP,
        [switch]$SkipFirewallChanges
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enforce risky-port firewall blocks')) { return }

    try {
        $ruleDefinitions = @(Get-AdvancedSecurityFirewallDefinitions -Feature RiskyPorts |
            Where-Object { -not $SkipUPnP -or $_.Group -ne 'UPnP' })

        if ($SkipFirewallChanges) {
            Write-Log -Level INFO -Message 'Risky-port firewall rules skipped by explicit firewall-layer choice; NetBIOS adapter hardening continues' -Module 'AdvancedSecurity'
        }
        else {
            foreach ($definition in $ruleDefinitions) {
                $null = Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition
            }
        }

        $netbiosState = Invoke-AdvancedSecurityNetBIOSDisable

        $verifiedRuleCount = if ($SkipFirewallChanges) { 0 } else { $ruleDefinitions.Count }
        Write-Log -Level SUCCESS -Message "Verified $verifiedRuleCount explicit risky-port block rules and $(@($netbiosState.Adapters).Count) NetBIOS adapter state(s)" -Module 'AdvancedSecurity'
        if ($SkipUPnP) {
            Write-Log -Level INFO -Message 'UPnP/SSDP firewall rules preserved by explicit user choice' -Module 'AdvancedSecurity'
        }
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Risky-port hardening failed: $($_.Exception.Message)" -Module 'AdvancedSecurity' -Exception $_.Exception
        return $false
    }
}
