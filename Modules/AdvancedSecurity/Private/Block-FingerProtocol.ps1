function Block-FingerProtocol {
    <#
    .SYNOPSIS
        Blocks outbound connections to TCP Port 79 (Finger protocol) via Windows Firewall

    .DESCRIPTION
        Creates the canonical Windows Firewall rule that blocks outbound TCP port 79.
        This removes one documented finger.exe command-retrieval path; it does
        not prevent ClickFix campaigns that use another executable, port or protocol.

        THREAT: ClickFix attacks use finger.exe to retrieve commands from remote servers
        on port 79, which are then piped to cmd.exe for execution.

        SCOPE: Exact outbound TCP/79 firewall state only.

    .PARAMETER DryRun
        Preview changes without applying them

    .EXAMPLE
        Block-FingerProtocol
        Blocks outbound finger protocol connections

    .NOTES
        Author: NexusOne23
        Version: 2.2.5
        Requires: Administrator privileges

        REFERENCES:
        - https://www.bleepingcomputer.com/news/security/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/
        - https://redteamnews.com/threat-intelligence/clickfix-malware-campaigns-resurrect-decades-old-finger-protocol-for-command-retrieval/
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Block FingerProtocol')) {
        return
    }


    try {
        $definition = @(Get-AdvancedSecurityFirewallDefinitions -Feature Finger)
        if ($definition.Count -ne 1) { throw "Expected one canonical Finger firewall rule, found $($definition.Count)" }
        $definition = $definition[0]

        Write-Log -Level INFO -Message "Checking for existing Finger protocol block rule..." -Module "AdvancedSecurity"

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would create or normalize the outbound TCP 79 block rule" -Module "AdvancedSecurity"
            return $true
        }

        Write-Log -Level INFO -Message "Creating Windows Firewall rule to block outbound finger protocol (TCP 79)..." -Module "AdvancedSecurity"
        $ruleApplied = Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition

        if ($ruleApplied) {
            Write-Log -Level SUCCESS -Message "Finger protocol (TCP port 79) outbound connections blocked" -Module "AdvancedSecurity"
            Write-Log -Level INFO -Message "Exact outbound TCP/79 rule verified; alternative malware paths are outside this control" -Module "AdvancedSecurity"

            Write-Host ""
            Write-Host "Firewall Rule Created:" -ForegroundColor Green
            Write-Host "Name: $($definition.DisplayName)" -ForegroundColor Gray
            Write-Host "Blocks: Outbound TCP port 79 (Finger protocol)" -ForegroundColor Gray
            Write-Host "Scope: Outbound TCP/79 only; other command-retrieval paths are not covered" -ForegroundColor Gray
            Write-Host ""

            return $true
        }
        else {
            Write-Log -Level ERROR -Message "Firewall rule creation failed - verification unsuccessful" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create finger protocol block rule: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
