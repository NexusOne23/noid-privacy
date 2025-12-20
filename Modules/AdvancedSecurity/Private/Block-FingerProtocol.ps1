function Block-FingerProtocol {
    <#
    .SYNOPSIS
        Blocks outbound connections to TCP Port 79 (Finger protocol) via Windows Firewall
        
    .DESCRIPTION
        Creates a Windows Firewall rule to block all outbound connections to TCP port 79,
        preventing abuse of the finger.exe command in ClickFix malware campaigns.
        
        THREAT: ClickFix attacks use finger.exe to retrieve commands from remote servers
        on port 79, which are then piped to cmd.exe for execution.
        
        MITIGATION: Block outbound port 79 to prevent finger.exe from reaching C2 servers.
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .EXAMPLE
        Block-FingerProtocol
        Blocks outbound finger protocol connections
        
    .NOTES
        Author: NexusOne23
        Version: 2.2.1
        Requires: Administrator privileges
        
        REFERENCES:
        - https://www.bleepingcomputer.com/news/security/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/
        - https://redteamnews.com/threat-intelligence/clickfix-malware-campaigns-resurrect-decades-old-finger-protocol-for-command-retrieval/
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $ruleName = "NoID Privacy - Block Finger Protocol (Port 79)"
        
        Write-Log -Level INFO -Message "Checking for existing Finger protocol block rule..." -Module "AdvancedSecurity"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log -Level INFO -Message "Finger protocol block rule already exists" -Module "AdvancedSecurity"
            
            # Show user that protection is already active
            Write-Host ""
            Write-Host "Finger Protocol Block: Already Protected" -ForegroundColor Green
            Write-Host "  Rule: $ruleName" -ForegroundColor Gray
            Write-Host "  Status: Active (Outbound TCP port 79 blocked)" -ForegroundColor Gray
            Write-Host "  Protection: ClickFix malware using finger.exe" -ForegroundColor Gray  
            Write-Host ""
            
            return $true
        }
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would create firewall rule to block outbound TCP port 79" -Module "AdvancedSecurity"
            return $true
        }
        
        Write-Log -Level INFO -Message "Creating Windows Firewall rule to block outbound finger protocol (TCP 79)..." -Module "AdvancedSecurity"
        
        # Create outbound firewall rule
        $ruleParams = @{
            DisplayName   = $ruleName
            Description   = "Blocks outbound connections to TCP port 79 (Finger protocol) to prevent ClickFix malware attacks. The finger.exe command is abused to retrieve malicious commands from remote servers."
            Direction     = "Outbound"
            Action        = "Block"
            Protocol      = "TCP"
            RemotePort    = 79
            Profile       = "Any"
            Enabled       = "True"
            ErrorAction   = "Stop"
        }
        
        New-NetFirewallRule @ruleParams | Out-Null
        
        # Verify rule was created
        $verifyRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($verifyRule) {
            Write-Log -Level SUCCESS -Message "Finger protocol (TCP port 79) outbound connections blocked" -Module "AdvancedSecurity"
            Write-Log -Level INFO -Message "ClickFix malware campaigns using finger.exe are now mitigated" -Module "AdvancedSecurity"
            
            Write-Host ""
            Write-Host "Firewall Rule Created:" -ForegroundColor Green
            Write-Host "Name: $ruleName" -ForegroundColor Gray
            Write-Host "Blocks: Outbound TCP port 79 (Finger protocol)" -ForegroundColor Gray
            Write-Host "Protection: ClickFix malware using finger.exe" -ForegroundColor Gray
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
