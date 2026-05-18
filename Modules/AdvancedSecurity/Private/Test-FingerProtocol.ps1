function Test-FingerProtocol {
    <#
    .SYNOPSIS
        Test if Finger Protocol (TCP 79) is blocked
    
    .DESCRIPTION
        Verifies that the Windows Firewall rule blocking outbound TCP port 79 
        is present and enabled. This prevents ClickFix malware attacks that 
        abuse finger.exe to retrieve commands from C2 servers.
        
    .OUTPUTS
        PSCustomObject with compliance result
    #>
    [CmdletBinding()]
    param()
    
    try {
        $ruleName = "NoID Privacy - Block Finger Protocol (Port 79)"
        
        # Check if firewall rule exists and is enabled
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($rule) {
            $isEnabled = $rule.Enabled -eq 'True'
            $isBlocking = $rule.Action -eq 'Block'
            $isOutbound = $rule.Direction -eq 'Outbound'
            
            $compliant = $isEnabled -and $isBlocking -and $isOutbound
            
            if ($compliant) {
                $status = "Finger Protocol blocked (TCP 79 outbound)"
            }
            else {
                $status = "Rule exists but misconfigured (Enabled: $isEnabled, Block: $isBlocking, Outbound: $isOutbound)"
            }
        }
        else {
            $compliant = $false
            $status = "Firewall rule not found"
        }
        
        return [PSCustomObject]@{
            Feature   = "Finger Protocol Block"
            Compliant = $compliant
            Status    = $status
            Details   = if ($rule) { "Rule: $ruleName" } else { "ClickFix malware protection not active" }
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature   = "Finger Protocol Block"
            Compliant = $false
            Status    = "Error checking: $($_.Exception.Message)"
            Details   = $null
        }
    }
}
