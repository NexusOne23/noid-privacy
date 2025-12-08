function Test-RiskyPorts {
    <#
    .SYNOPSIS
        Test risky firewall ports compliance
    
    .DESCRIPTION
        Checks if risky firewall ports (LLMNR, NetBIOS, UPnP/SSDP) are closed
    
    .EXAMPLE
        Test-RiskyPorts
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = [PSCustomObject]@{
            Feature       = "Risky Firewall Ports"
            Status        = "Unknown"
            Details       = @()
            OpenPorts     = @()
            DisabledRules = 0
            EnabledRules  = 0
            Compliant     = $false
        }
        
        $riskyPorts = @(5355, 137, 138, 139, 1900, 2869)
        
        # Detect NoID SSDP firewall block rule for UDP 1900
        $ssdpRuleName = "NoID Privacy - Block SSDP (UDP 1900)"
        $ssdpBlockRule = Get-NetFirewallRule -DisplayName $ssdpRuleName -ErrorAction SilentlyContinue
        $ssdpBlockActive = $false
        if ($ssdpBlockRule -and $ssdpBlockRule.Enabled -eq 'True' -and $ssdpBlockRule.Action -eq 'Block') {
            $ssdpBlockActive = $true
        }
        
        # PERFORMANCE FIX: Batch query instead of per-rule queries
        # Old approach: Get-NetFirewallRule | ForEach { Get-NetFirewallPortFilter } = 300 queries × 200ms = 60s!
        # New approach: Get all port filters once, then filter = 2-3s total
        
        # Get all inbound firewall rules (pre-filter by direction)
        $inboundRules = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue
        
        # Get all port filters in one batch query
        $allPortFilters = @{}
        Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $allPortFilters[$_.InstanceID] = $_
        }
        
        # Now filter rules by risky ports (fast lookup)
        $riskyRules = $inboundRules | Where-Object {
            $portFilter = $allPortFilters[$_.InstanceID]
            if ($portFilter) {
                ($portFilter.LocalPort -in $riskyPorts) -or ($portFilter.RemotePort -in $riskyPorts)
            }
            else {
                $false
            }
        }
        
        foreach ($rule in $riskyRules) {
            if ($rule.Enabled -eq $true) {
                $portFilter = $allPortFilters[$rule.InstanceID]

                if ($rule.Action -eq 'Allow') {
                    $result.EnabledRules++
                    $result.Details += "WARNING: Allow rule '$($rule.DisplayName)' is ENABLED (Port: $($portFilter.LocalPort))"
                }
                else {
                    $result.Details += "INFO: Block rule '$($rule.DisplayName)' is ENABLED (Port: $($portFilter.LocalPort))"
                }
            }
            else {
                $result.DisabledRules++
            }
        }
        
        # Check actual port listeners
        foreach ($port in $riskyPorts) {
            if ($port -in @(137, 138, 139, 2869)) {
                # TCP ports
                $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                if ($listener) {
                    $result.OpenPorts += "TCP $port"
                    $result.Details += "OPEN: TCP port $port is LISTENING!"
                }
            }
            else {
                # UDP ports (5355, 1900)
                $listener = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue
                if ($listener) {
                    $result.OpenPorts += "UDP $port"
                    $result.Details += "OPEN: UDP port $port is LISTENING!"
                }
            }
        }
        
        # Determine compliance
        $udp1900Open = $result.OpenPorts -contains "UDP 1900"
        $otherOpenPorts = $result.OpenPorts | Where-Object { $_ -ne "UDP 1900" }

        if ($result.OpenPorts.Count -eq 0 -and $result.EnabledRules -eq 0) {
            # Ideal case: no listeners and no allow rules
            $result.Status = "Secure"
            $result.Compliant = $true
            $result.Details += "All risky ports closed and firewall rules disabled"
        }
        elseif ($udp1900Open -and -not $otherOpenPorts -and $result.EnabledRules -eq 0 -and $ssdpBlockActive) {
            # Only open endpoint is UDP 1900, but protected by NoID block rule (inbound)
            $result.Status = "Secure (blocked by firewall)"
            $result.Compliant = $true
            $result.Details += "UDP 1900 is listening locally but inbound traffic is blocked by '$ssdpRuleName'"
        }
        elseif ($result.OpenPorts.Count -eq 0 -and $result.EnabledRules -gt 0) {
            $result.Status = "Partially Secure"
            $result.Compliant = $false
            $result.Details += "Ports closed but $($result.EnabledRules) firewall rules still enabled"
        }
        else {
            $result.Status = "Insecure"
            $result.Compliant = $false
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test risky ports: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature   = "Risky Firewall Ports"
            Status    = "Error"
            Details   = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
