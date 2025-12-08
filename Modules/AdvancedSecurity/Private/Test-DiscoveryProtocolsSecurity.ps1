function Test-DiscoveryProtocolsSecurity {
    <#
    .SYNOPSIS
        Tests WS-Discovery and mDNS hardening state.

    .DESCRIPTION
        Verifies that the following conditions are met:
        - OS-level mDNS resolver disabled (EnableMDNS = 0)
        - FDResPub and fdPHost services disabled and not running
        - NoID firewall BLOCK rules for WS-Discovery and mDNS exist and are enabled

        Returns a PSCustomObject with detailed fields and an overall Compliant flag.
    
    .EXAMPLE
        Test-DiscoveryProtocolsSecurity
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        EnableMDNS                     = $null
        FDResPubDisabled               = $false
        FdPHostDisabled                = $false
        FirewallRulesPresent           = $false
        FirewallRulesEnabled           = $false
        Udp3702ListenersClosed         = $null
        Udp5353ListenersClosed         = $null
        Tcp5357ListenersClosed         = $null
        Tcp5358ListenersClosed         = $null
        Compliant                      = $false
    }

    try {
        # 1) Check mDNS registry flag
        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (Test-Path $dnsParamsPath) {
            $props = Get-ItemProperty -Path $dnsParamsPath -ErrorAction SilentlyContinue
            if ($props.PSObject.Properties.Name -contains 'EnableMDNS') {
                $result.EnableMDNS = $props.EnableMDNS
            }
        }

        # 2) Check services
        $fdResPub = Get-Service -Name "FDResPub" -ErrorAction SilentlyContinue
        if ($fdResPub) {
            $result.FDResPubDisabled = ($fdResPub.StartType -eq 'Disabled' -and $fdResPub.Status -ne 'Running')
        }

        $fdPHost = Get-Service -Name "fdPHost" -ErrorAction SilentlyContinue
        if ($fdPHost) {
            $result.FdPHostDisabled = ($fdPHost.StartType -eq 'Disabled' -and $fdPHost.Status -ne 'Running')
        }

        # 3) Check firewall rules
        $ruleNames = @(
            "NoID-Block-WSD-UDP-3702",
            "NoID-Block-WSD-TCP-5357",
            "NoID-Block-WSD-TCP-5358",
            "NoID-Block-mDNS-UDP-5353"
        )

        $rules = @()
        foreach ($name in $ruleNames) {
            $r = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            if ($r) {
                $rules += $r
            }
        }

        if ($rules.Count -gt 0) {
            $result.FirewallRulesPresent = ($rules.Count -eq $ruleNames.Count)
            $result.FirewallRulesEnabled = ($rules | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }).Count -eq $ruleNames.Count
        }

        # 4) Optional: check that ports are not listening
        try {
            $udp3702 = Get-NetUDPEndpoint -LocalPort 3702 -ErrorAction SilentlyContinue
            $result.Udp3702ListenersClosed = (-not $udp3702)
        }
        catch {
            $result.Udp3702ListenersClosed = $null
        }

        try {
            $udp5353 = Get-NetUDPEndpoint -LocalPort 5353 -ErrorAction SilentlyContinue
            $result.Udp5353ListenersClosed = (-not $udp5353)
        }
        catch {
            $result.Udp5353ListenersClosed = $null
        }

        try {
            $tcp5357 = Get-NetTCPConnection -LocalPort 5357 -State Listen -ErrorAction SilentlyContinue
            $result.Tcp5357ListenersClosed = (-not $tcp5357)
        }
        catch {
            $result.Tcp5357ListenersClosed = $null
        }

        try {
            $tcp5358 = Get-NetTCPConnection -LocalPort 5358 -State Listen -ErrorAction SilentlyContinue
            $result.Tcp5358ListenersClosed = (-not $tcp5358)
        }
        catch {
            $result.Tcp5358ListenersClosed = $null
        }

        # Overall compliance: mDNS disabled, services disabled, firewall rules present+enabled
        $mdnsOk = ($result.EnableMDNS -eq 0)
        $servicesOk = $result.FDResPubDisabled -and $result.FdPHostDisabled
        $firewallOk = $result.FirewallRulesPresent -and $result.FirewallRulesEnabled

        $result.Compliant = $mdnsOk -and $servicesOk -and $firewallOk

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test discovery protocol security (WS-Discovery/mDNS): $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $result
    }
}
