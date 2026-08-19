function Test-DiscoveryProtocolsSecurity {
    <#
    .SYNOPSIS
        Tests WS-Discovery and mDNS hardening state.

    .DESCRIPTION
        Verifies that the following conditions are met:
        - OS-level mDNS resolver disabled (EnableMDNS = 0)
        - FDResPub and fdPHost services disabled and not running
        - NoID Privacy firewall BLOCK rules for WS-Discovery and mDNS exist and are enabled

        Returns a PSCustomObject with detailed fields and an overall Compliant flag.

    .EXAMPLE
        Test-DiscoveryProtocolsSecurity
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipFirewallChecks
    )

    $result = [PSCustomObject]@{
        EnableMDNS                     = $null
        EnableMDNSType                 = $null
        FDResPubDisabled               = $false
        FdPHostDisabled                = $false
        FirewallRulesPresent           = $false
        FirewallRulesEnabled           = $false
        FirewallChecksSkipped          = [bool]$SkipFirewallChecks
        Udp3702ListenersClosed         = $null
        Udp5353ListenersClosed         = $null
        Tcp5357ListenersClosed         = $null
        Tcp5358ListenersClosed         = $null
        Compliant                      = $false
        Pass                           = $false
        NotApplicable                  = $false
    }

    try {
        # 1) Check mDNS registry flag
        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (Test-Path -LiteralPath $dnsParamsPath -PathType Container -ErrorAction Stop) {
            $dnsKey = Get-Item -LiteralPath $dnsParamsPath -ErrorAction Stop
            if ($dnsKey.GetValueNames() -contains 'EnableMDNS') {
                $result.EnableMDNS = $dnsKey.GetValue('EnableMDNS')
                $result.EnableMDNSType = $dnsKey.GetValueKind('EnableMDNS').ToString()
            }
        }

        # 2) Check services
        $installedServices = @(Get-Service -ErrorAction Stop)
        $fdResPubMatches = @($installedServices | Where-Object { $_.Name -eq 'FDResPub' })
        if ($fdResPubMatches.Count -gt 1) { throw 'FDResPub service identity is ambiguous' }
        $fdResPub = if ($fdResPubMatches.Count -eq 1) { $fdResPubMatches[0] } else { $null }
        $result.FDResPubDisabled = (-not $fdResPub) -or ($fdResPub.StartType -eq 'Disabled' -and $fdResPub.Status -eq 'Stopped')

        $fdPHostMatches = @($installedServices | Where-Object { $_.Name -eq 'fdPHost' })
        if ($fdPHostMatches.Count -gt 1) { throw 'fdPHost service identity is ambiguous' }
        $fdPHost = if ($fdPHostMatches.Count -eq 1) { $fdPHostMatches[0] } else { $null }
        $result.FdPHostDisabled = (-not $fdPHost) -or ($fdPHost.StartType -eq 'Disabled' -and $fdPHost.Status -eq 'Stopped')

        # 3) Check firewall rules unless the user explicitly skipped that layer.
        $ruleDefinitions = @(Get-AdvancedSecurityFirewallDefinitions -Feature Discovery)
        if ($ruleDefinitions.Count -ne 4) { throw "Expected four canonical discovery firewall rules, found $($ruleDefinitions.Count)" }

        if (-not $SkipFirewallChecks) {
            $verifiedRules = @()
            foreach ($definition in $ruleDefinitions) {
                $verifiedRules += Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition
            }
            $result.FirewallRulesPresent = ($verifiedRules.Count -eq $ruleDefinitions.Count)
            $result.FirewallRulesEnabled = @($verifiedRules | Where-Object { $_.Compliant }).Count -eq $ruleDefinitions.Count
        }

        # 4) Optional listener evidence. Query complete inventories so a failed
        # provider call never becomes a false "closed" result.
        try {
            $udpListeners = @(Get-NetUDPEndpoint -ErrorAction Stop)
            $result.Udp3702ListenersClosed = @($udpListeners | Where-Object { [int]$_.LocalPort -eq 3702 }).Count -eq 0
            $result.Udp5353ListenersClosed = @($udpListeners | Where-Object { [int]$_.LocalPort -eq 5353 }).Count -eq 0
        }
        catch {
            $result.Udp3702ListenersClosed = $null
            $result.Udp5353ListenersClosed = $null
        }

        try {
            $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
            $result.Tcp5357ListenersClosed = @($tcpListeners | Where-Object { [int]$_.LocalPort -eq 5357 }).Count -eq 0
            $result.Tcp5358ListenersClosed = @($tcpListeners | Where-Object { [int]$_.LocalPort -eq 5358 }).Count -eq 0
        }
        catch {
            $result.Tcp5357ListenersClosed = $null
            $result.Tcp5358ListenersClosed = $null
        }

        # Overall compliance: mDNS disabled, services disabled, firewall rules present+enabled
        $mdnsOk = ($result.EnableMDNSType -eq 'DWord' -and [int]$result.EnableMDNS -eq 0)
        $servicesOk = $result.FDResPubDisabled -and $result.FdPHostDisabled
        $firewallOk = $SkipFirewallChecks -or ($result.FirewallRulesPresent -and $result.FirewallRulesEnabled)

        $result.Compliant = $mdnsOk -and $servicesOk -and $firewallOk
        $result.Pass = $result.Compliant

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test discovery protocol security (WS-Discovery/mDNS): $_" -Module "AdvancedSecurity" -Exception $_.Exception
        $result.Pass = $false
        $result.Compliant = $false
        return $result
    }
}
