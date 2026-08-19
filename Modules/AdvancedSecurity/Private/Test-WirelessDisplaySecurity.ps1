function Test-WirelessDisplaySecurity {
    [CmdletBinding()]
    param(
        [switch]$RequireCompleteDisable,
        [switch]$SkipFirewallChecks
    )

    $result = [ordered]@{
        AllowProjectionToPC=$null; RequirePinForPairing=$null
        AllowProjectionFromPC=$null; AllowMdnsAdvertisement=$null; AllowMdnsDiscovery=$null
        AllowProjectionFromPCOverInfrastructure=$null; AllowProjectionToPCOverInfrastructure=$null
        WiFiDirectServiceDisabled=$null; WiFiDirectAdaptersDisabled=$null
        FirewallRulesVerified=$null; Compliant=$false; FullyDisabled=$false; Error=$null
    }
    try {
        $connectPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        $key = Get-Item -LiteralPath $connectPath -ErrorAction Stop
        foreach ($name in @(
                'AllowProjectionToPC','RequirePinForPairing','AllowProjectionFromPC',
                'AllowMdnsAdvertisement','AllowMdnsDiscovery',
                'AllowProjectionFromPCOverInfrastructure','AllowProjectionToPCOverInfrastructure'
            )) {
            if ($key.GetValueNames() -contains $name) { $result[$name] = $key.GetValue($name) }
        }
        $baseOk = ($key.GetValueKind('AllowProjectionToPC').ToString() -eq 'DWord' -and
            [int]$result.AllowProjectionToPC -eq 0 -and
            $key.GetValueKind('RequirePinForPairing').ToString() -eq 'DWord' -and
            [int]$result.RequirePinForPairing -eq 2)
        $result.Compliant = $baseOk

        if ($RequireCompleteDisable) {
            $policyOk = $baseOk
            foreach ($name in @(
                    'AllowProjectionFromPC','AllowMdnsAdvertisement','AllowMdnsDiscovery',
                    'AllowProjectionFromPCOverInfrastructure','AllowProjectionToPCOverInfrastructure'
                )) {
                if ($key.GetValueNames() -notcontains $name -or $key.GetValueKind($name).ToString() -ne 'DWord' -or
                    [int]$result[$name] -ne 0) { $policyOk = $false }
            }

            $services = @(Get-Service -ErrorAction Stop)
            $wfdServiceMatches = @($services | Where-Object { $_.Name -eq 'WFDSConMgrSvc' })
            if ($wfdServiceMatches.Count -gt 1) { throw 'WFDSConMgrSvc service identity is ambiguous' }
            $wfdService = if ($wfdServiceMatches.Count -eq 1) { $wfdServiceMatches[0] } else { $null }
            $result.WiFiDirectServiceDisabled = (-not $wfdService) -or
                ($wfdService.Status -eq 'Stopped' -and $wfdService.StartType -eq 'Disabled')

            $wfdAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                    [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
                })
            $result.WiFiDirectAdaptersDisabled = @($wfdAdapters | Where-Object { [string]$_.Status -ne 'Disabled' }).Count -eq 0

            if ($SkipFirewallChecks) {
                $result.FirewallRulesVerified = $null
            }
            else {
                $ruleDefinitions = @(Get-AdvancedSecurityFirewallDefinitions -Feature Miracast)
                if ($ruleDefinitions.Count -ne 4) { throw "Expected four canonical Miracast firewall rules, found $($ruleDefinitions.Count)" }
                $firewallOk = $true
                foreach ($definition in $ruleDefinitions) {
                    $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition
                    if (-not $verification.Compliant) { $firewallOk = $false }
                }
                $result.FirewallRulesVerified = $firewallOk
            }

            $firewallRequirementOk = $SkipFirewallChecks -or [bool]$result.FirewallRulesVerified
            $result.FullyDisabled = $policyOk -and [bool]$result.WiFiDirectServiceDisabled -and
                [bool]$result.WiFiDirectAdaptersDisabled -and $firewallRequirementOk
        }
        return [PSCustomObject]$result
    }
    catch {
        $result.Error = $_.Exception.Message
        return [PSCustomObject]$result
    }
}
