function Test-RiskyPorts {
    [CmdletBinding()]
    param(
        [switch]$SkipUPnP,
        [switch]$SkipFirewallChecks
    )

    $details = [System.Collections.Generic.List[string]]::new()
    try {
        $definitions = @(Get-AdvancedSecurityFirewallDefinitions -Feature RiskyPorts |
            Where-Object { -not $SkipUPnP -or $_.Group -ne 'UPnP' })

        $failed = 0
        if ($SkipFirewallChecks) {
            $details.Add('Firewall rules: NotChecked by explicit firewall-layer choice')
        }
        else {
            foreach ($definition in $definitions) {
                $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition
                if (-not $verification.Compliant) { $failed++ }
                $details.Add("$($definition.Name): $(if ($verification.Compliant) { 'OK' } else { 'MISMATCH: ' + ($verification.Mismatches -join '; ') })")
            }
        }

        $netbios = Test-AdvancedSecurityNetBIOSDisabled
        if (-not [bool]$netbios.Compliant) { $failed++ }
        foreach ($adapter in @($netbios.Adapters)) {
            $matchingFailure = @($netbios.NonCompliant | Where-Object {
                    [string]$_.SettingID -ieq [string]$adapter.SettingID
                })
            $details.Add("Adapter $($adapter.SettingID): $(if ($matchingFailure.Count -eq 0) {
                        'NetbiosOptions=DWORD/2'
                    }
                    else {
                        'MISMATCH provider=' + [string]$matchingFailure[0].ProviderValue +
                            ', registry=' + [string]$matchingFailure[0].RegistryValueType +
                            '/' + [string]$matchingFailure[0].RegistryValue
                    })")
        }

        return [PSCustomObject]@{
            Feature='Risky Ports and NetBIOS'; Status=$(if ($failed -eq 0) { 'Secure' } else { 'Mismatch' })
            Details=@($details); Compliant=($failed -eq 0); CheckedRules=$(if ($SkipFirewallChecks) { 0 } else { $definitions.Count })
            FirewallCheckState=$(if ($SkipFirewallChecks) { 'NotChecked' } else { 'Checked' })
            UPnPPreserved=[bool]$SkipUPnP
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature='Risky Ports and NetBIOS'; Status='Error'; Details=@($_.Exception.Message)
            Compliant=$false; CheckedRules=0; FirewallCheckState=$(if ($SkipFirewallChecks) { 'NotChecked' } else { 'Checked' })
            UPnPPreserved=[bool]$SkipUPnP
        }
    }
}
