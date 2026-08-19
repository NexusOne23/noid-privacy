function Test-AdvancedSecurity {
    <#
    .SYNOPSIS
        Test Advanced Security compliance

    .DESCRIPTION
        Runs all compliance tests for Advanced Security hardening and returns
        a comprehensive intent-bound report. Every decision parameter must be
        supplied explicitly; the function never substitutes a profile/default
        as proof of an earlier user choice.

        Tests include:
        - RDP Security (NLA enforcement, SSL/TLS, disable status)
        - Administrative-share policy (effective after reboot; live shares preserved during Apply)
        - Risky Firewall Ports (LLMNR, NetBIOS, UPnP/SSDP closed)
        - NetBIOS adapter hardening (per-adapter TCP/IP NetBIOS state)
        - Risky Network Services (SSDPSRV, upnphost, lmhosts stopped)
        - Legacy TLS 1.0/1.1 disable state
        - WPAD auto-discovery disable state
        - Legacy SRP .lnk path-rule registry values
        - Windows Update policy configuration
        - Finger Protocol Block
        - Wireless Display Security
        - Discovery Protocols (WS-Discovery, mDNS)
        - Firewall Shields Up (Public)
        - IPv6 component disable (0xFF)

    .EXAMPLE
        $results = Test-AdvancedSecurity -SecurityProfile Balanced -DisableRDP $true `
          -AdminSharesDisabled $true -DisableUPnP $true `
          -DisableWirelessDisplayCompletely $false `
          -DisableDiscoveryProtocolsCompletely $false `
          -DisableIPv6Completely $false -SkipFirewallLayer:$false
        $results | Format-Table

    .OUTPUTS
        Array of PSCustomObjects with compliance results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Balanced', 'Enterprise', 'Maximum')]
        [string]$SecurityProfile,

        [Parameter(Mandatory = $false)]
        [bool]$DisableRDP,

        [Parameter(Mandatory = $false)]
        [bool]$AdminSharesDisabled,

        [Parameter(Mandatory = $false)]
        [bool]$DisableUPnP,

        [Parameter(Mandatory = $false)]
        [bool]$DisableWirelessDisplayCompletely,

        [Parameter(Mandatory = $false)]
        [bool]$DisableDiscoveryProtocolsCompletely,

        [Parameter(Mandatory = $false)]
        [bool]$DisableIPv6Completely,

        [Parameter(Mandatory = $false)]
        [switch]$SkipFirewallLayer,

        [bool]$RdpHostSupported = $true,

        [bool]$ManagedPolicySupported = $true,

        [bool]$WirelessDisplaySupported = $true,

        [object[]]$WinInetUsers
    )

    # A missing caller contract is not a runtime probe failure. Keep this guard
    # outside the catch below so callers receive a terminating parameter/intent
    # error instead of a misleading $null compliance result.
    $requiredIntentParameters = @(
        'SecurityProfile', 'DisableRDP', 'AdminSharesDisabled', 'DisableUPnP',
        'DisableWirelessDisplayCompletely', 'DisableDiscoveryProtocolsCompletely',
        'DisableIPv6Completely', 'SkipFirewallLayer'
    )
    $missingIntentParameters = @($requiredIntentParameters | Where-Object {
            -not $PSBoundParameters.ContainsKey($_)
        })
    if ($missingIntentParameters.Count -gt 0) {
        throw "AdvancedSecurity verification requires an explicit current intent; missing: $($missingIntentParameters -join ', ')"
    }

    try {

        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  ADVANCED SECURITY COMPLIANCE TEST" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""

        $null = Write-FirewallControllerRuntimeWarning -FirewallLayerSkipped ([bool]$SkipFirewallLayer)

        $results = @()

        # 1. RDP Security
        if (-not $RdpHostSupported) {
            $results += [PSCustomObject]@{
                Feature='RDP Security'; Status='NotApplicable'; Compliant=$null; CheckState='NotApplicable'
                Details='This Windows edition cannot act as a Remote Desktop host'
            }
        }
        else {
            Write-Host "Testing RDP Security..." -ForegroundColor Gray
            $rdpTest = Test-RdpSecurity
            if ($DisableRDP -and ($rdpTest.RDP_DenyType -ne 'DWord' -or $null -eq $rdpTest.RDP_DenyValue -or
                [int]$rdpTest.RDP_DenyValue -ne 1)) {
                $rdpTest.Compliant = $false
                $rdpTest.Status = 'Mismatch'
                $rdpTest.Details += "fDenyTSConnections expected 1, actual $($rdpTest.RDP_DenyValue)"
            }
            $results += $rdpTest
        }

        # 2. Admin Shares
        if ($AdminSharesDisabled) {
            Write-Host "Testing Administrative Shares..." -ForegroundColor Gray
            $adminSharesTest = Test-AdminShares -SkipFirewallChecks:$SkipFirewallLayer
            $results += $adminSharesTest
        }
        else {
            $results += [PSCustomObject]@{
                Feature='Admin Shares'; Status='NotChecked'; Compliant=$null; CheckState='NotChecked'
                Details='Intentionally kept for domain/management compatibility'
            }
        }

        # 3. Legacy TLS
        Write-Host "Testing Legacy TLS (1.0/1.1)..." -ForegroundColor Gray
        $tlsTest = Test-LegacyTLS
        $results += $tlsTest

        # 4. WPAD
        Write-Host "Testing WPAD Configuration..." -ForegroundColor Gray
        $wpadTest = if ($PSBoundParameters.ContainsKey('WinInetUsers')) {
            Test-WPAD -WinInetUsers $WinInetUsers
        }
        else {
            Test-WPAD
        }
        $results += $wpadTest

        # 5. Risky Ports
        if ($SkipFirewallLayer) {
            Write-Host "Testing NetBIOS adapter hardening; firewall rules are NotChecked..." -ForegroundColor Yellow
            $results += Test-RiskyPorts -SkipUPnP:(-not $DisableUPnP) -SkipFirewallChecks
        }
        else {
            Write-Host "Testing Risky Firewall Ports..." -ForegroundColor Gray
            $riskyPortsTest = Test-RiskyPorts -SkipUPnP:(-not $DisableUPnP)
            $results += $riskyPortsTest
        }

        # 6. Risky Services
        Write-Host "Testing Risky Network Services..." -ForegroundColor Gray
        $riskyServicesTest = Test-RiskyServices -SkipUPnP:(-not $DisableUPnP)
        $results += $riskyServicesTest

        # 7. Legacy SRP registry configuration (runtime enforcement is not asserted)
        Write-Host "Testing legacy SRP .lnk path-rule registry state..." -ForegroundColor Gray
        $srpTest = Test-SRPCompliance
        $results += $srpTest

        # 8. Windows Update Configuration
        Write-Host "Testing Windows Update Configuration..." -ForegroundColor Gray
        $wuTest = Test-WindowsUpdate -ManagedPoliciesSupported:$ManagedPolicySupported
        $results += $wuTest

        # 9. Finger Protocol Block
        if ($SkipFirewallLayer) {
            Write-Host "Skipping Finger Protocol Firewall Rule (explicit choice)..." -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                Feature    = 'Finger Protocol Block'
                Status     = 'NotChecked'
                Compliant  = $null
                CheckState = 'NotChecked'
                Details    = 'Firewall layer explicitly skipped'
            }
        }
        else {
            Write-Host "Testing Finger Protocol Block..." -ForegroundColor Gray
            $fingerTest = Test-FingerProtocol
            $results += $fingerTest
        }

        # 10. Wireless Display Security
        if (-not $WirelessDisplaySupported) {
            $results += [PSCustomObject]@{
                Feature='Wireless Display Security'; Status='NotApplicable'; Compliant=$null; CheckState='NotApplicable'
                Details='WirelessDisplay policy CSP is not supported on this Windows edition'
            }
        }
        else {
            Write-Host "Testing Wireless Display Security..." -ForegroundColor Gray
            $wirelessDisplayTest = Test-WirelessDisplaySecurity `
                -RequireCompleteDisable:$DisableWirelessDisplayCompletely `
                -SkipFirewallChecks:$SkipFirewallLayer
            if ($wirelessDisplayTest) {
                $wirelessCompliant = if ($DisableWirelessDisplayCompletely) {
                    [bool]$wirelessDisplayTest.FullyDisabled
                }
                else {
                    [bool]$wirelessDisplayTest.Compliant
                }
                $results += [PSCustomObject]@{
                    Feature    = "Wireless Display Security"
                    Status     = if ($wirelessDisplayTest.FullyDisabled) { "Fully Disabled" }
                                elseif ($wirelessCompliant) { "Hardened" }
                                else { "Mismatch" }
                    Compliant  = $wirelessCompliant
                    Details    = if ($wirelessDisplayTest.FullyDisabled) { "Fully Disabled" }
                                elseif ($wirelessCompliant) { "Hardened (receiving blocked, PIN required)" }
                                else { "Policy/service/adapter/firewall target mismatch" }
                }
            }
        }

        # 11. Discovery Protocols (WS-Discovery + mDNS) - Maximum profile only
        if ($SecurityProfile -eq 'Maximum' -and $DisableDiscoveryProtocolsCompletely) {
            Write-Host "Testing Discovery Protocols (WS-Discovery + mDNS)..." -ForegroundColor Gray
            $discoveryTest = Test-DiscoveryProtocolsSecurity -SkipFirewallChecks:$SkipFirewallLayer
            if ($discoveryTest) {
                $statusText = if ($discoveryTest.Compliant) { "Disabled (Maximum)" } else { "Mismatch" }
                $results += [PSCustomObject]@{
                    Feature   = "Discovery Protocols (WS-Discovery + mDNS)"
                    Status    = $statusText
                    Details   = "mDNS=" + $(if ($discoveryTest.EnableMDNS -eq 0) { "Disabled" } else { "Enabled/Not Set" }) +
                                "; Services: FDResPub=" + $discoveryTest.FDResPubDisabled + ", fdPHost=" + $discoveryTest.FdPHostDisabled +
                                "; Firewall=" + $(if ($discoveryTest.FirewallChecksSkipped) { 'NotChecked' } else { "RulesEnabled=$($discoveryTest.FirewallRulesEnabled)" })
                    Compliant = $discoveryTest.Compliant
                }
            }
        }
        else {
            $results += [PSCustomObject]@{
                Feature='Discovery Protocols (WS-Discovery + mDNS)'; Status='NotChecked'; Compliant=$null
                CheckState='NotChecked'; Details='Not selected; Maximum-profile optional feature'
            }
        }

        # 12. Firewall Shields Up (optional - Maximum profile only)
        if ($SkipFirewallLayer) {
            Write-Host "Skipping Firewall Shields Up (explicit firewall-layer choice)..." -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                Feature    = 'Firewall Shields Up (Public)'
                Status     = 'NotChecked'
                Compliant  = $null
                CheckState = 'NotChecked'
                Details    = 'Firewall layer explicitly skipped'
            }
        }
        elseif ($SecurityProfile -eq 'Maximum') {
            Write-Host "Testing Firewall Shields Up (Public)..." -ForegroundColor Gray
            $shieldsUpTest = Test-FirewallShieldsUp
            $statusText = if ($shieldsUpTest.IsEnabled) { "Enabled (Maximum)" } else { "Not enabled (Optional - Maximum profile only)" }
            $results += [PSCustomObject]@{
                Feature    = "Firewall Shields Up (Public)"
                Status     = $statusText
                Compliant  = $shieldsUpTest.Pass
                Details    = $shieldsUpTest.Message
            }
        }
        else {
            $results += [PSCustomObject]@{
                Feature='Firewall Shields Up (Public)'; Status='NotChecked'; Compliant=$null
                CheckState='NotChecked'; Details='Maximum-profile feature was not selected'
            }
        }

        # 13. IPv6 component-disable state (optional - Maximum profile only)
        if ($SecurityProfile -eq 'Maximum' -and $DisableIPv6Completely) {
            Write-Host "Testing IPv6 component-disable registry state..." -ForegroundColor Gray
            $ipv6Test = Test-IPv6Security
            $results += [PSCustomObject]@{
                Feature="IPv6 component disable (0xFF)"; Compliant=$ipv6Test.Compliant
                Status=$(if ($ipv6Test.Compliant) { 'Configured' } else { 'Mismatch' }); Details=$ipv6Test.Message
            }
        }
        else {
            $results += [PSCustomObject]@{
                Feature='IPv6 component disable (0xFF)'; Status='NotChecked'; Compliant=$null
                CheckState='NotChecked'; Details='Optional IPv6 component-disable state was not selected'
            }
        }

        # Summary
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  COMPLIANCE SUMMARY" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""

        $notCheckedCount = @($results | Where-Object {
                $_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -eq 'NotChecked'
            }).Count
        $notApplicableCount = @($results | Where-Object {
                $_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -eq 'NotApplicable'
            }).Count
        $checkedResults = @($results | Where-Object {
                -not ($_.PSObject.Properties.Name -contains 'CheckState' -and $_.CheckState -in @('NotChecked', 'NotApplicable'))
            })
        $compliantCount = @($checkedResults | Where-Object { $_.Compliant -eq $true }).Count
        $totalTests = $checkedResults.Count
        $compliancePercent = if ($totalTests -gt 0) { [math]::Round(($compliantCount / $totalTests) * 100, 1) } else { 0 }

        # Four-state reconciliation: the displayed total is the sum of all four
        # states, matching every other summary in the framework. The compliance
        # percentage keeps its applicable-only denominator ($totalTests).
        $nonCompliantCount = $totalTests - $compliantCount
        Write-Host "Total Tests:    $($results.Count)" -ForegroundColor White
        Write-Host "Compliant:      $compliantCount" -ForegroundColor Green
        Write-Host "Non-Compliant:  $nonCompliantCount" -ForegroundColor $(if ($nonCompliantCount -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Not Checked:    $notCheckedCount" -ForegroundColor $(if ($notCheckedCount -gt 0) { 'Yellow' } else { 'Gray' })
        Write-Host "Not Applicable: $notApplicableCount" -ForegroundColor $(if ($notApplicableCount -gt 0) { 'Yellow' } else { 'Gray' })
        # Green only at zero non-compliance: a percentage threshold must never
        # paint live non-compliance green.
        if ($totalTests -gt 0) {
            Write-Host "Compliance:     $compliancePercent%  (of $totalTests applicable checks)" -ForegroundColor $(if ($nonCompliantCount -eq 0) { 'Green' } else { 'Red' })
        }
        else {
            Write-Host "Compliance:     n/a (0 applicable checks)" -ForegroundColor Yellow
        }
        Write-Host ""

        # Detailed results table, rendered to the host: emitting Format-Table
        # objects to the pipeline never reaches the console when the caller
        # captures the function output and would pollute the returned object.
        if (($totalTests - $compliantCount) -eq 0 -and $notCheckedCount -eq 0) {
            Write-Host "All applicable checks compliant." -ForegroundColor Green
        }
        else {
            $tableFormat = @{Expression = { $_.Feature }; Label = "Feature"; Width = 30 },
            @{Expression = { $_.Status }; Label = "Status"; Width = 20 },
            @{Expression = { if ($_.Compliant) { "[X]" }else { "[ ]" } }; Label = "Compliant"; Width = 10 }

            Write-Host "DETAILED RESULTS:" -ForegroundColor White
            Write-Host (($results | Format-Table $tableFormat -AutoSize | Out-String).TrimEnd())
        }

        Write-Host ""

        # Return structured object with metadata for programmatic use
        return [PSCustomObject]@{
            Results        = $results
            TotalChecks    = $totalTests
            CompliantCount = $compliantCount
            NotCheckedCount = $notCheckedCount
            NotApplicableCount = $notApplicableCount
            Compliance     = $compliancePercent
            FirewallLayer  = $(if ($SkipFirewallLayer) { 'Skipped' } else { 'Checked' })
            FirewallSettingsSkipped = $(if ($SkipFirewallLayer) {
                    # Derive from the canonical inventory (16 rules + the Shields
                    # Up registry target) instead of hardcoding counts that can
                    # silently go stale when the inventory changes.
                    $firewallDefinitions = @(Get-AdvancedSecurityFirewallDefinitions)
                    $miracastRuleCount = @($firewallDefinitions | Where-Object { $_.Group -eq 'Miracast' }).Count
                    $firewallDefinitions.Count + 1 - $(if ($WirelessDisplaySupported) { 0 } else { $miracastRuleCount })
                }
                else { 0 })
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to run compliance tests: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        Write-Host ""
        Write-Host "ERROR: Failed to run compliance tests" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Gray
        Write-Host ""
        return $null
    }
}
