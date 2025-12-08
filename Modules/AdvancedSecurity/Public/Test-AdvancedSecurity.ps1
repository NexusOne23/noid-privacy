function Test-AdvancedSecurity {
    <#
    .SYNOPSIS
        Test Advanced Security compliance
    
    .DESCRIPTION
        Runs all compliance tests for Advanced Security hardening and returns
        a comprehensive report of the current security posture.
        
        Tests include:
        - RDP Security (NLA enforcement, SSL/TLS, disable status)
        - WDigest Protection (credential caching disabled)
        - Administrative Shares (disabled and removed)
        - Risky Firewall Ports (LLMNR, NetBIOS, UPnP/SSDP closed)
        - Risky Network Services (SSDPSRV, upnphost, lmhosts stopped)
        - Discovery Protocols (WS-Discovery, mDNS)
    
    .EXAMPLE
        Test-AdvancedSecurity
        Runs all compliance tests and displays results
    
    .EXAMPLE
        $results = Test-AdvancedSecurity
        $results | Format-Table
    
    .OUTPUTS
        Array of PSCustomObjects with compliance results
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  ADVANCED SECURITY COMPLIANCE TEST" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        
        $results = @()
        
        # 1. RDP Security
        Write-Host "Testing RDP Security..." -ForegroundColor Gray
        $rdpTest = Test-RdpSecurity
        $results += $rdpTest
        
        # 2. WDigest Protection
        Write-Host "Testing WDigest Protection..." -ForegroundColor Gray
        $wdigestTest = Test-WDigest
        $results += $wdigestTest
        
        # 3. Admin Shares
        Write-Host "Testing Administrative Shares..." -ForegroundColor Gray
        $adminSharesTest = Test-AdminShares
        $results += $adminSharesTest
        
        # 4. Legacy TLS
        Write-Host "Testing Legacy TLS (1.0/1.1)..." -ForegroundColor Gray
        $tlsTest = Test-LegacyTLS
        $results += $tlsTest
        
        # 5. WPAD
        Write-Host "Testing WPAD Configuration..." -ForegroundColor Gray
        $wpadTest = Test-WPAD
        $results += $wpadTest
        
        # 6. PowerShell v2
        Write-Host "Testing PowerShell v2 Status..." -ForegroundColor Gray
        $psv2Test = Test-PowerShellV2
        $results += $psv2Test
        
        # 7. Risky Ports
        Write-Host "Testing Risky Firewall Ports..." -ForegroundColor Gray
        $riskyPortsTest = Test-RiskyPorts
        $results += $riskyPortsTest
        
        # 8. Risky Services
        Write-Host "Testing Risky Network Services..." -ForegroundColor Gray
        $riskyServicesTest = Test-RiskyServices
        $results += $riskyServicesTest
        
        # 9. SRP Configuration (CVE-2025-9491)
        Write-Host "Testing SRP Configuration (CVE-2025-9491)..." -ForegroundColor Gray
        $srpTest = Test-SRPCompliance
        $results += $srpTest
        
        # 10. Windows Update Configuration
        Write-Host "Testing Windows Update Configuration..." -ForegroundColor Gray
        $wuTest = Test-WindowsUpdate
        $results += $wuTest
        
        # 11. Finger Protocol Block
        Write-Host "Testing Finger Protocol Block..." -ForegroundColor Gray
        $fingerTest = Test-FingerProtocol
        $results += $fingerTest
        
        # 12. Wireless Display Security
        Write-Host "Testing Wireless Display Security..." -ForegroundColor Gray
        $wirelessDisplayTest = Test-WirelessDisplaySecurity
        if ($wirelessDisplayTest) {
            $results += [PSCustomObject]@{
                Feature    = "Wireless Display Security"
                Compliant  = $wirelessDisplayTest.Compliant
                Details    = if ($wirelessDisplayTest.FullyDisabled) { "Fully Disabled" } 
                            elseif ($wirelessDisplayTest.Compliant) { "Hardened (receiving blocked, PIN required)" }
                            else { "NOT HARDENED - screen interception possible!" }
            }
        }
        
        # 13. Discovery Protocols (WS-Discovery + mDNS) - Maximum profile only
        Write-Host "Testing Discovery Protocols (WS-Discovery + mDNS)..." -ForegroundColor Gray
        $discoveryTest = Test-DiscoveryProtocolsSecurity
        if ($discoveryTest) {
            $results += [PSCustomObject]@{
                Feature   = "Discovery Protocols (WS-Discovery + mDNS)"
                Status    = if ($discoveryTest.Compliant) { "Secure" } else { "Insecure" }
                Details   = "mDNS=" + $(if ($discoveryTest.EnableMDNS -eq 0) { "Disabled" } else { "Enabled/Not Set" }) +
                            "; Services: FDResPub=" + $discoveryTest.FDResPubDisabled + ", fdPHost=" + $discoveryTest.FdPHostDisabled +
                            "; FirewallRulesEnabled=" + $discoveryTest.FirewallRulesEnabled
                Compliant = $discoveryTest.Compliant
            }
        }

        # 14. Firewall Shields Up (optional - Maximum profile only)
        Write-Host "Testing Firewall Shields Up (Public)..." -ForegroundColor Gray
        $shieldsUpTest = Test-FirewallShieldsUp
        # Always pass - this is an optional hardening only for the Maximum (air-gapped) profile
        $results += [PSCustomObject]@{
            Feature    = "Firewall Shields Up (Public)"
            Compliant  = $shieldsUpTest.Pass
            Details    = $shieldsUpTest.Message
        }
        
        # 15. IPv6 Disable (optional - Maximum profile only, mitm6 mitigation)
        Write-Host "Testing IPv6 Security (mitm6 mitigation)..." -ForegroundColor Gray
        $ipv6Test = Test-IPv6Security
        # Always pass - this is an optional hardening only for the Maximum profile
        $results += [PSCustomObject]@{
            Feature    = "IPv6 Disable (mitm6 mitigation)"
            Compliant  = $ipv6Test.Pass
            Details    = $ipv6Test.Message
        }
        
        # Summary
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  COMPLIANCE SUMMARY" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        
        $compliantCount = ($results | Where-Object { $_.Compliant -eq $true }).Count
        $totalTests = $results.Count
        $compliancePercent = [math]::Round(($compliantCount / $totalTests) * 100, 1)
        
        Write-Host "Total Tests:    $totalTests" -ForegroundColor White
        Write-Host "Compliant:      $compliantCount" -ForegroundColor Green
        Write-Host "Non-Compliant:  $($totalTests - $compliantCount)" -ForegroundColor Red
        Write-Host "Compliance:     $compliancePercent%" -ForegroundColor $(if ($compliancePercent -ge 80) { 'Green' } elseif ($compliancePercent -ge 50) { 'Yellow' } else { 'Red' })
        Write-Host ""
        
        # Detailed results table
        Write-Host "DETAILED RESULTS:" -ForegroundColor White
        Write-Host ""
        
        $tableFormat = @{Expression = { $_.Feature }; Label = "Feature"; Width = 30 },
        @{Expression = { $_.Status }; Label = "Status"; Width = 20 },
        @{Expression = { if ($_.Compliant) { "[X]" }else { "[ ]" } }; Label = "Compliant"; Width = 10 }
        
        $results | Format-Table $tableFormat -AutoSize
        
        Write-Host ""
        
        # Return structured object with metadata for programmatic use
        return [PSCustomObject]@{
            Results        = $results
            TotalChecks    = $totalTests
            CompliantCount = $compliantCount
            Compliance     = $compliancePercent
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
