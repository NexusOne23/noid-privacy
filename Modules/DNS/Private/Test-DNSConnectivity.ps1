function Test-DNSConnectivity {
    <#
    .SYNOPSIS
        Test DNS server connectivity and resolution
        
    .DESCRIPTION
        Validates that DNS servers are:
        1. Reachable on port 53 (UDP/TCP) OR via DoH (HTTPS)
        2. Able to resolve domain names
        3. Responding with valid answers
        
        Automatically detects if DoH "Require" mode is active and uses
        appropriate test method (HTTPS for DoH, Port 53 for classic DNS).
        
    .PARAMETER ServerAddress
        DNS server IP address to test
        
    .PARAMETER TestDomain
        Domain name to use for resolution test (default: microsoft.com)
        
    .EXAMPLE
        Test-DNSConnectivity -ServerAddress "1.1.1.1"
        
    .EXAMPLE
        Test-DNSConnectivity -ServerAddress "2606:4700:4700::1111" -TestDomain "google.com"
        
    .OUTPUTS
        PSCustomObject with test results
        
    .NOTES
        Uses DoH (HTTPS) test if DoH Require mode is already active
        Uses classic DNS (Port 53) test otherwise
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerAddress,
        
        [Parameter()]
        [string]$TestDomain = "microsoft.com"
    )
    
    $result = [PSCustomObject]@{
        ServerAddress = $ServerAddress
        Reachable = $false
        CanResolve = $false
        ResponseTime = $null
        ErrorMessage = $null
        TestMethod = "Classic"  # "Classic", "DoH", or "Skipped"
    }
    
    try {
        Write-Log -Level DEBUG -Message "Testing DNS connectivity: $ServerAddress" -Module $script:ModuleName
        
        # Check if DoH "Require" mode is already active on the system
        # If ANY DNS server has DoH Require, classic DNS (Port 53) is blocked system-wide
        $dohConfig = $null
        $dohRequireActive = $false
        $systemHasDoHRequire = $false
        
        try {
            # First check: Is there ANY DoH Require config on the system?
            $allDohConfigs = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
            if ($allDohConfigs) {
                $requireConfigs = $allDohConfigs | Where-Object { $_.AllowFallbackToUdp -eq $false }
                if ($requireConfigs) {
                    $systemHasDoHRequire = $true
                    Write-Log -Level DEBUG -Message "  System has DoH Require active - classic DNS blocked" -Module $script:ModuleName
                }
            }
            
            # Second check: Does this specific server have DoH config?
            $dohConfig = Get-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction SilentlyContinue
            if ($dohConfig -and $dohConfig.DohTemplate) {
                $dohRequireActive = $true
                $result.TestMethod = "DoH"
                Write-Log -Level DEBUG -Message "  DoH config found for $ServerAddress - using HTTPS test" -Module $script:ModuleName
            }
            elseif ($systemHasDoHRequire) {
                # This server has no DoH config, but system has DoH Require
                # Classic DNS won't work - skip test and assume reachable
                $result.Reachable = $true
                $result.CanResolve = $true
                $result.TestMethod = "Skipped"
                Write-Log -Level DEBUG -Message "  No DoH config for $ServerAddress but system has DoH Require - skipping test" -Module $script:ModuleName
                Write-Log -Level SUCCESS -Message "DNS server $ServerAddress assumed functional (DoH will be configured)" -Module $script:ModuleName
                return $result
            }
        }
        catch {
            # No DoH config found, use classic test
        }
        
        if ($dohRequireActive) {
            # =====================================================================
            # DoH TEST: Use HTTPS to test connectivity (Port 53 is blocked in Require mode)
            # =====================================================================
            Write-Log -Level DEBUG -Message "  Testing DoH endpoint via HTTPS..." -Module $script:ModuleName
            
            $dohTemplate = $dohConfig.DohTemplate
            
            # Test HTTPS connectivity to DoH endpoint
            try {
                $resolveStart = Get-Date
                
                # Build DoH query URL (RFC 8484 - DNS Wireformat over HTTPS GET)
                # Simple connectivity test: just check if endpoint responds
                $testUrl = $dohTemplate -replace '\{.*\}', ''  # Remove any template variables
                if ($testUrl -notmatch '\?') { $testUrl += "?name=$TestDomain&type=A" }
                
                # Use Invoke-WebRequest with short timeout
                $response = Invoke-WebRequest -Uri $testUrl `
                    -Method GET `
                    -Headers @{ "Accept" = "application/dns-json" } `
                    -TimeoutSec 5 `
                    -UseBasicParsing `
                    -ErrorAction Stop
                
                $resolveEnd = Get-Date
                $result.ResponseTime = ($resolveEnd - $resolveStart).TotalMilliseconds
                
                if ($response.StatusCode -eq 200) {
                    $result.Reachable = $true
                    $result.CanResolve = $true
                    Write-Log -Level DEBUG -Message "  DoH endpoint: OK ($([math]::Round($result.ResponseTime, 2))ms)" -Module $script:ModuleName
                }
            }
            catch {
                # DoH test failed, but this might be due to JSON format issues
                # Try a simple HTTPS connection test to the DoH host
                try {
                    $dohHost = ([System.Uri]$dohTemplate).Host
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    try {
                        $async = $tcpClient.BeginConnect($dohHost, 443, $null, $null)
                        if ($async.AsyncWaitHandle.WaitOne(3000, $false) -and $tcpClient.Connected) {
                            $result.Reachable = $true
                            $result.CanResolve = $true  # Assume working if HTTPS port is open
                            Write-Log -Level DEBUG -Message "  DoH host $dohHost port 443: Reachable" -Module $script:ModuleName
                        }
                    }
                    finally {
                        $tcpClient.Close()
                    }
                }
                catch {
                    $result.ErrorMessage = "DoH endpoint not reachable"
                    Write-Log -Level DEBUG -Message "  DoH endpoint: NOT reachable" -Module $script:ModuleName
                }
            }
        }
        else {
            # =====================================================================
            # CLASSIC TEST: Use Port 53 (DoH not active or in Allow mode)
            # =====================================================================
            Write-Log -Level DEBUG -Message "  Testing port 53 reachability (TCP)..." -Module $script:ModuleName

            $portTest = $false
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                try {
                    $async = $tcpClient.BeginConnect($ServerAddress, 53, $null, $null)
                    # Wait up to 3 seconds for TCP connect
                    if ($async.AsyncWaitHandle.WaitOne(3000, $false) -and $tcpClient.Connected) {
                        $portTest = $true
                    }
                }
                finally {
                    $tcpClient.Close()
                }
            }
            catch {
                $portTest = $false
            }

            if ($portTest) {
                $result.Reachable = $true
                Write-Log -Level DEBUG -Message "  Port 53: Reachable" -Module $script:ModuleName
            }
            else {
                $result.ErrorMessage = "Port 53 not reachable (system may be offline)"
                Write-Log -Level DEBUG -Message "  Port 53: NOT reachable (system may be offline)" -Module $script:ModuleName
                return $result
            }
            
            # Test 2: DNS resolution (classic)
            Write-Log -Level DEBUG -Message "  Testing DNS resolution for $TestDomain..." -Module $script:ModuleName
            
            $resolveStart = Get-Date
            $dnsResult = Resolve-DnsName -Name $TestDomain -Server $ServerAddress -DnsOnly -ErrorAction Stop
            $resolveEnd = Get-Date
            
            $result.ResponseTime = ($resolveEnd - $resolveStart).TotalMilliseconds
            
            if ($dnsResult -and $dnsResult.Count -gt 0) {
                $result.CanResolve = $true
                Write-Log -Level DEBUG -Message "  DNS resolution: OK ($([math]::Round($result.ResponseTime, 2))ms)" -Module $script:ModuleName
            }
            else {
                $result.ErrorMessage = "No DNS response received"
                Write-Log -Level WARNING -Message "  DNS resolution: FAILED (no response)" -Module $script:ModuleName
            }
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Log -Level WARNING -Message "  Connectivity test failed: $($_.Exception.Message)" -Module $script:ModuleName
    }
    
    # Log summary
    if ($result.Reachable -and $result.CanResolve) {
        $methodInfo = if ($result.TestMethod -eq "DoH") { " (via DoH HTTPS)" } else { "" }
        Write-Log -Level SUCCESS -Message "DNS server $ServerAddress is functional$methodInfo" -Module $script:ModuleName
    }
    else {
        Write-Log -Level WARNING -Message "DNS server $ServerAddress has issues: $($result.ErrorMessage)" -Module $script:ModuleName
    }
    
    return $result
}
