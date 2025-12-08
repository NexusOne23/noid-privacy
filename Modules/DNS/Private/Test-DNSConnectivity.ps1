function Test-DNSConnectivity {
    <#
    .SYNOPSIS
        Test DNS server connectivity and resolution
        
    .DESCRIPTION
        Validates that DNS servers are:
        1. Reachable on port 53 (UDP/TCP)
        2. Able to resolve domain names
        3. Responding with valid answers
        
        Tests both IPv4 and IPv6 connectivity if applicable.
        
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
        Uses Test-NetConnection for reachability
        Uses Resolve-DnsName for resolution testing
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
    }
    
    try {
        Write-Log -Level DEBUG -Message "Testing DNS connectivity: $ServerAddress" -Module $script:ModuleName
        
        # Test 1: Port 53 reachability (fast TCP check without noisy Test-NetConnection output)
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
        
        # Test 2: DNS resolution
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
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Log -Level WARNING -Message "  Connectivity test failed: $($_.Exception.Message)" -Module $script:ModuleName
    }
    
    # Log summary
    if ($result.Reachable -and $result.CanResolve) {
        Write-Log -Level SUCCESS -Message "DNS server $ServerAddress is functional" -Module $script:ModuleName
    }
    else {
        Write-Log -Level WARNING -Message "DNS server $ServerAddress has issues: $($result.ErrorMessage)" -Module $script:ModuleName
    }
    
    return $result
}
