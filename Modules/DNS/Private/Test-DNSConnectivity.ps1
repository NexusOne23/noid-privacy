function Test-DNSConnectivity {
    <#
    .SYNOPSIS
        Perform a best-effort pre-apply DNS server check.

    .DESCRIPTION
        Independently checks TCP port 53 and asks that exact resolver for a DNS
        answer. The result is informational: classic DNS normally starts with
        UDP, so a failed TCP probe does not suppress or invalidate the query.

    .PARAMETER ServerAddress
        DNS server IP address to test.

    .PARAMETER TestDomain
        Domain name used for the resolution check (default: microsoft.com).

    .OUTPUTS
        PSCustomObject with the probe result.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerAddress,

        [Parameter()]
        [string]$TestDomain = $(if ($env:NOIDPRIVACY_DNS_TEST_DOMAIN) { $env:NOIDPRIVACY_DNS_TEST_DOMAIN } else { 'microsoft.com' })
    )

    $result = [PSCustomObject]@{
        ServerAddress = $ServerAddress
        Reachable     = $false
        CanResolve    = $false
        ResponseTime  = $null
        ErrorMessage  = $null
        TestMethod    = 'ClassicDnsTcpPrecheck'
        SkippedByDohRequirePolicy = $false
    }

    try {
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($ServerAddress, [ref]$parsedAddress)) {
            throw "Invalid DNS server address: $ServerAddress"
        }
        if ([string]::IsNullOrWhiteSpace($TestDomain)) {
            throw 'DNS test domain must not be empty'
        }

        Write-Log -Level DEBUG -Message "Testing DNS TCP reachability: $ServerAddress`:53" -Module $script:ModuleName
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            try {
                $asyncResult = $tcpClient.BeginConnect($ServerAddress, 53, $null, $null)
                if ($asyncResult.AsyncWaitHandle.WaitOne(3000, $false) -and $tcpClient.Connected) {
                    $tcpClient.EndConnect($asyncResult)
                    $result.Reachable = $true
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "DNS TCP probe failed for $ServerAddress`: $($_.Exception.Message)" -Module $script:ModuleName
            }
        }
        finally {
            $tcpClient.Close()
        }

        # An active DoH REQUIRE policy (DoHPolicy=3, typically written by this
        # module's own previous Apply) forbids unencrypted DNS system-wide, so
        # the classic Resolve-DnsName probe below is guaranteed to fail with a
        # misleading Windows error. Skip it honestly instead of reporting a
        # false resolver warning; the TCP 53 probe above is socket-level and
        # remains valid.
        $dohRequirePolicyActive = $false
        try {
            $dnsClientPolicyKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
            if ($dnsClientPolicyKey -and $dnsClientPolicyKey.GetValueNames() -contains 'DoHPolicy' -and
                [int]$dnsClientPolicyKey.GetValue('DoHPolicy') -eq 3) {
                $dohRequirePolicyActive = $true
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "DoH policy state could not be read; keeping classic DNS probe: $($_.Exception.Message)" -Module $script:ModuleName
        }
        if ($dohRequirePolicyActive) {
            $result.SkippedByDohRequirePolicy = $true
            $result.TestMethod = 'TcpPrecheckOnlyDohRequirePolicyActive'
            Write-Log -Level DEBUG -Message "Classic DNS probe skipped for $ServerAddress`: active DoH REQUIRE policy forbids unencrypted queries" -Module $script:ModuleName
            return $result
        }

        try {
            $resolveStart = Get-Date
            $dnsResult = @(Resolve-DnsName -Name $TestDomain -Server $ServerAddress -DnsOnly -ErrorAction Stop)
            $result.ResponseTime = ((Get-Date) - $resolveStart).TotalMilliseconds
            if ($dnsResult.Count -eq 0) {
                $result.ErrorMessage = 'The DNS server returned no records'
                return $result
            }
            $result.CanResolve = $true
            Write-Log -Level DEBUG -Message "DNS pre-check succeeded for $ServerAddress" -Module $script:ModuleName
        }
        catch {
            $tcpContext = if ($result.Reachable) { 'TCP 53 reachable' } else { 'TCP 53 unavailable' }
            $result.ErrorMessage = "$tcpContext; DNS query failed: $($_.Exception.Message)"
            Write-Log -Level DEBUG -Message "DNS query pre-check failed for $ServerAddress`: $($result.ErrorMessage)" -Module $script:ModuleName
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Log -Level DEBUG -Message "DNS pre-check failed for $ServerAddress`: $($result.ErrorMessage)" -Module $script:ModuleName
    }

    return $result
}
