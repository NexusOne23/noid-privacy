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

function Test-DNSResolutionAfterApply {
    <#
    .SYNOPSIS
        Check online that Windows resolves a name with the DNS settings just applied.

    .DESCRIPTION
        Runs after Apply has verified the settings on this PC and flushed the
        resolver cache. Unlike the pre-apply probe it addresses no server: it
        asks the Windows DNS client, so the lookup takes the same path as every
        application, including an active DoH requirement. A VPN or a
        name-resolution policy can route a name elsewhere, so a pass shows that
        names resolve on this network, not which server answered. The result is
        information for the user and never changes the Apply result.

    .PARAMETER TestDomain
        Domain name used for the lookup (default: microsoft.com).

    .PARAMETER Attempts
        Number of lookups before the check is reported as failed.

    .PARAMETER RetryDelaySeconds
        Pause between attempts; a new DoH connection can need a moment.

    .OUTPUTS
        PSCustomObject with Resolved, Attempts and ErrorMessage.
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TestDomain = $(if ($env:NOIDPRIVACY_DNS_TEST_DOMAIN) { $env:NOIDPRIVACY_DNS_TEST_DOMAIN } else { 'microsoft.com' }),

        [Parameter()]
        [ValidateRange(1, 5)]
        [int]$Attempts = 3,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$RetryDelaySeconds = 2
    )

    $result = [PSCustomObject]@{
        Resolved     = $false
        Attempts     = 0
        ErrorMessage = $null
    }
    if ([string]::IsNullOrWhiteSpace($TestDomain)) {
        $result.ErrorMessage = 'DNS test domain must not be empty'
        return $result
    }

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $result.Attempts = $attempt
        try {
            $addresses = @(Resolve-DnsName -Name $TestDomain -DnsOnly -NoHostsFile -ErrorAction Stop |
                    Where-Object { [string]$_.Type -in @('A', 'AAAA') })
            if ($addresses.Count -gt 0) {
                $result.Resolved = $true
                $result.ErrorMessage = $null
                Write-Log -Level DEBUG -Message "Post-apply lookup of $TestDomain succeeded (attempt $attempt)" -Module $script:ModuleName
                return $result
            }
            $result.ErrorMessage = 'Windows returned no address for the test name'
        }
        catch {
            $result.ErrorMessage = $_.Exception.Message
        }
        Write-Log -Level DEBUG -Message "Post-apply lookup of $TestDomain failed (attempt $attempt): $($result.ErrorMessage)" -Module $script:ModuleName
        if ($attempt -lt $Attempts -and $RetryDelaySeconds -gt 0) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    return $result
}
