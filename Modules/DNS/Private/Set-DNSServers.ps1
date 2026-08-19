function Set-DNSServers {
    <#
    .SYNOPSIS
        Set DNS server addresses on network adapter

    .DESCRIPTION
        Configures DNS server addresses (IPv4 and IPv6) on specified network adapter.
        Uses Microsoft Best Practice: Set-DnsClientServerAddress with -Validate parameter.

        Always configures IPv4. IPv6 is configured only when that address family
        was included in the sealed pre-apply scope.

    .PARAMETER InterfaceIndex
        Network adapter interface index

    .PARAMETER IPv4Primary
        Primary IPv4 DNS server address

    .PARAMETER IPv4Secondary
        Secondary IPv4 DNS server address

    .PARAMETER IPv6Primary
        Primary IPv6 DNS server address

    .PARAMETER IPv6Secondary
        Secondary IPv6 DNS server address

    .PARAMETER Validate
        Validate DNS servers are reachable before applying (recommended)

    .PARAMETER DryRun
        Show what would be configured without applying changes

    .EXAMPLE
        Set-DNSServers -InterfaceIndex 12 -IPv4Primary "1.1.1.1" -IPv4Secondary "1.0.0.1" `
                       -IPv6Primary "2606:4700:4700::1111" -IPv6Secondary "2606:4700:4700::1001" -Validate

    .OUTPUTS
        System.Boolean - $true if successful, $false otherwise

    .NOTES
        Uses Set-DnsClientServerAddress cmdlet (PowerShell Best Practice)
        NEVER uses netsh (deprecated legacy method)
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [int]$InterfaceIndex,

        [Parameter(Mandatory = $true)]
        [string]$IPv4Primary,

        [Parameter(Mandatory = $true)]
        [string]$IPv4Secondary,

        [Parameter(Mandatory = $true)]
        [string]$IPv6Primary,

        [Parameter(Mandatory = $true)]
        [string]$IPv6Secondary,

        [Parameter(Mandatory = $true)]
        [bool]$ConfigureIPv6,

        [Parameter()]
        [switch]$Validate,

        [Parameter()]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set DNSServers')) {
        return
    }


    try {
        $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
        $adapterName = $adapter.Name

        $ipv4Addresses = @($IPv4Primary, $IPv4Secondary)
        $ipv6Addresses = @($IPv6Primary, $IPv6Secondary)
        foreach ($addressDefinition in @(
                [PSCustomObject]@{ Addresses = $ipv4Addresses; Family = [System.Net.Sockets.AddressFamily]::InterNetwork; Label = 'IPv4' },
                [PSCustomObject]@{ Addresses = $ipv6Addresses; Family = [System.Net.Sockets.AddressFamily]::InterNetworkV6; Label = 'IPv6' }
            )) {
            $canonical = @()
            foreach ($address in $addressDefinition.Addresses) {
                $parsedAddress = $null
                if (-not [System.Net.IPAddress]::TryParse([string]$address, [ref]$parsedAddress) -or
                    $parsedAddress.AddressFamily -ne $addressDefinition.Family) {
                    throw "$($addressDefinition.Label) DNS address is invalid: $address"
                }
                $canonical += $parsedAddress.ToString()
            }
            if ($canonical[0] -eq $canonical[1]) {
                throw "$($addressDefinition.Label) primary and secondary DNS addresses must be distinct"
            }
        }

        Write-Log -Level INFO -Message "Configuring DNS servers on adapter: $adapterName" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  IPv4: $($ipv4Addresses -join ', ')" -Module $script:ModuleName
        if ($ConfigureIPv6) {
            Write-Log -Level DEBUG -Message "  IPv6: $($ipv6Addresses -join ', ')" -Module $script:ModuleName
        }

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure DNS servers on $adapterName" -Module $script:ModuleName
            return $true
        }

        $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ErrorAction Stop)
        $ipv4Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 2 })
        if ($ipv4Instance.Count -ne 1) {
            throw 'IPv4 DNS client instance is unavailable or ambiguous'
        }
        $targets = @([PSCustomObject]@{ Instance = $ipv4Instance[0]; Addresses = $ipv4Addresses; Label = 'IPv4' })
        if ($ConfigureIPv6) {
            $ipv6Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 23 })
            if ($ipv6Instance.Count -ne 1) {
                throw 'IPv6 DNS client instance is unavailable or ambiguous'
            }
            $targets += [PSCustomObject]@{ Instance = $ipv6Instance[0]; Addresses = $ipv6Addresses; Label = 'IPv6' }
        }
        else {
            Write-Log -Level INFO -Message "IPv6 transport is disabled; effective resolver mutation is skipped while the separately sealed native DoH layer handles any Windows-visible static IPv6 pair" -Module $script:ModuleName
        }

        # An active DoH REQUIRE policy (DoHPolicy=3, typically written by this
        # module's own previous Apply) forbids the unencrypted probe that
        # -Validate performs, so live validation would fail on every re-apply
        # after REQUIRE hardening. The exact post-write readback below and the
        # module's DoH verification remain the authoritative proof.
        $dohRequirePolicyActive = $false
        try {
            $dnsClientPolicyKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
            if ($dnsClientPolicyKey -and $dnsClientPolicyKey.GetValueNames() -contains 'DoHPolicy' -and
                [int]$dnsClientPolicyKey.GetValue('DoHPolicy') -eq 3) {
                $dohRequirePolicyActive = $true
                Write-Log -Level DEBUG -Message 'Live IPv4 DNS validation disabled: active DoH REQUIRE policy forbids the unencrypted validation probe' -Module $script:ModuleName
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "DoH policy state could not be read; keeping live validation: $($_.Exception.Message)" -Module $script:ModuleName
        }

        # Retry logic with fast retries (adapter stabilization or offline detection)
        $maxRetries = 3
        $retryDelay = 1  # Fast 1-second retries (no exponential backoff needed)

        foreach ($target in $targets) {
            $configured = $false
            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                try {
                    $dnsParams = @{
                        InputObject    = $target.Instance
                        ServerAddresses = $target.Addresses
                        ErrorAction    = 'Stop'
                    }
                    # Windows' -Validate performs a live reachability check.
                    # A host can have a valid enabled IPv6 stack and default
                    # route while its current network does not route public
                    # IPv6.  In that state the cmdlet rejects well-formed IPv6
                    # resolver addresses even though the same write and exact
                    # readback succeed.  Keep live validation for IPv4; IPv6
                    # is already family-validated above and is proven by the
                    # exact post-write readback below.
                    if ($Validate -and $target.Label -eq 'IPv4' -and -not $dohRequirePolicyActive) {
                        $dnsParams.Validate = $true
                    }
                    Set-DnsClientServerAddress @dnsParams
                    $configured = $true
                    break
                }
                catch {
                    if ($attempt -lt $maxRetries) {
                        Write-Log -Level DEBUG -Message "$($target.Label) attempt $attempt failed, retrying: $($_.Exception.Message)" -Module $script:ModuleName
                        Start-Sleep -Seconds $retryDelay
                    }
                    else {
                        throw "$($target.Label) DNS configuration failed after $maxRetries attempts: $($_.Exception.Message)"
                    }
                }
            }
            if (-not $configured) { throw "$($target.Label) DNS configuration did not complete" }
        }

        $verifiedInstances = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ErrorAction Stop)
        foreach ($target in $targets) {
            $family = [int]$target.Instance.AddressFamily
            $verified = @($verifiedInstances | Where-Object { [int]$_.AddressFamily -eq $family })
            if ($verified.Count -ne 1) { throw "$($target.Label) DNS verification instance is unavailable" }
            $actualAddresses = @($verified[0].ServerAddresses)
            if ($actualAddresses.Count -ne $target.Addresses.Count) {
                throw "$($target.Label) DNS readback does not match the requested server list"
            }
            for ($index = 0; $index -lt $target.Addresses.Count; $index++) {
                $expectedAddress = [System.Net.IPAddress]::Parse([string]$target.Addresses[$index])
                $actualAddress = $null
                if (-not [System.Net.IPAddress]::TryParse([string]$actualAddresses[$index], [ref]$actualAddress) -or
                    -not $expectedAddress.Equals($actualAddress)) {
                    throw "$($target.Label) DNS server order/readback does not match the requested list"
                }
            }
        }

        return $true
    }
    catch {
        Write-ErrorLog -Message "Failed to set DNS servers on interface $InterfaceIndex" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
