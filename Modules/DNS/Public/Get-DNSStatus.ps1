function Get-DNSStatus {
    <#
    .SYNOPSIS
        Get current DNS configuration status

    .DESCRIPTION
        Retrieves and displays current DNS configuration for all physical network adapters:
        - DNS server addresses (IPv4 and IPv6)
        - DNS over HTTPS (DoH) status
        - DHCP vs Static configuration
        - Adapter status

    .PARAMETER Detailed
        Show detailed information including DoH templates

    .EXAMPLE
        Get-DNSStatus
        Display current DNS configuration

    .EXAMPLE
        Get-DNSStatus -Detailed
        Display detailed DNS configuration with DoH information

    .OUTPUTS
        PSCustomObject with DNS configuration status

    .NOTES
        Non-intrusive status check - does not modify configuration
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Detailed
    )

    try {
        $moduleName = "DNS"

        Write-Log -Level INFO -Message " " -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "DNS STATUS CHECK" -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName

        # Load and validate provider metadata before reporting against it.
        $providersConfig = Get-DnsProviderConfiguration

        # Get physical adapters
        $adapters = @(Get-PhysicalAdapters -IncludeDisabled)  # Force array

        if ($adapters.Count -eq 0) {
            throw 'No physical network adapters were found; DNS status has no auditable scope'
        }

        Write-Log -Level INFO -Message "Found $($adapters.Count) physical network adapter(s)" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName

        $allDohServers = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
        $ipv6TransportEnabled = Test-DNSIPv6StackEnabled
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $dohPolicyValue = $null
        if (Test-Path -LiteralPath $policyPath) {
            $policyKey = Get-Item -LiteralPath $policyPath -ErrorAction Stop
            if ($policyKey.GetValueNames() -contains 'DoHPolicy') {
                if ($policyKey.GetValueKind('DoHPolicy').ToString() -ne 'DWord') {
                    throw 'DoHPolicy exists with an unsupported non-DWORD type'
                }
                $dohPolicyValue = [int]$policyKey.GetValue('DoHPolicy')
            }
        }
        $dohPolicyLabel = if ($null -eq $dohPolicyValue) {
            'LOCAL/NOT CONFIGURED'
        }
        else {
            switch ($dohPolicyValue) {
                0 { 'DEFAULT/LOCAL (0)' }
                1 { 'PROHIBIT' }
                2 { 'ALLOW' }
                3 { 'REQUIRE' }
                default { "UNKNOWN ($dohPolicyValue)" }
            }
        }

        $statusResults = @()

        foreach ($adapter in $adapters) {
            Write-Log -Level INFO -Message "Adapter: $($adapter.Name)" -Module $moduleName
            Write-Log -Level INFO -Message "  Description: $($adapter.InterfaceDescription)" -Module $moduleName
            Write-Log -Level INFO -Message "  Status: $($adapter.Status)" -Module $moduleName

            # Get DNS configuration
            $dnsConfig = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop)

            $ipv4Addresses = @()
            $ipv6Addresses = @()

            foreach ($config in $dnsConfig) {
                if ($config.AddressFamily -eq 2) { # IPv4
                    if ($config.ServerAddresses.Count -gt 0) {
                        $ipv4Addresses = @($config.ServerAddresses)
                    }
                }
                elseif ($config.AddressFamily -eq 23) { # IPv6
                    if ($config.ServerAddresses.Count -gt 0) {
                        $ipv6Addresses = @($config.ServerAddresses)
                    }
                }
            }
            $interfaceGuidText = [string]$adapter.InterfaceGuid
            if (-not $interfaceGuidText.StartsWith('{')) { $interfaceGuidText = "{$interfaceGuidText}" }
            $ipv6Binding = $adapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
            $ipv6NativeManaged = [bool]$ipv6Binding.Enabled
            $nativeIPv4 = Get-DnsInterfaceDohState `
                -InterfaceGuid $interfaceGuidText -AddressFamily 2
            $nativeIPv6 = if ($ipv6NativeManaged) {
                Get-DnsInterfaceDohState -InterfaceGuid $interfaceGuidText -AddressFamily 23
            }
            else { $null }
            $nativeIPv4Addresses = @($nativeIPv4.NameServers)
            $nativeIPv6Addresses = if ($nativeIPv6) { @($nativeIPv6.NameServers) } else { @() }
            $configuredCanonicalAddresses = @(($ipv4Addresses + $ipv6Addresses +
                    $nativeIPv4Addresses + $nativeIPv6Addresses) |
                ForEach-Object { ConvertTo-DnsCanonicalAddress -Address ([string]$_) } |
                Sort-Object -Unique)
            $staticOverrides = @{}
            foreach ($familyDefinition in @(
                    [PSCustomObject]@{ Label = 'IPv4'; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuidText" },
                    [PSCustomObject]@{ Label = 'IPv6'; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$interfaceGuidText" }
                )) {
                $nameServer = $null
                if (Test-Path -LiteralPath $familyDefinition.Path) {
                    $interfaceKey = Get-Item -LiteralPath $familyDefinition.Path -ErrorAction Stop
                    if ($interfaceKey.GetValueNames() -contains 'NameServer') {
                        $nameServer = $interfaceKey.GetValue(
                            'NameServer',
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )
                    }
                }
                $staticOverrides[$familyDefinition.Label] = -not [string]::IsNullOrWhiteSpace([string]$nameServer)
            }

            $ipv4ConfigType = if ($staticOverrides.IPv4) { 'Static' } else { 'DHCP/default' }
            $ipv6ConfigType = if ($staticOverrides.IPv6) { 'Static' } else { 'DHCP/default' }
            $configType = if ($staticOverrides.IPv4 -and $staticOverrides.IPv6) { 'Static (IPv4+IPv6)' }
                elseif ($staticOverrides.IPv4 -or $staticOverrides.IPv6) { 'Mixed static/default' }
                else { 'DHCP/default' }
            Write-Log -Level INFO -Message "  Configuration: $configType" -Module $moduleName
            Write-Log -Level INFO -Message "    IPv4 source: $ipv4ConfigType" -Module $moduleName
            Write-Log -Level INFO -Message "    IPv6 source: $ipv6ConfigType" -Module $moduleName

            # Display IPv4
            if ($ipv4Addresses.Count -gt 0) {
                Write-Log -Level INFO -Message "  IPv4 DNS Servers:" -Module $moduleName
                foreach ($ipv4 in $ipv4Addresses) {
                    Write-Log -Level INFO -Message "    - $ipv4" -Module $moduleName
                }

            }
            else {
                Write-Log -Level INFO -Message "  IPv4 DNS Servers: None configured (using DHCP)" -Module $moduleName
            }

            # Display IPv6
            if ($ipv6Addresses.Count -gt 0) {
                Write-Log -Level INFO -Message "  IPv6 DNS Servers:" -Module $moduleName
                foreach ($ipv6 in $ipv6Addresses) {
                    Write-Log -Level INFO -Message "    - $ipv6" -Module $moduleName
                }
            }
            else {
                $transportReason = if (-not $ipv6NativeManaged) {
                    'adapter binding disabled'
                }
                elseif (-not $ipv6TransportEnabled) { 'transport disabled by DisabledComponents=0xFF' }
                else { 'none configured' }
                Write-Log -Level INFO -Message "  Effective IPv6 DNS Servers: None ($transportReason)" -Module $moduleName
            }
            if ($nativeIPv6Addresses.Count -gt 0) {
                Write-Log -Level INFO -Message "  Persisted native IPv6 DNS Servers (Windows Settings):" -Module $moduleName
                foreach ($ipv6 in $nativeIPv6Addresses) {
                    Write-Log -Level INFO -Message "    - $ipv6" -Module $moduleName
                }
            }

            # Identify a provider only from an exact applicable native resolver
            # pair, never from a single overlapping endpoint.
            $identifiedProvider = $null
            foreach ($providerProp in $providersConfig.providers.PSObject.Properties) {
                $provider = $providerProp.Value
                $expectedIPv4 = @(@($provider.ipv4.primary, $provider.ipv4.secondary) |
                    ForEach-Object { ConvertTo-DnsCanonicalAddress -Address ([string]$_) })
                $expectedIPv6 = @(@($provider.ipv6.primary, $provider.ipv6.secondary) |
                    ForEach-Object { ConvertTo-DnsCanonicalAddress -Address ([string]$_) })
                $actualIPv4 = @($nativeIPv4Addresses | ForEach-Object {
                        ConvertTo-DnsCanonicalAddress -Address ([string]$_)
                    })
                $actualIPv6 = @($nativeIPv6Addresses | ForEach-Object {
                        ConvertTo-DnsCanonicalAddress -Address ([string]$_)
                    })
                $ipv4Match = (($actualIPv4 | ConvertTo-Json -Compress) -ceq
                    ($expectedIPv4 | ConvertTo-Json -Compress))
                $ipv6Match = (-not $ipv6NativeManaged -or
                    (($actualIPv6 | ConvertTo-Json -Compress) -ceq
                     ($expectedIPv6 | ConvertTo-Json -Compress)))
                if ($ipv4Match -and $ipv6Match) {
                    $identifiedProvider = $provider
                    break
                }
            }
            if ($identifiedProvider) {
                Write-Log -Level INFO -Message "  Detected Provider: $($identifiedProvider.name) (exact native scope)" -Module $moduleName
            }

            # Check global registrations plus the native/UI-visible encrypted
            # state separately from effective IPv6 transport.
            $dohServers = @()
            foreach ($dohServer in $allDohServers) {
                $canonicalDohAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$dohServer.ServerAddress)
                if ($configuredCanonicalAddresses -contains $canonicalDohAddress) {
                    $dohServers += $dohServer
                }
            }
            $nativeIPv4Encrypted = $false
            $nativeIPv6Encrypted = -not $ipv6NativeManaged
            $dohConfigured = $false
            if ($identifiedProvider -and $dohPolicyValue -in @(2, 3)) {
                $allowFallback = ($dohPolicyValue -eq 2)
                $expectedNativeIPv4 = ConvertTo-DnsInterfaceDohTargetState `
                    -AddressFamily 2 `
                    -NameServers @($identifiedProvider.ipv4.primary, $identifiedProvider.ipv4.secondary) `
                    -DohTemplate ([string]$identifiedProvider.doh.template) `
                    -AllowFallbackToUdp $allowFallback
                $nativeIPv4Encrypted = Test-DnsInterfaceDohStateExact `
                    -Actual $nativeIPv4 -Expected $expectedNativeIPv4
                if ($ipv6NativeManaged) {
                    $expectedNativeIPv6 = ConvertTo-DnsInterfaceDohTargetState `
                        -AddressFamily 23 `
                        -NameServers @($identifiedProvider.ipv6.primary, $identifiedProvider.ipv6.secondary) `
                        -DohTemplate ([string]$identifiedProvider.doh.template) `
                        -AllowFallbackToUdp $allowFallback
                    $nativeIPv6Encrypted = Test-DnsInterfaceDohStateExact `
                        -Actual $nativeIPv6 -Expected $expectedNativeIPv6
                }
                $expectedRegistrationAddresses = @(
                    $identifiedProvider.ipv4.primary, $identifiedProvider.ipv4.secondary
                    $identifiedProvider.ipv6.primary, $identifiedProvider.ipv6.secondary
                )
                $registrationMatches = @(foreach ($address in $expectedRegistrationAddresses) {
                        $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$address)
                        @($allDohServers | Where-Object {
                                (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalAddress -and
                                [string]$_.DohTemplate -ceq [string]$identifiedProvider.doh.template -and
                                [bool]$_.AutoUpgrade -and
                                [bool]$_.AllowFallbackToUdp -eq $allowFallback
                            }).Count -eq 1
                    })
                $dohConfigured = ($nativeIPv4Encrypted -and $nativeIPv6Encrypted -and
                    @($registrationMatches | Where-Object { -not $_ }).Count -eq 0)
            }

            if ($dohServers.Count -gt 0) {
                Write-Log -Level SUCCESS -Message "  DoH resolver registration: PRESENT" -Module $moduleName
                Write-Log -Level INFO -Message "  DoH policy: $dohPolicyLabel" -Module $moduleName
                Write-Log -Level $(if ($nativeIPv4Encrypted) { 'SUCCESS' } else { 'WARNING' }) `
                    -Message "  Windows-visible IPv4 encrypted configuration: $(if ($nativeIPv4Encrypted) { 'EXACT' } else { 'NOT EXACT' })" -Module $moduleName
                if ($ipv6NativeManaged) {
                    Write-Log -Level $(if ($nativeIPv6Encrypted) { 'SUCCESS' } else { 'WARNING' }) `
                        -Message "  Windows-visible IPv6 encrypted configuration: $(if ($nativeIPv6Encrypted) { 'EXACT' } else { 'NOT EXACT' })" -Module $moduleName
                }
                Write-Log -Level INFO -Message "  IPv6 transport: $(if ($ipv6TransportEnabled -and $ipv6NativeManaged) { 'enabled' } else { 'disabled/outside effective resolver scope' })" -Module $moduleName
                Write-Log -Level INFO -Message "  Runtime transport note: configuration is present; this status command does not claim per-query wire verification" -Module $moduleName

                if ($Detailed) {
                    foreach ($doh in $dohServers) {
                        Write-Log -Level INFO -Message "    Server: $($doh.ServerAddress)" -Module $moduleName
                        Write-Log -Level INFO -Message "      Template: $($doh.DohTemplate)" -Module $moduleName
                        Write-Log -Level INFO -Message "      Fallback to UDP: $($doh.AllowFallbackToUdp)" -Module $moduleName
                        Write-Log -Level INFO -Message "      Auto-upgrade: $($doh.AutoUpgrade)" -Module $moduleName
                    }
                }
            }
            else {
                Write-Log -Level WARNING -Message "  DoH resolver registration: NOT PRESENT for configured adapter addresses" -Module $moduleName
                Write-Log -Level INFO -Message "  DoH policy: $dohPolicyLabel" -Module $moduleName
            }

            Write-Log -Level INFO -Message " " -Module $moduleName

            # Add to results
            $statusResults += [PSCustomObject]@{
                AdapterName = $adapter.Name
                AdapterDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                ConfigurationType = $configType
                IPv4ConfigurationType = $ipv4ConfigType
                IPv6ConfigurationType = $ipv6ConfigType
                IPv4Addresses = $ipv4Addresses
                IPv6Addresses = $ipv6Addresses
                NativeIPv4Addresses = $nativeIPv4Addresses
                NativeIPv6Addresses = $nativeIPv6Addresses
                IPv6BindingEnabled = $ipv6NativeManaged
                IPv6TransportEnabled = ($ipv6TransportEnabled -and $ipv6NativeManaged)
                NativeIPv4Encrypted = $nativeIPv4Encrypted
                NativeIPv6Encrypted = if ($ipv6NativeManaged) { $nativeIPv6Encrypted } else { $null }
                DoHEnabled = $dohConfigured
                DoHConfigured = $dohConfigured
                DoHRegistered = ($dohServers.Count -gt 0)
                DoHPolicy = $dohPolicyLabel
                DoHServers = $dohServers
                DetectedProvider = if ($identifiedProvider) { [string]$identifiedProvider.name } else { $null }
            }
        }

        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName

        return $statusResults
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve DNS status" -Module "DNS" -ErrorRecord $_
        throw
    }
}
