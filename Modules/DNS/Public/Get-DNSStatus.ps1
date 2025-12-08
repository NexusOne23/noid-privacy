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
        Show detailed information including DoH templates and provider ratings
        
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
        
        # Load provider configuration for identification
        $configPath = Join-Path $PSScriptRoot "..\Config\Providers.json"
        $providersConfig = $null
        
        if (Test-Path $configPath) {
            $providersConfig = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        }
        
        # Get physical adapters
        $adapters = @(Get-PhysicalAdapters -IncludeDisabled)  # Force array
        
        if ($adapters.Count -eq 0) {
            Write-Log -Level WARNING -Message "No physical network adapters found" -Module $moduleName
            return $null
        }
        
        Write-Log -Level INFO -Message "Found $($adapters.Count) physical network adapter(s)" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName
        
        $statusResults = @()
        
        foreach ($adapter in $adapters) {
            Write-Log -Level INFO -Message "Adapter: $($adapter.Name)" -Module $moduleName
            Write-Log -Level INFO -Message "  Description: $($adapter.InterfaceDescription)" -Module $moduleName
            Write-Log -Level INFO -Message "  Status: $($adapter.Status)" -Module $moduleName
            
            # Get DNS configuration
            $dnsConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            
            $ipv4Addresses = @()
            $ipv6Addresses = @()
            $isDHCP = $false
            
            foreach ($config in $dnsConfig) {
                if ($config.AddressFamily -eq 2) { # IPv4
                    if ($config.ServerAddresses.Count -eq 0) {
                        $isDHCP = $true
                    }
                    else {
                        $ipv4Addresses = $config.ServerAddresses
                    }
                }
                elseif ($config.AddressFamily -eq 23) { # IPv6
                    if ($config.ServerAddresses.Count -gt 0) {
                        # Filter out DHCP placeholder addresses
                        $ipv6Addresses = $config.ServerAddresses | Where-Object { 
                            $_ -notlike "fec0:0:0:ffff*" 
                        }
                    }
                }
            }
            
            # Determine configuration type
            $configType = if ($isDHCP) { "DHCP" } else { "Static" }
            Write-Log -Level INFO -Message "  Configuration: $configType" -Module $moduleName
            
            # Display IPv4
            if ($ipv4Addresses.Count -gt 0) {
                Write-Log -Level INFO -Message "  IPv4 DNS Servers:" -Module $moduleName
                foreach ($ipv4 in $ipv4Addresses) {
                    Write-Log -Level INFO -Message "    - $ipv4" -Module $moduleName
                }
                
                # Try to identify provider
                if ($providersConfig) {
                    $identifiedProvider = $null
                    foreach ($providerProp in $providersConfig.providers.PSObject.Properties) {
                        $provider = $providerProp.Value
                        if ($ipv4Addresses -contains $provider.ipv4.primary) {
                            $identifiedProvider = $provider.name
                            break
                        }
                    }
                    
                    if ($identifiedProvider) {
                        Write-Log -Level INFO -Message "  Detected Provider: $identifiedProvider" -Module $moduleName
                    }
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
                Write-Log -Level INFO -Message "  IPv6 DNS Servers: None configured" -Module $moduleName
            }
            
            # Check DoH status
            $dohServers = @()
            try {
                $allDohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
                if ($allDohServers) {
                    foreach ($dohServer in $allDohServers) {
                        if ($ipv4Addresses -contains $dohServer.ServerAddress) {
                            $dohServers += $dohServer
                        }
                    }
                }
            }
            catch {
                # DoH not supported or not configured
                $null = $null
            }
            
            if ($dohServers.Count -gt 0) {
                Write-Log -Level SUCCESS -Message "  DNS over HTTPS (DoH): ENABLED" -Module $moduleName
                
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
                Write-Log -Level WARNING -Message "  DNS over HTTPS (DoH): DISABLED" -Module $moduleName
            }
            
            Write-Log -Level INFO -Message " " -Module $moduleName
            
            # Add to results
            $statusResults += [PSCustomObject]@{
                AdapterName = $adapter.Name
                AdapterDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                ConfigurationType = $configType
                IPv4Addresses = $ipv4Addresses
                IPv6Addresses = $ipv6Addresses
                DoHEnabled = ($dohServers.Count -gt 0)
                DoHServers = $dohServers
            }
        }
        
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName
        
        return $statusResults
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve DNS status" -Module "DNS" -ErrorRecord $_
        return $null
    }
}
