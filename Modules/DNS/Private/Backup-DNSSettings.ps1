function Backup-DNSSettings {
    <#
    .SYNOPSIS
        Backup current DNS settings for all physical network adapters
        
    .DESCRIPTION
        Creates a comprehensive backup of DNS configuration including:
        - Current DNS server addresses (IPv4 and IPv6)
        - DHCP status (was DNS obtained from DHCP?)
        - DoH configuration
        - Adapter interface information
        
        Backup is stored using the framework's rollback system.
        
    .PARAMETER DryRun
        Show what would be backed up without actually creating backup
        
    .EXAMPLE
        Backup-DNSSettings
        Creates backup of current DNS settings
        
    .OUTPUTS
        System.String - Path to backup file or $null if failed
        
    .NOTES
        DHCP awareness is critical for correct rollback behavior
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        Write-Log -Level INFO -Message "Backing up DNS settings..." -Module $script:ModuleName
        
        # Get all physical adapters
        $adapters = @(Get-PhysicalAdapters)  # Force array
        
        if ($adapters.Count -eq 0) {
            Write-Log -Level WARNING -Message "No physical adapters found to backup" -Module $script:ModuleName
            return $null
        }
        
        Write-Log -Level DEBUG -Message "Found $($adapters.Count) adapter(s) to backup" -Module $script:ModuleName
        
        # Get netsh global DoH state
        $netshGlobalDoh = $null
        try {
            $netshResult = netsh dnsclient show global 2>&1 | Out-String
            if ($netshResult -match "DoH\s*:\s*(\w+)") {
                $netshGlobalDoh = $matches[1]
                Write-Log -Level DEBUG -Message "netsh global DoH state: $netshGlobalDoh" -Module $script:ModuleName
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Could not retrieve netsh global DoH state: $_" -Module $script:ModuleName
        }
        
        # Get all netsh DoH encryption entries
        $netshDohEntries = @()
        try {
            $netshEncryption = netsh dnsclient show encryption 2>&1 | Out-String
            # Parse netsh output for DoH servers
            # Format: "Server: X.X.X.X | Template: https://... | Auto-upgrade: yes | UDP fallback: no"
            $lines = $netshEncryption -split "`n"
            foreach ($line in $lines) {
                if ($line -match "Server:\s*(\S+)") {
                    $server = $matches[1]
                    $template = $null
                    $autoupgrade = $null
                    $udpfallback = $null
                    
                    if ($netshEncryption -match "Server:\s*$([regex]::Escape($server)).*?Template:\s*(\S+)") {
                        $template = $matches[1]
                    }
                    if ($netshEncryption -match "Server:\s*$([regex]::Escape($server)).*?Auto-upgrade:\s*(\w+)") {
                        $autoupgrade = $matches[1]
                    }
                    if ($netshEncryption -match "Server:\s*$([regex]::Escape($server)).*?UDP fallback:\s*(\w+)") {
                        $udpfallback = $matches[1]
                    }
                    
                    if ($template) {
                        $netshDohEntries += @{
                            Server = $server
                            Template = $template
                            AutoUpgrade = $autoupgrade
                            UdpFallback = $udpfallback
                        }
                        Write-Log -Level DEBUG -Message "Found netsh DoH entry: $server" -Module $script:ModuleName
                    }
                }
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Could not retrieve netsh DoH entries: $_" -Module $script:ModuleName
        }
        
        $dohEntries = @()
        try {
            $allDoh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
            if ($allDoh) {
                foreach ($entry in $allDoh) {
                    if ($entry.ServerAddress -and $entry.DohTemplate) {
                        $dohEntries += @{
                            ServerAddress = $entry.ServerAddress
                            DohTemplate = $entry.DohTemplate
                            AllowFallbackToUdp = $entry.AllowFallbackToUdp
                            AutoUpgrade = $entry.AutoUpgrade
                        }
                    }
                }
                Write-Log -Level DEBUG -Message "Backed up $($dohEntries.Count) DoH entries from Get-DnsClientDohServerAddress" -Module $script:ModuleName
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Could not retrieve DoH entries via Get-DnsClientDohServerAddress: $_" -Module $script:ModuleName
        }
        
        # Get DoH Policy Registry settings
        $dohPolicySettings = @{}
        try {
            $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            if (Test-Path $dnsClientPath) {
                $dohPolicy = (Get-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -ErrorAction SilentlyContinue).DoHPolicy
                if ($null -ne $dohPolicy) {
                    $dohPolicySettings['DoHPolicy'] = $dohPolicy
                }
            }
            
            $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            if (Test-Path $dnsParamsPath) {
                $enableAutoDoh = (Get-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue).EnableAutoDoh
                if ($null -ne $enableAutoDoh) {
                    $dohPolicySettings['EnableAutoDoh'] = $enableAutoDoh
                }
                
                # NOTE: Global DohFlags no longer used (we use per-adapter DohFlags instead)
                # Kept for backward compatibility with old backups, but not written anymore
            }
            
            Write-Log -Level DEBUG -Message "Backed up DoH policy settings: $($dohPolicySettings.Count) keys" -Module $script:ModuleName
        }
        catch {
            Write-Log -Level DEBUG -Message "Could not retrieve DoH policy settings: $_" -Module $script:ModuleName
        }
        
        $backupData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            NetshGlobalDoh = $netshGlobalDoh
            NetshDohEntries = $netshDohEntries
            DohEntries = $dohEntries
            DohPolicySettings = $dohPolicySettings
            Adapters = @()
        }
        
        foreach ($adapter in $adapters) {
            Write-Log -Level DEBUG -Message "Backing up adapter: $($adapter.Name)" -Module $script:ModuleName
            
            # Get current DNS configuration
            $dnsConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            
            # Collect DNS addresses first
            $ipv4Addresses = @()
            $ipv6Addresses = @()
            
            foreach ($config in $dnsConfig) {
                if ($config.AddressFamily -eq 2) { # IPv4
                    if ($config.ServerAddresses.Count -gt 0) {
                        $ipv4Addresses = $config.ServerAddresses
                    }
                }
                elseif ($config.AddressFamily -eq 23) { # IPv6
                    if ($config.ServerAddresses.Count -gt 0 -and
                        $config.ServerAddresses -notcontains "fec0:0:0:ffff::1" -and
                        $config.ServerAddresses -notcontains "fec0:0:0:ffff::2" -and
                        $config.ServerAddresses -notcontains "fec0:0:0:ffff::3") {
                        # Only if not DHCP placeholder addresses
                        $ipv6Addresses = $config.ServerAddresses
                    }
                }
            }
            
            # CRITICAL FIX: Determine DHCP status AFTER collecting all addresses
            # DNS is from DHCP only if NO addresses are configured (neither IPv4 nor IPv6)
            $isDHCP = ($ipv4Addresses.Count -eq 0) -and ($ipv6Addresses.Count -eq 0)
            
            # Get DoH configuration for this adapter's DNS servers
            $dohConfig = @()
            try {
                $allDohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
                if ($allDohServers) {
                    foreach ($dohServer in $allDohServers) {
                        if ($ipv4Addresses -contains $dohServer.ServerAddress -or 
                            $ipv6Addresses -contains $dohServer.ServerAddress) {
                            $dohConfig += @{
                                ServerAddress = $dohServer.ServerAddress
                                DohTemplate = $dohServer.DohTemplate
                                AllowFallbackToUdp = $dohServer.AllowFallbackToUdp
                                AutoUpgrade = $dohServer.AutoUpgrade
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not retrieve DoH configuration: $_" -Module $script:ModuleName
            }
            
            # Get DohFlags registry settings for this adapter
            $dohFlags = @{}
            try {
                $interfaceGuid = $adapter.InterfaceGuid
                $dohFlagsBasePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$interfaceGuid\DohInterfaceSettings\Doh"
                
                if (Test-Path $dohFlagsBasePath) {
                    # Check each DNS server IP
                    $allDnsIPs = $ipv4Addresses + $ipv6Addresses
                    foreach ($dnsIP in $allDnsIPs) {
                        $dohFlagsPath = "$dohFlagsBasePath\$dnsIP"
                        if (Test-Path $dohFlagsPath) {
                            $flagValue = (Get-ItemProperty -Path $dohFlagsPath -Name "DohFlags" -ErrorAction SilentlyContinue).DohFlags
                            if ($null -ne $flagValue) {
                                $dohFlags[$dnsIP] = $flagValue
                                Write-Log -Level DEBUG -Message "Found DohFlags for $dnsIP : $flagValue" -Module $script:ModuleName
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not retrieve DohFlags: $_" -Module $script:ModuleName
            }
            
            # Get DHCP DNS Override setting for this adapter
            $dhcpOverrideDisabled = $null
            try {
                $dnsClient = Get-DnsClient -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($dnsClient) {
                    $dhcpOverrideDisabled = (-not $dnsClient.RegisterThisConnectionsAddress)
                    Write-Log -Level DEBUG -Message "DHCP Override disabled: $dhcpOverrideDisabled" -Module $script:ModuleName
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not retrieve DHCP override setting: $_" -Module $script:ModuleName
            }
            
            $adapterBackup = @{
                InterfaceIndex = $adapter.InterfaceIndex
                InterfaceAlias = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                InterfaceGuid = $adapter.InterfaceGuid
                Status = $adapter.Status
                IsDHCP = $isDHCP
                IPv4Addresses = $ipv4Addresses
                IPv6Addresses = $ipv6Addresses
                DoHConfiguration = $dohConfig
                DohFlags = $dohFlags
                DhcpOverrideDisabled = $dhcpOverrideDisabled
            }
            
            $backupData.Adapters += $adapterBackup
            
            $statusText = if ($isDHCP) { "DHCP" } else { "Static" }
            $dnsText = if ($isDHCP) { "from DHCP" } else { "$($ipv4Addresses.Count) IPv4, $($ipv6Addresses.Count) IPv6" }
            Write-Log -Level INFO -Message "  - $($adapter.Name): $statusText ($dnsText)" -Module $script:ModuleName
        }
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would backup DNS settings for $($adapters.Count) adapter(s)" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - netsh global DoH state" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - netsh DoH encryption entries" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - DoH Policy Registry (DoHPolicy, EnableAutoDoh, DohFlags)" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - Per-adapter DohFlags registry" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - DHCP DNS override settings" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   - DNS server addresses" -Module $script:ModuleName
            return "DRYRUN"
        }
        
        # Convert to JSON and save using rollback system
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        $backupFile = Register-Backup -Type "DNS" -Data $backupJson
        
        if ($backupFile) {
            Write-Log -Level SUCCESS -Message "DNS settings backed up successfully" -Module $script:ModuleName
            return $backupFile
        }
        else {
            Write-Log -Level ERROR -Message "Failed to register DNS backup" -Module $script:ModuleName
            return $null
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to backup DNS settings" -Module $script:ModuleName -ErrorRecord $_
        return $null
    }
}
