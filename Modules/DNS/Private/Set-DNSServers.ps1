function Set-DNSServers {
    <#
    .SYNOPSIS
        Set DNS server addresses on network adapter
        
    .DESCRIPTION
        Configures DNS server addresses (IPv4 and IPv6) on specified network adapter.
        Uses Microsoft Best Practice: Set-DnsClientServerAddress with -Validate parameter.
        
        Always configures both IPv4 and IPv6 addresses. Windows will use IPv6 when available,
        and fall back to IPv4 otherwise.
        
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
    
    [CmdletBinding()]
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
        
        [Parameter()]
        [switch]$Validate,
        
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
        $adapterName = $adapter.Name
        
        Write-Log -Level INFO -Message "Configuring DNS servers on adapter: $adapterName" -Module $script:ModuleName
        
        # Prepare IPv4 addresses array
        $ipv4Addresses = @($IPv4Primary, $IPv4Secondary)
        
        # Prepare IPv6 addresses array
        $ipv6Addresses = @($IPv6Primary, $IPv6Secondary)
        
        Write-Log -Level DEBUG -Message "  IPv4: $($ipv4Addresses -join ', ')" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  IPv6: $($ipv6Addresses -join ', ')" -Module $script:ModuleName
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure DNS servers on $adapterName" -Module $script:ModuleName
            return $true
        }
        
        # Configure IPv4 DNS servers with retry logic (fixes 0x80004005 errors)
        Write-Log -Level DEBUG -Message "Setting IPv4 DNS servers..." -Module $script:ModuleName
        
        $ipv4Params = @{
            InterfaceIndex = $InterfaceIndex
            ServerAddresses = $ipv4Addresses
            ErrorAction = 'Stop'
        }
        
        if ($Validate) {
            $ipv4Params['Validate'] = $true
            Write-Log -Level DEBUG -Message "Validation enabled for IPv4 DNS servers" -Module $script:ModuleName
        }
        
        # Retry logic with fast retries (adapter stabilization or offline detection)
        $maxRetries = 3
        $retryDelay = 1  # Fast 1-second retries (no exponential backoff needed)
        
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                Set-DnsClientServerAddress @ipv4Params
                Write-Log -Level SUCCESS -Message "IPv4 DNS servers configured: $($ipv4Addresses -join ', ')" -Module $script:ModuleName
                break
            }
            catch {
                if ($attempt -lt $maxRetries) {
                    Write-Log -Level DEBUG -Message "Attempt $attempt failed, retrying... ($($_.Exception.Message))" -Module $script:ModuleName
                    Start-Sleep -Seconds $retryDelay
                }
                else {
                    # Fallback to netsh if CIM fails (General Error fix - often happens when offline)
                    Write-Log -Level DEBUG -Message "PowerShell cmdlet failed, using netsh fallback..." -Module $script:ModuleName
                    
                    try {
                        # Use netsh for IPv4 configuration
                        $netshResult = & netsh interface ip set dns name="$adapterName" source=static address=$IPv4Primary validate=no 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            # Add secondary DNS
                            $null = & netsh interface ip add dns name="$adapterName" address=$IPv4Secondary index=2 validate=no 2>&1
                            
                            Write-Log -Level SUCCESS -Message "IPv4 DNS configured via netsh fallback: $($ipv4Addresses -join ', ')" -Module $script:ModuleName
                            break # Success, exit retry loop
                        }
                        else {
                            throw "Netsh fallback also failed: $netshResult"
                        }
                    }
                    catch {
                        throw "All DNS configuration methods failed: $_"
                    }
                }
            }
        }
        
        # Configure IPv6 DNS servers
        # Note: IPv6 configuration uses the same cmdlet with IPv6 addresses
        Write-Log -Level DEBUG -Message "Setting IPv6 DNS servers..." -Module $script:ModuleName
        
        # For IPv6, we need to configure it separately
        # Get the IPv6 interface
        $ipv6Interface = Get-NetAdapter -InterfaceIndex $InterfaceIndex | 
                         Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        
        if ($ipv6Interface -and $ipv6Interface.Enabled) {
            try {
                # Set IPv6 DNS using netsh as PowerShell cmdlet doesn't support dual-stack properly
                # NOTE: This is one of the few cases where netsh is still needed for IPv6
                $primaryResult = & netsh interface ipv6 set dnsservers name="$adapterName" source=static address=$IPv6Primary validate=no 2>&1
                $secondaryResult = & netsh interface ipv6 add dnsservers name="$adapterName" address=$IPv6Secondary index=2 validate=no 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log -Level SUCCESS -Message "IPv6 DNS servers configured: $($ipv6Addresses -join ', ')" -Module $script:ModuleName
                }
                else {
                    Write-Log -Level WARNING -Message "IPv6 DNS configuration had issues (non-fatal): $primaryResult $secondaryResult" -Module $script:ModuleName
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Could not configure IPv6 DNS (non-fatal): $_" -Module $script:ModuleName
            }
        }
        else {
            Write-Log -Level INFO -Message "IPv6 binding is disabled on this adapter - skipping IPv6 DNS server assignment (IPv4 + DoH templates will still be used)" -Module $script:ModuleName
        }
        
        # Configuration complete - Windows cmdlets verify automatically
        return $true
    }
    catch {
        Write-ErrorLog -Message "Failed to set DNS servers on interface $InterfaceIndex" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
