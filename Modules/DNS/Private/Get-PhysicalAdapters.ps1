function Get-PhysicalAdapters {
    <#
    .SYNOPSIS
        Get physical network adapters (LAN/WLAN) excluding virtual adapters
        
    .DESCRIPTION
        Retrieves physical network adapters using multi-layer filtering to exclude:
        - Virtual adapters (Hyper-V, VMware, VirtualBox)
        - VPN adapters (TAP, OpenVPN, WireGuard, Cisco, etc.)
        - Tunnel adapters (Teredo, 6to4, ISATAP)
        - Loopback adapters
        
        Uses Microsoft Best Practice: Get-NetAdapter with -Physical switch
        and additional filtering based on InterfaceDescription patterns.
        
    .PARAMETER IncludeDisabled
        Include disabled adapters in results
        
    .EXAMPLE
        Get-PhysicalAdapters
        Returns all active physical network adapters
        
    .EXAMPLE
        Get-PhysicalAdapters -IncludeDisabled
        Returns all physical adapters including disabled ones
        
    .OUTPUTS
        Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter
        
    .NOTES
        Uses Get-NetAdapter -Physical for primary filtering (Microsoft Best Practice)
        Additional filtering excludes known virtual adapter patterns
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeDisabled
    )
    
    try {
        Write-Log -Level DEBUG -Message "Retrieving physical network adapters..." -Module $script:ModuleName
        
        # Layer 1: Get physical adapters only (Microsoft Best Practice)
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop
        
        # Layer 2: Filter by status if required
        if (-not $IncludeDisabled) {
            # Allow 'Up' (Connected) and 'Disconnected' (Cable unplugged)
            # Only filter out 'Disabled' (Administratively down) or 'Not Present'
            $adapters = $adapters | Where-Object { $_.Status -eq "Up" -or $_.Status -eq "Disconnected" }
            Write-Log -Level DEBUG -Message "Filtering to active/disconnected adapters (excluding disabled)" -Module $script:ModuleName
        }
        
        # Layer 3: Exclude virtual adapter patterns (COMPREHENSIVE!)
        # NOTE: We distinguish between HOST-side and GUEST-side virtual adapters:
        # - HOST-side (vEthernet, VMware Network Adapter VMnet*) → EXCLUDE
        # - GUEST-side (Microsoft Hyper-V Network Adapter in VM) → KEEP!
        $virtualPatterns = @(
            # Host-side virtualization adapters (NOT guest adapters!)
            '*vEthernet*',                    # Hyper-V HOST virtual switch
            '*VMware Network Adapter*',       # VMware HOST adapters (VMnet1, VMnet8)
            '*VirtualBox Host-Only*',         # VirtualBox HOST-only adapter
            '*Virtual*Adapter*',              # Generic virtual adapters
            '*Container*', '*WSL*', '*Docker*',
            # Generic VPN protocols
            '*VPN*', '*OpenVPN*', '*WireGuard*', '*TAP*',
            '*L2TP*', '*IKEv2*', '*RAS*', '*PPTP*',
            # Consumer VPN vendors
            '*NordVPN*', '*NordLynx*', '*ExpressVPN*', '*ProtonVPN*', '*Mullvad*',
            # Enterprise VPN vendors
            '*Cisco*', '*Pulse*', '*FortiClient*',
            '*Palo Alto*', '*PANGP*', # Palo Alto GlobalProtect (no "VPN" in name!)
            '*F5*', '*Checkpoint*', '*Check Point*', '*Sonicwall*', '*Juniper*',
            # Tunnel adapters
            '*Tunnel*', '*Teredo*', '*6to4*', '*ISATAP*', '*Loopback*'
        )
        
        # Layer 4: Check for active Windows VPN connections
        $activeVpnConnections = @()
        try {
            $vpnConns = Get-VpnConnection -ErrorAction SilentlyContinue
            $activeVpnConnections = $vpnConns | Where-Object { $_.ConnectionStatus -eq 'Connected' }
        }
        catch {
            Write-Log -Level DEBUG -Message "Get-VpnConnection not available or failed: $_" -Module $script:ModuleName
        }
        
        $filteredAdapters = @($adapters | Where-Object {
            $description = $_.InterfaceDescription
            $name = $_.Name
            $skipAdapter = $false
            $skipReason = ""
            
            # Check if adapter matches any virtual pattern
            foreach ($pattern in $virtualPatterns) {
                if ($description -like $pattern -or $name -like $pattern) {
                    $skipAdapter = $true
                    $skipReason = "Pattern match: $pattern"
                    break
                }
            }
            
            # Check if InterfaceType is Tunnel (131)
            if (-not $skipAdapter -and $_.InterfaceType -eq 131) {
                $skipAdapter = $true
                $skipReason = "InterfaceType = 131 (Tunnel)"
            }
            
            # Check MediaType for Tunnel
            if (-not $skipAdapter -and $_.MediaType -match "Tunnel") {
                $skipAdapter = $true
                $skipReason = "MediaType contains 'Tunnel'"
            }
            
            # Check for native Windows VPN connection
            if (-not $skipAdapter -and $activeVpnConnections) {
                $currentAdapterAlias = $_.InterfaceAlias
                $matchingVpn = $activeVpnConnections | Where-Object { $_.InterfaceAlias -eq $currentAdapterAlias }
                if ($matchingVpn) {
                    $skipAdapter = $true
                    $skipReason = "Native Windows VPN active: $($matchingVpn.Name)"
                }
            }
            
            if ($skipAdapter) {
                Write-Log -Level DEBUG -Message "Excluding adapter: $name - $skipReason" -Module $script:ModuleName
            }
            
            -not $skipAdapter
        })  # Close @( array wrapper
        
        if ($filteredAdapters.Count -eq 0) {
            Write-Log -Level WARNING -Message "No physical network adapters found" -Module $script:ModuleName
            return @()
        }
        
        Write-Log -Level DEBUG -Message "Found $($filteredAdapters.Count) physical network adapter(s)" -Module $script:ModuleName
        
        foreach ($adapter in $filteredAdapters) {
            Write-Log -Level DEBUG -Message "  - $($adapter.Name) ($($adapter.InterfaceDescription)) [Status: $($adapter.Status)]" -Module $script:ModuleName
        }
        
        return $filteredAdapters  # Already wrapped as array in line 83
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve physical network adapters" -Module $script:ModuleName -ErrorRecord $_
        return @()
    }
}
