# =======================================================================================
# SecurityBaseline-DNS-Common.ps1 - Common DNS Helper Functions
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Reset-NoID-DnsState {
    <#
    .SYNOPSIS
        Cleans up ALL DoH entries from ALL known providers
    .DESCRIPTION
        Deletes all DoH registrations (Cloudflare, AdGuard, NextDNS, Quad9)
        and removes per-adapter DoH registry keys to ensure clean state.
        
        CRITICAL: This prevents stale DoH entries from previous providers
        from interfering with new provider settings.
    .PARAMETER KeepAdapterDns
        If specified, keeps current DNS server addresses on adapters.
        Otherwise resets adapters to automatic DHCP DNS.
    #>
    [CmdletBinding()]
    param(
        [switch]$KeepAdapterDns
    )
    
    Write-Verbose "Cleaning up DNS state (all providers)..."
    
    # 1. Delete ALL known DoH server registrations
    $allKnownIps = @(
        # Cloudflare (Standard)
        '1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001',
        # Cloudflare (Family - Malware blocking)
        '1.1.1.2', '1.0.0.2', '2606:4700:4700::1112', '2606:4700:4700::1002',
        # Cloudflare (Family - Malware + Adult blocking)
        '1.1.1.3', '1.0.0.3', '2606:4700:4700::1113', '2606:4700:4700::1003',
        # AdGuard
        '94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff',
        # NextDNS
        '45.90.28.0', '45.90.30.0', '2a07:a8c0::', '2a07:a8c1::',
        # Quad9
        '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'
    ) | Select-Object -Unique
    
    foreach ($ip in $allKnownIps) {
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        try {
            netsh dnsclient delete encryption server=$ip 2>$null | Out-Null
            Write-Verbose "  Deleted DoH entry: $ip"
        }
        catch {
            # Ignore - entry might not exist
        }
    }
    
    # 2. Clean per-adapter DoH registry keys (all GUIDs)
    $basePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    if (Test-Path $basePath) {
        Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
            $adapterPath = $_.PSPath
            
            # Remove Doh4 settings
            if (Test-Path "$adapterPath\DohInterfaceSettings") {
                Remove-Item "$adapterPath\DohInterfaceSettings" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Verbose "  Cleaned DoH4 registry: $($_.PSChildName)"
            }
            
            # Remove Doh6 settings
            if (Test-Path "$adapterPath\Doh6") {
                Remove-Item "$adapterPath\Doh6" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Verbose "  Cleaned DoH6 registry: $($_.PSChildName)"
            }
        }
    }
    
    # 3. Optional: Reset adapters to automatic DHCP DNS
    if (-not $KeepAdapterDns) {
        Write-Verbose "Resetting adapters to automatic DNS..."
        Get-DnsClient -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceOperationalStatus -eq 'Up' } |
            ForEach-Object {
                try {
                    Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias `
                        -ResetServerAddresses -ErrorAction Stop
                    Write-Verbose "  Reset: $($_.InterfaceAlias)"
                }
                catch {
                    Write-Verbose "  Failed to reset: $($_.InterfaceAlias)"
                }
            }
    }
    
    Write-Verbose "DNS state cleanup complete"
}

function Get-NoID-NetworkAdapters {
    <#
    .SYNOPSIS
        Gets active network adapters excluding VPN and virtualization adapters
    .DESCRIPTION
        Returns only physical/real network adapters that should be configured
        with DNS settings. Skips VPN, virtual, and container adapters.
        
        CRITICAL: This ensures DNS settings are only applied to real network
        interfaces, not VPN tunnels or VM bridges.
    .OUTPUTS
        Array of NetAdapter objects (only real, active adapters)
    #>
    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance[]])]
    param()
    
    # Patterns for VPN adapters
    # COMPREHENSIVE LIST: Generic protocols + Consumer VPNs + Enterprise VPNs
    $vpnPatterns = @(
        # Generic VPN protocols
        '*VPN*', '*OpenVPN*', '*WireGuard*', '*TAP*',
        '*L2TP*', '*IKEv2*', '*RAS*', '*PPTP*',
        
        # Consumer VPN vendors
        '*NordVPN*', '*NordLynx*',     # NordVPN (NordLynx = WireGuard-based, no "VPN" in name!)
        '*ExpressVPN*',                 # ExpressVPN
        '*ProtonVPN*',                  # ProtonVPN
        '*Mullvad*',                    # Mullvad VPN
        
        # Enterprise VPN vendors
        '*Cisco*',                      # Cisco AnyConnect
        '*Pulse*',                      # Pulse Secure
        '*FortiClient*',                # FortiClient VPN
        '*Palo Alto*', '*PANGP*',       # Palo Alto GlobalProtect (PANGP adapter - NO "VPN" in name!)
        '*F5*',                         # F5 BIG-IP Edge Client
        '*Checkpoint*', '*Check Point*', # Check Point VPN
        '*Sonicwall*',                  # SonicWall VPN
        '*Juniper*'                     # Juniper Networks (NO "VPN" in name!)
    )
    
    # Patterns for virtualization adapters
    $virtPatterns = @(
        '*Virtual*', '*Hyper-V*', '*VMware*', '*VirtualBox*',
        '*Container*', '*WSL*', '*Docker*', '*vEthernet*'
    )
    
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' }
    
    # Get active native Windows VPN connections (Level 5)
    $activeVpnConnections = @()
    try {
        $vpnConns = Get-VpnConnection -ErrorAction SilentlyContinue
        $activeVpnConnections = $vpnConns | Where-Object { $_.ConnectionStatus -eq 'Connected' }
    }
    catch {
        Write-Verbose "Get-VpnConnection not available or failed: $_"
    }
    
    $realAdapters = @()
    
    foreach ($adapter in $allAdapters) {
        $skipAdapter = $false
        $skipReason = ""
        
        # LEVEL 1: Name/Description Pattern Matching
        $isVPN = $vpnPatterns | Where-Object {
            $adapter.InterfaceDescription -like $_ -or $adapter.Name -like $_
        }
        
        $isVirt = $virtPatterns | Where-Object {
            $adapter.InterfaceDescription -like $_ -or $adapter.Name -like $_
        }
        
        if ($isVPN) {
            $skipAdapter = $true
            $skipReason = "VPN pattern match (Name/Description)"
        }
        elseif ($isVirt) {
            $skipAdapter = $true
            $skipReason = "Virtual adapter pattern match"
        }
        
        # LEVEL 2: InterfaceType Check (131 = Tunnel)
        if (-not $skipAdapter -and $adapter.InterfaceType -eq 131) {
            $skipAdapter = $true
            $skipReason = "InterfaceType = 131 (Tunnel)"
        }
        
        # LEVEL 3: MediaType Check (contains "Tunnel")
        if (-not $skipAdapter -and $adapter.MediaType -match "Tunnel") {
            $skipAdapter = $true
            $skipReason = "MediaType contains 'Tunnel'"
        }
        
        # LEVEL 4: ComponentID Check (TAP adapter)
        if (-not $skipAdapter) {
            try {
                $binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue |
                    Where-Object { $_.ComponentID -match "tap" }
                if ($binding) {
                    $skipAdapter = $true
                    $skipReason = "ComponentID contains 'tap' (TAP adapter)"
                }
            }
            catch {
                Write-Verbose "ComponentID check failed for $($adapter.Name): $_"
            }
        }
        
        # LEVEL 5: Native Windows VPN Connection Check
        if (-not $skipAdapter -and $activeVpnConnections) {
            $matchingVpn = $activeVpnConnections | Where-Object { $_.Name -eq $adapter.InterfaceAlias }
            if ($matchingVpn) {
                $skipAdapter = $true
                $skipReason = "Native Windows VPN active: $($matchingVpn.Name)"
            }
        }
        
        # Final decision
        if ($skipAdapter) {
            Write-Verbose "Skipping adapter: $($adapter.Name) - $skipReason"
            continue
        }
        
        Write-Verbose "Including adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"
        $realAdapters += $adapter
    }
    
    # CRITICAL: Force return as array (even with 1 element!)
    # PowerShell "unwraps" single-element arrays on return
    # Using Write-Output with -NoEnumerate ensures .Count always works
    Write-Output -NoEnumerate $realAdapters
}

function Set-NoID-GlobalDoH {
    <#
    .SYNOPSIS
        Sets Windows DNS client to enforced DoH mode
    .DESCRIPTION
        Configures both Registry and netsh to enforce DNS-over-HTTPS.
        
        EnableAutoDoh Registry values:
        0 = Disabled (no DoH)
        1 = Allow auto-upgrade (opportunistic)
        2 = Enforce (strict - what we want!)
        
        CRITICAL: This ensures Windows ALWAYS uses encrypted DNS.
        Auditors and compliance tools check this Registry key.
    .PARAMETER Mode
        DoH enforcement level (0=disabled, 1=allow, 2=enforce)
        Default: 2 (enforce)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet(0, 1, 2)]
        [int]$Mode = 2
    )
    
    Write-Verbose "Setting global DoH mode: $Mode (2=enforce)"
    
    # 1. Registry: EnableAutoDoh = 2 (enforce)
    $dnsRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    if (-not (Test-Path $dnsRegPath)) {
        New-Item -Path $dnsRegPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    try {
        Set-ItemProperty -Path $dnsRegPath -Name 'EnableAutoDoh' `
            -Value $Mode -Type DWord -Force -ErrorAction Stop
        Write-Verbose "  Registry: EnableAutoDoh = $Mode"
    }
    catch {
        Write-Verbose "  Failed to set EnableAutoDoh registry: $_"
    }
    
    # 2. netsh: Activate DoH globally
    $dohState = if ($Mode -eq 0) { 'no' } else { 'yes' }
    try {
        netsh dnsclient set global doh=$dohState 2>$null | Out-Null
        Write-Verbose "  netsh: DoH = $dohState"
    }
    catch {
        Write-Verbose "  Failed to set global DoH via netsh: $_"
    }
}

# NOTE: No Export-ModuleMember needed - this file is dot-sourced, not imported as module
# All functions are automatically available in the calling scope
