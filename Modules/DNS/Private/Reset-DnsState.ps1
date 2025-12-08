function Reset-DnsState {
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
    
    Write-Log -Level DEBUG -Message "Cleaning up DNS state (all providers)..." -Module "DNS"
    
    # 1. Clear network caches FIRST (remove stale mappings before any changes)
    Write-Log -Level DEBUG -Message "Clearing DNS, ARP and NetBIOS caches..." -Module "DNS"
    
    # DNS cache
    ipconfig /flushdns 2>$null | Out-Null
    
    # ARP cache (use netsh - more reliable than arp -d * on international Windows)
    netsh interface ip delete arpcache 2>$null | Out-Null
    
    # NetBIOS name cache
    nbtstat -R 2>$null | Out-Null
    
    # 2. Delete ALL known DoH server registrations
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
            Write-Log -Level DEBUG -Message "  Deleted DoH entry: $ip" -Module "DNS"
        }
        catch {
            # Ignore - entry might not exist
            $null = $null
        }
    }
    
    # 3. Clean per-adapter DoH registry keys (all GUIDs)
    # CRITICAL: We clean these because Enable-DoH + manual DohFlags setting will recreate them
    $basePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    if (Test-Path $basePath) {
        Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
            $adapterPath = $_.PSPath
            
            # Remove DohInterfaceSettings (contains both Doh and Doh6 branches)
            if (Test-Path "$adapterPath\DohInterfaceSettings") {
                Remove-Item "$adapterPath\DohInterfaceSettings" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log -Level DEBUG -Message "  Cleaned DoH registry: $($_.PSChildName)" -Module "DNS"
            }
        }
    }
    
    # 4. Optional: Reset adapters to automatic DHCP DNS
    $adapterWasReset = $false
    if (-not $KeepAdapterDns) {
        Write-Log -Level DEBUG -Message "Resetting adapters to automatic DNS..." -Module "DNS"
        $adaptersToReset = Get-DnsClient -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceOperationalStatus -eq 'Up' }
        
        foreach ($adapter in $adaptersToReset) {
            try {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.InterfaceAlias `
                    -ResetServerAddresses -ErrorAction Stop
                Write-Log -Level DEBUG -Message "  Reset: $($adapter.InterfaceAlias)" -Module "DNS"
                $adapterWasReset = $true
            }
            catch {
                Write-Log -Level DEBUG -Message "  Failed to reset: $($adapter.InterfaceAlias)" -Module "DNS"
            }
        }
    }
    
    # 5. Clear caches AGAIN if adapter was reset (DHCP may have created new cache entries)
    if ($adapterWasReset) {
        Write-Log -Level DEBUG -Message "Clearing caches again after adapter reset..." -Module "DNS"
        ipconfig /flushdns 2>$null | Out-Null
        netsh interface ip delete arpcache 2>$null | Out-Null
        nbtstat -R 2>$null | Out-Null
    }
    
    Write-Log -Level DEBUG -Message "DNS state cleanup complete" -Module $script:ModuleName
}
