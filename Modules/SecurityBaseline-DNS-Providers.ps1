# =======================================================================================
# SecurityBaseline-DNS-Providers.ps1 - DNS-over-HTTPS Provider Configuration
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

# Load common DNS helper functions
. "$PSScriptRoot\SecurityBaseline-DNS-Common.ps1"

<#
.SYNOPSIS
    DNS Provider Functions for DoH Configuration

.DESCRIPTION
    Unified DNS-over-HTTPS providers with consistent implementation:
    - Cloudflare (1.1.1.1) - Fast, global CDN
    - AdGuard (94.140.14.14) - Privacy-focused, EU-based, ad-blocking
    - NextDNS (45.90.28.0) - Customizable, analytics dashboard
    - Quad9 (9.9.9.9) - Non-profit, GDPR-compliant, threat-blocking
    
    All providers now use:
    - Same cleanup logic (Reset-NoID-DnsState)
    - Same adapter selection (Get-NoID-NetworkAdapters)
    - Same IPv6 detection and ordering
    - Proper DoH registration with no fallback to unencrypted
#>

#region CLOUDFLARE DNS

function Enable-CloudflareDNS {
    <#
    .SYNOPSIS
        Configures Cloudflare DNS over HTTPS (DoH)
    .DESCRIPTION
        Enables Windows 11 native DoH and sets DNS to Cloudflare (1.1.1.1).
        Cloudflare is fast, global, and privacy-focused.
        
        Provider: Cloudflare (US/Global)
        IPv4: 1.1.1.1 (Primary), 1.0.0.1 (Secondary)
        IPv6: 2606:4700:4700::1111 (Primary), 2606:4700:4700::1001 (Secondary)
        Privacy: ***** | Speed: ***** | Location: Global CDN
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Cloudflare DNS over HTTPS (DoH)"
    Write-Info "Configuring Cloudflare DNS - Fast, global CDN..."
    Write-Info "Privacy-focused with WARP integration available"
    
    # CRITICAL: Clean ALL previous DNS state
    Reset-NoID-DnsState -KeepAdapterDns
    
    # Enforce DoH on OS level (Registry + netsh)
    Set-NoID-GlobalDoH -Mode 2
    
    # DoH configuration
    $dohTemplate = 'https://cloudflare-dns.com/dns-query'
    $ipv4Servers = @('1.1.1.1', '1.0.0.1')
    $ipv6Servers = @('2606:4700:4700::1111', '2606:4700:4700::1001')
    
    # Register DoH for all servers (IPv4 + IPv6)
    foreach ($server in ($ipv4Servers + $ipv6Servers)) {
        try {
            netsh dnsclient add encryption server=$server `
                dohtemplate=$dohTemplate autoupgrade=yes udpfallback=no 2>$null | Out-Null
            Write-Verbose "Registered DoH: $server"
        }
        catch {
            Write-Verbose "Failed to register DoH for $server : $_"
        }
    }
    
    # Configure adapters (skip VPN/VM)
    # CRITICAL: Force to array (prevents .Count errors with single adapter)
    $adapters = @(Get-NoID-NetworkAdapters)
    
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Warning "No suitable network adapters found (all are VPN/virtual)"
        return
    }
    
    foreach ($adapter in $adapters) {
        try {
            # Check if adapter has IPv6 enabled
            $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name `
                -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $ipv6Enabled = $ipv6Binding.Enabled
            
            if ($ipv6Enabled) {
                # CRITICAL FIX: IPv6 FIRST for DoH validation, then back to IPv4-first
                # Windows needs IPv6 at front to validate IPv6 DoH servers
                Write-Verbose "Setting IPv6 first (temporarily for DoH validation)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv6Servers + $ipv4Servers) -ErrorAction Stop
                
                # Wait for Windows to validate IPv6 DoH
                Write-Verbose "Waiting 5 seconds for IPv6 DoH validation..."
                Start-Sleep -Seconds 5
                
                # Reset to IPv4-first (faster for most users)
                Write-Verbose "Resetting DNS order (IPv4 first for speed)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv4Servers + $ipv6Servers) -ErrorAction Stop
                
                $totalServers = $ipv6Servers.Count + $ipv4Servers.Count
                Write-Info "  -> $($adapter.Name): IPv6 + IPv4 ($totalServers servers)"
            }
            else {
                # IPv4 only
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses $ipv4Servers -ErrorAction Stop
                Write-Info "  -> $($adapter.Name): IPv4 only ($($ipv4Servers.Count) servers)"
            }
            
            # CRITICAL: Set DoH Encryption Preference (DohFlags Registry)
            # Without this, Windows GUI shows "Unencrypted" even though DoH works!
            try {
                $adapterGuid = $adapter.InterfaceGuid
                Write-Verbose "Setting DohFlags for adapter GUID: $adapterGuid"
                
                # IPv4 Servers → Doh branch
                foreach ($ip in $ipv4Servers) {
                    try {
                        $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                        }
                        New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                        Write-Verbose "  DohFlags set: $ip (Encrypted Only)"
                    }
                    catch {
                        Write-Verbose "  Failed to set DohFlags for $ip : $_"
                    }
                }
                
                # IPv6 Servers → Doh6 branch (DIFFERENT from IPv4!)
                if ($ipv6Enabled) {
                    foreach ($ip in $ipv6Servers) {
                        try {
                            # CRITICAL: IPv6 uses Doh6 branch, not Doh!
                            $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                            $ipPath = "$basePath\$ip"
                            
                            # Create Doh6 parent if not exists
                            if (-not (Test-Path $basePath)) {
                                New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            # Create IP subkey
                            if (-not (Test-Path $ipPath)) {
                                New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            # Set DohFlags
                            New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "  DohFlags set: $ip (Encrypted Only, Doh6)"
                        }
                        catch {
                            Write-Verbose "  Failed to set DohFlags for $ip : $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not set DoH encryption preference (non-critical): $_"
            }
        }
        catch {
            Write-Warning "Failed to configure adapter $($adapter.Name): $_"
        }
    }
    
    # Clear DNS cache (with timeout - prevents hang)
    $job = $null
    try {
        Write-Info "Flushing DNS cache..."
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flushed successfully"
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flush timeout (non-critical)"
        }
    }
    catch {
        Write-Verbose "Could not flush DNS cache: $_"
    }
    finally {
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "Cloudflare DNS-over-HTTPS configured"
    Write-Info "IPv4: 1.1.1.1, 1.0.0.1"
    Write-Info "IPv6: 2606:4700:4700::1111, 2606:4700:4700::1001"
    Write-Info "All DNS queries are encrypted via HTTPS"
    
    # VALIDATION: Check if DoH is really configured
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $cloudflareDoH = $dohServers | Where-Object { $_.ServerAddress -match "1\.1\.1\.1|1\.0\.0\.1|2606:4700:4700" }
            if ($cloudflareDoH) {
                $dohCount = @($cloudflareDoH).Count
                Write-Verbose "DoH validation: $dohCount Cloudflare servers registered"
                foreach ($server in $cloudflareDoH) {
                    Write-Verbose "  Server: $($server.ServerAddress), Template: $($server.DohTemplate)"
                    if ($server.AllowFallbackToUdp -eq $false) {
                        Write-Verbose "  No fallback to unencrypted (Maximum Security!)"
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "DoH validation skipped (non-critical): $_"
    }
}

#endregion

#region ADGUARD DNS

function Enable-AdGuardDNS {
    <#
    .SYNOPSIS
        Configures AdGuard DNS over HTTPS (DoH)
    .DESCRIPTION
        Enables Windows 11 native DoH and sets DNS to AdGuard DNS.
        AdGuard DNS is privacy-focused, EU-based, with built-in ad/tracker blocking.
        
        Provider: AdGuard DNS (Cyprus, EU)
        IPv4: 94.140.14.14 (Primary), 94.140.15.15 (Secondary)
        IPv6: 2a10:50c0::ad1:ff (Primary), 2a10:50c0::ad2:ff (Secondary)
        Privacy: ***** | Speed: ****  | Location: EU (Cyprus)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "AdGuard DNS over HTTPS (DoH)"
    Write-Info "Configuring AdGuard DNS - Privacy-focused, EU-based..."
    Write-Info "Built-in ad and tracker blocking included"
    
    # CRITICAL: Clean ALL previous DNS state
    Reset-NoID-DnsState -KeepAdapterDns
    
    # Enforce DoH on OS level (Registry + netsh)
    Set-NoID-GlobalDoH -Mode 2
    
    # DoH configuration
    $dohTemplate = 'https://dns.adguard-dns.com/dns-query'
    $ipv4Servers = @('94.140.14.14', '94.140.15.15')
    $ipv6Servers = @('2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff')
    
    # Register DoH for all servers (IPv4 + IPv6)
    foreach ($server in ($ipv4Servers + $ipv6Servers)) {
        try {
            netsh dnsclient add encryption server=$server `
                dohtemplate=$dohTemplate autoupgrade=yes udpfallback=no 2>$null | Out-Null
            Write-Verbose "Registered DoH: $server"
        }
        catch {
            Write-Verbose "Failed to register DoH for $server : $_"
        }
    }
    
    # Configure adapters (skip VPN/VM)
    # CRITICAL: Force to array (prevents .Count errors with single adapter)
    $adapters = @(Get-NoID-NetworkAdapters)
    
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Warning "No suitable network adapters found (all are VPN/virtual)"
        return
    }
    
    foreach ($adapter in $adapters) {
        try {
            # Check if adapter has IPv6 enabled
            $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name `
                -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $ipv6Enabled = $ipv6Binding.Enabled
            
            if ($ipv6Enabled) {
                # CRITICAL FIX: IPv6 FIRST for DoH validation, then back to IPv4-first
                Write-Verbose "Setting IPv6 first (temporarily for DoH validation)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv6Servers + $ipv4Servers) -ErrorAction Stop
                
                # Wait for Windows to validate IPv6 DoH
                Write-Verbose "Waiting 5 seconds for IPv6 DoH validation..."
                Start-Sleep -Seconds 5
                
                # Reset to IPv4-first (faster for most users)
                Write-Verbose "Resetting DNS order (IPv4 first for speed)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv4Servers + $ipv6Servers) -ErrorAction Stop
                
                $totalServers = $ipv6Servers.Count + $ipv4Servers.Count
                Write-Info "  -> $($adapter.Name): IPv6 + IPv4 ($totalServers servers)"
            }
            else {
                # IPv4 only
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses $ipv4Servers -ErrorAction Stop
                Write-Info "  -> $($adapter.Name): IPv4 only ($($ipv4Servers.Count) servers)"
            }
            
            # CRITICAL: Set DoH Encryption Preference (DohFlags Registry)
            try {
                $adapterGuid = $adapter.InterfaceGuid
                Write-Verbose "Setting DohFlags for adapter GUID: $adapterGuid"
                
                # IPv4 Servers → Doh branch
                foreach ($ip in $ipv4Servers) {
                    try {
                        $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                        }
                        New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                        Write-Verbose "  DohFlags set: $ip (Encrypted Only)"
                    }
                    catch {
                        Write-Verbose "  Failed to set DohFlags for $ip : $_"
                    }
                }
                
                # IPv6 Servers → Doh6 branch
                if ($ipv6Enabled) {
                    foreach ($ip in $ipv6Servers) {
                        try {
                            $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                            $ipPath = "$basePath\$ip"
                            
                            if (-not (Test-Path $basePath)) {
                                New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            if (-not (Test-Path $ipPath)) {
                                New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "  DohFlags set: $ip (Encrypted Only, Doh6)"
                        }
                        catch {
                            Write-Verbose "  Failed to set DohFlags for $ip : $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not set DoH encryption preference (non-critical): $_"
            }
        }
        catch {
            Write-Warning "Failed to configure adapter $($adapter.Name): $_"
        }
    }
    
    # Clear DNS cache (with timeout)
    $job = $null
    try {
        Write-Info "Flushing DNS cache..."
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flushed successfully"
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flush timeout (non-critical)"
        }
    }
    catch {
        Write-Verbose "Could not flush DNS cache: $_"
    }
    finally {
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "AdGuard DNS-over-HTTPS configured"
    Write-Info "IPv4: 94.140.14.14, 94.140.15.15"
    Write-Info "IPv6: 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff"
    Write-Info "All DNS queries are encrypted via HTTPS"
    Write-Info "Built-in ad and tracker blocking active"
    
    # VALIDATION: Check if DoH is configured
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $adguardDoH = $dohServers | Where-Object { $_.ServerAddress -match "94\.140\.14|94\.140\.15|2a10:50c0" }
            if ($adguardDoH) {
                $dohCount = @($adguardDoH).Count
                Write-Verbose "DoH validation: $dohCount AdGuard servers registered"
            }
        }
    }
    catch {
        Write-Verbose "DoH validation skipped (non-critical): $_"
    }
}

#endregion

#region NEXTDNS

function Enable-NextDNS {
    <#
    .SYNOPSIS
        Configures NextDNS over HTTPS (DoH)
    .DESCRIPTION
        Enables Windows 11 native DoH and sets DNS to NextDNS.
        NextDNS is customizable with analytics dashboard and advanced filtering.
        
        Provider: NextDNS (Switzerland/Global)
        IPv4: 45.90.28.0 (Primary), 45.90.30.0 (Secondary)
        IPv6: 2a07:a8c0:: (Primary), 2a07:a8c1:: (Secondary)
        Privacy: ***** | Speed: ****  | Location: Global CDN
        
        NOTE: For custom filtering and analytics, sign up at nextdns.io
              and use the -ProfileId parameter with your configuration ID.
    .PARAMETER ProfileId
        Your NextDNS configuration ID (e.g., 'abc123').
        If not specified, uses generic public endpoint (limited features).
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ProfileId = ''
    )
    
    Write-Section "NextDNS over HTTPS (DoH)"
    Write-Info "Configuring NextDNS - Customizable, Global CDN..."
    
    if ($ProfileId) {
        Write-Info "Using custom profile ID: $ProfileId"
        Write-Info "Custom filtering and analytics enabled"
    }
    else {
        Write-Info "Using generic public endpoint (limited features)"
        Write-Info "For custom filtering: Sign up at https://nextdns.io"
    }
    
    # CRITICAL: Clean ALL previous DNS state
    Reset-NoID-DnsState -KeepAdapterDns
    
    # Enforce DoH on OS level (Registry + netsh)
    Set-NoID-GlobalDoH -Mode 2
    
    # DoH configuration
    $dohTemplate = if ($ProfileId) {
        "https://dns.nextdns.io/$ProfileId"
    }
    else {
        'https://dns.nextdns.io/dns-query'
    }
    
    $ipv4Servers = @('45.90.28.0', '45.90.30.0')
    $ipv6Servers = @('2a07:a8c0::', '2a07:a8c1::')
    
    # Register DoH for all servers (IPv4 + IPv6)
    foreach ($server in ($ipv4Servers + $ipv6Servers)) {
        try {
            netsh dnsclient add encryption server=$server `
                dohtemplate=$dohTemplate autoupgrade=yes udpfallback=no 2>$null | Out-Null
            Write-Verbose "Registered DoH: $server"
        }
        catch {
            Write-Verbose "Failed to register DoH for $server : $_"
        }
    }
    
    # Configure adapters (skip VPN/VM)
    # CRITICAL: Force to array (prevents .Count errors with single adapter)
    $adapters = @(Get-NoID-NetworkAdapters)
    
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Warning "No suitable network adapters found (all are VPN/virtual)"
        return
    }
    
    foreach ($adapter in $adapters) {
        try {
            # Check if adapter has IPv6 enabled
            $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name `
                -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $ipv6Enabled = $ipv6Binding.Enabled
            
            if ($ipv6Enabled) {
                # CRITICAL FIX: IPv6 FIRST for DoH validation, then back to IPv4-first
                Write-Verbose "Setting IPv6 first (temporarily for DoH validation)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv6Servers + $ipv4Servers) -ErrorAction Stop
                
                # Wait for Windows to validate IPv6 DoH
                Write-Verbose "Waiting 5 seconds for IPv6 DoH validation..."
                Start-Sleep -Seconds 5
                
                # Reset to IPv4-first (faster for most users)
                Write-Verbose "Resetting DNS order (IPv4 first for speed)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv4Servers + $ipv6Servers) -ErrorAction Stop
                
                $totalServers = $ipv6Servers.Count + $ipv4Servers.Count
                Write-Info "  -> $($adapter.Name): IPv6 + IPv4 ($totalServers servers)"
            }
            else {
                # IPv4 only
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses $ipv4Servers -ErrorAction Stop
                Write-Info "  -> $($adapter.Name): IPv4 only ($($ipv4Servers.Count) servers)"
            }
            
            # CRITICAL: Set DoH Encryption Preference (DohFlags Registry)
            try {
                $adapterGuid = $adapter.InterfaceGuid
                Write-Verbose "Setting DohFlags for adapter GUID: $adapterGuid"
                
                # IPv4 Servers → Doh branch
                foreach ($ip in $ipv4Servers) {
                    try {
                        $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                        }
                        New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                        Write-Verbose "  DohFlags set: $ip (Encrypted Only)"
                    }
                    catch {
                        Write-Verbose "  Failed to set DohFlags for $ip : $_"
                    }
                }
                
                # IPv6 Servers → Doh6 branch
                if ($ipv6Enabled) {
                    foreach ($ip in $ipv6Servers) {
                        try {
                            $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                            $ipPath = "$basePath\$ip"
                            
                            if (-not (Test-Path $basePath)) {
                                New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            if (-not (Test-Path $ipPath)) {
                                New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "  DohFlags set: $ip (Encrypted Only, Doh6)"
                        }
                        catch {
                            Write-Verbose "  Failed to set DohFlags for $ip : $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not set DoH encryption preference (non-critical): $_"
            }
        }
        catch {
            Write-Warning "Failed to configure adapter $($adapter.Name): $_"
        }
    }
    
    # Clear DNS cache (with timeout)
    $job = $null
    try {
        Write-Info "Flushing DNS cache..."
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flushed successfully"
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flush timeout (non-critical)"
        }
    }
    catch {
        Write-Verbose "Could not flush DNS cache: $_"
    }
    finally {
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "NextDNS DNS-over-HTTPS configured"
    Write-Info "IPv4: 45.90.28.0, 45.90.30.0"
    Write-Info "IPv6: 2a07:a8c0::, 2a07:a8c1::"
    Write-Info "All DNS queries are encrypted via HTTPS"
    
    # VALIDATION: Check if DoH is configured
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $nextdnsDoH = $dohServers | Where-Object { $_.ServerAddress -match "45\.90\.28|45\.90\.30|2a07:a8c" }
            if ($nextdnsDoH) {
                $dohCount = @($nextdnsDoH).Count
                Write-Verbose "DoH validation: $dohCount NextDNS servers registered"
            }
        }
    }
    catch {
        Write-Verbose "DoH validation skipped (non-critical): $_"
    }
}

#endregion

#region QUAD9 DNS

function Enable-Quad9DNS {
    <#
    .SYNOPSIS
        Configures Quad9 DNS over HTTPS (DoH)
    .DESCRIPTION
        Enables Windows 11 native DoH and sets DNS to Quad9.
        Quad9 is a non-profit, GDPR-compliant, threat-blocking DNS provider.
        
        Provider: Quad9 (Switzerland, Non-Profit)
        IPv4: 9.9.9.9 (Primary), 149.112.112.112 (Secondary)
        IPv6: 2620:fe::fe (Primary), 2620:fe::9 (Secondary)
        Privacy: ***** | Speed: ****  | Location: EU/Global
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Quad9 DNS over HTTPS (DoH)"
    Write-Info "Configuring Quad9 DNS - Non-profit, GDPR-compliant..."
    Write-Info "Built-in threat intelligence and malware blocking"
    
    # CRITICAL: Clean ALL previous DNS state
    Reset-NoID-DnsState -KeepAdapterDns
    
    # Enforce DoH on OS level (Registry + netsh)
    Set-NoID-GlobalDoH -Mode 2
    
    # DoH configuration
    $dohTemplate = 'https://dns.quad9.net/dns-query'
    $ipv4Servers = @('9.9.9.9', '149.112.112.112')
    $ipv6Servers = @('2620:fe::fe', '2620:fe::9')
    
    # Register DoH for all servers (IPv4 + IPv6)
    foreach ($server in ($ipv4Servers + $ipv6Servers)) {
        try {
            netsh dnsclient add encryption server=$server `
                dohtemplate=$dohTemplate autoupgrade=yes udpfallback=no 2>$null | Out-Null
            Write-Verbose "Registered DoH: $server"
        }
        catch {
            Write-Verbose "Failed to register DoH for $server : $_"
        }
    }
    
    # Configure adapters (skip VPN/VM)
    # CRITICAL: Force to array (prevents .Count errors with single adapter)
    $adapters = @(Get-NoID-NetworkAdapters)
    
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Warning "No suitable network adapters found (all are VPN/virtual)"
        return
    }
    
    foreach ($adapter in $adapters) {
        try {
            # Check if adapter has IPv6 enabled
            $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name `
                -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $ipv6Enabled = $ipv6Binding.Enabled
            
            if ($ipv6Enabled) {
                # CRITICAL FIX: IPv6 FIRST for DoH validation, then back to IPv4-first
                Write-Verbose "Setting IPv6 first (temporarily for DoH validation)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv6Servers + $ipv4Servers) -ErrorAction Stop
                
                # Wait for Windows to validate IPv6 DoH
                Write-Verbose "Waiting 5 seconds for IPv6 DoH validation..."
                Start-Sleep -Seconds 5
                
                # Reset to IPv4-first (faster for most users)
                Write-Verbose "Resetting DNS order (IPv4 first for speed)..."
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses ($ipv4Servers + $ipv6Servers) -ErrorAction Stop
                
                $totalServers = $ipv6Servers.Count + $ipv4Servers.Count
                Write-Info "  -> $($adapter.Name): IPv6 + IPv4 ($totalServers servers)"
            }
            else {
                # IPv4 only
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                    -ServerAddresses $ipv4Servers -ErrorAction Stop
                Write-Info "  -> $($adapter.Name): IPv4 only ($($ipv4Servers.Count) servers)"
            }
            
            # CRITICAL: Set DoH Encryption Preference (DohFlags Registry)
            try {
                $adapterGuid = $adapter.InterfaceGuid
                Write-Verbose "Setting DohFlags for adapter GUID: $adapterGuid"
                
                # IPv4 Servers → Doh branch
                foreach ($ip in $ipv4Servers) {
                    try {
                        $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                        }
                        New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                        Write-Verbose "  DohFlags set: $ip (Encrypted Only)"
                    }
                    catch {
                        Write-Verbose "  Failed to set DohFlags for $ip : $_"
                    }
                }
                
                # IPv6 Servers → Doh6 branch
                if ($ipv6Enabled) {
                    foreach ($ip in $ipv6Servers) {
                        try {
                            $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                            $ipPath = "$basePath\$ip"
                            
                            if (-not (Test-Path $basePath)) {
                                New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            if (-not (Test-Path $ipPath)) {
                                New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                            }
                            
                            New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "  DohFlags set: $ip (Encrypted Only, Doh6)"
                        }
                        catch {
                            Write-Verbose "  Failed to set DohFlags for $ip : $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not set DoH encryption preference (non-critical): $_"
            }
        }
        catch {
            Write-Warning "Failed to configure adapter $($adapter.Name): $_"
        }
    }
    
    # Clear DNS cache (with timeout)
    $job = $null
    try {
        Write-Info "Flushing DNS cache..."
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flushed successfully"
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Verbose "DNS cache flush timeout (non-critical)"
        }
    }
    catch {
        Write-Verbose "Could not flush DNS cache: $_"
    }
    finally {
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "Quad9 DNS-over-HTTPS configured"
    Write-Info "IPv4: 9.9.9.9, 149.112.112.112"
    Write-Info "IPv6: 2620:fe::fe, 2620:fe::9"
    Write-Info "All DNS queries are encrypted via HTTPS"
    Write-Info "Threat intelligence and malware blocking active"
    
    # VALIDATION: Check if DoH is configured
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $quad9DoH = $dohServers | Where-Object { $_.ServerAddress -match "9\.9\.9\.9|149\.112\.112|2620:fe" }
            if ($quad9DoH) {
                $dohCount = @($quad9DoH).Count
                Write-Verbose "DoH validation: $dohCount Quad9 servers registered"
            }
        }
    }
    catch {
        Write-Verbose "DoH validation skipped (non-critical): $_"
    }
}

#endregion

# NOTE: No Export-ModuleMember needed - this file is dot-sourced, not imported as module
# All functions are automatically available in the calling scope
