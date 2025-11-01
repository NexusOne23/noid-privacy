#Requires -Version 5.1
#Requires -RunAsAdministrator

# Enable Strict Mode
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    DNS Provider Functions for DoH Configuration

.DESCRIPTION
    Multiple DNS-over-HTTPS providers:
    - Cloudflare (1.1.1.1) - Fast, US-based
    - AdGuard (94.140.14.14) - Privacy-focused, EU
    - NextDNS (45.90.28.0) - Customizable, Global
    - Quad9 (9.9.9.9) - Non-profit, Switzerland
#>

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
    
    # Remove old DoH entries (idempotent)
    Write-Verbose "Removing old DoH entries..."
    $serversToRemove = @("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff")
    foreach ($server in $serversToRemove) {
        try {
            $null = netsh dnsclient delete encryption server=$server 2>&1
        }
        catch {
            Write-Verbose "Server $server not registered (OK)"
        }
    }
    
    # Register DoH servers
    Write-Verbose "Registering AdGuard DoH servers..."
    
    # IPv4 Primary
    $result = netsh dnsclient add encryption server=94.140.14.14 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 94.140.14.14"
    }
    
    # IPv4 Secondary
    $result = netsh dnsclient add encryption server=94.140.15.15 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 94.140.15.15"
    }
    
    # IPv6 Primary
    $result = netsh dnsclient add encryption server=2a10:50c0::ad1:ff dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2a10:50c0::ad1:ff"
    }
    
    # IPv6 Secondary
    $result = netsh dnsclient add encryption server=2a10:50c0::ad2:ff dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2a10:50c0::ad2:ff"
    }
    
    Write-Success "DoH servers registered: 4 AdGuard servers (IPv4 + IPv6)"
    
    # Enable DoH globally
    Write-Info "Activating DoH globally..."
    $result = netsh dnsclient set global doh=yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "DoH globally enabled"
    }
    
    # Configure network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*VPN*' -and $_.Name -notlike '*Virtual*' }
    
    Write-Info "Configuring $($adapters.Count) active adapter(s)..."
    
    foreach ($adapter in $adapters) {
        try {
            Write-Verbose "Processing: $($adapter.Name)"
            
            # Set DNS servers (IPv4 primary for speed)
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                -ServerAddresses @("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff") `
                -ErrorAction Stop
            
            Write-Verbose "  DNS servers set"
        }
        catch {
            Write-Warning "Adapter $($adapter.Name) could not be configured: $_"
        }
    }
    
    Write-Success "AdGuard DNS over HTTPS activated"
    Write-Info "IPv4: 94.140.14.14 (Primary), 94.140.15.15 (Secondary)"
    Write-Info "IPv6: 2a10:50c0::ad1:ff (Primary), 2a10:50c0::ad2:ff (Secondary)"
    Write-Info "Features: Ad blocking, Tracker blocking, Privacy-focused"
    Write-Warning "IMPORTANT: Reboot may be required for DoH to become active!"
}

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
        
        NOTE: For custom filtering, users should sign up at nextdns.io
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "NextDNS over HTTPS (DoH)"
    Write-Info "Configuring NextDNS - Customizable, Global CDN..."
    Write-Info "For custom filtering: Sign up at https://nextdns.io"
    
    # Remove old DoH entries
    Write-Verbose "Removing old DoH entries..."
    $serversToRemove = @("45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::")
    foreach ($server in $serversToRemove) {
        try {
            $null = netsh dnsclient delete encryption server=$server 2>&1
        }
        catch {
            Write-Verbose "Server $server not registered (OK)"
        }
    }
    
    # Register DoH servers
    Write-Verbose "Registering NextDNS DoH servers..."
    
    # IPv4 Primary
    $result = netsh dnsclient add encryption server=45.90.28.0 dohtemplate=https://dns.nextdns.io/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 45.90.28.0"
    }
    
    # IPv4 Secondary
    $result = netsh dnsclient add encryption server=45.90.30.0 dohtemplate=https://dns.nextdns.io/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 45.90.30.0"
    }
    
    # IPv6 Primary
    $result = netsh dnsclient add encryption server=2a07:a8c0:: dohtemplate=https://dns.nextdns.io/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2a07:a8c0::"
    }
    
    # IPv6 Secondary
    $result = netsh dnsclient add encryption server=2a07:a8c1:: dohtemplate=https://dns.nextdns.io/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2a07:a8c1::"
    }
    
    Write-Success "DoH servers registered: 4 NextDNS servers (IPv4 + IPv6)"
    
    # Enable DoH globally
    Write-Info "Activating DoH globally..."
    $result = netsh dnsclient set global doh=yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "DoH globally enabled"
    }
    
    # Configure network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*VPN*' -and $_.Name -notlike '*Virtual*' }
    
    Write-Info "Configuring $($adapters.Count) active adapter(s)..."
    
    foreach ($adapter in $adapters) {
        try {
            Write-Verbose "Processing: $($adapter.Name)"
            
            # Set DNS servers
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                -ServerAddresses @("45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::") `
                -ErrorAction Stop
            
            Write-Verbose "  DNS servers set"
        }
        catch {
            Write-Warning "Adapter $($adapter.Name) could not be configured: $_"
        }
    }
    
    Write-Success "NextDNS over HTTPS activated"
    Write-Info "IPv4: 45.90.28.0 (Primary), 45.90.30.0 (Secondary)"
    Write-Info "IPv6: 2a07:a8c0:: (Primary), 2a07:a8c1:: (Secondary)"
    Write-Info "Features: Customizable filtering, Analytics dashboard, Privacy logs"
    Write-Info "Advanced: Create account at https://nextdns.io for custom config"
    Write-Warning "IMPORTANT: Reboot may be required for DoH to become active!"
}

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
    
    # Remove old DoH entries
    Write-Verbose "Removing old DoH entries..."
    $serversToRemove = @("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9")
    foreach ($server in $serversToRemove) {
        try {
            $null = netsh dnsclient delete encryption server=$server 2>&1
        }
        catch {
            Write-Verbose "Server $server not registered (OK)"
        }
    }
    
    # Register DoH servers
    Write-Verbose "Registering Quad9 DoH servers..."
    
    # IPv4 Primary
    $result = netsh dnsclient add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 9.9.9.9"
    }
    
    # IPv4 Secondary
    $result = netsh dnsclient add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 149.112.112.112"
    }
    
    # IPv6 Primary
    $result = netsh dnsclient add encryption server=2620:fe::fe dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2620:fe::fe"
    }
    
    # IPv6 Secondary
    $result = netsh dnsclient add encryption server=2620:fe::9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2620:fe::9"
    }
    
    Write-Success "DoH servers registered: 4 Quad9 servers (IPv4 + IPv6)"
    
    # Enable DoH globally
    Write-Info "Activating DoH globally..."
    $result = netsh dnsclient set global doh=yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "DoH globally enabled"
    }
    
    # Configure network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*VPN*' -and $_.Name -notlike '*Virtual*' }
    
    Write-Info "Configuring $($adapters.Count) active adapter(s)..."
    
    foreach ($adapter in $adapters) {
        try {
            Write-Verbose "Processing: $($adapter.Name)"
            
            # Set DNS servers
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                -ServerAddresses @("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9") `
                -ErrorAction Stop
            
            Write-Verbose "  DNS servers set"
        }
        catch {
            Write-Warning "Adapter $($adapter.Name) could not be configured: $_"
        }
    }
    
    Write-Success "Quad9 DNS over HTTPS activated"
    Write-Info "IPv4: 9.9.9.9 (Primary), 149.112.112.112 (Secondary)"
    Write-Info "IPv6: 2620:fe::fe (Primary), 2620:fe::9 (Secondary)"
    Write-Info "Features: Threat blocking, Malware protection, GDPR-compliant"
    Write-Info "Organization: Quad9 Foundation (Non-profit, Switzerland)"
    Write-Warning "IMPORTANT: Reboot may be required for DoH to become active!"
}
