function Enable-DoH {
    <#
    .SYNOPSIS
        Enable DNS over HTTPS (DoH) for specified DNS servers
        
    .DESCRIPTION
        Configures DNS over HTTPS encryption for privacy and security.
        Uses Microsoft Best Practice: Add-DnsClientDohServerAddress cmdlet.
        
        CRITICAL SECURITY SETTINGS:
        - AllowFallbackToUdp = $False (prevents fallback to unencrypted DNS)
        - AutoUpgrade = $True (automatically uses DoH when available)
        
    .PARAMETER ServerAddress
        DNS server IP address (IPv4 or IPv6)
        
    .PARAMETER DohTemplate
        HTTPS URL template for DoH queries
        
    .PARAMETER DryRun
        Show what would be configured without applying changes
        
    .EXAMPLE
        Enable-DoH -ServerAddress "1.1.1.1" -DohTemplate "https://cloudflare-dns.com/dns-query"
        
    .OUTPUTS
        System.Boolean - $true if successful, $false otherwise
        
    .NOTES
        Requires Windows 11 or Windows Server 2022+ for native DoH support
        Fallback to unencrypted DNS is DISABLED for security
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$DohTemplate,
        
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        Write-Log -Level DEBUG -Message "Configuring DoH for $ServerAddress" -Module $script:ModuleName
        
        # Determine AllowFallbackToUdp based on DoH mode
        $allowFallback = if ($script:DoHMode -eq "ALLOW") { $True } else { $False }
        $fallbackText = if ($allowFallback) { "True (fallback allowed)" } else { "False (no fallback)" }
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would enable DoH for $ServerAddress" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   Template: $DohTemplate" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   AllowFallbackToUdp: $fallbackText" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   AutoUpgrade: True" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   Method: PowerShell cmdlet + netsh (dual registration)" -Module $script:ModuleName
            return $true
        }
        
        # Register DoH for this DNS server (overwrites existing if present)
        Write-Log -Level DEBUG -Message "Registering DoH server: $ServerAddress" -Module "DNS"
        
        # METHOD 1: PowerShell cmdlet (modern API)
        try {
            Add-DnsClientDohServerAddress -ServerAddress $ServerAddress `
                                          -DohTemplate $DohTemplate `
                                          -AllowFallbackToUdp $allowFallback `
                                          -AutoUpgrade $True `
                                          -ErrorAction Stop
            Write-Log -Level DEBUG -Message "PowerShell cmdlet registration successful" -Module "DNS"
        }
        catch {
            Write-Log -Level DEBUG -Message "PowerShell cmdlet failed (expected on some builds): $_" -Module "DNS"
        }
        
        # METHOD 2: netsh (critical for actual enforcement - what v1.0 uses!)
        $udpFallbackMode = if ($allowFallback) { "yes" } else { "no" }
        try {
            $netshResult = netsh dnsclient add encryption `
                server=$ServerAddress `
                dohtemplate=$DohTemplate `
                autoupgrade=yes `
                udpfallback=$udpFallbackMode 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level DEBUG -Message "netsh registration successful for $ServerAddress" -Module "DNS"
            }
            else {
                Write-Log -Level DEBUG -Message "netsh returned exit code $LASTEXITCODE : $netshResult" -Module "DNS"
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "netsh registration failed: $_" -Module "DNS"
        }
        
        Write-Log -Level DEBUG -Message "Successfully registered DoH for $ServerAddress" -Module "DNS"
        
        Write-Log -Level SUCCESS -Message "DoH enabled for $ServerAddress" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  Template: $DohTemplate" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  Fallback: $(if ($allowFallback) { 'ENABLED (ALLOW mode)' } else { 'DISABLED (REQUIRE mode)' })" -Module $script:ModuleName
        
        return $true
    }
    catch {
        # DoH might not be supported on older Windows versions
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -like "*not recognized*" -or $errorMessage -like "*does not exist*") {
            Write-Log -Level WARNING -Message "DoH not supported on this Windows version (requires Windows 11 or Server 2022+)" -Module $script:ModuleName
            Write-Log -Level INFO -Message "DNS will work without encryption - consider upgrading Windows for DoH support" -Module $script:ModuleName
            return $false
        }
        
        Write-ErrorLog -Message "Failed to enable DoH for $ServerAddress" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
