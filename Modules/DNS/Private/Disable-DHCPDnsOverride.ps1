function Disable-DHCPDnsOverride {
    <#
    .SYNOPSIS
        Prevent DHCP from overriding manually configured DNS servers
        
    .DESCRIPTION
        Sets adapter to NOT register its DNS address and ignore DHCP-provided DNS servers.
        This ensures your static DNS configuration (e.g., Cloudflare with DoH) cannot be overridden.
        
    .PARAMETER InterfaceIndex
        Network adapter interface index
        
    .PARAMETER DryRun
        Show what would be configured without applying changes
        
    .EXAMPLE
        Disable-DHCPDnsOverride -InterfaceIndex 12
        
    .NOTES
        Uses Set-DnsClient cmdlet (PowerShell Best Practice)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$InterfaceIndex,
        
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
        $adapterName = $adapter.Name
        
        Write-Log -Level DEBUG -Message "Preventing DHCP DNS override on adapter: $adapterName" -Module $script:ModuleName
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would disable DHCP DNS override on $adapterName" -Module $script:ModuleName
            return $true
        }
        
        # Set RegisterThisConnectionsAddress = $false to prevent DHCP from overriding DNS
        Set-DnsClient -InterfaceIndex $InterfaceIndex `
                     -RegisterThisConnectionsAddress $false `
                     -ErrorAction Stop
        
        Write-Log -Level SUCCESS -Message "DHCP DNS override disabled on $adapterName" -Module $script:ModuleName
        
        # Verify
        $dnsClient = Get-DnsClient -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
        if ($dnsClient.RegisterThisConnectionsAddress -eq $false) {
            Write-Log -Level DEBUG -Message "Verification passed: DHCP cannot override DNS" -Module $script:ModuleName
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "Verification failed: DHCP override not disabled" -Module $script:ModuleName
            return $false
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to disable DHCP DNS override on adapter $InterfaceIndex" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
