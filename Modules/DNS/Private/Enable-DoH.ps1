function Enable-DoH {
    <#
    .SYNOPSIS
        Enable DNS over HTTPS (DoH) for specified DNS servers

    .DESCRIPTION
        Registers or updates one DNS-over-HTTPS endpoint through the supported
        DnsClient PowerShell API. The DNS module separately owns the selected
        adapter/server order and native per-interface DNS_INTERFACE_SETTINGS3
        state that Windows Settings uses for its encrypted transport label.

        ENDPOINT SETTINGS:
        - AllowFallbackToUdp follows the sealed ALLOW/REQUIRE decision
        - AutoUpgrade = $True (use DoH for the registered server)

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
        NoID Privacy supports this path on its admitted Windows 11 client
        profiles. REQUIRE disables classic-DNS fallback; ALLOW permits it.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerAddress,

        [Parameter(Mandatory = $true)]
        [string]$DohTemplate,

        [Parameter()]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable DoH')) {
        return
    }


    try {
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($ServerAddress, [ref]$parsedAddress)) {
            throw "Invalid DoH server address: $ServerAddress"
        }
        $ServerAddress = $parsedAddress.ToString()
        $templateUri = $null
        if (-not [Uri]::TryCreate($DohTemplate, [UriKind]::Absolute, [ref]$templateUri) -or
            $templateUri.Scheme -ne 'https') {
            throw "Invalid HTTPS DoH template: $DohTemplate"
        }
        if ($script:DoHMode -notin @('ALLOW', 'REQUIRE')) {
            throw "Unsupported DoH mode: $($script:DoHMode)"
        }
        Write-Log -Level DEBUG -Message "Configuring DoH for $ServerAddress" -Module $script:ModuleName

        # Determine AllowFallbackToUdp based on DoH mode
        $allowFallback = if ($script:DoHMode -eq "ALLOW") { $True } else { $False }
        $fallbackText = if ($allowFallback) { "True (fallback allowed)" } else { "False (no fallback)" }

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would enable DoH for $ServerAddress" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   Template: $DohTemplate" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   AllowFallbackToUdp: $fallbackText" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   AutoUpgrade: True" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   Method: DnsClient PowerShell API" -Module $script:ModuleName
            return $true
        }

        # The filtered DnsClient query throws CmdletizationQuery_NotFound when
        # a valid custom resolver is not registered yet. Query the supported
        # list first so absence reaches Add-DnsClientDohServerAddress.
        $canonicalServerAddress = ConvertTo-DnsCanonicalAddress -Address $ServerAddress
        $existing = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object {
                (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalServerAddress
            })
        if ($existing.Count -gt 1) {
            throw "Multiple DoH registrations exist for $ServerAddress"
        }
        if ($existing.Count -eq 1) {
            Set-DnsClientDohServerAddress -ServerAddress ([string]$existing[0].ServerAddress) `
                -DohTemplate $DohTemplate `
                -AllowFallbackToUdp $allowFallback `
                -AutoUpgrade $true `
                -ErrorAction Stop | Out-Null
        }
        else {
            Add-DnsClientDohServerAddress -ServerAddress $ServerAddress `
                -DohTemplate $DohTemplate `
                -AllowFallbackToUdp $allowFallback `
                -AutoUpgrade $true `
                -ErrorAction Stop | Out-Null
        }

        $verified = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object {
                (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalServerAddress
            })
        if ($verified.Count -ne 1 -or
            [string]$verified[0].DohTemplate -cne $DohTemplate -or
            [bool]$verified[0].AllowFallbackToUdp -ne [bool]$allowFallback -or
            -not [bool]$verified[0].AutoUpgrade) {
            throw "DoH registration verification failed for $ServerAddress"
        }

        Write-Log -Level DEBUG -Message "Successfully registered DoH for $ServerAddress" -Module "DNS"

        Write-Log -Level SUCCESS -Message "DoH endpoint registration configured for $ServerAddress" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  Template: $DohTemplate" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "  Fallback: $(if ($allowFallback) { 'ENABLED (ALLOW mode)' } else { 'DISABLED (REQUIRE mode)' })" -Module $script:ModuleName

        return $true
    }
    catch {
        # DoH might not be supported on older Windows versions.
        # Detect via exception type instead of localized error-message substring,
        # so non-EN Windows reports the same "unsupported" message.
        $exc = $_.Exception
        $isCommandNotFound = ($exc -is [System.Management.Automation.CommandNotFoundException]) -or
                             ($exc.GetType().FullName -like '*CommandNotFoundException*')

        if ($isCommandNotFound) {
            Write-Log -Level ERROR -Message "Required Windows DnsClient DoH cmdlets are unavailable; encrypted DNS cannot be configured or verified" -Module $script:ModuleName
            return $false
        }

        Write-ErrorLog -Message "Failed to enable DoH for $ServerAddress" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
