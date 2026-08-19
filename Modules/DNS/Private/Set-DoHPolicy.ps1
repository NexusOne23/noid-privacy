function Set-DoHPolicy {
    <#
    .SYNOPSIS
        Enforce DNS-over-HTTPS (DoH) system-wide according to the selected mode

    .DESCRIPTION
        Sets Windows registry keys to enforce DoH policy based on $script:DoHMode:
        - DoHPolicy = 3 (REQUIRE DoH - mandatory encryption, no fallback)
        - DoHPolicy = 2 (ALLOW DoH - encryption preferred, fallback to UDP allowed)

        DoHPolicy values: 0=Default, 1=Prohibit, 2=Allow, 3=Require

        In REQUIRE mode this prevents Windows from silently falling back to
        unencrypted DNS on port 53. In ALLOW mode, encrypted DoH is still used
        for supported servers, but fallback to classic DNS is permitted for
        VPN/mobile/enterprise scenarios.

    .PARAMETER DryRun
        Show what would be configured without applying changes

    .EXAMPLE
        Set-DoHPolicy

    .NOTES
        Requires Administrator privileges
        Based on Microsoft DNS Client documentation
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set DoHPolicy')) {
        return
    }


    try {
        if ($script:DoHMode -notin @('ALLOW', 'REQUIRE')) {
            throw "Unsupported DoH mode: $($script:DoHMode)"
        }
        # Determine DoH mode (REQUIRE or ALLOW)
        $dohModeValue = if ($script:DoHMode -eq "ALLOW") { 2 } else { 3 }
        $dohModeText = if ($script:DoHMode -eq "ALLOW") { "ALLOW (with fallback)" } else { "REQUIRE (no fallback)" }

        Write-Log -Level INFO -Message "Enforcing DoH policy ($dohModeText)" -Module $script:ModuleName

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would set DoH policy to $dohModeText" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   DoHPolicy = $dohModeValue ($($script:DoHMode))" -Module $script:ModuleName
            return $true
        }

        # Registry path for DNS Client settings
        $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        # Original key/value existence is captured in DNS_PreState.json.
        if (-not (Test-Path $dnsClientPath)) {
            New-Item -Path $dnsClientPath -Force -ErrorAction Stop | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $dnsClientPath" -Module $script:ModuleName
        }

        # DoHPolicy = 2 (ALLOW) or 3 (REQUIRE).
        #    Values: 0=Default, 1=Prohibit, 2=Allow, 3=Require
        New-ItemProperty -LiteralPath $dnsClientPath -Name 'DoHPolicy' `
            -PropertyType DWord -Value ([int]$dohModeValue) -Force -ErrorAction Stop | Out-Null
        Write-Log -Level SUCCESS -Message "Set DoHPolicy = $dohModeValue ($dohModeText)" -Module $script:ModuleName

        $dnsClientKey = Get-Item -LiteralPath $dnsClientPath -ErrorAction Stop
        $actualPolicy = $dnsClientKey.GetValue('DoHPolicy')
        $actualType = $dnsClientKey.GetValueKind('DoHPolicy').ToString()
        if ([int]$actualPolicy -ne $dohModeValue -or $actualType -ne 'DWord') {
            throw "DoH policy readback did not match requested values"
        }

        Write-Log -Level SUCCESS -Message "DoH policy verified: $dohModeText" -Module $script:ModuleName
        return $true
    }
    catch {
        Write-ErrorLog -Message "Failed to set DoH policy" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
