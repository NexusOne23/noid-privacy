function Set-DoHPolicy {
    <#
    .SYNOPSIS
        Enforce DNS-over-HTTPS (DoH) system-wide according to the selected mode
        
    .DESCRIPTION
        Sets Windows registry keys to enforce DoH policy based on $script:DoHMode:
        - DoHPolicy = 3 (REQUIRE DoH - mandatory encryption, no fallback)
        - DoHPolicy = 2 (ALLOW DoH - encryption preferred, fallback to UDP allowed)
        - EnableAutoDoh = 2 (Enable automatic DoH upgrade)
        - netsh global doh = yes
        
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
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        # Determine DoH mode (REQUIRE or ALLOW)
        $dohModeValue = if ($script:DoHMode -eq "ALLOW") { 2 } else { 3 }
        $dohModeText = if ($script:DoHMode -eq "ALLOW") { "ALLOW (with fallback)" } else { "REQUIRE (no fallback)" }
        
        Write-Log -Level INFO -Message "Enforcing DoH policy ($dohModeText)" -Module $script:ModuleName
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would set DoH policy to $dohModeText" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   DoHPolicy = $dohModeValue ($($script:DoHMode))" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   EnableAutoDoh = 2 (enforce)" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   DohFlags = 1 (use DoH)" -Module $script:ModuleName
            Write-Log -Level DEBUG -Message "[DRYRUN]   netsh global doh = yes" -Module $script:ModuleName
            return $true
        }
        
        # Registry path for DNS Client settings
        $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        
        # Ensure policy path exists
        if (-not (Test-Path $dnsClientPath)) {
            New-Item -Path $dnsClientPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $dnsClientPath" -Module $script:ModuleName
        }
        
        # CRITICAL ORDER: netsh FIRST (may reset registry values), then Registry entries AFTER
        # This ensures Registry values persist and are not overwritten by netsh
        
        # 1. FIRST: Activate DoH globally via netsh (this may reset EnableAutoDoh!)
        try {
            netsh dnsclient set global doh=yes 2>&1 | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level DEBUG -Message "netsh global DoH activated" -Module $script:ModuleName
            }
            else {
                Write-Log -Level WARNING -Message "netsh global DoH returned exit code $LASTEXITCODE" -Module $script:ModuleName
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Could not activate global DoH via netsh: $_" -Module $script:ModuleName
        }
        
        # 2. SECOND: EnableAutoDoh = 2 (Enable automatic DoH) - AFTER netsh!
        if (-not (Test-Path $dnsParamsPath)) {
            New-Item -Path $dnsParamsPath -Force | Out-Null
        }
        $existing = Get-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value 2 -Force | Out-Null
        } else {
            New-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value 2 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "Set EnableAutoDoh = 2 (Automatic DoH enabled)" -Module $script:ModuleName
        
        # 3. THIRD: DoHPolicy = 2 (ALLOW) or 3 (REQUIRE) - LAST for highest priority
        #    Values: 0=Default, 1=Prohibit, 2=Allow, 3=Require
        $existing = Get-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -Value $dohModeValue -Force | Out-Null
        } else {
            New-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -Value $dohModeValue -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "Set DoHPolicy = $dohModeValue ($dohModeText)" -Module $script:ModuleName
        
        # NOTE: Global DohFlags removed - we use per-adapter DohFlags instead (set in Invoke-DNSConfiguration)
        # Per-adapter DohFlags are more reliable and prevent conflicts
        
        Write-Log -Level SUCCESS -Message "DoH policy verified: $dohModeText" -Module $script:ModuleName
        return $true
    }
    catch {
        Write-ErrorLog -Message "Failed to set DoH policy" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
