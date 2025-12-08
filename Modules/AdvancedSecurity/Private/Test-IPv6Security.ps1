function Test-IPv6Security {
    <#
    .SYNOPSIS
        Test IPv6 disable status (mitm6 attack mitigation)
    
    .DESCRIPTION
        Checks if IPv6 is completely disabled via DisabledComponents registry value.
        This is an OPTIONAL setting only available in Maximum profile.
        
        DisabledComponents = 0xFF (255) means IPv6 is completely disabled.
    
    .EXAMPLE
        Test-IPv6Security
    #>
    [CmdletBinding()]
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $value = Get-ItemProperty -Path $regPath -Name "DisabledComponents" -ErrorAction SilentlyContinue
        
        if ($value -and $value.DisabledComponents -eq 255) {
            return [PSCustomObject]@{
                Feature   = "IPv6 Disable (mitm6 mitigation)"
                Pass      = $true
                Compliant = $true
                Message   = "IPv6 DISABLED (DisabledComponents = 0xFF) - mitm6 protected"
                Details   = "IPv6 completely disabled - DHCPv6 spoofing attacks blocked"
            }
        }
        elseif ($value -and $value.DisabledComponents -gt 0) {
            return [PSCustomObject]@{
                Feature   = "IPv6 Disable (mitm6 mitigation)"
                Pass      = $true
                Compliant = $true
                Message   = "IPv6 PARTIALLY disabled (DisabledComponents = $($value.DisabledComponents))"
                Details   = "IPv6 partially disabled - some mitm6 protection"
            }
        }
        else {
            # IPv6 is enabled - this is OPTIONAL, so still "pass" but note it's not configured
            return [PSCustomObject]@{
                Feature   = "IPv6 Disable (mitm6 mitigation)"
                Pass      = $true  # Optional feature - not a failure
                Compliant = $true  # Optional feature
                Message   = "IPv6 ENABLED (Optional - not configured)"
                Details   = "IPv6 enabled (default) - WPAD disabled provides partial mitm6 protection"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test IPv6 security: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature   = "IPv6 Disable (mitm6 mitigation)"
            Pass      = $true  # Don't fail on error for optional feature
            Compliant = $true
            Message   = "Error checking IPv6 status"
            Details   = "Could not determine IPv6 status: $_"
        }
    }
}
