function Test-FirewallShieldsUp {
    <#
    .SYNOPSIS
        Test if Firewall Shields Up mode is enabled
    
    .DESCRIPTION
        Checks DoNotAllowExceptions value for PublicProfile firewall.
    #>
    [CmdletBinding()]
    param()
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
    $valueName = "DoNotAllowExceptions"
    
    try {
        $value = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
        
        if ($null -eq $value -or $value.$valueName -ne 1) {
            # Shields Up is OPTIONAL (Maximum profile only) - not a failure if not enabled
            return @{
                Pass = $true  # Optional feature - always pass
                Message = "Shields Up not enabled (Optional - Maximum profile only)"
                CurrentValue = if ($null -eq $value) { "Not Set" } else { $value.$valueName }
                IsEnabled = $false
            }
        }
        
        return @{
            Pass = $true
            Message = "Shields Up ENABLED (Public network blocks ALL incoming)"
            CurrentValue = 1
            IsEnabled = $true
        }
    }
    catch {
        return @{
            Pass = $true  # Don't fail on error for optional feature
            Message = "Error checking Shields Up: $_"
            CurrentValue = "Error"
            IsEnabled = $false
        }
    }
}
