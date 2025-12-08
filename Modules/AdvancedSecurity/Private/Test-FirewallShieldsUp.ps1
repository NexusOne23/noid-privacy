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
            return @{
                Pass = $false
                Message = "Shields Up NOT enabled (Public network allows configured exceptions)"
                CurrentValue = if ($null -eq $value) { "Not Set" } else { $value.$valueName }
            }
        }
        
        return @{
            Pass = $true
            Message = "Shields Up ENABLED (Public network blocks ALL incoming)"
            CurrentValue = 1
        }
    }
    catch {
        return @{
            Pass = $false
            Message = "Error checking Shields Up: $_"
            CurrentValue = "Error"
        }
    }
}
