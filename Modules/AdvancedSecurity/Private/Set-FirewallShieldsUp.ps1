function Set-FirewallShieldsUp {
    <#
    .SYNOPSIS
        Enable "Shields Up" mode - Block ALL incoming connections on Public network
    
    .DESCRIPTION
        Sets DoNotAllowExceptions=1 for PublicProfile firewall.
        This blocks ALL incoming connections, even from allowed apps.
        Goes BEYOND Microsoft Security Baseline.
    
    .PARAMETER Enable
        Enable Shields Up mode (block all incoming on Public)
    
    .PARAMETER Disable
        Disable Shields Up mode (allow configured exceptions)
    #>
    [CmdletBinding()]
    param(
        [switch]$Enable,
        [switch]$Disable
    )
    
    $moduleName = "AdvancedSecurity"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
    $valueName = "DoNotAllowExceptions"
    
    try {
        if ($Enable) {
            Write-Log -Level INFO -Message "Enabling Firewall Shields Up mode (Public profile)..." -Module $moduleName
            
            # Ensure path exists
            if (!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            # Set DoNotAllowExceptions = 1
            Set-ItemProperty -Path $regPath -Name $valueName -Value 1 -Type DWord -Force
            
            Write-Log -Level SUCCESS -Message "Firewall Shields Up ENABLED - All incoming connections blocked on Public network" -Module $moduleName
            Write-Host ""
            Write-Host "  SHIELDS UP: Public network now blocks ALL incoming connections" -ForegroundColor Green
            Write-Host "  This includes allowed apps (Teams, Discord, etc. cannot receive calls)" -ForegroundColor Yellow
            Write-Host ""
            
            return $true
        }
        elseif ($Disable) {
            Write-Log -Level INFO -Message "Disabling Firewall Shields Up mode..." -Module $moduleName
            
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name $valueName -Value 0 -Type DWord -Force
            }
            
            Write-Log -Level SUCCESS -Message "Firewall Shields Up disabled - Normal firewall exceptions apply" -Module $moduleName
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "No action specified for Set-FirewallShieldsUp" -Module $moduleName
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set Firewall Shields Up: $_" -Module $moduleName
        return $false
    }
}
