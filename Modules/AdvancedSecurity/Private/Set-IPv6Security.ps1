function Set-IPv6Security {
    <#
    .SYNOPSIS
        Disable IPv6 to prevent DHCPv6/Router Solicitation attacks (mitm6)
    
    .DESCRIPTION
        Disables IPv6 via registry to prevent:
        - mitm6 attacks (DHCPv6 spoofing → DNS takeover → NTLM relay)
        - IPv6 Router Advertisement spoofing
        - DHCPv6 poisoning attacks
        
        This is the recommended mitigation per Fox-IT security research.
        
        WARNING: May break Exchange Server and some Active Directory features.
        Only recommended for air-gapped or high-security systems.
    
    .PARAMETER DisableCompletely
        If true, completely disables IPv6 (DisabledComponents = 0xFF)
    
    .EXAMPLE
        Set-IPv6Security -DisableCompletely
    
    .NOTES
        Registry: HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents
        Value 0xFF = Disable all IPv6 components
        
        REBOOT REQUIRED for changes to take effect.
        
        References:
        - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
        - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
    #>
    [CmdletBinding()]
    param(
        [switch]$DisableCompletely
    )
    
    try {
        if (-not $DisableCompletely) {
            Write-Log -Level INFO -Message "IPv6 disable not requested - keeping default configuration" -Module "AdvancedSecurity"
            return $true
        }
        
        Write-Log -Level INFO -Message "Disabling IPv6 (mitm6 attack mitigation)..." -Module "AdvancedSecurity"
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        
        # Backup current value
        $currentValue = Get-ItemProperty -Path $regPath -Name "DisabledComponents" -ErrorAction SilentlyContinue
        $backupData = @{
            Path = $regPath
            Name = "DisabledComponents"
            PreviousValue = if ($currentValue) { $currentValue.DisabledComponents } else { "_NOT_SET" }
            NewValue = 255
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "Registry" -Data $backupJson -Name "IPv6_DisabledComponents"
        
        # Ensure registry path exists
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Set DisabledComponents to 0xFF (255) = Disable all IPv6 components
        Set-ItemProperty -Path $regPath -Name "DisabledComponents" -Value 255 -Type DWord -Force
        
        Write-Log -Level SUCCESS -Message "IPv6 disabled (DisabledComponents = 0xFF)" -Module "AdvancedSecurity"
        
        # Verify
        $verifyValue = (Get-ItemProperty -Path $regPath -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
        if ($verifyValue -eq 255) {
            Write-Log -Level SUCCESS -Message "IPv6 disable verified - REBOOT REQUIRED" -Module "AdvancedSecurity"
            
            Write-Host ""
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host "  IPv6 DISABLED (mitm6 Attack Mitigation)" -ForegroundColor Yellow
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Registry: DisabledComponents = 0xFF (255)" -ForegroundColor White
            Write-Host ""
            Write-Host "Protection against:" -ForegroundColor Cyan
            Write-Host "  - DHCPv6 spoofing (mitm6 tool)" -ForegroundColor Gray
            Write-Host "  - IPv6 Router Advertisement attacks" -ForegroundColor Gray
            Write-Host "  - DNS takeover via fake DHCPv6 server" -ForegroundColor Gray
            Write-Host "  - NTLM credential relay attacks" -ForegroundColor Gray
            Write-Host ""
            Write-Host "REBOOT REQUIRED for changes to take effect!" -ForegroundColor Red
            Write-Host ""
            
            return $true
        }
        else {
            Write-Log -Level ERROR -Message "IPv6 disable verification failed" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable IPv6: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
