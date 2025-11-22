function Disable-LegacyTLS {
    <#
    .SYNOPSIS
        Disable legacy TLS 1.0 and TLS 1.1
    
    .DESCRIPTION
        Disables TLS 1.0 and TLS 1.1 for both Client and Server to prevent
        BEAST, CRIME, and other attacks.
        
        Attack Prevention: BEAST, CRIME, weak cipher suites
        
        Impact: May break old internal web applications that haven't been updated
    
    .EXAMPLE
        Disable-LegacyTLS
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Disabling legacy TLS 1.0 and TLS 1.1..." -Module "AdvancedSecurity"
        
        $tlsVersions = @("TLS 1.0", "TLS 1.1")
        $components = @("Server", "Client")
        
        $setCount = 0
        
        foreach ($version in $tlsVersions) {
            foreach ($component in $components) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
                
                # Create path if needed
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                # Disable TLS version
                $existing = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $regPath -Name "Enabled" -Value 0 -Force | Out-Null
                } else {
                    New-ItemProperty -Path $regPath -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
                }
                
                $existing = Get-ItemProperty -Path $regPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value 1 -Force | Out-Null
                } else {
                    New-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null
                }
                
                Write-Log -Level SUCCESS -Message "Disabled $version $component" -Module "AdvancedSecurity"
                $setCount += 2
            }
        }
        
        Write-Log -Level SUCCESS -Message "Legacy TLS disabled ($setCount registry keys set)" -Module "AdvancedSecurity"
        Write-Host ""
        Write-Host "Legacy TLS Disabled:" -ForegroundColor Green
        Write-Host "  TLS 1.0: Client + Server" -ForegroundColor Gray
        Write-Host "  TLS 1.1: Client + Server" -ForegroundColor Gray
        Write-Host ""
        Write-Host "WARNING: Old web applications may not work!" -ForegroundColor Yellow
        Write-Host "Only TLS 1.2 and TLS 1.3 are now allowed." -ForegroundColor Gray
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable legacy TLS: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
