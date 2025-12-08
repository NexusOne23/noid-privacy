function Test-LegacyTLS {
    <#
    .SYNOPSIS
        Test Legacy TLS configuration compliance
    
    .DESCRIPTION
        Verifies that TLS 1.0 and TLS 1.1 are disabled for both Client and Server.
    
    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = [PSCustomObject]@{
            Feature = "Legacy TLS (1.0/1.1)"
            Status = "Unknown"
            Details = @()
            Compliant = $true
        }
        
        $tlsVersions = @("TLS 1.0", "TLS 1.1")
        $components = @("Server", "Client")
        $nonCompliantCount = 0
        
        foreach ($version in $tlsVersions) {
            foreach ($component in $components) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
                
                if (Test-Path $regPath) {
                    $enabled = (Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    $disabledByDefault = (Get-ItemProperty -Path $regPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault
                    
                    if ($enabled -eq 0) {
                        # Compliant
                    }
                    elseif ($null -eq $enabled -and $disabledByDefault -eq 1) {
                        # Compliant (implicitly disabled)
                    }
                    else {
                        $result.Details += "$version $component is NOT disabled (Enabled=$enabled)"
                        $nonCompliantCount++
                    }
                }
                else {
                    # Key missing usually means default (Enabled on old OS, Disabled on very new OS)
                    # For hardening, we expect explicit disable keys
                    $result.Details += "$version $component registry keys missing"
                    $nonCompliantCount++
                }
            }
        }
        
        if ($nonCompliantCount -eq 0) {
            $result.Status = "Secure (Disabled)"
            $result.Compliant = $true
        }
        else {
            $result.Status = "Insecure ($nonCompliantCount issues)"
            $result.Compliant = $false
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test Legacy TLS: $_" -Module "AdvancedSecurity"
        return [PSCustomObject]@{
            Feature = "Legacy TLS (1.0/1.1)"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
