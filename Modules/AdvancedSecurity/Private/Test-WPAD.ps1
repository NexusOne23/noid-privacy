function Test-WPAD {
    <#
    .SYNOPSIS
        Test WPAD configuration compliance
    
    .DESCRIPTION
        Verifies that Web Proxy Auto-Discovery (WPAD) is disabled.
    
    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = [PSCustomObject]@{
            Feature = "WPAD (Proxy Auto-Discovery)"
            Status = "Unknown"
            Details = @()
            Compliant = $true
        }
        
        $wpadKeys = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
                Name = "WpadOverride"
                Expected = 1
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "AutoDetect"
                Expected = 0
            }
        )
        
        $nonCompliantCount = 0
        
        foreach ($key in $wpadKeys) {
            if (Test-Path $key.Path) {
                $val = (Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue).($key.Name)
                
                if ($val -eq $key.Expected) {
                    # Compliant
                }
                else {
                    $result.Details += "$($key.Name) is NOT set to $($key.Expected) (Current: $val)"
                    $nonCompliantCount++
                }
            }
            else {
                # Key missing
                $result.Details += "Registry key missing: $($key.Path)"
                $nonCompliantCount++
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
        Write-Log -Level ERROR -Message "Failed to test WPAD: $_" -Module "AdvancedSecurity"
        return [PSCustomObject]@{
            Feature = "WPAD (Proxy Auto-Discovery)"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
