function Test-WirelessDisplaySecurity {
    <#
    .SYNOPSIS
        Tests Wireless Display (Miracast) security configuration.
    
    .DESCRIPTION
        Verifies that Wireless Display policies are configured securely:
        - AllowProjectionToPC = 0 (blocking receiving)
        - RequirePinForPairing = 2 (always require PIN)
        - Optionally: Complete disable of all Wireless Display
    
    .EXAMPLE
        Test-WirelessDisplaySecurity
    #>
    [CmdletBinding()]
    param()
    
    try {
        $connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
        
        $results = @{
            AllowProjectionToPC = $null
            RequirePinForPairing = $null
            AllowProjectionFromPC = $null
            AllowMdnsAdvertisement = $null
            AllowMdnsDiscovery = $null
            WiFiDirectServiceDisabled = $null
            Compliant = $false
            FullyDisabled = $false
        }
        
        if (Test-Path $connectPath) {
            $props = Get-ItemProperty -Path $connectPath -ErrorAction SilentlyContinue
            
            # Check basic hardening (always required)
            $results.AllowProjectionToPC = $props.AllowProjectionToPC
            $results.RequirePinForPairing = $props.RequirePinForPairing
            
            # Check optional complete disable
            $results.AllowProjectionFromPC = $props.AllowProjectionFromPC
            $results.AllowMdnsAdvertisement = $props.AllowMdnsAdvertisement
            $results.AllowMdnsDiscovery = $props.AllowMdnsDiscovery
            
            # Check WiFi Direct Service status (CRITICAL for complete block)
            $wfdService = Get-Service -Name "WFDSConMgrSvc" -ErrorAction SilentlyContinue
            $results.WiFiDirectServiceDisabled = ($null -eq $wfdService) -or ($wfdService.StartType -eq 'Disabled')
            
            # Basic compliance: receiving blocked + PIN required
            $results.Compliant = ($results.AllowProjectionToPC -eq 0) -and ($results.RequirePinForPairing -eq 2)
            
            # Fully disabled: all settings at 0/2 AND WiFi Direct service disabled
            $results.FullyDisabled = $results.Compliant -and 
                ($results.AllowProjectionFromPC -eq 0) -and 
                ($results.AllowMdnsAdvertisement -eq 0) -and 
                ($results.AllowMdnsDiscovery -eq 0) -and
                $results.WiFiDirectServiceDisabled
        }
        else {
            # Key doesn't exist = not hardened
            $results.Compliant = $false
            $results.FullyDisabled = $false
        }
        
        return [PSCustomObject]$results
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test Wireless Display security: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $null
    }
}
