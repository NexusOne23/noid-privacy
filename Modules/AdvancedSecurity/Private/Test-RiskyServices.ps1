function Test-RiskyServices {
    <#
    .SYNOPSIS
        Test risky network services compliance
    
    .DESCRIPTION
        Checks if risky network services (SSDPSRV, upnphost, lmhosts) are stopped and disabled
    
    .EXAMPLE
        Test-RiskyServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = [PSCustomObject]@{
            Feature = "Risky Network Services"
            Status = "Unknown"
            Details = @()
            RunningServices = @()
            StoppedServices = @()
            Compliant = $false
        }
        
        # Note: Computer Browser (Browser) is deprecated in Win10/11 - not included
        $services = @("SSDPSRV", "upnphost", "lmhosts")
        
        foreach ($svcName in $services) {
            $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            
            if (-not $service) {
                $result.Details += "$svcName - Not found (service may not be installed)"
                continue
            }
            
            if ($service.Status -eq 'Running') {
                $result.RunningServices += $svcName
                $result.Details += "WARNING - $svcName is RUNNING (StartType: $($service.StartType))"
            }
            else {
                $result.StoppedServices += $svcName
                
                if ($service.StartType -eq 'Disabled') {
                    $result.Details += "${svcName}: Stopped and Disabled"
                }
                else {
                    $result.Details += "WARNING: ${svcName} is stopped but StartType is $($service.StartType) (should be Disabled)"
                }
            }
        }
        
        # Determine compliance
        if ($result.RunningServices.Count -eq 0) {
            $stoppedAndDisabled = $true
            
            foreach ($svcName in $services) {
                $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($service -and $service.StartType -ne 'Disabled') {
                    $stoppedAndDisabled = $false
                    break
                }
            }
            
            if ($stoppedAndDisabled) {
                $result.Status = "Secure"
                $result.Compliant = $true
            }
            else {
                $result.Status = "Partially Secure"
                $result.Compliant = $false
            }
        }
        else {
            $result.Status = "Insecure"
            $result.Compliant = $false
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test risky services: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature = "Risky Network Services"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
