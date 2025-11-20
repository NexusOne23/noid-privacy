<#
.SYNOPSIS
    Verify cloud-delivered protection is enabled
    
.DESCRIPTION
    Some ASR rules require cloud protection to be enabled
    This function checks if it's active
    
.OUTPUTS
    Boolean - True if cloud protection is enabled
#>

function Test-CloudProtection {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        # Check via Get-MpPreference
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        if ($mpPref.MAPSReporting -eq 0) {
            Write-Log -Level WARNING -Message "Cloud-delivered protection (MAPS) is disabled" -Module "ASR"
            return $false
        }
        
        Write-Log -Level INFO -Message "Cloud-delivered protection is enabled (MAPS: $($mpPref.MAPSReporting))" -Module "ASR"
        return $true
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to check cloud protection status: $_" -Module "ASR"
        return $false
    }
}
