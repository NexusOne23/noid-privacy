<#
.SYNOPSIS
    Detect SCCM/Configuration Manager presence
    
.DESCRIPTION
    Checks if Configuration Manager client (CcmExec.exe) is running
    This is critical because PSExec/WMI ASR rule conflicts with SCCM
    
.OUTPUTS
    Boolean - True if ConfigMgr detected
#>

function Test-ConfigMgrPresence {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        # Check for CCM service
        $ccmService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        
        if ($ccmService -and $ccmService.Status -eq "Running") {
            Write-Log -Level WARNING -Message "Configuration Manager (SCCM) client detected" -Module "ASR"
            return $true
        }
        
        # Check for CCM process
        $ccmProcess = Get-Process -Name "CcmExec" -ErrorAction SilentlyContinue
        
        if ($ccmProcess) {
            Write-Log -Level WARNING -Message "Configuration Manager process detected" -Module "ASR"
            return $true
        }
        
        return $false
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to detect ConfigMgr: $_. Assuming not present." -Module "ASR"
        return $false
    }
}
