<#
.SYNOPSIS
    Detect SCCM/Configuration Manager presence

.DESCRIPTION
    Checks if Configuration Manager client (CcmExec.exe) is running
    This is critical because PSExec/WMI ASR rule conflicts with SCCM

.OUTPUTS
    Boolean when inspection succeeds; null when presence cannot be determined.
#>

function Test-ConfigMgrPresence {
    [CmdletBinding()]
    param()

    try {
        # Installed service registration is authoritative even while stopped;
        # the client can start later and would then conflict with the block rule.
        $ccmServiceMatches = @(Get-Service -ErrorAction Stop | Where-Object { [string]$_.Name -eq 'CcmExec' })
        if ($ccmServiceMatches.Count -gt 1) { throw 'Configuration Manager service identity is ambiguous' }
        $ccmService = if ($ccmServiceMatches.Count -eq 1) { $ccmServiceMatches[0] } else { $null }

        if ($ccmService) {
            Write-Log -Level WARNING -Message "Configuration Manager (SCCM) client service detected ($($ccmService.Status))" -Module "ASR"
            return $true
        }

        # Check for CCM process
        $ccmProcess = @(Get-Process -ErrorAction Stop | Where-Object { [string]$_.ProcessName -eq 'CcmExec' })

        if ($ccmProcess.Count -gt 0) {
            Write-Log -Level WARNING -Message "Configuration Manager process detected" -Module "ASR"
            return $true
        }

        return $false
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to determine ConfigMgr presence: $_. No presence claim will be inferred from the query failure." -Module "ASR"
        return $null
    }
}
