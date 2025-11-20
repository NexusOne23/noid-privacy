<#
.SYNOPSIS
    Backup current ASR registry settings
    
.DESCRIPTION
    Creates backup of ASR registry keys before modification
    
.PARAMETER BackupId
    Identifier for this backup
    
.OUTPUTS
    PSCustomObject with backup info
#>

function Backup-ASRRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupId = "ASR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    $result = [PSCustomObject]@{
        Success    = $true
        BackupPath = $null
        Errors     = @()
    }
    
    try {
        $asrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
        
        if (Test-Path $asrPath) {
            # Use Core/Rollback backup function
            try {
                Backup-RegistryKey -KeyPath $asrPath -BackupName "ASR_Config"
                Write-Log -Level INFO -Message "ASR registry backed up with ID: $BackupId" -Module "ASR"
            }
            catch {
                Write-Log -Level WARNING -Message "Registry backup failed: $_" -Module "ASR"
                $result.Errors += "Backup failed: $_"
            }
        }
        else {
            Write-Log -Level INFO -Message "No existing ASR configuration to backup" -Module "ASR"
        }
    }
    catch {
        $result.Success = $false
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "ASR backup failed: $($_.Exception.Message)" -Module "ASR"
    }
    
    return $result
}
