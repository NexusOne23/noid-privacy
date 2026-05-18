<#
.SYNOPSIS
    Restore ASR settings from backup
    
.DESCRIPTION
    Restores ASR registry settings from a previous backup created by Backup-ASRRegistry
    
.PARAMETER BackupId
    Identifier of the backup to restore
    
.OUTPUTS
    PSCustomObject with restore results
#>

function Restore-ASRSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupId
    )
    
    # This helper is deprecated. ASR restore is handled centrally by the
    # framework rollback system (Restore-Session / Restore-AllBackups).
    # Keeping this function to avoid breaking existing scripts, but make
    # its behavior explicit and safe.
    Write-Log -Level WARNING -Message "Restore-ASRSettings is deprecated. Use the main rollback workflow (Restore-AllBackups or GUI Restore) instead." -Module "ASR"
    throw "Restore-ASRSettings is deprecated. Use the framework rollback (Core\Rollback.ps1) instead."
}
