<#
.SYNOPSIS
    Restore Xbox XblGameSave Standby Task state
    
.DESCRIPTION
    Restores the Xbox XblGameSave Standby Task to its original state
    from backup created by Backup-XboxTask.
    
    Handles three scenarios:
    - Task did not exist before: Do nothing
    - Task was Disabled: Keep it disabled (no action needed)
    - Task was Ready/Running: Re-enable it
    
.PARAMETER BackupPath
    Path to backup JSON file created by Backup-XboxTask
    
.OUTPUTS
    PSCustomObject with restore status
    
.NOTES
    Part of BAVR (Backup-Apply-Verify-Restore) workflow
#>

function Restore-XboxTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        Errors = @()
    }
    
    if (-not (Test-Path $BackupPath)) {
        $result.Errors += "Backup file not found: $BackupPath"
        return $result
    }
    
    try {
        Write-Log -Level DEBUG -Message "Restoring Xbox task state from: $BackupPath" -Module "SecurityBaseline"
        
        # Load backup
        $backupData = Get-Content $BackupPath -Raw | ConvertFrom-Json
        
        # If task did not exist before, do nothing
        if (-not $backupData.Exists) {
            Write-Log -Level DEBUG -Message "Xbox task did not exist before hardening - no restore needed" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }
        
        # Check if task currently exists
        $task = Get-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction SilentlyContinue
        
        if (-not $task) {
            Write-Log -Level WARNING -Message "Xbox task exists in backup but not found on system - cannot restore" -Module "SecurityBaseline"
            $result.Errors += "Xbox task not found on system (may have been uninstalled)"
            $result.Success = $true  # Not a critical error
            return $result
        }
        
        # Restore original state
        $originalState = $backupData.State
        $currentState = $task.State.ToString()
        
        Write-Log -Level DEBUG -Message "Xbox task - Original: $originalState, Current: $currentState" -Module "SecurityBaseline"
        
        # If original state was Ready (enabled), and current is Disabled, re-enable it
        if ($originalState -eq "Ready" -and $currentState -eq "Disabled") {
            Enable-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction Stop | Out-Null
            Write-Log -Level DEBUG -Message "Xbox task re-enabled to match original state" -Module "SecurityBaseline"
        }
        elseif ($originalState -eq "Disabled" -and $currentState -eq "Disabled") {
            Write-Log -Level DEBUG -Message "Xbox task was already disabled before hardening - keeping disabled" -Module "SecurityBaseline"
        }
        else {
            Write-Log -Level DEBUG -Message "Xbox task state matches original or no action needed" -Module "SecurityBaseline"
        }
        
        $result.Success = $true
        Write-Log -Level DEBUG -Message "Xbox task state restored successfully" -Module "SecurityBaseline"
        
    }
    catch {
        $result.Errors += "Xbox task restore failed: $_"
        Write-Error "Xbox task restore failed: $_"
    }
    
    return $result
}
