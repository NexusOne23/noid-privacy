<#
.SYNOPSIS
    Backup Xbox XblGameSave Standby Task state
    
.DESCRIPTION
    Backs up the current state (Enabled/Disabled/Ready) of the Xbox XblGameSave
    Standby Task before it is modified by the Security Baseline.
    
    Saves to JSON file containing:
    - Task existence status
    - Task state (if exists)
    - Timestamp
    
.PARAMETER BackupPath
    Path where backup JSON will be saved
    
.OUTPUTS
    PSCustomObject with backup status
    
.NOTES
    Part of BAVR (Backup-Apply-Verify-Restore) workflow
#>

function Backup-XboxTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        BackupPath = $BackupPath
        Errors = @()
    }
    
    try {
        # Note: "Backing up..." message already logged by caller (Invoke-SecurityBaseline)
        $taskPath = "\Microsoft\XblGameSave\"
        $taskName = "XblGameSaveTask"
        
        # Check if task exists
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        
        if (-not $task) {
            Write-Log -Level DEBUG -Message "Xbox task not found (not installed) - backing up non-existent state" -Module "SecurityBaseline"
            
            $backupData = @{
                Timestamp = Get-Date -Format "o"
                TaskPath = $taskPath
                TaskName = $taskName
                Exists = $false
                State = $null
            }
        }
        else {
            Write-Log -Level DEBUG -Message "Xbox task found - State: $($task.State)" -Module "SecurityBaseline"
            
            $backupData = @{
                Timestamp = Get-Date -Format "o"
                TaskPath = $taskPath
                TaskName = $taskName
                Exists = $true
                State = $task.State.ToString()
            }
        }
        
        # Save backup to JSON
        $backupData | ConvertTo-Json -Depth 3 | Out-File -FilePath $BackupPath -Encoding UTF8 -Force
        
        $result.Success = $true
        Write-Log -Level DEBUG -Message "Xbox task state backed up to: $BackupPath" -Module "SecurityBaseline"
        
    }
    catch {
        $result.Errors += "Xbox task backup failed: $_"
        Write-Error "Xbox task backup failed: $_"
    }
    
    return $result
}
