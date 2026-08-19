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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore XboxTask')) {
        return [PSCustomObject]@{ Success = $false; Errors = @('Operation was not confirmed') }
    }


    $result = [PSCustomObject]@{
        Success = $false
        Errors = @()
    }

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        $result.Errors += "Backup file not found: $BackupPath"
        return $result
    }

    try {
        Write-Log -Level DEBUG -Message "Restoring Xbox task state from: $BackupPath" -Module "SecurityBaseline"

        # Load backup
        $backupData = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

        if ($backupData.SchemaVersion -ne 2 -or
            [string]$backupData.TaskPath -ne '\Microsoft\XblGameSave\' -or
            [string]$backupData.TaskName -ne 'XblGameSaveTask') {
            throw 'Xbox task backup has an invalid schema or target'
        }

        # If task did not exist before, do not delete a task that may have been
        # installed independently after Apply.
        if (-not $backupData.Exists) {
            Write-Log -Level DEBUG -Message "Xbox task did not exist before hardening - no restore needed" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }

        # Check if task currently exists
        $task = Get-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction Stop

        if (-not $task) {
            throw 'Xbox task existed at backup time but is missing during restore'
        }

        # Restore original state
        if ([bool]$backupData.Enabled) {
            Enable-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction Stop | Out-Null
        }
        else {
            Disable-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction Stop | Out-Null
        }
        $verifiedTask = Get-ScheduledTask -TaskPath $backupData.TaskPath -TaskName $backupData.TaskName -ErrorAction Stop
        $enabledNow = $verifiedTask.State.ToString() -ne 'Disabled'
        if ($enabledNow -ne [bool]$backupData.Enabled) {
            throw "Xbox task restore verification failed: expected Enabled=$($backupData.Enabled), actual Enabled=$enabledNow"
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
