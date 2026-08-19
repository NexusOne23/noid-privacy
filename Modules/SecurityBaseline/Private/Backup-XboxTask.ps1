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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success = $false
        BackupPath = $BackupPath
        Errors = @()
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Backup XboxTask')) {
        $result.Errors += 'Operation was not confirmed'
        return $result
    }

    try {
        # Note: "Backing up..." message already logged by caller (Invoke-SecurityBaseline)
        $taskPath = "\Microsoft\XblGameSave\"
        $taskName = "XblGameSaveTask"

        # Query success and absence must be distinguishable; a failed query is
        # not a valid "task absent" backup.
        $taskMatches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -eq $taskPath -and $_.TaskName -eq $taskName
        })
        if ($taskMatches.Count -gt 1) { throw 'Xbox task identity is ambiguous' }
        $task = if ($taskMatches.Count -eq 1) { $taskMatches[0] } else { $null }

        if (-not $task) {
            Write-Log -Level DEBUG -Message "Xbox task not found (not installed) - backing up non-existent state" -Module "SecurityBaseline"

            $backupData = @{
                SchemaVersion = 2
                Timestamp = Get-Date -Format "o"
                TaskPath = $taskPath
                TaskName = $taskName
                Exists = $false
                Enabled = $null
            }
        }
        else {
            Write-Log -Level DEBUG -Message "Xbox task found - State: $($task.State)" -Module "SecurityBaseline"

            $backupData = @{
                SchemaVersion = 2
                Timestamp = Get-Date -Format "o"
                TaskPath = $taskPath
                TaskName = $taskName
                Exists = $true
                Enabled = ($task.State.ToString() -ne 'Disabled')
            }
        }

        # Save backup to JSON via .NET WriteAllText (UTF-8 NO-BOM).
        $backupJson = $backupData | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($BackupPath, $backupJson, [System.Text.UTF8Encoding]::new($false))

        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw 'Xbox task backup artifact was not created'
        }
        $roundTrip = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$roundTrip.SchemaVersion -ne 2 -or
            [string]$roundTrip.TaskPath -cne $taskPath -or
            [string]$roundTrip.TaskName -cne $taskName -or
            [bool]$roundTrip.Exists -ne [bool]$backupData.Exists -or
            ([bool]$roundTrip.Exists -and $null -eq $roundTrip.Enabled)) {
            throw 'Xbox task backup failed round-trip validation'
        }
        $result.Success = $true
        Write-Log -Level DEBUG -Message "Xbox task state backed up to: $BackupPath" -Module "SecurityBaseline"

    }
    catch {
        $result.Errors += "Xbox task backup failed: $_"
        Write-Error "Xbox task backup failed: $_"
    }

    return $result
}
