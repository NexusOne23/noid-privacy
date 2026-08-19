function Disable-TelemetryTasks {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory = $true)][array]$Tasks)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable TelemetryTasks')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Disabling scheduled tasks..." -Module "Privacy"
        $installedTasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($taskPath in $Tasks) {
            try {
                $taskFolder = Split-Path $taskPath -Parent
                $taskName = Split-Path $taskPath -Leaf
                $taskFolderName = $taskFolder.Trim([char]'\')
                $taskFolder = if ([string]::IsNullOrWhiteSpace($taskFolderName)) { '\' } else { '\' + $taskFolderName + '\' }
                $taskMatches = @($installedTasks | Where-Object { [string]$_.TaskPath -eq $taskFolder -and [string]$_.TaskName -eq $taskName })
                if ($taskMatches.Count -ne 1) {
                    throw "Sealed Privacy task identity no longer resolves exactly once (found $($taskMatches.Count))"
                }
                $task = $taskMatches[0]
                Disable-ScheduledTask -TaskPath $taskFolder -TaskName $taskName -ErrorAction Stop | Out-Null
                $task = Get-ScheduledTask -TaskPath $taskFolder -TaskName $taskName -ErrorAction Stop
                if ([string]$task.State -ne 'Disabled') { throw "Task state after disable is $($task.State)" }
                Write-Log -Level SUCCESS -Message "Disabled task: $taskPath" -Module "Privacy"
            } catch {
                throw "Failed to disable scheduled task '$taskPath': $($_.Exception.Message)"
            }
        }

        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to disable tasks: $_" -Module "Privacy"
        return $false
    }
}
