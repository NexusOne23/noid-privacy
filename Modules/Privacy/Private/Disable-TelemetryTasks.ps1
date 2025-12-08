function Disable-TelemetryTasks {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][array]$Tasks)
    
    try {
        Write-Log -Level INFO -Message "Disabling scheduled tasks..." -Module "Privacy"
        
        foreach ($taskPath in $Tasks) {
            try {
                Disable-ScheduledTask -TaskPath (Split-Path $taskPath -Parent) -TaskName (Split-Path $taskPath -Leaf) -ErrorAction Stop
                Write-Log -Level SUCCESS -Message "Disabled task: $taskPath" -Module "Privacy"
            } catch {
                Write-Log -Level WARNING -Message "Task not found or cannot disable: $taskPath" -Module "Privacy"
            }
        }
        
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to disable tasks: $_" -Module "Privacy"
        return $false
    }
}
