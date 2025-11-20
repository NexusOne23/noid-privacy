<#
.SYNOPSIS
    Disable Xbox XblGameSave Standby Task
    
.DESCRIPTION
    Disables the Xbox XblGameSave Standby Task which runs in the background
    even if Xbox features are disabled. This is a privacy/security measure.
    
    Task: \Microsoft\XblGameSave\XblGameSaveTask
    
.PARAMETER DryRun
    Preview changes without applying
    
.OUTPUTS
    PSCustomObject with Success status
    
.NOTES
    Part of Microsoft Security Baseline recommendation
#>

function Disable-XboxTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        TaskDisabled = $false
        Errors = @()
    }
    
    try {
        $taskPath = "\Microsoft\XblGameSave\"
        $taskName = "XblGameSaveTask"
        
        # Check if task exists
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        
        if (-not $task) {
            Write-Log -Level DEBUG -Message "Xbox task not found (probably not installed)" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }
        
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable task: $taskPath$taskName" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }
        
        # Disable the task
        Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        
        $result.Success = $true
        $result.TaskDisabled = $true
        Write-Log -Level DEBUG -Message "Disabled Xbox task: $taskPath$taskName" -Module "SecurityBaseline"
        
    }
    catch {
        $result.Errors += "Failed to disable Xbox task: $($_.Exception.Message)"
        Write-Warning "Failed to disable Xbox task: $_"
    }
    
    return $result
}
