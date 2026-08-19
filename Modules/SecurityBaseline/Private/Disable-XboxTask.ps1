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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable XboxTask')) {
        return [PSCustomObject]@{ Success = $false; TaskExists = $false; TaskDisabled = $false; Errors = @('Operation was not confirmed') }
    }


    $result = [PSCustomObject]@{
        Success = $false
        # "The task is present" and "the task was disabled" are different facts.
        # DryRun can only ever report the first.
        TaskExists = $false
        TaskDisabled = $false
        Errors = @()
    }

    try {
        $taskPath = "\Microsoft\XblGameSave\"
        $taskName = "XblGameSaveTask"

        # Check if task exists
        $taskMatches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -eq $taskPath -and $_.TaskName -eq $taskName
        })
        if ($taskMatches.Count -gt 1) { throw 'Xbox task identity is ambiguous' }
        $task = if ($taskMatches.Count -eq 1) { $taskMatches[0] } else { $null }

        if (-not $task) {
            Write-Log -Level DEBUG -Message "Xbox task not found (probably not installed)" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }

        # The task exists. Say so explicitly: the caller previously told the two
        # cases apart only by TaskDisabled, which is $false in BOTH the
        # not-installed and the DryRun branch, so a preview on a machine that has
        # the task reported "not found (not installed)" - and the following Apply
        # then disabled it. The preview is the only pre-change information DryRun
        # exists to give.
        $result.TaskExists = $true

        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable task: $taskPath$taskName" -Module "SecurityBaseline"
            $result.Success = $true
            return $result
        }

        # Disable the task
        Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        $verifiedTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        if ($verifiedTask.State.ToString() -ne 'Disabled') {
            throw "Xbox task verification failed: state is $($verifiedTask.State)"
        }

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
