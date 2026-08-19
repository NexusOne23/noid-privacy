#Requires -Version 5.1

function Remove-BloatwareApps {
    <#
    .SYNOPSIS
        Removes only the exact per-user package instances sealed in Tier 2 prestate.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ActionLog
    )

    $result = [PSCustomObject]@{
        Success = $false
        TargetPackages = 0
        Removed = 0
        Failed = 0
        FailedApps = [System.Collections.Generic.List[string]]::new()
    }
    $null = Assert-PrivacyBloatwareActionLog -ActionLog $ActionLog
    $userContext = Get-PrivacyUserContext
    $userSid = [string]$userContext.Sid
    if ([string]$ActionLog.InteractiveUserSid -cne $userSid) {
        throw "Tier 2 sealed user changed before Apply: expected $($ActionLog.InteractiveUserSid), got $userSid"
    }
    $presentEntries = @($ActionLog.Entries | Where-Object { [bool]$_.Present })
    $result.TargetPackages = $presentEntries.Count

    if (-not $PSCmdlet.ShouldProcess($userSid, "Remove $($presentEntries.Count) sealed Tier 2 package instance(s); local app data can be lost")) {
        return $result
    }

    if ($presentEntries.Count -eq 0) {
        $result.Success = $true
        Write-Log -Level SUCCESS -Message 'Tier 2 removal: no sealed installed package instances require removal' -Module 'Privacy'
        return $result
    }

    try {
        $worker = Invoke-PrivacyUserAppxRemoval -User $userContext -Entries $presentEntries
        $result.Removed = [int]$worker.Removed
        $result.Failed = [int]$worker.Failed
        foreach ($failedEntry in @($worker.Entries | Where-Object { -not [bool]$_.Removed })) {
            $result.FailedApps.Add("$($failedEntry.AppName): $($failedEntry.Error)")
        }
        $result.Success = ([bool]$worker.Success -and $result.Failed -eq 0 -and
            $result.Removed -eq $result.TargetPackages)
    }
    catch {
        $result.Failed = $result.TargetPackages
        $result.FailedApps.Add("current-user task: $($_.Exception.Message)")
        Write-Log -Level ERROR -Message "Tier 2 current-user removal failed: $($_.Exception.Message)" -Module 'Privacy'
    }
    Write-Log -Level $(if ($result.Success) { 'SUCCESS' } else { 'ERROR' }) -Message "Tier 2 removal: $($result.Removed)/$($result.TargetPackages) removed and verified, $($result.Failed) failed" -Module 'Privacy'
    return $result
}
