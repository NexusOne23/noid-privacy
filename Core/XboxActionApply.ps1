#Requires -Version 5.1

function Invoke-NoIDXboxActionScopeApply {
    <#
    .SYNOPSIS
        Applies a reviewed Xbox state inside the caller's mutation transaction.
    .DESCRIPTION
        The caller owns the shared mutation lock and records settings before
        invoking this helper. App installations are not an exact version/data
        restore. On failure, the caller may restore settings only after all
        workers have stopped, and must report any partial app change separately.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]$PreState,
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$DesiredState
    )

    Assert-NoIDXboxActionState $PreState
    $live = Get-NoIDXboxActionState
    Assert-NoIDXboxActionState $live
    if ($live.fingerprint -cne $PreState.fingerprint) {
        throw 'Xbox changed after it was displayed; refresh before applying'
    }
    $user = Get-PrivacyUserContext -Refresh
    if ($user.Sid -cne $PreState.targets.userSid -or $user.SessionId -ne $PreState.targets.sessionId) {
        throw 'Xbox desktop identity changed before applying'
    }
    if ($live.state -ceq $DesiredState) {
        return [pscustomobject]@{Changed=$false;AppResult=$null;PostState=$live}
    }
    if (-not $PSCmdlet.ShouldProcess('Xbox apps and settings', "Apply $DesiredState; leave games and shared Gaming Services unchanged")) {
        throw 'Xbox action was not confirmed'
    }
    $settingsCompleted = $false
    $appsStarted = $false
    $appsCompleted = $false
    $settingsAfterApply = $null
    try {
        Invoke-NoIDXboxSettingsApply -PreState $PreState.targets.settings -DesiredState $DesiredState `
            -ComponentSnapshot $PreState.targets.components -Confirm:$false
        $settingsCompleted = $true
        $settingsAfterApply = Get-NoIDXboxSettingsState
        $appsStarted = $true
        $appResult = if ($DesiredState -ceq 'Disable') {
            Invoke-NoIDXboxAppRemoval -User $user -Entries @($PreState.targets.components.RemovablePackages) -Confirm:$false
        }
        else {
            Invoke-NoIDXboxAppRecovery -User $user -Confirm:$false
        }
        $appsCompleted = $true
        if (-not $appResult.Success) {
            $message = 'Xbox app changes did not complete; settings and installed apps must be checked separately'
            if ($DesiredState -ceq 'Enable') {
                $failed = @($appResult.Entries | Where-Object Outcome -In @('Failed','NeedsNetwork') |
                    ForEach-Object { $_.Name+': '+$(if($_.Outcome -ceq 'NeedsNetwork') {'Internet access is required'} else {$_.Error}) })
                if ($failed.Count -gt 0) { $message += ': '+($failed -join '; ') }
            }
            $exception = [InvalidOperationException]::new($message)
            $exception.Data['AppChangesIncomplete'] = $true
            $exception.Data['WorkerQuiesced'] = $true
            throw $exception
        }
        $post = Get-NoIDXboxActionState
        Assert-NoIDXboxActionState $post
        if ($post.state -cne $DesiredState -or $post.targets.userSid -cne $user.Sid -or
            $post.targets.sessionId -ne $user.SessionId) {
            throw 'Xbox live state did not reach the requested state for the original desktop user'
        }
        return [pscustomobject]@{Changed=$true;AppResult=$appResult;PostState=$post}
    }
    catch {
        if ($settingsCompleted) { $_.Exception.Data['XboxSettingsWriteStarted'] = $true }
        $_.Exception.Data['XboxAppsMayHaveChanged'] = $appsStarted
        if ($null -ne $settingsAfterApply) { $_.Exception.Data['XboxSettingsAfterApply'] = $settingsAfterApply }
        if (-not $_.Exception.Data.Contains('WorkerQuiesced')) {
            $_.Exception.Data['WorkerQuiesced'] = (-not $appsStarted -or $appsCompleted)
        }
        throw
    }
}
