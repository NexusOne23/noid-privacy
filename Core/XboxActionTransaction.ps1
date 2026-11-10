#Requires -Version 5.1

function Assert-NoIDXboxWorkersIdle {
    [CmdletBinding()]
    param()

    # A previous process may have lost its mutex while its app worker survived.
    # Check only NoID's exact temporary worker names; never stop unrelated tasks.
    $active = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {
        $_.TaskName -cmatch '^NoID-(XboxRecovery|PrivacyAppx)-[0-9a-f]{32}$' -and
        [string]$_.State -cnotin @('Ready','Disabled')
    })
    if ($active.Count -gt 0) { throw 'A previous NoID app operation is still running or its state is unknown; wait before changing Xbox settings' }
}

function Invoke-NoIDXboxAction {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$DesiredState,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedFingerprint,
        [string]$BackupDirectory = (Join-Path $script:FrameworkRoot 'Backups')
    )

    $mutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
    $held = $false
    $pre = $null
    $prepared = $null
    $mutated = $false
    $settingsAfterApply = $null
    $appsMayHaveChanged = $false
    $workerQuiesced = $true
    try {
        try { $held = $mutex.WaitOne(0, $false) }
        catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another NoID mutation is already running' }
        Assert-NoIDXboxWorkersIdle
        $pre = Get-NoIDXboxActionState
        Assert-NoIDXboxActionState $pre
        if ($pre.fingerprint -cne $ExpectedFingerprint) {
            throw 'Xbox changed after it was displayed; refresh before applying'
        }
        if ($pre.state -ceq $DesiredState) {
            $intentWarning = ''
            if (-not $WhatIfPreference) {
                $intentWarning = Update-NoIDXboxIntentAfterChange -SourceKind QuickActionLiveConfirmation -LiveState $pre
            }
            return [pscustomobject][ordered]@{
                schemaVersion=1;success=$true;status='NoChange';actionId='Xbox';desiredState=$DesiredState
                preFingerprint=$pre.fingerprint;postFingerprint=$pre.fingerprint;backupPath=''
                mutated=$false;verified=$true;error=$intentWarning
            }
        }
        if (-not $PSCmdlet.ShouldProcess('Xbox', "Apply $DesiredState; record settings only, without backing up app data")) {
            throw 'Xbox action was not confirmed'
        }
        $prepared = New-NoIDXboxPreparedSession -PreState $pre -DesiredState $DesiredState -BackupDirectory $BackupDirectory -Confirm:$false
        $operation = Invoke-NoIDXboxActionScopeApply -PreState $pre -DesiredState $DesiredState -Confirm:$false
        $mutated = $operation.Changed
        $appsMayHaveChanged = $operation.Changed
        $settingsAfterApply = $operation.PostState.targets.settings
        $null = Complete-NoIDXboxSession -PreparedSession $prepared -PostState $operation.PostState -Confirm:$false
        $intentWarning = Update-NoIDXboxIntentAfterChange -SourceKind QuickActionApply -SessionPath $prepared.SessionPath
        return [pscustomobject][ordered]@{
            schemaVersion=1;success=$true;status='Applied';actionId='Xbox';desiredState=$DesiredState
            preFingerprint=$pre.fingerprint;postFingerprint=$operation.PostState.fingerprint;backupPath=$prepared.SessionPath
            mutated=$true;verified=$true;error=$intentWarning
        }
    }
    catch {
        $failure = $_.Exception
        $message = $failure.Message
        if ($failure.Data.Contains('XboxSettingsWriteStarted')) { $mutated = [bool]$failure.Data['XboxSettingsWriteStarted'] }
        if ($failure.Data.Contains('XboxAppsMayHaveChanged')) { $appsMayHaveChanged = [bool]$failure.Data['XboxAppsMayHaveChanged'] }
        if ($failure.Data.Contains('WorkerQuiesced')) { $workerQuiesced = [bool]$failure.Data['WorkerQuiesced'] }
        if ($failure.Data.Contains('XboxSettingsAfterApply')) { $settingsAfterApply = $failure.Data['XboxSettingsAfterApply'] }
        $settingsRestored = $false
        if ($mutated -and $pre) {
            try {
                if (-not $workerQuiesced) { throw 'The app worker has not been confirmed stopped; settings were retained' }
                Assert-NoIDXboxWorkersIdle
                $current = Get-NoIDXboxSettingsState
                $currentHash = Get-QuickActionObjectSha256 $current
                if ($currentHash -cne (Get-QuickActionObjectSha256 $pre.targets.settings)) {
                    # A partial settings failure has no verified poststate. Do
                    # not overwrite unexplained values or a later external edit.
                    if ($null -eq $settingsAfterApply -or $currentHash -cne (Get-QuickActionObjectSha256 $settingsAfterApply)) {
                        throw 'Current settings cannot be attributed to this operation; automatic restore was refused'
                    }
                    $null = Restore-NoIDXboxActionSettings -Settings $pre.targets.settings -ExpectedCurrentSettings $current -Confirm:$false
                }
                $settingsRestored = $true
            }
            catch { $message += ' Settings recovery: '+$_.Exception.Message }
        }
        $status = if (-not $mutated) { 'Failed' }
            elseif ($settingsRestored) { 'ApplyFailedSettingsRestored' } else { 'ApplyFailedSettingsRestoreFailed' }
        if ($prepared) {
            try {
                $recordStatus = if (-not $mutated) { 'Rejected' } else { $status }
                $document = Set-NoIDXboxFailedSession -SessionPath $prepared.SessionPath -Status $recordStatus -Confirm:$false
                if (-not $mutated -or $settingsRestored) {
                    # This receipt closes configuration overlap only. The
                    # schema-4 manifest explicitly excludes app restoration.
                    $null = Write-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest -Scopes @('action:Xbox') -Confirm:$false
                }
            }
            catch { $message += ' Failure record could not be completed: '+$_.Exception.Message }
        }
        if ($appsMayHaveChanged) { $message += ' Apps may have changed; refresh Xbox and retry the intended setting. App versions and app data were not restored.' }
        return [pscustomobject][ordered]@{
            schemaVersion=1;success=$false;status=$status;actionId='Xbox';desiredState=$DesiredState
            preFingerprint=$(if ($pre) {$pre.fingerprint} else {''});postFingerprint=''
            backupPath=$(if ($prepared) {$prepared.SessionPath} else {''})
            mutated=[bool]$mutated;verified=$false;error=$message
        }
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
