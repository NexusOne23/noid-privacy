#Requires -Version 5.1

. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Get-PrivacyUserContext.ps1')
. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacyWindowsSearch.ps1')

function Assert-NoIDXboxRecoveryResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$UserSid,
        [Parameter(Mandatory)][int]$SessionId
    )

    Assert-NoIDXboxObjectFields $Record @('SchemaVersion','UserSid','SessionId','Success','Entries')
    if ($Record.SchemaVersion -isnot [int] -or $Record.SchemaVersion -ne 1 -or
        $Record.UserSid -cne $UserSid -or $Record.SessionId -isnot [int] -or
        $Record.SessionId -ne $SessionId -or $Record.Success -isnot [bool]) {
        throw 'Xbox recovery result has an invalid schema or user binding'
    }
    $catalog = Get-NoIDXboxComponentCatalog
    if (@($Record.Entries).Count -ne $catalog.Apps.Count) { throw 'Xbox recovery result is incomplete' }
    $success = $true
    foreach ($app in $catalog.Apps) {
        $identityMatches = @($Record.Entries | Where-Object { $_.Name -ceq $app.Name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox recovery result has a missing or duplicate app identity' }
        $entry = $identityMatches[0]
        Assert-NoIDXboxObjectFields $entry @('Name','Required','Outcome','BeforePresent','Present','Healthy','Error')
        if ($entry.Required -isnot [bool] -or $entry.Required -ne $app.RequiredWhenEnabled -or
            $entry.Outcome -cnotin @('AlreadyPresent','RegisteredLocally','InstalledFromStore','OptionalUnavailable','NeedsNetwork','Failed') -or
            $entry.Error -isnot [string] -or $entry.Error.Length -gt 8192) {
            throw 'Xbox recovery app result contains invalid metadata'
        }
        foreach ($field in @('BeforePresent','Present','Healthy')) {
            if ($null -ne $entry.$field -and $entry.$field -isnot [bool]) { throw 'Xbox recovery app evidence is not Boolean' }
        }
        if (($null -eq $entry.Present) -ne ($null -eq $entry.Healthy) -or
            ($entry.Healthy -and -not $entry.Present)) { throw 'Xbox recovery app evidence is inconsistent' }
        if ($entry.Outcome -cin @('AlreadyPresent','RegisteredLocally','InstalledFromStore')) {
            if ($entry.BeforePresent -isnot [bool] -or $entry.Present -ne $true -or
                $entry.Healthy -ne $true -or $entry.Error.Length -ne 0 -or
                ($entry.Outcome -ceq 'AlreadyPresent' -and -not $entry.BeforePresent) -or
                ($entry.Outcome -ceq 'InstalledFromStore' -and -not $app.StoreId)) {
                throw 'Xbox recovery success lacks complete healthy app evidence'
            }
        }
        elseif ($entry.Outcome -ceq 'OptionalUnavailable') {
            if ($app.RequiredWhenEnabled -or $app.StoreId -or $entry.BeforePresent -isnot [bool] -or
                $entry.Present -ne $false -or $entry.Healthy -ne $false -or $entry.Error.Length -ne 0) {
                throw 'Xbox recovery optional absence is invalid'
            }
        }
        else { $success = $false }
    }
    if ($Record.Success -ne $success) { throw 'Xbox recovery success summary disagrees with its app results' }
}

function New-NoIDXboxRecoveryExchange {
    <# Keep the original result handle open: never follow a user-replaced result path. #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param([Parameter(Mandatory)][string]$UserSid)

    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $path = Join-Path $parent ('NoID-XboxRecovery-' + [Guid]::NewGuid().ToString('N'))
    if (-not $PSCmdlet.ShouldProcess($path, 'Create a protected Xbox result exchange')) { return }
    $directory = [IO.DirectoryInfo]::new($path)
    $stream = $null
    $created = $false
    try {
        if ($directory.Exists -or [IO.File]::Exists($path)) { throw 'Xbox exchange path already exists' }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @('S-1-5-18','S-1-5-32-544',$UserSid)) {
            $rights = if ($sid -ceq $UserSid) { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
                else { [Security.AccessControl.FileSystemRights]::FullControl }
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), $rights, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
        $directory.Create($security)
        Assert-PrivacyWorkerExchangeDirectory -Path $path
        $actual = $directory.GetAccessControl()
        if (-not $actual.AreAccessRulesProtected -or
            $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544') {
            throw 'Xbox exchange ownership or inheritance is unsafe'
        }
        $rules = @($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 3) { throw 'Xbox exchange has unexpected permissions' }
        foreach ($sid in @('S-1-5-18','S-1-5-32-544',$UserSid)) {
            $grant = @($rules | Where-Object { $_.IdentityReference.Value -ceq $sid })
            $rights = if ($sid -ceq $UserSid) {
                [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
            } else { [Security.AccessControl.FileSystemRights]::FullControl }
            if ($grant.Count -ne 1 -or $grant[0].FileSystemRights -ne $rights -or
                $grant[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $grant[0].InheritanceFlags -ne $inheritance -or
                $grant[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
                throw 'Xbox exchange grants unexpected access'
            }
        }
        $created = $true
        $resultPath = Join-Path $path 'result.json'
        # FileShare excludes Delete. The original handle remains open through
        # validation; a changed path cannot redirect a privileged result read.
        $stream = [IO.File]::Open($resultPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $file = [IO.FileInfo]::new($resultPath)
        $acl = $file.GetAccessControl()
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($UserSid),
            ([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write),
            [Security.AccessControl.AccessControlType]::Allow))
        $file.SetAccessControl($acl)
        return [pscustomobject]@{Directory=$path;ResultPath=$resultPath;Stream=$stream}
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created) {
            Remove-PrivacyWorkerExchangeDirectory -Path $path -ResultPath (Join-Path $path 'result.json') -Confirm:$false
        }
        throw
    }
}

function Read-NoIDXboxRecoveryExchange {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Exchange)

    $stream = $Exchange.Stream
    $length = $stream.Length
    if ($length -lt 2 -or $length -gt 262144) { throw 'Xbox recovery result exceeds its permitted size or is empty' }
    $stream.Position = 0
    $bytes = [byte[]]::new([int]$length)
    $offset = 0
    while ($offset -lt $length) {
        $read = $stream.Read($bytes, $offset, [int]$length - $offset)
        if ($read -lt 1) { throw 'Xbox recovery result changed during its bounded read' }
        $offset += $read
    }
    if ($stream.Length -ne $length) { throw 'Xbox recovery result changed during its bounded read' }
    try {
        return ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -ErrorAction Stop)
    }
    catch { throw 'Xbox recovery result is not valid UTF-8 JSON' }
}

function Invoke-NoIDXboxRecoveryWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExpectedSid,
        [Parameter(Mandatory)][int]$ExpectedSessionId,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $source = [string]$MyInvocation.MyCommand.ScriptBlock.File
    $repoRoot = Split-Path (Split-Path $source -Parent) -Parent
    foreach ($relativePath in @(
        'Core\Runtime.ps1','Core\Logger.ps1','Core\XboxComponents.ps1','Core\XboxSettings.ps1',
        'Core\XboxAppRecovery.ps1','Modules\Privacy\Private\Get-PrivacyUserContext.ps1',
        'Modules\Privacy\Public\Restore-BloatwareApps.ps1'
    )) { . (Join-Path $repoRoot $relativePath) }
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $record = Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid $ExpectedSid -ExpectedSessionId $ExpectedSessionId `
        -TimeoutSeconds $TimeoutSeconds -Confirm:$false
    Assert-NoIDXboxRecoveryResult -Record $record -UserSid $ExpectedSid -SessionId $ExpectedSessionId
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $record -Depth 8 -Compress))
    if ($bytes.Length -gt 262144) { throw 'Xbox recovery result exceeds its permitted size' }
    $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $stream.SetLength(0)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    }
    finally { $stream.Dispose() }
    return $record
}

function Confirm-NoIDXboxRecoveryResult {
    <# The elevated caller verifies live registrations independently of worker output. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$UserSid)

    $snapshot = Get-NoIDXboxComponentSnapshot -UserSid $UserSid
    foreach ($entry in $Record.Entries) {
        $app = @($snapshot.Apps | Where-Object { $_.Name -ceq $entry.Name })[0]
        $entry.Present = $app.Present
        $entry.Healthy = $app.Healthy
        if (($entry.Required -and -not $app.Present) -or ($app.Present -and -not $app.Healthy) -or
            (-not $app.Present -and $entry.Outcome -cin @('AlreadyPresent','RegisteredLocally','InstalledFromStore'))) {
            $entry.Outcome = 'Failed'
            $verificationError = 'The app is absent or unhealthy in the independent registration check'
            $entry.Error = if ([string]::IsNullOrWhiteSpace($entry.Error)) { $verificationError }
                else { ($entry.Error.Substring(0, [Math]::Min($entry.Error.Length, 7900)) + '; ' + $verificationError) }
        }
        elseif ($entry.Outcome -ceq 'OptionalUnavailable' -and $app.Present) {
            $entry.Outcome = 'RegisteredLocally'
        }
    }
    $Record.Success = @($Record.Entries | Where-Object { $_.Outcome -cin @('Failed','NeedsNetwork') }).Count -eq 0
    return $Record
}

function Invoke-NoIDXboxAppRecovery {
    <# A bounded original-user job; temporary task/exchange data are not backup sessions. #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]$User,
        [ValidateRange(60,1800)][int]$TimeoutSeconds=1200
    )

    $source = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($source)) { throw 'Xbox recovery worker source is unavailable' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Xbox app orchestration requires an elevated administrator token'
    }
    $sid = [string]$User.Sid
    $session = $User.SessionId
    if ($sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or $session -isnot [int] -or $session -lt 1) {
        throw 'Xbox recovery user binding is invalid'
    }
    $desktop = Get-PrivacyUserContext -Refresh
    if ($desktop.Sid -cne $sid -or $desktop.SessionId -ne $session) { throw 'Xbox recovery desktop identity changed' }
    $null = Assert-NoIDXboxUnmanagedDevice
    $snapshot = Get-NoIDXboxComponentSnapshot -UserSid $sid
    if ($snapshot.RemovalBlocked) { throw 'An active app-removal policy still blocks Xbox; enable Xbox settings first' }
    if (-not $PSCmdlet.ShouldProcess('Xbox apps', 'Recover apps in the original desktop account')) { return }

    $exchange = $null
    $hidden = $null
    $registered = $false
    $quiesced = $true
    $taskName = 'NoID-XboxRecovery-' + [Guid]::NewGuid().ToString('N')
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $record = $null
    try {
        $exchange = New-NoIDXboxRecoveryExchange -UserSid $sid -Confirm:$false
        $escapedSource = $source.Replace("'", "''")
        $escapedOutput = $exchange.ResultPath.Replace("'", "''")
        $workerSeconds = $TimeoutSeconds - 10
        $command = "`$ErrorActionPreference='Stop'; . '$escapedSource'; " +
            "`$record=Invoke-NoIDXboxRecoveryWorker -ExpectedSid '$sid' -ExpectedSessionId $session " +
            "-OutputPath '$escapedOutput' -TimeoutSeconds $workerSeconds; if(-not `$record.Success){exit 1}"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $hidden = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId $session
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds + 5))
        $null = Register-ScheduledTask -TaskName $taskName -Action $hidden.Action -Principal $hidden.Principal -Settings $settings -ErrorAction Stop
        $registered = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $timer = [Diagnostics.Stopwatch]::StartNew()
        do {
            $state = Get-NoIDScheduledTaskState -TaskName $taskName
            if ($state -cnotin @('Ready','Disabled','Running','Queued')) {
                throw 'Xbox app recovery worker state could not be verified'
            }
            if ($state -notin @('Running','Queued')) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
                if ($info.LastRunTime.Year -ge 2000 -and $info.LastTaskResult -notin @(267009,267011)) { break }
            }
            Start-Sleep -Milliseconds 200
        } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        if ($state -in @('Running','Queued') -or $timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Xbox app recovery timed out' }
        if ([int64]$info.LastTaskResult -notin @(0,1)) { throw 'Xbox app recovery worker could not complete' }
        $record = Read-NoIDXboxRecoveryExchange -Exchange $exchange
        Assert-NoIDXboxRecoveryResult -Record $record -UserSid $sid -SessionId $session
        if (([int64]$info.LastTaskResult -eq 0) -ne $record.Success) { throw 'Xbox recovery result disagrees with its worker exit status' }
        $record = Confirm-NoIDXboxRecoveryResult -Record $record -UserSid $sid
        Assert-NoIDXboxRecoveryResult -Record $record -UserSid $sid -SessionId $session
    }
    catch { $operationError = $_ }
    finally {
        if ($registered) {
            try {
                $state = Get-NoIDScheduledTaskState -TaskName $taskName
                if ($state -in @('Running','Queued')) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $timer = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Milliseconds 100
                        $state = Get-NoIDScheduledTaskState -TaskName $taskName
                    } while ($state -in @('Running','Queued') -and $timer.Elapsed.TotalSeconds -lt 10)
                    if ($state -in @('Running','Queued')) { throw 'Xbox recovery worker remained active after its stop deadline' }
                }
                if ($state -cnotin @('Ready','Disabled')) {
                    throw 'Xbox recovery worker termination could not be verified'
                }
            }
            catch { $quiesced=$false; $cleanupErrors.Add('Xbox worker could not be stopped') }
            if ($quiesced) {
                try { $null = Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false }
                catch { $cleanupErrors.Add('Xbox temporary task could not be removed') }
            }
        }
        if ($null -ne $exchange) { $exchange.Stream.Dispose() }
        # Keep evidence and launcher when a worker cannot be stopped (its staged
        # files end with this process). Never claim a safe rollback while an
        # app process may still be writing.
        if ($quiesced) {
            if ($null -ne $hidden) {
                try { Remove-NoIDHiddenWorkerLauncher -Launcher $hidden -Confirm:$false }
                catch { $cleanupErrors.Add('Xbox hidden launcher cleanup failed') }
            }
            if ($null -ne $exchange) {
                try { Remove-PrivacyWorkerExchangeDirectory -Path $exchange.Directory -ResultPath $exchange.ResultPath -Confirm:$false }
                catch { $cleanupErrors.Add('Xbox result exchange cleanup failed') }
            }
        }
    }
    if ($cleanupErrors.Count -gt 0) {
        $exception = [InvalidOperationException]::new(($cleanupErrors -join '; '))
        $exception.Data['WorkerQuiesced'] = $quiesced
        throw $exception
    }
    if ($null -ne $operationError) {
        $operationError.Exception.Data['WorkerQuiesced'] = $quiesced
        $PSCmdlet.ThrowTerminatingError($operationError)
    }
    return $record
}
