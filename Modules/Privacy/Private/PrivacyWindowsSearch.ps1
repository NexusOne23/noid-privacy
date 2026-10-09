#Requires -Version 5.1

. (Join-Path $PSScriptRoot '..\..\..\Core\HiddenWorker.ps1')

$script:PrivacyWindowsSearchHelperPath = $PSCommandPath
# The worker runs in its own process; it loads the shared registry helpers
# (Test-NoIDRegistryKey) that Get-PrivacyWindowsSearchRegistryState uses.
$script:PrivacyWindowsSearchRuntimePath = Join-Path (Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'Core') 'Runtime.ps1'

function Get-PrivacyWindowsSearchApiState {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    if (-not (Get-Command Get-WindowsSearchSetting -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft WindowsSearch Get-WindowsSearchSetting cmdlet is unavailable'
    }
    $settings = @(Get-WindowsSearchSetting -ErrorAction Stop | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace([string]$_.Setting)) {
                throw 'WindowsSearch returned an unnamed setting'
            }
            [PSCustomObject]@{ Setting = [string]$_.Setting; Value = [string]$_.Value }
        } | Sort-Object Setting)
    if ($settings.Count -lt 1 -or
        @($settings.Setting | Group-Object | Where-Object Count -ne 1).Count -gt 0) {
        throw 'WindowsSearch returned an invalid or duplicate setting inventory'
    }
    $webResults = @($settings | Where-Object Setting -ceq 'EnableWebResultsSetting')
    if ($webResults.Count -ne 1 -or [string]$webResults[0].Value -notin @('True', 'False')) {
        throw 'WindowsSearch did not return one Boolean EnableWebResultsSetting state'
    }
    return [PSCustomObject]@{
        WebResultsEnabled = [bool]::Parse([string]$webResults[0].Value)
        Settings = @($settings)
    }
}

function Get-PrivacyWindowsSearchRegistryState {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $entries = [Collections.Generic.List[object]]::new()
    foreach ($root in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
        )) {
        if (-not (Test-NoIDRegistryKey -LiteralPath $root)) { continue }
        $keys = @((Get-Item -LiteralPath $root -ErrorAction Stop)) +
            @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop)
        foreach ($key in $keys) {
            $keyPath = ([string]$key.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
            # Empty keys are state too. A value-only observation cannot detect
            # a native refresh creating or deleting an empty root or child.
            $entries.Add([PSCustomObject]@{
                    Path = $keyPath; Name = $null; Type = 'Key'; ValueJson = $null
                })
            foreach ($name in @($key.GetValueNames() | Sort-Object)) {
                $value = $key.GetValue(
                    [string]$name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $entries.Add([PSCustomObject]@{
                        Path = $keyPath
                        Name = [string]$name
                        Type = $key.GetValueKind([string]$name).ToString()
                        ValueJson = ([PSCustomObject]@{ Value = $value } |
                            ConvertTo-Json -Compress -Depth 20)
                    })
            }
        }
    }
    return @($entries | Sort-Object Path, Name)
}

function Test-PrivacyWindowsSearchExactState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual
    )

    return (($Expected | ConvertTo-Json -Compress -Depth 20) -ceq
        ($Actual | ConvertTo-Json -Compress -Depth 20))
}

function Invoke-PrivacyWindowsSearchWorker {
    <#
    .SYNOPSIS
        Queries or refreshes Windows Search in the original Explorer token.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Query', 'RefreshWebResults')]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')]
        [string]$ExpectedSid,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ExpectedSessionId,

        [bool]$WebResultsEnabled = $false,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $record = [ordered]@{
        SchemaVersion = 1
        CapturedUtc = [DateTime]::UtcNow.ToString('o')
        Operation = $Operation
        User = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        SessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        RequestedWebResultsEnabled = $(if ($Operation -eq 'RefreshWebResults') { [bool]$WebResultsEnabled } else { $null })
        BeforeWebResultsEnabled = $null
        WebResultsEnabled = $null
        Settings = @()
        RegistryStateUnchanged = $(if ($Operation -eq 'RefreshWebResults') { $false } else { $null })
        Success = $false
        Error = $null
    }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        # The user worker can retain a full token only when the account has no
        # filtered token: UAC disabled, or the built-in Administrator without
        # Admin Approval Mode. The exact SID/session binding below still proves
        # that the worker runs as the Explorer user in every case.
        $uacPolicy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        $enableLua = $uacPolicy.PSObject.Properties['EnableLUA']
        $filterAdministrator = $uacPolicy.PSObject.Properties['FilterAdministratorToken']
        $unfilteredAccount = ($null -ne $enableLua -and [int64]$enableLua.Value -eq 0) -or
            ($identity.User.Value -match '-500$' -and ($null -eq $filterAdministrator -or [int64]$filterAdministrator.Value -eq 0))
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $unfilteredAccount) {
            throw 'WindowsSearch worker unexpectedly has an administrator token'
        }
        if ([string]$record.Sid -cne $ExpectedSid -or
            [int]$record.SessionId -ne $ExpectedSessionId) {
            throw "WindowsSearch worker identity mismatch: $($record.Sid)/$($record.SessionId)"
        }

        $beforeApi = Get-PrivacyWindowsSearchApiState
        $record.BeforeWebResultsEnabled = [bool]$beforeApi.WebResultsEnabled
        if ($Operation -eq 'RefreshWebResults') {
            if (-not (Get-Command Set-WindowsSearchSetting -ErrorAction SilentlyContinue)) {
                throw 'The Microsoft WindowsSearch Set-WindowsSearchSetting cmdlet is unavailable'
            }
            $registryBefore = @(Get-PrivacyWindowsSearchRegistryState)
            $null = Set-WindowsSearchSetting `
                -EnableWebResultsSetting ([bool]$WebResultsEnabled) `
                -ErrorAction Stop
            $registryAfter = @(Get-PrivacyWindowsSearchRegistryState)
            $record.RegistryStateUnchanged = Test-PrivacyWindowsSearchExactState `
                -Expected $registryBefore -Actual $registryAfter
            if (-not [bool]$record.RegistryStateUnchanged) {
                throw 'The native WindowsSearch refresh changed registry state outside the pre-applied BAVR target'
            }
        }

        # Query is a single live read, not a before/after transition. Calling
        # the native WindowsSearch provider twice here adds no evidence and can
        # turn one successful preflight into a failure when the second provider
        # call stalls. Refresh still needs its independent post-operation read.
        $afterApi = if ($Operation -eq 'RefreshWebResults') {
            Get-PrivacyWindowsSearchApiState
        }
        else {
            $beforeApi
        }
        $record.WebResultsEnabled = [bool]$afterApi.WebResultsEnabled
        $record.Settings = @($afterApi.Settings)
        if ($Operation -eq 'RefreshWebResults') {
            $beforeOther = @($beforeApi.Settings | Where-Object Setting -cne 'EnableWebResultsSetting')
            $afterOther = @($afterApi.Settings | Where-Object Setting -cne 'EnableWebResultsSetting')
            if (-not (Test-PrivacyWindowsSearchExactState -Expected $beforeOther -Actual $afterOther)) {
                throw 'The native WindowsSearch refresh changed an unrelated Search API setting'
            }
            if ([bool]$record.WebResultsEnabled -ne [bool]$WebResultsEnabled) {
                throw "WindowsSearch effective web-results verification failed: expected $WebResultsEnabled, got $($record.WebResultsEnabled)"
            }
        }
        $record.Success = $true
    }
    catch {
        $record.Error = $_.Exception.ToString()
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "WindowsSearch worker output directory is unavailable: $parent"
    }
    $temporaryOutputPath = $OutputPath + '.tmp'
    [IO.File]::WriteAllText(
        $temporaryOutputPath,
        ($record | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryOutputPath -Destination $OutputPath -Force -ErrorAction Stop
    return [PSCustomObject]$record
}

function Invoke-PrivacyWindowsSearchUserState {
    <#
    .SYNOPSIS
        Executes the documented WindowsSearch cmdlets in the Explorer user token.

    .DESCRIPTION
        The elevated NoID Privacy process can belong to a separate administrator
        account. A transient dispatcher starts a worker with the original logged-on
        token (limited for split tokens), validates its SID/session, publishes
        one ACL-scoped result, and is removed before this function returns.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]$User,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Query', 'RefreshWebResults')]
        [string]$Operation,

        [bool]$WebResultsEnabled = $false,

        # The first WindowsSearch provider call after boot or after a Privacy
        # restore was measured at about 150 seconds on Windows 11 24H2, so the
        # former 120-second limit failed a Restore that a retry completed. The
        # bound matches the Privacy AppX worker.
        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 300
    )

    foreach ($property in @('Account', 'Sid', 'SessionId')) {
        if (-not $User.PSObject.Properties[$property]) {
            throw "WindowsSearch user context is missing '$property'"
        }
    }
    $sid = [string]$User.Sid
    $sessionId = [int]$User.SessionId
    if ([string]::IsNullOrWhiteSpace([string]$User.Account) -or
        $sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or $sessionId -lt 1) {
        throw 'WindowsSearch user context is invalid'
    }
    $caller = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'WindowsSearch user-token orchestration requires an elevated administrator token'
    }
    $currentUser = Get-PrivacyUserContext -Refresh
    if ([string]$currentUser.Account -cne [string]$User.Account -or
        [string]$currentUser.Sid -cne $sid -or
        [int]$currentUser.SessionId -ne $sessionId) {
        throw 'Interactive Privacy user identity changed before the WindowsSearch operation'
    }
    foreach ($workerSource in @($script:PrivacyWindowsSearchHelperPath, $script:PrivacyWindowsSearchRuntimePath)) {
        if (-not (Test-Path -LiteralPath $workerSource -PathType Leaf)) {
            throw "WindowsSearch helper source is unavailable: $workerSource"
        }
    }

    $identifier = [Guid]::NewGuid().ToString('N')
    $taskName = "NoID-WindowsSearch-$identifier"
    $exchangeDirectory = Join-Path $env:ProgramData $taskName
    $resultPath = Join-Path $exchangeDirectory 'result.json'
    $exchangeCreated = $false
    $hiddenWorker = $null
    $taskRegistered = $false
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $recordToReturn = $null
    try {
        $directory = New-Item -ItemType Directory -Path $exchangeDirectory -ErrorAction Stop
        $exchangeCreated = $true
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inherited = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $noInheritance = [Security.AccessControl.InheritanceFlags]::None
        $noPropagation = [Security.AccessControl.PropagationFlags]::None
        # The worker only creates result.json.tmp and renames it in place: it
        # may add and change files, but never delete or replace the folder.
        foreach ($access in @(
                @{Sid='S-1-5-18';Rights=[Security.AccessControl.FileSystemRights]::FullControl;Inheritance=$inherited;Propagation=$noPropagation}
                @{Sid='S-1-5-32-544';Rights=[Security.AccessControl.FileSystemRights]::FullControl;Inheritance=$inherited;Propagation=$noPropagation}
                @{Sid=$sid;Rights=([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::CreateFiles);Inheritance=$noInheritance;Propagation=$noPropagation}
                @{Sid=$sid;Rights=[Security.AccessControl.FileSystemRights]::Modify;Inheritance=[Security.AccessControl.InheritanceFlags]::ObjectInherit;Propagation=[Security.AccessControl.PropagationFlags]::InheritOnly}
            )) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new([string]$access.Sid),
                [Security.AccessControl.FileSystemRights]$access.Rights,
                [Security.AccessControl.InheritanceFlags]$access.Inheritance,
                [Security.AccessControl.PropagationFlags]$access.Propagation,
                [Security.AccessControl.AccessControlType]::Allow
            )
            $null = $security.AddAccessRule($rule)
        }
        $directory.SetAccessControl($security)

        $escapedHelper = $script:PrivacyWindowsSearchHelperPath.Replace("'", "''")
        $escapedRuntime = $script:PrivacyWindowsSearchRuntimePath.Replace("'", "''")
        $escapedOutput = $resultPath.Replace("'", "''")
        $webResultsLiteral = if ($WebResultsEnabled) { '$true' } else { '$false' }
        $workerCommand = "& { . '$escapedRuntime'; . '$escapedHelper'; " +
            "`$result = Invoke-PrivacyWindowsSearchWorker -Operation '$Operation' " +
            "-ExpectedSid '$sid' -ExpectedSessionId $sessionId " +
            "-WebResultsEnabled:$webResultsLiteral -OutputPath '$escapedOutput'; " +
            "if (-not `$result.Success) { exit 1 } }"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))
        $hiddenWorker = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encodedCommand -UserSid $sid -SessionId $sessionId
        $action = $hiddenWorker.Action
        $principal = $hiddenWorker.Principal
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds ([int]$TimeoutSeconds + 5))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        $waitTimer = [Diagnostics.Stopwatch]::StartNew()
        $waitLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        do {
            # A direct lookup: Get-ScheduledTask enumerates every task and fails
            # when another program deletes one meanwhile.
            $taskState = Get-NoIDScheduledTaskState -TaskName $taskName
            if ($taskState -notin @('Running', 'Queued') -and
                (Test-Path -LiteralPath $resultPath -PathType Leaf)) { break }
            if ($taskState -notin @('Running', 'Queued')) {
                Assert-NoIDHiddenWorkerTaskPending -TaskName $taskName -ResultPath $resultPath
            }
            Start-Sleep -Milliseconds 200
        } while ($waitTimer.Elapsed -lt $waitLimit)
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            throw "WindowsSearch user operation timed out; task result=$($taskInfo.LastTaskResult)"
        }
        # The user can add files to the exchange directory; never read through
        # a directory that was replaced by a link.
        Assert-PrivacyWorkerExchangeDirectory -Path $exchangeDirectory
        $resultFile = Get-Item -LiteralPath $resultPath -Force -ErrorAction Stop
        if ([bool]($resultFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $resultFile.Length -lt 2 -or $resultFile.Length -gt 262144) {
            throw 'WindowsSearch worker result is not a valid regular bounded file'
        }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ([int64]$taskInfo.LastTaskResult -ne 0) {
            # The worker records its own error text; surface it so the cause
            # is visible after the exchange directory is removed.
            $workerError = try {
                [string](Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop).Error
            }
            catch { '' }
            throw ("WindowsSearch user operation task failed with result $($taskInfo.LastTaskResult)" +
                $(if (-not [string]::IsNullOrWhiteSpace($workerError)) { ": $workerError" } else { '' }))
        }
        $record = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $expectedProperties = @(
            'SchemaVersion','CapturedUtc','Operation','User','Sid','SessionId',
            'RequestedWebResultsEnabled','BeforeWebResultsEnabled','WebResultsEnabled',
            'Settings','RegistryStateUnchanged','Success','Error'
        )
        $recordProperties = @($record.PSObject.Properties.Name)
        $capturedUtc = [DateTime]::MinValue
        $apiSettings = @($record.Settings)
        $webSetting = @($apiSettings | Where-Object Setting -ceq 'EnableWebResultsSetting')
        if ($recordProperties.Count -ne $expectedProperties.Count -or
            @(Compare-Object -ReferenceObject $expectedProperties -DifferenceObject $recordProperties).Count -ne 0 -or
            [int]$record.SchemaVersion -ne 1 -or [string]$record.Operation -cne $Operation -or
            [string]$record.Sid -cne $sid -or [int]$record.SessionId -ne $sessionId -or
            [string]::IsNullOrWhiteSpace([string]$record.User) -or
            -not [DateTime]::TryParse([string]$record.CapturedUtc, [ref]$capturedUtc) -or
            $record.BeforeWebResultsEnabled -isnot [bool] -or
            $record.WebResultsEnabled -isnot [bool] -or
            $apiSettings.Count -lt 1 -or
            @($apiSettings | Where-Object {
                    [string]::IsNullOrWhiteSpace([string]$_.Setting) -or
                    -not $_.PSObject.Properties['Value']
                }).Count -gt 0 -or
            @($apiSettings.Setting | Group-Object | Where-Object Count -ne 1).Count -gt 0 -or
            $webSetting.Count -ne 1 -or
            [bool]::Parse([string]$webSetting[0].Value) -ne [bool]$record.WebResultsEnabled -or
            $record.Success -isnot [bool] -or -not [bool]$record.Success -or
            ($Operation -eq 'RefreshWebResults' -and
                ($record.RequestedWebResultsEnabled -isnot [bool] -or
                 [bool]$record.RequestedWebResultsEnabled -ne [bool]$WebResultsEnabled -or
                 $record.RegistryStateUnchanged -isnot [bool] -or
                 -not [bool]$record.RegistryStateUnchanged -or
                 [bool]$record.WebResultsEnabled -ne [bool]$WebResultsEnabled))) {
            throw "WindowsSearch user operation failed validation: $($record.Error)"
        }
        $recordToReturn = $record
    }
    catch {
        $operationError = $_
    }
    finally {
        if ($taskRegistered) {
            try {
                $taskState = Get-NoIDScheduledTaskState -TaskName $taskName
                if ($taskState -in @('Running', 'Queued')) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $stopTimer = [Diagnostics.Stopwatch]::StartNew()
                    $stopLimit = [TimeSpan]::FromSeconds(10)
                    do {
                        Start-Sleep -Milliseconds 100
                        $taskState = Get-NoIDScheduledTaskState -TaskName $taskName
                    } while ($taskState -in @('Running', 'Queued') -and $stopTimer.Elapsed -lt $stopLimit)
                    if ($taskState -in @('Running', 'Queued')) {
                        throw 'WindowsSearch worker remained active after its stop deadline'
                    }
                }
                $null = Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false
                if ($null -ne (Get-NoIDScheduledTaskState -TaskName $taskName)) {
                    throw 'WindowsSearch transient task remains registered after cleanup'
                }
            }
            catch { $cleanupErrors.Add("task cleanup failed: $($_.Exception.Message)") }
        }
        if ($null -ne $hiddenWorker) {
            try { Remove-NoIDHiddenWorkerLauncher -Launcher $hiddenWorker -Confirm:$false }
            catch { $cleanupErrors.Add("hidden launcher cleanup failed: $($_.Exception.Message)") }
        }
        if ($exchangeCreated) {
            try {
                Remove-PrivacyWorkerExchangeDirectory -Path $exchangeDirectory -ResultPath $resultPath -Confirm:$false
                if ([IO.Directory]::Exists($exchangeDirectory)) {
                    throw 'WindowsSearch exchange directory remains after cleanup'
                }
            }
            catch { $cleanupErrors.Add("exchange cleanup failed: $($_.Exception.Message)") }
        }
    }

    if ($cleanupErrors.Count -gt 0) {
        $prefix = if ($null -ne $operationError) {
            "WindowsSearch user operation failed: $($operationError.Exception.Message); "
        } else { '' }
        throw ($prefix + ($cleanupErrors -join '; '))
    }
    if ($null -ne $operationError) { $PSCmdlet.ThrowTerminatingError($operationError) }
    return $recordToReturn
}

function Assert-PrivacyWorkerExchangeDirectory {
    <#
    .SYNOPSIS
        Rejects a missing or link-replaced worker exchange directory before a
        privileged read of the worker result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $directory = [IO.DirectoryInfo]::new($Path)
    if (-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Worker exchange directory is missing or was replaced by a reparse point: $Path"
    }
}

function Remove-PrivacyWorkerExchangeDirectory {
    <#
    .SYNOPSIS
        Removes a user-worker exchange directory without following links.

    .DESCRIPTION
        The interactive user can modify the exchange directory. Windows
        PowerShell 5.1 can follow a junction during a recursive delete and
        would then remove foreign content with this process's privileges.
        Only the worker's result file and its temporary file are removed,
        followed by the then empty directory. A directory that was replaced by
        a link is removed as a link only, and the cleanup reports it.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ResultPath
    )

    $directory = [IO.DirectoryInfo]::new($Path)
    if (-not $directory.Exists) { return }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Remove worker exchange directory')) { return }
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        # Deleting a directory reparse point removes only the link.
        [IO.Directory]::Delete($Path, $false)
        throw "Worker exchange directory was replaced by a reparse point: $Path"
    }
    foreach ($knownFile in @($ResultPath, ($ResultPath + '.tmp'))) {
        # File.Delete removes a file link itself, never its target.
        if ([IO.File]::Exists($knownFile)) { [IO.File]::Delete($knownFile) }
    }
    # Fails on any unexpected content instead of deleting it.
    [IO.Directory]::Delete($Path, $false)
}
