#Requires -Version 5.1

$script:PrivacyWindowsSearchHelperPath = $PSCommandPath

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
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $keys = @((Get-Item -LiteralPath $root -ErrorAction Stop)) +
            @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop)
        foreach ($key in $keys) {
            foreach ($name in @($key.GetValueNames() | Sort-Object)) {
                $value = $key.GetValue(
                    [string]$name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $entries.Add([PSCustomObject]@{
                        Path = ([string]$key.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
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
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
        account. A transient limited scheduled task uses the already logged-on
        Explorer token without credentials, validates its SID/session, publishes
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

        [ValidateRange(5, 120)]
        [int]$TimeoutSeconds = 120
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
    if (-not (Test-Path -LiteralPath $script:PrivacyWindowsSearchHelperPath -PathType Leaf)) {
        throw "WindowsSearch helper source is unavailable: $script:PrivacyWindowsSearchHelperPath"
    }

    $identifier = [Guid]::NewGuid().ToString('N')
    $taskName = "NoID-WindowsSearch-$identifier"
    $exchangeDirectory = Join-Path $env:ProgramData $taskName
    $resultPath = Join-Path $exchangeDirectory 'result.json'
    $taskRegistered = $false
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $recordToReturn = $null
    try {
        $directory = New-Item -ItemType Directory -Path $exchangeDirectory -ErrorAction Stop
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [Security.AccessControl.PropagationFlags]::None
        foreach ($access in @(
                @{Sid='S-1-5-18';Rights=[Security.AccessControl.FileSystemRights]::FullControl}
                @{Sid='S-1-5-32-544';Rights=[Security.AccessControl.FileSystemRights]::FullControl}
                @{Sid=$sid;Rights=[Security.AccessControl.FileSystemRights]::Modify}
            )) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new([string]$access.Sid),
                [Security.AccessControl.FileSystemRights]$access.Rights,
                $inheritance,
                $propagation,
                [Security.AccessControl.AccessControlType]::Allow
            )
            $null = $security.AddAccessRule($rule)
        }
        $directory.SetAccessControl($security)

        $escapedHelper = $script:PrivacyWindowsSearchHelperPath.Replace("'", "''")
        $escapedOutput = $resultPath.Replace("'", "''")
        $webResultsLiteral = if ($WebResultsEnabled) { '$true' } else { '$false' }
        $workerCommand = "& { . '$escapedHelper'; " +
            "`$result = Invoke-PrivacyWindowsSearchWorker -Operation '$Operation' " +
            "-ExpectedSid '$sid' -ExpectedSessionId $sessionId " +
            "-WebResultsEnabled:$webResultsLiteral -OutputPath '$escapedOutput'; " +
            "if (-not `$result.Success) { exit 1 } }"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $action = New-ScheduledTaskAction -Execute $powershell `
            -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
        $principal = New-ScheduledTaskPrincipal -UserId ([string]$User.Account) `
            -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds ([int]$TimeoutSeconds + 5))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if ([string]$task.State -ne 'Running' -and
                (Test-Path -LiteralPath $resultPath -PathType Leaf)) { break }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            throw "WindowsSearch user operation timed out; task result=$($taskInfo.LastTaskResult)"
        }
        $resultFile = Get-Item -LiteralPath $resultPath -Force -ErrorAction Stop
        if ([bool]($resultFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $resultFile.Length -lt 2 -or $resultFile.Length -gt 262144) {
            throw 'WindowsSearch worker result is not a valid regular bounded file'
        }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ([int64]$taskInfo.LastTaskResult -ne 0) {
            throw "WindowsSearch user operation task failed with result $($taskInfo.LastTaskResult)"
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
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                if ([string]$task.State -eq 'Running') {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
                    do {
                        Start-Sleep -Milliseconds 100
                        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    } while ([string]$task.State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline)
                    if ([string]$task.State -eq 'Running') {
                        throw 'WindowsSearch worker remained active after its stop deadline'
                    }
                }
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    throw 'WindowsSearch transient task remains registered after cleanup'
                }
            }
            catch { $cleanupErrors.Add("task cleanup failed: $($_.Exception.Message)") }
        }
        try {
            if (Test-Path -LiteralPath $exchangeDirectory) {
                Remove-Item -LiteralPath $exchangeDirectory -Recurse -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $exchangeDirectory) {
                throw 'WindowsSearch exchange directory remains after cleanup'
            }
        }
        catch { $cleanupErrors.Add("exchange cleanup failed: $($_.Exception.Message)") }
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
