#Requires -Version 5.1

$script:PrivacyUserAppxHelperPath = $PSCommandPath

function Invoke-PrivacyUserAppxRemovalWorker {
    <#
    .SYNOPSIS
        Removes sealed AppX parent identities inside the original Explorer token.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')]
        [string]$ExpectedSid,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ExpectedSessionId,

        [Parameter(Mandatory = $true)]
        [string]$EncodedRequest,

        [Parameter(Mandatory = $true)]
        [ValidateRange(20, 590)]
        [int]$OperationTimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $record = [ordered]@{
        SchemaVersion = 1
        CapturedUtc = [DateTime]::UtcNow.ToString('o')
        User = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        SessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        TargetPackages = 0
        Removed = 0
        Failed = 0
        Entries = @()
        Success = $false
        Error = $null
    }
    $entryResults = [Collections.Generic.List[object]]::new()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Privacy AppX worker unexpectedly has an administrator token'
        }
        if ([string]$record.Sid -cne $ExpectedSid -or [int]$record.SessionId -ne $ExpectedSessionId) {
            throw "Privacy AppX worker identity mismatch: $($record.Sid)/$($record.SessionId)"
        }
        $requestJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedRequest))
        $request = $requestJson | ConvertFrom-Json -ErrorAction Stop
        $requestProperties = @($request.PSObject.Properties.Name)
        if ($requestProperties.Count -ne 3 -or
            @(Compare-Object -ReferenceObject @('SchemaVersion','UserSid','Entries') -DifferenceObject $requestProperties).Count -ne 0 -or
            [int]$request.SchemaVersion -ne 1 -or [string]$request.UserSid -cne $ExpectedSid) {
            throw 'Privacy AppX worker request schema or user binding is invalid'
        }
        $entries = @($request.Entries)
        if ($entries.Count -lt 1 -or $entries.Count -gt 100) {
            throw 'Privacy AppX worker request has an invalid target count'
        }
        $seenIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $entries) {
            $properties = @($entry.PSObject.Properties.Name)
            $appName = [string]$entry.AppName
            $packageFullName = [string]$entry.PackageFullName
            if ($properties.Count -ne 2 -or
                @(Compare-Object -ReferenceObject @('AppName','PackageFullName') -DifferenceObject $properties).Count -ne 0 -or
                $appName -notmatch '^[A-Za-z0-9][A-Za-z0-9.]{2,127}$' -or
                $packageFullName -notmatch '^[A-Za-z0-9][A-Za-z0-9._~-]{5,255}$' -or
                -not $seenIdentities.Add("$appName`0$packageFullName")) {
                throw 'Privacy AppX worker request contains a malformed or duplicate package identity'
            }
        }
        $record.TargetPackages = $entries.Count
        $operationDeadline = [DateTime]::UtcNow.AddSeconds($OperationTimeoutSeconds)

        # Validate every app's complete removable parent set before the first
        # mutation. A new Bundle/version between Backup and worker execution is
        # drift, never an invitation to remove an unsealed package.
        foreach ($group in @($entries | Group-Object AppName)) {
            $packages = @(Get-AppxPackage -Name ([string]$group.Name) `
                    -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
            $bundles = @($packages | Where-Object {
                    $_.PSObject.Properties['IsBundle'] -and [bool]$_.IsBundle
                })
            $removable = if ($bundles.Count -gt 0) { @($bundles) } else { @($packages) }
            $expectedNames = @($group.Group | ForEach-Object { [string]$_.PackageFullName } | Sort-Object)
            $actualNames = @($removable | ForEach-Object { [string]$_.PackageFullName } | Sort-Object)
            if ($expectedNames.Count -ne $actualNames.Count -or
                @(Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames -CaseSensitive).Count -ne 0) {
                throw "Privacy AppX identity drifted before current-user removal: $($group.Name)"
            }
        }

        foreach ($group in @($entries | Group-Object AppName)) {
            $groupEntries = @($group.Group)
            try {
                if ([DateTime]::UtcNow -ge $operationDeadline) {
                    throw 'Privacy AppX worker reached its overall operation deadline'
                }
                foreach ($entry in $groupEntries) {
                    $fullName = [string]$entry.PackageFullName
                    $stillRegistered = @(Get-AppxPackage -Name ([string]$group.Name) `
                            -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop | Where-Object {
                            [string]$_.PackageFullName -ceq $fullName
                        })
                    if ($stillRegistered.Count -gt 1) {
                        throw "Privacy AppX identity became ambiguous during removal: $fullName"
                    }
                    if ($stillRegistered.Count -eq 1) {
                        Remove-AppxPackage -Package $fullName -ErrorAction Stop
                    }
                }
                do {
                    $remaining = @(Get-AppxPackage -Name ([string]$group.Name) `
                            -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
                    if ($remaining.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 250
                } while ([DateTime]::UtcNow -lt $operationDeadline)
                if ($remaining.Count -ne 0) {
                    throw "Privacy AppX package remained registered after removal deadline: $($group.Name)"
                }
                foreach ($entry in $groupEntries) {
                    $entryResults.Add([pscustomobject]@{
                            AppName=[string]$entry.AppName;PackageFullName=[string]$entry.PackageFullName
                            Removed=$true;Error=''
                        })
                    $record.Removed++
                }
            }
            catch {
                foreach ($entry in $groupEntries) {
                    $entryResults.Add([pscustomobject]@{
                            AppName=[string]$entry.AppName;PackageFullName=[string]$entry.PackageFullName
                            Removed=$false;Error=$_.Exception.Message
                        })
                    $record.Failed++
                }
            }
        }
        $record.Entries = @($entryResults)
        $record.Success = ($record.Failed -eq 0 -and $record.Removed -eq $record.TargetPackages)
        if (-not $record.Success) { $record.Error = 'One or more current-user AppX removals failed' }
    }
    catch {
        $record.Error = $_.Exception.Message
        if ([int]$record.TargetPackages -gt 0 -and [int]$record.Failed -eq 0) {
            $record.Failed = [int]$record.TargetPackages
        }
        $record.Entries = @($entryResults)
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Privacy AppX worker output directory is unavailable: $parent"
    }
    $temporaryOutputPath = $OutputPath + '.tmp'
    [IO.File]::WriteAllText(
        $temporaryOutputPath,
        ($record | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryOutputPath -Destination $OutputPath -Force -ErrorAction Stop
    return [pscustomobject]$record
}

function Invoke-PrivacyUserAppxRemoval {
    <#
    .SYNOPSIS
        Runs exact AppX removal in the already logged-on Explorer token.

    .DESCRIPTION
        Remove-AppxPackage -User can report success while leaving the logged-on
        target in Installed(pending removal). A transient limited Task Scheduler
        worker uses the original interactive token without credentials. The
        elevated caller independently verifies both package visibility and the
        target user's deployment state, then removes the task and exchange data.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [ValidateRange(30, 600)][int]$TimeoutSeconds = 300
    )

    foreach ($property in @('Account','Sid','SessionId')) {
        if (-not $User.PSObject.Properties[$property]) { throw "Privacy user context is missing '$property'" }
    }
    $entryCount = @($Entries).Count
    $sid = [string]$User.Sid
    $sessionId = [int]$User.SessionId
    if ([string]::IsNullOrWhiteSpace([string]$User.Account) -or
        $sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or $sessionId -lt 1 -or $entryCount -lt 1) {
        throw 'Privacy AppX user context or target set is invalid'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Privacy AppX user-token orchestration requires an elevated administrator token'
    }
    $currentUser = Get-PrivacyUserContext -Refresh
    if ([string]$currentUser.Account -cne [string]$User.Account -or
        [string]$currentUser.Sid -cne $sid -or [int]$currentUser.SessionId -ne $sessionId) {
        throw 'Interactive Privacy user identity changed before AppX removal'
    }
    if (-not (Test-Path -LiteralPath $script:PrivacyUserAppxHelperPath -PathType Leaf)) {
        throw "Privacy AppX helper source is unavailable: $script:PrivacyUserAppxHelperPath"
    }

    $firewallFamilies = @(Get-PrivacyAppxOrdinalUniqueStrings -Values @($Entries | ForEach-Object {
            if (-not $_.PSObject.Properties['PackageFamilyName']) {
                throw 'Privacy AppX target is missing its sealed package-family identity'
            }
            [string]$_.PackageFamilyName
        }))
    if ($firewallFamilies.Count -lt 1 -or
        @($firewallFamilies | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        throw 'Privacy AppX target set has an invalid package-family inventory'
    }
    $firewallPrestate = Get-PrivacyAppxFirewallState -PackageFamilyNames $firewallFamilies
    $requestEntries = @($Entries | ForEach-Object {
        [ordered]@{AppName=[string]$_.AppName;PackageFullName=[string]$_.PackageFullName}
    })
    $request = [ordered]@{SchemaVersion=1;UserSid=$sid;Entries=$requestEntries}
    $requestJson = ConvertTo-Json -InputObject $request -Depth 6 -Compress
    $encodedRequest = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($requestJson))
    $identifier = [Guid]::NewGuid().ToString('N')
    $taskName = "NoID-PrivacyAppx-$identifier"
    $exchangeDirectory = Join-Path $env:ProgramData $taskName
    $resultPath = Join-Path $exchangeDirectory 'result.json'
    $taskRegistered = $false
    $workerMayHaveMutated = $false
    $workerQuiesced = $true
    $operationError = $null
    $preservationError = $null
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

        $escapedHelper = $script:PrivacyUserAppxHelperPath.Replace("'", "''")
        $escapedOutput = $resultPath.Replace("'", "''")
        $workerTimeoutSeconds = [int]$TimeoutSeconds - 10
        $workerCommand = "& { . '$escapedHelper'; " +
            "`$result = Invoke-PrivacyUserAppxRemovalWorker -ExpectedSid '$sid' " +
            "-ExpectedSessionId $sessionId -EncodedRequest '$encodedRequest' " +
            "-OperationTimeoutSeconds $workerTimeoutSeconds -OutputPath '$escapedOutput'; " +
            "if (-not `$result.Success) { exit 1 } }"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))
        $powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $action = New-ScheduledTaskAction -Execute $powerShell `
            -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId ([string]$User.Account) `
            -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds ([int]$TimeoutSeconds + 5))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $taskPrincipal `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
        # Once Start is attempted, assume the worker may have mutated AppX and
        # collateral firewall state even when the caller later observes an
        # exception, timeout, partial result, or invalid postcondition.
        $workerMayHaveMutated = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $taskState = (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State
            if ($taskState -ne 'Running' -and (Test-Path -LiteralPath $resultPath -PathType Leaf)) { break }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            throw "Privacy AppX user operation timed out; task result=$($taskInfo.LastTaskResult)"
        }
        $resultFile = Get-Item -LiteralPath $resultPath -Force -ErrorAction Stop
        if ([bool]($resultFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $resultFile.Length -lt 2 -or $resultFile.Length -gt 262144) {
            throw 'Privacy AppX worker result is not a valid regular bounded file'
        }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ([int64]$taskInfo.LastTaskResult -ne 0) {
            throw "Privacy AppX user operation task failed with result $($taskInfo.LastTaskResult)"
        }
        $record = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $recordProperties = @($record.PSObject.Properties.Name)
        $expectedRecordProperties = @(
            'SchemaVersion','CapturedUtc','User','Sid','SessionId','TargetPackages',
            'Removed','Failed','Entries','Success','Error'
        )
        $outputEntries = @($record.Entries)
        $expectedIdentities = @($requestEntries | ForEach-Object { "$($_.AppName)`0$($_.PackageFullName)" } | Sort-Object)
        $actualIdentities = @($outputEntries | ForEach-Object {
                $properties = @($_.PSObject.Properties.Name)
                if ($properties.Count -ne 4 -or
                    @(Compare-Object -ReferenceObject @('AppName','PackageFullName','Removed','Error') -DifferenceObject $properties).Count -ne 0 -or
                    $_.Removed -isnot [bool]) {
                    throw 'Privacy AppX worker entry schema is invalid'
                }
                "$([string]$_.AppName)`0$([string]$_.PackageFullName)"
            } | Sort-Object)
        $capturedUtc = [DateTime]::MinValue
        if ($recordProperties.Count -ne $expectedRecordProperties.Count -or
            @(Compare-Object -ReferenceObject $expectedRecordProperties -DifferenceObject $recordProperties).Count -ne 0 -or
            [int]$record.SchemaVersion -ne 1 -or [string]$record.Sid -cne $sid -or
            [int]$record.SessionId -ne $sessionId -or [string]::IsNullOrWhiteSpace([string]$record.User) -or
            -not [DateTime]::TryParse([string]$record.CapturedUtc, [ref]$capturedUtc) -or
            [int]$record.TargetPackages -ne $entryCount -or $outputEntries.Count -ne $entryCount -or
            $expectedIdentities.Count -ne $actualIdentities.Count -or
            @(Compare-Object -ReferenceObject $expectedIdentities -DifferenceObject $actualIdentities -CaseSensitive).Count -ne 0 -or
            [int]$record.Removed -ne $entryCount -or [int]$record.Failed -ne 0 -or
            @($outputEntries | Where-Object { -not [bool]$_.Removed }).Count -ne 0 -or
            $record.Success -isnot [bool] -or -not [bool]$record.Success) {
            throw "Privacy AppX user operation failed validation: $($record.Error)"
        }

        # The limited worker result is informative; the elevated caller owns
        # the authoritative postcondition and rejects pending-removal states.
        foreach ($group in @($Entries | Group-Object AppName)) {
            $visible = @(Get-AppxPackage -User $sid -Name ([string]$group.Name) `
                    -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
            $allUsers = @(Get-AppxPackage -AllUsers -Name ([string]$group.Name) `
                    -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
            $targetStates = @($allUsers | ForEach-Object {
                    $_.PackageUserInformation | Where-Object { $_.UserSecurityId.Sid -eq $sid }
                })
            if ($visible.Count -ne 0 -or $targetStates.Count -ne 0) {
                throw "Privacy AppX removal did not reach an absent target-user state: $($group.Name)"
            }
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
                        throw 'Privacy AppX worker remained active after its stop deadline'
                    }
                }
            }
            catch {
                $workerQuiesced = $false
                $cleanupErrors.Add("worker quiesce failed: $($_.Exception.Message)")
            }
            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            }
            catch { $cleanupErrors.Add("task unregister failed: $($_.Exception.Message)") }
        }
        # Windows can delete capability rules belonging to a different local
        # user even when a multi-app worker later fails. Quiesce the worker
        # first, then preserve every sealed non-target-user rule on all paths.
        if ($workerMayHaveMutated) {
            if (-not $workerQuiesced) {
                $preservationError = 'cross-user firewall preservation was unsafe because the worker could not be quiesced'
            }
            else {
                try {
                    $firewallPreservation = Restore-PrivacyAppxFirewallState -State $firewallPrestate `
                        -Scope OtherUsers -TargetUserSid $sid
                    if (-not [bool]$firewallPreservation.Success) {
                        throw 'Privacy AppX cross-user firewall preservation did not report success'
                    }
                }
                catch { $preservationError = $_.Exception.Message }
            }
        }
        try {
            if (Test-Path -LiteralPath $exchangeDirectory) {
                Remove-Item -LiteralPath $exchangeDirectory -Recurse -Force -ErrorAction Stop
            }
        }
        catch { $cleanupErrors.Add("exchange cleanup failed: $($_.Exception.Message)") }
    }

    $followUpFailures = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace([string]$preservationError)) {
        $followUpFailures.Add("firewall preservation failed: $preservationError")
    }
    foreach ($cleanupError in @($cleanupErrors)) { $followUpFailures.Add($cleanupError) }
    if ($followUpFailures.Count -gt 0) {
        $operationPrefix = if ($null -ne $operationError) {
            "Privacy AppX user operation failed: $($operationError.Exception.Message); "
        }
        else { '' }
        throw ($operationPrefix + ($followUpFailures -join '; '))
    }
    if ($null -ne $operationError) { $PSCmdlet.ThrowTerminatingError($operationError) }
    return $recordToReturn
}
