function Test-PrivacyCompliance {
    <#
    .SYNOPSIS
        Exactly verifies every applicable target selected for the Privacy run.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Snapshot,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BloatwareActionResult
    )

    $details = [System.Collections.Generic.List[object]]::new()
    try {
        $unsealedPlan = $null
        $registryTargets = if ($Snapshot) {
            $null = Assert-PrivacyRegistrySnapshot -Snapshot $Snapshot
            if ([int]$Snapshot.SchemaVersion -ne 7) { throw 'Privacy verification requires a schema-7 Apply snapshot' }
            @($Snapshot.Entries | ForEach-Object {
                    [PSCustomObject]@{
                        Path = [string]$_.Path; Name = [string]$_.Name
                        Type = [string]$_.ApplyType; Value = $_.ApplyValue
                    }
                })
        }
        else {
            $unsealedPlan = Get-PrivacyTargetPlan -Config $Config
            @($unsealedPlan.ApplicableTargets)
        }
        foreach ($target in $registryTargets) {
            $status = 'FAIL'; $actual = $null; $actualType = $null; $errorText = $null
            try {
                if (-not (Test-Path -LiteralPath $target.Path -PathType Container)) { throw 'registry key is missing' }
                $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                if ($key.GetValueNames() -notcontains [string]$target.Name) { throw 'registry value is missing' }
                $actualType = $key.GetValueKind([string]$target.Name).ToString()
                $actual = $key.GetValue([string]$target.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $expectedJson = ConvertTo-Json -InputObject $target.Value -Compress -Depth 10
                $actualJson = ConvertTo-Json -InputObject $actual -Compress -Depth 10
                if ($actualType -ne [string]$target.Type -or $actualJson -cne $expectedJson) {
                    throw "expected $($target.Type)/$expectedJson; actual $actualType/$actualJson"
                }
                $status = 'PASS'
            }
            catch { $errorText = $_.Exception.Message }
            $details.Add([PSCustomObject]@{
                    Kind='Registry'; Target="$($target.Path)::$($target.Name)"; Status=$status
                    Expected=$target.Value; ExpectedType=$target.Type; Actual=$actual; ActualType=$actualType; Error=$errorText
                })
        }

        # BingSearchEnabled is one declared setting, so keep one report row and
        # bind its raw registry verification to Microsoft's effective
        # WindowsSearch API state. This prevents a green registry-only result
        # while the live Search UI still exposes web/Bing suggestions.
        $webSearchDetails = @($details | Where-Object {
                [string]$_.Target -match '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Search::BingSearchEnabled$'
            })
        if ($webSearchDetails.Count -ne 1) {
            throw 'Privacy verification requires exactly one BingSearchEnabled report target'
        }
        $webSearchDetail = $webSearchDetails[0]
        try {
            $searchUser = Get-PrivacyUserContext -Refresh
            if ($Snapshot -and [string]$searchUser.Sid -cne [string]$Snapshot.InteractiveUserSid) {
                throw 'interactive user differs from the sealed Privacy Search target'
            }
            $searchState = Invoke-PrivacyWindowsSearchUserState -User $searchUser -Operation Query
            $registryActual = $webSearchDetail.Actual
            $registryExpected = $webSearchDetail.Expected
            $webSearchDetail.Kind = 'Registry+WindowsSearchAPI'
            $webSearchDetail.ExpectedType = 'DWord + Boolean effective state'
            $webSearchDetail.ActualType = "$($webSearchDetail.ActualType) + Boolean effective state"
            $webSearchDetail.Expected = "Registry=$registryExpected; EnableWebResultsSetting=False"
            $webSearchDetail.Actual = "Registry=$registryActual; EnableWebResultsSetting=$([bool]$searchState.WebResultsEnabled)"
            if ([bool]$searchState.WebResultsEnabled) {
                throw 'effective WindowsSearch web results remain enabled'
            }
        }
        catch {
            $existingError = [string]$webSearchDetail.Error
            $webSearchDetail.Status = 'FAIL'
            $searchErrors = @($existingError, $_.Exception.Message) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -Unique
            $webSearchDetail.Error = $searchErrors -join '; '
        }
        $notCheckedRegistryTargets = if ($Snapshot) { @($Snapshot.NotCheckedRegistryTargets) } else { @($unsealedPlan.NotCheckedTargets) }
        $notApplicableRegistryTargets = if ($Snapshot) { @($Snapshot.NotApplicableRegistryTargets) } else { @($unsealedPlan.NotApplicableTargets) }
        foreach ($target in $notCheckedRegistryTargets) {
                $details.Add([PSCustomObject]@{
                        Kind = 'Registry'; Target = "$($target.Path)::$($target.Name)"
                        Status = 'NotChecked'; Expected = $target.ApplyValue
                        ExpectedType = $target.ApplyType; Actual = 'Not written'
                        ActualType = $null; Error = [string]$target.Reason
                    })
        }
        foreach ($target in $notApplicableRegistryTargets) {
                $details.Add([PSCustomObject]@{
                        Kind = 'Registry'; Target = "$($target.Path)::$($target.Name)"
                        Status = 'NotApplicable'; Expected = $target.ApplyValue
                        ExpectedType = $target.ApplyType; Actual = 'Not written'
                        ActualType = $null; Error = [string]$target.Reason
                    })
        }

        $configuredServiceNames = @($Config.Services | ForEach-Object { [string]$_.Name })
        $configuredTaskPaths = @($Config.ScheduledTasks | ForEach-Object { [string]$_ })
        if ($Snapshot) {
            if ((@($Snapshot.DeclaredServiceNames | Sort-Object) -join ([char]31)) -cne
                (@($configuredServiceNames | Sort-Object) -join ([char]31)) -or
                (@($Snapshot.DeclaredScheduledTaskPaths | Sort-Object) -join ([char]31)) -cne
                (@($configuredTaskPaths | Sort-Object) -join ([char]31))) {
                throw 'Privacy verification config service/task scope differs from the sealed snapshot'
            }
        }

        $installedServices = if ($configuredServiceNames.Count -gt 0) { @(Get-Service -ErrorAction Stop) } else { @() }
        foreach ($definition in @($Config.Services)) {
            $serviceMatches = @($installedServices | Where-Object { [string]$_.Name -eq [string]$definition.Name })
            if ($serviceMatches.Count -gt 1) { throw "Privacy service identity is ambiguous: $($definition.Name)" }
            $sealedApplicable = -not $Snapshot -or [string]$definition.Name -cin @($Snapshot.ApplicableServiceNames)
            if ($Snapshot -and $sealedApplicable -and $serviceMatches.Count -ne 1) {
                $details.Add([PSCustomObject]@{ Kind='Service'; Target=$definition.Name; Status='FAIL'; Expected='Disabled/Stopped (sealed applicable)'; Actual='Missing'; Error='sealed applicable service disappeared' })
            }
            elseif ($Snapshot -and -not $sealedApplicable -and $serviceMatches.Count -ne 0) {
                $details.Add([PSCustomObject]@{ Kind='Service'; Target=$definition.Name; Status='FAIL'; Expected='Absent (sealed NotApplicable)'; Actual='Present'; Error='service appeared after applicability was sealed' })
            }
            elseif ($serviceMatches.Count -eq 0) {
                $details.Add([PSCustomObject]@{ Kind='Service'; Target=$definition.Name; Status='NotApplicable'; Expected='Disabled'; Actual='Not installed'; Error=$null })
            }
            else {
                $service = $serviceMatches[0]
                $ok = ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped')
                $details.Add([PSCustomObject]@{ Kind='Service'; Target=$definition.Name; Status=$(if($ok){'PASS'}else{'FAIL'}); Expected='Disabled/Stopped'; Actual="$($service.StartType)/$($service.Status)"; Error=$(if($ok){$null}else{'service is not disabled and stopped'}) })
            }
        }

        $installedTasks = if ($configuredTaskPaths.Count -gt 0) { @(Get-ScheduledTask -ErrorAction Stop) } else { @() }
        foreach ($taskPath in @($Config.ScheduledTasks)) {
            $taskName = Split-Path $taskPath -Leaf; $taskFolder = Split-Path $taskPath -Parent
            $taskFolderName = $taskFolder.Trim([char]'\')
            $taskFolder = if ([string]::IsNullOrWhiteSpace($taskFolderName)) { '\' } else { '\' + $taskFolderName + '\' }
            $taskMatches = @($installedTasks | Where-Object { [string]$_.TaskPath -eq $taskFolder -and [string]$_.TaskName -eq $taskName })
            if ($taskMatches.Count -gt 1) { throw "Privacy scheduled-task identity is ambiguous: $taskPath" }
            $sealedApplicable = -not $Snapshot -or [string]$taskPath -cin @($Snapshot.ApplicableScheduledTaskPaths)
            if ($Snapshot -and $sealedApplicable -and $taskMatches.Count -ne 1) {
                $details.Add([PSCustomObject]@{ Kind='ScheduledTask'; Target=$taskPath; Status='FAIL'; Expected='Disabled (sealed applicable)'; Actual='Missing'; Error='sealed applicable task disappeared' })
            }
            elseif ($Snapshot -and -not $sealedApplicable -and $taskMatches.Count -ne 0) {
                $details.Add([PSCustomObject]@{ Kind='ScheduledTask'; Target=$taskPath; Status='FAIL'; Expected='Absent (sealed NotApplicable)'; Actual='Present'; Error='task appeared after applicability was sealed' })
            }
            elseif ($taskMatches.Count -eq 0) {
                $details.Add([PSCustomObject]@{ Kind='ScheduledTask'; Target=$taskPath; Status='NotApplicable'; Expected='Disabled'; Actual='Not installed'; Error=$null })
            }
            else {
                $task = $taskMatches[0]
                $ok = ([string]$task.State -eq 'Disabled')
                $details.Add([PSCustomObject]@{ Kind='ScheduledTask'; Target=$taskPath; Status=$(if($ok){'PASS'}else{'FAIL'}); Expected='Disabled'; Actual=[string]$task.State; Error=$(if($ok){$null}else{'task is not disabled'}) })
            }
        }

        # Tier 2 classic bloatware removal is reported here for visibility only. It is
        # a best-effort action, NEVER an exact restore, and must never be counted in
        # the BAVR DeclaredChecks/Passed/Failed/NotApplicable totals above.
        if ($BloatwareActionResult) {
            $details.Add([PSCustomObject]@{
                    Kind = 'BloatwareActions'; Target = 'Tier 2 classic app removal (current user)'
                    Status = 'Informational'
                    Expected = 'Informational only -- best-effort action, not an exact-BAVR target'
                    Actual = "Removed=$([int]$BloatwareActionResult.Removed)/$([int]$BloatwareActionResult.TargetPackages), Failed=$([int]$BloatwareActionResult.Failed), Success=$([bool]$BloatwareActionResult.Success)"
                    Error = if ([bool]$BloatwareActionResult.Success) { $null } else { 'One or more explicitly selected Tier 2 package removals failed' }
                })
        }

        $applicable = @($details | Where-Object { $_.Status -notin @('NotApplicable', 'NotChecked', 'Informational') })
        $passed = @($applicable | Where-Object { $_.Status -eq 'PASS' }).Count
        $failed = @($applicable | Where-Object { $_.Status -eq 'FAIL' }).Count
        $notApplicable = @($details | Where-Object { $_.Status -eq 'NotApplicable' }).Count
        $notChecked = @($details | Where-Object { $_.Status -eq 'NotChecked' }).Count
        $declaredChecksCount = @($details | Where-Object { $_.Status -ne 'Informational' }).Count
        $percentage = if ($applicable.Count -gt 0) { [math]::Round(($passed / $applicable.Count) * 100, 1) } else { 0 }
        foreach ($failure in @($details | Where-Object { $_.Status -eq 'FAIL' })) {
            Write-Log -Level ERROR -Message "Privacy verification failed: $($failure.Target) - $($failure.Error)" -Module 'Privacy'
        }
        return [PSCustomObject]@{
            Compliant=$failed -eq 0 -and $applicable.Count -gt 0
            DeclaredChecks=$declaredChecksCount; TotalChecks=$applicable.Count; Passed=$passed; Failed=$failed
            NotChecked=$notChecked; NotApplicable=$notApplicable; Percentage=$percentage
            FailedChecks=@($details | Where-Object { $_.Status -eq 'FAIL' }); Details=@($details)
            BloatwareActions=$BloatwareActionResult
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Privacy verification could not establish its scope: $($_.Exception.Message)" -Module 'Privacy'
        return [PSCustomObject]@{
            Compliant=$false; DeclaredChecks=1; TotalChecks=1; Passed=0; Failed=1; NotChecked=0; NotApplicable=0; Percentage=0
            FailedChecks=@($_.Exception.Message); Details=@([PSCustomObject]@{ Status='FAIL'; Error=$_.Exception.Message })
        }
    }
}
