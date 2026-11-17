#Requires -Version 5.1

. (Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'Core\AsrPolicyRuntime.ps1')

function Test-ASRCombinedSessionPrestate {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $ASRSnapshot,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityBaselineRegistryBackupPath
    )

    if (-not (Test-Path -LiteralPath $SecurityBaselineRegistryBackupPath -PathType Leaf)) {
        throw "SecurityBaseline registry prestate not found: $SecurityBaselineRegistryBackupPath"
    }
    $baseline = Get-Content -LiteralPath $SecurityBaselineRegistryBackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $baselineSchema = [int]$baseline.SchemaVersion
    if ($baselineSchema -notin @(3, 4) -or
        -not $baseline.PSObject.Properties['Computer'] -or
        -not $baseline.PSObject.Properties['ComputerClearKeys']) {
        throw 'SecurityBaseline registry prestate has an unsupported schema'
    }

    $policyKeyName = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $directStates = @($baseline.Computer | Where-Object {
            $normalizedKeyName = ([string]$_.KeyName) -replace '^\[', '' -replace '\]$', ''
            $normalizedKeyName.Equals($policyKeyName, [StringComparison]::OrdinalIgnoreCase)
        })
    $clearStates = @($baseline.ComputerClearKeys | Where-Object {
            $normalizedKeyName = ([string]$_.KeyName) -replace '^\[', '' -replace '\]$', ''
            $normalizedKeyName.Equals($policyKeyName, [StringComparison]::OrdinalIgnoreCase)
        })
    if ($clearStates.Count -gt 1) {
        throw 'SecurityBaseline registry prestate has duplicate ASR clear-key state'
    }

    function Convert-ASRBaselineRegistryType {
        param([Parameter(Mandatory = $true)][string]$Type)
        switch ($Type) {
            'REG_DWORD'     { 'DWord' }
            'REG_QWORD'     { 'QWord' }
            'REG_SZ'        { 'String' }
            'REG_EXPAND_SZ' { 'ExpandString' }
            'REG_BINARY'    { 'Binary' }
            'REG_MULTI_SZ'  { 'MultiString' }
            default { throw "Unsupported SecurityBaseline ASR registry type: $Type" }
        }
    }

    $baselineValues = @{}
    $keyExistence = [System.Collections.Generic.List[bool]]::new()
    $completeKeyState = $clearStates.Count -eq 1
    if ($completeKeyState) {
        $clearState = $clearStates[0]
        if (-not $clearState.PSObject.Properties['KeyExisted'] -or
            -not $clearState.PSObject.Properties['Values']) {
            throw 'SecurityBaseline ASR clear-key prestate is incomplete'
        }
        $keyExistence.Add([bool]$clearState.KeyExisted)
        foreach ($valueState in @($clearState.Values)) {
            $name = [string]$valueState.Name
            $identity = $name.ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($name) -or $baselineValues.ContainsKey($identity)) {
                throw "SecurityBaseline ASR clear-key prestate has an invalid or duplicate value: $name"
            }
            $baselineValues[$identity] = [PSCustomObject]@{
                Exists       = $true
                OriginalName = $name
                Type         = Convert-ASRBaselineRegistryType -Type ([string]$valueState.Type)
                Value        = $valueState.Value
            }
        }
    }

    foreach ($state in $directStates) {
        if (-not $state.PSObject.Properties['ValueName'] -or
            -not $state.PSObject.Properties['KeyExisted'] -or
            -not $state.PSObject.Properties['Exists']) {
            throw 'SecurityBaseline ASR value prestate is incomplete'
        }
        $keyExistence.Add([bool]$state.KeyExisted)
        if ($completeKeyState) { continue }
        $name = [string]$state.ValueName
        $identity = $name.ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($name) -or $baselineValues.ContainsKey($identity)) {
            throw "SecurityBaseline ASR prestate has an invalid or duplicate target: $name"
        }
        $exists = [bool]$state.Exists
        $originalName = if ($exists -and $baselineSchema -ge 4) {
            [string]$state.OriginalValueName
        }
        elseif ($exists) {
            $name
        }
        else {
            $null
        }
        if ($exists -and
            ([string]::IsNullOrWhiteSpace($originalName) -or
             -not $originalName.Equals($name, [StringComparison]::OrdinalIgnoreCase))) {
            throw "SecurityBaseline ASR original value-name identity is invalid: $name"
        }
        $baselineValues[$identity] = [PSCustomObject]@{
            Exists       = $exists
            OriginalName = $originalName
            Type         = if ($exists) {
                Convert-ASRBaselineRegistryType -Type ([string]$state.Type)
            }
            else { $null }
            Value        = if ($exists) { $state.OriginalValue } else { $null }
        }
    }

    $baselineOwnedTargets = 0
    $expectedTargets = @()
    foreach ($target in @($ASRSnapshot.Targets)) {
        $id = [string]$target.GUID
        $identity = $id.ToLowerInvariant()
        $baselineOwned = $completeKeyState -or $baselineValues.ContainsKey($identity)
        $state = if ($completeKeyState) {
            $baselineOwnedTargets++
            if ($baselineValues.ContainsKey($identity)) {
                $baselineValues[$identity]
            }
            else {
                [PSCustomObject]@{ Exists=$false; OriginalName=$null; Type=$null; Value=$null }
            }
        }
        elseif ($baselineValues.ContainsKey($identity)) {
            $baselineOwnedTargets++
            $baselineValues[$identity]
        }
        else {
            $target.PolicyValue
        }
        $expectedTargets += [PSCustomObject]@{
            GUID          = $id
            State         = $state
            BaselineOwned = [bool]$baselineOwned
            Target        = $target
        }
    }
    if ($baselineOwnedTargets -eq 0 -or $keyExistence.Count -eq 0) {
        throw 'SecurityBaseline registry prestate contains no ASR target overlap'
    }
    $distinctKeyExistence = @($keyExistence | Select-Object -Unique)
    if ($distinctKeyExistence.Count -ne 1) {
        throw 'SecurityBaseline ASR key-existence prestate is inconsistent'
    }
    $expectedKeyExists = [bool]$distinctKeyExistence[0]
    if (-not $expectedKeyExists -and
        @($expectedTargets | Where-Object { [bool]$_.State.Exists }).Count -gt 0) {
        throw 'Combined ASR session prestate records values under an absent policy key'
    }

    $policyPath = [string]$ASRSnapshot.PolicyPath
    $liveKeyExists = Test-NoIDRegistryKey -LiteralPath $policyPath
    if ($liveKeyExists -ne $expectedKeyExists) { return $false }

    if ($liveKeyExists) {
        $policyKey = Get-Item -LiteralPath $policyPath -ErrorAction Stop
        foreach ($expected in $expectedTargets) {
            $id = [string]$expected.GUID
            $state = $expected.State
            $expectedName = if ([bool]$state.Exists) { [string]$state.OriginalName } else { $id }
            $matchingNames = @($policyKey.GetValueNames() | Where-Object {
                    ([string]$_).Equals($expectedName, [StringComparison]::OrdinalIgnoreCase)
                })
            $exists = $matchingNames.Count -eq 1
            if ($exists -ne [bool]$state.Exists) { return $false }
            if (-not $exists) { continue }
            if ([string]$matchingNames[0] -cne $expectedName) { return $false }
            $type = $policyKey.GetValueKind([string]$matchingNames[0]).ToString()
            $value = $policyKey.GetValue(
                [string]$matchingNames[0], $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            $actualJson = [PSCustomObject]@{ Value=$value } | ConvertTo-Json -Compress -Depth 10
            $expectedJson = [PSCustomObject]@{ Value=$state.Value } | ConvertTo-Json -Compress -Depth 10
            if ($type -cne [string]$state.Type -or $actualJson -cne $expectedJson) {
                return $false
            }
        }
    }

    # Baseline-owned rules expose only the later baseline layer through
    # Get-MpPreference, so their earlier effective state cannot be inferred
    # from the ASR snapshot. Every non-overlapping target remains directly
    # observable and must still match its exact original effective state.
    $current = (ConvertFrom-ASRPreference -Preference (
            Get-MpPreference -ErrorAction Stop
        )).Map
    foreach ($expected in @($expectedTargets | Where-Object { -not [bool]$_.BaselineOwned })) {
        $id = [string]$expected.GUID
        $target = $expected.Target
        $exists = $current.ContainsKey($id)
        if ($exists -ne [bool]$target.OriginalExists -or
            ($exists -and [int]$current[$id] -ne [int]$target.OriginalAction)) {
            return $false
        }
    }
    return $true
}

function Restore-ASRState {
    <#
    .SYNOPSIS
        Restore only the ASR targets owned by one sealed module invocation,
        preserving unrelated Defender rules and every later foreign change.

    .DESCRIPTION
        A target whose owned policy value another tool or person changed after
        Apply keeps its current value and is reported; every other target
        returns to its exact prestate. With Microsoft Defender stopped (another
        antivirus owns the PC), the owned policy values are still restored and
        Defender applies them when it runs again.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityBaselineRegistryBackupPath
    )

    $result = [PSCustomObject]@{
        Success=$false
        Restored=0
        AlreadyAtCombinedSessionPrestate=$false
        Errors=@()
        Warnings=@()
        KeptTargets=@()
        RetainedKeys=@()
    }
    if (-not $PSCmdlet.ShouldProcess($BackupPath, 'Restore exact target-scoped ASR prestate')) {
        $result.Errors += 'ASR restore was not confirmed'
        return $result
    }

    try {
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-ASRSnapshot -Snapshot $snapshot
        Restore-NoIDPendingAsrRuntime -Confirm:$false
        $schemaVersion = [int]$snapshot.SchemaVersion
        $absentAncestorKeys = if ($schemaVersion -ge 4) { @($snapshot.AbsentAncestorKeys) } else { @() }

        # A SecurityBaseline restore in the same session may already have put
        # every target back. That check reads Defender itself; when it cannot
        # (Defender stopped) or does not match, the full restore below runs.
        if ($schemaVersion -eq 5 -and
            -not [string]::IsNullOrWhiteSpace($SecurityBaselineRegistryBackupPath)) {
            $atCombinedPrestate = $false
            try {
                $atCombinedPrestate = Test-ASRCombinedSessionPrestate `
                    -ASRSnapshot $snapshot `
                    -SecurityBaselineRegistryBackupPath $SecurityBaselineRegistryBackupPath
            }
            catch {
                $atCombinedPrestate = $false
            }
            if ($atCombinedPrestate) {
                Sync-NoIDAsrPolicyRuntime -RuleId ([string]$snapshot.Targets[0].GUID) -Confirm:$false
                $result.Success = $true
                $result.Restored = [int]$snapshot.TargetCount
                $result.AlreadyAtCombinedSessionPrestate = $true
                return $result
            }
        }

        # Only the effective-state checks need a running Defender.
        $defenderAvailable = $true
        $current = @{}
        try {
            $current = (ConvertFrom-ASRPreference -Preference (Get-MpPreference -ErrorAction Stop)).Map
        }
        catch {
            $defenderAvailable = $false
            $defenderError = $_.Exception.Message
        }
        if (-not $defenderAvailable) {
            if ($schemaVersion -lt 5) {
                throw "Microsoft Defender must be running to restore this earlier ASR session, which changed Defender's own rule list: $defenderError"
            }
            $result.Warnings += "Microsoft Defender is not running or did not answer ($defenderError). NoID Privacy's ASR policy values are restored; Defender applies them when it runs again."
        }

        $policyPath = [string]$snapshot.PolicyPath
        $policyKeyExists = Test-NoIDRegistryKey -LiteralPath $policyPath
        $policyKey = if ($policyKeyExists) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }

        # Two live states are this session's own: the Apply result it sealed,
        # and the restore target itself (another module that shares the value,
        # such as SecurityBaseline, already put the prestate back). Any other
        # owned policy value was changed after Apply by someone else: that
        # target keeps its current value and is reported. When only Defender's
        # effective action differs, another policy layer controls the rule; the
        # owned policy value is still restored, but the effective action is not
        # this restore's to verify.
        $keptTargets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $effectiveUnverified = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($target in @($snapshot.Targets)) {
            $id = [string]$target.GUID
            $effectiveDrift = $false
            if ($defenderAvailable) {
                $liveExists = $current.ContainsKey($id)
                $matchesApply = $liveExists -and [int]$current[$id] -eq [int]$target.RequestedAction
                $matchesRestoreTarget = if ([bool]$target.OriginalExists) {
                    $liveExists -and [int]$current[$id] -eq [int]$target.OriginalAction
                }
                else {
                    -not $liveExists
                }
                $effectiveDrift = -not $matchesApply -and -not $matchesRestoreTarget
            }
            if ([bool]$target.PolicyOverride) {
                $policyValueExists = $policyKeyExists -and ($policyKey.GetValueNames() -contains $id)
                $wantsPolicyValue = [bool]$target.PolicyValue.Exists
                $policyDrift = $false
                if (-not $policyValueExists) {
                    # Absent is only this session's own state when the restore target is absent too.
                    $policyDrift = $wantsPolicyValue
                }
                else {
                    $type = $policyKey.GetValueKind($id).ToString()
                    $data = [string]$policyKey.GetValue($id, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $appliedData = ([int]$target.RequestedAction).ToString([Globalization.CultureInfo]::InvariantCulture)
                    $matchesAppliedPolicy = $type -eq 'String' -and $data -ceq $appliedData
                    $matchesRestorePolicy = $wantsPolicyValue -and
                        $type -eq [string]$target.PolicyValue.Type -and
                        $data -ceq ([string]$target.PolicyValue.Value)
                    $policyDrift = -not $matchesAppliedPolicy -and -not $matchesRestorePolicy
                }
                if ($policyDrift) {
                    $null = $keptTargets.Add($id)
                    $result.Warnings += "ASR rule $id was changed after Apply by another tool or person and keeps its current policy value."
                    continue
                }
                if ($effectiveDrift) {
                    $null = $effectiveUnverified.Add($id)
                    $result.Warnings += "ASR rule $id is controlled by another policy or tool (Defender reports action $([int]$current[$id])); NoID Privacy's own policy value was restored."
                }
            }
            elseif ($effectiveDrift) {
                $null = $keptTargets.Add($id)
                $result.Warnings += "ASR rule $id was changed after Apply by another tool or person and keeps its current action."
            }
        }
        $result.KeptTargets = @($keptTargets)

        $desired = @{}
        foreach ($entry in $current.GetEnumerator()) { $desired[[string]$entry.Key] = [int]$entry.Value }
        foreach ($target in @($snapshot.Targets)) {
            $id = [string]$target.GUID
            if ($keptTargets.Contains($id)) { continue }
            if ([bool]$target.OriginalExists) { $desired[$id] = [int]$target.OriginalAction }
            else { $desired.Remove($id) }
        }

        # Schema 5 Apply owns only target-scoped policy values and never writes
        # the merged effective Defender view into local preferences. Restoring
        # those exact policy values preserves the original local rule store;
        # the runtime notification below makes Defender consume the change.
        # Schema 3/4 remains supported for sessions
        # created by earlier releases that did mutate local preferences.
        if ($schemaVersion -lt 5) {
            try {
                if ($desired.Count -gt 0) {
                    $desiredIds = @($desired.Keys | Sort-Object)
                    $desiredActions = @($desiredIds | ForEach-Object { [int]$desired[$_] })
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $desiredIds `
                        -AttackSurfaceReductionRules_Actions $desiredActions -ErrorAction Stop | Out-Null
                }
                else {
                    $removeTargets = @($snapshot.Targets | Where-Object { -not $keptTargets.Contains([string]$_.GUID) })
                    if ($removeTargets.Count -gt 0) {
                        $removeIds = @($removeTargets | ForEach-Object { [string]$_.GUID })
                        $removeActions = @($removeTargets | ForEach-Object { [int]$_.RequestedAction })
                        Remove-MpPreference -AttackSurfaceReductionRules_Ids $removeIds `
                            -AttackSurfaceReductionRules_Actions $removeActions -ErrorAction Stop | Out-Null
                    }
                }
            }
            catch {
                $result.Errors += "Defender's local ASR rule list could not be restored: $($_.Exception.Message)"
            }
        }

        # Each owned policy value is written on its own.
        $policyTargets = @($snapshot.Targets | Where-Object {
                [bool]$_.PolicyOverride -and -not $keptTargets.Contains([string]$_.GUID)
            })
        $policyKey = $null
        Remove-Variable -Name policyKey -ErrorAction SilentlyContinue
        if (@($policyTargets | Where-Object { [bool]$_.PolicyValue.Exists }).Count -gt 0 -and
            -not (Test-NoIDRegistryKey -LiteralPath $policyPath)) {
            # The key existed before Apply (an existing value implies it) and was
            # removed later; it is recreated for the values this session owns.
            New-NoIDRegistryKey -LiteralPath $policyPath | Out-Null
        }
        if ($policyTargets.Count -gt 0 -and (Test-NoIDRegistryKey -LiteralPath $policyPath)) {
            foreach ($target in $policyTargets) {
                $id = [string]$target.GUID
                try {
                    $currentNames = @((Get-Item -LiteralPath $policyPath -ErrorAction Stop).GetValueNames())
                    if ([bool]$target.PolicyValue.Exists) {
                        $restoreName = if ($schemaVersion -ge 4) {
                            [string]$target.PolicyValue.OriginalName
                        }
                        else {
                            $id
                        }
                        $value = switch ([string]$target.PolicyValue.Type) {
                            'Binary' { [byte[]]@($target.PolicyValue.Value) }
                            'MultiString' { [string[]]@($target.PolicyValue.Value) }
                            'DWord' { [int]$target.PolicyValue.Value }
                            'QWord' { [long]$target.PolicyValue.Value }
                            default { [string]$target.PolicyValue.Value }
                        }
                        if ($currentNames -contains $id) {
                            Remove-ItemProperty -LiteralPath $policyPath -Name $id -ErrorAction Stop
                        }
                        New-ItemProperty -LiteralPath $policyPath -Name $restoreName -PropertyType ([string]$target.PolicyValue.Type) `
                            -Value $value -Force -ErrorAction Stop | Out-Null
                    }
                    elseif ($currentNames -contains $id) {
                        Remove-ItemProperty -LiteralPath $policyPath -Name $id -ErrorAction Stop
                    }
                }
                catch {
                    $result.Errors += "ASR policy value $id could not be restored: $($_.Exception.Message)"
                }
            }
        }

        # An originally absent key is removed once it is empty. If it now holds
        # policy NoID Privacy does not own (another tool's rule, a rule kept
        # above), it is kept and reported instead of deleting that policy.
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cleanupPaths = @()
        if (-not [bool]$snapshot.PolicyKeyExisted) { $cleanupPaths += $policyPath }
        $cleanupPaths += @($absentAncestorKeys | Sort-Object { $_.Length } -Descending)
        foreach ($cleanupPath in $cleanupPaths) {
            try {
                if (-not (Test-NoIDRegistryKey -LiteralPath $cleanupPath)) { continue }
                $cleanupKey = Get-Item -LiteralPath $cleanupPath -ErrorAction Stop
                $remainingValues = @($cleanupKey.GetValueNames())
                $remainingSubKeys = @($cleanupKey.GetSubKeyNames())
                $cleanupKey = $null
                if ($remainingValues.Count -eq 0 -and $remainingSubKeys.Count -eq 0) {
                    Remove-Item -LiteralPath $cleanupPath -Force -ErrorAction Stop
                    continue
                }
                $foreignSubKeys = @($remainingSubKeys | Where-Object { -not $retainedKeys.Contains("$cleanupPath\$_") })
                $null = $retainedKeys.Add($cleanupPath)
                $result.RetainedKeys += $cleanupPath
                if ($remainingValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                    $result.Warnings += (Format-NoIDRetainedKeyNotice -Path $cleanupPath `
                            -Values ([string[]]$remainingValues) -SubKeys ([string[]]$foreignSubKeys))
                }
            }
            catch {
                $result.Errors += "Could not remove originally absent ASR key $cleanupPath`: $($_.Exception.Message)"
            }
        }

        if ($defenderAvailable) {
            # Exact owned-target verification; unrelated Defender rules are preserved.
            try {
                Sync-NoIDAsrPolicyRuntime -RuleId ([string]$snapshot.Targets[0].GUID) -Confirm:$false
                $afterMap = (ConvertFrom-ASRPreference -Preference (
                        Get-MpPreference -ErrorAction Stop
                    )).Map
                $verifyIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($key in @($desired.Keys) + @($afterMap.Keys)) {
                    if (-not $effectiveUnverified.Contains([string]$key)) { $null = $verifyIds.Add([string]$key) }
                }
                foreach ($id in $verifyIds) {
                    if ($desired.ContainsKey($id) -ne $afterMap.ContainsKey($id) -or
                        ($desired.ContainsKey($id) -and [int]$afterMap[$id] -ne [int]$desired[$id])) {
                        $result.Errors += "ASR Defender target verification failed after restore: $id"
                    }
                }
            }
            catch {
                $result.Errors += "Defender did not confirm the restored ASR state: $($_.Exception.Message)"
            }
        }

        $policyExistsAfter = Test-NoIDRegistryKey -LiteralPath $policyPath
        if ($policyExistsAfter -and -not [bool]$snapshot.PolicyKeyExisted -and -not $retainedKeys.Contains($policyPath)) {
            $result.Errors += 'ASR policy key-existence verification failed after restore'
        }
        $policyAfter = if ($policyExistsAfter) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }
        foreach ($target in $policyTargets) {
            $id = [string]$target.GUID
            $expectedName = if ($schemaVersion -ge 4 -and [bool]$target.PolicyValue.Exists) {
                [string]$target.PolicyValue.OriginalName
            }
            else {
                $id
            }
            $matchingNames = @(if ($policyExistsAfter) {
                    $policyAfter.GetValueNames() | Where-Object {
                        ([string]$_).Equals($expectedName, [StringComparison]::OrdinalIgnoreCase)
                    }
                })
            $exists = $matchingNames.Count -eq 1
            if ($exists -ne [bool]$target.PolicyValue.Exists) {
                $result.Errors += "ASR policy target existence verification failed after restore: $id"
                continue
            }
            if ($exists) {
                if ($schemaVersion -ge 4 -and [string]$matchingNames[0] -cne $expectedName) {
                    $result.Errors += "ASR policy target value-name casing verification failed after restore: $id"
                    continue
                }
                $type = $policyAfter.GetValueKind([string]$matchingNames[0]).ToString()
                $value = $policyAfter.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $actualJson = [PSCustomObject]@{ Value=$value } | ConvertTo-Json -Compress -Depth 10
                $expectedJson = [PSCustomObject]@{ Value=$target.PolicyValue.Value } | ConvertTo-Json -Compress -Depth 10
                if ($type -cne [string]$target.PolicyValue.Type -or $actualJson -cne $expectedJson) {
                    $result.Errors += "ASR policy target verification failed after restore: $id"
                }
            }
        }
        foreach ($ancestorPath in $absentAncestorKeys) {
            if ((Test-NoIDRegistryKey -LiteralPath $ancestorPath) -and -not $retainedKeys.Contains($ancestorPath)) {
                $result.Errors += "ASR absent ancestor remains after restore: $ancestorPath"
            }
        }

        $result.Restored = [int]$snapshot.TargetCount - $keptTargets.Count
        $result.Success = @($result.Errors).Count -eq 0
    }
    catch {
        $result.Errors += "ASR restore failed: $($_.Exception.Message)"
    }
    return $result
}
