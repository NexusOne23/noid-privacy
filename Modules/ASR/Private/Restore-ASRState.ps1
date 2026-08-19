#Requires -Version 5.1

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
    $liveKeyExists = Test-Path -LiteralPath $policyPath -PathType Container -ErrorAction Stop
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
        preserving unrelated Defender rules and refusing concurrent target drift.
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
    }
    if (-not $PSCmdlet.ShouldProcess($BackupPath, 'Restore exact target-scoped ASR prestate')) {
        $result.Errors += 'ASR restore was not confirmed'
        return $result
    }

    try {
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-ASRSnapshot -Snapshot $snapshot
        $schemaVersion = [int]$snapshot.SchemaVersion
        $absentAncestorKeys = if ($schemaVersion -ge 4) { @($snapshot.AbsentAncestorKeys) } else { @() }

        if ($schemaVersion -eq 5 -and
            -not [string]::IsNullOrWhiteSpace($SecurityBaselineRegistryBackupPath) -and
            (Test-ASRCombinedSessionPrestate `
                -ASRSnapshot $snapshot `
                -SecurityBaselineRegistryBackupPath $SecurityBaselineRegistryBackupPath)) {
            $result.Success = $true
            $result.Restored = [int]$snapshot.TargetCount
            $result.AlreadyAtCombinedSessionPrestate = $true
            return $result
        }

        $preference = Get-MpPreference -ErrorAction Stop
        $current = (ConvertFrom-ASRPreference -Preference $preference).Map

        $policyPath = [string]$snapshot.PolicyPath
        $policyKeyExists = Test-Path -LiteralPath $policyPath -PathType Container -ErrorAction Stop
        $policyKey = if ($policyKeyExists) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }

        # Validate every owned live target before the first restore mutation.
        #
        # Two live states are legitimate:
        #   1. the Apply result this session sealed -- nothing touched it since;
        #   2. the restore target itself -- something already put the sealed
        #      pre-state back, so restoring this target is a no-op.
        # Case 2 is reached whenever another module owns the same value: the
        # ASR rule set overlaps the Security Baseline registry policies, and a
        # baseline apply or restore can legitimately land on the very value
        # this restore is about to write. Refusing there aborted the whole
        # module restore over a target that already held the wanted state.
        # Any other live value is genuinely foreign later state and still blocks.
        foreach ($target in @($snapshot.Targets)) {
            $id = [string]$target.GUID
            $liveExists = $current.ContainsKey($id)
            $matchesApply = $liveExists -and [int]$current[$id] -eq [int]$target.RequestedAction
            $matchesRestoreTarget = if ([bool]$target.OriginalExists) {
                $liveExists -and [int]$current[$id] -eq [int]$target.OriginalAction
            }
            else {
                -not $liveExists
            }
            if (-not $matchesApply -and -not $matchesRestoreTarget) {
                throw "ASR target drifted after Apply; refusing to overwrite later state: $id"
            }
            if ([bool]$target.PolicyOverride) {
                $policyValueExists = $policyKeyExists -and ($policyKey.GetValueNames() -contains $id)
                $wantsPolicyValue = [bool]$target.PolicyValue.Exists
                if (-not $policyValueExists) {
                    # Absent is only acceptable when the restore target is absent too.
                    if ($wantsPolicyValue) {
                        throw "ASR policy target disappeared after Apply: $id"
                    }
                    continue
                }
                $type = $policyKey.GetValueKind($id).ToString()
                $data = [string]$policyKey.GetValue($id, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $appliedData = ([int]$target.RequestedAction).ToString([Globalization.CultureInfo]::InvariantCulture)
                $matchesAppliedPolicy = $type -eq 'String' -and $data -ceq $appliedData
                $matchesRestorePolicy = $wantsPolicyValue -and
                    $type -eq [string]$target.PolicyValue.Type -and
                    $data -ceq ([string]$target.PolicyValue.Value)
                if (-not $matchesAppliedPolicy -and -not $matchesRestorePolicy) {
                    throw "ASR policy target drifted after Apply; refusing to overwrite later state: $id"
                }
            }
        }

        if (-not [bool]$snapshot.PolicyKeyExisted -and $policyKeyExists) {
            $ownedNames = @($snapshot.Targets | Where-Object { [bool]$_.PolicyOverride } | ForEach-Object { [string]$_.GUID })
            $laterValues = @($policyKey.GetValueNames() | Where-Object { $_ -notin $ownedNames })
            $laterSubKeys = @($policyKey.GetSubKeyNames())
            if ($laterValues.Count -gt 0 -or $laterSubKeys.Count -gt 0) {
                throw 'Originally absent ASR policy key contains later unowned state; refusing destructive restore'
            }
        }
        foreach ($ancestorPath in $absentAncestorKeys) {
            if (-not (Test-Path -LiteralPath $ancestorPath -PathType Container -ErrorAction Stop)) { continue }
            $cursor = [string]$ancestorPath
            while (-not $cursor.Equals($policyPath, [StringComparison]::OrdinalIgnoreCase)) {
                $cursorKey = Get-Item -LiteralPath $cursor -ErrorAction Stop
                if (@($cursorKey.GetValueNames()).Count -ne 0) {
                    throw "Originally absent ASR ancestor contains later unowned values: $cursor"
                }
                $remainingPath = $policyPath.Substring($cursor.Length + 1)
                $nextSegment = $remainingPath.Split('\')[0]
                $subKeys = @($cursorKey.GetSubKeyNames())
                if ($subKeys.Count -ne 1 -or
                    -not ([string]$subKeys[0]).Equals($nextSegment, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Originally absent ASR ancestor contains later unowned subkeys: $cursor"
                }
                $cursor = "$cursor\$nextSegment"
            }
        }

        $desired = @{}
        foreach ($entry in $current.GetEnumerator()) { $desired[[string]$entry.Key] = [int]$entry.Value }
        foreach ($target in @($snapshot.Targets)) {
            $id = [string]$target.GUID
            if ([bool]$target.OriginalExists) { $desired[$id] = [int]$target.OriginalAction }
            else { $desired.Remove($id) }
        }

        # Schema 5 Apply owns only target-scoped policy values and never writes
        # the merged effective Defender view into local preferences. Restoring
        # those exact policy values is therefore sufficient and preserves the
        # original local rule store. Schema 3/4 remains supported for sessions
        # created by earlier releases that did mutate local preferences.
        if ($schemaVersion -lt 5) {
            if ($desired.Count -gt 0) {
                $desiredIds = @($desired.Keys | Sort-Object)
                $desiredActions = @($desiredIds | ForEach-Object { [int]$desired[$_] })
                Set-MpPreference -AttackSurfaceReductionRules_Ids $desiredIds `
                    -AttackSurfaceReductionRules_Actions $desiredActions -ErrorAction Stop | Out-Null
            }
            else {
                $removeIds = @($snapshot.Targets | ForEach-Object { [string]$_.GUID })
                $removeActions = @($snapshot.Targets | ForEach-Object { [int]$_.RequestedAction })
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $removeIds `
                    -AttackSurfaceReductionRules_Actions $removeActions -ErrorAction Stop | Out-Null
            }
        }

        $policyTargets = @($snapshot.Targets | Where-Object { [bool]$_.PolicyOverride })
        if ($policyTargets.Count -gt 0 -and $policyKeyExists) {
            foreach ($target in $policyTargets) {
                $id = [string]$target.GUID
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
                    $currentNames = @((Get-Item -LiteralPath $policyPath -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains $id) {
                        Remove-ItemProperty -LiteralPath $policyPath -Name $id -ErrorAction Stop
                    }
                    New-ItemProperty -LiteralPath $policyPath -Name $restoreName -PropertyType ([string]$target.PolicyValue.Type) `
                        -Value $value -Force -ErrorAction Stop | Out-Null
                }
                else {
                    $currentNames = @((Get-Item -LiteralPath $policyPath -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains $id) {
                        Remove-ItemProperty -LiteralPath $policyPath -Name $id -ErrorAction Stop
                    }
                }
            }
            if (-not [bool]$snapshot.PolicyKeyExisted) {
                $policyKey = $null
                Remove-Variable -Name policyKey -ErrorAction SilentlyContinue
                $candidate = Get-Item -LiteralPath $policyPath -ErrorAction Stop
                if ($candidate.GetValueNames().Count -ne 0 -or $candidate.GetSubKeyNames().Count -ne 0) {
                    throw 'ASR policy key is no longer empty after removing module-owned values'
                }
                $candidate = $null
                Remove-Item -LiteralPath $policyPath -Force -ErrorAction Stop
            }
        }
        elseif ($policyTargets.Count -gt 0 -and [bool]$snapshot.PolicyKeyExisted) {
            throw 'ASR policy key vanished after pre-restore validation'
        }
        foreach ($ancestorPath in @($absentAncestorKeys | Sort-Object { $_.Length } -Descending)) {
            if (-not (Test-Path -LiteralPath $ancestorPath -PathType Container -ErrorAction Stop)) { continue }
            $ancestorKey = Get-Item -LiteralPath $ancestorPath -ErrorAction Stop
            if (@($ancestorKey.GetValueNames()).Count -ne 0 -or $ancestorKey.SubKeyCount -ne 0) {
                throw "Originally absent ASR ancestor contains state after target restore: $ancestorPath"
            }
            Remove-Item -LiteralPath $ancestorPath -Force -ErrorAction Stop
        }

        # Exact owned-target verification; unrelated Defender rules are preserved.
        $afterMap = (ConvertFrom-ASRPreference -Preference (
                Get-MpPreference -ErrorAction Stop
            )).Map
        if ($afterMap.Count -ne $desired.Count) {
            throw "ASR post-restore count mismatch: expected $($desired.Count), got $($afterMap.Count)"
        }
        foreach ($entry in $desired.GetEnumerator()) {
            if (-not $afterMap.ContainsKey([string]$entry.Key) -or
                [int]$afterMap[[string]$entry.Key] -ne [int]$entry.Value) {
                throw "ASR Defender target verification failed after restore: $($entry.Key)"
            }
        }

        $policyExistsAfter = Test-Path -LiteralPath $policyPath -PathType Container -ErrorAction Stop
        if ($policyExistsAfter -ne [bool]$snapshot.PolicyKeyExisted) {
            throw 'ASR policy key-existence verification failed after restore'
        }
        $policyAfter = if ($policyExistsAfter) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }
        foreach ($target in @($snapshot.Targets | Where-Object { [bool]$_.PolicyOverride })) {
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
                throw "ASR policy target existence verification failed after restore: $id"
            }
            if ($exists) {
                if ($schemaVersion -ge 4 -and [string]$matchingNames[0] -cne $expectedName) {
                    throw "ASR policy target value-name casing verification failed after restore: $id"
                }
                $type = $policyAfter.GetValueKind([string]$matchingNames[0]).ToString()
                $value = $policyAfter.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $actualJson = [PSCustomObject]@{ Value=$value } | ConvertTo-Json -Compress -Depth 10
                $expectedJson = [PSCustomObject]@{ Value=$target.PolicyValue.Value } | ConvertTo-Json -Compress -Depth 10
                if ($type -cne [string]$target.PolicyValue.Type -or $actualJson -cne $expectedJson) {
                    throw "ASR policy target verification failed after restore: $id"
                }
            }
        }
        foreach ($ancestorPath in $absentAncestorKeys) {
            if (Test-Path -LiteralPath $ancestorPath -PathType Container -ErrorAction Stop) {
                throw "ASR absent ancestor remains after restore: $ancestorPath"
            }
        }

        $result.Success = $true
        $result.Restored = [int]$snapshot.TargetCount
    }
    catch {
        $result.Errors += "ASR restore failed: $($_.Exception.Message)"
    }
    return $result
}
