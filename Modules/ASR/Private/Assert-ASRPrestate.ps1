#Requires -Version 5.1

function Assert-ASRPrestate {
    <#
    .SYNOPSIS
        Reconcile every owned Defender/policy target against the decision-bound
        ASR snapshot before and after sealing.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$ExpectedRules,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Array]$ExpectedNotApplicable
    )

    $artifacts = @($global:BackupIndex | Where-Object { [string]$_.Module -eq 'ASR' })
    $activeArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -eq 'ASR' -and [string]$_.Name -eq 'ASR_ActiveConfiguration'
        })
    if ($artifacts.Count -ne 1 -or $activeArtifacts.Count -ne 1) {
        throw "ASR prestate requires exactly one typed artifact; found $($artifacts.Count)/$($activeArtifacts.Count)"
    }

    $snapshot = Get-Content -LiteralPath $activeArtifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $null = Assert-ASRSnapshot -Snapshot $snapshot
    if ([int]$snapshot.TargetCount -ne $ExpectedRules.Count -or
        [int]$snapshot.NotApplicableCount -ne $ExpectedNotApplicable.Count) {
        throw 'ASR sealed plan count does not match the frozen applicability decision'
    }

    $expectedTargets = @{}
    foreach ($rule in $ExpectedRules) {
        $id = ([Guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
        if ($expectedTargets.ContainsKey($id)) { throw "Duplicate frozen ASR target: $id" }
        $expectedTargets[$id] = [int]$rule.Action
    }
    foreach ($target in @($snapshot.Targets)) {
        $id = [string]$target.GUID
        if (-not $expectedTargets.ContainsKey($id) -or
            [int]$expectedTargets[$id] -ne [int]$target.RequestedAction) {
            throw "ASR sealed target differs from the frozen decision: $id"
        }
    }
    $expectedNA = @{}
    foreach ($entry in $ExpectedNotApplicable) {
        $id = ([Guid]([string]$entry.GUID)).ToString('D').ToLowerInvariant()
        $expectedNA[$id] = [string]$entry.Reason
    }
    foreach ($entry in @($snapshot.NotApplicable)) {
        if (-not $expectedNA.ContainsKey([string]$entry.GUID) -or
            [string]$expectedNA[[string]$entry.GUID] -cne [string]$entry.Reason) {
            throw "ASR sealed NotApplicable decision differs from the frozen plan: $($entry.GUID)"
        }
    }

    $authority = Get-MpComputerStatus -ErrorAction Stop
    if ([string]$authority.AMRunningMode -ne 'Normal' -or
        -not [bool]$authority.AntivirusEnabled -or
        -not [bool]$authority.RealTimeProtectionEnabled) {
        throw 'Defender is no longer the proven active primary real-time engine after ASR backup'
    }
    $preference = Get-MpPreference -ErrorAction Stop
    $current = (ConvertFrom-ASRPreference -Preference $preference).Map

    $policyPath = [string]$snapshot.PolicyPath
    $policyKeyExists = Test-Path -LiteralPath $policyPath -PathType Container -ErrorAction Stop
    if ($policyKeyExists -ne [bool]$snapshot.PolicyKeyExisted) {
        throw 'ASR policy Rules-key existence changed after backup'
    }
    if ([int]$snapshot.SchemaVersion -ge 4) {
        foreach ($ancestorPath in @($snapshot.AbsentAncestorKeys)) {
            if (Test-Path -LiteralPath ([string]$ancestorPath) -PathType Container -ErrorAction Stop) {
                throw "ASR absent policy ancestor appeared after backup: $ancestorPath"
            }
        }
    }
    $policyKey = if ($policyKeyExists) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }

    foreach ($target in @($snapshot.Targets)) {
        $id = [string]$target.GUID
        $exists = $current.ContainsKey($id)
        if ($exists -ne [bool]$target.OriginalExists -or
            ($exists -and [int]$current[$id] -ne [int]$target.OriginalAction)) {
            throw "Defender ASR target changed after backup: $id"
        }
        if ([bool]$target.PolicyOverride) {
            $expectedPolicyName = if ([int]$snapshot.SchemaVersion -ge 4 -and [bool]$target.PolicyValue.Exists) {
                [string]$target.PolicyValue.OriginalName
            }
            else {
                $id
            }
            $matchingNames = @(if ($policyKeyExists) {
                    $policyKey.GetValueNames() | Where-Object {
                        ([string]$_).Equals($expectedPolicyName, [StringComparison]::OrdinalIgnoreCase)
                    }
                })
            $valueExists = $matchingNames.Count -eq 1
            if ($valueExists -ne [bool]$target.PolicyValue.Exists) {
                throw "ASR policy target existence changed after backup: $id"
            }
            if ($valueExists) {
                if ([int]$snapshot.SchemaVersion -ge 4 -and [string]$matchingNames[0] -cne $expectedPolicyName) {
                    throw "ASR policy target value-name casing changed after backup: $id"
                }
                $type = $policyKey.GetValueKind([string]$matchingNames[0]).ToString()
                $value = $policyKey.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $actualJson = [PSCustomObject]@{ Value=$value } | ConvertTo-Json -Compress -Depth 10
                $expectedJson = [PSCustomObject]@{ Value=$target.PolicyValue.Value } | ConvertTo-Json -Compress -Depth 10
                if ($type -cne [string]$target.PolicyValue.Type -or $actualJson -cne $expectedJson) {
                    throw "ASR policy target changed after backup: $id"
                }
            }
        }
    }

    return $snapshot
}
