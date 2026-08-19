#Requires -Version 5.1

function Assert-ASRSnapshot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot
    )

    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $targets = @($Snapshot.Targets)
    $notApplicable = @($Snapshot.NotApplicable)
    $schemaVersion = [int]$Snapshot.SchemaVersion
    if ($schemaVersion -notin @(3, 4, 5) -or
        [string]$Snapshot.Target -cne 'WindowsClientDefenderASR' -or
        [string]$Snapshot.PolicyPath -cne $policyPath -or
        $Snapshot.PolicyKeyExisted -isnot [bool] -or
        [int]$Snapshot.DeclaredCount -ne ($targets.Count + $notApplicable.Count) -or
        [int]$Snapshot.TargetCount -ne $targets.Count -or
        [int]$Snapshot.NotApplicableCount -ne $notApplicable.Count -or
        $targets.Count -eq 0) {
        throw 'ASR snapshot has an invalid schema, identity or count'
    }
    if ($schemaVersion -ge 4) {
        if (-not $Snapshot.PSObject.Properties['AbsentAncestorKeys']) {
            throw "ASR schema $schemaVersion snapshot has no absent-ancestor inventory"
        }
        $allowedAncestors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $policyBoundary = 'HKLM:\SOFTWARE\Policies'
        $ancestorCursor = $policyPath.Substring(0, $policyPath.LastIndexOf('\'))
        while ($ancestorCursor.Length -gt $policyBoundary.Length) {
            $null = $allowedAncestors.Add($ancestorCursor)
            $ancestorCursor = $ancestorCursor.Substring(0, $ancestorCursor.LastIndexOf('\'))
        }
        $seenAncestors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($ancestorPath in @($Snapshot.AbsentAncestorKeys)) {
            if ([string]::IsNullOrWhiteSpace([string]$ancestorPath) -or
                -not $allowedAncestors.Contains([string]$ancestorPath) -or
                -not $seenAncestors.Add([string]$ancestorPath)) {
                throw "ASR snapshot contains an invalid or duplicate absent ancestor: $ancestorPath"
            }
        }
    }

    $seen = [System.Collections.Generic.HashSet[Guid]]::new()
    $supportedTypes = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')
    foreach ($target in $targets) {
        $parsed = [Guid]::Empty
        if ([string]::IsNullOrWhiteSpace([string]$target.Name) -or
            -not [Guid]::TryParseExact([string]$target.GUID, 'D', [ref]$parsed) -or
            [string]$target.GUID -cne $parsed.ToString('D').ToLowerInvariant() -or
            -not $seen.Add($parsed) -or
            [int]$target.RequestedAction -notin @(0, 1, 2, 6) -or
            $target.OriginalExists -isnot [bool] -or
            $target.PolicyOverride -isnot [bool] -or
            $target.UserConfigurable -isnot [bool] -or
            [string]$target.BaselineStatus -notin @('Block', 'Audit', 'Missing') -or
            ($schemaVersion -lt 5 -and
                [bool]$target.PolicyOverride -ne ([bool]$target.UserConfigurable -or [string]$target.BaselineStatus -eq 'Audit')) -or
            ($schemaVersion -eq 5 -and -not [bool]$target.PolicyOverride)) {
            throw "ASR snapshot contains an invalid or duplicate target: $($target.GUID)"
        }
        if ([bool]$target.OriginalExists) {
            if (-not $target.PSObject.Properties['OriginalAction'] -or
                [int]$target.OriginalAction -notin @(0, 1, 2, 6)) {
                throw "ASR snapshot target has invalid original Defender action: $($target.GUID)"
            }
        }
        elseif ($null -ne $target.OriginalAction) {
            throw "ASR snapshot target records data for an originally absent Defender rule: $($target.GUID)"
        }

        if ([bool]$target.PolicyOverride) {
            if (-not $target.PSObject.Properties['PolicyValue'] -or $null -eq $target.PolicyValue -or
                $target.PolicyValue.Exists -isnot [bool]) {
                throw "ASR snapshot policy prestate is missing: $($target.GUID)"
            }
            if ($schemaVersion -ge 4 -and -not $target.PolicyValue.PSObject.Properties['OriginalName']) {
                throw "ASR schema $schemaVersion policy prestate has no original value name: $($target.GUID)"
            }
            if ([bool]$target.PolicyValue.Exists) {
                $type = [string]$target.PolicyValue.Type
                if ($schemaVersion -ge 4 -and
                    (-not $target.PolicyValue.PSObject.Properties['OriginalName'] -or
                     [string]::IsNullOrWhiteSpace([string]$target.PolicyValue.OriginalName) -or
                     -not ([string]$target.PolicyValue.OriginalName).Equals([string]$target.GUID, [StringComparison]::OrdinalIgnoreCase))) {
                    throw "ASR snapshot policy original value-name identity is invalid: $($target.GUID)"
                }
                if ($type -notin $supportedTypes) {
                    throw "ASR snapshot policy value has unsupported type '$type': $($target.GUID)"
                }
                switch ($type) {
                    'DWord' { if ([long]$target.PolicyValue.Value -lt [int]::MinValue -or [long]$target.PolicyValue.Value -gt [uint32]::MaxValue) { throw 'ASR DWord prestate is out of range' } }
                    'QWord' { $null = [convert]::ToInt64($target.PolicyValue.Value) }
                    'String' { if ($target.PolicyValue.Value -isnot [string]) { throw 'ASR String prestate is not a string' } }
                    'ExpandString' { if ($target.PolicyValue.Value -isnot [string]) { throw 'ASR ExpandString prestate is not a string' } }
                    'MultiString' { foreach ($item in @($target.PolicyValue.Value)) { if ($item -isnot [string]) { throw 'ASR MultiString prestate contains a non-string' } } }
                    'Binary' { foreach ($item in @($target.PolicyValue.Value)) { if ([int]$item -lt 0 -or [int]$item -gt 255) { throw 'ASR Binary prestate contains a byte outside 0..255' } } }
                }
            }
            elseif ($null -ne $target.PolicyValue.Type -or $null -ne $target.PolicyValue.Value -or
                ($schemaVersion -ge 4 -and $null -ne $target.PolicyValue.OriginalName)) {
                throw "ASR snapshot policy prestate records data for an absent value: $($target.GUID)"
            }
        }
        elseif ($null -ne $target.PolicyValue) {
            throw "ASR snapshot contains policy state for a non-policy target: $($target.GUID)"
        }
    }

    foreach ($entry in $notApplicable) {
        $parsed = [Guid]::Empty
        if ([string]::IsNullOrWhiteSpace([string]$entry.Name) -or
            [string]::IsNullOrWhiteSpace([string]$entry.Reason) -or
            -not [Guid]::TryParseExact([string]$entry.GUID, 'D', [ref]$parsed) -or
            [string]$entry.GUID -cne $parsed.ToString('D').ToLowerInvariant() -or
            -not $seen.Add($parsed)) {
            throw "ASR snapshot contains an invalid, duplicate or overlapping NotApplicable rule: $($entry.GUID)"
        }
    }

    return $true
}
