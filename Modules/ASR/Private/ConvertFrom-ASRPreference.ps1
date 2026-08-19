#Requires -Version 5.1

function ConvertFrom-ASRPreference {
    <#
    .SYNOPSIS
        Normalize and validate the paired ASR arrays returned by Defender.

    .DESCRIPTION
        Get-MpPreference represents an empty ASR configuration on supported
        Windows 11 builds as one null placeholder in each array.  That exact
        paired representation is normalized to an empty state.  Every other
        null, mismatched, malformed, unsupported, or duplicate state is
        rejected before a caller can use it for backup, apply, or restore.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Preference
    )

    $ids = @($Preference.AttackSurfaceReductionRules_Ids)
    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -eq 1 -and $actions.Count -eq 1 -and
        $null -eq $ids[0] -and $null -eq $actions[0]) {
        $ids = @()
        $actions = @()
    }
    if ($ids.Count -ne $actions.Count) {
        throw "Defender returned mismatched ASR IDs/actions: $($ids.Count)/$($actions.Count)"
    }

    $map = @{}
    $normalizedIds = [System.Collections.Generic.List[string]]::new()
    $normalizedActions = [System.Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $ids.Count; $index++) {
        if ($null -eq $ids[$index] -or $null -eq $actions[$index]) {
            throw "Defender returned a partial null ASR state at index $index"
        }
        $parsed = [Guid]::Empty
        $action = 0
        if (-not [Guid]::TryParse([string]$ids[$index], [ref]$parsed) -or
            -not [int]::TryParse(
                [string]$actions[$index],
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$action
            ) -or $action -notin @(0, 1, 2, 6)) {
            throw "Defender returned an invalid ASR state: $($ids[$index])/$($actions[$index])"
        }
        $id = $parsed.ToString('D').ToLowerInvariant()
        if ($map.ContainsKey($id)) { throw "Defender returned duplicate ASR rule $id" }
        $map[$id] = $action
        $normalizedIds.Add($id)
        $normalizedActions.Add($action)
    }

    return [PSCustomObject]@{
        Ids     = [string[]]$normalizedIds.ToArray()
        Actions = [int[]]$normalizedActions.ToArray()
        Map     = $map
        Count   = [int]$map.Count
    }
}
