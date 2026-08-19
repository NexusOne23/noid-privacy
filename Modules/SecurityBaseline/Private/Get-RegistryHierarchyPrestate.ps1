#Requires -Version 5.1

function Get-RegistryHierarchyPrestate {
    <#
    .SYNOPSIS
        Captures absent parent keys that a later New-Item -Force would create.

    .DESCRIPTION
        Registry value snapshots normally record only the target key.  When
        several parent keys are absent, PowerShell creates the complete path;
        restoring only the target then leaves empty parent keys behind.  This
        helper records those parents before Apply so BAVR can remove and verify
        the complete created hierarchy without guessing during Restore.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [string]$BoundaryPath
    )

    $normalizedTarget = $TargetPath.TrimEnd('\')
    $normalizedBoundary = $BoundaryPath.TrimEnd('\')
    if (-not $normalizedTarget.StartsWith("$normalizedBoundary\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Registry target is outside its hierarchy boundary: $TargetPath"
    }

    $missingParents = [System.Collections.Generic.List[string]]::new()
    $cursor = $normalizedTarget.Substring(0, $normalizedTarget.LastIndexOf('\'))
    while ($cursor.Length -gt $normalizedBoundary.Length) {
        if (Test-Path -LiteralPath $cursor -PathType Container -ErrorAction Stop) {
            break
        }
        $missingParents.Add($cursor)
        $separator = $cursor.LastIndexOf('\')
        if ($separator -lt 0) {
            throw "Registry hierarchy has no valid parent: $cursor"
        }
        $cursor = $cursor.Substring(0, $separator)
    }

    return [string[]]@($missingParents)
}

function Get-ExactRegistryValueName {
    <#
    .SYNOPSIS
        Returns the casing-preserving native name of a registry value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryKey]$Key,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $nameMatches = @($Key.GetValueNames() | Where-Object {
            ([string]$_).Equals($Name, [StringComparison]::OrdinalIgnoreCase)
        })
    if ($nameMatches.Count -ne 1) {
        throw "Expected exactly one registry value-name match for '$Name'; found $($nameMatches.Count)"
    }
    return [string]$nameMatches[0]
}
