#Requires -Version 5.1

function Get-AntiAIIntentTargetPlan {
    <#
    .SYNOPSIS
        Resolves a durable Apply-time AntiAI scope against the current target definitions.

    .DESCRIPTION
        The intent supplies only the sealed applicable/not-applicable identity
        partition. Expected registry type/data still comes from the reviewed
        current inventory, and every current identity must match exactly once.
        Live product detection is deliberately not consulted.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory)]$Intent)

    foreach ($property in @('applicableTargets','notApplicableTargets')) {
        if (-not $Intent.PSObject.Properties[$property]) {
            throw "Durable AntiAI intent is missing '$property'"
        }
    }
    $canonicalPath = {
        param([string]$Path)
        if ($Path -match '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\(.+)$') {
            return 'HKCU:\' + $Matches[1]
        }
        return $Path
    }

    $targets = @(Get-AntiAIRegistryTargets)
    if ($targets.Count -ne 43) {
        throw "Current AntiAI inventory must contain 43 targets; got $($targets.Count)"
    }
    $targetMap = @{}
    foreach ($target in $targets) {
        $identityPath = & $canonicalPath ([string]$target.Path)
        $identity = ($identityPath + "`0" + [string]$target.Name).ToLowerInvariant()
        if ($targetMap.ContainsKey($identity)) { throw "Current AntiAI inventory contains duplicate '$identity'" }
        $targetMap[$identity] = $target
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $applicable = [System.Collections.Generic.List[object]]::new()
    $notApplicable = [System.Collections.Generic.List[object]]::new()
    foreach ($bucket in @(
            [PSCustomObject]@{ Name='applicableTargets'; Destination=$applicable },
            [PSCustomObject]@{ Name='notApplicableTargets'; Destination=$notApplicable }
        )) {
        foreach ($record in @($Intent.($bucket.Name))) {
            $path = & $canonicalPath ([string]$record.path)
            $name = [string]$record.name
            $identity = ($path + "`0" + $name).ToLowerInvariant()
            if (-not $seen.Add($identity) -or -not $targetMap.ContainsKey($identity)) {
                throw "Durable AntiAI intent contains an unknown or duplicate target: $path::$name"
            }
            if ($bucket.Name -eq 'applicableTargets') {
                $bucket.Destination.Add($targetMap[$identity])
            }
            else {
                $current = $targetMap[$identity]
                $bucket.Destination.Add([PSCustomObject]@{
                        Path = [string]$current.Path
                        Name = [string]$current.Name
                        Feature = [string]$current.Feature
                        Reason = 'Not applicable in the sealed Apply-time target plan; live applicability was not substituted'
                    })
            }
        }
    }
    if ($seen.Count -ne $targetMap.Count) {
        $missing = @($targetMap.Keys | Where-Object { -not $seen.Contains($_) })
        throw "Durable AntiAI intent does not cover the current inventory: $($missing -join ', ')"
    }
    return [PSCustomObject]@{
        DeclaredCount = 43
        ApplicableCount = $applicable.Count
        NotApplicableCount = $notApplicable.Count
        ApplicableTargets = @($applicable)
        NotApplicableTargets = @($notApplicable)
        EvidenceSource = 'DurableApplyIntent'
    }
}
