#Requires -Version 5.1

function Get-ASRApplicabilityPlan {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$Rules
    )

    $applicable = @()
    $notApplicable = @()
    foreach ($rule in $Rules) {
        if ([bool]$rule.WindowsClientApplicable) {
            $applicable += $rule
            continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$rule.NotApplicableReason)) {
            throw "ASR rule has no Windows-client applicability reason: $($rule.GUID)"
        }
        $notApplicable += [PSCustomObject]@{
            Name   = [string]$rule.Name
            GUID   = [string]$rule.GUID
            Reason = [string]$rule.NotApplicableReason
        }
    }

    if ($Rules.Count -ne ($applicable.Count + $notApplicable.Count)) {
        throw 'ASR applicability plan does not reconcile to the declared rule count'
    }
    if ($applicable.Count -eq 0) {
        throw 'ASR applicability plan contains no Windows-client rules'
    }

    return [PSCustomObject]@{
        DeclaredCount      = [int]$Rules.Count
        Applicable         = @($applicable)
        ApplicableCount    = [int]$applicable.Count
        NotApplicable      = @($notApplicable)
        NotApplicableCount = [int]$notApplicable.Count
    }
}
