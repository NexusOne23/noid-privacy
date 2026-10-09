#Requires -Version 5.1

function Get-PrivacyVerificationPresentation {
    <#
    .SYNOPSIS
        Builds the user-facing verdict for the selected Privacy profile.

    .DESCRIPTION
        The presentation is derived only from the reconciled live verification
        buckets for the authoritative selected profile. The three standalone
        base-profile scorecards are diagnostic comparisons and never influence
        this verdict.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MSRecommended', 'Strict', 'Paranoid')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Total,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Passed,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Failed,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NotChecked,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NotCheckedDeliberate,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NotApplicable
    )

    if (($Passed + $Failed + $NotChecked + $NotApplicable) -ne $Total) {
        throw "Privacy presentation buckets do not reconcile: passed=$Passed, failed=$Failed, notChecked=$NotChecked, notApplicable=$NotApplicable, total=$Total"
    }
    if ($NotCheckedDeliberate -gt $NotChecked) {
        throw "Privacy deliberate NotChecked count exceeds the NotChecked bucket: deliberate=$NotCheckedDeliberate, notChecked=$NotChecked"
    }

    $evaluated = $Passed + $Failed
    $notCheckedUnresolved = $NotChecked - $NotCheckedDeliberate
    # An unproven required target is a failed check (not proven); only the
    # machine buckets keep the distinction.
    $status = if (($Failed + $notCheckedUnresolved) -gt 0) {
        'FAILED'
    }
    else { 'PASSED' }

    return [PSCustomObject][ordered]@{
        Mode = $Mode
        Status = $status
        Total = $Total
        Evaluated = $evaluated
        Passed = $Passed
        Failed = $Failed
        NotChecked = $NotChecked
        NotCheckedDeliberate = $NotCheckedDeliberate
        NotCheckedUnresolved = $notCheckedUnresolved
        NotApplicable = $NotApplicable
    }
}

function Get-PrivacyUnavailablePresentation {
    <#
    .SYNOPSIS
        Builds the single user-facing Privacy result when no selected profile
        can be proven.

    .DESCRIPTION
        The maximum Privacy inventory remains in the verification scope. Live
        profile scorecards may still be retained as machine-readable evidence,
        but they are not shown as competing user verdicts and no profile is
        guessed from the live state.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Total
    )

    return [PSCustomObject][ordered]@{
        Status = 'FAILED'
        Total = $Total
        NoteLine = 'Not proven: no saved Privacy profile; the selected profile is never guessed from the live state.'
        DetailActual = "No saved Privacy profile; this row represents all $Total declared Privacy targets whose selected profile cannot be inferred."
    }
}
