#Requires -Version 5.1

function Format-VerificationCountsLine {
    <#
    .SYNOPSIS
        Formats the one count line every verification surface uses.

    .DESCRIPTION
        The console, the HTML report and the Pro GUI share one vocabulary:
        passed, failed, by choice and not applicable. A required check that
        could not be proven (no saved choice, or the live state could not be
        read) is a failed check; the line names that reason next to measured
        mismatches so the two causes stay distinguishable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Passed,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Mismatched,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$NotProven,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$ByChoice,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$NotApplicable,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Total
    )

    $failed = $Mismatched + $NotProven
    $failedText = if ($Mismatched -gt 0 -and $NotProven -gt 0) {
        "$failed failed ($Mismatched mismatched, $NotProven not proven)"
    }
    elseif ($NotProven -gt 0) {
        "$failed failed (not proven)"
    }
    else { "$failed failed" }
    return "$Passed passed; $failedText; $ByChoice by choice; $NotApplicable not applicable ($Total targets)"
}

function Get-VerificationModulePresentation {
    <#
    .SYNOPSIS
        Builds one reconciled console verdict for a verification module.

    .DESCRIPTION
        Every caller provides a complete four-state partition of Total:
        Passed, Failed (measured mismatch), NotChecked and NotApplicable.
        NotChecked splits into authoritative user choices (BY CHOICE, never
        required) and unresolved evidence. Unresolved evidence is presented as
        failed ("not proven"): the module passes only when every required
        check is proven. The machine counters are unchanged by this wording.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

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
        [int]$NotApplicable,

        # Optional second line: why checks are not proven, why the module
        # failed closed, or which saved choice excluded it.
        [Parameter()]
        [AllowEmptyString()]
        [string]$Note = '',

        [Parameter()]
        [AllowEmptyString()]
        [string]$Context = ''
    )

    if (($Passed + $Failed + $NotChecked + $NotApplicable) -ne $Total) {
        throw "Verification module presentation for '$Name' does not reconcile"
    }
    if ($NotCheckedDeliberate -gt $NotChecked) {
        throw "Verification module presentation for '$Name' has more deliberate exclusions than NotChecked targets"
    }

    $unproven = $NotChecked - $NotCheckedDeliberate
    $status = if (($Failed + $unproven) -gt 0) {
        'FAILED'
    }
    elseif ($NotApplicable -eq $Total) {
        'NOT APPLICABLE'
    }
    else { 'PASSED' }
    $color = switch ($status) {
        'FAILED'         { 'Red' }
        'NOT APPLICABLE' { 'DarkGray' }
        default          { 'Green' }
    }
    $contextSuffix = if ([string]::IsNullOrWhiteSpace($Context)) { '' } else { " $Context" }
    $noteLine = if (-not [string]::IsNullOrWhiteSpace($Note)) {
        $Note
    }
    elseif ($unproven -gt 0) {
        'Not proven: each report row names the missing evidence.'
    }
    else { '' }

    return [PSCustomObject]@{
        Name = $Name
        Status = $status
        Color = $color
        StatusLine = "${Name}: [$status]$contextSuffix"
        SummaryLine = Format-VerificationCountsLine -Passed $Passed -Mismatched $Failed -NotProven $unproven `
            -ByChoice $NotCheckedDeliberate -NotApplicable $NotApplicable -Total $Total
        NoteLine = $noteLine
        NotCheckedUnresolved = $unproven
    }
}

function Write-VerificationModulePresentation {
    <#
    .SYNOPSIS
        Writes a module presentation using its status-specific console color.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Presentation
    )

    Write-Host "  $([string]$Presentation.StatusLine)" -ForegroundColor ([string]$Presentation.Color)
    Write-Host "  $([string]$Presentation.SummaryLine)" -ForegroundColor ([string]$Presentation.Color)
    if (-not [string]::IsNullOrWhiteSpace([string]$Presentation.NoteLine)) {
        Write-Host "  $([string]$Presentation.NoteLine)" -ForegroundColor ([string]$Presentation.Color)
    }
}
