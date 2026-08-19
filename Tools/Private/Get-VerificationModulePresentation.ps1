#Requires -Version 5.1

function Get-VerificationModulePresentation {
    <#
    .SYNOPSIS
        Builds one reconciled console verdict for a verification module.

    .DESCRIPTION
        Separates failed live checks, unresolved evidence, authoritatively
        deliberate exclusions, and targets unsupported by the current host.
        Every caller must provide a complete four-state partition of Total.
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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Summary,

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
    $status = if ($Failed -gt 0) {
        'FAILED'
    }
    elseif ($unproven -gt 0) {
        'INCOMPLETE'
    }
    elseif ($NotApplicable -eq $Total) {
        'NOT APPLICABLE'
    }
    else { 'VERIFIED' }
    $color = switch ($status) {
        'FAILED'     { 'Red' }
        'INCOMPLETE' { 'Yellow' }
        'NOT APPLICABLE' { 'DarkGray' }
        default      { 'Green' }
    }
    $contextSuffix = if ([string]::IsNullOrWhiteSpace($Context)) { '' } else { " $Context" }

    return [PSCustomObject]@{
        Name = $Name
        Status = $status
        Color = $color
        StatusLine = "${Name}: [$status]$contextSuffix"
        SummaryLine = $Summary
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
}
