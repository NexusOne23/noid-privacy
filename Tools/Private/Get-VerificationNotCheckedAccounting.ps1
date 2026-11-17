#Requires -Version 5.1

function Get-VerificationNotCheckedAccounting {
    <#
    .SYNOPSIS
        Reconciles structured NotChecked evidence by affected target count.

    .DESCRIPTION
        NotChecked is the stable public state. Each detail must additionally
        declare why evidence is absent (ByChoice, NoSavedChoice, or
        CannotVerify), the source that proves that disposition, a stable
        reason code, and how many declared targets the detail represents.
        This keeps human wording out of the security
        classifier and permits an explicitly weighted summary row, such as the
        unknown 127-target Privacy profile, without losing count integrity.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Details,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$ExpectedCount,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Context = 'verification result'
    )

    $counts = [ordered]@{
        ByChoice       = 0
        NoSavedChoice  = 0
        CannotVerify   = 0
    }
    $affectedTotal = 0

    foreach ($detail in @($Details)) {
        if ($null -eq $detail) {
            throw "$Context contains a null NotChecked detail"
        }

        $dispositionProperty = $detail.PSObject.Properties['VerificationDisposition']
        $evidenceSourceProperty = $detail.PSObject.Properties['VerificationEvidenceSource']
        $reasonCodeProperty = $detail.PSObject.Properties['VerificationReasonCode']
        $affectedProperty = $detail.PSObject.Properties['AffectedTargetCount']
        if ($null -eq $dispositionProperty -or
            [string]::IsNullOrWhiteSpace([string]$dispositionProperty.Value)) {
            throw "$Context contains a NotChecked detail without VerificationDisposition"
        }
        if ($null -eq $reasonCodeProperty -or
            [string]::IsNullOrWhiteSpace([string]$reasonCodeProperty.Value)) {
            throw "$Context contains a NotChecked detail without VerificationReasonCode"
        }
        if ([string]$reasonCodeProperty.Value -cnotmatch '^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$') {
            throw "$Context contains an invalid VerificationReasonCode: $($reasonCodeProperty.Value)"
        }
        if ($null -eq $evidenceSourceProperty -or
            [string]::IsNullOrWhiteSpace([string]$evidenceSourceProperty.Value)) {
            throw "$Context contains a NotChecked detail without VerificationEvidenceSource"
        }
        if ($null -eq $affectedProperty) {
            throw "$Context contains a NotChecked detail without AffectedTargetCount"
        }
        $checkStateProperty = $detail.PSObject.Properties['CheckState']
        if ($null -eq $checkStateProperty -or [string]$checkStateProperty.Value -cne 'NotChecked') {
            throw "$Context contains a disposition detail whose CheckState is not NotChecked"
        }

        $disposition = [string]$dispositionProperty.Value
        if ($disposition -cnotin @('ByChoice', 'NoSavedChoice', 'CannotVerify')) {
            throw "$Context contains an invalid VerificationDisposition: $disposition"
        }

        $evidenceSource = [string]$evidenceSourceProperty.Value
        $validEvidenceSources = switch ($disposition) {
            'ByChoice' { @('ApplyIntent', 'WindowsState') }
            'NoSavedChoice' { @('None') }
            'CannotVerify' { @('RuntimeQuery') }
        }
        if ($evidenceSource -cnotin $validEvidenceSources) {
            throw "$Context contains invalid evidence source '$evidenceSource' for $disposition"
        }

        $affectedText = [Convert]::ToString(
            $affectedProperty.Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
        $affectedLong = [long]0
        if (-not [long]::TryParse(
                $affectedText,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$affectedLong
            ) -or $affectedLong -gt [int]::MaxValue) {
            throw "$Context contains a non-integer AffectedTargetCount"
        }
        $affected = [int]$affectedLong
        if ($affected -lt 1) {
            throw "$Context contains a non-positive AffectedTargetCount: $affected"
        }
        if ($affectedTotal -gt ([int]::MaxValue - $affected)) {
            throw "$Context affected-target count exceeds Int32 capacity"
        }

        $counts[$disposition] = [int]$counts[$disposition] + $affected
        $affectedTotal += $affected
    }

    if ($affectedTotal -ne $ExpectedCount) {
        throw "$Context NotChecked details cover $affectedTotal target(s); expected $ExpectedCount"
    }

    return [PSCustomObject][ordered]@{
        Total           = $affectedTotal
        ByChoice        = [int]$counts.ByChoice
        NoSavedChoice   = [int]$counts.NoSavedChoice
        CannotVerify    = [int]$counts.CannotVerify
        Unresolved      = [int]$counts.NoSavedChoice + [int]$counts.CannotVerify
        DetailRows      = @($Details).Count
    }
}

function Get-VerificationScopeUnavailableResult {
    <#
    .SYNOPSIS
        Builds the result of a verification area whose checks could not be executed.

    .DESCRIPTION
        An error while an area is measured says nothing about the settings of
        the PC: a query, a helper or the declared scope failed. The area is
        reported as not checked (CannotVerify) with one weighted row that
        names the error, never as measured mismatches. The verdict stays
        failed, because a required check passes only when it is proven; the
        counts tell "differs" and "could not be read" apart.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Setting', 'Policy', 'Rule', 'Check')][string]$LabelProperty,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Label,
        [Parameter()][AllowEmptyString()][string]$Path = '',
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Expected,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ReasonCode,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$Total,
        [Parameter()][ValidateRange(0, [int]::MaxValue)][int]$NotApplicable = 0,
        [Parameter()][AllowEmptyCollection()][object[]]$NotApplicableDetails = @()
    )

    if ($NotApplicable -gt $Total) {
        throw "Verification area '$Category' has more not-applicable targets than declared targets"
    }
    $unavailable = $Total - $NotApplicable
    $details = @()
    if ($unavailable -gt 0) {
        $detail = [ordered]@{ $LabelProperty = $Label }
        if (-not [string]::IsNullOrWhiteSpace($Path)) { $detail.Path = $Path }
        $detail.Expected = $Expected
        $detail.Actual = "Could not be verified: $Message"
        $detail.CheckState = 'NotChecked'
        $detail.VerificationDisposition = 'CannotVerify'
        $detail.VerificationEvidenceSource = 'RuntimeQuery'
        $detail.VerificationReasonCode = $ReasonCode
        $detail.AffectedTargetCount = $unavailable
        $details = @([PSCustomObject]$detail)
    }
    $accounting = Get-VerificationNotCheckedAccounting -Details $details -ExpectedCount $unavailable `
        -Context "Verification area '$Category' (not executable)"

    return [PSCustomObject][ordered]@{
        Category                = $Category
        Total                   = $Total
        Passed                  = 0
        Failed                  = 0
        NotChecked              = $unavailable
        NotCheckedDeliberate    = [int]$accounting.ByChoice
        NotCheckedNoSavedChoice = [int]$accounting.NoSavedChoice
        NotCheckedCannotVerify  = [int]$accounting.CannotVerify
        NotApplicable           = $NotApplicable
        PassedDetails           = @()
        FailedDetails           = @()
        NotCheckedDetails       = $details
        NotApplicableDetails    = @($NotApplicableDetails)
    }
}
