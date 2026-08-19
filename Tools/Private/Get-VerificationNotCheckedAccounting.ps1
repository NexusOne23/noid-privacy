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
        unknown 117-target Privacy profile, without losing count integrity.
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
