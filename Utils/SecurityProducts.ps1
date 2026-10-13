#Requires -Version 5.1

function Test-IsMicrosoftDefenderSecurityCenterProduct {
    <#
    .SYNOPSIS
        Identifies the first-party Defender Security Center record without a
        localized display-name comparison.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Product
    )

    # SecurityCenter2 identity data is stable; DisplayName is presentation text
    # and can be localized, so it must never decide third-party status.
    $defenderInstanceId = '{D68DDC3A-831F-4FAE-9E44-DA132C1ACF46}'
    $instanceId = [string]$Product.instanceGuid
    if (-not [string]::IsNullOrWhiteSpace($instanceId) -and
        $instanceId.Equals($defenderInstanceId, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    foreach ($propertyName in @('pathToSignedProductExe', 'pathToSignedReportingExe')) {
        $property = $Product.PSObject.Properties[$propertyName]
        if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            continue
        }

        $identity = ([string]$property.Value).Trim().Trim('"')
        if ($identity.StartsWith('windowsdefender://', [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }

        $leaf = [IO.Path]::GetFileName($identity)
        if ($leaf -and $leaf.Equals('MsMpEng.exe', [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}
