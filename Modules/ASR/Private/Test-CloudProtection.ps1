<#
.SYNOPSIS
    Verify cloud-delivered protection is configured as enabled

.DESCRIPTION
    Some ASR rules require cloud protection to be enabled
    Checks the documented MAPS membership returned by Get-MpPreference.
    This does not test connectivity or cloud enforcement at runtime.

.OUTPUTS
    Boolean - True only for Basic or Advanced MAPS membership
#>

function Test-ASRCloudProtectionPreference {
    <# Checks configuration only, never claims cloud connectivity or enforcement. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Preference)

    $membership = if ($null -ne $Preference -and $null -ne $Preference.PSObject.Properties['MAPSReporting']) {
        $Preference.MAPSReporting
    } else { $null }
    $isInteger = $membership -is [byte] -or $membership -is [sbyte] -or
        $membership -is [int16] -or $membership -is [uint16] -or
        $membership -is [int32] -or $membership -is [uint32] -or
        $membership -is [int64] -or $membership -is [uint64]
    return ($isInteger -and $membership -in @(1, 2))
}

function Test-CloudProtection {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        # Check via Get-MpPreference
        $mpPref = Get-MpPreference -ErrorAction Stop

        if (-not (Test-ASRCloudProtectionPreference -Preference $mpPref)) {
            Write-Log -Level WARNING -Message 'Cloud-delivered protection (MAPS) is disabled or its enabled configuration could not be established' -Module 'ASR'
            return $false
        }

        Write-Log -Level INFO -Message "Cloud-delivered protection is configured as enabled (MAPS: $($mpPref.MAPSReporting)); connectivity is not tested" -Module 'ASR'
        return $true
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to check cloud protection status: $_" -Module "ASR"
        return $false
    }
}
