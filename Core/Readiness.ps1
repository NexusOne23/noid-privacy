#Requires -Version 5.1

function Get-NoIDASRReadiness {
    <# Read-only prerequisite evidence. No policy writes and no network probe. #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $defender = 'Unknown'
    try {
        $states = @(Get-MpComputerStatus -ErrorAction Stop)
        if ($states.Count -ne 1 -or
            -not $states[0].PSObject.Properties['AMRunningMode'] -or
            -not $states[0].PSObject.Properties['AntivirusEnabled'] -or
            -not $states[0].PSObject.Properties['RealTimeProtectionEnabled'] -or
            $states[0].AntivirusEnabled -isnot [bool] -or
            $states[0].RealTimeProtectionEnabled -isnot [bool] -or
            [string]::IsNullOrWhiteSpace([string]$states[0].AMRunningMode)) {
            throw 'Defender returned incomplete status information'
        }
        $defender = if ([string]$states[0].AMRunningMode -ceq 'Normal' -and
            $states[0].AntivirusEnabled -and $states[0].RealTimeProtectionEnabled) { 'Active' } else { 'Unavailable' }
    }
    catch { $defender = 'Unknown' }

    $cloud = 'Unknown'
    if ($defender -eq 'Active') {
        try {
            $preferences = @(Get-MpPreference -ErrorAction Stop)
            if ($preferences.Count -ne 1 -or -not $preferences[0].PSObject.Properties['MAPSReporting']) {
                throw 'Defender returned no cloud-protection setting'
            }
            $membership = $preferences[0].MAPSReporting
            $integer = $membership -is [byte] -or $membership -is [sbyte] -or
                $membership -is [int16] -or $membership -is [uint16] -or
                $membership -is [int32] -or $membership -is [uint32] -or
                $membership -is [int64] -or $membership -is [uint64]
            if (-not $integer -or $membership -notin @(0, 1, 2)) { throw 'Invalid cloud-protection setting' }
            $cloud = if ($membership -eq 0) { 'Disabled' } else { 'Enabled' }
        }
        catch { $cloud = 'Unknown' }
    }
    return [PSCustomObject]@{ Defender = $defender; CloudProtection = $cloud }
}

function Get-NoIDHardeningReadiness {
    <# The CLI and GUI read the same engine-owned edition/management rules. #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'Modules/ASR/Private/Test-ConfigMgrPresence.ps1')
    . (Join-Path $root 'Modules/AdvancedSecurity/Private/Get-AdvancedSecurityApplicability.ps1')
    . (Join-Path $root 'Modules/Privacy/Private/Get-PrivacyManagementState.ps1')
    $asr = Get-NoIDASRReadiness
    $configMgr = Test-ConfigMgrPresence
    $rdp = $null; $wireless = $null; $edition = 'Unknown'
    try {
        $advanced = Get-AdvancedSecurityApplicability
        $rdp = [bool]$advanced.RdpHostSupported
        $wireless = [bool]$advanced.WirelessDisplaySupported
        $edition = [string]$advanced.EditionFamily
    }
    catch { Write-Log -Level WARNING -Message 'Windows edition support could not be checked.' -Module 'Readiness' }
    $management = Get-PrivacyManagementState
    return [PSCustomObject][ordered]@{
        SchemaVersion = 1
        Defender = [string]$asr.Defender
        CloudProtection = [string]$asr.CloudProtection
        ConfigMgrDetected = $configMgr
        Edition = $edition
        RdpHostSupported = $rdp
        WirelessDisplaySupported = $wireless
        ManagementStateKnown = [bool]$management.StateKnown
        ExternallyManaged = [bool]$management.ExternallyManaged
    }
}

function Get-NoIDASRPreflightDecision {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)][PSCustomObject]$Readiness,
        [Parameter(Mandatory = $true)][bool]$ContinueWithoutCloud,
        [Parameter(Mandatory = $true)][bool]$AllowPartialHardening
    )
    if ([string]$Readiness.Defender -cnotin @('Active','Unavailable','Unknown') -or
        [string]$Readiness.CloudProtection -cnotin @('Enabled','Disabled','Unknown')) {
        throw 'Invalid ASR readiness contract'
    }
    $reason = if ($Readiness.Defender -eq 'Unavailable') { 'DefenderUnavailable' }
        elseif ($Readiness.Defender -eq 'Unknown') { 'DefenderUnknown' }
        elseif ($Readiness.CloudProtection -ne 'Enabled' -and -not $ContinueWithoutCloud) { 'CloudProtectionRequired' }
        else { '' }
    return [PSCustomObject]@{
        Blocked = -not [string]::IsNullOrEmpty($reason) -and -not $AllowPartialHardening
        SkipASR = -not [string]::IsNullOrEmpty($reason) -and $AllowPartialHardening
        Reason = $reason
    }
}
