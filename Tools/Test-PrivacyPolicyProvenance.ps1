#Requires -Version 5.1

<#
.SYNOPSIS
    Validate high-risk Privacy policy semantics against the inbox ADMX definitions.

.DESCRIPTION
    Exact registry readback cannot detect a semantically wrong ADMX value. This
    gate binds the Strict/Paranoid JSON provenance and values to the actual
    SettingSync, Messaging, GroupPolicy and DeviceSetup ADMX contracts on a
    supported Windows release image.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AdmxPath = (Join-Path $env:SystemRoot 'PolicyDefinitions\SettingSync.admx'),

    [Parameter(Mandatory = $false)]
    [string]$PolicyDefinitionsRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$targetsValidated = 0
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($PolicyDefinitionsRoot)) {
    $PolicyDefinitionsRoot = Split-Path -Parent $AdmxPath
}
if (-not (Test-Path -LiteralPath $AdmxPath -PathType Leaf)) {
    throw "SettingSync ADMX is missing: $AdmxPath"
}
[xml]$admx = Get-Content -LiteralPath $AdmxPath -Raw -Encoding UTF8 -ErrorAction Stop

function Get-InboxAdmxPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$PolicyName
    )
    $path = Join-Path $PolicyDefinitionsRoot $FileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Inbox ADMX is missing: $path"
    }
    [xml]$document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
    $policy = $document.SelectSingleNode("//*[local-name()='policy' and @name='$PolicyName']")
    if ($null -eq $policy) { throw "$FileName lacks policy '$PolicyName'" }
    return [PSCustomObject]@{
        FileName = $FileName
        Path = $path
        Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Policy = $policy
    }
}

function Get-PolicyNode {
    param([Parameter(Mandatory = $true)][string]$Name)
    $node = $admx.SelectSingleNode("//*[local-name()='policy' and @name='$Name']")
    if ($null -eq $node) { throw "SettingSync ADMX lacks policy '$Name'" }
    return $node
}

$disable = Get-PolicyNode -Name 'DisableSettingSync'
$backup = Get-PolicyNode -Name 'EnableWindowsBackup'
$disableEnabled = $disable.SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
$override = $disable.SelectSingleNode("./*[local-name()='elements']/*[@id='CheckBox_UserOverride']")
$overrideFalse = $override.SelectSingleNode("./*[local-name()='falseValue']/*[local-name()='decimal']")
$backupDisabled = $backup.SelectSingleNode("./*[local-name()='disabledValue']/*[local-name()='decimal']")
if ([string]$disable.key -cne 'Software\Policies\Microsoft\Windows\SettingSync' -or
    [string]$disable.valueName -cne 'DisableSettingSync' -or
    [int]$disableEnabled.value -ne 2 -or
    [string]$override.valueName -cne 'DisableSettingSyncUserOverride' -or
    [int]$overrideFalse.value -ne 1 -or
    [string]$backup.key -cne 'Software\Policies\Microsoft\Windows\SettingSync' -or
    [string]$backup.valueName -cne 'EnableWindowsBackup' -or
    [int]$backupDisabled.value -ne 0) {
    throw 'Inbox SettingSync ADMX no longer matches the sealed NoID Privacy semantic contract'
}

$messageContract = Get-InboxAdmxPolicy -FileName 'messaging.admx' -PolicyName 'AllowMessageSync'
$fontContract = Get-InboxAdmxPolicy -FileName 'GroupPolicy.admx' -PolicyName 'EnableFontProviders'
$metadataContract = Get-InboxAdmxPolicy -FileName 'DeviceSetup.admx' -PolicyName 'DeviceMetadata_PreventDeviceMetadataFromNetwork'
$messageDisabled = $messageContract.Policy.SelectSingleNode("./*[local-name()='disabledValue']/*[local-name()='decimal']")
$fontDisabled = $fontContract.Policy.SelectSingleNode("./*[local-name()='disabledValue']/*[local-name()='decimal']")
$metadataEnabled = $metadataContract.Policy.SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
if ([string]$messageContract.Policy.key -cne 'Software\Policies\Microsoft\Windows\Messaging' -or
    [string]$messageContract.Policy.valueName -cne 'AllowMessageSync' -or [int]$messageDisabled.value -ne 0 -or
    [string]$fontContract.Policy.key -cne 'Software\Policies\Microsoft\Windows\System' -or
    [string]$fontContract.Policy.valueName -cne 'EnableFontProviders' -or [int]$fontDisabled.value -ne 0 -or
    [string]$metadataContract.Policy.key -cne 'SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -or
    [string]$metadataContract.Policy.valueName -cne 'PreventDeviceMetadataFromNetwork' -or
    [int]$metadataEnabled.value -ne 1) {
    throw 'Inbox Messaging/Font/Device-Metadata ADMX semantics no longer match the sealed NoID Privacy contract'
}

foreach ($mode in @('Strict', 'Paranoid')) {
    $path = Join-Path $root "Modules\Privacy\Config\Privacy-$mode.json"
    $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $values = $config.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
    $contracts = @(
        @{ Name='DisableSettingSync'; Value=2; Policy='DisableSettingSync'; State='Enabled'; Element=$null },
        @{ Name='DisableSettingSyncUserOverride'; Value=1; Policy='DisableSettingSync'; State=$null; Element='CheckBox_UserOverride' },
        @{ Name='EnableWindowsBackup'; Value=0; Policy='EnableWindowsBackup'; State='Disabled'; Element=$null }
    )
    foreach ($contract in $contracts) {
        $definition = $values.PSObject.Properties[[string]$contract.Name].Value
        if ([string]$definition.Type -cne 'DWord' -or [int]$definition.Value -ne [int]$contract.Value -or
            [string]$definition.Provenance.AdmxFile -cne 'SettingSync.admx' -or
            [string]$definition.Provenance.AdmxPolicy -cne [string]$contract.Policy -or
            [int]$definition.Provenance.AdmxValue -ne [int]$contract.Value -or
            [string]::IsNullOrWhiteSpace([string]$definition.Provenance.PrimarySource)) {
            throw "$mode Privacy ADMX provenance/value contract failed: $($contract.Name)"
        }
        if ($null -ne $contract.State -and
            [string]$definition.Provenance.AdmxState -cne [string]$contract.State) {
            throw "$mode Privacy ADMX state contract failed: $($contract.Name)"
        }
        if ($null -ne $contract.Element -and
            ([string]$definition.Provenance.AdmxElement -cne [string]$contract.Element -or
                [bool]$definition.Provenance.AdmxElementState)) {
            throw "$mode Privacy ADMX element contract failed: $($contract.Name)"
        }
        $targetsValidated++
    }
}

$profileContracts = @(
    @{ Mode='Strict'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging'; Name='AllowMessageSync'; Value=0; File='messaging.admx'; Policy='AllowMessageSync'; State='Disabled' },
    @{ Mode='Paranoid'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging'; Name='AllowMessageSync'; Value=0; File='messaging.admx'; Policy='AllowMessageSync'; State='Disabled' },
    @{ Mode='Paranoid'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableFontProviders'; Value=0; File='GroupPolicy.admx'; Policy='EnableFontProviders'; State='Disabled' },
    @{ Mode='Paranoid'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; Name='PreventDeviceMetadataFromNetwork'; Value=1; File='DeviceSetup.admx'; Policy='DeviceMetadata_PreventDeviceMetadataFromNetwork'; State='Enabled' }
)
foreach ($contract in $profileContracts) {
    $configPath = Join-Path $root "Modules\Privacy\Config\Privacy-$($contract.Mode).json"
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $section = $config.InputAndSync.PSObject.Properties[[string]$contract.Path]
    $definitionProperty = if ($null -ne $section) {
        $section.Value.PSObject.Properties[[string]$contract.Name]
    }
    else { $null }
    $definition = if ($null -ne $definitionProperty) { $definitionProperty.Value } else { $null }
    if ($null -eq $definition -or [string]$definition.Type -cne 'DWord' -or
        [int]$definition.Value -ne [int]$contract.Value -or
        [string]$definition.Provenance.AdmxFile -cne [string]$contract.File -or
        [string]$definition.Provenance.AdmxPolicy -cne [string]$contract.Policy -or
        [string]$definition.Provenance.AdmxState -cne [string]$contract.State -or
        [int]$definition.Provenance.AdmxValue -ne [int]$contract.Value -or
        [string]::IsNullOrWhiteSpace([string]$definition.Provenance.PrimarySource)) {
        throw "$($contract.Mode) Privacy ADMX provenance/value contract failed: $($contract.Name)"
    }
    $targetsValidated++
}

$admxEvidence = @(
    [PSCustomObject]@{ FileName='SettingSync.admx'; Path=$AdmxPath; Sha256=(Get-FileHash -LiteralPath $AdmxPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() },
    [PSCustomObject]@{ FileName=$messageContract.FileName; Path=$messageContract.Path; Sha256=$messageContract.Sha256 },
    [PSCustomObject]@{ FileName=$fontContract.FileName; Path=$fontContract.Path; Sha256=$fontContract.Sha256 },
    [PSCustomObject]@{ FileName=$metadataContract.FileName; Path=$metadataContract.Path; Sha256=$metadataContract.Sha256 }
)

[PSCustomObject]@{
    Success = $true
    AdmxPath = $AdmxPath
    AdmxSha256 = [string]$admxEvidence[0].Sha256
    AdmxFiles = $admxEvidence
    Modes = @('Strict', 'Paranoid')
    TargetsValidated = $targetsValidated
}
