#Requires -Version 5.1

# Comparison labels only. These projections never authorize a Windows write,
# restore apps or replace another module's profile and removal choices.
. (Join-Path $PSScriptRoot 'XboxComponents.ps1')

function Get-NoIDXboxIntentRegistryTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('SecurityBaseline','Privacy')][string]$ModuleName)

    $catalog = Get-NoIDXboxComponentCatalog
    if ($ModuleName -ceq 'SecurityBaseline') {
        [pscustomobject]@{Path=$catalog.RecordingPolicyPath;Name=$catalog.RecordingPolicyName;Type='DWord'}
    }
    else {
        foreach ($app in @($catalog.Apps | Where-Object Name -CIn @(
            'Microsoft.GamingApp','Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay','Microsoft.Xbox.TCUI'
        ))) {
            [pscustomobject]@{Path=$catalog.RemovalPolicyRoot+'\'+$app.PackageFamilyName;Name='RemovePackage';Type='DWord'}
        }
        [pscustomobject]@{Path=$catalog.RemovalPolicyRoot;Name='DynamicRemovalList';Type='MultiString'}
    }
}

function Assert-NoIDXboxIntentProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Projection,
        [Parameter(Mandatory)][ValidateSet('SecurityBaseline','Privacy')][string]$ModuleName
    )

    $fields = @('registryValues')
    if ($ModuleName -ceq 'SecurityBaseline') { $fields += 'services' }
    $null = Assert-NoIDIntentExactProperties $Projection $fields 'Xbox intent projection'
    $targets = @(Get-NoIDXboxIntentRegistryTargets $ModuleName)
    if (@($Projection.registryValues).Count -ne $targets.Count) { throw 'Xbox intent registry scope is incomplete' }
    foreach ($target in $targets) {
        $identityMatches = @($Projection.registryValues | Where-Object { $_.path -ceq $target.Path -and $_.name -ceq $target.Name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox intent registry identity is missing or duplicated' }
        $value = $identityMatches[0]
        $null = Assert-NoIDIntentExactProperties $value @('path','name','present','value') 'Xbox intent registry value'
        if ($value.present -isnot [bool]) { throw 'Xbox intent registry presence is invalid' }
        if (-not $value.present) {
            if ($null -ne $value.value) { throw 'Xbox intent absent value contains invented data' }
        }
        elseif ($target.Type -ceq 'DWord') {
            if (($value.value -isnot [int] -and $value.value -isnot [long]) -or $value.value -notin @(0,1)) {
                throw 'Xbox intent registry flag is invalid'
            }
        }
        else {
            $families = @((Get-NoIDXboxComponentCatalog).Apps.PackageFamilyName)
            if ($value.value -isnot [array] -or $value.value.Count -gt $families.Count -or
                @($value.value | Where-Object { $_ -isnot [string] -or $_ -cnotin $families }).Count -gt 0 -or
                @($value.value | Sort-Object -Unique).Count -ne $value.value.Count) {
                throw 'Xbox intent dynamic list contains an unrelated or duplicate package'
            }
        }
    }
    if ($ModuleName -ceq 'SecurityBaseline') {
        $names = @((Get-NoIDXboxComponentCatalog).Services)
        if (@($Projection.services).Count -ne $names.Count) { throw 'Xbox intent service scope is incomplete' }
        foreach ($name in $names) {
            $identityMatches = @($Projection.services | Where-Object name -CEQ $name)
            if ($identityMatches.Count -ne 1) { throw 'Xbox intent service identity is missing or duplicated' }
            $service = $identityMatches[0]
            $null = Assert-NoIDIntentExactProperties $service @('name','exists','startType') 'Xbox intent service'
            if ($service.exists -isnot [bool] -or
                ($service.exists -and $service.startType -cnotin @('Automatic','Manual','Disabled')) -or
                (-not $service.exists -and $null -ne $service.startType)) { throw 'Xbox intent service state is invalid' }
        }
    }
}

function New-NoIDXboxIntentProjection {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification='Pure in-memory projection; no system state is changed.')]
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][ValidateSet('SecurityBaseline','Privacy')][string]$ModuleName
    )

    Assert-NoIDXboxSettingsState $Settings
    $families = @((Get-NoIDXboxComponentCatalog).Apps.PackageFamilyName)
    $projection = [pscustomobject][ordered]@{
        registryValues = @(foreach ($target in @(Get-NoIDXboxIntentRegistryTargets $ModuleName)) {
            $record = @($Settings.RegistryValues | Where-Object { $_.path -ceq $target.Path -and $_.name -ceq $target.Name })[0]
            $value = $record.value
            if ($record.valueExisted -and $target.Type -ceq 'MultiString') {
                # Preserve the original Privacy expectation for non-Xbox
                # entries. Their current presence cannot become an exception.
                $value = @($families | Where-Object { $_ -in @($record.value) })
            }
            [pscustomobject][ordered]@{path=$target.Path;name=$target.Name;present=[bool]$record.valueExisted;value=$value}
        })
    }
    if ($ModuleName -ceq 'SecurityBaseline') {
        $projection | Add-Member -NotePropertyName services -NotePropertyValue @($Settings.Services | ForEach-Object {
            [pscustomobject][ordered]@{name=$_.name;exists=[bool]$_.exists;startType=$_.startType}
        })
    }
    Assert-NoIDXboxIntentProjection $projection $ModuleName
    return $projection
}

function Update-NoIDXboxIntentState {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification='Optional comparison-label bookkeeping after a confirmed and verified Xbox operation.')]
    param(
        [Parameter(Mandatory)][ValidateSet('QuickActionApply','QuickActionRestore','QuickActionLiveConfirmation')][string]$SourceKind,
        [string]$SessionPath,
        $LiveState
    )

    $state = Read-NoIDIntentState -AllowMissing
    if (-not $state) { return $true }
    if ($SourceKind -ceq 'QuickActionLiveConfirmation') {
        Assert-NoIDXboxActionState $LiveState
        if (-not $LiveState.actionable -or $LiveState.state -cnotin @('Enable','Disable')) {
            throw 'Xbox intent requires a complete confirmed state'
        }
        $settings = $LiveState.targets.settings
        $sourceId = 'Xbox'
        $evidence = $LiveState.fingerprint
    }
    else {
        $document = Get-NoIDXboxSessionDocument -SessionPath $SessionPath -AllowIncomplete
        $sourceId = $document.Manifest.sessionId
        if ($SourceKind -ceq 'QuickActionApply') {
            if ($document.Manifest.status -cne 'Applied') { throw 'Xbox intent Apply requires a sealed successful session' }
            if (Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest) {
                throw 'Xbox intent cannot reapply a restored session'
            }
            $settings = $document.PostState.targets.settings
            $evidence = (Get-FileHash -LiteralPath (Join-Path $document.SessionPath 'manifest.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
        else {
            $receipt = Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest
            if (-not $receipt -or 'action:Xbox' -cnotin @($receipt.restoredScopes)) {
                throw 'Xbox intent Restore requires a validated settings receipt'
            }
            $settings = $document.PreState.targets.settings
            $evidence = (Get-FileHash -LiteralPath (Join-Path $document.SessionPath 'restore-receipt.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
    }
    # The mutation owner still holds the mutex. Never relabel a stale receipt
    # or session after another operation has changed the current settings.
    if ((Get-QuickActionObjectSha256 (Get-NoIDXboxSettingsState)) -cne (Get-QuickActionObjectSha256 $settings)) {
        throw 'Xbox intent evidence no longer matches current settings'
    }
    $stamp = [DateTime]::UtcNow.ToString('o')
    $touched = $false
    foreach ($moduleName in @('SecurityBaseline','Privacy')) {
        $property = $state.modules.PSObject.Properties[$moduleName]
        if (-not $property) { continue }
        $record = $property.Value
        $projection = New-NoIDXboxIntentProjection -Settings $settings -ModuleName $moduleName
        if ($record.intent.PSObject.Properties['xboxSettings'] -and
            (Get-QuickActionObjectSha256 $record.intent.xboxSettings) -ceq (Get-QuickActionObjectSha256 $projection)) { continue }
        $record.intent | Add-Member -NotePropertyName xboxSettings -NotePropertyValue $projection -Force
        $record.recordedAt=$stamp; $record.sourceKind=$SourceKind; $record.sourceId=$sourceId; $record.sourceEvidenceSha256=$evidence
        $touched = $true
    }
    if (-not $touched) { return $true }
    $state.updatedAt = $stamp
    $null = Publish-NoIDIntentState -State $state
    $null = Assert-NoIDIntentState (Read-NoIDIntentState)
    return $true
}

function Get-NoIDXboxIntentRegistryResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Expected)

    $type = if ($Expected.name -ceq 'DynamicRemovalList') { 'MultiString' } else { 'DWord' }
    $expectedValue = $Expected.value
    if ($type -ceq 'MultiString' -and $Expected.present) { $expectedValue = @($Expected.value | Sort-Object) }
    $expectedText = if ($Expected.present) { $type+'/'+(ConvertTo-Json -InputObject $expectedValue -Compress) } else { 'Absent' }
    $actualText = 'Absent'
    $present = $false
    $valueMatches = $false
    try { $key = Get-Item -LiteralPath $Expected.path -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { $key = $null }
    if ($key -and @($key.GetValueNames()) -contains $Expected.name) {
        $present = $true
        $actualType = $key.GetValueKind($Expected.name).ToString()
        $value = $key.GetValue($Expected.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($actualType -ceq 'MultiString') { $value = @($value | Sort-Object) }
        $actualText = $actualType+'/'+(ConvertTo-Json -InputObject $value -Compress)
        $valueMatches = $Expected.present -and $actualType -ceq $type -and $actualText -ceq $expectedText
    }
    elseif (-not $Expected.present) { $valueMatches = $true }
    return [pscustomobject]@{Passed=[bool]$valueMatches;Expected=$expectedText+' (Xbox selection)';Actual=$actualText;Present=$present}
}

function Update-NoIDXboxIntentAfterChange {
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification='Optional comparison labels; the verified operation owns confirmation.')]
    param(
        [Parameter(Mandatory)][ValidateSet('QuickActionApply','QuickActionRestore','QuickActionLiveConfirmation')][string]$SourceKind,
        [string]$SessionPath,
        $LiveState
    )

    try {
        $null = Update-NoIDXboxIntentState @PSBoundParameters
        return ''
    }
    catch {
        $warning = 'Xbox settings were verified, but saved report choices could not be updated: '+$_.Exception.Message
        try { Write-Log -Level WARNING -Message $warning -Module QuickActions }
        catch { return $warning } # Logging must not undo a verified operation.
        return $warning
    }
}
