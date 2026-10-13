#Requires -Version 5.1

function Get-NoIDXboxActionTargetIds {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $catalog = Get-NoIDXboxComponentCatalog
    $ids = @(Get-NoIDXboxSettingsRegistryTargets | ForEach-Object { 'registry:'+$_.Path+'::'+$_.Name })
    $ids += @($catalog.Services | ForEach-Object { 'service:'+$_ })
    $ids += 'scheduled-task:'+$catalog.TaskPath+$catalog.TaskName
    $ids += @($catalog.Apps | ForEach-Object { 'user-app:'+ $_.PackageFamilyName })
    $sorted = [string[]]$ids
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    return $sorted
}

function Assert-NoIDXboxActionTargets {
    <# Validate both the original-user binding and the complete closed observations. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Targets)

    Assert-NoIDXboxObjectFields $Targets @('userSid','sessionId','settings','components')
    if ($Targets.userSid -isnot [string] -or $Targets.userSid -cnotmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or
        $Targets.sessionId -isnot [int] -or $Targets.sessionId -lt 1) {
        throw 'Xbox action targets have an invalid desktop identity'
    }
    $components = $Targets.components
    Assert-NoIDXboxObjectFields $components @(
        'UserSid','Apps','RemovablePackages','Services','Task','RecordingAllowed','RecordingPolicySupported',
        'RemovalBlocked','Applicability','RecordingPolicy','RemovalPolicyEnabled','RemovalPolicyValues','DynamicRemovalList'
    )
    if ($components.UserSid -cne $Targets.userSid) { throw 'Xbox action targets disagree about the desktop identity' }
    Assert-NoIDXboxSettingsState $Targets.settings
    $null = Resolve-NoIDXboxComponentState $components
    $null = Get-NoIDXboxRemovalPolicyPlan $components
    Assert-NoIDXboxObjectFields $components.Applicability @(
        'RecordingPolicySupported','RemovalPolicySupported','ManagementStateKnown','DomainJoined','MdmRegistered'
    )
    Assert-NoIDXboxRemovalRequest -Entries @($components.RemovablePackages)
    foreach ($definition in (Get-NoIDXboxComponentCatalog).Apps) {
        $app = @($components.Apps | Where-Object Name -CEQ $definition.Name)[0]
        Assert-NoIDXboxObjectFields $app @('Name','Present','Healthy')
        if ($app.Present -ne (@($components.RemovablePackages | Where-Object AppName -CEQ $definition.Name).Count -gt 0)) {
            throw 'Xbox registration and removal inventories disagree'
        }
    }
    $policyValues = @($components.RecordingPolicy) + @($components.RemovalPolicyValues) + @($components.DynamicRemovalList)
    foreach ($value in $Targets.settings.RegistryValues) {
        $matching = @($policyValues | Where-Object { $_.path -ceq $value.path -and $_.name -ceq $value.name })
        if ($matching.Count -ne 1 -or
            (Get-QuickActionObjectSha256 $matching[0]) -cne (Get-QuickActionObjectSha256 $value)) {
            throw 'Xbox registry settings changed during the state read'
        }
    }
    foreach ($service in $Targets.settings.Services) {
        $matching = @($components.Services | Where-Object Name -CEQ $service.name)[0]
        Assert-NoIDXboxObjectFields $matching @('Name','Exists','StartType','Status')
        if ($matching.Exists -ne $service.exists -or $matching.StartType -cne $service.startType -or
            $matching.Status -cne $service.status) {
            throw 'Xbox service settings changed during the state read'
        }
    }
    if ((Get-QuickActionObjectSha256 $components.Task) -cne (Get-QuickActionObjectSha256 $Targets.settings.Task)) {
        throw 'Xbox scheduled task changed during the state read'
    }
    $recordingAllowed = Get-NoIDXboxPolicyFlag $components.RecordingPolicy -Default $true
    if ($components.RecordingAllowed -ne $recordingAllowed -or
        $components.RecordingPolicySupported -ne $components.Applicability.RecordingPolicySupported) {
        throw 'Xbox recording policy summary disagrees with its measured values'
    }
    $nativePaths = @(Get-NoIDXboxNativeRemovalPolicyPaths)
    $removalEnabled = (Get-NoIDXboxPolicyFlag $components.RemovalPolicyEnabled) -and $components.Applicability.RemovalPolicySupported
    $blocked = $false
    if ($removalEnabled) {
        foreach ($value in $components.RemovalPolicyValues) {
            if ($value.path -cin $nativePaths -and (Get-NoIDXboxPolicyFlag $value)) { $blocked = $true }
        }
        if ($components.DynamicRemovalList.valueExisted -and
            @($components.DynamicRemovalList.value | Where-Object { $_ -iin (Get-NoIDXboxComponentCatalog).Apps.PackageFamilyName }).Count -gt 0) {
            $blocked = $true
        }
    }
    if ($components.RemovalBlocked -ne $blocked) { throw 'Xbox removal policy summary disagrees with its measured values' }
}

function Get-NoIDXboxActionState {
    <#
    .SYNOPSIS
        Reads the Xbox switch without installing apps or creating a backup.
    .DESCRIPTION
        Mixed remains actionable so either direction can complete a partial
        setup. Policy ownership and inconsistent or failed Windows reads cannot
        grant write access. The full fingerprint binds the original desktop,
        exact removable parents and configuration shown to the user.
    #>
    [CmdletBinding()]
    param()

    $user = Get-PrivacyUserContext -Refresh
    $components = Get-NoIDXboxComponentSnapshot -UserSid $user.Sid
    $settings = Get-NoIDXboxSettingsState
    $targets = [pscustomobject][ordered]@{
        userSid=$user.Sid;sessionId=$user.SessionId;settings=$settings;components=$components
    }
    Assert-NoIDXboxActionTargets $targets
    $currentUser = Get-PrivacyUserContext -Refresh
    if ($currentUser.Sid -cne $user.Sid -or $currentUser.SessionId -ne $user.SessionId) {
        throw 'Xbox desktop identity changed during the state read'
    }
    $state = Resolve-NoIDXboxComponentState $components
    $ownership = $components.Applicability
    $actionable = $ownership.ManagementStateKnown -and -not $ownership.DomainJoined -and -not $ownership.MdmRegistered
    $reason = if ($actionable) { '' } else {
        'Xbox settings are managed by your organization or device management could not be checked'
    }
    return Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State $state `
        -Actionable:$actionable -Reason $reason -TargetIds (Get-NoIDXboxActionTargetIds) -Targets $targets
}

function Assert-NoIDXboxActionState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    Assert-NoIDXboxObjectFields $State @(
        'schemaVersion','actionId','owningModule','state','actionable','reason','targetIds','targets','fingerprint'
    )
    if ($State.schemaVersion -isnot [int] -or $State.schemaVersion -ne 1 -or
        $State.actionId -cne 'Xbox' -or $State.owningModule -cne 'SecurityBaseline' -or
        $State.state -cnotin @('Enable','Disable','Mixed') -or $State.actionable -isnot [bool] -or
        -not $State.actionable -or $State.reason -cne '' -or
        $State.fingerprint -isnot [string] -or $State.fingerprint -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Xbox action state has an invalid identity or is not actionable'
    }
    Assert-NoIDXboxActionTargets $State.targets
    $ownership = $State.targets.components.Applicability
    if (-not $ownership.ManagementStateKnown -or $ownership.DomainJoined -or $ownership.MdmRegistered) {
        throw 'Xbox action state does not grant authority on a managed device'
    }
    $ids = @(Get-NoIDXboxActionTargetIds)
    if (($ids -join "`0") -cne (@($State.targetIds) -join "`0")) {
        throw 'Xbox action state does not declare its exact target set'
    }
    $observed = Resolve-NoIDXboxComponentState $State.targets.components
    if ($State.state -cne $observed) { throw 'Xbox action state disagrees with its observations' }
    $expected = Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State $observed `
        -Actionable:$true -TargetIds $ids -Targets $State.targets
    if ($State.fingerprint -cne $expected.fingerprint) { throw 'Xbox action state fingerprint is invalid' }
}
