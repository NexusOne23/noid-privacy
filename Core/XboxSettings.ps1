#Requires -Version 5.1

function Get-NoIDXboxSettingsRegistryTargets {
    [CmdletBinding()]
    param()

    $catalog = Get-NoIDXboxComponentCatalog
    [pscustomobject]@{Path=$catalog.RecordingPolicyPath;Name=$catalog.RecordingPolicyName;Type='DWord'}
    foreach ($app in $catalog.Apps) {
        [pscustomobject]@{Path=$catalog.RemovalPolicyRoot+'\'+$app.PackageFamilyName;Name='RemovePackage';Type='DWord'}
        if ($app.LegacyPolicyName) {
            [pscustomobject]@{Path=$catalog.RemovalPolicyRoot+'\'+$app.LegacyPolicyName;Name='RemovePackage';Type='DWord'}
        }
    }
    [pscustomobject]@{Path=$catalog.RemovalPolicyRoot;Name='DynamicRemovalList';Type='MultiString'}
}

function Assert-NoIDXboxObjectFields {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string[]]$Names)

    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count -or
        @(Compare-Object -ReferenceObject $Names -DifferenceObject $actual -CaseSensitive).Count -gt 0) {
        throw 'Xbox settings evidence has an unexpected field set'
    }
}

function Assert-NoIDXboxSettingsState {
    <# Validate the complete closed restore scope before the first write. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    Assert-NoIDXboxObjectFields $State @('SchemaVersion','RegistryValues','Services','Task')
    if ($State.SchemaVersion -isnot [int] -or $State.SchemaVersion -ne 1) {
        throw 'Xbox settings evidence has an unsupported schema'
    }
    $targets = @(Get-NoIDXboxSettingsRegistryTargets)
    $values = @($State.RegistryValues)
    if ($values.Count -ne $targets.Count) { throw 'Xbox settings registry scope is incomplete' }
    foreach ($target in $targets) {
        $identityMatches = @($values | Where-Object { $_.path -ceq $target.Path -and $_.name -ceq $target.Name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox settings registry scope contains a missing or duplicate identity' }
        $value = $identityMatches[0]
        Assert-NoIDXboxObjectFields $value @('kind','path','name','keyExisted','valueExisted','originalName','type','value','absentAncestorKeys')
        if ($value.kind -cne 'RegistryValue' -or $value.keyExisted -isnot [bool] -or $value.valueExisted -isnot [bool]) {
            throw 'Xbox settings registry existence is invalid'
        }
        if ($value.valueExisted) {
            if (-not $value.keyExisted -or $value.type -cne $target.Type -or
                [string]$value.originalName -ine $target.Name) {
                throw 'Xbox settings registry value has an invalid original identity or type'
            }
            if ($target.Type -ceq 'DWord') {
                if (($value.value -isnot [int] -and $value.value -isnot [long]) -or $value.value -notin @(0,1)) {
                    throw 'Xbox settings registry flag is not a measured DWORD'
                }
            }
            elseif ($null -eq $value.value -or $value.value -isnot [Array] -or
                @($value.value | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
                throw 'Xbox settings dynamic list is not a measured string array'
            }
        }
        elseif ($null -ne $value.originalName -or $null -ne $value.type -or $null -ne $value.value) {
            throw 'Xbox settings absent value contains invented data'
        }
        $ancestors = @($value.absentAncestorKeys)
        if (($value.keyExisted -and $ancestors.Count -ne 0) -or (-not $value.keyExisted -and $ancestors.Count -eq 0)) {
            throw 'Xbox settings absent-key evidence is inconsistent'
        }
        $expectedAncestor = [string]$target.Path
        foreach ($ancestor in $ancestors) {
            if ($ancestor -isnot [string] -or $ancestor -cne $expectedAncestor -or
                $ancestor -notmatch '^HKLM:\\SOFTWARE\\.+') {
                throw 'Xbox settings cleanup path escapes its exact ancestor chain'
            }
            $expectedAncestor = $expectedAncestor.Substring(0, $expectedAncestor.LastIndexOf('\'))
        }
    }

    $catalog = Get-NoIDXboxComponentCatalog
    if (@($State.Services).Count -ne $catalog.Services.Count) { throw 'Xbox settings service scope is incomplete' }
    foreach ($name in $catalog.Services) {
        $identityMatches = @($State.Services | Where-Object { $_.name -ceq $name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox settings service identity is missing or duplicated' }
        $service = $identityMatches[0]
        Assert-NoIDXboxObjectFields $service @('kind','name','exists','status','startType','delayedAutoStartExists','delayedAutoStart')
        if ($service.kind -cne 'Service' -or $service.exists -isnot [bool] -or $service.delayedAutoStartExists -isnot [bool]) {
            throw 'Xbox settings service evidence is malformed'
        }
        if ($service.exists) {
            if ($service.startType -cnotin @('Automatic','Manual','Disabled') -or $service.status -cnotin @('Running','Stopped','Paused') -or
                ($service.delayedAutoStartExists -and (($service.delayedAutoStart -isnot [int] -and $service.delayedAutoStart -isnot [long]) -or $service.delayedAutoStart -notin @(0,1))) -or
                (-not $service.delayedAutoStartExists -and $null -ne $service.delayedAutoStart)) {
                throw 'Xbox settings service state is unsupported'
            }
        }
        elseif ($null -ne $service.status -or $null -ne $service.startType -or $service.delayedAutoStartExists -or $null -ne $service.delayedAutoStart) {
            throw 'Xbox settings absent service contains invented data'
        }
    }
    Assert-NoIDXboxObjectFields $State.Task @('TaskPath','TaskName','Exists','Enabled')
    if ($State.Task.TaskPath -cne $catalog.TaskPath -or $State.Task.TaskName -cne $catalog.TaskName -or
        $State.Task.Exists -isnot [bool] -or
        ($State.Task.Exists -and $State.Task.Enabled -isnot [bool]) -or
        (-not $State.Task.Exists -and $null -ne $State.Task.Enabled)) {
        throw 'Xbox settings task identity or enabled state is invalid'
    }
}

function Get-NoIDXboxSettingsState {
    [CmdletBinding()]
    param()

    $catalog = Get-NoIDXboxComponentCatalog
    # A successful full enumeration distinguishes absence from a failed
    # per-name service query. The second read must agree about existence.
    $serviceNames = @(Get-Service -ErrorAction Stop | ForEach-Object Name)
    $services = @($catalog.Services | ForEach-Object {
        $state = Get-QuickActionServiceState -Name $_
        if ([bool]$state.exists -ne ($_ -in $serviceNames)) { throw 'Xbox service existence changed or could not be measured' }
        $state
    })
    $state = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RegistryValues = @(Get-NoIDXboxSettingsRegistryTargets | ForEach-Object {
            Get-QuickActionRegistryValueState -Path $_.Path -Name $_.Name
        })
        Services = $services
        Task = Get-NoIDXboxTaskState
    }
    Assert-NoIDXboxSettingsState $state
    return $state
}

function Set-NoIDXboxTaskEnabled {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param([Parameter(Mandatory)][bool]$Enabled)

    $catalog = Get-NoIDXboxComponentCatalog
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $task = $scheduler.GetFolder($catalog.TaskPath.TrimEnd('\')).GetTask($catalog.TaskName)
    if ([bool]$task.Enabled -eq $Enabled) { return }
    if ($PSCmdlet.ShouldProcess($catalog.TaskPath+$catalog.TaskName, 'Set Xbox task enabled state')) {
        $task.Enabled = $Enabled
        if ([bool]$task.Enabled -ne $Enabled) { throw 'Xbox task did not reach its requested state' }
    }
}

function Assert-NoIDXboxServiceStopScope {
    <# Never force-stop services belonging to games or unrelated software. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    $names = @((Get-NoIDXboxComponentCatalog).Services)
    foreach ($service in @($State.Services | Where-Object exists)) {
        $controller = Get-Service -Name $service.name -ErrorAction Stop
        foreach ($dependent in @($controller.DependentServices)) {
            if ($dependent.Name -notin $names -and [string]$dependent.Status -ne 'Stopped') {
                throw 'An unrelated service depends on Xbox; close the dependent application before switching Xbox off'
            }
        }
    }
}

function Invoke-NoIDXboxSettingsApply {
    <# App removal/recovery is a separate operation with a separate result. #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]$PreState,
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$DesiredState,
        [Parameter(Mandatory)]$ComponentSnapshot
    )

    Assert-NoIDXboxSettingsState $PreState
    $null = Resolve-NoIDXboxComponentState $ComponentSnapshot
    $catalog = Get-NoIDXboxComponentCatalog
    $policyChanges = @(Get-NoIDXboxRemovalPolicyPlan $ComponentSnapshot)
    if ($DesiredState -ceq 'Disable') { Assert-NoIDXboxServiceStopScope $PreState }
    $applicability = Assert-NoIDXboxUnmanagedDevice
    Assert-NoIDXboxApplicability $ComponentSnapshot.Applicability
    foreach ($name in @('RecordingPolicySupported','RemovalPolicySupported','ManagementStateKnown','DomainJoined','MdmRegistered')) {
        if ($applicability.$name -ne $ComponentSnapshot.Applicability.$name) {
            throw 'Xbox applicability changed since the measured component state'
        }
    }
    $liveSettings = Get-NoIDXboxSettingsState
    if ((Get-QuickActionObjectSha256 $liveSettings) -cne (Get-QuickActionObjectSha256 $PreState)) {
        throw 'Xbox settings changed after the prestate was captured; refresh before applying'
    }
    if (-not $PSCmdlet.ShouldProcess('Xbox settings', "Apply $DesiredState within the closed Xbox scope")) { return }

    # Only exceptions from the actual write block permit compensation. A
    # stale read, changed identity or dependency refusal above made no change.
    try {
        if ($DesiredState -ceq 'Enable') {
            foreach ($change in $policyChanges) {
                Set-QuickActionRegistryValue -Path $change.Path -Name $change.Name -Type $change.Type -Value $change.Value -Confirm:$false
            }
            foreach ($service in @($PreState.Services | Where-Object exists)) {
                if ($service.startType -ceq 'Disabled') {
                    Set-Service -Name $service.name -StartupType Manual -ErrorAction Stop
                }
                if ($service.status -ceq 'Paused') { Resume-Service -Name $service.name -ErrorAction Stop }
            }
        }
        else {
            # No -Force: a newly started external dependent must cause a visible
            # failure, never an implicit stop outside these four Xbox services.
            foreach ($service in @($PreState.Services | Where-Object exists)) {
                $controller = Get-Service -Name $service.name -ErrorAction Stop
                if ([string]$controller.Status -ne 'Stopped') {
                    Stop-Service -Name $service.name -ErrorAction Stop
                    $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
                }
                Set-Service -Name $service.name -StartupType Disabled -ErrorAction Stop
            }
        }
        if ($PreState.Task.Exists) { Set-NoIDXboxTaskEnabled -Enabled ($DesiredState -ceq 'Enable') -Confirm:$false }
        if ($applicability.RecordingPolicySupported) {
            Set-QuickActionRegistryValue -Path $catalog.RecordingPolicyPath -Name $catalog.RecordingPolicyName `
                -Type DWord -Value ([int]($DesiredState -ceq 'Enable')) -Confirm:$false
        }
    }
    catch {
        $_.Exception.Data['XboxSettingsWriteStarted'] = $true
        throw
    }
}

function Restore-NoIDXboxSettingsState {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([Parameter(Mandatory)]$State)

    Assert-NoIDXboxSettingsState $State
    # Validate all native identities before allowing the existing exact service
    # restore helper to change them. Never delete a newly appeared OS component.
    $current = Get-NoIDXboxSettingsState
    if ($current.Task.Exists -ne $State.Task.Exists) { throw 'Xbox task existence changed since the recorded settings' }
    foreach ($service in $State.Services) {
        $live = @($current.Services | Where-Object { $_.name -ceq $service.name })[0]
        if ($live.exists -ne $service.exists) { throw 'Xbox service existence changed since the recorded settings' }
    }
    $stopping = @($current.Services | Where-Object {
        $live = $_
        $recorded = @($State.Services | Where-Object { $_.name -ceq $live.name })[0]
        $live.exists -and $recorded.status -ceq 'Stopped' -and $live.status -cne 'Stopped'
    })
    Assert-NoIDXboxServiceStopScope ([pscustomobject]@{Services=$stopping})
    $null = Assert-NoIDXboxUnmanagedDevice
    if (-not $PSCmdlet.ShouldProcess('Xbox settings', 'Restore the exact recorded settings; app installations are separate')) { return }
    foreach ($service in @($State.Services | Where-Object exists)) {
        $controller = Get-Service -Name $service.name -ErrorAction Stop
        if ($service.status -cin @('Running','Paused') -and [string]$controller.Status -ceq 'Stopped') {
            Set-Service -Name $service.name -StartupType Manual -ErrorAction Stop
            Start-Service -Name $service.name -ErrorAction Stop
            $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
        }
        $controller.Refresh()
        if ($service.status -ceq 'Stopped' -and [string]$controller.Status -cne 'Stopped') {
            Stop-Service -Name $service.name -ErrorAction Stop
            $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
        }
        elseif ($service.status -ceq 'Running' -and [string]$controller.Status -ceq 'Paused') {
            Resume-Service -Name $service.name -ErrorAction Stop
        }
        elseif ($service.status -ceq 'Paused' -and [string]$controller.Status -cne 'Paused') {
            Suspend-Service -Name $service.name -ErrorAction Stop
        }
        Set-Service -Name $service.name -StartupType $service.startType -ErrorAction Stop
        if ($service.delayedAutoStartExists) {
            Set-QuickActionRegistryValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service.name) `
                -Name 'DelayedAutoStart' -Type DWord -Value $service.delayedAutoStart -Confirm:$false
        }
        else {
            Remove-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service.name) `
                -Name 'DelayedAutoStart' -ErrorAction SilentlyContinue
        }
    }
    if ($State.Task.Exists) { Set-NoIDXboxTaskEnabled -Enabled $State.Task.Enabled -Confirm:$false }
    foreach ($value in $State.RegistryValues) { Restore-QuickActionRegistryValue -State $value -Confirm:$false }
}
