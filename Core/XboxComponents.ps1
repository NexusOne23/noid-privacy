#Requires -Version 5.1

function Get-NoIDXboxComponentCatalog {
    <#
    .SYNOPSIS
        Defines the closed Xbox scope shared by detection and mutation.
    .DESCRIPTION
        The six apps match Privacy's Xbox targets. Shared Gaming Services,
        games and their data are outside this switch in both directions.
        Additional game prerequisites are managed by Xbox when installing
        games. Retired components are optional; the current Xbox app replaces
        Xbox Console Companion.
    #>
    [CmdletBinding()]
    param()

    $apps = @(
        @{ Name='Microsoft.GamingApp'; StoreId='9MV0B5HZVK9Z'; Required=$true; Remove=$true; LegacyPolicy='GamingApp' }
        @{ Name='Microsoft.XboxApp'; StoreId=''; Required=$false; Remove=$true; LegacyPolicy='' }
        @{ Name='Microsoft.XboxGamingOverlay'; StoreId='9NZKPSTSNW4P'; Required=$true; Remove=$true; LegacyPolicy='XboxGamingOverlay' }
        @{ Name='Microsoft.XboxIdentityProvider'; StoreId='9WZDNCRD1HKW'; Required=$true; Remove=$true; LegacyPolicy='XboxIdentityProvider' }
        @{ Name='Microsoft.XboxSpeechToTextOverlay'; StoreId=''; Required=$false; Remove=$true; LegacyPolicy='XboxSpeechToTextOverlay' }
        @{ Name='Microsoft.Xbox.TCUI'; StoreId=''; Required=$false; Remove=$true; LegacyPolicy='XboxTCUI' }
    ) | ForEach-Object {
        [pscustomobject][ordered]@{
            Name = [string]$_.Name
            PackageFamilyName = [string]$_.Name + '_8wekyb3d8bbwe'
            StoreId = [string]$_.StoreId
            RequiredWhenEnabled = [bool]$_.Required
            RemoveWhenDisabled = [bool]$_.Remove
            LegacyPolicyName = [string]$_.LegacyPolicy
        }
    }
    return [pscustomobject][ordered]@{
        Apps = @($apps)
        Services = @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
        TaskPath = '\Microsoft\XblGameSave\'
        TaskName = 'XblGameSaveTask'
        RecordingPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
        RecordingPolicyName = 'AllowGameDVR'
        RemovalPolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
    }
}

function Resolve-NoIDXboxComponentState {
    <#
    .SYNOPSIS
        Classifies a complete measured Xbox inventory without changing Windows.
    .DESCRIPTION
        Mixed is a usable repair state, not a query failure. Missing, malformed
        or duplicate evidence throws instead of being treated as an absent app
        or disabled service. Enable describes the measured Xbox installation
        and NoID settings; game prerequisites, sign-in and subscriptions are
        separate. It does not certify that every game is ready to play.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Snapshot)

    $catalog = Get-NoIDXboxComponentCatalog
    foreach ($name in @('Apps','Services','Task','RecordingAllowed','RecordingPolicySupported','RemovalBlocked')) {
        if (-not $Snapshot.PSObject.Properties[$name]) { throw "Xbox inventory lacks $name" }
    }
    if ($Snapshot.RecordingAllowed -isnot [bool] -or $Snapshot.RemovalBlocked -isnot [bool] -or
        $Snapshot.RecordingPolicySupported -isnot [bool]) {
        throw 'Xbox policy evidence must contain measured Boolean values'
    }
    $apps = @($Snapshot.Apps)
    if ($apps.Count -ne @($catalog.Apps).Count) { throw 'Xbox package inventory is incomplete' }
    $enabled = (-not $Snapshot.RecordingPolicySupported -or $Snapshot.RecordingAllowed) -and -not $Snapshot.RemovalBlocked
    $disabled = -not $Snapshot.RecordingPolicySupported -or -not $Snapshot.RecordingAllowed
    foreach ($definition in $catalog.Apps) {
        $identityMatches = @($apps | Where-Object { [string]$_.Name -ceq $definition.Name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox package inventory contains a missing or duplicate identity' }
        $app = $identityMatches[0]
        if ($app.Present -isnot [bool] -or $app.Healthy -isnot [bool] -or
            (-not $app.Present -and $app.Healthy)) {
            throw 'Xbox package registration evidence is invalid'
        }
        if (($definition.RequiredWhenEnabled -and -not $app.Present) -or
            ($app.Present -and -not $app.Healthy)) { $enabled = $false }
        if ($definition.RemoveWhenDisabled -and $app.Present) { $disabled = $false }
    }

    $services = @($Snapshot.Services)
    if ($services.Count -ne @($catalog.Services).Count) { throw 'Xbox service inventory is incomplete' }
    foreach ($name in $catalog.Services) {
        $identityMatches = @($services | Where-Object { [string]$_.Name -ceq $name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox service inventory contains a missing or duplicate identity' }
        $service = $identityMatches[0]
        if ($service.Exists -isnot [bool]) { throw 'Xbox service existence was not measured' }
        if (-not $service.Exists) {
            # Baseline services are optional OS components.
            continue
        }
        if ($service.StartType -cnotin @('Automatic','Manual','Disabled') -or
            $service.Status -cnotin @('Running','Stopped','Paused')) {
            throw 'Xbox service state is invalid or still changing'
        }
        if ($service.StartType -ceq 'Disabled' -or $service.Status -ceq 'Paused') { $enabled = $false }
        if ($service.StartType -cne 'Disabled' -or $service.Status -cne 'Stopped') { $disabled = $false }
    }
    $task = $Snapshot.Task
    if ($task.Exists -isnot [bool] -or ($task.Exists -and $task.Enabled -isnot [bool])) {
        throw 'Xbox scheduled-task existence or enabled state was not measured'
    }
    if ($task.Exists) {
        if (-not $task.Enabled) { $enabled = $false }
        if ($task.Enabled) { $disabled = $false }
    }
    if ($enabled) { return 'Enable' }
    if ($disabled) { return 'Disable' }
    return 'Mixed'
}

function Get-NoIDXboxTaskState {
    [CmdletBinding()]
    param()

    $catalog = Get-NoIDXboxComponentCatalog
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $exists = $true
    $enabled = $null
    try {
        $task = $scheduler.GetFolder($catalog.TaskPath.TrimEnd('\')).GetTask($catalog.TaskName)
        $enabled = [bool]$task.Enabled
    }
    catch {
        # A missing folder/task is a valid optional OS component. Access
        # denied, service failure and every other COM error must propagate.
        $exception = $_.Exception
        $missing = $false
        while ($null -ne $exception) {
            if ($exception.HResult -in @(-2147024894, -2147024893)) { $missing = $true }
            $exception = $exception.InnerException
        }
        if (-not $missing) { throw }
        $exists = $false
    }
    return [pscustomobject][ordered]@{
        TaskPath = $catalog.TaskPath; TaskName = $catalog.TaskName
        Exists = $exists; Enabled = $enabled
    }
}

function Get-NoIDXboxPolicyFlag {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Value, [bool]$Default = $false)

    if ($Value.valueExisted -isnot [bool]) { throw 'Xbox policy existence was not measured' }
    if (-not $Value.valueExisted) { return $Default }
    if ($Value.type -cne 'DWord' -or ($Value.value -isnot [int] -and $Value.value -isnot [long]) -or
        $Value.value -notin @(0, 1)) {
        throw 'Xbox policy has an unsupported type or value'
    }
    return ([int]$Value.value -eq 1)
}

function Get-NoIDXboxApplicability {
    <# Reuse Privacy's edition and policy-controller evidence without duplicating SKU rules. #>
    [CmdletBinding()]
    param()

    $source = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($source)) { throw 'Xbox applicability helper source is unavailable' }
    $privateRoot = Join-Path (Split-Path (Split-Path $source -Parent) -Parent) 'Modules\Privacy\Private'
    foreach ($file in @('Get-PrivacyManagementState.ps1','Get-PrivacyUcpdProtectionState.ps1','Get-PrivacyApplicability.ps1')) {
        . (Join-Path $privateRoot $file)
    }
    $privacy = Get-PrivacyApplicability
    return [pscustomobject][ordered]@{
        RecordingPolicySupported = $privacy.WindowsManagedPolicySupported
        RemovalPolicySupported = $privacy.Tier1PolicyRemovalOsSupported
        ManagementStateKnown = $privacy.ManagementStateKnown
        DomainJoined = $privacy.DomainJoined
        MdmRegistered = $privacy.MdmRegistered
    }
}

function Assert-NoIDXboxApplicability {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Applicability)

    foreach ($name in @('RecordingPolicySupported','RemovalPolicySupported','ManagementStateKnown','DomainJoined','MdmRegistered')) {
        if (-not $Applicability.PSObject.Properties[$name] -or $Applicability.$name -isnot [bool]) {
            throw 'Xbox applicability evidence is incomplete or malformed'
        }
    }
}

function Assert-NoIDXboxUnmanagedDevice {
    <# Read ownership immediately before mutation; a cached GUI query is not authority. #>
    [CmdletBinding()]
    param()

    $applicability = Get-NoIDXboxApplicability
    Assert-NoIDXboxApplicability $applicability
    if (-not $applicability.ManagementStateKnown -or $applicability.DomainJoined -or $applicability.MdmRegistered) {
        throw 'Xbox settings are managed by your organization or device management could not be checked'
    }
    return $applicability
}

function Get-NoIDXboxNativeRemovalPolicyPaths {
    <# Only the current native ADMX identities affect removal; legacy CSP labels are inert. #>
    [CmdletBinding()]
    param()

    $source = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($source)) { throw 'Xbox policy helper source is unavailable' }
    $repoRoot = Split-Path (Split-Path $source -Parent) -Parent
    . (Join-Path $repoRoot 'Modules\Privacy\Private\Get-PrivacyTier1PolicyDefinition.ps1')
    $families = @((Get-NoIDXboxComponentCatalog).Apps.PackageFamilyName)
    foreach ($target in (Get-PrivacyTier1PolicyDefinition).Targets) {
        if ($target.PSObject.Properties['PackageFamilyName'] -and $target.PackageFamilyName -cin $families) {
            [string]$target.Path
        }
    }
}

function Get-NoIDXboxRemovalPolicyPlan {
    <#
    .SYNOPSIS
        Plans only the Xbox exceptions needed to permit app installation.
    .DESCRIPTION
        Never disable the global app-removal policy: other selected apps must
        remain blocked. Preserve unrelated dynamic entries, including their
        order. This function performs no writes and creates no backup.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)]$Snapshot)

    $catalog = Get-NoIDXboxComponentCatalog
    $null = Resolve-NoIDXboxComponentState -Snapshot $Snapshot
    foreach ($property in @('RemovalPolicyEnabled','RemovalPolicyValues','DynamicRemovalList','Applicability')) {
        if (-not $Snapshot.PSObject.Properties[$property]) { throw "Xbox policy snapshot lacks $property" }
    }
    Assert-NoIDXboxApplicability $Snapshot.Applicability
    if ($Snapshot.RemovalPolicyEnabled.path -cne $catalog.RemovalPolicyRoot -or
        $Snapshot.RemovalPolicyEnabled.name -cne 'Enabled') {
        throw 'Xbox removal policy root identity is invalid'
    }
    $null = Get-NoIDXboxPolicyFlag -Value $Snapshot.RemovalPolicyEnabled

    $expected = @($catalog.Apps | ForEach-Object {
        [pscustomobject]@{Path=$catalog.RemovalPolicyRoot+'\'+$_.PackageFamilyName;Name='RemovePackage'}
        if ($_.LegacyPolicyName) {
            [pscustomobject]@{Path=$catalog.RemovalPolicyRoot+'\'+$_.LegacyPolicyName;Name='RemovePackage'}
        }
    })
    $values = @($Snapshot.RemovalPolicyValues)
    if ($values.Count -ne $expected.Count) { throw 'Xbox removal policy inventory is incomplete' }
    $changes = [Collections.Generic.List[object]]::new()
    foreach ($target in $expected) {
        $identityMatches = @($values | Where-Object { $_.path -ceq $target.Path -and $_.name -ceq $target.Name })
        if ($identityMatches.Count -ne 1) { throw 'Xbox removal policy inventory has a missing or duplicate identity' }
        if (Get-NoIDXboxPolicyFlag -Value $identityMatches[0]) {
            $changes.Add([pscustomobject][ordered]@{
                Path=$target.Path;Name=$target.Name;Type='DWord';Value=0
            })
        }
    }
    $dynamic = $Snapshot.DynamicRemovalList
    if ($dynamic.path -cne $catalog.RemovalPolicyRoot -or $dynamic.name -cne 'DynamicRemovalList' -or
        $dynamic.valueExisted -isnot [bool]) {
        throw 'Xbox dynamic removal policy identity or existence is invalid'
    }
    if ($dynamic.valueExisted) {
        if ($dynamic.type -cne 'MultiString' -or $null -eq $dynamic.value -or $dynamic.value -isnot [Array]) {
            throw 'Xbox dynamic removal policy requires a measured string array'
        }
        $remaining = [Collections.Generic.List[string]]::new()
        $removed = 0
        foreach ($family in @($dynamic.value)) {
            if ($family -isnot [string] -or [string]::IsNullOrWhiteSpace($family)) {
                throw 'Xbox dynamic removal policy contains an invalid entry'
            }
            if ($family -iin @($catalog.Apps.PackageFamilyName)) { $removed++ }
            else { $remaining.Add($family) }
        }
        if ($removed -gt 0) {
            $changes.Add([pscustomobject][ordered]@{
                Path=$catalog.RemovalPolicyRoot;Name='DynamicRemovalList';Type='MultiString';Value=$remaining.ToArray()
            })
        }
    }
    # Unsupported editions do not enforce this policy. Leave inert values
    # untouched instead of implying that rewriting them unblocks installation.
    if (-not $Snapshot.Applicability.RemovalPolicySupported) { return @() }
    return $changes.ToArray()
}

function Get-NoIDXboxComponentSnapshot {
    <#
    .SYNOPSIS
        Reads only the named Xbox packages, services, task and policy values.
    .DESCRIPTION
        The privileged caller supplies the original interactive user's SID.
        A complete successful enumeration proves absence; query errors are
        never converted to missing packages or services. No Store/network
        access, user worker, backup or application launch is needed for reads.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')]
        [string]$UserSid
    )

    $catalog = Get-NoIDXboxComponentCatalog
    $applicability = Get-NoIDXboxApplicability
    Assert-NoIDXboxApplicability $applicability
    $nativePolicyPaths = @(Get-NoIDXboxNativeRemovalPolicyPaths)
    $packages = @(Get-AppxPackage -User $UserSid -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
    $removablePackages = @(Get-NoIDXboxAppRemovalInventory -Packages $packages)
    $apps = @($catalog.Apps | ForEach-Object {
        $definition = $_
        $identityMatches = @($packages | Where-Object { [string]$_.Name -ceq $definition.Name })
        $healthy = ($identityMatches.Count -gt 0)
        foreach ($package in $identityMatches) {
            if ([string]$package.PackageFamilyName -cne $definition.PackageFamilyName) {
                throw 'An Xbox package has an unexpected publisher/family identity'
            }
            if ([string]$package.Status -cne 'Ok') { $healthy = $false }
        }
        [pscustomobject][ordered]@{
            Name = $definition.Name
            Present = ($identityMatches.Count -gt 0)
            Healthy = [bool]$healthy
        }
    })
    # One successful enumeration avoids interpreting a per-name access error
    # as an absent optional service. Do not query unrelated service settings.
    $allServices = @(Get-Service -ErrorAction Stop)
    $readServices = {
        param([string[]]$Names)
        foreach ($name in $Names) {
            $identityMatches = @($allServices | Where-Object { [string]$_.Name -ceq $name })
            if ($identityMatches.Count -gt 1) { throw 'Xbox service identity is ambiguous' }
            [pscustomobject][ordered]@{
                Name = $name
                Exists = ($identityMatches.Count -eq 1)
                StartType = $(if ($identityMatches.Count -eq 1) { [string]$identityMatches[0].StartType } else { $null })
                Status = $(if ($identityMatches.Count -eq 1) { [string]$identityMatches[0].Status } else { $null })
            }
        }
    }
    $recording = Get-QuickActionRegistryValueState -Path $catalog.RecordingPolicyPath -Name $catalog.RecordingPolicyName
    $rootEnabled = Get-QuickActionRegistryValueState -Path $catalog.RemovalPolicyRoot -Name 'Enabled'
    $removalEnabled = (Get-NoIDXboxPolicyFlag -Value $rootEnabled) -and $applicability.RemovalPolicySupported
    $policies = [Collections.Generic.List[object]]::new()
    $blocked = $false
    foreach ($app in $catalog.Apps) {
        $value = Get-QuickActionRegistryValueState -Path ($catalog.RemovalPolicyRoot + '\' + $app.PackageFamilyName) -Name 'RemovePackage'
        $selected = Get-NoIDXboxPolicyFlag -Value $value
        $policies.Add($value)
        if ($removalEnabled -and $selected -and
            ($catalog.RemovalPolicyRoot + '\' + $app.PackageFamilyName) -cin $nativePolicyPaths) { $blocked = $true }
        if ($app.LegacyPolicyName) {
            $legacyValue = Get-QuickActionRegistryValueState -Path ($catalog.RemovalPolicyRoot + '\' + $app.LegacyPolicyName) -Name 'RemovePackage'
            $null = Get-NoIDXboxPolicyFlag -Value $legacyValue
            $policies.Add($legacyValue)
        }
    }
    $dynamic = Get-QuickActionRegistryValueState -Path $catalog.RemovalPolicyRoot -Name 'DynamicRemovalList'
    if ($dynamic.valueExisted) {
        if ($dynamic.type -cne 'MultiString' -or $dynamic.value -isnot [Array] -or
            @($dynamic.value | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw 'Xbox dynamic removal policy has an unsupported type or value'
        }
        if ($removalEnabled -and @($dynamic.value | Where-Object { [string]$_ -in @($catalog.Apps.PackageFamilyName) }).Count -gt 0) {
            $blocked = $true
        }
    }
    $snapshot = [pscustomobject][ordered]@{
        UserSid = $UserSid
        Apps = $apps
        RemovablePackages = $removablePackages
        Services = @(& $readServices $catalog.Services)
        Task = Get-NoIDXboxTaskState
        RecordingAllowed = Get-NoIDXboxPolicyFlag -Value $recording -Default $true
        RecordingPolicySupported = $applicability.RecordingPolicySupported
        RemovalBlocked = [bool]$blocked
        Applicability = $applicability
        RecordingPolicy = $recording
        RemovalPolicyEnabled = $rootEnabled
        RemovalPolicyValues = @($policies.ToArray())
        DynamicRemovalList = $dynamic
    }
    # Validate all observations before the caller can display a binary state.
    $null = Resolve-NoIDXboxComponentState -Snapshot $snapshot
    return $snapshot
}

function Get-NoIDXboxAppRemovalInventory {
    <#
    .SYNOPSIS
        Selects exact removable Xbox parent packages from a successful query.
    .DESCRIPTION
        Prefer Bundle parents where present, matching Privacy's removal worker.
        Games, shared Gaming Services and lookalike publishers never enter the
        returned inventory. A caller must seal it and revalidate it inside the
        original user's token before removing any package.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Packages)

    $result = [Collections.Generic.List[object]]::new()
    foreach ($app in @((Get-NoIDXboxComponentCatalog).Apps | Where-Object RemoveWhenDisabled)) {
        $identityMatches = @($Packages | Where-Object { [string]$_.Name -ceq $app.Name })
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($package in $identityMatches) {
            $pattern = '^' + [regex]::Escape($app.Name) + '_[0-9]+(?:\.[0-9]+){3}_(?:x64|x86|arm64|neutral)_(?:~)?_8wekyb3d8bbwe$'
            if ([string]$package.PackageFamilyName -cne $app.PackageFamilyName -or
                [string]$package.PackageFullName -cnotmatch $pattern -or
                -not $seen.Add([string]$package.PackageFullName)) {
                throw 'Xbox removal inventory contains an unexpected publisher, malformed or duplicate package identity'
            }
            if (-not $package.PSObject.Properties['IsBundle'] -or $package.IsBundle -isnot [bool] -or
                [bool]$package.IsBundle -ne ([string]$package.PackageFullName -cmatch '_neutral_~_8wekyb3d8bbwe$')) {
                throw 'Xbox removal inventory has inconsistent Bundle evidence'
            }
        }
        $bundles = @($identityMatches | Where-Object IsBundle)
        $parents = if ($bundles.Count -gt 0) { $bundles } else { $identityMatches }
        foreach ($package in @($parents | Sort-Object PackageFullName)) {
            $result.Add([pscustomobject][ordered]@{
                AppName=$app.Name
                PackageFullName=[string]$package.PackageFullName
                PackageFamilyName=$app.PackageFamilyName
            })
        }
    }
    return $result.ToArray()
}
