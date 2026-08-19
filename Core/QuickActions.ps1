#Requires -Version 5.1

<#
.SYNOPSIS
    Canonical action-scoped Quick Action query/apply/verify/restore engine.

.DESCRIPTION
    Shared privileged backend for the GUI's nine Quick Actions. The Shell
    engine loads this code for one canonical mutation/restore contract, but the
    Shell menu exposes no Quick Action UI or parameters. Every action owns a
    closed target set, performs a fresh optimistic-concurrency read immediately
    before Backup, seals exact pre/post fingerprints, and restores only that
    target set.
#>

$script:QuickActionSchemaVersion = 3
$script:QuickActionStateSchemaVersion = 1
$script:QuickActionReceiptSchemaVersion = 1
$script:NoIDMutationMutexName = 'Global\NoIDPrivacyMutationV1'
# Batch-scoped Get-MpPreference snapshot. Non-null ONLY while
# Get-AllQuickActionStates runs its nine-action read: both ASR actions share
# one Defender WMI round-trip (the second-costliest part of a page load).
# A failed batch snapshot is remembered as an error so the two ASR actions
# report it immediately instead of each paying its own slow Defender timeout.
# Single-action reads and the post-apply Wait-QuickActionState polling always
# see $null here and take their own fresh reading.
$script:QuickActionBatchMpPreference = $null
$script:QuickActionBatchMpPreferenceError = $null
# Batch-scoped named-firewall-rule snapshot, same lifecycle as the Defender
# snapshot above: non-null ONLY while Get-AllQuickActionStates runs. One
# Get-NetFirewallRule call for all six canonical NoID Privacy rule names replaces six
# per-name CIM round-trips (the costliest part of a page load), and UPnP plus
# WirelessDisplay consume the same reading. Missing names stay absent exactly
# as an empty per-name query would, duplicate names keep triggering the
# ambiguity guard, and the per-rule port-filter value checks stay live. On any
# snapshot failure the batch stays $null and every action falls back to its
# own live per-name query. Single-action reads, apply, verify polling and
# restore always see $null here and query live.
$script:QuickActionBatchNamedFirewallRules = $null

# EncryptedDNS uses the same side-effect-free address, adapter and native
# DNS_INTERFACE_SETTINGS3 helpers as the DNS module. Load that closed helper
# surface in the script scope that owns the Quick Action functions. Loading it
# lazily inside Get-QuickActionDnsResolverEvidence would create the functions
# only in that function's local scope: the query could then succeed while the
# subsequent state comparison or Apply failed because ConvertTo/Test/Set had
# already gone out of scope.
$quickActionDnsHelperPaths = @(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\DNS\Private\ConvertTo-DnsCanonicalAddress.ps1'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\DNS\Private\DnsInterfaceDoh.ps1'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\DNS\Private\Get-PhysicalAdapters.ps1'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\DNS\Private\Test-DNSIPv6StackEnabled.ps1')
)
foreach ($quickActionDnsHelperPath in $quickActionDnsHelperPaths) {
    if (-not (Test-Path -LiteralPath $quickActionDnsHelperPath -PathType Leaf)) {
        throw "DNS Quick Action helper is missing: $quickActionDnsHelperPath"
    }
    . $quickActionDnsHelperPath
}
Remove-Variable -Name quickActionDnsHelperPath, quickActionDnsHelperPaths -ErrorAction SilentlyContinue

function Get-QuickActionDefinitions {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @(
        [PSCustomObject][ordered]@{
            Id = 'ManagementTools'
            OwningModule = 'ASR'
            States = @('Allow', 'Block')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            RegistryName = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        },
        [PSCustomObject][ordered]@{
            Id = 'NewSoftware'
            OwningModule = 'ASR'
            States = @('Allow', 'Block')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            RegistryName = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        },
        [PSCustomObject][ordered]@{
            Id = 'EncryptedDNS'
            OwningModule = 'DNS'
            States = @('Allow', 'Require')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            RegistryName = 'DoHPolicy'
        },
        [PSCustomObject][ordered]@{
            Id = 'BitLockerUSB'
            OwningModule = 'SecurityBaseline'
            States = @('Allow', 'Enforce')
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE'
            RegistryName = 'RDVDenyWriteAccess'
        },
        [PSCustomObject][ordered]@{
            Id = 'RDP'
            OwningModule = 'AdvancedSecurity'
            States = @('Disable', 'Enable')
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            RegistryName = 'fDenyTSConnections'
        },
        [PSCustomObject][ordered]@{
            Id = 'UPnP'
            OwningModule = 'AdvancedSecurity'
            States = @('Allow', 'Block')
            RegistryPath = $null
            RegistryName = $null
        },
        [PSCustomObject][ordered]@{
            Id = 'WirelessDisplay'
            OwningModule = 'AdvancedSecurity'
            States = @('Enable', 'Disable')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
            RegistryName = $null
        },
        [PSCustomObject][ordered]@{
            Id = 'EdgeExtensions'
            OwningModule = 'EdgeHardening'
            States = @('Allow', 'Block')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            RegistryName = '1'
        },
        [PSCustomObject][ordered]@{
            Id = 'SmartScreen'
            OwningModule = 'SecurityBaseline'
            States = @('Warn', 'Block')
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            RegistryName = 'ShellSmartScreenLevel'
        }
    )
}

function Get-QuickActionDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
            'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
        )]
        [string]$ActionId
    )

    $definitionMatches = @(Get-QuickActionDefinitions | Where-Object { [string]$_.Id -ceq $ActionId })
    if ($definitionMatches.Count -ne 1) {
        throw "Quick Action definition identity is not unique: $ActionId"
    }
    return $definitionMatches[0]
}

function Get-QuickActionModuleRestoreScopes {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
            'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
        )]
        [string]$ActionId
    )

    $definition = Get-QuickActionDefinition -ActionId $ActionId
    $scopes = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $null = $scopes.Add([string]$definition.OwningModule)

    # Both ASR Quick Actions target values that are also present in the
    # Microsoft Security Baseline registry inventory. A SecurityBaseline-only
    # restore can therefore overwrite a newer ASR action even though the
    # action's primary owner is ASR. Restore ordering follows target ownership,
    # not the display/primary module label.
    if ($ActionId -in @('ManagementTools', 'NewSoftware')) {
        $null = $scopes.Add('SecurityBaseline')
    }

    $ordered = [string[]]@($scopes)
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    return $ordered
}

function ConvertTo-QuickActionCanonicalJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    # Named binding preserves empty arrays as [] on Windows PowerShell 5.1.
    # Pipeline binding enumerates an empty array and produces no JSON at all.
    return (ConvertTo-Json -InputObject $InputObject -Compress -Depth 30)
}

function Get-QuickActionObjectSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    $json = ConvertTo-QuickActionCanonicalJson -InputObject $InputObject
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-QuickActionRegistryValueState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Path -notmatch '^HKLM:\\[^\\].*' -or
        $Path.Contains('\\') -or
        $Path.EndsWith('\', [StringComparison]::Ordinal) -or
        [string]::IsNullOrWhiteSpace($Name) -or
        $Name.IndexOfAny([char[]]@('\', '/', '*', '?', '[', ']')) -ge 0) {
        throw "Quick Action registry identity is not canonical: $Path::$Name"
    }

    $keyExisted = Test-Path -LiteralPath $Path -PathType Container
    $absentAncestors = [System.Collections.Generic.List[string]]::new()
    if (-not $keyExisted) {
        $cursor = $Path
        while ($cursor -match '^HKLM:\\.+') {
            if (Test-Path -LiteralPath $cursor -PathType Container) { break }
            $absentAncestors.Add($cursor)
            $parent = Split-Path $cursor -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor -or $parent -eq 'HKLM:\') {
                break
            }
            $cursor = $parent
        }
    }

    $valueExisted = $false
    $originalName = $null
    $type = $null
    $value = $null
    if ($keyExisted) {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        try {
            $matchingNames = @($key.GetValueNames() | Where-Object {
                    ([string]$_).Equals($Name, [StringComparison]::OrdinalIgnoreCase)
                })
            if ($matchingNames.Count -gt 1) {
                throw "Quick Action registry value identity is ambiguous: $Path::$Name"
            }
            if ($matchingNames.Count -eq 1) {
                $valueExisted = $true
                $originalName = [string]$matchingNames[0]
                $type = $key.GetValueKind($originalName).ToString()
                $rawValue = $key.GetValue(
                    $originalName,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $value = switch ($type) {
                    'Binary' { [byte[]]$rawValue }
                    'MultiString' { [string[]]$rawValue }
                    'DWord' { [int64]([uint32]$rawValue) }
                    'QWord' { [string]([uint64]$rawValue).ToString([Globalization.CultureInfo]::InvariantCulture) }
                    default { [string]$rawValue }
                }
            }
        }
        finally {
            if ($key -is [IDisposable]) { $key.Dispose() }
        }
    }

    return [PSCustomObject][ordered]@{
        kind = 'RegistryValue'
        path = $Path
        name = $Name
        keyExisted = [bool]$keyExisted
        valueExisted = [bool]$valueExisted
        originalName = $originalName
        type = $type
        value = $value
        absentAncestorKeys = [string[]]$absentAncestors.ToArray()
    }
}

function Set-QuickActionRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        $Value
    )

    if (-not $PSCmdlet.ShouldProcess("$Path::$Name", "Set exact $Type value")) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    try {
        $matchingNames = @($key.GetValueNames() | Where-Object {
                ([string]$_).Equals($Name, [StringComparison]::OrdinalIgnoreCase)
            })
        if ($matchingNames.Count -gt 1) {
            throw "Quick Action registry value identity became ambiguous: $Path::$Name"
        }
        $writeName = if ($matchingNames.Count -eq 1) { [string]$matchingNames[0] } else { $Name }
    }
    finally {
        if ($key -is [IDisposable]) { $key.Dispose() }
    }

    Remove-ItemProperty -LiteralPath $Path -Name $writeName -ErrorAction SilentlyContinue
    $writeValue = switch ($Type) {
        'DWord' { [uint32]([int64]$Value) }
        'QWord' { [uint64]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture) }
        'Binary' { [byte[]]$Value }
        'MultiString' { [string[]]$Value }
        default { [string]$Value }
    }
    New-ItemProperty -LiteralPath $Path -Name $writeName -PropertyType $Type `
        -Value $writeValue -Force -ErrorAction Stop | Out-Null
}

function Remove-QuickActionEmptyAncestors {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        $children = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        try {
            $valueCount = @($key.GetValueNames()).Count
        }
        finally {
            if ($key -is [IDisposable]) { $key.Dispose() }
        }
        if ($children.Count -eq 0 -and $valueCount -eq 0) {
            if ($PSCmdlet.ShouldProcess($path, 'Remove originally absent empty registry key')) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            }
        }
    }
}

function Restore-QuickActionRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    if ([string]$State.kind -cne 'RegistryValue' -or
        [string]::IsNullOrWhiteSpace([string]$State.path) -or
        [string]::IsNullOrWhiteSpace([string]$State.name) -or
        $State.keyExisted -isnot [bool] -or
        $State.valueExisted -isnot [bool]) {
        throw 'Quick Action registry restore state is malformed'
    }

    $path = [string]$State.path
    $name = [string]$State.name
    if ([bool]$State.valueExisted) {
        if (-not [bool]$State.keyExisted -or
            [string]$State.type -notin @('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord') -or
            [string]::IsNullOrWhiteSpace([string]$State.originalName)) {
            throw "Quick Action registry restore state is internally inconsistent: $path::$name"
        }
        Set-QuickActionRegistryValue -Path $path -Name ([string]$State.originalName) `
            -Type ([string]$State.type) -Value $State.value -Confirm:$false
    }
    else {
        if (Test-Path -LiteralPath $path -PathType Container) {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            try {
                $matchingNames = @($key.GetValueNames() | Where-Object {
                        ([string]$_).Equals($name, [StringComparison]::OrdinalIgnoreCase)
                    })
            }
            finally {
                if ($key -is [IDisposable]) { $key.Dispose() }
            }
            if ($matchingNames.Count -gt 1) {
                throw "Quick Action registry restore target is ambiguous: $path::$name"
            }
            if ($matchingNames.Count -eq 1 -and
                $PSCmdlet.ShouldProcess("$path::$($matchingNames[0])", 'Restore original value absence')) {
                Remove-ItemProperty -LiteralPath $path -Name ([string]$matchingNames[0]) -ErrorAction Stop
            }
        }
        $absentAncestors = @($State.absentAncestorKeys)
        if ($absentAncestors.Count -gt 0) {
            Remove-QuickActionEmptyAncestors -Paths $absentAncestors -Confirm:$false
        }
    }
}

function Get-QuickActionServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $services = @(Get-Service -Name $Name -ErrorAction SilentlyContinue)
    if ($services.Count -eq 0) {
        return [PSCustomObject][ordered]@{
            kind = 'Service'
            name = $Name
            exists = $false
            status = $null
            startType = $null
            delayedAutoStartExists = $false
            delayedAutoStart = $null
        }
    }
    if ($services.Count -ne 1) {
        throw "Quick Action service identity is ambiguous: $Name"
    }
    $service = $services[0]
    $stableStates = @('Running', 'Stopped', 'Paused')
    if ([string]$service.Status -notin $stableStates) {
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 200
            $service.Refresh()
        } while ([string]$service.Status -notin $stableStates -and [DateTime]::UtcNow -lt $deadline)
    }
    if ([string]$service.Status -notin $stableStates) {
        throw "Quick Action service remained transient: $Name/$($service.Status)"
    }

    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $serviceKey = Get-Item -LiteralPath $servicePath -ErrorAction Stop
    try {
        $delayedExists = $serviceKey.GetValueNames() -contains 'DelayedAutoStart'
        $delayedValue = if ($delayedExists) { [int]$serviceKey.GetValue('DelayedAutoStart') } else { $null }
        if ($delayedExists -and
            ($serviceKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord' -or $delayedValue -notin @(0, 1))) {
            throw "Quick Action service has invalid DelayedAutoStart state: $Name"
        }
    }
    finally {
        if ($serviceKey -is [IDisposable]) { $serviceKey.Dispose() }
    }

    return [PSCustomObject][ordered]@{
        kind = 'Service'
        name = $Name
        exists = $true
        status = [string]$service.Status
        startType = [string]$service.StartType
        delayedAutoStartExists = [bool]$delayedExists
        delayedAutoStart = $delayedValue
    }
}

function Set-QuickActionServiceMode {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Manual', 'Disabled')]
        [string]$StartType,

        [Parameter(Mandatory = $false)]
        [switch]$Stop
    )

    $service = Get-Service -Name $Name -ErrorAction Stop
    if ($Stop -and [string]$service.Status -ne 'Stopped') {
        if ($PSCmdlet.ShouldProcess($Name, 'Stop service for Quick Action')) {
            Stop-Service -Name $Name -Force -ErrorAction Stop
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(20)
            )
        }
    }
    if ($PSCmdlet.ShouldProcess($Name, "Set service startup to $StartType")) {
        Set-Service -Name $Name -StartupType $StartType -ErrorAction Stop
    }
}

function Set-QuickActionServiceRuntime {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Running
    )

    $service = Get-Service -Name $Name -ErrorAction Stop
    $targetStatus = if ($Running) {
        [System.ServiceProcess.ServiceControllerStatus]::Running
    }
    else {
        [System.ServiceProcess.ServiceControllerStatus]::Stopped
    }
    if ($service.Status -eq $targetStatus) { return }
    if ($Running) {
        if ($PSCmdlet.ShouldProcess($Name, 'Start service for Quick Action')) {
            if ([string]$service.Status -eq 'Paused') {
                Resume-Service -Name $Name -ErrorAction Stop
            }
            else {
                Start-Service -Name $Name -ErrorAction Stop
            }
            $service.WaitForStatus($targetStatus, [TimeSpan]::FromSeconds(20))
        }
    }
    elseif ($PSCmdlet.ShouldProcess($Name, 'Stop service for Quick Action')) {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        $service.WaitForStatus($targetStatus, [TimeSpan]::FromSeconds(20))
    }
    $service.Refresh()
    if ($service.Status -ne $targetStatus) {
        throw "Quick Action service runtime did not converge: $Name/$($service.Status)"
    }
}

function Restore-QuickActionServiceState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    if ([string]$State.kind -cne 'Service' -or $State.exists -isnot [bool]) {
        throw 'Quick Action service restore state is malformed'
    }
    if (-not [bool]$State.exists) {
        if (@(Get-Service -Name ([string]$State.name) -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "Originally absent Quick Action service appeared later: $($State.name)"
        }
        return
    }
    if ([string]$State.status -notin @('Running', 'Stopped', 'Paused') -or
        [string]$State.startType -notin @('Automatic', 'Manual', 'Disabled')) {
        throw "Quick Action service restore state is unsupported: $($State.name)"
    }

    $name = [string]$State.name
    $service = Get-Service -Name $name -ErrorAction Stop
    if ([string]$State.status -in @('Running', 'Paused') -and [string]$service.Status -eq 'Stopped') {
        Set-Service -Name $name -StartupType Manual -ErrorAction Stop
        Start-Service -Name $name -ErrorAction Stop
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(20)
        )
    }
    $service.Refresh()
    switch ([string]$State.status) {
        'Running' {
            if ([string]$service.Status -eq 'Paused') { Resume-Service -Name $name -ErrorAction Stop }
            elseif ([string]$service.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop }
        }
        'Stopped' {
            if ([string]$service.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction Stop }
        }
        'Paused' {
            if ([string]$service.Status -ne 'Paused') { Suspend-Service -Name $name -ErrorAction Stop }
        }
    }
    Set-Service -Name $name -StartupType ([string]$State.startType) -ErrorAction Stop

    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if ([bool]$State.delayedAutoStartExists) {
        Set-QuickActionRegistryValue -Path $servicePath -Name 'DelayedAutoStart' `
            -Type DWord -Value ([int]$State.delayedAutoStart) -Confirm:$false
    }
    else {
        Remove-ItemProperty -LiteralPath $servicePath -Name 'DelayedAutoStart' -ErrorAction SilentlyContinue
    }
}

function Get-QuickActionFirewallGroupState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Group
    )

    $rules = @(Get-NetFirewallRule -Group $Group -ErrorAction Stop | Sort-Object Name)
    if ($rules.Count -eq 0) {
        throw "Quick Action firewall group has no rules: $Group"
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $entries = foreach ($rule in $rules) {
        if ([string]::IsNullOrWhiteSpace([string]$rule.Name) -or -not $seen.Add([string]$rule.Name)) {
            throw "Quick Action firewall rule identity is empty or duplicated in group: $Group"
        }
        [PSCustomObject][ordered]@{
            name = [string]$rule.Name
            enabled = [string]$rule.Enabled
            direction = [string]$rule.Direction
            action = [string]$rule.Action
            profile = [string]$rule.Profile
            group = [string]$rule.Group
        }
    }

    return [PSCustomObject][ordered]@{
        kind = 'FirewallGroup'
        group = $Group
        rules = @($entries)
    }
}

function Set-QuickActionFirewallGroupEnabled {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    $enabledValue = if ($Enabled) { 'True' } else { 'False' }
    foreach ($rule in @($State.rules)) {
        $ruleMatches = @(Get-NetFirewallRule -Name ([string]$rule.name) -ErrorAction Stop)
        if ($ruleMatches.Count -ne 1 -or
            -not ([string]$ruleMatches[0].Group).Equals([string]$State.group, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Quick Action firewall group identity changed: $($rule.name)"
        }
        if ($PSCmdlet.ShouldProcess([string]$rule.name, "Set firewall enabled=$Enabled")) {
            Set-NetFirewallRule -Name ([string]$rule.name) -Enabled $enabledValue -ErrorAction Stop
        }
    }
}

function Restore-QuickActionFirewallGroupState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    foreach ($rule in @($State.rules)) {
        $enabled = switch ([string]$rule.enabled) {
            'True' { $true }
            'False' { $false }
            default { throw "Unsupported sealed firewall enabled state: $($rule.enabled)" }
        }
        $ruleMatches = @(Get-NetFirewallRule -Name ([string]$rule.name) -ErrorAction Stop)
        if ($ruleMatches.Count -ne 1) {
            throw "Quick Action firewall rule identity changed during restore: $($rule.name)"
        }
        $current = $ruleMatches[0]
        foreach ($property in @('Direction', 'Action', 'Profile', 'Group')) {
            $sealedName = $property.ToLowerInvariant()
            if (-not ([string]$current.$property).Equals(
                    [string]$rule.$sealedName,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Quick Action firewall rule non-owned property changed: $($rule.name)/$property"
            }
        }
        if ($PSCmdlet.ShouldProcess([string]$rule.name, "Restore firewall enabled=$enabled")) {
            $enabledValue = if ($enabled) { 'True' } else { 'False' }
            Set-NetFirewallRule -Name ([string]$rule.name) -Enabled $enabledValue -ErrorAction Stop
        }
    }
}

function Get-QuickActionCanonicalFirewallDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('UPnP', 'WirelessDisplay')]
        [string]$SetName
    )

    if ($SetName -eq 'UPnP') {
        return @(
            [PSCustomObject][ordered]@{
                name = 'NoID-Block-SSDP-UDP-1900'
                displayName = 'NoID Privacy - Block SSDP UDP 1900'
                protocol = 'UDP'
                localPort = '1900'
            },
            [PSCustomObject][ordered]@{
                name = 'NoID-Block-UPnP-TCP-2869'
                displayName = 'NoID Privacy - Block UPnP TCP 2869'
                protocol = 'TCP'
                localPort = '2869'
            }
        )
    }

    return @(
        [PSCustomObject][ordered]@{
            name = 'NoID-Block-Miracast-TCP-7236'
            displayName = 'NoID Privacy - Block Miracast TCP 7236'
            protocol = 'TCP'
            localPort = '7236'
        },
        [PSCustomObject][ordered]@{
            name = 'NoID-Block-Miracast-TCP-7250'
            displayName = 'NoID Privacy - Block Miracast TCP 7250'
            protocol = 'TCP'
            localPort = '7250'
        },
        [PSCustomObject][ordered]@{
            name = 'NoID-Block-Miracast-UDP-7236'
            displayName = 'NoID Privacy - Block Miracast UDP 7236'
            protocol = 'UDP'
            localPort = '7236'
        },
        [PSCustomObject][ordered]@{
            name = 'NoID-Block-Miracast-UDP-7250'
            displayName = 'NoID Privacy - Block Miracast UDP 7250'
            protocol = 'UDP'
            localPort = '7250'
        }
    )
}

function Get-QuickActionNamedFirewallRuleSnapshot {
    <#
    .SYNOPSIS
        Reads all six canonical NoID Privacy rule names in one Get-NetFirewallRule call.
    .DESCRIPTION
        Returns a case-insensitive dictionary keyed by rule name whose values
        are the exact rule objects a per-name query would have returned: a
        missing name simply has no entry (the per-name query would have been
        empty), and a duplicated name accumulates every match so the caller's
        ambiguity guard still fires. Only Get-AllQuickActionStates stores this
        as the batch snapshot; every other path keeps querying live per name.
    #>
    [CmdletBinding()]
    param()

    $definitions = @(
        Get-QuickActionCanonicalFirewallDefinitions -SetName UPnP
        Get-QuickActionCanonicalFirewallDefinitions -SetName WirelessDisplay
    )
    $ruleNames = [string[]]@($definitions | ForEach-Object { [string]$_.name })
    $snapshot = [System.Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($rule in @(Get-NetFirewallRule -Name $ruleNames -ErrorAction SilentlyContinue)) {
        $ruleName = [string]$rule.Name
        if ([string]::IsNullOrWhiteSpace($ruleName)) {
            throw 'A firewall rule without a name cannot enter the Quick Action snapshot.'
        }
        if ($snapshot.ContainsKey($ruleName)) {
            $snapshot[$ruleName] = @($snapshot[$ruleName]) + @($rule)
        }
        else {
            $snapshot[$ruleName] = @($rule)
        }
    }
    return $snapshot
}

function Get-QuickActionNamedFirewallState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('UPnP', 'WirelessDisplay')]
        [string]$SetName
    )

    $entries = foreach ($definition in Get-QuickActionCanonicalFirewallDefinitions -SetName $SetName) {
        # The whole if-expression is wrapped in @(): assigning an if that
        # yields a one-element list would unwrap it to a bare object on
        # Windows PowerShell 5.1 and break the .Count checks below.
        $rules = @(if ($null -ne $script:QuickActionBatchNamedFirewallRules) {
                if ($script:QuickActionBatchNamedFirewallRules.ContainsKey([string]$definition.name)) {
                    $script:QuickActionBatchNamedFirewallRules[[string]$definition.name]
                }
            }
            else {
                Get-NetFirewallRule -Name ([string]$definition.name) -ErrorAction SilentlyContinue
            })
        if ($rules.Count -gt 1) {
            throw "Quick Action named firewall identity is ambiguous: $($definition.name)"
        }
        if ($rules.Count -eq 0) {
            [PSCustomObject][ordered]@{
                name = [string]$definition.name
                exists = $false
                canonical = $true
                displayName = [string]$definition.displayName
                protocol = [string]$definition.protocol
                localPort = [string]$definition.localPort
            }
            continue
        }

        $rule = $rules[0]
        $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
        $canonical = $portFilters.Count -eq 1 -and
            [string]$rule.Enabled -eq 'True' -and
            [string]$rule.Direction -eq 'Inbound' -and
            [string]$rule.Action -eq 'Block' -and
            [string]$rule.Profile -eq 'Any' -and
            [string]$portFilters[0].Protocol -eq [string]$definition.protocol -and
            [string]$portFilters[0].LocalPort -eq [string]$definition.localPort -and
            [string]$portFilters[0].RemotePort -eq 'Any'
        [PSCustomObject][ordered]@{
            name = [string]$definition.name
            exists = $true
            canonical = [bool]$canonical
            displayName = [string]$rule.DisplayName
            protocol = if ($portFilters.Count -eq 1) { [string]$portFilters[0].Protocol } else { $null }
            localPort = if ($portFilters.Count -eq 1) { [string]$portFilters[0].LocalPort } else { $null }
        }
    }

    return [PSCustomObject][ordered]@{
        kind = 'NamedFirewallRules'
        setName = $SetName
        rules = @($entries)
    }
}

function Set-QuickActionNamedFirewallRules {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('UPnP', 'WirelessDisplay')]
        [string]$SetName,

        [Parameter(Mandatory = $true)]
        [bool]$Present
    )

    foreach ($definition in Get-QuickActionCanonicalFirewallDefinitions -SetName $SetName) {
        $rules = @(Get-NetFirewallRule -Name ([string]$definition.name) -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 1) {
            throw "Quick Action named firewall identity is ambiguous: $($definition.name)"
        }
        if ($Present) {
            if ($rules.Count -eq 0 -and
                $PSCmdlet.ShouldProcess([string]$definition.name, 'Create canonical block rule')) {
                New-NetFirewallRule `
                    -Name ([string]$definition.name) `
                    -DisplayName ([string]$definition.displayName) `
                    -Description 'NoID Privacy Quick Action v1' `
                    -Direction Inbound `
                    -Action Block `
                    -Enabled True `
                    -Profile Any `
                    -Protocol ([string]$definition.protocol) `
                    -LocalPort ([string]$definition.localPort) `
                    -ErrorAction Stop | Out-Null
            }
        }
        elseif ($rules.Count -eq 1) {
            $currentSet = Get-QuickActionNamedFirewallState -SetName $SetName
            $currentEntry = @($currentSet.rules | Where-Object {
                    [string]$_.name -ceq [string]$definition.name
                })[0]
            if (-not [bool]$currentEntry.canonical) {
                throw "Refusing to remove noncanonical firewall rule: $($definition.name)"
            }
            if ($PSCmdlet.ShouldProcess([string]$definition.name, 'Remove canonical block rule')) {
                Remove-NetFirewallRule -Name ([string]$definition.name) -ErrorAction Stop
            }
        }
    }
}

function Restore-QuickActionNamedFirewallState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    if ([string]$State.kind -cne 'NamedFirewallRules' -or
        [string]$State.setName -notin @('UPnP', 'WirelessDisplay')) {
        throw 'Quick Action named-firewall restore state is malformed'
    }
    $noncanonical = @($State.rules | Where-Object { [bool]$_.exists -and -not [bool]$_.canonical })
    if ($noncanonical.Count -gt 0) {
        throw "A sealed Quick Action firewall prestate is noncanonical: $($noncanonical[0].name)"
    }
    $existingCount = @($State.rules | Where-Object { [bool]$_.exists }).Count
    if ($existingCount -notin @(0, @($State.rules).Count)) {
        throw 'Quick Action named-firewall prestate is mixed and cannot be restored as one closed set'
    }
    Set-QuickActionNamedFirewallRules -SetName ([string]$State.setName) `
        -Present:($existingCount -gt 0) -Confirm:$false
}

function Get-QuickActionWiFiDirectAdapterState {
    [CmdletBinding()]
    param()

    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
        } | Sort-Object { [string]$_.InterfaceGuid })
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $entries = foreach ($adapter in $adapters) {
        $guid = ([Guid]$adapter.InterfaceGuid).ToString('D').ToLowerInvariant()
        if (-not $seen.Add($guid) -or [string]$adapter.AdminStatus -notin @('Up', 'Down')) {
            throw "Quick Action Wi-Fi Direct adapter identity/state is invalid: $guid"
        }
        [PSCustomObject][ordered]@{
            interfaceGuid = $guid
            name = [string]$adapter.Name
            interfaceIndex = [int]$adapter.InterfaceIndex
            interfaceDescription = [string]$adapter.InterfaceDescription
            adminStatus = [string]$adapter.AdminStatus
        }
    }
    return [PSCustomObject][ordered]@{
        kind = 'WiFiDirectAdapters'
        adapters = @($entries)
    }
}

function Set-QuickActionWiFiDirectAdapters {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    foreach ($entry in @($State.adapters)) {
        $adapterMatches = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                ([string]$_.InterfaceGuid).Equals(
                    [string]$entry.interfaceGuid,
                    [StringComparison]::OrdinalIgnoreCase
                )
            })
        if ($adapterMatches.Count -ne 1 -or
            [string]$adapterMatches[0].Name -cne [string]$entry.name -or
            [int]$adapterMatches[0].InterfaceIndex -ne [int]$entry.interfaceIndex -or
            [string]$adapterMatches[0].InterfaceDescription -cne [string]$entry.interfaceDescription) {
            throw "Quick Action Wi-Fi Direct adapter identity changed: $($entry.interfaceGuid)"
        }
        if ($PSCmdlet.ShouldProcess([string]$entry.interfaceGuid, "Set adapter enabled=$Enabled")) {
            if ($Enabled) {
                Enable-NetAdapter -Name ([string]$entry.name) `
                    -IncludeHidden -Confirm:$false -ErrorAction Stop
            }
            else {
                Disable-NetAdapter -Name ([string]$entry.name) `
                    -IncludeHidden -Confirm:$false -ErrorAction Stop
            }
        }
    }
}

function Restore-QuickActionWiFiDirectAdapterState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    foreach ($entry in @($State.adapters)) {
        $enable = [string]$entry.adminStatus -eq 'Up'
        Set-QuickActionWiFiDirectAdapters `
            -State ([PSCustomObject][ordered]@{
                kind = 'WiFiDirectAdapters'
                adapters = @($entry)
            }) `
            -Enabled:$enable `
            -Confirm:$false
    }
}

function Complete-QuickActionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [string]$OwningModule,

        [Parameter(Mandatory = $true)]
        [string]$State,

        [Parameter(Mandatory = $true)]
        [bool]$Actionable,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Reason = '',

        [Parameter(Mandatory = $true)]
        [string[]]$TargetIds,

        [Parameter(Mandatory = $true)]
        $Targets
    )

    $orderedTargetIds = [string[]]@($TargetIds)
    [Array]::Sort($orderedTargetIds, [StringComparer]::Ordinal)
    $seenTargetIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $invalidTargetId = $false
    foreach ($targetId in $orderedTargetIds) {
        if ([string]::IsNullOrWhiteSpace($targetId) -or -not $seenTargetIds.Add($targetId)) {
            $invalidTargetId = $true
        }
    }
    if ($invalidTargetId) {
        throw "Quick Action target IDs are empty or duplicated: $ActionId"
    }
    $payload = [ordered]@{
        actionId = $ActionId
        owningModule = $OwningModule
        state = $State
        actionable = $Actionable
        reason = $Reason
        targetIds = $orderedTargetIds
        targets = $Targets
    }
    return [PSCustomObject][ordered]@{
        schemaVersion = $script:QuickActionStateSchemaVersion
        actionId = $ActionId
        owningModule = $OwningModule
        state = $State
        actionable = $Actionable
        reason = $Reason
        targetIds = $orderedTargetIds
        targets = $Targets
        fingerprint = Get-QuickActionObjectSha256 -InputObject $payload
    }
}

function Get-QuickActionAsrState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    if (-not (Get-Command ConvertFrom-ASRPreference -ErrorAction SilentlyContinue)) {
        $normalizerPath = Join-Path $script:FrameworkRoot 'Modules\ASR\Private\ConvertFrom-ASRPreference.ps1'
        if (-not (Test-Path -LiteralPath $normalizerPath -PathType Leaf)) {
            throw "ASR preference normalizer is missing: $normalizerPath"
        }
        . $normalizerPath
    }

    $ruleId = ([Guid]([string]$Definition.RegistryName)).ToString('D').ToLowerInvariant()
    $registry = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name $ruleId
    if ($null -ne $script:QuickActionBatchMpPreferenceError) {
        throw $script:QuickActionBatchMpPreferenceError
    }
    $mpPreference = if ($null -ne $script:QuickActionBatchMpPreference) {
        $script:QuickActionBatchMpPreference
    }
    else {
        Get-MpPreference -ErrorAction Stop
    }
    $effective = ConvertFrom-ASRPreference -Preference $mpPreference
    $effectiveAction = if ($effective.Map.ContainsKey($ruleId)) {
        [int]$effective.Map[$ruleId]
    }
    else {
        $null
    }
    $unrelated = @($effective.Map.GetEnumerator() | Where-Object {
            [string]$_.Key -cne $ruleId
        } | Sort-Object Key | ForEach-Object {
            [PSCustomObject][ordered]@{
                id = [string]$_.Key
                action = [int]$_.Value
            }
        })
    $unrelatedFingerprint = Get-QuickActionObjectSha256 -InputObject $unrelated

    $actionable = $true
    $reason = ''
    if ([bool]$registry.valueExisted) {
        $registryAction = 0
        if ([string]$registry.type -cne 'String' -or
            -not [int]::TryParse(
                [string]$registry.value,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$registryAction
            ) -or $registryAction -notin @(0, 1, 2, 6) -or
            $null -eq $effectiveAction -or [int]$effectiveAction -ne $registryAction) {
            $actionable = $false
            $reason = 'ASR policy/effective state is contradictory or has an unsupported type.'
        }
    }

    $state = if (-not $actionable) {
        'Unknown'
    }
    elseif ($null -eq $effectiveAction -or [int]$effectiveAction -eq 2) {
        'Allow'
    }
    elseif ([int]$effectiveAction -eq 1) {
        'Block'
    }
    else {
        $actionable = $false
        $reason = "ASR mode $effectiveAction cannot be represented by the binary Quick Action."
        'Unknown'
    }

    $targets = [PSCustomObject][ordered]@{
        policyValue = $registry
        effectiveTarget = [PSCustomObject][ordered]@{
            kind = 'AsrEffectiveRule'
            id = $ruleId
            exists = ($null -ne $effectiveAction)
            action = $effectiveAction
        }
        unrelatedEffectiveRules = [PSCustomObject][ordered]@{
            kind = 'AsrUnrelatedRules'
            count = $unrelated.Count
            fingerprint = $unrelatedFingerprint
            entries = $unrelated
        }
    }
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds @(
            "registry:$([string]$Definition.RegistryPath)::$ruleId",
            "asr-effective:$ruleId",
            "asr-unrelated:*"
        ) `
        -Targets $targets
}

function Get-QuickActionBitLockerState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $registry = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name ([string]$Definition.RegistryName)
    $actionable = $true
    $reason = ''
    if (-not [bool]$registry.valueExisted) {
        $state = 'Allow'
    }
    elseif ([string]$registry.type -cne 'DWord' -or [int64]$registry.value -notin @(0, 1)) {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'RDVDenyWriteAccess has an unsupported type or value.'
    }
    elseif ([int64]$registry.value -eq 1) {
        $state = 'Enforce'
    }
    else {
        $state = 'Allow'
    }
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds @("registry:$([string]$Definition.RegistryPath)::$([string]$Definition.RegistryName)") `
        -Targets ([PSCustomObject][ordered]@{ policyValue = $registry })
}

function Get-QuickActionSmartScreenState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    # The OS SmartScreen policy pair is owned by the SecurityBaseline module:
    # EnableSmartScreen=1 plus ShellSmartScreenLevel Block/Warn. The toggle
    # changes only the level; EnableSmartScreen is captured as scope evidence
    # and fails closed when the policy layer is not applied at all.
    $level = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name ([string]$Definition.RegistryName)
    $enable = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name 'EnableSmartScreen'
    $actionable = $true
    $reason = ''
    $state = 'Unknown'
    if (-not [bool]$enable.valueExisted -or [string]$enable.type -cne 'DWord' -or [int64]$enable.value -ne 1) {
        $actionable = $false
        $reason = 'The EnableSmartScreen policy is not applied; apply the SecurityBaseline module first.'
    }
    elseif (-not [bool]$level.valueExisted -or [string]$level.type -cne 'String' -or [string]$level.value -cnotin @('Block', 'Warn')) {
        $actionable = $false
        $reason = 'ShellSmartScreenLevel is absent or has an unsupported type or value.'
    }
    else {
        $state = [string]$level.value
    }
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds @(
            "registry:$([string]$Definition.RegistryPath)::EnableSmartScreen",
            "registry:$([string]$Definition.RegistryPath)::$([string]$Definition.RegistryName)"
        ) `
        -Targets ([PSCustomObject][ordered]@{ policyValue = $level; enableValue = $enable })
}

function Get-QuickActionEdgeExtensionsState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $registry = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name ([string]$Definition.RegistryName)
    $allNames = @()
    if (Test-Path -LiteralPath ([string]$Definition.RegistryPath) -PathType Container) {
        $key = Get-Item -LiteralPath ([string]$Definition.RegistryPath) -ErrorAction Stop
        try {
            $allNames = @($key.GetValueNames() | Sort-Object)
        }
        finally {
            if ($key -is [IDisposable]) { $key.Dispose() }
        }
    }
    $otherNames = @($allNames | Where-Object {
            -not ([string]$_).Equals([string]$Definition.RegistryName, [StringComparison]::OrdinalIgnoreCase)
        })
    $actionable = $true
    $reason = ''
    if ($otherNames.Count -gt 0) {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'The Edge extension blocklist contains administrator/custom entries outside the NoID Privacy wildcard target.'
    }
    elseif (-not [bool]$registry.valueExisted) {
        $state = 'Allow'
    }
    elseif ([string]$registry.type -cne 'String' -or [string]$registry.value -cne '*') {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'The Edge extension wildcard entry is noncanonical and will not be overwritten.'
    }
    else {
        $state = 'Block'
    }

    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds @(
            "registry:$([string]$Definition.RegistryPath)::$([string]$Definition.RegistryName)",
            "registry-value-names:$([string]$Definition.RegistryPath)"
        ) `
        -Targets ([PSCustomObject][ordered]@{
            wildcardValue = $registry
            allValueNames = [string[]]$allNames
        })
}

function Get-QuickActionDnsResolverEvidence {
    [CmdletBinding()]
    param()

    $computerSystems = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
    if ($computerSystems.Count -ne 1) {
        throw "Expected one computer-system record for DoH applicability; found $($computerSystems.Count)"
    }
    $domainJoined = [bool]$computerSystems[0].PartOfDomain

    $routeIndexes = @(
        Get-NetRoute -ErrorAction Stop |
            Where-Object {
                [string]$_.DestinationPrefix -in @('0.0.0.0/0', '::/0') -and
                [string]$_.State -ne 'Unreachable'
            } |
            Sort-Object RouteMetric, InterfaceMetric |
            ForEach-Object { [int]$_.InterfaceIndex } |
            Select-Object -Unique
    )
    if ($routeIndexes.Count -eq 0) {
        throw 'No active default-route interface is available for DoH applicability.'
    }

    $requiredDnsQuickActionFunctions = @(
        'ConvertTo-DnsCanonicalAddress',
        'ConvertTo-DnsInterfaceDohTargetState',
        'Get-DnsInterfaceDohState',
        'Get-PhysicalAdapters',
        'Set-DnsInterfaceDohState',
        'Test-DnsInterfaceDohStateExact',
        'Test-DNSIPv6StackEnabled'
    )
    $missingDnsQuickActionFunctions = @($requiredDnsQuickActionFunctions | Where-Object {
            -not (Get-Command $_ -CommandType Function -ErrorAction SilentlyContinue)
        })
    if ($missingDnsQuickActionFunctions.Count -gt 0) {
        throw "DNS Quick Action helper surface is incomplete: $($missingDnsQuickActionFunctions -join ', ')"
    }

    $managedAdapters = @(Get-PhysicalAdapters -RequireVpnInspection)
    if ($managedAdapters.Count -eq 0) {
        throw 'No managed physical DNS adapter is available for the DNS Quick Action.'
    }
    $ipv6StackEnabled = Test-DNSIPv6StackEnabled
    $addressSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $adapterEvidence = [System.Collections.Generic.List[object]]::new()
    $interfaceDohEvidence = [System.Collections.Generic.List[object]]::new()
    $managedFamilyComplete = $true
    $interfaceDohFamilyComplete = $true
    $activeRouteIndexes = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($routeIndex in $routeIndexes) { $null = $activeRouteIndexes.Add([int]$routeIndex) }
    foreach ($adapter in $managedAdapters) {
        $interfaceIndex = [int]$adapter.InterfaceIndex
        $interfaceName = [string]$adapter.Name
        if ([string]::IsNullOrWhiteSpace($interfaceName) -or
            [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid)) {
            throw "Managed DNS interface has no stable name/GUID: $interfaceIndex"
        }
        $interfaceGuidValue = [Guid]::Empty
        if (-not [Guid]::TryParse(
                ([string]$adapter.InterfaceGuid).Trim([char[]]@('{', '}')),
                [ref]$interfaceGuidValue
            )) {
            throw "Managed DNS interface has an invalid GUID: $interfaceIndex"
        }
        $interfaceGuid = $interfaceGuidValue.ToString('D').ToLowerInvariant()
        $ipv6Bindings = @(Get-NetAdapterBinding `
                -Name $interfaceName `
                -ComponentID ms_tcpip6 `
                -ErrorAction Stop)
        if ($ipv6Bindings.Count -ne 1) {
            throw "Managed DNS interface has ambiguous IPv6 binding state: $interfaceIndex"
        }
        $managedFamilies = if ([bool]$ipv6Bindings[0].Enabled -and $ipv6StackEnabled) {
            @(2, 23)
        }
        else { @(2) }
        # DisabledComponents=0xFF suppresses effective IPv6 resolver readback,
        # but it does not remove the binding, static NameServer value, or the
        # native DNS_INTERFACE_SETTINGS3 state shown by Windows Settings. The
        # Quick Action therefore owns that visible IPv6 DoH layer whenever the
        # adapter binding is enabled, without claiming active IPv6 transport.
        $interfaceDohFamilies = if ([bool]$ipv6Bindings[0].Enabled) { @(2, 23) } else { @(2) }
        $records = @(Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ErrorAction Stop)
        $addresses = [System.Collections.Generic.List[string]]::new()
        foreach ($family in $managedFamilies) {
            $familyRecords = @($records | Where-Object { [int]$_.AddressFamily -eq $family })
            if ($familyRecords.Count -ne 1) {
                throw "DNS address-family state is incomplete or ambiguous: $interfaceIndex/$family"
            }
            $familyAddresses = [System.Collections.Generic.List[string]]::new()
            $record = $familyRecords[0]
            foreach ($rawAddress in @($record.ServerAddresses)) {
                $parsed = $null
                if (-not [System.Net.IPAddress]::TryParse([string]$rawAddress, [ref]$parsed)) {
                    throw "Windows returned an invalid DNS server address: $rawAddress"
                }
                $canonical = $parsed.ToString()
                $expectedFamily = if ($family -eq 2) {
                    [System.Net.Sockets.AddressFamily]::InterNetwork
                }
                else { [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
                if ($parsed.AddressFamily -ne $expectedFamily) {
                    throw "Windows returned a DNS server in the wrong address family: $interfaceIndex/$family/$canonical"
                }
                $null = $addressSet.Add($canonical)
                $addresses.Add($canonical)
                $familyAddresses.Add($canonical)
            }
            if ($familyAddresses.Count -eq 0) {
                $managedFamilyComplete = $false
            }
        }
        foreach ($family in $interfaceDohFamilies) {
            $nativeState = Get-DnsInterfaceDohState `
                -InterfaceGuid $interfaceGuid `
                -AddressFamily $family
            $nativeAddresses = [string[]]@($nativeState.NameServers)
            if ($nativeAddresses.Count -eq 0) {
                $interfaceDohFamilyComplete = $false
                continue
            }
            $interfaceDohEvidence.Add([PSCustomObject][ordered]@{
                    interfaceIndex = $interfaceIndex
                    interfaceGuid = $interfaceGuid
                    addressFamily = $family
                    serverAddresses = $nativeAddresses
                    nativeState = $nativeState
                })
        }
        $adapterEvidence.Add([PSCustomObject][ordered]@{
                interfaceIndex = $interfaceIndex
                interfaceGuid = $interfaceGuid
                activeDefaultRoute = $activeRouteIndexes.Contains($interfaceIndex)
                serverAddresses = @($addresses.ToArray() | Sort-Object -Unique)
            })
    }
    $activeAdapterEvidence = @($adapterEvidence | Where-Object activeDefaultRoute)
    if ($activeAdapterEvidence.Count -eq 0) {
        throw 'No active default-route interface belongs to the managed DNS adapter set.'
    }
    $activeAddresses = @($activeAdapterEvidence.serverAddresses | Sort-Object -Unique)
    if ($activeAddresses.Count -eq 0) {
        throw 'Active default-route interfaces have no DNS server addresses.'
    }
    $addresses = @($addressSet | Sort-Object)

    $providersPath = Join-Path $script:FrameworkRoot 'Modules\DNS\Config\Providers.json'
    $configuration = Get-Content -LiteralPath $providersPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $providerMatches = [System.Collections.Generic.List[string]]::new()
    foreach ($providerProperty in @($configuration.providers.PSObject.Properties)) {
        $provider = $providerProperty.Value
        $providerAddresses = @(
            [string]$provider.ipv4.primary,
            [string]$provider.ipv4.secondary,
            [string]$provider.ipv6.primary,
            [string]$provider.ipv6.secondary
        )
        if (@($activeAddresses | Where-Object { $_ -notin $providerAddresses }).Count -eq 0) {
            $providerMatches.Add([string]$providerProperty.Name)
        }
    }

    $registrations = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
    $registrationEvidence = [System.Collections.Generic.List[object]]::new()
    $registrationValid = $true
    $providerKey = if ($providerMatches.Count -eq 1) { [string]$providerMatches[0] } else { $null }
    $providerId = if ($providerKey) { [string]$configuration.providers.$providerKey.intentToken } else { $null }
    $expectedProviderId = if ($providerKey) {
        switch ($providerKey) {
            'cloudflare' { 'Cloudflare' }
            'quad9' { 'Quad9' }
            'adguard' { 'AdGuard' }
            default { $null }
        }
    }
    else { $null }
    if ($providerKey -and $providerId -cne $expectedProviderId) {
        throw "Embedded DNS provider '$providerKey' has no canonical intent token"
    }
    $expectedTemplate = if ($providerKey) {
        [string]$configuration.providers.$providerKey.doh.template
    }
    else {
        $null
    }
    $managedAddresses = if ($providerKey) {
        @(
            [string]$configuration.providers.$providerKey.ipv4.primary,
            [string]$configuration.providers.$providerKey.ipv4.secondary,
            [string]$configuration.providers.$providerKey.ipv6.primary,
            [string]$configuration.providers.$providerKey.ipv6.secondary
        ) | ForEach-Object { ConvertTo-DnsCanonicalAddress -Address $_ }
    }
    else { [string[]]$addresses }
    $managedAddressesMatchProvider = $providerKey -and
        @($addresses | Where-Object { $_ -notin $managedAddresses }).Count -eq 0
    $nativeAddressesMatchProvider = [bool]$providerKey
    if ($providerKey) {
        foreach ($interfaceState in @($interfaceDohEvidence)) {
            $expectedNativeAddresses = if ([int]$interfaceState.addressFamily -eq 2) {
                @(
                    [string]$configuration.providers.$providerKey.ipv4.primary,
                    [string]$configuration.providers.$providerKey.ipv4.secondary
                )
            }
            else {
                @(
                    [string]$configuration.providers.$providerKey.ipv6.primary,
                    [string]$configuration.providers.$providerKey.ipv6.secondary
                )
            }
            $expectedNativeAddresses = @($expectedNativeAddresses | ForEach-Object {
                    ConvertTo-DnsCanonicalAddress -Address $_
                })
            if ((@($interfaceState.serverAddresses) -join [char]0) -cne
                ($expectedNativeAddresses -join [char]0)) {
                $nativeAddressesMatchProvider = $false
                break
            }
        }
    }
    foreach ($address in $managedAddresses) {
        $registrationMatches = @($registrations | Where-Object {
                ([string]$_.ServerAddress).Equals($address, [StringComparison]::OrdinalIgnoreCase)
            })
        if ($registrationMatches.Count -ne 1) {
            $registrationValid = $false
            $registrationEvidence.Add([PSCustomObject][ordered]@{
                    serverAddress = $address
                    count = $registrationMatches.Count
                    dohTemplate = $null
                    autoUpgrade = $null
                    allowFallbackToUdp = $null
                })
            continue
        }
        $entry = $registrationMatches[0]
        $template = [string]$entry.DohTemplate
        $autoUpgrade = [bool]$entry.AutoUpgrade
        if (-not $providerKey -or
            -not $template.Equals($expectedTemplate, [StringComparison]::OrdinalIgnoreCase) -or
            -not $autoUpgrade) {
            $registrationValid = $false
        }
        $registrationEvidence.Add([PSCustomObject][ordered]@{
                serverAddress = $address
                count = 1
                dohTemplate = $template
                autoUpgrade = $autoUpgrade
                allowFallbackToUdp = [bool]$entry.AllowFallbackToUdp
            })
    }

    $supported = -not $domainJoined -and $providerMatches.Count -eq 1 -and
        $managedAddressesMatchProvider -and $managedFamilyComplete -and
        $interfaceDohFamilyComplete -and $nativeAddressesMatchProvider -and
        $registrationValid -and $interfaceDohEvidence.Count -gt 0
    $reason = if ($domainJoined) {
        'Require DoH is unavailable on a domain-joined computer.'
    }
    elseif ($providerMatches.Count -ne 1) {
        'Active resolver addresses do not map unambiguously to one embedded supported provider.'
    }
    elseif (-not $managedAddressesMatchProvider) {
        'A managed physical adapter uses resolver addresses outside the active embedded provider.'
    }
    elseif (-not $managedFamilyComplete) {
        'A managed physical adapter family has no resolver state; reapply the DNS module.'
    }
    elseif (-not $interfaceDohFamilyComplete) {
        'A binding-enabled adapter family has no native secure-DNS resolver state; reapply the DNS module.'
    }
    elseif (-not $nativeAddressesMatchProvider) {
        'Native adapter resolver addresses do not match the active embedded provider; reapply the DNS module.'
    }
    elseif (-not $registrationValid) {
        'One or more active resolver addresses lack the exact registered HTTPS DoH template.'
    }
    elseif ($interfaceDohEvidence.Count -eq 0) {
        'Active resolver interfaces expose no native secure-DNS state.'
    }
    else {
        ''
    }

    return [PSCustomObject][ordered]@{
        kind = 'DnsResolverEvidence'
        supported = [bool]$supported
        reason = $reason
        domainJoined = $domainJoined
        providerId = $providerId
        adapters = @($adapterEvidence.ToArray() | Sort-Object interfaceIndex)
        addresses = [string[]]$addresses
        activeAddresses = [string[]]$activeAddresses
        managedAddresses = [string[]]@($managedAddresses)
        registrations = @($registrationEvidence.ToArray() | Sort-Object serverAddress)
        dohTemplate = $expectedTemplate
        interfaceDohScopeVersion = 2
        interfaceDohStates = @($interfaceDohEvidence.ToArray() |
            Sort-Object interfaceIndex, addressFamily)
    }
}

function Get-QuickActionEncryptedDnsState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $registry = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name ([string]$Definition.RegistryName)
    $resolver = Get-QuickActionDnsResolverEvidence
    $actionable = [bool]$resolver.supported
    $reason = [string]$resolver.reason
    if (-not [bool]$registry.valueExisted) {
        $state = 'Allow'
    }
    elseif ([string]$registry.type -cne 'DWord' -or [int64]$registry.value -notin @(2, 3)) {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'DoHPolicy has an unsupported mode or registry type.'
    }
    elseif ([int64]$registry.value -eq 3) {
        $state = 'Require'
    }
    else {
        $state = 'Allow'
    }
    if (-not [bool]$resolver.supported) {
        $state = 'Unknown'
    }
    elseif ($state -ne 'Unknown') {
        $allowFallback = $state -eq 'Allow'
        $globalFallbackMatches = @($resolver.registrations | Where-Object {
                [bool]$_.allowFallbackToUdp -ne $allowFallback
            }).Count -eq 0
        $nativeStateMatches = $true
        foreach ($interfaceState in @($resolver.interfaceDohStates)) {
            $expectedNativeState = ConvertTo-DnsInterfaceDohTargetState `
                -AddressFamily ([int]$interfaceState.addressFamily) `
                -NameServers ([string[]]@($interfaceState.serverAddresses)) `
                -DohTemplate ([string]$resolver.dohTemplate) `
                -AllowFallbackToUdp $allowFallback
            if (-not (Test-DnsInterfaceDohStateExact `
                    -Actual $interfaceState.nativeState `
                    -Expected $expectedNativeState)) {
                $nativeStateMatches = $false
                break
            }
        }
        if (-not $globalFallbackMatches -or -not $nativeStateMatches) {
            $state = 'Unknown'
            $actionable = $false
            $reason = 'DoH policy, endpoint fallback, and native adapter encryption state are inconsistent; reapply the DNS module.'
        }
    }

    $targetIds = @("registry:$([string]$Definition.RegistryPath)::$([string]$Definition.RegistryName)")
    $targetIds += @($resolver.managedAddresses | ForEach-Object { "dns-resolver:$_" })
    $targetIds += @($resolver.interfaceDohStates | ForEach-Object {
            "dns-interface:$([string]$_.interfaceGuid):$([int]$_.addressFamily)"
        })
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds $targetIds `
        -Targets ([PSCustomObject][ordered]@{
            policyValue = $registry
            resolverEvidence = $resolver
        })
}

function Get-QuickActionRdpState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $deny = Get-QuickActionRegistryValueState `
        -Path ([string]$Definition.RegistryPath) `
        -Name ([string]$Definition.RegistryName)
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $nla = Get-QuickActionRegistryValueState -Path $policyPath -Name 'UserAuthentication'
    $tls = Get-QuickActionRegistryValueState -Path $policyPath -Name 'SecurityLayer'
    $firewall = Get-QuickActionFirewallGroupState -Group '@FirewallAPI.dll,-28752'
    $rdpServices = @(@('TermService', 'SessionEnv', 'UmRdpService') | ForEach-Object {
            Get-QuickActionServiceState -Name $_
        })

    $registryValid = (-not [bool]$deny.valueExisted -or
            ([string]$deny.type -eq 'DWord' -and [int64]$deny.value -in @(0, 1))) -and
        (-not [bool]$nla.valueExisted -or [string]$nla.type -eq 'DWord') -and
        (-not [bool]$tls.valueExisted -or [string]$tls.type -eq 'DWord')
    $serviceScopeValid = $rdpServices.Count -eq 3 -and
        @($rdpServices | Where-Object {
                -not [bool]$_.exists -or [string]$_.startType -eq 'Disabled'
            }).Count -eq 0
    $allFirewallDisabled = @($firewall.rules | Where-Object { [string]$_.enabled -ne 'False' }).Count -eq 0
    $allFirewallEnabled = @($firewall.rules | Where-Object { [string]$_.enabled -ne 'True' }).Count -eq 0
    $denied = (-not [bool]$deny.valueExisted) -or [int64]$deny.value -eq 1
    $enabledSecure = [bool]$deny.valueExisted -and [int64]$deny.value -eq 0 -and
        [bool]$nla.valueExisted -and [string]$nla.type -eq 'DWord' -and [int64]$nla.value -eq 1 -and
        [bool]$tls.valueExisted -and [string]$tls.type -eq 'DWord' -and [int64]$tls.value -eq 2 -and
        $allFirewallEnabled

    $actionable = $registryValid -and $serviceScopeValid
    $reason = ''
    if (-not $registryValid) {
        $state = 'Unknown'
        $reason = 'RDP registry state has an unsupported type or value.'
    }
    elseif (-not $serviceScopeValid) {
        $state = 'Unknown'
        $reason = 'The required RDP service scope is absent or disabled and will not be overwritten.'
    }
    elseif ($denied -and $allFirewallDisabled) {
        $state = 'Disable'
    }
    elseif ($enabledSecure) {
        $state = 'Enable'
    }
    else {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'RDP connection, NLA/TLS, and firewall-group state are contradictory.'
    }

    $targetIds = @(
        "registry:$([string]$Definition.RegistryPath)::$([string]$Definition.RegistryName)",
        "registry:$policyPath::UserAuthentication",
        "registry:$policyPath::SecurityLayer"
    )
    $targetIds += @($firewall.rules | ForEach-Object { "firewall-rule:$([string]$_.name)" })
    $targetIds += @($rdpServices | ForEach-Object { "service:$([string]$_.name)" })
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds $targetIds `
        -Targets ([PSCustomObject][ordered]@{
            denyConnections = $deny
            networkLevelAuthentication = $nla
            securityLayer = $tls
            firewallGroup = $firewall
            rdpServices = $rdpServices
        })
}

function ConvertTo-QuickActionRdpLegacyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    if ([string]$State.actionId -cne 'RDP') {
        throw 'Only an RDP Quick Action state has a legacy RDP projection'
    }

    # Recompute the frozen v2.2.5 logical verdict solely from the registry/firewall
    # targets that version sealed. A new service-side error must neither block
    # nor authorize restoration of an old session: those services were outside
    # its optimistic-concurrency and mutation scope.
    $deny = $State.targets.denyConnections
    $nla = $State.targets.networkLevelAuthentication
    $tls = $State.targets.securityLayer
    $firewall = $State.targets.firewallGroup
    $registryValid = (-not [bool]$deny.valueExisted -or
            ([string]$deny.type -eq 'DWord' -and [int64]$deny.value -in @(0, 1))) -and
        (-not [bool]$nla.valueExisted -or [string]$nla.type -eq 'DWord') -and
        (-not [bool]$tls.valueExisted -or [string]$tls.type -eq 'DWord')
    $allFirewallDisabled = @($firewall.rules | Where-Object {
            [string]$_.enabled -ne 'False'
        }).Count -eq 0
    $allFirewallEnabled = @($firewall.rules | Where-Object {
            [string]$_.enabled -ne 'True'
        }).Count -eq 0
    $denied = (-not [bool]$deny.valueExisted) -or [int64]$deny.value -eq 1
    $enabledSecure = [bool]$deny.valueExisted -and [int64]$deny.value -eq 0 -and
        [bool]$nla.valueExisted -and [string]$nla.type -eq 'DWord' -and [int64]$nla.value -eq 1 -and
        [bool]$tls.valueExisted -and [string]$tls.type -eq 'DWord' -and [int64]$tls.value -eq 2 -and
        $allFirewallEnabled

    $actionable = $registryValid
    $reason = ''
    if (-not $registryValid) {
        $legacyState = 'Unknown'
        $reason = 'RDP registry state has an unsupported type or value.'
    }
    elseif ($denied -and $allFirewallDisabled) {
        $legacyState = 'Disable'
    }
    elseif ($enabledSecure) {
        $legacyState = 'Enable'
    }
    else {
        $legacyState = 'Unknown'
        $actionable = $false
        $reason = 'RDP connection, NLA/TLS, and firewall-group state are contradictory.'
    }
    return Complete-QuickActionState `
        -ActionId ([string]$State.actionId) `
        -OwningModule ([string]$State.owningModule) `
        -State $legacyState `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds @($State.targetIds | Where-Object { [string]$_ -notlike 'service:*' }) `
        -Targets ([PSCustomObject][ordered]@{
            denyConnections = $State.targets.denyConnections
            networkLevelAuthentication = $State.targets.networkLevelAuthentication
            securityLayer = $State.targets.securityLayer
            firewallGroup = $State.targets.firewallGroup
        })
}

function Get-QuickActionSessionComparableState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $LiveState,

        [Parameter(Mandatory = $true)]
        $SealedState
    )

    $sealedTargetProperties = [string[]]@($SealedState.targets.PSObject.Properties.Name)
    if ([string]$SealedState.actionId -ceq 'RDP' -and
        'rdpServices' -notin $sealedTargetProperties) {
        # Legacy v2.2.5 RDP sessions predate the explicit capture of the three
        # services Windows starts as a side effect of enabling RDP. Preserve
        # their sealed registry/firewall contract without weakening new
        # sessions, whose full state compares directly below.
        return ConvertTo-QuickActionRdpLegacyState -State $LiveState
    }
    if ([string]$SealedState.actionId -ceq 'EncryptedDNS' -and
        'interfaceDohStates' -notin [string[]]@(
            $SealedState.targets.resolverEvidence.PSObject.Properties.Name
        )) {
        # Earlier 2.2.5 Quick Action sessions owned only DoHPolicy. Project a
        # live state onto that exact historic scope so those sealed sessions
        # remain restorable, while every new session owns endpoint fallback
        # and native per-interface DNS_INTERFACE_SETTINGS3 state as well.
        $policy = $LiveState.targets.policyValue
        $resolver = $LiveState.targets.resolverEvidence
        $liveActiveAdapters = @($resolver.adapters | Where-Object activeDefaultRoute)
        $sealedLegacyAdapters = @($SealedState.targets.resolverEvidence.adapters)
        $legacyAdapterSetMatches = $liveActiveAdapters.Count -eq $sealedLegacyAdapters.Count -and
            @($liveActiveAdapters | Where-Object {
                    [int]$_.interfaceIndex -notin [int[]]@($sealedLegacyAdapters.interfaceIndex)
                }).Count -eq 0
        $legacyAdapters = if ($legacyAdapterSetMatches) {
            @($sealedLegacyAdapters | ForEach-Object {
                    $sealedInterfaceIndex = [int]$_.interfaceIndex
                    $liveMatch = @($liveActiveAdapters | Where-Object {
                            [int]$_.interfaceIndex -eq $sealedInterfaceIndex
                        })
                    [PSCustomObject][ordered]@{
                        interfaceIndex = $sealedInterfaceIndex
                        serverAddresses = [string[]]@($liveMatch[0].serverAddresses)
                    }
                })
        }
        else {
            @($liveActiveAdapters | ForEach-Object {
                [PSCustomObject][ordered]@{
                    interfaceIndex = [int]$_.interfaceIndex
                    serverAddresses = [string[]]@($_.serverAddresses)
                }
            })
        }
        $legacyAddresses = [string[]]@($legacyAdapters.serverAddresses | Sort-Object -Unique)
        $legacyRegistrations = @($resolver.registrations | Where-Object {
                [string]$_.serverAddress -in $legacyAddresses
            })
        $legacyRegistrationValid = $legacyRegistrations.Count -eq $legacyAddresses.Count -and
            @($legacyRegistrations | Where-Object {
                    [int]$_.count -ne 1 -or
                    -not ([string]$_.dohTemplate).Equals(
                        [string]$resolver.dohTemplate,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [bool]$_.autoUpgrade
                }).Count -eq 0
        $actionable = -not [bool]$resolver.domainJoined -and
            -not [string]::IsNullOrWhiteSpace([string]$resolver.providerId) -and
            $legacyRegistrationValid -and $legacyAdapterSetMatches
        $reason = if ([bool]$resolver.domainJoined) {
            'Require DoH is unavailable on a domain-joined computer.'
        }
        elseif ([string]::IsNullOrWhiteSpace([string]$resolver.providerId)) {
            'Active resolver addresses do not map unambiguously to one embedded supported provider.'
        }
        elseif (-not $legacyRegistrationValid) {
            'One or more active resolver addresses lack the exact registered HTTPS DoH template.'
        }
        elseif (-not $legacyAdapterSetMatches) {
            'The active resolver-interface set changed since this legacy Quick Action session.'
        }
        else { '' }
        if (-not [bool]$policy.valueExisted) {
            $state = 'Allow'
        }
        elseif ([string]$policy.type -cne 'DWord' -or [int64]$policy.value -notin @(2, 3)) {
            $state = 'Unknown'
            $actionable = $false
            $reason = 'DoHPolicy has an unsupported mode or registry type.'
        }
        elseif ([int64]$policy.value -eq 3) { $state = 'Require' }
        else { $state = 'Allow' }
        if (-not [bool]$actionable) { $state = 'Unknown' }
        $legacyResolver = [PSCustomObject][ordered]@{
            kind = [string]$resolver.kind
            supported = [bool]$actionable
            reason = $reason
            domainJoined = [bool]$resolver.domainJoined
            providerId = $resolver.providerId
            adapters = @($legacyAdapters)
            addresses = [string[]]@($legacyAddresses)
            registrations = @($legacyRegistrations)
        }
        return Complete-QuickActionState `
            -ActionId EncryptedDNS `
            -OwningModule DNS `
            -State $state `
            -Actionable:$actionable `
            -Reason $reason `
            -TargetIds ([string[]]@($SealedState.targetIds)) `
            -Targets ([PSCustomObject][ordered]@{
                policyValue = $policy
                resolverEvidence = $legacyResolver
            })
    }
    if ([string]$SealedState.actionId -ceq 'EncryptedDNS' -and
        'interfaceDohStates' -in [string[]]@(
            $SealedState.targets.resolverEvidence.PSObject.Properties.Name
        ) -and
        'interfaceDohScopeVersion' -notin [string[]]@(
            $SealedState.targets.resolverEvidence.PSObject.Properties.Name
        )) {
        # Native-interface-aware 2.2.5 sessions predate the split between
        # effective IPv6 transport and UI-visible IPv6 DoH state. Project the
        # live state onto the exact adapter-family identities sealed then. An
        # old session can therefore restore its original IPv4-only scope on a
        # DisabledComponents=0xFF host, while it neither owns nor masks drift
        # in the newly managed IPv6 native layer.
        $liveResolver = $LiveState.targets.resolverEvidence
        $sealedResolver = $SealedState.targets.resolverEvidence
        $sealedInterfaceIds = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($sealedInterface in @($sealedResolver.interfaceDohStates)) {
            $null = $sealedInterfaceIds.Add(
                "$([string]$sealedInterface.interfaceGuid):$([int]$sealedInterface.addressFamily)"
            )
        }
        $projectedInterfaces = @($liveResolver.interfaceDohStates | Where-Object {
                $sealedInterfaceIds.Contains(
                    "$([string]$_.interfaceGuid):$([int]$_.addressFamily)"
                )
            } | Sort-Object interfaceIndex, addressFamily)
        $registrationValid = @($liveResolver.registrations).Count -eq
            @($liveResolver.managedAddresses).Count -and
            @($liveResolver.registrations | Where-Object {
                    [int]$_.count -ne 1 -or
                    -not ([string]$_.dohTemplate).Equals(
                        [string]$liveResolver.dohTemplate,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [bool]$_.autoUpgrade
                }).Count -eq 0
        $interfaceSetComplete = $projectedInterfaces.Count -eq $sealedInterfaceIds.Count
        $policy = $LiveState.targets.policyValue
        $policyValid = [bool]$policy.valueExisted -and
            [string]$policy.type -ceq 'DWord' -and
            [int64]$policy.value -in @(2, 3)
        $allowFallback = $policyValid -and [int64]$policy.value -eq 2
        $fallbackValid = $policyValid -and
            @($liveResolver.registrations | Where-Object {
                    [bool]$_.allowFallbackToUdp -ne $allowFallback
                }).Count -eq 0
        $nativeValid = $interfaceSetComplete
        if ($nativeValid) {
            foreach ($interfaceState in $projectedInterfaces) {
                $expected = ConvertTo-DnsInterfaceDohTargetState `
                    -AddressFamily ([int]$interfaceState.addressFamily) `
                    -NameServers ([string[]]@($interfaceState.serverAddresses)) `
                    -DohTemplate ([string]$liveResolver.dohTemplate) `
                    -AllowFallbackToUdp $allowFallback
                if (-not (Test-DnsInterfaceDohStateExact `
                        -Actual $interfaceState.nativeState -Expected $expected)) {
                    $nativeValid = $false
                    break
                }
            }
        }
        $actionable = -not [bool]$liveResolver.domainJoined -and
            -not [string]::IsNullOrWhiteSpace([string]$liveResolver.providerId) -and
            $registrationValid -and $interfaceSetComplete -and
            $policyValid -and $fallbackValid -and $nativeValid
        $reason = if ([bool]$liveResolver.domainJoined) {
            'Require DoH is unavailable on a domain-joined computer.'
        }
        elseif ([string]::IsNullOrWhiteSpace([string]$liveResolver.providerId)) {
            'Active resolver addresses do not map unambiguously to one embedded supported provider.'
        }
        elseif (-not $registrationValid) {
            'One or more active resolver addresses lack the exact registered HTTPS DoH template.'
        }
        elseif (-not $interfaceSetComplete) {
            'The native adapter-family set changed since this Quick Action session.'
        }
        elseif (-not $policyValid) {
            'DoHPolicy has an unsupported mode or registry type.'
        }
        elseif (-not $fallbackValid -or -not $nativeValid) {
            'DoH policy, endpoint fallback, and native adapter encryption state are inconsistent; reapply the DNS module.'
        }
        else { '' }
        $state = if ($actionable -and [int64]$policy.value -eq 3) { 'Require' }
            elseif ($actionable) { 'Allow' }
            else { 'Unknown' }
        $projectedResolver = [PSCustomObject][ordered]@{
            kind = $liveResolver.kind
            supported = [bool]$actionable
            reason = $reason
            domainJoined = $liveResolver.domainJoined
            providerId = $liveResolver.providerId
            adapters = @($liveResolver.adapters)
            addresses = [string[]]@($liveResolver.addresses)
            activeAddresses = [string[]]@($liveResolver.activeAddresses)
            managedAddresses = [string[]]@($liveResolver.managedAddresses)
            registrations = @($liveResolver.registrations)
            dohTemplate = $liveResolver.dohTemplate
            interfaceDohStates = @($projectedInterfaces)
        }
        return Complete-QuickActionState `
            -ActionId EncryptedDNS `
            -OwningModule DNS `
            -State $state `
            -Actionable:$actionable `
            -Reason $reason `
            -TargetIds ([string[]]@($SealedState.targetIds)) `
            -Targets ([PSCustomObject][ordered]@{
                policyValue = $LiveState.targets.policyValue
                resolverEvidence = $projectedResolver
            })
    }
    return $LiveState
}

function Get-QuickActionUpnpState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $services = @(
        Get-QuickActionServiceState -Name 'SSDPSRV'
        Get-QuickActionServiceState -Name 'upnphost'
    )
    $firewall = Get-QuickActionNamedFirewallState -SetName UPnP
    $noncanonical = @($firewall.rules | Where-Object { [bool]$_.exists -and -not [bool]$_.canonical })
    $existingServices = @($services | Where-Object { [bool]$_.exists })
    $blockedServices = @($existingServices | Where-Object {
            [string]$_.startType -eq 'Disabled' -and [string]$_.status -eq 'Stopped'
        }).Count -eq $existingServices.Count
    $allowedServices = @($existingServices | Where-Object {
            [string]$_.startType -ne 'Disabled'
        }).Count -eq $existingServices.Count
    $allRulesPresent = @($firewall.rules | Where-Object {
            [bool]$_.exists -and [bool]$_.canonical
        }).Count -eq @($firewall.rules).Count
    $allRulesAbsent = @($firewall.rules | Where-Object { [bool]$_.exists }).Count -eq 0

    $actionable = $noncanonical.Count -eq 0
    $reason = ''
    if (-not $actionable) {
        $state = 'Unknown'
        $reason = "Firewall rule '$($noncanonical[0].name)' conflicts with the canonical UPnP action."
    }
    elseif ($blockedServices -and $allRulesPresent) {
        $state = 'Block'
    }
    elseif ($allowedServices -and $allRulesAbsent) {
        $state = 'Allow'
    }
    else {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'UPnP service and firewall state are mixed.'
    }

    $targetIds = @($services | ForEach-Object { "service:$([string]$_.name)" })
    $targetIds += @($firewall.rules | ForEach-Object { "firewall-rule:$([string]$_.name)" })
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds $targetIds `
        -Targets ([PSCustomObject][ordered]@{
            services = $services
            firewallRules = $firewall
        })
}

function Get-QuickActionWirelessDisplayState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    $path = [string]$Definition.RegistryPath
    $desiredValues = [ordered]@{
        AllowProjectionToPC = 0
        RequirePinForPairing = 2
        AllowProjectionFromPC = 0
        AllowMdnsAdvertisement = 0
        AllowMdnsDiscovery = 0
        AllowProjectionFromPCOverInfrastructure = 0
        AllowProjectionToPCOverInfrastructure = 0
    }
    $policies = foreach ($name in $desiredValues.Keys) {
        Get-QuickActionRegistryValueState -Path $path -Name $name
    }
    $firewall = Get-QuickActionNamedFirewallState -SetName WirelessDisplay
    $service = Get-QuickActionServiceState -Name 'WFDSConMgrSvc'
    $adapters = Get-QuickActionWiFiDirectAdapterState

    $policyDisabled = $true
    $policyAbsent = $true
    foreach ($policy in $policies) {
        if (-not [bool]$policy.valueExisted) {
            $policyDisabled = $false
            continue
        }
        $policyAbsent = $false
        if ([string]$policy.type -ne 'DWord' -or
            [int64]$policy.value -ne [int64]$desiredValues[[string]$policy.name]) {
            $policyDisabled = $false
        }
    }
    $noncanonical = @($firewall.rules | Where-Object { [bool]$_.exists -and -not [bool]$_.canonical })
    $allRulesPresent = @($firewall.rules | Where-Object {
            [bool]$_.exists -and [bool]$_.canonical
        }).Count -eq @($firewall.rules).Count
    $allRulesAbsent = @($firewall.rules | Where-Object { [bool]$_.exists }).Count -eq 0
    $serviceDisabled = -not [bool]$service.exists -or
        ([string]$service.startType -eq 'Disabled' -and [string]$service.status -eq 'Stopped')
    $serviceEnabled = -not [bool]$service.exists -or [string]$service.startType -ne 'Disabled'
    $adaptersDisabled = @($adapters.adapters | Where-Object { [string]$_.adminStatus -ne 'Down' }).Count -eq 0
    $adaptersEnabled = @($adapters.adapters | Where-Object { [string]$_.adminStatus -ne 'Up' }).Count -eq 0

    $actionable = $noncanonical.Count -eq 0
    $reason = ''
    if (-not $actionable) {
        $state = 'Unknown'
        $reason = "Firewall rule '$($noncanonical[0].name)' conflicts with the canonical Wireless Display action."
    }
    elseif ($policyDisabled -and $allRulesPresent -and $serviceDisabled -and $adaptersDisabled) {
        $state = 'Disable'
    }
    elseif ($policyAbsent -and $allRulesAbsent -and $serviceEnabled -and $adaptersEnabled) {
        $state = 'Enable'
    }
    else {
        $state = 'Unknown'
        $actionable = $false
        $reason = 'Wireless Display policy, firewall, service, or adapter state is mixed.'
    }

    $targetIds = @($policies | ForEach-Object { "registry:$path::$([string]$_.name)" })
    $targetIds += @($firewall.rules | ForEach-Object { "firewall-rule:$([string]$_.name)" })
    $targetIds += "service:$([string]$service.name)"
    $targetIds += @($adapters.adapters | ForEach-Object { "net-adapter:$([string]$_.interfaceGuid)" })
    return Complete-QuickActionState `
        -ActionId ([string]$Definition.Id) `
        -OwningModule ([string]$Definition.OwningModule) `
        -State $state `
        -Actionable:$actionable `
        -Reason $reason `
        -TargetIds $targetIds `
        -Targets ([PSCustomObject][ordered]@{
            policyValues = @($policies)
            firewallRules = $firewall
            service = $service
            adapters = $adapters
        })
}

function Get-QuickActionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
            'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
        )]
        [string]$ActionId
    )

    $definition = Get-QuickActionDefinition -ActionId $ActionId
    $state = switch ($ActionId) {
        { $_ -in @('ManagementTools', 'NewSoftware') } {
            Get-QuickActionAsrState -Definition $definition
            break
        }
        'EncryptedDNS' {
            Get-QuickActionEncryptedDnsState -Definition $definition
            break
        }
        'BitLockerUSB' {
            Get-QuickActionBitLockerState -Definition $definition
            break
        }
        'RDP' {
            Get-QuickActionRdpState -Definition $definition
            break
        }
        'UPnP' {
            Get-QuickActionUpnpState -Definition $definition
            break
        }
        'WirelessDisplay' {
            Get-QuickActionWirelessDisplayState -Definition $definition
            break
        }
        'EdgeExtensions' {
            Get-QuickActionEdgeExtensionsState -Definition $definition
            break
        }
        'SmartScreen' {
            Get-QuickActionSmartScreenState -Definition $definition
            break
        }
    }
    return $state
}

function Get-AllQuickActionStates {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $results = [System.Collections.Generic.List[object]]::new()
    # One Defender snapshot for the whole batch: both ASR actions consume the
    # same reading. A failed snapshot stays $null so each ASR action falls
    # back to its own call (and reports its own error state on failure).
    $script:QuickActionBatchMpPreference = $null
    $script:QuickActionBatchMpPreferenceError = $null
    $script:QuickActionBatchNamedFirewallRules = $null
    try {
        try {
            $script:QuickActionBatchMpPreference = Get-MpPreference -ErrorAction Stop
        }
        catch {
            $script:QuickActionBatchMpPreference = $null
            $script:QuickActionBatchMpPreferenceError = $_.Exception
        }
        try {
            # One firewall round-trip for all six canonical rule names; UPnP
            # and WirelessDisplay consume the same reading. The snapshot is
            # purely an accelerator: on any failure it stays $null and both
            # actions fall back to their own live per-name queries.
            $script:QuickActionBatchNamedFirewallRules = Get-QuickActionNamedFirewallRuleSnapshot
        }
        catch {
            $script:QuickActionBatchNamedFirewallRules = $null
        }
        foreach ($definition in Get-QuickActionDefinitions) {
            try {
                $results.Add((Get-QuickActionState -ActionId ([string]$definition.Id)))
            }
            catch {
                $results.Add((Complete-QuickActionState `
                            -ActionId ([string]$definition.Id) `
                            -OwningModule ([string]$definition.OwningModule) `
                            -State 'Unknown' `
                            -Actionable:$false `
                            -Reason $_.Exception.Message `
                            -TargetIds @("unavailable:$([string]$definition.Id)") `
                            -Targets ([PSCustomObject][ordered]@{
                                queryError = $_.Exception.Message
                            })))
            }
        }
    }
    finally {
        $script:QuickActionBatchMpPreference = $null
        $script:QuickActionBatchMpPreferenceError = $null
        $script:QuickActionBatchNamedFirewallRules = $null
    }
    return @($results.ToArray())
}

function Wait-QuickActionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Predicate,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 20
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $state = Get-QuickActionState -ActionId $ActionId
        if (& $Predicate $state) { return $state }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return Get-QuickActionState -ActionId $ActionId
}

function Invoke-QuickActionScopeApply {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $PreState,

        [Parameter(Mandatory = $true)]
        [string]$DesiredState
    )

    $actionId = [string]$PreState.actionId
    switch ($actionId) {
        { $_ -in @('ManagementTools', 'NewSoftware') } {
            $action = if ($DesiredState -eq 'Block') { 1 } else { 2 }
            Set-QuickActionRegistryValue `
                -Path ([string]$PreState.targets.policyValue.path) `
                -Name ([string]$PreState.targets.policyValue.name) `
                -Type String `
                -Value $action.ToString([Globalization.CultureInfo]::InvariantCulture) `
                -Confirm:$false
        }
        'EncryptedDNS' {
            $allowFallback = $DesiredState -eq 'Allow'
            foreach ($registration in @($PreState.targets.resolverEvidence.registrations)) {
                Set-DnsClientDohServerAddress `
                    -ServerAddress ([string]$registration.serverAddress) `
                    -DohTemplate ([string]$registration.dohTemplate) `
                    -AllowFallbackToUdp $allowFallback `
                    -AutoUpgrade $true `
                    -ErrorAction Stop | Out-Null
            }
            foreach ($interfaceState in @($PreState.targets.resolverEvidence.interfaceDohStates)) {
                $targetState = ConvertTo-DnsInterfaceDohTargetState `
                    -AddressFamily ([int]$interfaceState.addressFamily) `
                    -NameServers ([string[]]@($interfaceState.serverAddresses)) `
                    -DohTemplate ([string]$PreState.targets.resolverEvidence.dohTemplate) `
                    -AllowFallbackToUdp $allowFallback
                $null = Set-DnsInterfaceDohState `
                    -InterfaceGuid ([string]$interfaceState.interfaceGuid) `
                    -AddressFamily ([int]$interfaceState.addressFamily) `
                    -NameServers ([string[]]@($targetState.NameServers)) `
                    -Properties ([object[]]@($targetState.Properties)) `
                    -Confirm:$false
            }
            $policy = if ($DesiredState -eq 'Require') { 3 } else { 2 }
            Set-QuickActionRegistryValue `
                -Path ([string]$PreState.targets.policyValue.path) `
                -Name ([string]$PreState.targets.policyValue.name) `
                -Type DWord `
                -Value $policy `
                -Confirm:$false
        }
        'BitLockerUSB' {
            $value = if ($DesiredState -eq 'Enforce') { 1 } else { 0 }
            Set-QuickActionRegistryValue `
                -Path ([string]$PreState.targets.policyValue.path) `
                -Name ([string]$PreState.targets.policyValue.name) `
                -Type DWord `
                -Value $value `
                -Confirm:$false
        }
        'SmartScreen' {
            # Only the level moves; EnableSmartScreen=1 stays untouched in
            # both states and is protected by the fingerprint over targets.
            $level = if ($DesiredState -eq 'Block') { 'Block' } else { 'Warn' }
            Set-QuickActionRegistryValue `
                -Path ([string]$PreState.targets.policyValue.path) `
                -Name ([string]$PreState.targets.policyValue.name) `
                -Type String `
                -Value $level `
                -Confirm:$false
        }
        'EdgeExtensions' {
            if ($DesiredState -eq 'Block') {
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.wildcardValue.path) `
                    -Name ([string]$PreState.targets.wildcardValue.name) `
                    -Type String `
                    -Value '*' `
                    -Confirm:$false
            }
            else {
                Restore-QuickActionRegistryValue `
                    -State ([PSCustomObject][ordered]@{
                        kind = 'RegistryValue'
                        path = [string]$PreState.targets.wildcardValue.path
                        name = [string]$PreState.targets.wildcardValue.name
                        keyExisted = $true
                        valueExisted = $false
                        originalName = $null
                        type = $null
                        value = $null
                        absentAncestorKeys = @()
                    }) `
                    -Confirm:$false
            }
        }
        'RDP' {
            if ($DesiredState -eq 'Enable') {
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.networkLevelAuthentication.path) `
                    -Name ([string]$PreState.targets.networkLevelAuthentication.name) `
                    -Type DWord -Value 1 -Confirm:$false
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.securityLayer.path) `
                    -Name ([string]$PreState.targets.securityLayer.name) `
                    -Type DWord -Value 2 -Confirm:$false
                Set-QuickActionFirewallGroupEnabled `
                    -State $PreState.targets.firewallGroup `
                    -Enabled:$true `
                    -Confirm:$false
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.denyConnections.path) `
                    -Name ([string]$PreState.targets.denyConnections.name) `
                    -Type DWord -Value 0 -Confirm:$false
                foreach ($name in @('TermService', 'SessionEnv', 'UmRdpService')) {
                    Set-QuickActionServiceRuntime -Name $name -Running:$true -Confirm:$false
                }
            }
            else {
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.denyConnections.path) `
                    -Name ([string]$PreState.targets.denyConnections.name) `
                    -Type DWord -Value 1 -Confirm:$false
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.networkLevelAuthentication.path) `
                    -Name ([string]$PreState.targets.networkLevelAuthentication.name) `
                    -Type DWord -Value 1 -Confirm:$false
                Set-QuickActionRegistryValue `
                    -Path ([string]$PreState.targets.securityLayer.path) `
                    -Name ([string]$PreState.targets.securityLayer.name) `
                    -Type DWord -Value 2 -Confirm:$false
                Set-QuickActionFirewallGroupEnabled `
                    -State $PreState.targets.firewallGroup `
                    -Enabled:$false `
                    -Confirm:$false
                foreach ($name in @('SessionEnv', 'UmRdpService', 'TermService')) {
                    Set-QuickActionServiceRuntime -Name $name -Running:$false -Confirm:$false
                }
            }
        }
        'UPnP' {
            if ($DesiredState -eq 'Block') {
                foreach ($name in @('upnphost', 'SSDPSRV')) {
                    $service = @($PreState.targets.services | Where-Object { [string]$_.name -ceq $name })[0]
                    if ([bool]$service.exists) {
                        Set-QuickActionServiceMode -Name $name -StartType Disabled -Stop -Confirm:$false
                    }
                }
                Set-QuickActionNamedFirewallRules -SetName UPnP -Present:$true -Confirm:$false
            }
            else {
                Set-QuickActionNamedFirewallRules -SetName UPnP -Present:$false -Confirm:$false
                foreach ($name in @('SSDPSRV', 'upnphost')) {
                    $service = @($PreState.targets.services | Where-Object { [string]$_.name -ceq $name })[0]
                    if ([bool]$service.exists) {
                        Set-QuickActionServiceMode -Name $name -StartType Manual -Confirm:$false
                    }
                }
            }
        }
        'WirelessDisplay' {
            if ($DesiredState -eq 'Disable') {
                $desiredValues = [ordered]@{
                    AllowProjectionToPC = 0
                    RequirePinForPairing = 2
                    AllowProjectionFromPC = 0
                    AllowMdnsAdvertisement = 0
                    AllowMdnsDiscovery = 0
                    AllowProjectionFromPCOverInfrastructure = 0
                    AllowProjectionToPCOverInfrastructure = 0
                }
                foreach ($policy in @($PreState.targets.policyValues)) {
                    Set-QuickActionRegistryValue `
                        -Path ([string]$policy.path) `
                        -Name ([string]$policy.name) `
                        -Type DWord `
                        -Value ([int]$desiredValues[[string]$policy.name]) `
                        -Confirm:$false
                }
                if ([bool]$PreState.targets.service.exists) {
                    Set-QuickActionServiceMode `
                        -Name ([string]$PreState.targets.service.name) `
                        -StartType Disabled -Stop -Confirm:$false
                }
                Set-QuickActionWiFiDirectAdapters `
                    -State $PreState.targets.adapters `
                    -Enabled:$false `
                    -Confirm:$false
                Set-QuickActionNamedFirewallRules `
                    -SetName WirelessDisplay `
                    -Present:$true `
                    -Confirm:$false
            }
            else {
                foreach ($policy in @($PreState.targets.policyValues)) {
                    Restore-QuickActionRegistryValue `
                        -State ([PSCustomObject][ordered]@{
                            kind = 'RegistryValue'
                            path = [string]$policy.path
                            name = [string]$policy.name
                            keyExisted = $true
                            valueExisted = $false
                            originalName = $null
                            type = $null
                            value = $null
                            absentAncestorKeys = @()
                        }) `
                        -Confirm:$false
                }
                Set-QuickActionNamedFirewallRules `
                    -SetName WirelessDisplay `
                    -Present:$false `
                    -Confirm:$false
                if ([bool]$PreState.targets.service.exists) {
                    Set-QuickActionServiceMode `
                        -Name ([string]$PreState.targets.service.name) `
                        -StartType Manual `
                        -Confirm:$false
                }
                Set-QuickActionWiFiDirectAdapters `
                    -State $PreState.targets.adapters `
                    -Enabled:$true `
                    -Confirm:$false
            }
        }
        default {
            throw "No Quick Action Apply implementation exists for $actionId"
        }
    }
}

function Restore-QuickActionScopeState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    switch ([string]$State.actionId) {
        { $_ -in @('ManagementTools', 'NewSoftware') } {
            Restore-QuickActionRegistryValue -State $State.targets.policyValue -Confirm:$false
        }
        'EncryptedDNS' {
            $resolverProperties = [string[]]@(
                $State.targets.resolverEvidence.PSObject.Properties.Name
            )
            if ('interfaceDohStates' -in $resolverProperties) {
                foreach ($registration in @($State.targets.resolverEvidence.registrations)) {
                    Set-DnsClientDohServerAddress `
                        -ServerAddress ([string]$registration.serverAddress) `
                        -DohTemplate ([string]$registration.dohTemplate) `
                        -AllowFallbackToUdp ([bool]$registration.allowFallbackToUdp) `
                        -AutoUpgrade ([bool]$registration.autoUpgrade) `
                        -ErrorAction Stop | Out-Null
                }
                foreach ($interfaceState in @($State.targets.resolverEvidence.interfaceDohStates)) {
                    $null = Set-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$interfaceState.interfaceGuid) `
                        -AddressFamily ([int]$interfaceState.addressFamily) `
                        -NameServers ([string[]]@($interfaceState.nativeState.NameServers)) `
                        -Properties ([object[]]@($interfaceState.nativeState.Properties)) `
                        -Confirm:$false
                }
            }
            Restore-QuickActionRegistryValue -State $State.targets.policyValue -Confirm:$false
        }
        'BitLockerUSB' {
            Restore-QuickActionRegistryValue -State $State.targets.policyValue -Confirm:$false
        }
        'SmartScreen' {
            # Restore the complete sealed scope: the level the action changed
            # and the EnableSmartScreen evidence value, so the post-restore
            # fingerprint can reproduce the sealed prestate exactly.
            Restore-QuickActionRegistryValue -State $State.targets.policyValue -Confirm:$false
            Restore-QuickActionRegistryValue -State $State.targets.enableValue -Confirm:$false
        }
        'EdgeExtensions' {
            Restore-QuickActionRegistryValue -State $State.targets.wildcardValue -Confirm:$false
        }
        'RDP' {
            # Deny first while restoring the remaining secure connection scope.
            Set-QuickActionRegistryValue `
                -Path ([string]$State.targets.denyConnections.path) `
                -Name ([string]$State.targets.denyConnections.name) `
                -Type DWord -Value 1 -Confirm:$false
            Restore-QuickActionRegistryValue -State $State.targets.networkLevelAuthentication -Confirm:$false
            Restore-QuickActionRegistryValue -State $State.targets.securityLayer -Confirm:$false
            Restore-QuickActionFirewallGroupState -State $State.targets.firewallGroup -Confirm:$false
            Restore-QuickActionRegistryValue -State $State.targets.denyConnections -Confirm:$false
            if ('rdpServices' -in [string[]]@($State.targets.PSObject.Properties.Name)) {
                foreach ($service in @($State.targets.rdpServices)) {
                    Restore-QuickActionServiceState -State $service -Confirm:$false
                }
            }
        }
        'UPnP' {
            Restore-QuickActionNamedFirewallState -State $State.targets.firewallRules -Confirm:$false
            foreach ($service in @($State.targets.services | Sort-Object {
                        if ([string]$_.name -eq 'SSDPSRV') { 0 } else { 1 }
                    })) {
                Restore-QuickActionServiceState -State $service -Confirm:$false
            }
        }
        'WirelessDisplay' {
            foreach ($policy in @($State.targets.policyValues)) {
                Restore-QuickActionRegistryValue -State $policy -Confirm:$false
            }
            Restore-QuickActionNamedFirewallState -State $State.targets.firewallRules -Confirm:$false
            Restore-QuickActionServiceState -State $State.targets.service -Confirm:$false
            Restore-QuickActionWiFiDirectAdapterState -State $State.targets.adapters -Confirm:$false
        }
        default {
            throw "No Quick Action Restore implementation exists for $($State.actionId)"
        }
    }
}

function Assert-QuickActionStateArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    $required = @(
        'schemaVersion', 'actionId', 'owningModule', 'state', 'actionable',
        'reason', 'targetIds', 'targets', 'fingerprint'
    )
    $actual = @($State.PSObject.Properties.Name)
    if ($actual.Count -ne $required.Count -or
        @(Compare-Object -ReferenceObject $required -DifferenceObject $actual).Count -ne 0) {
        throw 'Quick Action state artifact has an unexpected field set'
    }
    $definition = Get-QuickActionDefinition -ActionId ([string]$State.actionId)
    if ([int]$State.schemaVersion -ne $script:QuickActionStateSchemaVersion -or
        [string]$State.owningModule -cne [string]$definition.OwningModule -or
        [string]$State.state -notin @($definition.States) -or
        $State.actionable -isnot [bool] -or
        -not [bool]$State.actionable -or
        -not [string]::IsNullOrEmpty([string]$State.reason) -or
        [string]$State.fingerprint -notmatch '^[0-9a-f]{64}$') {
        throw 'Quick Action state artifact identity or actionable state is invalid'
    }
    $targetIds = [string[]]@($State.targetIds)
    $orderedTargetIds = [string[]]@($targetIds)
    [Array]::Sort($orderedTargetIds, [StringComparer]::Ordinal)
    $seenTargetIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $invalidTargetId = $false
    foreach ($targetId in $targetIds) {
        if ([string]::IsNullOrWhiteSpace($targetId) -or -not $seenTargetIds.Add($targetId)) {
            $invalidTargetId = $true
        }
    }
    if ($targetIds.Count -eq 0 -or
        $invalidTargetId -or
        ($targetIds -join "`0") -cne ($orderedTargetIds -join "`0")) {
        throw 'Quick Action state artifact target IDs are empty, duplicated, or unsorted'
    }
    $payload = [ordered]@{
        actionId = [string]$State.actionId
        owningModule = [string]$State.owningModule
        state = [string]$State.state
        actionable = [bool]$State.actionable
        reason = [string]$State.reason
        targetIds = $targetIds
        targets = $State.targets
    }
    $expectedFingerprint = Get-QuickActionObjectSha256 -InputObject $payload
    if ($expectedFingerprint -cne [string]$State.fingerprint) {
        throw 'Quick Action state artifact fingerprint is invalid'
    }
    return $true
}

function New-QuickActionPreparedSession {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        $PreState,

        [Parameter(Mandatory = $true)]
        [string]$DesiredState,

        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = (Join-Path $script:FrameworkRoot 'Backups')
    )

    if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force -ErrorAction Stop | Out-Null
    }
    $backupRoot = Get-Item -LiteralPath $BackupDirectory -Force -ErrorAction Stop
    if ([bool]($backupRoot.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Quick Action backup root is a reparse point: $BackupDirectory"
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $sessionId = "Session_${timestamp}_${nonce}_QuickAction_$([string]$PreState.actionId)"
    $sessionPath = Join-Path $BackupDirectory $sessionId
    if ($PSCmdlet.ShouldProcess($sessionPath, 'Create prepared Quick Action BAVR session')) {
        New-Item -ItemType Directory -Path $sessionPath -ErrorAction Stop | Out-Null
    }

    $prePath = Join-Path $sessionPath 'prestate.json'
    $preJson = ConvertTo-QuickActionCanonicalJson -InputObject $PreState
    $null = Write-AtomicUtf8File -Path $prePath -Content $preJson
    $preHash = (Get-FileHash -LiteralPath $prePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schemaVersion = $script:QuickActionSchemaVersion
        recordType = 'QuickActionSession'
        sessionId = $sessionId
        displayName = "Quick Action: $([string]$PreState.actionId) -> $DesiredState"
        sessionType = 'quickAction'
        timestamp = Get-Date -Format 'o'
        frameworkVersion = Get-FrameworkVersion
        actionId = [string]$PreState.actionId
        owningModule = [string]$PreState.owningModule
        desiredState = $DesiredState
        expectedPreFingerprint = [string]$PreState.fingerprint
        preFingerprint = [string]$PreState.fingerprint
        postFingerprint = ''
        targetIds = @($PreState.targetIds)
        status = 'Prepared'
        restorable = $false
        artifacts = @(
            [ordered]@{
                role = 'prestate'
                relativePath = 'prestate.json'
                sha256 = $preHash
            }
        )
    }
    $manifestPath = Join-Path $sessionPath 'manifest.json'
    $null = Write-AtomicUtf8File `
        -Path $manifestPath `
        -Content (ConvertTo-QuickActionCanonicalJson -InputObject $manifest)
    return [PSCustomObject]@{
        SessionPath = $sessionPath
        ManifestPath = $manifestPath
        PrePath = $prePath
        Manifest = $manifest
    }
}

function Complete-QuickActionSession {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        $PreparedSession,

        [Parameter(Mandatory = $true)]
        $PostState
    )

    if (-not $PSCmdlet.ShouldProcess(
            [string]$PreparedSession.SessionPath,
            'Seal Quick Action poststate and completed manifest'
        )) {
        return $null
    }

    $postPath = Join-Path ([string]$PreparedSession.SessionPath) 'poststate.json'
    $null = Write-AtomicUtf8File `
        -Path $postPath `
        -Content (ConvertTo-QuickActionCanonicalJson -InputObject $PostState)
    $postHash = (Get-FileHash -LiteralPath $postPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $manifest = $PreparedSession.Manifest
    $manifest.postFingerprint = [string]$PostState.fingerprint
    $manifest.status = 'Applied'
    $manifest.restorable = $true
    $manifest.artifacts = @(
        @($manifest.artifacts)[0],
        [ordered]@{
            role = 'poststate'
            relativePath = 'poststate.json'
            sha256 = $postHash
        }
    )
    $null = Write-AtomicUtf8File `
        -Path ([string]$PreparedSession.ManifestPath) `
        -Content (ConvertTo-QuickActionCanonicalJson -InputObject $manifest)
    return $manifest
}

function Set-QuickActionFailedSessionStatus {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        $PreparedSession,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ApplyFailedRolledBack', 'ApplyFailedRollbackFailed')]
        [string]$Status
    )

    if (-not $PSCmdlet.ShouldProcess(
            [string]$PreparedSession.SessionPath,
            "Seal failed Quick Action session status '$Status'"
        )) {
        return
    }

    $manifest = $PreparedSession.Manifest
    $manifest.status = $Status
    $manifest.restorable = $false
    $manifest.postFingerprint = ''
    $null = Write-AtomicUtf8File `
        -Path ([string]$PreparedSession.ManifestPath) `
        -Content (ConvertTo-QuickActionCanonicalJson -InputObject $manifest)
}

function Get-QuickActionSessionDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $false)]
        $Manifest
    )

    $sessionRoot = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')
    if (-not $Manifest) {
        $manifestPath = Join-Path $sessionRoot 'manifest.json'
        $Manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    $required = @(
        'schemaVersion', 'recordType', 'sessionId', 'displayName', 'sessionType',
        'timestamp', 'frameworkVersion', 'actionId', 'owningModule',
        'desiredState', 'expectedPreFingerprint', 'preFingerprint',
        'postFingerprint', 'targetIds', 'status', 'restorable', 'artifacts'
    )
    $actual = @($Manifest.PSObject.Properties.Name)
    if ($actual.Count -ne $required.Count -or
        @(Compare-Object -ReferenceObject $required -DifferenceObject $actual).Count -ne 0) {
        throw 'Quick Action manifest has an unexpected field set'
    }
    $definition = Get-QuickActionDefinition -ActionId ([string]$Manifest.actionId)
    $sessionLeaf = Split-Path $sessionRoot -Leaf
    if ([int]$Manifest.schemaVersion -ne $script:QuickActionSchemaVersion -or
        [string]$Manifest.recordType -cne 'QuickActionSession' -or
        [string]$Manifest.sessionId -cne $sessionLeaf -or
        [string]$Manifest.sessionType -cne 'quickAction' -or
        [string]$Manifest.owningModule -cne [string]$definition.OwningModule -or
        [string]$Manifest.desiredState -notin @($definition.States) -or
        [string]$Manifest.displayName -cne "Quick Action: $([string]$Manifest.actionId) -> $([string]$Manifest.desiredState)" -or
        [string]$Manifest.status -cne 'Applied' -or
        $Manifest.restorable -isnot [bool] -or -not [bool]$Manifest.restorable) {
        throw 'Quick Action manifest identity/status is invalid or non-restorable'
    }
    foreach ($fingerprintProperty in @(
            'expectedPreFingerprint', 'preFingerprint', 'postFingerprint'
        )) {
        if ([string]$Manifest.$fingerprintProperty -notmatch '^[0-9a-f]{64}$') {
            throw "Quick Action manifest has invalid $fingerprintProperty"
        }
    }
    if ([string]$Manifest.expectedPreFingerprint -cne [string]$Manifest.preFingerprint) {
        throw 'Quick Action manifest pre-fingerprint binding is inconsistent'
    }
    $null = ConvertFrom-NoIDRoundtripTimestamp `
        -Value $Manifest.timestamp `
        -Context 'Quick Action manifest'

    $artifacts = @($Manifest.artifacts)
    $artifactRoles = (@($artifacts.role | Sort-Object) -join "`0")
    if ($artifacts.Count -ne 2 -or
        $artifactRoles -cne (@('poststate', 'prestate') -join "`0")) {
        throw 'Quick Action manifest must contain exactly one prestate and one poststate artifact'
    }
    $allowedFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $allowedFiles.Add([System.IO.Path]::GetFullPath((Join-Path $sessionRoot 'manifest.json')))
    $states = @{}
    foreach ($artifact in $artifacts) {
        $fields = @($artifact.PSObject.Properties.Name)
        if ($fields.Count -ne 3 -or
            @(Compare-Object -ReferenceObject @('role', 'relativePath', 'sha256') -DifferenceObject $fields).Count -ne 0 -or
            [string]$artifact.role -notin @('prestate', 'poststate') -or
            [string]$artifact.relativePath -cne "$([string]$artifact.role).json" -or
            [string]$artifact.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Quick Action manifest contains an invalid artifact record'
        }
        $path = Resolve-SessionChildPath -SessionPath $sessionRoot -RelativePath ([string]$artifact.relativePath)
        $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or
            [bool]($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Quick Action artifact is not a real file: $path"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($hash -cne [string]$artifact.sha256) {
            throw "Quick Action artifact integrity check failed: $path"
        }
        $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-QuickActionStateArtifact -State $state
        $states[[string]$artifact.role] = $state
        $null = $allowedFiles.Add([System.IO.Path]::GetFullPath($path))
    }
    $pre = $states.prestate
    $post = $states.poststate
    if ([string]$pre.actionId -cne [string]$Manifest.actionId -or
        [string]$post.actionId -cne [string]$Manifest.actionId -or
        [string]$pre.owningModule -cne [string]$Manifest.owningModule -or
        [string]$post.owningModule -cne [string]$Manifest.owningModule -or
        [string]$pre.fingerprint -cne [string]$Manifest.preFingerprint -or
        [string]$post.fingerprint -cne [string]$Manifest.postFingerprint -or
        [string]$post.state -cne [string]$Manifest.desiredState -or
        (@($pre.targetIds) -join "`0") -cne (@($Manifest.targetIds) -join "`0") -or
        (@($post.targetIds) -join "`0") -cne (@($Manifest.targetIds) -join "`0")) {
        throw 'Quick Action manifest does not bind its exact state artifacts'
    }

    $receiptPath = Join-Path $sessionRoot 'restore-receipt.json'
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        $receipt = Get-SessionRestoreReceipt -SessionPath $sessionRoot -Manifest $Manifest
        $expectedScope = "action:$([string]$Manifest.actionId)"
        if (@($receipt.restoredScopes).Count -ne 1 -or
            [string]$receipt.restoredScopes[0] -cne $expectedScope) {
            throw 'Quick Action restore receipt does not contain its one exact action scope'
        }
        $null = $allowedFiles.Add([System.IO.Path]::GetFullPath($receiptPath))
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $sessionRoot -Force -ErrorAction Stop)) {
        if ($entry.PSIsContainer -or
            [bool]($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            -not $allowedFiles.Contains([System.IO.Path]::GetFullPath($entry.FullName))) {
            throw "Quick Action session contains an undeclared entry: $($entry.FullName)"
        }
    }

    return [PSCustomObject]@{
        Manifest = $Manifest
        PreState = $pre
        PostState = $post
        SessionPath = $sessionRoot
    }
}

function Get-SessionRestoreReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        $Manifest
    )

    $receiptPath = Join-Path $SessionPath 'restore-receipt.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { return $null }
    $receiptFile = Get-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
    if ([bool]($receiptFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        $receiptFile.Length -lt 2 -or $receiptFile.Length -gt 65536) {
        throw 'Restore receipt is not a valid regular bounded file'
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $required = @(
        'schemaVersion', 'recordType', 'sessionId', 'manifestSha256',
        'completedAt', 'restoredScopes'
    )
    $actual = @($receipt.PSObject.Properties.Name)
    $manifestPath = Join-Path $SessionPath 'manifest.json'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $scopes = @($receipt.restoredScopes)
    $canonicalScopeSet = [System.Collections.Generic.SortedSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($scope in $scopes) {
        $null = $canonicalScopeSet.Add([string]$scope)
    }
    $canonicalScopes = @($canonicalScopeSet)
    if ($actual.Count -ne $required.Count -or
        @(Compare-Object -ReferenceObject $required -DifferenceObject $actual).Count -ne 0 -or
        [int]$receipt.schemaVersion -ne $script:QuickActionReceiptSchemaVersion -or
        [string]$receipt.recordType -cne 'NoIDRestoreReceipt' -or
        [string]$receipt.sessionId -cne [string]$Manifest.sessionId -or
        [string]$receipt.manifestSha256 -cne $manifestHash -or
        $scopes.Count -eq 0 -or
        @($scopes | Where-Object { [string]$_ -notmatch '^(?:module|action):[A-Za-z0-9]+$' }).Count -gt 0 -or
        $canonicalScopes.Count -ne $scopes.Count -or
        ($scopes -join "`0") -cne ($canonicalScopes -join "`0")) {
        throw 'Restore receipt identity, manifest binding, or scope set is invalid'
    }
    $null = ConvertFrom-NoIDRoundtripTimestamp `
        -Value $receipt.completedAt `
        -Context 'Restore receipt'
    return $receipt
}

function Write-SessionRestoreReceipt {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )

    $existing = Get-SessionRestoreReceipt -SessionPath $SessionPath -Manifest $Manifest
    $combinedScopes = @($Scopes)
    if ($existing) {
        $combinedScopes += @($existing.restoredScopes)
    }
    $scopeSet = [System.Collections.Generic.SortedSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($scope in $combinedScopes) {
        $null = $scopeSet.Add([string]$scope)
    }
    $allScopes = @($scopeSet)
    if ($allScopes.Count -eq 0 -or
        @($allScopes | Where-Object { [string]$_ -notmatch '^(?:module|action):[A-Za-z0-9]+$' }).Count -gt 0) {
        throw 'Refusing to write an empty or malformed restore receipt scope set'
    }
    $manifestPath = Join-Path $SessionPath 'manifest.json'
    $receipt = [ordered]@{
        schemaVersion = $script:QuickActionReceiptSchemaVersion
        recordType = 'NoIDRestoreReceipt'
        sessionId = [string]$Manifest.sessionId
        manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        completedAt = Get-Date -Format 'o'
        restoredScopes = $allScopes
    }
    $receiptPath = Join-Path $SessionPath 'restore-receipt.json'
    if ($PSCmdlet.ShouldProcess($receiptPath, 'Write manifest-bound restore receipt')) {
        $null = Write-AtomicUtf8File `
            -Path $receiptPath `
            -Content (ConvertTo-QuickActionCanonicalJson -InputObject $receipt)
    }
    $validated = Get-SessionRestoreReceipt -SessionPath $SessionPath -Manifest $Manifest
    if (-not $validated) { throw 'Restore receipt did not validate after write' }
    return $validated
}

function Test-QuickActionManifestIsNewer {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Candidate,

        [Parameter(Mandatory = $true)]
        $Selected
    )

    $candidateTime = [DateTime]::Parse(
        [string]$Candidate.timestamp,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    $selectedTime = [DateTime]::Parse(
        [string]$Selected.timestamp,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    if ($candidateTime -gt $selectedTime) { return $true }
    if ($candidateTime -lt $selectedTime) { return $false }
    return [string]::CompareOrdinal([string]$Candidate.sessionId, [string]$Selected.sessionId) -gt 0
}

function Assert-NoNewerOverlapForQuickActionRestore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SelectedDocument
    )

    $selectedManifest = $SelectedDocument.Manifest
    $backupRoot = Split-Path ([string]$SelectedDocument.SessionPath) -Parent
    $selectedTargets = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($selectedManifest.targetIds),
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($folder in @(Get-ChildItem -LiteralPath $backupRoot -Directory -Force -ErrorAction Stop)) {
        if ($folder.FullName -eq [string]$SelectedDocument.SessionPath) { continue }
        $manifestPath = Join-Path $folder.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { continue }
        try {
            $candidate = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if (-not (Test-QuickActionManifestIsNewer -Candidate $candidate -Selected $selectedManifest)) {
                continue
            }
            if ([int]$candidate.schemaVersion -eq 3 -and
                [string]$candidate.recordType -eq 'QuickActionSession' -and
                [bool]$candidate.restorable) {
                $candidateTargets = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]@($candidate.targetIds),
                    [StringComparer]::OrdinalIgnoreCase
                )
                $candidateTargets.IntersectWith($selectedTargets)
                if ($candidateTargets.Count -gt 0) {
                    try {
                        $receipt = Get-SessionRestoreReceipt `
                            -SessionPath $folder.FullName `
                            -Manifest $candidate
                    }
                    catch {
                        throw "A newer overlapping Quick Action has invalid restore evidence and must be resolved first: $($candidate.sessionId). $($_.Exception.Message)"
                    }
                    if (-not $receipt -or
                        "action:$([string]$candidate.actionId)" -notin @($receipt.restoredScopes)) {
                        throw "A newer overlapping Quick Action must be restored first: $($candidate.sessionId)"
                    }
                }
            }
            elseif ([int]$candidate.schemaVersion -eq 2 -and
                [bool]$candidate.restorable) {
                # Overlap follows the sealed TARGET scope, not the display label.
                # Both ASR Quick Actions also write values the SecurityBaseline
                # inventory declares, so a newer SecurityBaseline-only session can
                # overwrite an ASR Quick Action while its owningModule label says
                # 'ASR' and matches nothing in that session's module list. The
                # guard then saw no overlap, the post-fingerprint gate passed
                # because the baseline had rewritten the identical value, and the
                # Quick Action restore silently reverted the newer baseline.
                # Get-QuickActionModuleRestoreScopes is the same set the mirror
                # guard (Assert-NoNewerQuickActionOverlapForModuleRestore) uses.
                $selectedScopes = @(Get-QuickActionModuleRestoreScopes `
                        -ActionId ([string]$selectedManifest.actionId))
                $overlappingScopes = @($selectedScopes | Where-Object {
                        $_ -in @($candidate.modules.name)
                    })
                if ($overlappingScopes.Count -gt 0) {
                    try {
                        $receipt = Get-SessionRestoreReceipt `
                            -SessionPath $folder.FullName `
                            -Manifest $candidate
                    }
                    catch {
                        throw "A newer overlapping module session has invalid restore evidence and must be resolved first: $($candidate.sessionId). $($_.Exception.Message)"
                    }
                    # Every overlapping scope must be restored, not just the one
                    # that happens to carry the owning-module label.
                    foreach ($overlappingScope in $overlappingScopes) {
                        if (-not $receipt -or
                            "module:$overlappingScope" -notin @($receipt.restoredScopes)) {
                            throw "A newer overlapping module session must be restored first: $($candidate.sessionId)"
                        }
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like 'A newer overlapping*') { throw }
            # A malformed unrelated directory cannot prove overlap. If its
            # current changes overlap, the selected post-fingerprint gate below
            # still refuses Restore.
        }
    }
}

function Assert-NoNewerQuickActionOverlapForModuleRestore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames
    )

    $backupRoot = Split-Path $SessionPath -Parent
    foreach ($folder in @(Get-ChildItem -LiteralPath $backupRoot -Directory -Force -ErrorAction Stop)) {
        if ($folder.FullName -eq $SessionPath) { continue }
        $manifestPath = Join-Path $folder.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { continue }
        try {
            $candidate = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([int]$candidate.schemaVersion -ne 3 -or
                [string]$candidate.recordType -ne 'QuickActionSession' -or
                -not [bool]$candidate.restorable -or
                -not (Test-QuickActionManifestIsNewer -Candidate $candidate -Selected $Manifest)) {
                continue
            }

            $candidateActionId = [string]$candidate.actionId
            $knownActionIds = @(
                'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
                'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
            )
            if ($candidateActionId -cnotin $knownActionIds) {
                throw "A newer overlapping Quick Action has an unknown action identity and must be resolved first: $($candidate.sessionId)"
            }
            $affectedModules = @(Get-QuickActionModuleRestoreScopes -ActionId $candidateActionId)
            if (@($affectedModules | Where-Object { $_ -in $ModuleNames }).Count -eq 0) {
                continue
            }

            try {
                $receipt = Get-SessionRestoreReceipt -SessionPath $folder.FullName -Manifest $candidate
            }
            catch {
                throw "A newer overlapping Quick Action has invalid restore evidence and must be resolved first: $($candidate.sessionId). $($_.Exception.Message)"
            }
            if (-not $receipt -or "action:$([string]$candidate.actionId)" -notin @($receipt.restoredScopes)) {
                throw "A newer overlapping Quick Action must be restored first: $($candidate.sessionId)"
            }
        }
        catch {
            if ($_.Exception.Message -like 'A newer overlapping Quick Action*') { throw }
            # An unrelated malformed directory cannot prove overlap. Manifests
            # that identify a relevant newer action are handled fail-closed in
            # the explicit branch above.
        }
    }
}

function Invoke-QuickAction {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
            'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
        )]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Block', 'Require', 'Enforce', 'Disable', 'Enable', 'Warn')]
        [string]$DesiredState,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedFingerprint
    )

    $definition = Get-QuickActionDefinition -ActionId $ActionId
    if ($DesiredState -notin @($definition.States)) {
        throw "State '$DesiredState' is invalid for Quick Action '$ActionId'"
    }
    $mutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
    $mutexHeld = $false
    $prepared = $null
    $preState = $null
    $mutationStarted = $false
    try {
        try {
            $mutexHeld = $mutex.WaitOne(0, $false)
        }
        catch [Threading.AbandonedMutexException] {
            $mutexHeld = $true
        }
        if (-not $mutexHeld) {
            throw 'Another Quick Action or Quick Action restore is already running.'
        }

        $preState = Get-QuickActionState -ActionId $ActionId
        if (-not [bool]$preState.actionable) {
            throw "Quick Action is not actionable: $($preState.reason)"
        }
        if ([string]$preState.fingerprint -cne $ExpectedFingerprint) {
            throw 'Quick Action state changed after it was displayed. Refresh and review the current Windows state.'
        }
        if ([string]$preState.state -ceq $DesiredState) {
            $intentArguments = @{
                ActionId = $ActionId
                DesiredState = $DesiredState
                SourceKind = 'QuickActionLiveConfirmation'
                SourceEvidenceSha256 = [string]$preState.fingerprint
            }
            if ($ActionId -eq 'EncryptedDNS') {
                $intentArguments.DnsProvider = [string]$preState.targets.resolverEvidence.providerId
            }
            # Nothing was mutated on this path, so failing here is correct - but
            # the function reports failure by throwing, never by returning
            # $false, which made this deliberate message unreachable and let the
            # raw internal exception surface to the user instead.
            try {
                $null = Update-NoIDQuickActionIntentState @intentArguments
            }
            catch {
                throw "Quick Action live state matched, but durable intent could not be updated: $($_.Exception.Message)"
            }
            return [PSCustomObject][ordered]@{
                schemaVersion = 1
                success = $true
                status = 'NoChange'
                actionId = $ActionId
                desiredState = $DesiredState
                preFingerprint = [string]$preState.fingerprint
                postFingerprint = [string]$preState.fingerprint
                backupPath = ''
                mutated = $false
                verified = $true
                error = ''
            }
        }
        if (-not $PSCmdlet.ShouldProcess(
                $env:COMPUTERNAME,
                "Apply Quick Action $ActionId -> $DesiredState with sealed BAVR"
            )) {
            throw 'Quick Action was not confirmed.'
        }

        $prepared = New-QuickActionPreparedSession `
            -PreState $preState `
            -DesiredState $DesiredState `
            -Confirm:$false
        $mutationStarted = $true
        Invoke-QuickActionScopeApply `
            -PreState $preState `
            -DesiredState $DesiredState `
            -Confirm:$false

        $postState = Wait-QuickActionState `
            -ActionId $ActionId `
            -Predicate {
                param($candidate)
                [bool]$candidate.actionable -and
                [string]$candidate.state -ceq $DesiredState -and
                (@($candidate.targetIds) -join "`0") -ceq (@($preState.targetIds) -join "`0") -and
                ($ActionId -notin @('ManagementTools', 'NewSoftware') -or
                    [string]$candidate.targets.unrelatedEffectiveRules.fingerprint -ceq
                        [string]$preState.targets.unrelatedEffectiveRules.fingerprint)
            }
        if (-not [bool]$postState.actionable -or
            [string]$postState.state -cne $DesiredState -or
            (@($postState.targetIds) -join "`0") -cne (@($preState.targetIds) -join "`0")) {
            throw 'Quick Action post-Apply verification did not reach the requested closed state.'
        }
        if ($ActionId -in @('ManagementTools', 'NewSoftware') -and
            [string]$postState.targets.unrelatedEffectiveRules.fingerprint -cne
                [string]$preState.targets.unrelatedEffectiveRules.fingerprint) {
            throw 'Quick Action changed unrelated effective ASR rules.'
        }

        $null = Complete-QuickActionSession -PreparedSession $prepared -PostState $postState -Confirm:$false
        $null = Get-QuickActionSessionDocument -SessionPath ([string]$prepared.SessionPath)
        # The sealed session and exact live readback are the mutation's success
        # authority. Durable intent is a later comparison label; inability to
        # maintain it must stay visible, but must never undo an already verified
        # Windows change.
        try {
            if (-not (Update-NoIDQuickActionIntentState `
                    -ActionId $ActionId `
                    -DesiredState $DesiredState `
                    -SourceKind QuickActionApply `
                    -SourceSessionPath ([string]$prepared.SessionPath))) {
                throw 'intent update returned failure'
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Quick Action was applied and verified, but its optional durable-intent label could not be updated: $($_.Exception.Message)" -Module 'QuickActions'
        }
        return [PSCustomObject][ordered]@{
            schemaVersion = 1
            success = $true
            status = 'Applied'
            actionId = $ActionId
            desiredState = $DesiredState
            preFingerprint = [string]$preState.fingerprint
            postFingerprint = [string]$postState.fingerprint
            backupPath = [string]$prepared.SessionPath
            mutated = $true
            verified = $true
            error = ''
        }
    }
    catch {
        $applyError = $_.Exception.Message
        $rollbackSucceeded = $false
        $rollbackError = ''
        if ($mutationStarted -and $preState) {
            try {
                Restore-QuickActionScopeState -State $preState -Confirm:$false
                $restored = Wait-QuickActionState `
                    -ActionId $ActionId `
                    -Predicate {
                        param($candidate)
                        [string]$candidate.fingerprint -ceq [string]$preState.fingerprint
                    }
                if ([string]$restored.fingerprint -cne [string]$preState.fingerprint) {
                    throw 'Compensating restore fingerprint differs from the sealed prestate.'
                }
                $intentArguments = @{
                    ActionId = $ActionId
                    DesiredState = [string]$preState.state
                    SourceKind = 'QuickActionLiveConfirmation'
                    SourceEvidenceSha256 = [string]$preState.fingerprint
                }
                if ($ActionId -eq 'EncryptedDNS') {
                    $intentArguments.DnsProvider = [string]$preState.targets.resolverEvidence.providerId
                }
                # Update-NoIDQuickActionIntentState signals every failure by
                # throwing; it has no $false exit. Leaving the call bare let an
                # optional label failure reach the outer catch, so a compensating
                # restore that had already been verified against the exact
                # pre-state fingerprint was sealed as ApplyFailedRollbackFailed
                # and the user was told to recover a machine that was in fact
                # fully restored. The label is optional - the restore is not.
                try {
                    $null = Update-NoIDQuickActionIntentState @intentArguments
                }
                catch {
                    Write-Log -Level WARNING -Message "Compensating restore succeeded, but its optional durable-intent label could not be reconciled: $($_.Exception.Message)" -Module 'QuickActions'
                }
                $rollbackSucceeded = $true
            }
            catch {
                $rollbackError = $_.Exception.Message
            }
        }
        if ($prepared) {
            Set-QuickActionFailedSessionStatus `
                -PreparedSession $prepared `
                -Status $(if ($rollbackSucceeded) { 'ApplyFailedRolledBack' } else { 'ApplyFailedRollbackFailed' }) `
                -Confirm:$false
        }
        $combinedError = if ($rollbackError) {
            "$applyError Compensating restore failed: $rollbackError"
        }
        else {
            $applyError
        }
        # The sealed session status above already distinguishes a successful
        # compensating restore from a failed one. Reporting the failed case as a
        # plain 'Failed' while mutated=$true described a state the GUI contract
        # rejects as impossible, so the single most dangerous outcome - applied,
        # rollback failed, system left half-changed - was discarded instead of
        # shown. 'Failed' remains reserved for runs that never mutated (mutex
        # busy, not actionable, fingerprint drift, refused confirmation): the
        # contract rejects a rollback status without a sealed mutation session.
        return [PSCustomObject][ordered]@{
            schemaVersion = 1
            success = $false
            status = $(if ($rollbackSucceeded) { 'ApplyFailedRolledBack' } elseif ($mutationStarted) { 'ApplyFailedRollbackFailed' } else { 'Failed' })
            actionId = $ActionId
            desiredState = $DesiredState
            preFingerprint = if ($preState) { [string]$preState.fingerprint } else { '' }
            postFingerprint = ''
            backupPath = if ($prepared) { [string]$prepared.SessionPath } else { '' }
            mutated = [bool]$mutationStarted
            verified = $false
            error = $combinedError
        }
    }
    finally {
        if ($mutexHeld) {
            try { $mutex.ReleaseMutex() }
            catch { Write-Verbose "Mutation mutex release failed: $($_.Exception.Message)" }
        }
        $mutex.Dispose()
    }
}

function Restore-QuickActionSession {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $document = Get-QuickActionSessionDocument -SessionPath $SessionPath
    $mutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
    $mutexHeld = $false
    $receiptCleanupSafeForCompensation = $true
    try {
        try {
            $mutexHeld = $mutex.WaitOne(0, $false)
        }
        catch [Threading.AbandonedMutexException] {
            $mutexHeld = $true
        }
        if (-not $mutexHeld) {
            throw 'Another Quick Action or Quick Action restore is already running.'
        }
        $receipt = Get-SessionRestoreReceipt `
            -SessionPath ([string]$document.SessionPath) `
            -Manifest $document.Manifest
        if ($receipt -and
            "action:$([string]$document.Manifest.actionId)" -in @($receipt.restoredScopes)) {
            # Idempotent success: validated receipt evidence already binds this
            # exact session manifest to a completed action restore. Do not
            # rewrite current intent from historical evidence: a newer Apply may
            # have legitimately changed the live state and its comparison label.
            return $true
        }
        Assert-NoNewerOverlapForQuickActionRestore -SelectedDocument $document
        $current = Get-QuickActionState -ActionId ([string]$document.Manifest.actionId)
        $currentPostComparable = Get-QuickActionSessionComparableState `
            -LiveState $current `
            -SealedState $document.PostState
        $currentPreComparable = Get-QuickActionSessionComparableState `
            -LiveState $current `
            -SealedState $document.PreState

        # Recover the only crash window that cannot be made atomic with a live
        # Windows mutation: the system already equals the sealed prestate, but
        # the manifest-bound receipt was not durably written. Reconcile the
        # receipt instead of misclassifying the restored state as foreign drift.
        if ([string]$currentPreComparable.fingerprint -ceq [string]$document.PreState.fingerprint) {
            if (-not $PSCmdlet.ShouldProcess(
                    [string]$document.SessionPath,
                    "Record already completed Quick Action restore $([string]$document.Manifest.sessionId)"
                )) {
                return $false
            }
            $null = Write-SessionRestoreReceipt `
                -SessionPath ([string]$document.SessionPath) `
                -Manifest $document.Manifest `
                -Scopes @("action:$([string]$document.Manifest.actionId)") `
                -Confirm:$false
            try {
                if (-not (Update-NoIDQuickActionIntentState `
                        -ActionId ([string]$document.Manifest.actionId) `
                        -DesiredState ([string]$document.PreState.state) `
                        -SourceKind QuickActionRestore `
                        -SourceSessionPath ([string]$document.SessionPath))) {
                    throw 'intent update returned failure'
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Recovered Quick Action restore receipt; optional intent-label reconciliation failed: $($_.Exception.Message)" -Module 'QuickActions'
            }
            return $true
        }

        if ([string]$currentPostComparable.fingerprint -cne [string]$document.PostState.fingerprint) {
            throw 'Current Quick Action state differs from the sealed post-Apply fingerprint; refusing to overwrite drift or newer state.'
        }
        if (-not $PSCmdlet.ShouldProcess(
                $env:COMPUTERNAME,
                "Restore Quick Action session $([string]$document.Manifest.sessionId)"
            )) {
            return $false
        }
        try {
            Restore-QuickActionScopeState -State $document.PreState -Confirm:$false
            $restored = Wait-QuickActionState `
                -ActionId ([string]$document.Manifest.actionId) `
                -Predicate {
                    param($candidate)
                    $candidateComparable = Get-QuickActionSessionComparableState `
                        -LiveState $candidate `
                        -SealedState $document.PreState
                    [string]$candidateComparable.fingerprint -ceq [string]$document.PreState.fingerprint
                }
            $restoredComparable = Get-QuickActionSessionComparableState `
                -LiveState $restored `
                -SealedState $document.PreState
            if ([string]$restoredComparable.fingerprint -cne [string]$document.PreState.fingerprint) {
                throw 'Quick Action Restore equality differs from the sealed prestate.'
            }
            # The manifest-bound receipt is the restore transaction's critical
            # publication step. Optional intent is only a later comparison label.
            try {
                $null = Write-SessionRestoreReceipt `
                    -SessionPath ([string]$document.SessionPath) `
                    -Manifest $document.Manifest `
                    -Scopes @("action:$([string]$document.Manifest.actionId)") `
                    -Confirm:$false
            }
            catch {
                $publicationError = $_.Exception.Message
                $expectedScope = "action:$([string]$document.Manifest.actionId)"
                $publishedReceipt = $null
                try {
                    $publishedReceipt = Get-SessionRestoreReceipt `
                        -SessionPath ([string]$document.SessionPath) `
                        -Manifest $document.Manifest
                }
                catch {
                    $publishedReceipt = $null
                }

                # A transient post-write read failure can happen after the
                # atomic receipt was already published. A strict second read
                # that proves the exact scope completes the transaction and
                # must not be compensated back to the poststate.
                if ($publishedReceipt -and
                    $expectedScope -in @($publishedReceipt.restoredScopes)) {
                    Write-Log -Level WARNING -Message "Quick Action restore receipt validated after a transient publication error: $publicationError" -Module 'QuickActions'
                }
                else {
                    # If publication cannot be proven, remove our own candidate
                    # receipt before compensating the live state. Otherwise a
                    # receipt could claim Restore after compensation has put the
                    # system back at the sealed poststate.
                    $receiptPath = Join-Path ([string]$document.SessionPath) 'restore-receipt.json'
                    try {
                        if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
                            Remove-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
                        }
                        if (Test-Path -LiteralPath $receiptPath) {
                            throw 'restore-receipt.json still exists after cleanup'
                        }
                    }
                    catch {
                        $receiptCleanupSafeForCompensation = $false
                        throw "Restore receipt publication failed and its candidate file could not be removed safely: $publicationError; cleanup: $($_.Exception.Message)"
                    }
                    throw "Restore receipt publication failed: $publicationError"
                }
            }
        }
        catch {
            $restoreError = $_.Exception.Message
            if (-not $receiptCleanupSafeForCompensation) {
                throw "$restoreError Live state remains at the verified sealed prestate because compensating it with unresolved receipt evidence would create a false restore record."
            }
            try {
                Restore-QuickActionScopeState -State $document.PostState -Confirm:$false
                $recoveredPost = Wait-QuickActionState `
                    -ActionId ([string]$document.Manifest.actionId) `
                    -Predicate {
                        param($candidate)
                        $candidateComparable = Get-QuickActionSessionComparableState `
                            -LiveState $candidate `
                            -SealedState $document.PostState
                        [string]$candidateComparable.fingerprint -ceq [string]$document.PostState.fingerprint
                    }
                $recoveredPostComparable = Get-QuickActionSessionComparableState `
                    -LiveState $recoveredPost `
                    -SealedState $document.PostState
                if ([string]$recoveredPostComparable.fingerprint -cne [string]$document.PostState.fingerprint) {
                    throw 'Poststate compensation equality failed.'
                }
                try {
                    if (-not (Update-NoIDQuickActionIntentState `
                            -ActionId ([string]$document.Manifest.actionId) `
                            -DesiredState ([string]$document.PostState.state) `
                            -SourceKind QuickActionApply `
                            -SourceSessionPath ([string]$document.SessionPath))) {
                        throw 'intent update returned failure'
                    }
                }
                catch {
                    Write-Log -Level WARNING -Message "Quick Action poststate compensation succeeded; optional intent-label compensation failed: $($_.Exception.Message)" -Module 'QuickActions'
                }
            }
            catch {
                throw "$restoreError Restore compensation also failed: $($_.Exception.Message)"
            }
            throw $restoreError
        }
        try {
            if (-not (Update-NoIDQuickActionIntentState `
                    -ActionId ([string]$document.Manifest.actionId) `
                    -DesiredState ([string]$document.PreState.state) `
                    -SourceKind QuickActionRestore `
                    -SourceSessionPath ([string]$document.SessionPath))) {
                throw 'intent update returned failure'
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Quick Action restore is verified and receipted; optional intent-label update failed: $($_.Exception.Message)" -Module 'QuickActions'
        }
        return $true
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Quick Action restore failed: $($_.Exception.Message)" -Module 'QuickActions'
        }
        return $false
    }
    finally {
        if ($mutexHeld) {
            try { $mutex.ReleaseMutex() }
            catch { Write-Verbose "Mutation mutex release failed: $($_.Exception.Message)" }
        }
        $mutex.Dispose()
    }
}
