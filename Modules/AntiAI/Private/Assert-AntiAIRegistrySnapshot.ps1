#Requires -Version 5.1

function Assert-AntiAIRegistrySnapshot {
    <#
    .SYNOPSIS
        Validates the complete sealed AntiAI registry prestate contract.

    .DESCRIPTION
        This validator is deliberately free of registry mutations. It binds a
        schema-v4 snapshot to the exact AntiAI path/name inventory. Applicable
        entries carry exact prestates; documented non-applicable identities are
        sealed separately and are never mutated by Restore.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Snapshot,

        # Restore validates the self-describing sealed prestate without binding
        # it to the current release's target count. This preserves rollback of
        # older sessions after a later release adds or retires policies.
        [Parameter(Mandatory = $false)]
        [switch]$RestoreOnly
    )

    if ($null -eq $Snapshot) {
        throw 'AntiAI registry snapshot is null'
    }
    foreach ($property in @(
            'SchemaVersion', 'DeclaredTargetCount', 'ApplicableTargetCount',
            'NotApplicableTargetCount', 'Entries', 'NotApplicableTargets'
        )) {
        if (-not $Snapshot.PSObject.Properties[$property]) {
            throw "AntiAI registry snapshot is missing '$property'"
        }
    }

    $entries = @($Snapshot.Entries)
    $notApplicableTargets = @($Snapshot.NotApplicableTargets)
    if ([int]$Snapshot.SchemaVersion -ne 4 -or
        [int]$Snapshot.DeclaredTargetCount -lt 1 -or
        [int]$Snapshot.ApplicableTargetCount -ne $entries.Count -or
        [int]$Snapshot.NotApplicableTargetCount -ne $notApplicableTargets.Count -or
        $entries.Count + $notApplicableTargets.Count -ne [int]$Snapshot.DeclaredTargetCount -or
        [int]$Snapshot.DeclaredTargetCount -ne 43) {
        throw 'AntiAI registry snapshot has an invalid schema or exact target count'
    }

    # Frozen schema-4 restore allowlist, not a projection of today's policy
    # file. Future AntiAI inventory changes require a new schema while keeping
    # this list, so legacy v2.2.5 sessions remain restorable without accepting
    # arbitrary registry paths from an old JSON document.
    $allowedMachineTargets = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' = @(
            'LetAppsAccessGenerativeAI'
        )
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' = @(
            'AgentConnectorMinimumPolicy', 'AgentConsentDuration', 'AllowRecallEnablement',
            'AllowRecallExport', 'ConfigureAgentConnectors', 'DenyAppListForRecall',
            'DenyUriListForRecall', 'DisableAgentConnectors', 'DisableAgentWorkspaces',
            'DisableAIDataAnalysis', 'DisableClickToDo', 'DisableRemoteAgentConnectors',
            'DisableSettingsAgent', 'SetDenyAppListForRecall', 'SetDenyUriListForRecall',
            'SetMaximumStorageDurationForRecallSnapshots', 'SetMaximumStorageSpaceForRecallSnapshots'
        )
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge' = @(
            'AIGenThemesEnabled', 'AllowBrowsingWithCopilot', 'BuiltInAIAPIsEnabled',
            'ComposeInlineEnabled', 'CopilotAddressBarSuggestionsEnabled',
            'CopilotNewTabPageEnabled', 'CopilotPageContext', 'EdgeEntraCopilotPageContext',
            'EdgeHistoryAISearchEnabled', 'GenAILocalFoundationalModelSettings',
            'HubsSidebarEnabled', 'M365LinksAutoOpenCopilotEnabled',
            'Microsoft365CopilotChatIconEnabled', 'NewTabPageBingChatEnabled',
            'ShareBrowsingHistoryWithCopilotSearchAllowed',
            'StandaloneHubsSidebarEnabled', 'VisualSearchEnabled'
        )
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' = @(
            'DisableCocreator', 'DisableGenerativeFill', 'DisableImageCreator'
        )
        'HKLM:\SOFTWARE\Policies\WindowsNotepad' = @('DisableAIFeatures')
    }
    $allowedUserTargets = @{
        'SOFTWARE\Policies\Microsoft\Windows\WindowsAI' = @('DisableRecallDataProviders')
        'Software\Policies\Microsoft\Windows\WindowsCopilot' = @('TurnOffWindowsCopilot')
        'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' = @('ShowCopilotButton')
        'Software\Policies\Microsoft\Windows\CopilotKey' = @('SetCopilotHardwareKey')
    }

    $expectedIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $allowedMachineTargets.Keys) {
        foreach ($name in $allowedMachineTargets[$path]) {
            $null = $expectedIdentities.Add("$path`0$name")
        }
    }
    foreach ($suffix in $allowedUserTargets.Keys) {
        foreach ($name in $allowedUserTargets[$suffix]) {
            $null = $expectedIdentities.Add("HKU:\<SID>\$suffix`0$name")
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $userSid = $null
    $keyExistence = @{}
    foreach ($entry in $entries) {
        foreach ($property in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
            if (-not $entry.PSObject.Properties[$property]) {
                throw "AntiAI registry snapshot entry is missing '$property'"
            }
        }

        $path = [string]$entry.Path
        $name = [string]$entry.Name
        if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name)) {
            throw 'AntiAI registry snapshot contains an empty path or value name'
        }
        if ($entry.KeyExisted -isnot [bool] -or $entry.Exists -isnot [bool]) {
            throw "AntiAI registry snapshot existence flags must be Boolean: $path::$name"
        }

        $canonicalIdentity = $null
        if ($allowedMachineTargets.ContainsKey($path) -and $name -in $allowedMachineTargets[$path]) {
            $canonicalIdentity = "$path`0$name"
        }
        elseif ($path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$' -and
            $allowedUserTargets.ContainsKey($Matches[2]) -and
            $name -in $allowedUserTargets[$Matches[2]]) {
            if ($null -eq $userSid) {
                $userSid = [string]$Matches[1]
            }
            elseif (-not $userSid.Equals([string]$Matches[1], [StringComparison]::OrdinalIgnoreCase)) {
                throw 'AntiAI registry snapshot spans more than one interactive user SID'
            }
            $canonicalIdentity = "HKU:\<SID>\$($Matches[2])`0$name"
        }
        else {
            throw "AntiAI registry snapshot target is outside the exact allowlist: $path::$name"
        }
        if (-not $seen.Add($canonicalIdentity)) {
            throw "AntiAI registry snapshot contains a duplicate target: $path::$name"
        }

        if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
            throw "AntiAI snapshot claims a value in an originally absent key: $path::$name"
        }
        if (-not [bool]$entry.Exists) {
            if ($null -ne $entry.Type -or $null -ne $entry.Value) {
                throw "Absent AntiAI value must have null Type and Value: $path::$name"
            }
        }
        else {
            $type = [string]$entry.Type
            if ($type -notin @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')) {
                throw "Unsupported AntiAI registry value type '$type' for $path::$name"
            }
            switch ($type) {
                'DWord' {
                    if ($entry.Value -isnot [int] -and $entry.Value -isnot [long]) {
                        throw "AntiAI DWord prestate is not an integer: $path::$name"
                    }
                    $null = [int]$entry.Value
                }
                'QWord' {
                    if ($entry.Value -isnot [int] -and $entry.Value -isnot [long]) {
                        throw "AntiAI QWord prestate is not an integer: $path::$name"
                    }
                    $null = [long]$entry.Value
                }
                'String' {
                    if ($entry.Value -isnot [string]) { throw "AntiAI String value is not a string: $path::$name" }
                }
                'ExpandString' {
                    if ($entry.Value -isnot [string]) { throw "AntiAI ExpandString value is not a string: $path::$name" }
                }
                'MultiString' {
                    foreach ($item in @($entry.Value)) {
                        if ($item -isnot [string]) { throw "AntiAI MultiString contains a non-string item: $path::$name" }
                    }
                }
                'Binary' {
                    foreach ($item in @($entry.Value)) {
                        if (($item -isnot [int] -and $item -isnot [long]) -or
                            [int]$item -lt 0 -or [int]$item -gt 255) {
                            throw "AntiAI Binary contains a byte outside 0..255: $path::$name"
                        }
                    }
                }
            }
        }

        $pathIdentity = $path.ToLowerInvariant()
        if ($keyExistence.ContainsKey($pathIdentity) -and
            [bool]$keyExistence[$pathIdentity] -ne [bool]$entry.KeyExisted) {
            throw "Inconsistent AntiAI key-existence prestate: $path"
        }
        $keyExistence[$pathIdentity] = [bool]$entry.KeyExisted
    }

    foreach ($notApplicable in $notApplicableTargets) {
        foreach ($property in @('Path', 'Name', 'Reason')) {
            if (-not $notApplicable.PSObject.Properties[$property]) {
                throw "AntiAI non-applicable target is missing '$property'"
            }
        }
        $path = [string]$notApplicable.Path
        $name = [string]$notApplicable.Name
        if ([string]::IsNullOrWhiteSpace($path) -or
            [string]::IsNullOrWhiteSpace($name) -or
            [string]::IsNullOrWhiteSpace([string]$notApplicable.Reason)) {
            throw 'AntiAI non-applicable target has an empty identity or reason'
        }

        $canonicalIdentity = $null
        if ($allowedMachineTargets.ContainsKey($path) -and $name -in $allowedMachineTargets[$path]) {
            $canonicalIdentity = "$path`0$name"
        }
        elseif ($path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$' -and
            $allowedUserTargets.ContainsKey($Matches[2]) -and
            $name -in $allowedUserTargets[$Matches[2]]) {
            if ($null -eq $userSid) {
                $userSid = [string]$Matches[1]
            }
            elseif (-not $userSid.Equals([string]$Matches[1], [StringComparison]::OrdinalIgnoreCase)) {
                throw 'AntiAI registry snapshot spans more than one interactive user SID'
            }
            $canonicalIdentity = "HKU:\<SID>\$($Matches[2])`0$name"
        }
        else {
            throw "AntiAI non-applicable target is outside the exact allowlist: $path::$name"
        }
        if (-not $seen.Add($canonicalIdentity)) {
            throw "AntiAI snapshot contains an applicable/non-applicable duplicate: $path::$name"
        }
    }

    if (-not $RestoreOnly) {
        if ($seen.Count -ne $expectedIdentities.Count) {
            throw 'AntiAI registry snapshot does not contain the complete canonical target inventory'
        }
        foreach ($identity in $expectedIdentities) {
            if (-not $seen.Contains($identity)) {
                throw "AntiAI registry snapshot is missing canonical target '$identity'"
            }
        }
    }
    elseif ($seen.Count -ne [int]$Snapshot.DeclaredTargetCount) {
        throw 'AntiAI restore snapshot identity count does not reconcile'
    }
    return $true
}
