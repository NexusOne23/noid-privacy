#Requires -Version 5.1

function Assert-PrivacyRegistrySnapshot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Snapshot,

        [Parameter(Mandatory = $false)]
        [object[]]$ExpectedTargets,

        [Parameter(Mandatory = $false)]
        [object[]]$ExpectedNotApplicableTargets,

        [Parameter(Mandatory = $false)]
        [object[]]$ExpectedNotCheckedTargets,

        [Parameter(Mandatory = $false)]
        [switch]$RestoreOnly
    )

    $definitionFile = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($definitionFile)) { throw 'Privacy snapshot validator source path is unavailable' }
    $privateRoot = Split-Path -Parent $definitionFile

    $entries = @($Snapshot.Entries)
    $schemaVersion = [int]$Snapshot.SchemaVersion
    if ($schemaVersion -notin @(2, 3, 4, 5, 6, 7) -or $entries.Count -eq 0 -or
        [int]$Snapshot.TargetCount -ne $entries.Count) {
        throw 'Privacy registry snapshot has an invalid schema or target count'
    }
    # Newer snapshots additionally seal the ancestor levels Apply creates
    # implicitly, so Restore can remove them again. The property is additive
    # and presence-gated: schema 7 remains the decision-bound contract, and
    # older sealed sessions without the inventory keep their previous
    # (ancestor-retaining) restore semantics.
    if ($Snapshot.PSObject.Properties['AbsentAncestorKeys']) {
        $declaredEntryPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) { $null = $declaredEntryPaths.Add([string]$entry.Path) }
        $seenAncestors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($ancestorValue in @($Snapshot.AbsentAncestorKeys)) {
            $ancestorPath = ([string]$ancestorValue).TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($ancestorPath) -or
                -not $seenAncestors.Add($ancestorPath) -or
                ($ancestorPath -notmatch '(?i)^HKLM:\\SOFTWARE\\' -and
                 $ancestorPath -notmatch '(?i)^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\')) {
                throw "Invalid or duplicate Privacy absent ancestor: $ancestorPath"
            }
            $ownedDescendants = @($declaredEntryPaths | Where-Object {
                    $_.StartsWith("$ancestorPath\", [StringComparison]::OrdinalIgnoreCase)
                })
            if ($ownedDescendants.Count -eq 0) {
                throw "Privacy absent ancestor owns no declared target: $ancestorPath"
            }
        }
    }

    $allowedMachinePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput',
        'HKLM:\SOFTWARE\Policies\Microsoft\Dsh',
        'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice',
        'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search',
        'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive',
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
    )
    if ($RestoreOnly) {
        if (-not (Get-Command Get-PrivacyTier1Schema7RestorePolicyDefinition -ErrorAction SilentlyContinue) -or
            -not (Get-Command Get-PrivacyTier1LegacyV225RestorePolicyDefinition -ErrorAction SilentlyContinue)) {
            . (Join-Path $privateRoot 'Get-PrivacyTier1RestorePolicyDefinitions.ps1')
        }
        $tier1Definition = Get-PrivacyTier1Schema7RestorePolicyDefinition
        $tier1LegacyDefinition = Get-PrivacyTier1LegacyV225RestorePolicyDefinition
    }
    else {
        if (-not (Get-Command Get-PrivacyTier1PolicyDefinition -ErrorAction SilentlyContinue) -or
            -not (Get-Command Get-PrivacyTier1LegacyV225PolicyDefinition -ErrorAction SilentlyContinue)) {
            . (Join-Path $privateRoot 'Get-PrivacyTier1PolicyDefinition.ps1')
        }
        $tier1Definition = Get-PrivacyTier1PolicyDefinition
        $tier1LegacyDefinition = Get-PrivacyTier1LegacyV225PolicyDefinition
    }
    $tier1CurrentIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $tier1LegacyIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $tier1Identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($target in @($tier1Definition.Targets)) {
        $identity = "$($target.Path)`0$($target.Name)"
        $null = $tier1CurrentIdentities.Add($identity)
        $null = $tier1Identities.Add($identity)
    }
    foreach ($target in @($tier1LegacyDefinition.Targets)) {
        $identity = "$($target.Path)`0$($target.Name)"
        $null = $tier1LegacyIdentities.Add($identity)
        $null = $tier1Identities.Add($identity)
    }
    $allowedUserSuffixes = @(
        'Control Panel\International\User Profile',
        'SOFTWARE\Microsoft\InputPersonalization',
        'SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore',
        'SOFTWARE\Microsoft\Personalization\Settings',
        'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'Software\Microsoft\Windows\CurrentVersion\Search',
        'Software\Microsoft\Windows\CurrentVersion\SearchSettings',
        'Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders',
        'Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications',
        'Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement',
        'Software\Policies\Microsoft\Windows\CloudContent',
        'Software\Policies\Microsoft\Windows\Explorer'
    )
    $supportedTypes = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')
    $snapshotSid = $null
    if ($schemaVersion -in @(3, 4, 5, 6, 7)) {
        if (-not $Snapshot.PSObject.Properties['Mode'] -or
            [string]$Snapshot.Mode -notin @('MSRecommended', 'Strict', 'Paranoid') -or
            -not $Snapshot.PSObject.Properties['InteractiveUserSid']) {
            throw 'Privacy schema-3 snapshot is missing a valid mode or interactive-user SID'
        }
        $snapshotSid = [string]$Snapshot.InteractiveUserSid
        if ($snapshotSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') {
            throw 'Privacy schema-3 snapshot contains an unsupported interactive-user SID'
        }
        foreach ($runtimeProperty in @(
                'DeclaredServiceNames', 'ApplicableServiceNames',
                'DeclaredScheduledTaskPaths', 'ApplicableScheduledTaskPaths',
                'DeclaredRegistryTargetCount', 'NotApplicableRegistryTargets',
                'EditionFamily', 'BuildNumber'
            )) {
            if (-not $Snapshot.PSObject.Properties[$runtimeProperty]) {
                throw "Privacy schema-3 snapshot is missing runtime inventory '$runtimeProperty'"
            }
        }
        $declaredServices = @($Snapshot.DeclaredServiceNames | ForEach-Object { [string]$_ })
        $applicableServices = @($Snapshot.ApplicableServiceNames | ForEach-Object { [string]$_ })
        $declaredTasks = @($Snapshot.DeclaredScheduledTaskPaths | ForEach-Object { [string]$_ })
        $applicableTasks = @($Snapshot.ApplicableScheduledTaskPaths | ForEach-Object { [string]$_ })
        if (@($declaredServices | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
            @($declaredServices | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
            @($applicableServices | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
            @($applicableServices | Where-Object { $_ -notin $declaredServices }).Count -gt 0) {
            throw 'Privacy schema-3 service applicability inventory is invalid'
        }
        if (@($declaredTasks | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -notmatch '^\\[^\\].+' }).Count -gt 0 -or
            @($declaredTasks | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
            @($applicableTasks | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
            @($applicableTasks | Where-Object { $_ -notin $declaredTasks }).Count -gt 0) {
            throw 'Privacy schema-3 scheduled-task applicability inventory is invalid'
        }
        $notCheckedCount = if ($schemaVersion -in @(4, 5, 6, 7)) { @($Snapshot.NotCheckedRegistryTargets).Count } else { 0 }
        if ([string]$Snapshot.EditionFamily -notin @('Home', 'Professional', 'Enterprise', 'Education', 'IoTEnterprise') -or
            [int]$Snapshot.BuildNumber -lt 26100 -or
            [int]$Snapshot.DeclaredRegistryTargetCount -ne ($entries.Count + $notCheckedCount + @($Snapshot.NotApplicableRegistryTargets).Count)) {
            throw 'Privacy schema-3 registry applicability inventory is invalid'
        }
        if ($schemaVersion -in @(4, 5, 6, 7)) {
            foreach ($propertyName in @('DomainJoined','MdmRegistered','ManagementStateKnown','MultiSession','Tier1PolicyRemovalSelected','Tier2BloatwareRemovalSelected','NotCheckedRegistryTargets')) {
                if (-not $Snapshot.PSObject.Properties[$propertyName]) { throw "Privacy schema-4 snapshot is missing '$propertyName'" }
            }
            foreach ($booleanName in @('DomainJoined','MdmRegistered','ManagementStateKnown','MultiSession','Tier1PolicyRemovalSelected','Tier2BloatwareRemovalSelected')) {
                if ($Snapshot.$booleanName -isnot [bool]) { throw "Privacy schema-4 decision/applicability field is not Boolean: $booleanName" }
            }
            if ($schemaVersion -in @(6, 7)) {
                if (-not $Snapshot.PSObject.Properties['WeatherWidgetRemovalSelected'] -or
                    $Snapshot.WeatherWidgetRemovalSelected -isnot [bool] -or
                    ([bool]$Snapshot.WeatherWidgetRemovalSelected -and -not [bool]$Snapshot.Tier2BloatwareRemovalSelected)) {
                    throw 'Privacy schema-6/7 snapshot has an invalid Weather Widget decision'
                }
            }
            $hasUcpdKnown = $null -ne $Snapshot.PSObject.Properties['UcpdProtectionStateKnown']
            $hasUcpdActive = $null -ne $Snapshot.PSObject.Properties['UcpdProtectionActive']
            if ($hasUcpdKnown -ne $hasUcpdActive) {
                throw 'Privacy schema-4 snapshot contains an incomplete UCPD applicability contract'
            }
            if ($hasUcpdKnown -and
                ($Snapshot.UcpdProtectionStateKnown -isnot [bool] -or
                    $Snapshot.UcpdProtectionActive -isnot [bool] -or
                    -not $Snapshot.PSObject.Properties['UcpdStatus'])) {
                throw 'Privacy schema-4 UCPD applicability fields are invalid'
            }
            if ($schemaVersion -eq 7) {
                if (-not $Snapshot.PSObject.Properties['AppxFirewallState']) {
                    throw 'Privacy schema-7 snapshot is missing AppX firewall collateral state'
                }
                if (-not (Get-Command Assert-PrivacyAppxFirewallState -ErrorAction SilentlyContinue)) {
                    . (Join-Path $privateRoot 'PrivacyAppxFirewall.ps1')
                }
                $null = Assert-PrivacyAppxFirewallState -State $Snapshot.AppxFirewallState
                if (-not [bool]$Snapshot.Tier2BloatwareRemovalSelected -and
                    (@($Snapshot.AppxFirewallState.PackageFamilyNames).Count -ne 0 -or
                        [int]$Snapshot.AppxFirewallState.EntryCount -ne 0)) {
                    throw 'Privacy schema-7 unselected Tier 2 decision contains AppX firewall targets'
                }
            }
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $keyExistence = @{}
    foreach ($entry in $entries) {
        $required = @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')
        if ($schemaVersion -in @(3, 4, 5, 6, 7)) { $required += @('ApplyType', 'ApplyValue') }
        foreach ($propertyName in $required) {
            if (-not $entry.PSObject.Properties[$propertyName]) {
                throw "Privacy registry snapshot entry is missing '$propertyName'"
            }
        }

        $path = [string]$entry.Path
        $name = [string]$entry.Name
        if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or
            -not $seen.Add("$path`0$name")) {
            throw "Privacy registry snapshot contains an invalid or duplicate target: $path::$name"
        }
        if ($entry.KeyExisted -isnot [bool] -or $entry.Exists -isnot [bool]) {
            throw "Privacy registry snapshot contains a non-Boolean existence field: $path::$name"
        }

        $allowed = $path -in $allowedMachinePaths -or $tier1Identities.Contains("$path`0$name")
        if (-not $allowed -and $path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$') {
            if ($schemaVersion -in @(3, 4, 5, 6, 7) -and $Matches[1] -ne $snapshotSid) {
                throw "Privacy registry snapshot mixes interactive-user SIDs: $path::$name"
            }
            $allowed = $Matches[2] -in $allowedUserSuffixes
        }
        if (-not $allowed) {
            throw "Privacy registry snapshot target is outside the exact allowlist: $path::$name"
        }

        if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
            throw "Privacy snapshot claims an existing value in an absent key: $path::$name"
        }
        if ([bool]$entry.Exists) {
            if ([string]$entry.Type -cnotin $supportedTypes -or $null -eq $entry.Value) {
                throw "Privacy snapshot contains an invalid existing value state: $path::$name"
            }
        }
        elseif ($schemaVersion -in @(3, 4, 5, 6, 7) -and
            ($null -ne $entry.Type -or $null -ne $entry.Value)) {
            throw "Privacy schema-3 absent value must have null type and data: $path::$name"
        }

        if ($schemaVersion -in @(3, 4, 5, 6, 7) -and
            ([string]$entry.ApplyType -cnotin $supportedTypes -or $null -eq $entry.ApplyValue)) {
            throw "Privacy snapshot contains an invalid Apply type/value: $path::$name"
        }
        $pathIdentity = $path.ToLowerInvariant()
        if ($keyExistence.ContainsKey($pathIdentity) -and
            [bool]$keyExistence[$pathIdentity] -ne [bool]$entry.KeyExisted) {
            throw "Privacy snapshot contains inconsistent key-existence state: $path"
        }
        $keyExistence[$pathIdentity] = [bool]$entry.KeyExisted
    }

    if ($schemaVersion -in @(3, 4, 5, 6, 7)) {
        if ($schemaVersion -in @(4, 5, 6, 7)) {
            foreach ($entry in @($Snapshot.NotCheckedRegistryTargets)) {
                foreach ($propertyName in @('Path', 'Name', 'ApplyType', 'ApplyValue', 'Reason')) {
                    if (-not $entry.PSObject.Properties[$propertyName]) { throw "Privacy NotChecked entry is missing '$propertyName'" }
                }
                $path = [string]$entry.Path; $name = [string]$entry.Name
                if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or
                    [string]::IsNullOrWhiteSpace([string]$entry.Reason) -or
                    [string]$entry.ApplyType -cnotin $supportedTypes -or $null -eq $entry.ApplyValue -or
                    -not $seen.Add("$path`0$name") -or -not $tier1Identities.Contains("$path`0$name")) {
                    throw "Privacy snapshot contains an invalid/duplicate NotChecked target: $path::$name"
                }
            }
        }
        foreach ($entry in @($Snapshot.NotApplicableRegistryTargets)) {
            foreach ($propertyName in @('Path', 'Name', 'ApplyType', 'ApplyValue', 'Reason')) {
                if (-not $entry.PSObject.Properties[$propertyName]) {
                    throw "Privacy NotApplicable entry is missing '$propertyName'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or
                [string]::IsNullOrWhiteSpace([string]$entry.Reason) -or
                [string]$entry.ApplyType -cnotin $supportedTypes -or $null -eq $entry.ApplyValue -or
                -not $seen.Add("$path`0$name")) {
                throw "Privacy snapshot contains an invalid/duplicate NotApplicable target: $path::$name"
            }
            $allowed = $path -in $allowedMachinePaths -or $tier1Identities.Contains("$path`0$name")
            if (-not $allowed -and $path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$') {
                if ($Matches[1] -ne $snapshotSid) {
                    throw "Privacy NotApplicable target uses another interactive-user SID: $path::$name"
                }
                $allowed = $Matches[2] -in $allowedUserSuffixes
            }
            if (-not $allowed) {
                throw "Privacy NotApplicable target is outside the exact allowlist: $path::$name"
            }
        }
        $allTier1 = @(@($entries) + @($Snapshot.NotCheckedRegistryTargets) + @($Snapshot.NotApplicableRegistryTargets)) |
            Where-Object { $tier1Identities.Contains("$($_.Path)`0$($_.Name)") }
        if (@($allTier1).Count -gt 0) {
            $allTier1Identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in @($allTier1)) { $null = $allTier1Identities.Add("$($entry.Path)`0$($entry.Name)") }
            $isCurrentContract = ($allTier1Identities.Count -eq $tier1CurrentIdentities.Count)
            if ($isCurrentContract) {
                foreach ($identity in $tier1CurrentIdentities) {
                    if (-not $allTier1Identities.Contains($identity)) { $isCurrentContract = $false; break }
                }
            }
            $isLegacyContract = ($allTier1Identities.Count -eq $tier1LegacyIdentities.Count)
            if ($isLegacyContract) {
                foreach ($identity in $tier1LegacyIdentities) {
                    if (-not $allTier1Identities.Contains($identity)) { $isLegacyContract = $false; break }
                }
            }
            if (-not $isCurrentContract -and -not $isLegacyContract) {
                throw 'Privacy snapshot must contain one complete Tier 1 contract; current/legacy mixtures are invalid'
            }
        }
        if ($schemaVersion -in @(4, 5, 6, 7)) {
            if (@($allTier1).Count -ne 27) { throw 'Privacy schema-4 snapshot does not account for all 27 Tier 1 targets' }
            $appliedTier1 = @($entries | Where-Object { $tier1Identities.Contains("$($_.Path)`0$($_.Name)") })
            $notCheckedTier1 = @($Snapshot.NotCheckedRegistryTargets | Where-Object {
                    $tier1Identities.Contains("$($_.Path)`0$($_.Name)")
                })
            if ([bool]$Snapshot.Tier1PolicyRemovalSelected -and $notCheckedTier1.Count -ne 0) {
                throw 'Privacy schema-4 selected Tier 1 decision contains NotChecked targets'
            }
            if (-not [bool]$Snapshot.Tier1PolicyRemovalSelected -and $appliedTier1.Count -ne 0) {
                throw 'Privacy schema-4 unselected Tier 1 decision contains Apply targets'
            }
        }
    }

    if ($schemaVersion -in @(3, 4, 5, 6, 7) -and $ExpectedTargets) {
        $expected = @($ExpectedTargets)
        if ($expected.Count -ne $entries.Count) {
            throw "Privacy snapshot target count differs from the selected Apply plan: $($entries.Count)/$($expected.Count)"
        }
        $entryMap = @{}
        foreach ($entry in $entries) { $entryMap[("$($entry.Path)`0$($entry.Name)").ToLowerInvariant()] = $entry }
        foreach ($target in $expected) {
            $identity = ("$($target.Path)`0$($target.Name)").ToLowerInvariant()
            if (-not $entryMap.ContainsKey($identity)) {
                throw "Privacy snapshot is missing selected Apply target: $($target.Path)::$($target.Name)"
            }
            $entry = $entryMap[$identity]
            $expectedJson = [PSCustomObject]@{ Value = $target.Value } | ConvertTo-Json -Compress -Depth 20
            $actualJson = [PSCustomObject]@{ Value = $entry.ApplyValue } | ConvertTo-Json -Compress -Depth 20
            if ([string]$entry.ApplyType -ne [string]$target.Type -or $actualJson -cne $expectedJson) {
                throw "Privacy snapshot Apply contract mismatch: $($target.Path)::$($target.Name)"
            }
        }
    }

    if ($schemaVersion -in @(3, 4, 5, 6, 7) -and $null -ne $ExpectedNotApplicableTargets) {
        $expectedNA = @($ExpectedNotApplicableTargets)
        $actualNA = @($Snapshot.NotApplicableRegistryTargets)
        if ($expectedNA.Count -ne $actualNA.Count) {
            throw "Privacy NotApplicable target count differs from the selected plan: $($actualNA.Count)/$($expectedNA.Count)"
        }
        $actualMap = @{}
        foreach ($target in $actualNA) { $actualMap[("$($target.Path)`0$($target.Name)").ToLowerInvariant()] = $target }
        foreach ($target in $expectedNA) {
            $identity = ("$($target.Path)`0$($target.Name)").ToLowerInvariant()
            if (-not $actualMap.ContainsKey($identity)) {
                throw "Privacy snapshot is missing NotApplicable target: $($target.Path)::$($target.Name)"
            }
            $actual = $actualMap[$identity]
            $expectedJson = [PSCustomObject]@{ Value = $target.ApplyValue } | ConvertTo-Json -Compress -Depth 20
            $actualJson = [PSCustomObject]@{ Value = $actual.ApplyValue } | ConvertTo-Json -Compress -Depth 20
            if ([string]$actual.ApplyType -ne [string]$target.ApplyType -or
                [string]$actual.Reason -cne [string]$target.Reason -or $actualJson -cne $expectedJson) {
                throw "Privacy snapshot NotApplicable contract mismatch: $($target.Path)::$($target.Name)"
            }
        }
    }

    if ($schemaVersion -in @(4, 5, 6, 7) -and $null -ne $ExpectedNotCheckedTargets) {
        $expectedNC = @($ExpectedNotCheckedTargets)
        $actualNC = @($Snapshot.NotCheckedRegistryTargets)
        if ($expectedNC.Count -ne $actualNC.Count) {
            throw "Privacy NotChecked target count differs from the selected plan: $($actualNC.Count)/$($expectedNC.Count)"
        }
        $actualMap = @{}
        foreach ($target in $actualNC) { $actualMap[("$($target.Path)`0$($target.Name)").ToLowerInvariant()] = $target }
        foreach ($target in $expectedNC) {
            $identity = ("$($target.Path)`0$($target.Name)").ToLowerInvariant()
            if (-not $actualMap.ContainsKey($identity)) { throw "Privacy snapshot is missing NotChecked target: $($target.Path)::$($target.Name)" }
            $actual = $actualMap[$identity]
            $expectedJson = [PSCustomObject]@{ Value = $target.ApplyValue } | ConvertTo-Json -Compress -Depth 20
            $actualJson = [PSCustomObject]@{ Value = $actual.ApplyValue } | ConvertTo-Json -Compress -Depth 20
            if ([string]$actual.ApplyType -ne [string]$target.ApplyType -or $actualJson -cne $expectedJson -or
                [string]$actual.Reason -cne [string]$target.Reason) {
                throw "Privacy NotChecked contract mismatch: $($target.Path)::$($target.Name)"
            }
        }
    }

    return $true
}
