#Requires -Version 5.1

function Assert-PrivacyPrestate {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SnapshotPath,

        [Parameter(Mandatory = $true)]
        [object[]]$Artifacts,

        # The caller performs this availability/identity preflight before the
        # module manifest is sealed. Its immediate post-seal reconciliation
        # repeats every durable/live prestate check below, but must not launch
        # the same transient native API probe a second time.
        [switch]$WindowsSearchPreflightAlreadyProven
    )

    $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $null = Assert-PrivacyRegistrySnapshot -Snapshot $snapshot
    $currentApplicability = Get-PrivacyApplicability
    if ([string]$currentApplicability.EditionFamily -ne [string]$snapshot.EditionFamily -or
        [int]$currentApplicability.BuildNumber -ne [int]$snapshot.BuildNumber) {
        throw "Privacy Windows applicability changed before Apply: expected $($snapshot.EditionFamily)/$($snapshot.BuildNumber), got $($currentApplicability.EditionFamily)/$($currentApplicability.BuildNumber)"
    }
    if ([int]$snapshot.SchemaVersion -in @(4, 5, 6, 7) -and
        ([bool]$currentApplicability.DomainJoined -ne [bool]$snapshot.DomainJoined -or
            [bool]$currentApplicability.MdmRegistered -ne [bool]$snapshot.MdmRegistered -or
            [bool]$currentApplicability.ManagementStateKnown -ne [bool]$snapshot.ManagementStateKnown -or
            [bool]$currentApplicability.MultiSession -ne [bool]$snapshot.MultiSession)) {
        throw 'Privacy management/multi-session applicability changed before Apply'
    }
    if ($snapshot.PSObject.Properties['UcpdProtectionStateKnown']) {
        $currentUcpd = Get-PrivacyUcpdProtectionState
        if ([bool]$currentUcpd.StateKnown -ne [bool]$snapshot.UcpdProtectionStateKnown -or
            [bool]$currentUcpd.Active -ne [bool]$snapshot.UcpdProtectionActive -or
            [string]$currentUcpd.Status -cne [string]$snapshot.UcpdStatus) {
            throw 'Privacy UCPD applicability changed before Apply'
        }
    }
    if ([int]$snapshot.SchemaVersion -eq 7 -and
        -not $WindowsSearchPreflightAlreadyProven) {
        # Preflight the documented per-user API in the actual Explorer token
        # before any target is mutated. This catches a missing cmdlet, a UAC
        # credential-account mismatch, or an Explorer identity change while
        # the sealed registry prestate is still untouched.
        $searchUser = Get-PrivacyUserContext -Refresh
        if ([string]$searchUser.Sid -cne [string]$snapshot.InteractiveUserSid) {
            throw 'Interactive Privacy user changed before WindowsSearch preflight'
        }
        $searchPreflight = Invoke-PrivacyWindowsSearchUserState -User $searchUser -Operation Query
        if (-not [bool]$searchPreflight.Success) {
            throw 'WindowsSearch user-token preflight did not report success'
        }
    }

    foreach ($entry in @($snapshot.Entries)) {
        $keyExists = Test-Path -LiteralPath ([string]$entry.Path) -PathType Container
        if ($keyExists -ne [bool]$entry.KeyExisted) {
            throw "Privacy prestate key drifted before Apply: $($entry.Path)"
        }
        $valueExists = $false
        $actualType = $null
        $actualValue = $null
        if ($keyExists) {
            $key = Get-Item -LiteralPath ([string]$entry.Path) -ErrorAction Stop
            $valueExists = $key.GetValueNames() -contains [string]$entry.Name
            if ($valueExists) {
                $actualType = $key.GetValueKind([string]$entry.Name).ToString()
                $actualValue = $key.GetValue(
                    [string]$entry.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
            }
        }
        if ($valueExists -ne [bool]$entry.Exists) {
            throw "Privacy prestate value existence drifted before Apply: $($entry.Path)::$($entry.Name)"
        }
        if ($valueExists) {
            $expectedJson = [PSCustomObject]@{ Value = $entry.Value } | ConvertTo-Json -Compress -Depth 20
            $actualJson = [PSCustomObject]@{ Value = $actualValue } | ConvertTo-Json -Compress -Depth 20
            if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                throw "Privacy prestate value/type drifted before Apply: $($entry.Path)::$($entry.Name)"
            }
        }
    }

    $artifactList = @($Artifacts)
    if (@($artifactList | Where-Object { [string]$_.Type -eq 'Privacy' -and [string]$_.Name -eq 'Privacy_PreState' }).Count -ne 1) {
        throw 'Privacy prestate inventory does not contain exactly one Privacy_PreState artifact'
    }
    $bloatwareArtifacts = @($artifactList | Where-Object {
            [string]$_.Type -eq 'Privacy' -and [string]$_.Name -eq 'Privacy_BloatwareActions'
        })
    $expectedBloatwareArtifacts = if ([int]$snapshot.SchemaVersion -in @(4, 5, 6, 7) -and [bool]$snapshot.Tier2BloatwareRemovalSelected) { 1 } else { 0 }
    if ($bloatwareArtifacts.Count -ne $expectedBloatwareArtifacts) {
        throw "Privacy Tier 2 decision/artifact mismatch: expected $expectedBloatwareArtifacts, found $($bloatwareArtifacts.Count)"
    }
    if ($bloatwareArtifacts.Count -eq 1) {
        $sealedInventory = Get-Content -LiteralPath ([string]$bloatwareArtifacts[0].BackupFile) -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-PrivacyBloatwareActionLog -ActionLog $sealedInventory
        if ([string]$sealedInventory.InteractiveUserSid -cne [string]$snapshot.InteractiveUserSid) {
            throw 'Privacy Tier 2 inventory user differs from the registry prestate user'
        }
        if ([int]$snapshot.SchemaVersion -in @(6, 7) -and
            [bool]$sealedInventory.WeatherWidgetRemovalSelected -ne [bool]$snapshot.WeatherWidgetRemovalSelected) {
            throw 'Privacy Weather Widget decision differs between registry prestate and Tier 2 action log'
        }
        $liveInventory = Get-PrivacyBloatwareActionLog -IncludeWeatherWidget ([bool]($snapshot.PSObject.Properties['WeatherWidgetRemovalSelected'] -and $snapshot.WeatherWidgetRemovalSelected))
        $null = Assert-PrivacyBloatwareActionLog -ActionLog $liveInventory
        if ([string]$liveInventory.CatalogSha256 -cne [string]$sealedInventory.CatalogSha256 -or
            [string]$liveInventory.InventorySha256 -cne [string]$sealedInventory.InventorySha256) {
            throw 'Privacy Tier 2 package/provisioning inventory drifted before Apply'
        }
        if ([int]$snapshot.SchemaVersion -eq 7) {
            $sealedFamilies = @(Get-PrivacyAppxOrdinalUniqueStrings -Values @(
                    $sealedInventory.Entries | Where-Object { [bool]$_.Present } |
                        ForEach-Object { [string]$_.PackageFamilyName }
                ))
            $null = Assert-PrivacyAppxFirewallState -State $snapshot.AppxFirewallState `
                -ExpectedPackageFamilyNames $sealedFamilies
        }
    }
    if ([int]$snapshot.SchemaVersion -eq 7) {
        $liveFirewallState = Get-PrivacyAppxFirewallState `
            -PackageFamilyNames @($snapshot.AppxFirewallState.PackageFamilyNames)
        if ([string]$liveFirewallState.StateSha256 -cne [string]$snapshot.AppxFirewallState.StateSha256) {
            throw 'Privacy AppX firewall collateral state drifted before Apply'
        }
    }
    $tier1AppArtifacts = @($artifactList | Where-Object {
            [string]$_.Type -eq 'Privacy' -and [string]$_.Name -eq 'Privacy_Tier1AppInventory'
        })
    $expectedTier1AppArtifacts = if ([int]$snapshot.SchemaVersion -in @(5, 6, 7) -and [bool]$snapshot.Tier1PolicyRemovalSelected) { 1 } else { 0 }
    if ($tier1AppArtifacts.Count -ne $expectedTier1AppArtifacts) {
        throw "Privacy Tier 1 decision/artifact mismatch: expected $expectedTier1AppArtifacts, found $($tier1AppArtifacts.Count)"
    }
    if ($tier1AppArtifacts.Count -eq 1) {
        $sealedTier1Inventory = Get-Content -LiteralPath ([string]$tier1AppArtifacts[0].BackupFile) -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-PrivacyTier1AppInventory -Inventory $sealedTier1Inventory
        if ([string]$sealedTier1Inventory.InteractiveUserSid -cne [string]$snapshot.InteractiveUserSid) {
            throw 'Privacy Tier 1 app inventory user differs from the registry prestate user'
        }
        $liveTier1Inventory = Get-PrivacyTier1AppInventory
        $null = Assert-PrivacyTier1AppInventory -Inventory $liveTier1Inventory
        if ([string]$liveTier1Inventory.PolicySha256 -cne [string]$sealedTier1Inventory.PolicySha256 -or
            [string]$liveTier1Inventory.CatalogSha256 -cne [string]$sealedTier1Inventory.CatalogSha256 -or
            [string]$liveTier1Inventory.InventorySha256 -cne [string]$sealedTier1Inventory.InventorySha256) {
            throw 'Privacy Tier 1 package/provisioning inventory drifted before Apply'
        }
    }
    $serviceArtifactNames = @($artifactList | Where-Object { [string]$_.Type -eq 'Service' } |
        ForEach-Object { ([string]$_.ServiceName).ToLowerInvariant() } | Sort-Object)
    $expectedServiceNames = @($snapshot.ApplicableServiceNames |
        ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
    if (($serviceArtifactNames -join "`0") -cne ($expectedServiceNames -join "`0")) {
        throw 'Privacy service artifacts do not match the sealed applicability inventory'
    }
    $taskArtifactPaths = @($artifactList | Where-Object { [string]$_.Type -eq 'ScheduledTask' } |
        ForEach-Object { ("$([string]$_.TaskPath)$([string]$_.TaskName)").ToLowerInvariant() } | Sort-Object)
    $expectedTaskPaths = @($snapshot.ApplicableScheduledTaskPaths |
        ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
    if (($taskArtifactPaths -join "`0") -cne ($expectedTaskPaths -join "`0")) {
        throw 'Privacy scheduled-task artifacts do not match the sealed applicability inventory'
    }
    $liveServices = @(Get-Service -ErrorAction Stop)
    foreach ($absentService in @($snapshot.DeclaredServiceNames | Where-Object { $_ -notin @($snapshot.ApplicableServiceNames) })) {
        if (@($liveServices | Where-Object { [string]$_.Name -eq [string]$absentService }).Count -gt 0) {
            throw "Originally absent Privacy service appeared before Apply: $absentService"
        }
    }
    $liveTasks = if (@($snapshot.DeclaredScheduledTaskPaths).Count -gt 0) { @(Get-ScheduledTask -ErrorAction Stop) } else { @() }
    foreach ($absentTaskPath in @($snapshot.DeclaredScheduledTaskPaths | Where-Object { $_ -notin @($snapshot.ApplicableScheduledTaskPaths) })) {
        $absentTaskName = Split-Path ([string]$absentTaskPath) -Leaf
        $absentTaskFolder = Split-Path ([string]$absentTaskPath) -Parent
        $folderName = $absentTaskFolder.Trim([char]'\')
        $absentTaskFolder = if ([string]::IsNullOrWhiteSpace($folderName)) { '\' } else { '\' + $folderName + '\' }
        if (@($liveTasks | Where-Object {
                    [string]$_.TaskPath -eq $absentTaskFolder -and [string]$_.TaskName -eq $absentTaskName
                }).Count -gt 0) {
            throw "Originally absent Privacy scheduled task appeared before Apply: $absentTaskPath"
        }
    }
    foreach ($artifact in @($artifactList | Where-Object { [string]$_.Type -eq 'Service' })) {
        $state = Get-Content -LiteralPath ([string]$artifact.BackupFile) -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $service = Get-Service -Name ([string]$state.Name) -ErrorAction Stop
        if ([string]$service.StartType -ne [string]$state.StartType -or
            [string]$service.Status -ne [string]$state.Status) {
            throw "Privacy service prestate drifted before Apply: $($state.Name)"
        }
        $serviceKey = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($state.Name)" -ErrorAction Stop
        $delayedExists = $serviceKey.GetValueNames() -contains 'DelayedAutoStart'
        if ($delayedExists -ne [bool]$state.DelayedAutoStartExists -or
            ($delayedExists -and
                ($serviceKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord' -or
                 [int]$serviceKey.GetValue('DelayedAutoStart') -ne [int]$state.DelayedAutoStart))) {
            throw "Privacy service delayed-start prestate drifted before Apply: $($state.Name)"
        }
    }
    foreach ($artifact in @($artifactList | Where-Object { [string]$_.Type -eq 'ScheduledTask' })) {
        $state = Get-Content -LiteralPath ([string]$artifact.BackupFile) -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $task = Get-ScheduledTask -TaskPath ([string]$state.TaskPath) -TaskName ([string]$state.TaskName) -ErrorAction Stop
        $actualXml = Export-ScheduledTask -TaskPath ([string]$state.TaskPath) -TaskName ([string]$state.TaskName) -ErrorAction Stop
        [xml]$expectedDocument = [string]$state.XmlDefinition
        [xml]$actualDocument = [string]$actualXml
        $enabled = [string]$task.State -ne 'Disabled'
        if ($expectedDocument.OuterXml -cne $actualDocument.OuterXml -or $enabled -ne [bool]$state.Enabled) {
            throw "Privacy scheduled-task prestate drifted before Apply: $($state.TaskPath)$($state.TaskName)"
        }
    }

    return $true
}
