#Requires -Version 5.1

function Assert-EdgePolicySnapshot {
    <#
    .SYNOPSIS
        Validate a complete Edge BAVR prestate before any registry mutation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Snapshot,

        # Restore consumes the sealed, self-describing target list. It must not
        # require today's policy inventory or Apply values to equal an older
        # release's plan.
        [Parameter(Mandatory = $false)]
        [switch]$RestoreOnly
    )

    if ($null -eq $Snapshot) { throw 'Edge policy snapshot is null' }
    foreach ($property in @('SchemaVersion', 'CapturedAt', 'AllowExtensions', 'TargetCount', 'Entries')) {
        if (-not $Snapshot.PSObject.Properties[$property]) {
            throw "Edge policy snapshot is missing '$property'"
        }
    }
    $schemaVersion = [int]$Snapshot.SchemaVersion
    if ($schemaVersion -notin @(4, 5, 6) -or
        $Snapshot.AllowExtensions -isnot [bool] -or
        [int]$Snapshot.TargetCount -ne @($Snapshot.Entries).Count -or
        @($Snapshot.Entries).Count -eq 0) {
        throw 'Edge policy snapshot has an invalid schema, Boolean profile or target count'
    }

    # These are frozen schema counts, not today's inventory. A restore may not
    # become incomplete merely because all surviving paths happen to be on the
    # allowlist. Conversely, a later Apply inventory must not redefine them.
    $expectedDeclaredCount = switch ($schemaVersion) {
        4 { if ([bool]$Snapshot.AllowExtensions) { 22 } else { 23 } }
        5 { if ([bool]$Snapshot.AllowExtensions) { 22 } else { 23 } }
        6 { if ([bool]$Snapshot.AllowExtensions) { 25 } else { 26 } }
    }
    $recordedDeclaredCount = if ($schemaVersion -eq 4) {
        [int]$Snapshot.TargetCount
    }
    else {
        if (-not $Snapshot.PSObject.Properties['DeclaredTargetCount']) {
            throw "Edge schema-$schemaVersion snapshot is missing 'DeclaredTargetCount'"
        }
        [int]$Snapshot.DeclaredTargetCount
    }
    if ($recordedDeclaredCount -ne $expectedDeclaredCount) {
        throw "Edge schema-$schemaVersion snapshot does not contain its complete frozen profile inventory"
    }

    # Frozen restore allowlists are deliberately independent of today's Edge
    # policy files. Schema 4/5 are the original v2.2.5 inventory; schema 6 adds
    # the three later privacy controls. Future inventories must get a new schema
    # and keep these lists so an update can restore older sealed sessions without
    # accepting arbitrary values under the broad Edge policy roots.
    $restoreRootNames = @(
        'ApplicationBoundEncryptionEnabled', 'AuthSchemes', 'BasicAuthOverHttpEnabled',
        'BrowserLegacyExtensionPointsBlockingEnabled', 'DiagnosticData', 'DynamicCodeSettings',
        'EdgeShoppingAssistantEnabled', 'EnableUnsafeSwiftShader',
        'InternetExplorerIntegrationReloadInIEModeAllowed',
        'InternetExplorerIntegrationZoneIdentifierMhtFileAllowed',
        'InternetExplorerModeToolbarButtonEnabled', 'NativeMessagingUserLevelHosts',
        'PersonalizationReportingEnabled', 'PreventSmartScreenPromptOverride',
        'PreventSmartScreenPromptOverrideForFiles', 'SharedArrayBufferUnrestrictedAccessAllowed',
        'SitePerProcess', 'SmartScreenEnabled', 'SmartScreenPuaEnabled', 'SSLErrorOverrideAllowed',
        'TrackingPrevention', 'TyposquattingCheckerEnabled'
    )
    if ($schemaVersion -eq 6) {
        $restoreRootNames += @(
            'SearchSuggestEnabled', 'AddressBarTrendingSuggestEnabled',
            'EdgeReadingModeServiceBasedExtractionEnabled'
        )
    }
    $restoreAllowedNamesByPath = @{
        'HKLM:\Software\Policies\Microsoft\Edge' = @($restoreRootNames)
    }
    if (-not [bool]$Snapshot.AllowExtensions) {
        $restoreAllowedNamesByPath['HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'] = @('1')
    }
    try {
        $null = [DateTime]::ParseExact(
            [string]$Snapshot.CapturedAt,
            'o',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch { throw 'Edge policy snapshot has an invalid capture timestamp' }

    # Schema 4 has no NotApplicable bucket, but the common restore
    # reconciliation below still enumerates it. Initialize the empty set before
    # the schema split so production StrictMode cannot turn a valid frozen
    # schema-4 restore into an unbound-variable failure.
    $seenNotApplicable = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($schemaVersion -in @(5, 6)) {
        foreach ($property in @(
                'RuntimeApplicability', 'DeclaredTargetCount',
                'NotApplicableCount', 'NotApplicable'
            )) {
            if (-not $Snapshot.PSObject.Properties[$property]) {
                throw "Edge schema-$schemaVersion snapshot is missing '$property'"
            }
        }
        if ($schemaVersion -eq 6 -and -not $Snapshot.PSObject.Properties['EdgeInstallationStatus']) {
            throw "Edge schema-6 snapshot is missing 'EdgeInstallationStatus'"
        }
        if ([int]$Snapshot.DeclaredTargetCount -lt 1 -or
            [int]$Snapshot.NotApplicableCount -ne @($Snapshot.NotApplicable).Count -or
            [int]$Snapshot.TargetCount + [int]$Snapshot.NotApplicableCount -ne [int]$Snapshot.DeclaredTargetCount) {
            throw "Edge schema-$schemaVersion declared/applicable/NotApplicable counts do not reconcile"
        }

        if (-not $RestoreOnly) {
            $targetArguments = @{
                AllowExtensions      = [bool]$Snapshot.AllowExtensions
                RuntimeApplicability = $Snapshot.RuntimeApplicability
            }
            if ($schemaVersion -eq 6) {
                $targetArguments.EdgeInstallationStatus = $Snapshot.EdgeInstallationStatus
            }
            else {
                $targetArguments.LegacyV225 = $true
            }
            $declaredTargets = @(Get-EdgePolicyTargets @targetArguments)
            $expectedTargets = @($declaredTargets | Where-Object { [bool]$_.Applicable })
            $expectedNotApplicable = @($declaredTargets | Where-Object { -not [bool]$_.Applicable })
            if ([int]$Snapshot.DeclaredTargetCount -ne $declaredTargets.Count -or
                [int]$Snapshot.NotApplicableCount -ne $expectedNotApplicable.Count) {
                throw "Edge schema-$schemaVersion current inventory does not match the sealed plan"
            }
            $expectedNotApplicableMap = @{}
            foreach ($target in $expectedNotApplicable) {
                $identity = [string]::Concat([string]$target.Path, [char]0, [string]$target.Name).ToLowerInvariant()
                $expectedNotApplicableMap[$identity] = [string]$target.NotApplicableReason
            }
        }
        foreach ($item in @($Snapshot.NotApplicable)) {
            foreach ($property in @('Path', 'Name', 'Reason')) {
                if (-not $item.PSObject.Properties[$property]) {
                    throw "Edge NotApplicable entry is missing '$property'"
                }
            }
            $identity = [string]::Concat([string]$item.Path, [char]0, [string]$item.Name)
            $normalizedIdentity = $identity.ToLowerInvariant()
            $validRestoreIdentity = $restoreAllowedNamesByPath.ContainsKey([string]$item.Path) -and
                [string]$item.Name -in @($restoreAllowedNamesByPath[[string]$item.Path]) -and
                -not [string]::IsNullOrWhiteSpace([string]$item.Reason)
            if (-not $seenNotApplicable.Add($identity) -or
                ($RestoreOnly -and -not $validRestoreIdentity) -or
                (-not $RestoreOnly -and (
                    -not $expectedNotApplicableMap.ContainsKey($normalizedIdentity) -or
                    [string]$item.Reason -cne [string]$expectedNotApplicableMap[$normalizedIdentity]
                ))) {
                throw "Edge NotApplicable inventory mismatch: $($item.Path)::$($item.Name)"
            }
        }
        if (-not $RestoreOnly -and $seenNotApplicable.Count -ne $expectedNotApplicableMap.Count) {
            throw 'Edge NotApplicable inventory is incomplete'
        }
    }
    else {
        $expectedTargets = if ($RestoreOnly) { $null }
        else { @(Get-EdgePolicyTargets -AllowExtensions:([bool]$Snapshot.AllowExtensions) -LegacyV225) }
    }
    if (-not $RestoreOnly -and $expectedTargets.Count -ne [int]$Snapshot.TargetCount) {
        throw 'Edge policy snapshot profile does not match its canonical target count'
    }
    $expected = @{}
    if (-not $RestoreOnly) {
        foreach ($target in $expectedTargets) {
            $identity = [string]::Concat([string]$target.Path, [char]0, [string]$target.Name).ToLowerInvariant()
            $expected[$identity] = $target
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $keyExistence = @{}
    foreach ($entry in @($Snapshot.Entries)) {
        foreach ($property in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
            if (-not $entry.PSObject.Properties[$property]) {
                throw "Edge policy snapshot entry is missing '$property'"
            }
        }
        if ($schemaVersion -in @(5, 6)) {
            foreach ($property in @('ApplyType', 'ApplyValue')) {
                if (-not $entry.PSObject.Properties[$property]) {
                    throw "Edge schema-$schemaVersion snapshot entry is missing '$property'"
                }
            }
        }
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $identity = [string]::Concat($path, [char]0, $name)
        $normalizedIdentity = $identity.ToLowerInvariant()
        $restorePathAllowed = $restoreAllowedNamesByPath.ContainsKey($path) -and
            $name -in @($restoreAllowedNamesByPath[$path])
        if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or
            ($RestoreOnly -and -not $restorePathAllowed) -or
            (-not $RestoreOnly -and -not $expected.ContainsKey($normalizedIdentity)) -or
            -not $seen.Add($identity)) {
            throw "Edge policy snapshot contains an invalid, duplicate or unowned target: $path::$name"
        }
        if ($schemaVersion -in @(5, 6) -and -not $RestoreOnly) {
            $expectedTarget = $expected[$normalizedIdentity]
            $expectedApplyJson = ConvertTo-Json -InputObject @($expectedTarget.Value) -Compress -Depth 20
            $actualApplyJson = ConvertTo-Json -InputObject @($entry.ApplyValue) -Compress -Depth 20
            if ([string]$entry.ApplyType -cne [string]$expectedTarget.Type -or
                $actualApplyJson -cne $expectedApplyJson) {
                throw "Edge schema-$schemaVersion Apply contract mismatch: $path::$name"
            }
        }
        if ($entry.KeyExisted -isnot [bool] -or $entry.Exists -isnot [bool]) {
            throw "Edge policy snapshot existence flags must be Boolean: $path::$name"
        }
        if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
            throw "Edge policy snapshot claims a value in an originally absent key: $path::$name"
        }
        if (-not [bool]$entry.Exists) {
            if ($null -ne $entry.Type -or $null -ne $entry.Value) {
                throw "Absent Edge value must have null Type and Value: $path::$name"
            }
        }
        else {
            $type = [string]$entry.Type
            if ($type -notin @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')) {
                throw "Unsupported Edge registry value type '$type' for $path::$name"
            }
            switch ($type) {
                'DWord' {
                    $numeric = 0L
                    if (-not [long]::TryParse([string]$entry.Value, [ref]$numeric) -or
                        $numeric -lt [int]::MinValue -or $numeric -gt [int]::MaxValue) {
                        throw "Edge DWord prestate is not a valid 32-bit integer: $path::$name"
                    }
                }
                'QWord' {
                    $numeric = 0L
                    if (-not [long]::TryParse([string]$entry.Value, [ref]$numeric)) {
                        throw "Edge QWord prestate is not an integer: $path::$name"
                    }
                }
                'String'       { if ($entry.Value -isnot [string]) { throw "Edge String prestate is not a string: $path::$name" } }
                'ExpandString' { if ($entry.Value -isnot [string]) { throw "Edge ExpandString prestate is not a string: $path::$name" } }
                'MultiString'  { foreach ($item in @($entry.Value)) { if ($item -isnot [string]) { throw "Edge MultiString contains a non-string: $path::$name" } } }
                'Binary'       { foreach ($item in @($entry.Value)) { if ([int]$item -lt 0 -or [int]$item -gt 255) { throw "Edge Binary contains a byte outside 0..255: $path::$name" } } }
            }
        }

        $pathIdentity = $path.ToLowerInvariant()
        if ($keyExistence.ContainsKey($pathIdentity) -and
            [bool]$keyExistence[$pathIdentity] -ne [bool]$entry.KeyExisted) {
            throw "Edge policy snapshot has inconsistent key-existence state: $path"
        }
        $keyExistence[$pathIdentity] = [bool]$entry.KeyExisted
    }

    if ($RestoreOnly) {
        foreach ($identity in $seenNotApplicable) {
            if ($seen.Contains($identity)) {
                throw "Edge restore snapshot lists one target as both applicable and NotApplicable: $identity"
            }
        }
        if ($seen.Count -ne [int]$Snapshot.TargetCount -or
            ($schemaVersion -in @(5, 6) -and
                $seen.Count + @($Snapshot.NotApplicable).Count -ne $expectedDeclaredCount)) {
            throw 'Edge restore snapshot target count does not reconcile'
        }
    }
    else {
        if ($seen.Count -ne $expected.Count) {
            throw 'Edge policy snapshot does not contain the complete canonical target inventory'
        }
        foreach ($identity in $expected.Keys) {
            if (-not $seen.Contains($identity)) { throw "Edge policy snapshot is missing canonical target '$identity'" }
        }
    }
    return $true
}
