#Requires -Version 5.1

function Get-PrivacyBloatwareConfig {
    <#
    .SYNOPSIS
        Loads and strictly validates the Tier 2 removal and reinstall catalogs.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$PreCopilot,

        [Parameter(Mandatory = $false)]
        [switch]$PreviousV33,

        [Parameter(Mandatory = $false)]
        [switch]$PreviousV34
    )

    if (@(@($PreCopilot, $PreviousV33, $PreviousV34) | Where-Object { $_ }).Count -gt 1) {
        throw 'Privacy bloatware catalog accepts only one restore-only contract selector'
    }

    $definitionFile = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($definitionFile)) { throw 'Privacy bloatware loader source path is unavailable' }
    $moduleRoot = Split-Path -Parent (Split-Path -Parent $definitionFile)
    $bloatwarePath = Join-Path $moduleRoot 'Config\Bloatware.json'
    $mapPath = Join-Path $moduleRoot 'Config\Bloatware-Map.json'
    foreach ($requiredPath in @($bloatwarePath, $mapPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Privacy bloatware configuration is missing: $requiredPath"
        }
    }
    $bloatware = Get-Content -LiteralPath $bloatwarePath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $map = Get-Content -LiteralPath $mapPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    foreach ($requiredSection in @('RemoveApps', 'OptionalRemoveApps', 'ProtectedApps')) {
        if (-not $bloatware.PSObject.Properties[$requiredSection]) {
            throw "Privacy bloatware configuration section is missing: $requiredSection"
        }
    }
    if (-not $map.PSObject.Properties['Mappings']) {
        throw 'Privacy Bloatware-Map configuration section is missing: Mappings'
    }

    $removeApps = @($bloatware.RemoveApps | ForEach-Object { [string]$_ })
    if (-not $bloatware.OptionalRemoveApps.PSObject.Properties['WeatherWidget']) {
        throw 'Privacy bloatware OptionalRemoveApps is missing WeatherWidget'
    }
    $weatherWidgetApp = [string]$bloatware.OptionalRemoveApps.WeatherWidget
    $optionalRemoveApps = @($bloatware.OptionalRemoveApps.PSObject.Properties | ForEach-Object { [string]$_.Value })
    $allRemoveApps = @($removeApps + $optionalRemoveApps)
    $protectedApps = @($bloatware.ProtectedApps | ForEach-Object { [string]$_ })
    foreach ($catalog in @(
            [PSCustomObject]@{ Name='RemoveApps'; Values=$removeApps },
            [PSCustomObject]@{ Name='OptionalRemoveApps'; Values=$optionalRemoveApps },
            [PSCustomObject]@{ Name='AllRemoveApps'; Values=$allRemoveApps },
            [PSCustomObject]@{ Name='ProtectedApps'; Values=$protectedApps }
        )) {
        if ($catalog.Values.Count -eq 0 -or
            @($catalog.Values | Where-Object { $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.]+$' }).Count -gt 0 -or
            @($catalog.Values | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
            throw "Privacy bloatware $($catalog.Name) contains an empty, wildcard, malformed, or duplicate entry"
        }
    }
    if (@($bloatware.OptionalRemoveApps.PSObject.Properties).Count -ne 1 -or
        $weatherWidgetApp -cne 'MicrosoftWindows.Client.WebExperience') {
        throw 'Privacy bloatware OptionalRemoveApps must contain only the canonical WeatherWidget package'
    }
    $overlap = @($allRemoveApps | Where-Object { $_ -in $protectedApps })
    if ($overlap.Count -gt 0) {
        throw "Privacy bloatware RemoveApps overlaps ProtectedApps: $($overlap -join ', ')"
    }

    $mappingNames = @($map.Mappings.PSObject.Properties.Name)
    if ($mappingNames.Count -ne $allRemoveApps.Count -or
        @($mappingNames | Where-Object { $_ -notin $allRemoveApps }).Count -gt 0 -or
        @($allRemoveApps | Where-Object { $_ -notin $mappingNames }).Count -gt 0) {
        throw 'Privacy Bloatware-Map must contain exactly one mapping for every removal-list app'
    }

    $normalizedMappings = [ordered]@{}
    foreach ($appName in @($allRemoveApps | Sort-Object)) {
        $definition = $map.Mappings.$appName
        if (-not $definition.PSObject.Properties['StoreId'] -or
            -not $definition.PSObject.Properties['ExpectedPackageNames']) {
            throw "Privacy Bloatware-Map entry is incomplete: $appName"
        }
        $storeId = [string]$definition.StoreId
        $expectedNames = @($definition.ExpectedPackageNames | ForEach-Object { [string]$_ })
        $replacementNote = if ($definition.PSObject.Properties['ReplacementNote']) { [string]$definition.ReplacementNote } else { $null }
        if ((-not [string]::IsNullOrWhiteSpace($storeId) -and $storeId -notmatch '^[A-Z0-9]{12}$') -or
            @($expectedNames | Where-Object { $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.]+$' }).Count -gt 0 -or
            @($expectedNames | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
            ([string]::IsNullOrWhiteSpace($storeId) -and $expectedNames.Count -ne 0) -or
            (-not [string]::IsNullOrWhiteSpace($storeId) -and $expectedNames.Count -eq 0) -or
            ($definition.PSObject.Properties['ReplacementNote'] -and [string]::IsNullOrWhiteSpace($replacementNote)) -or
            (-not [string]::IsNullOrWhiteSpace($storeId) -and $appName -notin $expectedNames -and [string]::IsNullOrWhiteSpace($replacementNote))) {
            throw "Privacy Bloatware-Map entry has an invalid Store/expected-package contract: $appName"
        }
        # A device-wide (Tier 1) Store route exists only where the per-user (Tier 2)
        # route is withheld, and its note must say why the tiers differ.
        $hasDeprovisionedStoreId = [bool]$definition.PSObject.Properties['DeprovisionedStoreId']
        if ($hasDeprovisionedStoreId -ne [bool]$definition.PSObject.Properties['DeprovisionedExpectedPackageNames']) {
            throw "Privacy Bloatware-Map entry has an incomplete device-wide Store contract: $appName"
        }
        $normalizedMapping = [ordered]@{
            StoreId = $storeId
            ExpectedPackageNames = @($expectedNames)
            ReplacementNote = $replacementNote
        }
        if ($hasDeprovisionedStoreId) {
            $deprovisionedStoreId = [string]$definition.DeprovisionedStoreId
            $deprovisionedNames = @($definition.DeprovisionedExpectedPackageNames | ForEach-Object { [string]$_ })
            if ($deprovisionedStoreId -notmatch '^[A-Z0-9]{12}$' -or $deprovisionedNames.Count -eq 0 -or
                @($deprovisionedNames | Where-Object { $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.]+$' }).Count -gt 0 -or
                @($deprovisionedNames | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
                $appName -notin $deprovisionedNames -or
                -not [string]::IsNullOrWhiteSpace($storeId) -or
                [string]::IsNullOrWhiteSpace($replacementNote)) {
                throw "Privacy Bloatware-Map entry has an invalid device-wide Store contract: $appName"
            }
            $normalizedMapping['DeprovisionedStoreId'] = $deprovisionedStoreId
            $normalizedMapping['DeprovisionedExpectedPackageNames'] = @($deprovisionedNames)
        }
        $normalizedMappings[$appName] = [PSCustomObject]$normalizedMapping
    }

    $catalogDocument = [ordered]@{
        # Preserve the schema-2 semantic catalog hash: the optional split changes
        # selection, not the canonical set or its restore mappings.
        RemoveApps = @($allRemoveApps | Sort-Object)
        ProtectedApps = @($protectedApps | Sort-Object)
        Mappings = $normalizedMappings
    }
    $catalogJson = ConvertTo-Json -InputObject $catalogDocument -Compress -Depth 10
    # Windows PowerShell 5.1/Newtonsoft escapes HTML-sensitive characters while
    # PowerShell 7 does not. Normalize to the 5.1 representation so the sealed
    # semantic catalog identity is stable in release tooling and future hosts.
    $catalogJson = $catalogJson.Replace('&', '\u0026').Replace("'", '\u0027').Replace('<', '\u003c').Replace('>', '\u003e')
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $catalogHash = ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($catalogJson)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    if ($PreCopilot -or $PreviousV33 -or $PreviousV34) {
        # Restore-only: catalogs up to v3.4 had no device-wide Store route for
        # Xbox TCUI; sessions sealed against them keep the local-only route.
        $normalizedMappings['Microsoft.Xbox.TCUI'] = [PSCustomObject]@{
            StoreId = ''
            ExpectedPackageNames = @()
            ReplacementNote = $null
        }
    }

    if ($PreCopilot -or $PreviousV33) {
        # Restore-only reconstruction of the immediately preceding v3.3 map.
        # New Backup/Apply never consumes this Store mapping: its real
        # post-removal install was proven unreliable and is absent from v3.4.
        $normalizedMappings['Microsoft.BingNews'] = [PSCustomObject]@{
            StoreId = '9WZDNCRFHVFW'
            ExpectedPackageNames = @('Microsoft.BingNews')
            ReplacementNote = $null
        }
    }

    if ($PreviousV34) {
        # Restore-only reconstruction of the v3.4 map, which had no device-wide
        # Store route for News; sessions sealed against it stay restorable.
        $normalizedMappings['Microsoft.BingNews'] = [PSCustomObject]@{
            StoreId = ''
            ExpectedPackageNames = @()
            ReplacementNote = "The current Storefront and WinGet show still resolve product 9WZDNCRFHVFW, but the release-gate install/postcheck fails with ERROR_PACKAGE_ALREADY_EXISTS (0x80073CFB) when the removed user's package remains staged/provisioned, which is the normal Tier 2 recovery state. Only sealed local package-family re-registration is claimed until the Store fallback passes that exact post-removal scenario."
        }
        $previousV34Hash = 'b4d4e4a75315a05dbe320b627cb7fe1704886bec592f7ceaf1bef7fe7fe08bd4'
        $previousV34Document = [ordered]@{
            RemoveApps = @($allRemoveApps | Sort-Object)
            ProtectedApps = @($protectedApps | Sort-Object)
            Mappings = $normalizedMappings
        }
        $previousV34Json = ConvertTo-Json -InputObject $previousV34Document -Compress -Depth 10
        $previousV34Json = $previousV34Json.Replace('&', '\u0026').Replace("'", '\u0027').Replace('<', '\u003c').Replace('>', '\u003e')
        $previousV34Sha = [Security.Cryptography.SHA256]::Create()
        try {
            $catalogHash = ([BitConverter]::ToString($previousV34Sha.ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($previousV34Json)))).Replace('-', '').ToLowerInvariant()
        }
        finally { $previousV34Sha.Dispose() }
        if ($catalogHash -cne $previousV34Hash) {
            throw 'Privacy v3.4 recovery catalog no longer reproduces its pinned semantic hash'
        }
    }
    elseif ($PreviousV33) {
        $previousHash = '9f46fbd428cd4922290c8644fff25bebec88cb8a531604c69d430bb1a5398e9a'
        $previousDocument = [ordered]@{
            RemoveApps = @($allRemoveApps | Sort-Object)
            ProtectedApps = @($protectedApps | Sort-Object)
            Mappings = $normalizedMappings
        }
        $previousJson = ConvertTo-Json -InputObject $previousDocument -Compress -Depth 10
        $previousJson = $previousJson.Replace('&', '\u0026').Replace("'", '\u0027').Replace('<', '\u003c').Replace('>', '\u003e')
        $previousSha = [Security.Cryptography.SHA256]::Create()
        try {
            $catalogHash = ([BitConverter]::ToString($previousSha.ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($previousJson)))).Replace('-', '').ToLowerInvariant()
        }
        finally { $previousSha.Dispose() }
        if ($catalogHash -cne $previousHash) {
            throw 'Privacy v3.3 recovery catalog no longer reproduces its pinned semantic hash'
        }
    }
    elseif ($PreCopilot) {
        $legacyHash = 'd49968d0b86d8a03b8c52582b59e067a169971c92a3f39ebff11ce49453f19f3'
        $removeApps = @($removeApps | Where-Object { $_ -cne 'Microsoft.Copilot' })
        $allRemoveApps = @($removeApps + $optionalRemoveApps)
        $legacyMappings = [ordered]@{}
        foreach ($appName in @($allRemoveApps | Sort-Object)) {
            $legacyMappings[$appName] = $normalizedMappings[$appName]
        }
        $legacyDocument = [ordered]@{
            RemoveApps = @($allRemoveApps | Sort-Object)
            ProtectedApps = @($protectedApps | Sort-Object)
            Mappings = $legacyMappings
        }
        $legacyJson = ConvertTo-Json -InputObject $legacyDocument -Compress -Depth 10
        $legacyJson = $legacyJson.Replace('&', '\u0026').Replace("'", '\u0027').Replace('<', '\u003c').Replace('>', '\u003e')
        $legacySha = [Security.Cryptography.SHA256]::Create()
        try {
            $catalogHash = ([BitConverter]::ToString($legacySha.ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($legacyJson)))).Replace('-', '').ToLowerInvariant()
        }
        finally { $legacySha.Dispose() }
        if ($catalogHash -cne $legacyHash) {
            throw 'Privacy pre-Copilot recovery catalog no longer reproduces its pinned semantic hash'
        }
        $normalizedMappings = $legacyMappings
    }

    return [PSCustomObject]@{
        RemoveApps = $removeApps
        OptionalRemoveApps = [PSCustomObject]@{ WeatherWidget = $weatherWidgetApp }
        AllRemoveApps = $allRemoveApps
        ProtectedApps = $protectedApps
        Mappings = [PSCustomObject]$normalizedMappings
        CatalogSha256 = $catalogHash
        Contract = if ($PreCopilot) { 'PreCopilotV32' } elseif ($PreviousV33) { 'PreviousV33' } elseif ($PreviousV34) { 'PreviousV34' } else { 'CurrentV35' }
    }
}
