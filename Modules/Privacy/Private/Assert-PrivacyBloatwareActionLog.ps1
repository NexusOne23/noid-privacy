#Requires -Version 5.1

function Assert-PrivacyBloatwareActionLog {
    <#
    .SYNOPSIS
        Validates and binds a Tier 2 inventory to the canonical catalog and user.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ActionLog,

        [Parameter(Mandatory = $false)]
        [switch]$AllowLegacyNonReplayable
    )

    if ([int]$ActionLog.SchemaVersion -eq 1 -and $AllowLegacyNonReplayable) {
        if ([string]$ActionLog.Mode -cne 'standard' -or
            [string]$ActionLog.InteractiveUserSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or
            @($ActionLog.Entries).Count -eq 0) {
            throw 'Legacy Privacy bloatware action log is malformed'
        }
        foreach ($entry in @($ActionLog.Entries)) {
            foreach ($required in @('AppName','Present','PackageFullName','PackageFamilyName','Version','Provisioned','WingetId')) {
                if (-not $entry.PSObject.Properties[$required]) { throw "Legacy Privacy bloatware entry is missing '$required'" }
            }
        }
        return $true
    }
    $schemaVersion = [int]$ActionLog.SchemaVersion
    if ($schemaVersion -notin @(2, 3) -or [string]$ActionLog.Mode -cne 'standard') {
        throw 'Privacy bloatware action log has an unsupported schema or mode'
    }
    if ($schemaVersion -eq 3 -and
        (-not $ActionLog.PSObject.Properties['WeatherWidgetRemovalSelected'] -or
            $ActionLog.WeatherWidgetRemovalSelected -isnot [bool])) {
        throw 'Privacy schema-3 bloatware action log has an invalid Weather Widget decision'
    }
    if ([string]$ActionLog.InteractiveUserSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') {
        throw 'Privacy bloatware action log has an invalid interactive-user SID'
    }
    try {
        # Windows PowerShell 5.1 preserves ISO timestamps as strings while
        # PowerShell 7 ConvertFrom-Json materializes the same JSON token as a
        # DateTime. Validate the wire form exactly when it is still available;
        # a DateTime here is already the parser's representation of that token.
        if ($ActionLog.Timestamp -is [DateTime]) {
            $null = ([DateTime]$ActionLog.Timestamp).ToUniversalTime()
        }
        elseif ($ActionLog.Timestamp -is [string]) {
            $null = [DateTime]::ParseExact([string]$ActionLog.Timestamp, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        }
        else {
            throw 'Timestamp has an unsupported JSON type'
        }
    }
    catch { throw 'Privacy bloatware action log has an invalid timestamp' }
    if ([string]$ActionLog.CatalogSha256 -notmatch '^[a-f0-9]{64}$' -or
        [string]$ActionLog.InventorySha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'Privacy bloatware action log has an invalid catalog/inventory hash'
    }

    $currentConfig = Get-PrivacyBloatwareConfig
    $previousConfig = Get-PrivacyBloatwareConfig -PreviousV33
    $legacyConfig = Get-PrivacyBloatwareConfig -PreCopilot
    $config = if ([string]$ActionLog.CatalogSha256 -ceq [string]$currentConfig.CatalogSha256) {
        $currentConfig
    }
    elseif ([string]$ActionLog.CatalogSha256 -ceq [string]$legacyConfig.CatalogSha256) {
        $legacyConfig
    }
    elseif ([string]$ActionLog.CatalogSha256 -ceq [string]$previousConfig.CatalogSha256) {
        $previousConfig
    }
    else { $null }
    if ($null -eq $config) {
        throw 'Privacy bloatware action log is bound to a different removal/reinstall catalog'
    }
    $selectedApps = if ($schemaVersion -eq 2) {
        @($config.AllRemoveApps)
    }
    else {
        $apps = @($config.RemoveApps)
        if ([bool]$ActionLog.WeatherWidgetRemovalSelected) {
            $apps += [string]$config.OptionalRemoveApps.WeatherWidget
        }
        @($apps)
    }
    $entries = @($ActionLog.Entries)
    $seenPackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($appName in $selectedApps) {
        $appEntries = @($entries | Where-Object { [string]$_.AppName -eq $appName })
        if ($appEntries.Count -eq 0) { throw "Privacy bloatware action log is missing catalog app: $appName" }
        $mapping = $config.Mappings.$appName
        $presentStates = @($appEntries | ForEach-Object { [bool]$_.Present } | Select-Object -Unique)
        if ($presentStates.Count -ne 1 -or (-not $presentStates[0] -and $appEntries.Count -ne 1)) {
            throw "Privacy bloatware action log has an inconsistent absent/present inventory: $appName"
        }
        foreach ($entry in $appEntries) {
            foreach ($required in @('AppName','Present','PackageFullName','PackageFamilyName','Version','ProvisionedPackageNames','StoreId','ExpectedPackageNames')) {
                if (-not $entry.PSObject.Properties[$required]) { throw "Privacy bloatware entry is missing '$required': $appName" }
            }
            if ($entry.Present -isnot [bool] -or [string]$entry.StoreId -cne [string]$mapping.StoreId -or
                (@($entry.ExpectedPackageNames | Sort-Object) -join ([char]31)) -cne (@($mapping.ExpectedPackageNames | Sort-Object) -join ([char]31))) {
                throw "Privacy bloatware entry differs from the canonical mapping: $appName"
            }
            if ([bool]$entry.Present) {
                if ([string]::IsNullOrWhiteSpace([string]$entry.PackageFullName) -or
                    [string]::IsNullOrWhiteSpace([string]$entry.PackageFamilyName) -or
                    [string]::IsNullOrWhiteSpace([string]$entry.Version) -or
                    -not $seenPackages.Add([string]$entry.PackageFullName)) {
                    throw "Privacy bloatware entry has an invalid/duplicate present package identity: $appName"
                }
            }
            elseif ($null -ne $entry.PackageFullName -or $null -ne $entry.PackageFamilyName -or $null -ne $entry.Version) {
                throw "Privacy bloatware entry contains package identity while absent: $appName"
            }
            $provisionedNames = @($entry.ProvisionedPackageNames | ForEach-Object { [string]$_ })
            if (@($provisionedNames | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
                @($provisionedNames | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
                throw "Privacy bloatware entry has an invalid provisioned-package inventory: $appName"
            }
        }
    }
    if (@($entries | Where-Object { [string]$_.AppName -notin $selectedApps }).Count -gt 0) {
        throw 'Privacy bloatware action log contains an app outside the selected canonical removal catalog'
    }
    if ((Get-PrivacyBloatwareInventoryFingerprint -Entries $entries) -cne [string]$ActionLog.InventorySha256) {
        throw 'Privacy bloatware action log inventory hash does not match its contents'
    }
    return $true
}
