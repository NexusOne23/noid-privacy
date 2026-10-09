#Requires -Version 5.1

function Assert-PrivacyTier1AppInventory {
    <#
    .SYNOPSIS
        Validates a sealed Tier 1 app inventory against both current catalogs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Inventory
    )

    if ([int]$Inventory.SchemaVersion -ne 1 -or [string]$Inventory.Mode -cne 'tier1-policy') {
        throw 'Privacy Tier 1 app inventory has an unsupported schema or mode'
    }
    if ([string]$Inventory.InteractiveUserSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') {
        throw 'Privacy Tier 1 app inventory has an invalid interactive-user SID'
    }
    try {
        # Windows PowerShell 5.1 preserves ISO timestamps as strings while
        # PowerShell 7 ConvertFrom-Json materializes the same JSON token as a
        # DateTime. Validate the wire form exactly when it is still available;
        # a DateTime here is already the parser's representation of that token.
        if ($Inventory.Timestamp -is [DateTime]) {
            $null = ([DateTime]$Inventory.Timestamp).ToUniversalTime()
        }
        elseif ($Inventory.Timestamp -is [string]) {
            $null = [DateTime]::ParseExact([string]$Inventory.Timestamp, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        }
        else {
            throw 'Timestamp has an unsupported JSON type'
        }
    }
    catch { throw 'Privacy Tier 1 app inventory has an invalid timestamp' }
    foreach ($hashName in @('PolicySha256','CatalogSha256','InventorySha256')) {
        if ([string]$Inventory.$hashName -notmatch '^[a-f0-9]{64}$') {
            throw "Privacy Tier 1 app inventory has an invalid $hashName"
        }
    }

    $currentCatalog = Get-PrivacyTier1AppCatalog
    $previousCatalog = Get-PrivacyTier1AppCatalog -PreviousV33
    $preCopilotCatalog = Get-PrivacyTier1AppCatalog -PreCopilot
    $legacyCatalog = Get-PrivacyTier1AppCatalog -LegacyV225
    $catalog = if ([string]$Inventory.PolicySha256 -ceq [string]$currentCatalog.PolicySha256 -and
        [string]$Inventory.CatalogSha256 -ceq [string]$currentCatalog.CatalogSha256) {
        $currentCatalog
    }
    elseif ([string]$Inventory.PolicySha256 -ceq [string]$preCopilotCatalog.PolicySha256 -and
        [string]$Inventory.CatalogSha256 -ceq [string]$preCopilotCatalog.CatalogSha256) {
        $preCopilotCatalog
    }
    elseif ([string]$Inventory.PolicySha256 -ceq [string]$previousCatalog.PolicySha256 -and
        [string]$Inventory.CatalogSha256 -ceq [string]$previousCatalog.CatalogSha256) {
        $previousCatalog
    }
    elseif ([string]$Inventory.PolicySha256 -ceq [string]$legacyCatalog.PolicySha256 -and
        [string]$Inventory.CatalogSha256 -ceq [string]$legacyCatalog.CatalogSha256) {
        $legacyCatalog
    }
    else {
        $null
    }
    if ($null -eq $catalog) {
        throw 'Privacy Tier 1 app inventory is bound to a different policy or Store catalog'
    }

    $entries = @($Inventory.Entries)
    if ($entries.Count -lt @($catalog.Apps).Count) {
        throw 'Privacy Tier 1 app inventory does not cover the complete removal policy catalog'
    }
    $seenPackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($app in @($catalog.Apps)) {
        $appName = [string]$app.AppName
        $appEntries = @($entries | Where-Object { [string]$_.AppName -eq $appName })
        if ($appEntries.Count -eq 0) { throw "Privacy Tier 1 app inventory is missing policy app: $appName" }
        $presentStates = @($appEntries | ForEach-Object { [bool]$_.Present } | Select-Object -Unique)
        if ($presentStates.Count -ne 1 -or (-not $presentStates[0] -and $appEntries.Count -ne 1)) {
            throw "Privacy Tier 1 app inventory has an inconsistent absent/present state: $appName"
        }
        foreach ($entry in $appEntries) {
            foreach ($required in @('AppName','Present','PackageFullName','PackageFamilyName','Version','ProvisionedPackageNames','StoreId','ExpectedPackageNames')) {
                if (-not $entry.PSObject.Properties[$required]) { throw "Privacy Tier 1 app entry is missing '$required': $appName" }
            }
            if ($entry.Present -isnot [bool] -or [string]$entry.StoreId -cne [string]$app.StoreId -or
                (@($entry.ExpectedPackageNames | Sort-Object) -join ([char]31)) -cne (@($app.ExpectedPackageNames | Sort-Object) -join ([char]31))) {
                throw "Privacy Tier 1 app entry differs from the canonical mapping: $appName"
            }
            if ([bool]$entry.Present) {
                if ([string]::IsNullOrWhiteSpace([string]$entry.PackageFullName) -or
                    [string]::IsNullOrWhiteSpace([string]$entry.PackageFamilyName) -or
                    [string]::IsNullOrWhiteSpace([string]$entry.Version) -or
                    -not $seenPackages.Add([string]$entry.PackageFullName)) {
                    throw "Privacy Tier 1 app entry has an invalid/duplicate package identity: $appName"
                }
            }
            elseif ($null -ne $entry.PackageFullName -or $null -ne $entry.PackageFamilyName -or $null -ne $entry.Version) {
                throw "Privacy Tier 1 app entry contains package identity while absent: $appName"
            }
            $provisionedNames = @($entry.ProvisionedPackageNames | ForEach-Object { [string]$_ })
            if (@($provisionedNames | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
                @($provisionedNames | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
                throw "Privacy Tier 1 app entry has an invalid provisioned-package inventory: $appName"
            }
        }
    }
    if (@($entries | Where-Object { [string]$_.AppName -notin @($catalog.Apps.AppName) }).Count -gt 0) {
        throw 'Privacy Tier 1 app inventory contains an app outside the removal policy catalog'
    }
    if ((Get-PrivacyBloatwareInventoryFingerprint -Entries $entries) -cne [string]$Inventory.InventorySha256) {
        throw 'Privacy Tier 1 app inventory hash does not match its contents'
    }
    return $true
}
