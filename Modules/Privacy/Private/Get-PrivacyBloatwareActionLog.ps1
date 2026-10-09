#Requires -Version 5.1

function Get-PrivacyBloatwareActionLog {
    <#
    .SYNOPSIS
        Captures a complete, catalog-bound pre-removal Tier 2 inventory.

    .DESCRIPTION
        Enumeration failures abort backup. Nothing unreadable is converted into
        NotPresent or not provisioned. This inventory records package identities
        needed for audit and best-effort reinstall; it is not an exact copy of app
        data, licenses, dependencies, or provisioning payloads.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeWeatherWidget = $false
    )

    $config = Get-PrivacyBloatwareConfig
    $userSid = (Get-PrivacyUserContext).Sid
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)

    $entries = [System.Collections.Generic.List[object]]::new()
    $selectedApps = @($config.RemoveApps)
    if ($IncludeWeatherWidget) {
        $selectedApps += [string]$config.OptionalRemoveApps.WeatherWidget
    }
    foreach ($appName in $selectedApps) {
        $mapping = $config.Mappings.$appName
        $provisionedNames = @($provisioned | Where-Object { [string]$_.DisplayName -eq $appName } |
                ForEach-Object { [string]$_.PackageName } | Sort-Object -Unique)
        # Store-delivered apps are commonly represented by both a Main package
        # and its parent Bundle. Removing the Main identity for another user can
        # return without error while leaving the bundle registration intact.
        # Seal the exact parent Bundle when one exists; otherwise seal the Main
        # package. Resource packages are deliberately outside this query.
        $packages = @(Get-AppxPackage -Name $appName -User $userSid `
                -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
        $bundlePackages = @($packages | Where-Object {
                $_.PSObject.Properties['IsBundle'] -and [bool]$_.IsBundle
            })
        $removablePackages = @()
        if ($bundlePackages.Count -gt 0) { $removablePackages = @($bundlePackages) }
        else { $removablePackages = @($packages) }
        if ($removablePackages.Count -eq 0) {
            $entries.Add([PSCustomObject]@{
                    AppName = $appName; Present = $false
                    PackageFullName = $null; PackageFamilyName = $null; Version = $null
                    ProvisionedPackageNames = $provisionedNames
                    StoreId = [string]$mapping.StoreId
                    ExpectedPackageNames = @($mapping.ExpectedPackageNames)
                })
            continue
        }

        foreach ($package in $removablePackages) {
            $entries.Add([PSCustomObject]@{
                    AppName = $appName; Present = $true
                    PackageFullName = [string]$package.PackageFullName
                    PackageFamilyName = [string]$package.PackageFamilyName
                    Version = [string]$package.Version
                    ProvisionedPackageNames = $provisionedNames
                    StoreId = [string]$mapping.StoreId
                    ExpectedPackageNames = @($mapping.ExpectedPackageNames)
                })
        }
    }

    $entryArray = @($entries)
    return [PSCustomObject]@{
        SchemaVersion = 3
        Mode = 'standard'
        WeatherWidgetRemovalSelected = $IncludeWeatherWidget
        InteractiveUserSid = $userSid
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        CatalogSha256 = [string]$config.CatalogSha256
        InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entryArray
        Entries = $entryArray
    }
}
