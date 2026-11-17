#Requires -Version 5.1

function Get-PrivacyTier1AppInventory {
    <#
    .SYNOPSIS
        Captures the original user's pre-policy state for Tier 1 removal apps.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $catalog = Get-PrivacyTier1AppCatalog
    $userSid = [string](Get-PrivacyUserContext).Sid
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($app in @($catalog.Apps)) {
        $provisionedNames = @($provisioned | Where-Object { [string]$_.DisplayName -eq [string]$app.AppName } |
                ForEach-Object { [string]$_.PackageName } | Sort-Object -Unique)
        $packages = @(Get-AppxPackage -Name ([string]$app.AppName) -User $userSid -ErrorAction Stop)
        if ($packages.Count -eq 0) {
            $entries.Add([PSCustomObject]@{
                    AppName = [string]$app.AppName; Present = $false
                    PackageFullName = $null; PackageFamilyName = $null; Version = $null
                    ProvisionedPackageNames = $provisionedNames
                    StoreId = [string]$app.StoreId
                    ExpectedPackageNames = @($app.ExpectedPackageNames)
                })
            continue
        }
        foreach ($package in $packages) {
            $entries.Add([PSCustomObject]@{
                    AppName = [string]$app.AppName; Present = $true
                    PackageFullName = [string]$package.PackageFullName
                    PackageFamilyName = [string]$package.PackageFamilyName
                    Version = [string]$package.Version
                    ProvisionedPackageNames = $provisionedNames
                    StoreId = [string]$app.StoreId
                    ExpectedPackageNames = @($app.ExpectedPackageNames)
                })
        }
    }

    $entryArray = @($entries)
    return [PSCustomObject]@{
        SchemaVersion = 1
        Mode = 'tier1-policy'
        InteractiveUserSid = $userSid
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        PolicySha256 = [string]$catalog.PolicySha256
        CatalogSha256 = [string]$catalog.CatalogSha256
        InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entryArray
        Entries = $entryArray
    }
}
