#Requires -Version 5.1

# 2.2.5 to 2.2.9 removed the six Xbox apps when switching Xbox off. Since 2.3.0
# the switch removes no app; the recorded package inventory is still validated
# because it binds every measured state and its fingerprint.

function Assert-NoIDXboxAppInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    if ($Entries.Count -gt 100) { throw 'Xbox app inventory exceeds its bounded package count' }
    $catalog = Get-NoIDXboxComponentCatalog
    $allowed = @($catalog.Apps | Where-Object LegacyRemoveWhenDisabled)
    $packages = @(foreach ($entry in $Entries) {
        Assert-NoIDXboxObjectFields $entry @('AppName','PackageFullName','PackageFamilyName')
        if ($entry.AppName -isnot [string] -or $entry.PackageFullName -isnot [string] -or
            $entry.PackageFamilyName -isnot [string] -or $entry.AppName -cnotin @($allowed.Name)) {
            throw 'Xbox app inventory contains an app outside the six Xbox families'
        }
        [pscustomobject]@{
            Name=$entry.AppName;PackageFamilyName=$entry.PackageFamilyName;PackageFullName=$entry.PackageFullName
            IsBundle=($entry.PackageFullName -cmatch '_neutral_~_8wekyb3d8bbwe$')
        }
    })
    $parents = @(Get-NoIDXboxAppRemovalInventory -Packages $packages)
    if ($parents.Count -ne $Entries.Count) { throw 'Xbox app inventory contains a child package instead of its Bundle parent' }
}
