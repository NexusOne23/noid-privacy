#Requires -Version 5.1

function Get-PrivacyBloatwareInventoryFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entries
    )

    $normalized = @($Entries | Sort-Object AppName, PackageFullName | ForEach-Object {
            [ordered]@{
                AppName = [string]$_.AppName
                Present = [bool]$_.Present
                PackageFullName = if ($null -eq $_.PackageFullName) { $null } else { [string]$_.PackageFullName }
                PackageFamilyName = if ($null -eq $_.PackageFamilyName) { $null } else { [string]$_.PackageFamilyName }
                Version = if ($null -eq $_.Version) { $null } else { [string]$_.Version }
                ProvisionedPackageNames = @($_.ProvisionedPackageNames | ForEach-Object { [string]$_ } | Sort-Object)
                StoreId = [string]$_.StoreId
                ExpectedPackageNames = @($_.ExpectedPackageNames | ForEach-Object { [string]$_ } | Sort-Object)
            }
        })
    $json = ConvertTo-Json -InputObject $normalized -Compress -Depth 10
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}
