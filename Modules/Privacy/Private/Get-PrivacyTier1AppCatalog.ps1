#Requires -Version 5.1

function Get-PrivacyTier1AppCatalog {
    <#
    .SYNOPSIS
        Binds Tier 1 policy identifiers to verified package/Store identities.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$LegacyV225,

        [Parameter(Mandatory = $false)]
        [switch]$PreCopilot,

        [Parameter(Mandatory = $false)]
        [switch]$PreviousV33
    )

    if (@(@($LegacyV225, $PreCopilot, $PreviousV33) | Where-Object { $_ }).Count -gt 1) {
        throw 'Tier 1 app catalog accepts only one legacy contract selector'
    }
    $bloatware = if ($PreviousV33) {
        Get-PrivacyBloatwareConfig -PreviousV33
    }
    else {
        Get-PrivacyBloatwareConfig -PreCopilot:($LegacyV225 -or $PreCopilot)
    }
    if ($LegacyV225) {
        $policy = Get-PrivacyTier1LegacyV225PolicyDefinition
        $policyToPackage = [ordered]@{
            BingNews                 = 'Microsoft.BingNews'
            MicrosoftSolitaireCollection = 'Microsoft.MicrosoftSolitaireCollection'
            MicrosoftStickyNotes    = 'Microsoft.MicrosoftStickyNotes'
            BingWeather              = 'Microsoft.BingWeather'
            GamingApp                = 'Microsoft.GamingApp'
            XboxGamingOverlay        = 'Microsoft.XboxGamingOverlay'
            XboxIdentityProvider     = 'Microsoft.XboxIdentityProvider'
            XboxSpeechToTextOverlay  = 'Microsoft.XboxSpeechToTextOverlay'
            XboxTCUI                 = 'Microsoft.Xbox.TCUI'
        }
    }
    elseif ($PreCopilot) {
        $policy = Get-PrivacyTier1PreCopilotPolicyDefinition
        $policyToPackage = [ordered]@{
            BingNews                 = 'Microsoft.BingNews'
            MicrosoftSolitaireCollection = 'Microsoft.MicrosoftSolitaireCollection'
            BingWeather              = 'Microsoft.BingWeather'
            GamingApp                = 'Microsoft.GamingApp'
            XboxIdentityProvider     = 'Microsoft.XboxIdentityProvider'
            XboxSpeechToTextOverlay  = 'Microsoft.XboxSpeechToTextOverlay'
            XboxTCUI                 = 'Microsoft.Xbox.TCUI'
        }
    }
    else {
        $policy = Get-PrivacyTier1PolicyDefinition
        $policyToPackage = [ordered]@{
            Copilot                  = 'Microsoft.Copilot'
            BingNews                 = 'Microsoft.BingNews'
            MicrosoftSolitaireCollection = 'Microsoft.MicrosoftSolitaireCollection'
            BingWeather              = 'Microsoft.BingWeather'
            GamingApp                = 'Microsoft.GamingApp'
            XboxIdentityProvider     = 'Microsoft.XboxIdentityProvider'
            XboxSpeechToTextOverlay  = 'Microsoft.XboxSpeechToTextOverlay'
            XboxTCUI                 = 'Microsoft.Xbox.TCUI'
        }
    }

    $removalTargets = @($policy.RemovalTargets)
    $removalIds = @($removalTargets | ForEach-Object { [string]$_.PolicyId })
    if ($removalTargets.Count -ne $policyToPackage.Count -or
        @($removalIds | Where-Object { -not $policyToPackage.Contains($_) }).Count -gt 0 -or
        @($policyToPackage.Keys | Where-Object { $_ -notin $removalIds }).Count -gt 0) {
        throw 'Tier 1 app restore catalog does not exactly cover the selected policy removal targets'
    }

    $apps = [System.Collections.Generic.List[object]]::new()
    foreach ($target in $removalTargets) {
        $path = [string]$target.Path
        $policyId = [string]$target.PolicyId
        $packageFamilyName = if ($LegacyV225) { $null } else { [string]$target.PackageFamilyName }
        if ([string]::IsNullOrWhiteSpace($policyId)) {
            throw "Tier 1 removal target has no policy ID: $path"
        }
        if ($LegacyV225) {
            if ($path.Substring($path.LastIndexOf([char]'\') + 1) -cne $policyId) {
                throw "Legacy Tier 1 removal target has an invalid symbolic-ID binding: $path"
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($packageFamilyName) -or
            $path.Substring($path.LastIndexOf([char]'\') + 1) -cne $packageFamilyName) {
            throw "Tier 1 removal target has an invalid policy/PFN binding: $path"
        }
        $appName = [string]$policyToPackage[$policyId]
        if ($appName -notin $bloatware.RemoveApps) {
            throw "Tier 1 app restore mapping is outside the verified removal catalog: $policyId -> $appName"
        }
        $mapping = $bloatware.Mappings.$appName
        $apps.Add([PSCustomObject]@{
                PolicyId = $policyId
                PackageFamilyName = $packageFamilyName
                AppName = $appName
                StoreId = [string]$mapping.StoreId
                ExpectedPackageNames = @($mapping.ExpectedPackageNames | ForEach-Object { [string]$_ })
                PolicyPath = $path
                PolicyName = [string]$target.Name
                PolicyType = [string]$target.Type
                PolicyValue = [int]$target.Value
            })
    }
    if (@($apps.AppName | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        throw 'Tier 1 app restore catalog contains duplicate package identities'
    }

    $normalized = if ($LegacyV225) {
        @($apps | Sort-Object PolicyId | ForEach-Object {
                [ordered]@{
                    PolicyId = [string]$_.PolicyId
                    AppName = [string]$_.AppName
                    PolicyPath = [string]$_.PolicyPath
                    PolicyName = [string]$_.PolicyName
                    PolicyType = [string]$_.PolicyType
                    PolicyValue = [int]$_.PolicyValue
                }
            })
    }
    else {
        @($apps | Sort-Object PolicyId | ForEach-Object {
                [ordered]@{
                    PolicyId = [string]$_.PolicyId
                    PackageFamilyName = [string]$_.PackageFamilyName
                    AppName = [string]$_.AppName
                    PolicyPath = [string]$_.PolicyPath
                    PolicyName = [string]$_.PolicyName
                    PolicyType = [string]$_.PolicyType
                    PolicyValue = [int]$_.PolicyValue
                }
            })
    }
    $json = ConvertTo-Json -InputObject $normalized -Compress -Depth 8
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $policyHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    return [PSCustomObject]@{
        Contract = if ($LegacyV225) { 'LegacyV225' } elseif ($PreCopilot) { 'PreCopilotPFN' } elseif ($PreviousV33) { 'PreviousV33PFN' } else { 'CurrentPFN' }
        Apps = @($apps)
        PolicySha256 = $policyHash
        CatalogSha256 = [string]$bloatware.CatalogSha256
    }
}
