#Requires -Version 5.1

function Get-EdgePolicyTargets {
    <#
    .SYNOPSIS
        Load and validate the canonical Edge policy target inventory.

    .DESCRIPTION
        Treats the v139 baseline manifest and the parsed policy data as one
        fail-closed contract. The LGPO **delvals. row is validated as metadata
        but never returned as a registry value target.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$EdgePoliciesPath,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$RuntimeApplicability,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$EdgeInstallationStatus,

        [Parameter(Mandatory = $false)]
        [switch]$LegacyV225
    )

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($EdgePoliciesPath)) {
        $EdgePoliciesPath = Join-Path $moduleRoot 'Config\EdgePolicies.json'
    }
    $summaryPath = Join-Path $moduleRoot 'Config\Summary.json'

    foreach ($requiredFile in @($EdgePoliciesPath, $summaryPath)) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf -ErrorAction Stop)) {
            throw "Required Edge configuration file is missing: $requiredFile"
        }
    }

    # Do not wrap ConvertFrom-Json in @(): Windows PowerShell 5.1 would retain
    # the top-level JSON array as one nested Object[] entry.
    $policies = Get-Content -LiteralPath $EdgePoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $summary = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    foreach ($property in @(
            'SchemaVersion', 'BaselineVersion', 'OfficialPackage', 'MicrosoftBaselinePolicyCount',
            'PrivacyAdditionPolicyCount', 'ManagedPolicyCount', 'MetadataEntryCount',
            'DefaultSelectedPolicyCount', 'StrictSelectedPolicyCount',
            'LegacyV225ManagedPolicyCount', 'LegacyV225DefaultSelectedPolicyCount',
            'LegacyV225StrictSelectedPolicyCount', 'LegacyV225ExcludedPolicyNames',
            'MicrosoftBaselinePolicyNames', 'PrivacyAdditionPolicyNames',
            'MinimumEdgeMajorByPolicy', 'ManagedWindowsOnlyPolicies', 'MetadataEntry',
            'PolicyPaths', 'Sources', 'IntentionalDeviations'
        )) {
        if (-not $summary.PSObject.Properties[$property]) {
            throw "Edge summary is missing '$property'"
        }
    }
    if ([int]$summary.SchemaVersion -ne 2 -or [string]$summary.BaselineVersion -ne 'Microsoft Edge v139') {
        throw 'Edge summary schema or baseline version is unsupported'
    }
    if ([string]$summary.OfficialPackage.FileName -ne 'Microsoft Edge v139 Security Baseline.zip' -or
        [int64]$summary.OfficialPackage.SizeBytes -ne 400613 -or
        [string]$summary.OfficialPackage.Sha256 -cne 'ac54ff9ccb9e86c4f65d8be7968e499f2ed1f9daa4aecb6294f429141c943e3f' -or
        [string]::IsNullOrWhiteSpace([string]$summary.OfficialPackage.DownloadPage)) {
        throw 'Edge official-package provenance is missing or invalid'
    }

    $allowedPaths = @($summary.PolicyPaths | ForEach-Object { [string]$_ })
    if ($allowedPaths.Count -ne 2 -or
        'HKLM:\Software\Policies\Microsoft\Edge' -notin $allowedPaths -or
        'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -notin $allowedPaths) {
        throw 'Edge summary policy paths do not match the exact module allowlist'
    }

    $baselineNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($summary.MicrosoftBaselinePolicyNames)) {
        if ([string]::IsNullOrWhiteSpace([string]$name) -or -not $baselineNames.Add([string]$name)) {
            throw "Edge baseline name inventory contains an invalid duplicate: $name"
        }
    }
    $privacyNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($summary.PrivacyAdditionPolicyNames)) {
        if ([string]::IsNullOrWhiteSpace([string]$name) -or
            $baselineNames.Contains([string]$name) -or
            -not $privacyNames.Add([string]$name)) {
            throw "Edge privacy-addition inventory contains an invalid or overlapping name: $name"
        }
    }
    if ($baselineNames.Count -ne [int]$summary.MicrosoftBaselinePolicyCount -or
        $privacyNames.Count -ne [int]$summary.PrivacyAdditionPolicyCount -or
        $baselineNames.Count + $privacyNames.Count -ne [int]$summary.ManagedPolicyCount) {
        throw 'Edge summary policy counts do not match the declared name inventories'
    }

    $legacyExcludedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($summary.LegacyV225ExcludedPolicyNames)) {
        if (-not $privacyNames.Contains([string]$name) -or -not $legacyExcludedNames.Add([string]$name)) {
            throw "Edge legacy v2.2.5 exclusion inventory contains an invalid duplicate or unknown privacy name: $name"
        }
    }
    if ($legacyExcludedNames.Count -ne 3 -or
        [int]$summary.LegacyV225ManagedPolicyCount -ne
            ([int]$summary.ManagedPolicyCount - $legacyExcludedNames.Count) -or
        [int]$summary.LegacyV225DefaultSelectedPolicyCount -ne
            ([int]$summary.DefaultSelectedPolicyCount - $legacyExcludedNames.Count) -or
        [int]$summary.LegacyV225StrictSelectedPolicyCount -ne
            ([int]$summary.StrictSelectedPolicyCount - $legacyExcludedNames.Count)) {
        throw 'Edge legacy v2.2.5 inventory does not reconcile with the current canonical inventory'
    }

    $managedOnly = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($summary.ManagedWindowsOnlyPolicies)) {
        if (-not $baselineNames.Contains([string]$name) -or -not $managedOnly.Add([string]$name)) {
            throw "Edge managed-Windows inventory contains an invalid duplicate or unknown name: $name"
        }
    }
    if ($RuntimeApplicability) {
        foreach ($property in @(
                'SchemaVersion', 'EditionFamily', 'OperatingSystemSKU', 'EditionID',
                'DomainJoined', 'MdmRegistered', 'MdmEditionEligible',
                'ManagedWindowsEligible', 'EvidenceSource'
            )) {
            if (-not $RuntimeApplicability.PSObject.Properties[$property]) {
                throw "Edge runtime applicability is missing '$property'"
            }
        }
        if ([int]$RuntimeApplicability.SchemaVersion -ne 1 -or
            $RuntimeApplicability.DomainJoined -isnot [bool] -or
            $RuntimeApplicability.MdmRegistered -isnot [bool] -or
            $RuntimeApplicability.MdmEditionEligible -isnot [bool] -or
            $RuntimeApplicability.ManagedWindowsEligible -isnot [bool]) {
            throw 'Edge runtime applicability has an invalid schema or Boolean state'
        }
    }
    if ($EdgeInstallationStatus) {
        foreach ($property in @('Installed', 'Path', 'Version', 'Major')) {
            if (-not $EdgeInstallationStatus.PSObject.Properties[$property]) {
                throw "Edge installation status is missing '$property'"
            }
        }
        if ($EdgeInstallationStatus.Installed -isnot [bool]) {
            throw 'Edge installation status has a non-Boolean Installed state'
        }
        if ([bool]$EdgeInstallationStatus.Installed) {
            [version]$parsedVersion = $null
            if ([string]::IsNullOrWhiteSpace([string]$EdgeInstallationStatus.Path) -or
                [string]::IsNullOrWhiteSpace([string]$EdgeInstallationStatus.Version) -or
                -not [version]::TryParse([string]$EdgeInstallationStatus.Version, [ref]$parsedVersion) -or
                [int]$EdgeInstallationStatus.Major -ne [int]$parsedVersion.Major) {
                throw 'Installed Edge status has inconsistent path, version or major fields'
            }
        }
        elseif ($null -ne $EdgeInstallationStatus.Path -or
            $null -ne $EdgeInstallationStatus.Version -or
            $null -ne $EdgeInstallationStatus.Major) {
            throw 'Absent Edge status must have null path, version and major fields'
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenManagedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $targets = [System.Collections.Generic.List[object]]::new()
    $metadataCount = 0

    foreach ($policy in $policies) {
        foreach ($property in @('KeyName', 'ValueName', 'Type', 'Data')) {
            if (-not $policy.PSObject.Properties[$property]) {
                throw "Edge policy entry is missing '$property'"
            }
        }

        $relativeKey = ([string]$policy.KeyName).Trim()
        if ($relativeKey -notmatch '^\[Software\\Policies\\Microsoft\\Edge(?:\\ExtensionInstallBlocklist)?$') {
            throw "Edge policy key is outside the exact allowlist: $relativeKey"
        }
        $path = 'HKLM:\' + $relativeKey.Substring(1)
        $name = [string]$policy.ValueName
        if ([string]::IsNullOrWhiteSpace($name) -or -not $seen.Add("$path`0$name")) {
            throw "Edge policy target is empty or duplicated: $path::$name"
        }

        if ($name -match '^\*\*delvals') {
            $metadataCount++
            if ($name -cne [string]$summary.MetadataEntry.Name -or
                $path -cne [string]$summary.MetadataEntry.Path -or
                [string]$policy.Type -ne 'REG_SZ') {
                throw 'Edge GPO metadata row does not match the single declared **delvals. marker'
            }
            continue
        }

        $origin = if ($baselineNames.Contains($name)) { 'MicrosoftBaseline' }
        elseif ($privacyNames.Contains($name)) { 'NoIDPrivacy' }
        else { throw "Edge policy is not classified as baseline or privacy addition: $path::$name" }

        if (-not $seenManagedNames.Add($name)) {
            throw "Edge managed policy names must be globally unique: $name"
        }
        if ($name -eq '1' -and $path -cne 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist') {
            throw 'The numeric Edge blocklist value is bound to the wrong key'
        }
        if ($name -ne '1' -and $path -cne 'HKLM:\Software\Policies\Microsoft\Edge') {
            throw "Edge root policy is bound to the wrong key: $path::$name"
        }

        $minimumProperty = $summary.MinimumEdgeMajorByPolicy.PSObject.Properties[$name]
        if (-not $minimumProperty -or [int]$minimumProperty.Value -lt 77) {
            throw "Edge policy has no valid documented minimum major version: $name"
        }

        $type = switch ([string]$policy.Type) {
            'REG_DWORD' {
                if ($policy.Data -isnot [byte] -and $policy.Data -isnot [int16] -and
                    $policy.Data -isnot [int32] -and $policy.Data -isnot [int64]) {
                    throw "Edge DWord policy data is not an integer: $path::$name"
                }
                if ([int64]$policy.Data -lt [int]::MinValue -or [int64]$policy.Data -gt [int]::MaxValue) {
                    throw "Edge DWord policy data is outside the supported signed 32-bit range: $path::$name"
                }
                'DWord'
            }
            'REG_SZ' {
                if ($policy.Data -isnot [string]) {
                    throw "Edge String policy data is not a string: $path::$name"
                }
                'String'
            }
            'REG_EXPAND_SZ' {
                if ($policy.Data -isnot [string]) {
                    throw "Edge ExpandString policy data is not a string: $path::$name"
                }
                'ExpandString'
            }
            'REG_MULTI_SZ' {
                foreach ($item in @($policy.Data)) {
                    if ($item -isnot [string]) { throw "Edge MultiString contains a non-string: $path::$name" }
                }
                'MultiString'
            }
            'REG_BINARY' {
                foreach ($item in @($policy.Data)) {
                    if ([int]$item -lt 0 -or [int]$item -gt 255) { throw "Edge Binary contains a byte outside 0..255: $path::$name" }
                }
                'Binary'
            }
            default { throw "Unsupported Edge registry type '$($policy.Type)' for $path::$name" }
        }

        $value = switch ($type) {
            'DWord'       { [int]$policy.Data }
            'Binary'      { [byte[]]@($policy.Data) }
            'MultiString' { [string[]]@($policy.Data) }
            default       { [string]$policy.Data }
        }

        $requiresManagedWindows = $managedOnly.Contains($name)
        $managementApplicable = (-not $requiresManagedWindows -or -not $RuntimeApplicability -or
            [bool]$RuntimeApplicability.ManagedWindowsEligible)
        # Documented machine policies are safe to stage for an absent or older
        # Edge and will be consumed after the browser reaches their floor. A
        # residual old executable must never make controls for the current/new
        # installation disappear from the owned set.
        $applicable = $managementApplicable
        $notApplicableReasons = [System.Collections.Generic.List[string]]::new()
        if (-not $managementApplicable) {
            $notApplicableReasons.Add("Requires AD domain join or Pro/Enterprise MDM registration; detected $($RuntimeApplicability.EvidenceSource)/$($RuntimeApplicability.EditionFamily)")
        }
        $targets.Add([PSCustomObject]@{
                Path                       = $path
                Name                       = $name
                Type                       = $type
                Value                      = $value
                Origin                     = $origin
                MinimumEdgeMajor           = [int]$minimumProperty.Value
                RequiresManagedWindows     = $requiresManagedWindows
                ApplicabilityEvaluated     = ($null -ne $RuntimeApplicability -or $null -ne $EdgeInstallationStatus)
                Applicable                 = $applicable
                NotApplicableReason        = $(if ($applicable) { $null } else { @($notApplicableReasons) -join '; ' })
                Selected                   = -not ($AllowExtensions -and $name -eq '1')
            })
    }

    if ($metadataCount -ne [int]$summary.MetadataEntryCount -or
        $seenManagedNames.Count -ne [int]$summary.ManagedPolicyCount -or
        @($policies).Count -ne ($seenManagedNames.Count + $metadataCount)) {
        throw 'Edge parsed configuration count does not match the exact summary contract'
    }
    foreach ($name in @($baselineNames) + @($privacyNames)) {
        if (-not $seenManagedNames.Contains([string]$name)) {
            throw "Edge parsed configuration is missing declared policy '$name'"
        }
    }

    if ($LegacyV225) {
        $targets = @($targets | Where-Object { -not $legacyExcludedNames.Contains([string]$_.Name) })
    }
    $selected = @($targets | Where-Object { $_.Selected })
    $expectedSelected = if ($AllowExtensions) {
        if ($LegacyV225) { [int]$summary.LegacyV225DefaultSelectedPolicyCount }
        else { [int]$summary.DefaultSelectedPolicyCount }
    }
    else {
        if ($LegacyV225) { [int]$summary.LegacyV225StrictSelectedPolicyCount }
        else { [int]$summary.StrictSelectedPolicyCount }
    }
    $expectedManaged = if ($LegacyV225) { [int]$summary.LegacyV225ManagedPolicyCount }
    else { [int]$summary.ManagedPolicyCount }
    if ($selected.Count -ne $expectedSelected -or $targets.Count -ne $expectedManaged) {
        throw "Edge selected target count drift: selected=$($selected.Count), expected=$expectedSelected, managed=$($targets.Count)"
    }

    return $selected
}
