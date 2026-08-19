#Requires -Version 5.1

$script:PrivacyAppxFirewallRegistryPath =
    'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'

function Get-PrivacyAppxOrdinalUniqueStrings {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Values)

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $list = [Collections.Generic.List[string]]::new()
    foreach ($value in @($Values)) {
        $text = [string]$value
        if ($seen.Add($text)) { $list.Add($text) }
    }
    $result = $list.ToArray()
    [Array]::Sort($result, [StringComparer]::Ordinal)
    return $result
}

function Get-PrivacyAppxFirewallRuleField {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Data,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z][A-Za-z0-9]{1,15}$')][string]$Field
    )

    $prefix = $Field + '='
    $fieldMatches = @($Data.Split('|') | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($fieldMatches.Count -gt 1) { throw "AppX firewall rule contains duplicate '$Field' fields" }
    if ($fieldMatches.Count -eq 0) { return $null }
    return $fieldMatches[0].Substring($prefix.Length)
}

function Get-PrivacyAppxFirewallStateHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$State)

    $canonical = [ordered]@{
        SchemaVersion = [int]$State.SchemaVersion
        RegistryPath = [string]$State.RegistryPath
        KeyExisted = [bool]$State.KeyExisted
        PackageFamilyNames = @($State.PackageFamilyNames | ForEach-Object { [string]$_ })
        EntryCount = [int]$State.EntryCount
        Entries = @($State.Entries | ForEach-Object {
                [ordered]@{Name=[string]$_.Name;Type=[string]$_.Type;Data=[string]$_.Data}
            })
    }
    $json = ConvertTo-Json -InputObject $canonical -Depth 8 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
                $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))
            )).Replace('-','').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Assert-PrivacyAppxFirewallState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$ExpectedPackageFamilyNames
    )

    $expectedProperties = @(
        'SchemaVersion','RegistryPath','KeyExisted','PackageFamilyNames',
        'EntryCount','Entries','StateSha256'
    )
    $actualProperties = @($State.PSObject.Properties.Name)
    if ($actualProperties.Count -ne $expectedProperties.Count -or
        @(Compare-Object -ReferenceObject $expectedProperties -DifferenceObject $actualProperties).Count -ne 0 -or
        [int]$State.SchemaVersion -ne 1 -or
        [string]$State.RegistryPath -cne $script:PrivacyAppxFirewallRegistryPath -or
        $State.KeyExisted -isnot [bool]) {
        throw 'Privacy AppX firewall state has an invalid schema or registry binding'
    }

    $families = @($State.PackageFamilyNames | ForEach-Object { [string]$_ })
    $sortedFamilies = @(Get-PrivacyAppxOrdinalUniqueStrings -Values $families)
    if (($families -join ([char]31)) -cne ($sortedFamilies -join ([char]31)) -or
        @($families | Where-Object {
                $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,127}_[A-Za-z0-9]{5,32}$'
            }).Count -gt 0) {
        throw 'Privacy AppX firewall state contains invalid or unsorted package-family identities'
    }
    if ($null -ne $ExpectedPackageFamilyNames) {
        $expectedFamilies = @(Get-PrivacyAppxOrdinalUniqueStrings -Values @(
                $ExpectedPackageFamilyNames | ForEach-Object { [string]$_ }
            ))
        if (($families -join ([char]31)) -cne ($expectedFamilies -join ([char]31))) {
            throw 'Privacy AppX firewall state differs from the sealed package-family inventory'
        }
    }

    $familySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($family in $families) { $null = $familySet.Add($family) }
    $entries = @($State.Entries)
    if ([int]$State.EntryCount -ne $entries.Count -or
        (-not [bool]$State.KeyExisted -and $entries.Count -ne 0)) {
        throw 'Privacy AppX firewall state has an invalid entry/key count'
    }
    $seenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $lastName = $null
    foreach ($entry in $entries) {
        $properties = @($entry.PSObject.Properties.Name)
        if ($properties.Count -ne 3 -or
            @(Compare-Object -ReferenceObject @('Name','Type','Data') -DifferenceObject $properties).Count -ne 0) {
            throw 'Privacy AppX firewall entry has an invalid schema'
        }
        $name = [string]$entry.Name
        $data = [string]$entry.Data
        $family = Get-PrivacyAppxFirewallRuleField -Data $data -Field PFN
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 2048 -or
            [string]$entry.Type -cne 'String' -or [string]::IsNullOrWhiteSpace($data) -or
            [string]::IsNullOrWhiteSpace($family) -or -not $familySet.Contains($family) -or
            -not $seenNames.Add($name)) {
            throw 'Privacy AppX firewall entry is malformed, duplicated, or outside the sealed families'
        }
        if ($null -ne $lastName -and [string]::CompareOrdinal($lastName, $name) -ge 0) {
            throw 'Privacy AppX firewall entries are not strictly ordinal-sorted'
        }
        $lastName = $name
    }
    if ([string]$State.StateSha256 -notmatch '^[a-f0-9]{64}$' -or
        (Get-PrivacyAppxFirewallStateHash -State $State) -cne [string]$State.StateSha256) {
        throw 'Privacy AppX firewall state hash does not match its contents'
    }
    return $true
}

function Get-PrivacyAppxFirewallState {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$PackageFamilyNames)

    $families = @(Get-PrivacyAppxOrdinalUniqueStrings -Values @(
            $PackageFamilyNames | ForEach-Object { [string]$_ }
        ))
    $familySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($family in $families) {
        if ($family -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,127}_[A-Za-z0-9]{5,32}$') {
            throw "Unsupported Privacy AppX package-family identity: $family"
        }
        $null = $familySet.Add($family)
    }

    $keyExisted = Test-Path -LiteralPath $script:PrivacyAppxFirewallRegistryPath -PathType Container
    $entries = [Collections.Generic.List[object]]::new()
    if ($keyExisted -and $families.Count -gt 0) {
        $key = Get-Item -LiteralPath $script:PrivacyAppxFirewallRegistryPath -ErrorAction Stop
        $valueNames = [string[]]@($key.GetValueNames())
        [Array]::Sort($valueNames, [StringComparer]::Ordinal)
        foreach ($name in $valueNames) {
            $data = $key.GetValue(
                [string]$name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if ($null -eq $data) { continue }
            $family = Get-PrivacyAppxFirewallRuleField -Data ([string]$data) -Field PFN
            if ([string]::IsNullOrWhiteSpace($family) -or -not $familySet.Contains($family)) { continue }
            $type = $key.GetValueKind([string]$name).ToString()
            if ($type -cne 'String') {
                throw "Privacy AppX firewall rule has unsupported registry type '$type': $name"
            }
            $entries.Add([pscustomobject]@{Name=[string]$name;Type='String';Data=[string]$data})
        }
    }
    $state = [pscustomobject]@{
        SchemaVersion=1
        RegistryPath=$script:PrivacyAppxFirewallRegistryPath
        KeyExisted=[bool]$keyExisted
        PackageFamilyNames=$families
        EntryCount=$entries.Count
        Entries=@($entries)
        StateSha256=''
    }
    $state.StateSha256 = Get-PrivacyAppxFirewallStateHash -State $state
    $null = Assert-PrivacyAppxFirewallState -State $state -ExpectedPackageFamilyNames $families
    return $state
}

function Restore-PrivacyAppxFirewallState {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]$State,
        [ValidateSet('All','OtherUsers')][string]$Scope = 'All',
        [ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')][string]$TargetUserSid
    )

    $null = Assert-PrivacyAppxFirewallState -State $State
    if ($Scope -eq 'OtherUsers' -and [string]::IsNullOrWhiteSpace($TargetUserSid)) {
        throw 'OtherUsers AppX firewall restore requires the removed user SID'
    }
    $inScope = {
        param($Entry)
        if ($Scope -eq 'All') { return $true }
        $owner = Get-PrivacyAppxFirewallRuleField -Data ([string]$Entry.Data) -Field LUOwn
        return [string]$owner -cne $TargetUserSid
    }
    $expectedEntries = @($State.Entries | Where-Object { & $inScope $_ })
    $currentState = Get-PrivacyAppxFirewallState -PackageFamilyNames @($State.PackageFamilyNames)
    $currentEntries = @($currentState.Entries | Where-Object { & $inScope $_ })
    $expectedMap = @{}
    foreach ($entry in $expectedEntries) { $expectedMap[[string]$entry.Name] = $entry }
    $currentMap = @{}
    foreach ($entry in $currentEntries) { $currentMap[[string]$entry.Name] = $entry }
    $restored = 0
    $removed = 0

    if (-not (Test-Path -LiteralPath $script:PrivacyAppxFirewallRegistryPath -PathType Container)) {
        if ($expectedEntries.Count -eq 0) {
            return [pscustomobject]@{Success=$true;Restored=0;Removed=0;Verified=0;Scope=$Scope}
        }
        New-Item -Path $script:PrivacyAppxFirewallRegistryPath -Force -ErrorAction Stop | Out-Null
    }
    foreach ($entry in $currentEntries) {
        if (-not $expectedMap.ContainsKey([string]$entry.Name)) {
            Remove-ItemProperty -LiteralPath $script:PrivacyAppxFirewallRegistryPath `
                -Name ([string]$entry.Name) -ErrorAction Stop
            $removed++
        }
    }
    foreach ($entry in $expectedEntries) {
        $requiresWrite = -not $currentMap.ContainsKey([string]$entry.Name) -or
            [string]$currentMap[[string]$entry.Name].Name -cne [string]$entry.Name -or
            [string]$currentMap[[string]$entry.Name].Data -cne [string]$entry.Data
        if ($requiresWrite) {
            New-ItemProperty -LiteralPath $script:PrivacyAppxFirewallRegistryPath `
                -Name ([string]$entry.Name) -PropertyType String -Value ([string]$entry.Data) `
                -Force -ErrorAction Stop | Out-Null
            $restored++
        }
    }

    $verifiedState = Get-PrivacyAppxFirewallState -PackageFamilyNames @($State.PackageFamilyNames)
    $verifiedEntries = @($verifiedState.Entries | Where-Object { & $inScope $_ })
    $expectedJson = ConvertTo-Json -InputObject @($expectedEntries) -Depth 5 -Compress
    $actualJson = ConvertTo-Json -InputObject @($verifiedEntries) -Depth 5 -Compress
    if ($actualJson -cne $expectedJson) {
        throw "Privacy AppX firewall $Scope restore verification failed"
    }
    return [pscustomobject]@{
        Success=$true;Restored=$restored;Removed=$removed;Verified=$verifiedEntries.Count;Scope=$Scope
    }
}
