function Assert-AdvancedSecurityRegistrySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,

        [switch]$RestoreOnly
    )

    if ([int]$Snapshot.SchemaVersion -ne 5) {
        throw "Unsupported AdvancedSecurity registry snapshot schema: $($Snapshot.SchemaVersion)"
    }
    foreach ($property in @(
            'SkipFirewallLayer', 'DisableRDP', 'AdminSharesDisabled', 'DisableUPnP',
            'DisableWirelessDisplayCompletely', 'DisableDiscoveryProtocolsCompletely',
            'DisableIPv6Completely', 'EnableFirewallShieldsUp',
            'RdpHostSupported', 'ManagedPolicySupported', 'WirelessDisplaySupported'
        )) {
        if (-not $Snapshot.PSObject.Properties[$property] -or $Snapshot.$property -isnot [bool]) {
            throw "AdvancedSecurity registry snapshot has no Boolean decision '$property'"
        }
    }
    if (-not $Snapshot.PSObject.Properties['EditionFamily'] -or
        [string]$Snapshot.EditionFamily -notin @('Home', 'Professional', 'Enterprise', 'Education', 'IoTEnterprise')) {
        throw 'AdvancedSecurity registry snapshot has an invalid EditionFamily'
    }
    $expectedRdpSupport = [string]$Snapshot.EditionFamily -in @('Professional', 'Enterprise', 'Education')
    $expectedManagedPolicySupport = [string]$Snapshot.EditionFamily -in @('Professional', 'Enterprise', 'Education', 'IoTEnterprise')
    if ([bool]$Snapshot.RdpHostSupported -ne $expectedRdpSupport -or
        [bool]$Snapshot.ManagedPolicySupported -ne $expectedManagedPolicySupport -or
        [bool]$Snapshot.WirelessDisplaySupported -ne $expectedManagedPolicySupport) {
        throw 'AdvancedSecurity registry snapshot edition applicability is internally inconsistent'
    }
    $capturedAt = [DateTimeOffset]::MinValue
    if (-not $Snapshot.PSObject.Properties['CapturedAt'] -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$Snapshot.CapturedAt,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$capturedAt
        )) {
        throw 'AdvancedSecurity registry snapshot has an invalid CapturedAt timestamp'
    }

    if (-not $Snapshot.PSObject.Properties['WinInetUsers']) {
        throw 'AdvancedSecurity registry snapshot has no WinInetUsers inventory'
    }
    $winInetUsers = @($Snapshot.WinInetUsers)
    if ($winInetUsers.Count -gt 1) {
        throw 'AdvancedSecurity registry snapshot contains more than one current-session WinINet user'
    }
    $winInetSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $winInetUsers) {
        foreach ($property in @('Account', 'Sid', 'SessionId', 'AutoDetectEnabled')) {
            if (-not $user.PSObject.Properties[$property]) {
                throw "AdvancedSecurity WinINet prestate is missing '$property'"
            }
        }
        $sid = [string]$user.Sid
        if ([string]::IsNullOrWhiteSpace([string]$user.Account) -or
            $sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or
            [int]$user.SessionId -lt 1 -or
            $user.AutoDetectEnabled -isnot [bool] -or
            -not $winInetSids.Add($sid)) {
            throw 'AdvancedSecurity WinINet prestate contains an invalid or duplicate user state'
        }
    }

    $entries = @($Snapshot.Entries)
    if ($entries.Count -eq 0 -or [int]$Snapshot.TargetCount -ne $entries.Count) {
        throw 'AdvancedSecurity registry snapshot has an invalid target count'
    }
    $snapshotUserSids = @($entries | ForEach-Object {
            if ([string]$_.Path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') { $Matches[1] }
        } | Sort-Object -Unique)
    if ($snapshotUserSids.Count -ne 0) {
        throw 'AdvancedSecurity registry snapshot contains a user-hive target outside the machine registry contract'
    }

    $targetCommand = if ($RestoreOnly) {
        'Get-AdvancedSecuritySchema5RegistryTargets'
    }
    else {
        'Get-AdvancedSecurityRegistryTargets'
    }
    if (-not (Get-Command $targetCommand -ErrorAction SilentlyContinue)) {
        throw "Required AdvancedSecurity registry-target helper is unavailable: $targetCommand"
    }
    $targetParameters = @{
        SkipFirewallLayer                  = [bool]$Snapshot.SkipFirewallLayer
        DisableRDP                        = [bool]$Snapshot.DisableRDP
        AdminSharesDisabled               = [bool]$Snapshot.AdminSharesDisabled
        DisableWirelessDisplayCompletely  = [bool]$Snapshot.DisableWirelessDisplayCompletely
        DisableDiscoveryProtocolsCompletely = [bool]$Snapshot.DisableDiscoveryProtocolsCompletely
        DisableIPv6Completely             = [bool]$Snapshot.DisableIPv6Completely
        EnableFirewallShieldsUp            = [bool]$Snapshot.EnableFirewallShieldsUp
        RdpHostSupported                   = [bool]$Snapshot.RdpHostSupported
        ManagedPolicySupported             = [bool]$Snapshot.ManagedPolicySupported
        WirelessDisplaySupported           = [bool]$Snapshot.WirelessDisplaySupported
    }
    $expectedTargets = @(& $targetCommand @targetParameters)
    $expectedIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($target in $expectedTargets) {
        $null = $expectedIdentities.Add("$($target.Path)`0$([string]$target.Name)`0$([bool]$target.KeyOnly)")
    }
    if ($expectedIdentities.Count -ne $expectedTargets.Count) {
        throw 'Canonical AdvancedSecurity registry target schema contains duplicate identities'
    }

    $seenIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $keyExistence = @{}
    foreach ($entry in $entries) {
        foreach ($requiredProperty in @('Path', 'Name', 'KeyOnly', 'KeyExisted', 'Exists', 'Value', 'Type')) {
            if (-not $entry.PSObject.Properties[$requiredProperty]) {
                throw "AdvancedSecurity registry snapshot entry is missing '$requiredProperty'"
            }
        }
        foreach ($booleanProperty in @('KeyOnly', 'KeyExisted', 'Exists')) {
            if ($entry.$booleanProperty -isnot [bool]) {
                throw "AdvancedSecurity registry snapshot entry has non-Boolean '$booleanProperty'"
            }
        }
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $identity = "$path`0$name`0$([bool]$entry.KeyOnly)"
        if ([string]::IsNullOrWhiteSpace($path) -or
            -not $expectedIdentities.Contains($identity) -or
            -not $seenIdentities.Add($identity)) {
            throw "AdvancedSecurity registry snapshot contains an invalid or duplicate target: $path::$name"
        }
        if ([bool]$entry.KeyOnly) {
            if (-not [string]::IsNullOrEmpty($name) -or [bool]$entry.Exists -or
                $null -ne $entry.Value -or -not [string]::IsNullOrEmpty([string]$entry.Type)) {
                throw "AdvancedSecurity key-only entry contains value state: $path"
            }
        }
        else {
            if ([string]::IsNullOrWhiteSpace($name)) {
                throw "AdvancedSecurity value entry has no name: $path"
            }
            if ([bool]$entry.Exists) {
                if (-not [bool]$entry.KeyExisted -or [string]$entry.Type -notin @(
                        'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                    )) {
                    throw "AdvancedSecurity existing value state is invalid: $path::$name"
                }
                if ([string]$entry.Type -eq 'Binary' -and
                    @($entry.Value | Where-Object { [int64]$_ -lt 0 -or [int64]$_ -gt 255 }).Count -gt 0) {
                    throw "AdvancedSecurity binary value contains an invalid byte: $path::$name"
                }
            }
            elseif ($null -ne $entry.Value -or -not [string]::IsNullOrEmpty([string]$entry.Type)) {
                throw "AdvancedSecurity absent value contains data/type: $path::$name"
            }
        }

        $pathIdentity = $path.ToLowerInvariant()
        if ($keyExistence.ContainsKey($pathIdentity) -and
            [bool]$keyExistence[$pathIdentity].Existed -ne [bool]$entry.KeyExisted) {
            throw "AdvancedSecurity registry snapshot has inconsistent key existence: $path"
        }
        if (-not $keyExistence.ContainsKey($pathIdentity)) {
            $keyExistence[$pathIdentity] = [PSCustomObject]@{ Path=$path; Existed=[bool]$entry.KeyExisted }
        }
    }
    if ($seenIdentities.Count -ne $expectedIdentities.Count) {
        throw "AdvancedSecurity registry snapshot is incomplete: expected $($expectedIdentities.Count), found $($seenIdentities.Count)"
    }

    return [PSCustomObject]@{
        Entries       = $entries
        UserSids      = $snapshotUserSids
        WinInetUsers  = $winInetUsers
        KeyExistence  = $keyExistence
        TargetCount   = $seenIdentities.Count
    }
}
