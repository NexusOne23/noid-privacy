#Requires -Version 5.1

function Restore-PrivacyRegistryState {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success  = $false
        Restored = 0
        Verified = 0
        FirewallRestored = 0
        FirewallRemoved = 0
        FirewallVerified = 0
        SearchRefresh = 'NotApplicable'
        Errors   = [System.Collections.Generic.List[string]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new()
        RetainedKeys = [System.Collections.Generic.List[string]]::new()
    }
    $mountedUserHives = [System.Collections.Generic.List[object]]::new()

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "Privacy registry-state backup not found: $BackupPath"
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-PrivacyRegistrySnapshot -Snapshot $snapshot -RestoreOnly
        $entries = @($snapshot.Entries)
        if ([int]$snapshot.SchemaVersion -notin @(2, 3, 4, 5, 6, 7) -or
            $entries.Count -eq 0 -or
            [int]$snapshot.TargetCount -ne $entries.Count) {
            throw 'Privacy registry-state backup has an invalid schema or target count'
        }
        $snapshotUserSids = @($entries | ForEach-Object {
                if ([string]$_.Path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') { $Matches[1] }
            } | Sort-Object -Unique)
        if ($snapshotUserSids.Count -gt 0 -and
            -not (Get-Command 'Resolve-NoIDRestoreUserHive' -ErrorAction SilentlyContinue)) {
            throw 'Core user-hive restore helper is unavailable'
        }
        # The machine-wide values never depend on the original user's hive.
        # Without it, HKLM is restored and that user's part is reported.
        foreach ($sid in $snapshotUserSids) {
            $userHive = Resolve-NoIDRestoreUserHive -Sid $sid
            if ($userHive.Available) {
                $mountedUserHives.Add($userHive.Mount)
                continue
            }
            if ($userHive.ProfileRemoved) {
                $result.Warnings.Add("The user profile HKU:\$sid no longer exists; its user values went with it. The machine-wide values were restored.")
            }
            else {
                $result.Errors.Add("User values in HKU:\$sid were not restored because the user hive could not be loaded: $($userHive.Message)")
            }
            $userPrefix = "HKU:\$sid\"
            $entries = @($entries | Where-Object {
                    -not ([string]$_.Path).StartsWith($userPrefix, [StringComparison]::OrdinalIgnoreCase)
                })
        }
        $restoredUserPrefixes = @($mountedUserHives | ForEach-Object { "HKU:\$($_.Sid)\" })

        $allowedMachinePaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput',
            'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting',
            'HKLM:\SOFTWARE\Policies\Microsoft\Dsh',
            'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice',
            'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search',
            'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive',
            'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
        )
        if (-not (Get-Command Get-PrivacyTier1Schema7RestorePolicyDefinition -ErrorAction SilentlyContinue) -or
            -not (Get-Command Get-PrivacyTier1LegacyV225RestorePolicyDefinition -ErrorAction SilentlyContinue)) {
            $definitionFile = [string]$MyInvocation.MyCommand.ScriptBlock.File
            if ([string]::IsNullOrWhiteSpace($definitionFile)) {
                throw 'Privacy restore helper source path is unavailable'
            }
            . (Join-Path (Split-Path -Parent $definitionFile) 'Get-PrivacyTier1RestorePolicyDefinitions.ps1')
        }
        $tier1Definition = Get-PrivacyTier1Schema7RestorePolicyDefinition
        $tier1LegacyDefinition = Get-PrivacyTier1LegacyV225RestorePolicyDefinition
        $tier1Identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($target in @($tier1Definition.Targets)) { $null = $tier1Identities.Add("$($target.Path)`0$($target.Name)") }
        foreach ($target in @($tier1LegacyDefinition.Targets)) { $null = $tier1Identities.Add("$($target.Path)`0$($target.Name)") }
        $allowedUserSuffixes = @(
            'Control Panel\International\User Profile',
            'SOFTWARE\Microsoft\InputPersonalization',
            'SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore',
            'SOFTWARE\Microsoft\Personalization\Settings',
            'Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo',
            'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
            'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
            'Software\Microsoft\Windows\CurrentVersion\Search',
            'Software\Microsoft\Windows\CurrentVersion\SearchSettings',
            'Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders',
            'Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications',
            'Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement',
            'Software\Policies\Microsoft\Windows\CloudContent',
            'Software\Policies\Microsoft\Windows\Explorer'
        )
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $keyExistence = @{}

        # Validate all targets and schema fields before the first mutation.
        foreach ($entry in $entries) {
            foreach ($requiredProperty in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
                if (-not $entry.PSObject.Properties[$requiredProperty]) {
                    throw "Privacy registry-state entry is missing '$requiredProperty'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([string]::IsNullOrWhiteSpace($path) -or
                [string]::IsNullOrWhiteSpace($name) -or
                -not $seenEntries.Add("$path`0$name")) {
                throw "Privacy registry-state contains an invalid or duplicate target: $path::$name"
            }
            $allowed = $path -in $allowedMachinePaths -or $tier1Identities.Contains("$path`0$name")
            if (-not $allowed -and $path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$') {
                $hiveRoot = "HKU:\$($Matches[1])"
                if (-not (Test-NoIDRegistryKey -LiteralPath $hiveRoot)) {
                    throw "Original Privacy user hive is not loaded: $hiveRoot"
                }
                $allowed = $Matches[2] -in $allowedUserSuffixes
            }
            if (-not $allowed) {
                throw "Refusing Privacy restore target outside the exact allowlist: $path::$name"
            }
            if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
                throw "Privacy entry claims an existing value in an originally absent key: $path::$name"
            }
            if ([bool]$entry.Exists -and [string]$entry.Type -notin @(
                    'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                )) {
                throw "Unsupported Privacy registry type '$($entry.Type)' for $path::$name"
            }
            $pathIdentity = $path.ToLowerInvariant()
            if ($keyExistence.ContainsKey($pathIdentity) -and
                [bool]$keyExistence[$pathIdentity].Existed -ne [bool]$entry.KeyExisted) {
                throw "Inconsistent Privacy key-existence prestate: $path"
            }
            if (-not $keyExistence.ContainsKey($pathIdentity)) {
                $keyExistence[$pathIdentity] = [PSCustomObject]@{ Path = $path; Existed = [bool]$entry.KeyExisted }
            }
        }

        # Newer snapshots seal the ancestor levels Apply created implicitly.
        # Fold them into the same existence map as the target keys: the
        # unowned-state pre-check below then refuses foreign drift inside them
        # before any mutation, and the deepest-first cleanup loop removes them
        # once empty - so an exact restore no longer leaves NoID-created empty
        # policy keys behind. Presence-gated and additive; sealed sessions
        # without the inventory keep their previous semantics.
        if ($snapshot.PSObject.Properties['AbsentAncestorKeys']) {
            foreach ($ancestorValue in @($snapshot.AbsentAncestorKeys)) {
                $ancestorPath = ([string]$ancestorValue).TrimEnd('\')
                if ($ancestorPath -match '(?i)^HKU:\\' -and
                    @($restoredUserPrefixes | Where-Object { $ancestorPath.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
                    continue
                }
                $ancestorIdentity = $ancestorPath.ToLowerInvariant()
                if ($keyExistence.ContainsKey($ancestorIdentity)) {
                    if ([bool]$keyExistence[$ancestorIdentity].Existed) {
                        throw "Privacy absent ancestor conflicts with a key the prestate saw existing: $ancestorPath"
                    }
                    continue
                }
                $keyExistence[$ancestorIdentity] = [PSCustomObject]@{ Path = $ancestorPath; Existed = $false }
            }
        }

        # Each owned value is written on its own: one failing value is
        # reported and never keeps the remaining values from their prestate.
        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-NoIDRegistryKey -LiteralPath ([string]$keyState.Path))) {
                try {
                    New-NoIDRegistryKey -LiteralPath ([string]$keyState.Path) | Out-Null
                    $result.Restored++
                }
                catch {
                    $result.Errors.Add("Could not recreate originally existing key $($keyState.Path): $($_.Exception.Message)")
                }
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            try {
                if ([bool]$entry.Exists) {
                    $value = $null
                    switch ([string]$entry.Type) {
                        'DWord'       { $value = [int]$entry.Value }
                        'QWord'       { $value = [long]$entry.Value }
                        'Binary'      { $value = [byte[]]@($entry.Value) }
                        'MultiString' { $value = [string[]]@($entry.Value) }
                        default       { $value = [string]$entry.Value }
                    }
                    New-ItemProperty -LiteralPath $path -Name $name -PropertyType ([string]$entry.Type) `
                        -Value $value -Force -ErrorAction Stop | Out-Null
                    $result.Restored++
                }
                elseif (Test-NoIDRegistryKey -LiteralPath $path) {
                    $key = Get-Item -LiteralPath $path -ErrorAction Stop
                    if ($key.GetValueNames() -contains $name) {
                        Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                        $result.Restored++
                    }
                }
            }
            catch {
                $result.Errors.Add("Could not restore $path::$name`: $($_.Exception.Message)")
            }
        }

        # An originally absent key is removed once it is empty. If it now holds
        # data this snapshot does not own (another program's policy, a value the
        # user added), it is kept and reported instead of destroying that data.
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cleanupPaths = @($keyExistence.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            try {
                if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { continue }
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $remainingValues = @($key.GetValueNames())
                if ($remainingValues.Count -eq 0 -and $key.SubKeyCount -eq 0) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    $result.Restored++
                    if (Test-NoIDRegistryKey -LiteralPath $path) {
                        throw 'the key still exists after removal'
                    }
                    continue
                }
                $foreignSubKeys = @($key.GetSubKeyNames() | Where-Object { -not $retainedKeys.Contains("$path\$_") })
                $null = $retainedKeys.Add($path)
                $result.RetainedKeys.Add($path)
                if ($remainingValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                    $result.Warnings.Add((Format-NoIDRetainedKeyNotice -Path $path `
                                -Values ([string[]]$remainingValues) -SubKeys ([string[]]$foreignSubKeys)))
                }
            }
            catch {
                $result.Errors.Add("Could not remove originally absent Privacy key $path`: $($_.Exception.Message)")
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            $valueExists = $false
            $actualValue = $null
            $actualType = $null
            if (Test-NoIDRegistryKey -LiteralPath $path) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $valueExists = $key.GetValueNames() -contains $name
                if ($valueExists) {
                    $actualValue = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $actualType = $key.GetValueKind($name).ToString()
                }
            }
            if ($valueExists -ne [bool]$entry.Exists) {
                $result.Errors.Add("Privacy value-existence verification failed: $path::$name")
                continue
            }
            if ($valueExists) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    $result.Errors.Add("Privacy type/value verification failed: $path::$name")
                    continue
                }
            }
            $keyExists = Test-NoIDRegistryKey -LiteralPath $path
            if ($keyExists -ne [bool]$entry.KeyExisted -and -not $retainedKeys.Contains($path)) {
                $result.Errors.Add("Privacy key-existence verification failed: $path")
                continue
            }
            $result.Verified++
        }

        if ([int]$snapshot.SchemaVersion -eq 7) {
            if (-not (Get-Command Restore-PrivacyAppxFirewallState -ErrorAction SilentlyContinue)) {
                $definitionFile = [string]$MyInvocation.MyCommand.ScriptBlock.File
                if ([string]::IsNullOrWhiteSpace($definitionFile)) {
                    throw 'Privacy restore helper source path is unavailable'
                }
                . (Join-Path (Split-Path -Parent $definitionFile) 'PrivacyAppxFirewall.ps1')
            }
            try {
                $firewallRestore = Restore-PrivacyAppxFirewallState -State $snapshot.AppxFirewallState -Scope All
                if (-not [bool]$firewallRestore.Success) {
                    throw 'Privacy AppX firewall collateral restore did not report success'
                }
                $result.FirewallRestored = [int]$firewallRestore.Restored
                $result.FirewallRemoved = [int]$firewallRestore.Removed
                $result.FirewallVerified = [int]$firewallRestore.Verified
            }
            catch {
                $result.Errors.Add($_.Exception.Message)
            }
        }

        # Notifying Windows only makes running apps pick the restored values up
        # now; they read them at the next sign-in regardless.
        try {
            $null = Send-PrivacySearchPolicyChangeNotification -Entries $entries
        }
        catch {
            $result.Warnings.Add("Windows was not notified of the restored Search settings ($($_.Exception.Message)); they take effect at the next sign-in.")
        }

        # Registry restore remains authoritative even when the original user is
        # logged off. If that user owns the current Explorer session, also call
        # Microsoft's per-user API with its already-restored effective value so
        # the visible Search surface refreshes immediately. A different/no
        # Explorer session is not a target and will load the exact registry
        # prestate normally on the original user's next sign-in.
        if ([int]$snapshot.SchemaVersion -eq 7) {
            $searchUser = Get-PrivacyUserContext -Refresh -AllowNone
            if ($null -eq $searchUser) {
                $result.SearchRefresh = 'DeferredNoInteractiveUser'
            }
            elseif ([string]$searchUser.Sid -cne [string]$snapshot.InteractiveUserSid) {
                $result.SearchRefresh = 'DeferredDifferentInteractiveUser'
            }
            else {
                # The registry prestate above is authoritative and verified. A
                # failed live refresh only delays the visible Search surface
                # until the next sign-in, like a logged-off original user.
                try {
                    $restoredSearchState = Invoke-PrivacyWindowsSearchUserState `
                        -User $searchUser -Operation Query
                    $searchRefresh = Invoke-PrivacyWindowsSearchUserState `
                        -User $searchUser `
                        -Operation RefreshWebResults `
                        -WebResultsEnabled ([bool]$restoredSearchState.WebResultsEnabled)
                    if (-not [bool]$searchRefresh.Success -or
                        [bool]$searchRefresh.WebResultsEnabled -ne [bool]$restoredSearchState.WebResultsEnabled -or
                        -not [bool]$searchRefresh.RegistryStateUnchanged) {
                        throw 'Restored WindowsSearch effective state did not refresh exactly'
                    }
                    $result.SearchRefresh = 'Verified'
                }
                catch {
                    $result.SearchRefresh = 'DeferredRefreshFailed'
                    $result.Warnings.Add("The Search box did not refresh live ($($_.Exception.Message)); the restored Search settings take effect at the next sign-in.")
                }
            }
        }

        $result.Success = ($result.Errors.Count -eq 0 -and $result.Verified -eq $entries.Count -and
            ([int]$snapshot.SchemaVersion -ne 7 -or
                $result.FirewallVerified -eq [int]$snapshot.AppxFirewallState.EntryCount))
    }
    catch {
        $result.Errors.Add($_.Exception.Message)
    }
    finally {
        Remove-Variable -Name key, registryKey -ErrorAction SilentlyContinue
        foreach ($mount in @($mountedUserHives | Sort-Object { [string]$_.Sid } -Descending)) {
            if (-not (Dismount-UserRegistryHiveAfterRestore -Mount $mount)) {
                $result.Errors.Add("Temporary Privacy user hive could not be unloaded: $($mount.Sid)")
                $result.Success = $false
            }
        }
    }
    return $result
}
