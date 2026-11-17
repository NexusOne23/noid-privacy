#Requires -Version 5.1

function Restore-AntiAIRegistryState {
    <#
    .SYNOPSIS
        Restores and verifies the exact AntiAI registry prestate.

    .DESCRIPTION
        Restores value existence, type and unexpanded data as well as registry
        key existence. An originally absent key is removed once empty; one that
        still holds other settings (a later third-party, administrator or other
        NoID Privacy change) is kept and reported instead of deleting them.
        Without the original user's hive, the machine-wide values are still
        restored and that user's part is reported.
    #>
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
        Errors   = [System.Collections.Generic.List[string]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new()
        RetainedKeys = [System.Collections.Generic.List[string]]::new()
    }
    $mountedUserHives = [System.Collections.Generic.List[object]]::new()

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf -ErrorAction Stop)) {
            throw "AntiAI registry-state backup not found: $BackupPath"
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly
        $entries = @($snapshot.Entries)

        $snapshotUserSids = @($entries | ForEach-Object {
                if ([string]$_.Path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') { $Matches[1] }
            } | Sort-Object -Unique)
        if ($snapshotUserSids.Count -gt 0 -and
            -not (Get-Command 'Resolve-NoIDRestoreUserHive' -ErrorAction SilentlyContinue)) {
            throw 'Core user-hive restore helper is unavailable'
        }
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

        $allowedMachinePaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
            'HKLM:\SOFTWARE\Policies\Microsoft\Copilot',
            'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate',
            'HKLM:\SOFTWARE\Policies\Mxc',
            'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint',
            'HKLM:\SOFTWARE\Policies\WindowsNotepad'
        )
        $allowedUserSuffixes = @(
            'SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
            'Software\Policies\Microsoft\Windows\WindowsCopilot',
            # Schema-4 sessions may still own the legacy ShowCopilotButton value.
            'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
            'Software\Policies\Microsoft\Windows\CopilotKey',
            'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId',
            'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId'
        )
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $keyExistence = @{}
        $preparedValues = @{}

        # Validate the complete document before the first registry mutation.
        $deferredStartupEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) {
            foreach ($requiredProperty in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
                if (-not $entry.PSObject.Properties[$requiredProperty]) {
                    throw "AntiAI registry-state entry is missing '$requiredProperty'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([string]::IsNullOrWhiteSpace($path) -or
                [string]::IsNullOrWhiteSpace($name) -or
                -not $seenEntries.Add("$path`0$name")) {
                throw "AntiAI registry-state contains an invalid or duplicate target: $path::$name"
            }

            $allowed = $path -in $allowedMachinePaths
            if (-not $allowed -and $path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\(.+)$') {
                $hiveRoot = "HKU:\$($Matches[1])"
                if (-not (Test-NoIDRegistryKey -LiteralPath $hiveRoot)) {
                    throw "Original interactive user hive is not loaded for AntiAI restore: $hiveRoot"
                }
                $allowed = $Matches[2] -in $allowedUserSuffixes
                # HKU\SID\Software\Classes is the user's UsrClass.dat only while
                # Windows has the profile loaded. In an NTUSER.DAT mounted for
                # restore it is an unrelated key, so refuse before any change.
                # The other AntiAI values never depend on it and are still restored.
                if ($allowed -and $Matches[2].StartsWith('Software\Classes\', [StringComparison]::OrdinalIgnoreCase) -and
                    -not (Test-NoIDRegistryKey -LiteralPath "Registry::HKEY_USERS\$($Matches[1])_Classes")) {
                    $null = $deferredStartupEntries.Add("$path`0$name")
                    $result.Errors.Add("The Copilot app start-up setting was not restored because the user who applied AntiAI is not signed in; sign in as that user and run Restore again: $path::$name")
                }
            }
            if (-not $allowed) {
                throw "Refusing AntiAI restore target outside the exact allowlist: $path::$name"
            }
            if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
                throw "AntiAI entry claims an existing value in an originally absent key: $path::$name"
            }
            if ([bool]$entry.Exists -and [string]$entry.Type -notin @(
                    'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                )) {
                throw "Unsupported AntiAI registry value type '$($entry.Type)' for $path::$name"
            }

            $pathIdentity = $path.ToLowerInvariant()
            if ($keyExistence.ContainsKey($pathIdentity) -and
                [bool]$keyExistence[$pathIdentity].Existed -ne [bool]$entry.KeyExisted) {
                throw "Inconsistent AntiAI key-existence prestate: $path"
            }
            if (-not $keyExistence.ContainsKey($pathIdentity)) {
                $keyExistence[$pathIdentity] = [PSCustomObject]@{
                    Path    = $path
                    Existed = [bool]$entry.KeyExisted
                }
            }
            if ([bool]$entry.Exists) {
                $entryIdentity = "$path`0$name"
                $preparedValues[$entryIdentity] = [PSCustomObject]@{
                    Type = [string]$entry.Type
                    Value = switch ([string]$entry.Type) {
                        'DWord'       { [int]$entry.Value }
                        'QWord'       { [long]$entry.Value }
                        'Binary'      { [byte[]]@($entry.Value) }
                        'MultiString' { [string[]]@($entry.Value) }
                        default       { [string]$entry.Value }
                    }
                }
            }
        }

        if ($deferredStartupEntries.Count -gt 0) {
            $entries = @($entries | Where-Object { -not $deferredStartupEntries.Contains("$([string]$_.Path)`0$([string]$_.Name)") })
            foreach ($pathIdentity in @($keyExistence.Keys)) {
                if (@($entries | Where-Object { ([string]$_.Path).ToLowerInvariant() -eq $pathIdentity }).Count -eq 0) {
                    $keyExistence.Remove($pathIdentity)
                }
            }
        }

        # Recreate keys that existed even when they contained none of the owned
        # values. This preserves an originally empty key exactly. Each owned
        # value is written on its own: one failing value is reported and never
        # keeps the remaining values from their prestate.
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
                    $prepared = $preparedValues["$path`0$name"]
                    New-ItemProperty -LiteralPath $path -Name $name -PropertyType $prepared.Type `
                        -Value $prepared.Value -Force -ErrorAction Stop | Out-Null
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

        # Remove originally absent keys once empty. A key that still holds other
        # settings (for example Edge policies a later Edge session wrote) is
        # kept and reported instead of deleting them.
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $absentPaths = @($keyExistence.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $absentPaths) {
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
                $result.Errors.Add("Could not remove originally absent AntiAI key $path`: $($_.Exception.Message)")
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
                    $actualValue = $key.GetValue(
                        $name,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $actualType = $key.GetValueKind($name).ToString()
                }
            }
            if ($valueExists -ne [bool]$entry.Exists) {
                $result.Errors.Add("AntiAI value-existence verification failed: $path::$name")
                continue
            }
            if ($valueExists) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    $result.Errors.Add("AntiAI type/value verification failed: $path::$name")
                    continue
                }
            }
            $keyExists = Test-NoIDRegistryKey -LiteralPath $path
            if ($keyExists -ne [bool]$entry.KeyExisted -and -not $retainedKeys.Contains($path)) {
                $result.Errors.Add("AntiAI key-existence verification failed: $path")
                continue
            }
            $result.Verified++
        }

        $result.Success = ($result.Errors.Count -eq 0 -and $result.Verified -eq $entries.Count)
    }
    catch {
        $result.Errors.Add($_.Exception.Message)
    }
    finally {
        Remove-Variable -Name key, registryKey -ErrorAction SilentlyContinue
        foreach ($mount in @($mountedUserHives | Sort-Object { [string]$_.Sid } -Descending)) {
            if (-not (Dismount-UserRegistryHiveAfterRestore -Mount $mount)) {
                $result.Errors.Add("Temporary AntiAI user hive could not be unloaded: $($mount.Sid)")
                $result.Success = $false
            }
        }
    }

    return $result
}
