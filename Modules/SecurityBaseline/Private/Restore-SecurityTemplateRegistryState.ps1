function Restore-SecurityTemplateRegistryState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success       = $false
        ItemsRestored = 0
        ItemsVerified = 0
        Errors        = @()
        Warnings      = @()
        RetainedKeys  = @()
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore targeted security-template registry state')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "Targeted security-template registry backup not found: $BackupPath"
        }
        $backup = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $entries = @($backup.Values)
        $schemaVersion = [int]$backup.SchemaVersion
        if ($schemaVersion -notin @(2, 3) -or
            $entries.Count -eq 0 -or
            [int]$backup.TargetCount -ne $entries.Count) {
            throw 'Targeted security-template registry backup has an invalid schema or target count'
        }
        if ($schemaVersion -eq 3 -and -not $backup.PSObject.Properties['AbsentAncestorKeys']) {
            throw 'Security-template schema 3 backup has no absent-ancestor inventory'
        }

        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $keyStates = @{}
        foreach ($entry in $entries) {
            foreach ($requiredProperty in @('Path', 'Name', 'KeyExisted', 'Exists', 'Value', 'Type')) {
                if (-not $entry.PSObject.Properties[$requiredProperty]) {
                    throw "Security-template registry entry is missing '$requiredProperty'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ($path -notmatch '^HKLM:\\(SOFTWARE|SYSTEM)\\' -or
                [string]::IsNullOrWhiteSpace($name) -or
                -not $seen.Add("$path`0$name")) {
                throw "Invalid or duplicate security-template registry target: $path\$name"
            }
            if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
                throw "Existing security-template value is recorded under an originally absent key: $path\$name"
            }
            if ([bool]$entry.Exists -and [string]$entry.Type -notin @(
                    'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                )) {
                throw "Unsupported security-template registry type '$($entry.Type)': $path\$name"
            }
            if ($schemaVersion -eq 3) {
                if (-not $entry.PSObject.Properties['OriginalName']) {
                    throw "Security-template schema 3 entry has no original value name: $path\$name"
                }
                if ([bool]$entry.Exists -and
                    ([string]::IsNullOrWhiteSpace([string]$entry.OriginalName) -or
                     -not ([string]$entry.OriginalName).Equals($name, [StringComparison]::OrdinalIgnoreCase))) {
                    throw "Security-template original value-name identity is invalid: $path\$name"
                }
                if (-not [bool]$entry.Exists -and $null -ne $entry.OriginalName) {
                    throw "Absent security-template value has an original value name: $path\$name"
                }
            }
            $identity = $path.ToLowerInvariant()
            if ($keyStates.ContainsKey($identity) -and
                [bool]$keyStates[$identity].Existed -ne [bool]$entry.KeyExisted) {
                throw "Inconsistent security-template key-existence prestate: $path"
            }
            if (-not $keyStates.ContainsKey($identity)) {
                $keyStates[$identity] = [PSCustomObject]@{ Path = $path; Existed = [bool]$entry.KeyExisted }
            }
        }

        if ($schemaVersion -eq 3) {
            $declaredTargetPaths = @($keyStates.Values | ForEach-Object { [string]$_.Path })
            $seenAncestorPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($ancestorPathValue in @($backup.AbsentAncestorKeys)) {
                $ancestorPath = ([string]$ancestorPathValue).TrimEnd('\')
                if ([string]::IsNullOrWhiteSpace($ancestorPath) -or
                    -not $seenAncestorPaths.Add($ancestorPath) -or
                    $ancestorPath -notmatch '(?i)^HKLM:\\(SOFTWARE|SYSTEM)\\' -or
                    @($declaredTargetPaths | Where-Object {
                            $_.StartsWith("$ancestorPath\", [StringComparison]::OrdinalIgnoreCase)
                        }).Count -eq 0) {
                    throw "Invalid, duplicate or unowned security-template absent ancestor: $ancestorPath"
                }
                $identity = $ancestorPath.ToLowerInvariant()
                if (-not $keyStates.ContainsKey($identity)) {
                    $keyStates[$identity] = [PSCustomObject]@{ Path = $ancestorPath; Existed = $false }
                }
                elseif ([bool]$keyStates[$identity].Existed) {
                    throw "Security-template ancestor conflicts with existing-key prestate: $ancestorPath"
                }
            }
        }

        # HKLM:\...\Policies\System is shared with the sibling SecurityBaseline
        # restore routines. Sibling-owned values are not unowned state: their
        # owners handle them in the same restore session, and the sibling that
        # restores last (Restore-UACStandardUserElevation) enforces final key
        # absence. Owners: Computer-RegistryPolicies.json direct values
        # (Restore-RegistryPolicies) + ConsentPromptBehaviorUser
        # (Restore-UACStandardUserElevation).
        $sharedUacPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $siblingOwnedUacPolicyValues = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($siblingName in @(
                'MSAOptional', 'DisableAutomaticRestartSignOn', 'LocalAccountTokenFilterPolicy',
                'EnableMPR', 'ConsentPromptBehaviorUser'
            )) { $null = $siblingOwnedUacPolicyValues.Add($siblingName) }

        # Each owned value is written on its own: one failing value is
        # reported and never keeps the remaining values from their prestate.
        foreach ($keyState in $keyStates.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-NoIDRegistryKey -LiteralPath ([string]$keyState.Path))) {
                try {
                    New-NoIDRegistryKey -LiteralPath ([string]$keyState.Path) | Out-Null
                    $result.ItemsRestored++
                }
                catch {
                    $result.Errors += "Could not recreate originally existing key $($keyState.Path): $($_.Exception.Message)"
                }
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = if ($schemaVersion -eq 3 -and [bool]$entry.Exists) {
                [string]$entry.OriginalName
            }
            else {
                [string]$entry.Name
            }
            try {
                if ([bool]$entry.Exists) {
                    $kind = switch ([string]$entry.Type) {
                        'DWord'       { [Microsoft.Win32.RegistryValueKind]::DWord }
                        'QWord'       { [Microsoft.Win32.RegistryValueKind]::QWord }
                        'String'      { [Microsoft.Win32.RegistryValueKind]::String }
                        'ExpandString'{ [Microsoft.Win32.RegistryValueKind]::ExpandString }
                        'MultiString' { [Microsoft.Win32.RegistryValueKind]::MultiString }
                        'Binary'      { [Microsoft.Win32.RegistryValueKind]::Binary }
                    }
                    $value = switch ([string]$entry.Type) {
                        'DWord'       { [int]$entry.Value }
                        'QWord'       { [long]$entry.Value }
                        'Binary'      { [byte[]]@($entry.Value) }
                        'MultiString' { [string[]]@($entry.Value) }
                        default       { [string]$entry.Value }
                    }
                    $currentNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains $name) {
                        Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction Stop
                    }
                    New-ItemProperty -Path $path -Name $name -Value $value `
                        -PropertyType ([string]$kind) -Force -ErrorAction Stop | Out-Null
                }
                elseif (Test-NoIDRegistryKey -LiteralPath $path) {
                    $currentNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains $name) {
                        Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction Stop
                    }
                }
                $result.ItemsRestored++
            }
            catch {
                $result.Errors += "Could not restore $path\$name`: $($_.Exception.Message)"
            }
        }

        # An originally absent key is removed once it is empty. If it now holds
        # data this snapshot does not own, it is kept and reported instead of
        # destroying that data; verification accepts it as present.
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cleanupPaths = @($keyStates.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            try {
                if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { continue }
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $remainingValues = @($key.GetValueNames())
                $isSharedUacPath = $path.Equals($sharedUacPolicyPath, [StringComparison]::OrdinalIgnoreCase)
                if ($isSharedUacPath -and
                    $key.SubKeyCount -eq 0 -and
                    $remainingValues.Count -gt 0 -and
                    @($remainingValues | Where-Object { -not $siblingOwnedUacPolicyValues.Contains([string]$_) }).Count -eq 0) {
                    # Only sibling-owned values remain; deletion of the shared key is
                    # deferred to the sibling that restores last in this session.
                    continue
                }
                if ($remainingValues.Count -ne 0 -or $key.SubKeyCount -ne 0) {
                    $foreignValues = @($remainingValues | Where-Object {
                            -not ($isSharedUacPath -and $siblingOwnedUacPolicyValues.Contains([string]$_))
                        })
                    $foreignSubKeys = @($key.GetSubKeyNames() | Where-Object {
                            -not $retainedKeys.Contains("$path\$_")
                        })
                    $null = $retainedKeys.Add($path)
                    $result.RetainedKeys += $path
                    if ($foreignValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                        $result.Warnings += (Format-NoIDRetainedKeyNotice -Path $path `
                                -Values ([string[]]$foreignValues) -SubKeys ([string[]]$foreignSubKeys))
                    }
                    continue
                }
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                if (Test-NoIDRegistryKey -LiteralPath $path) {
                    throw 'the key still exists after removal'
                }
            }
            catch {
                $result.Errors += "Could not remove originally absent key $path`: $($_.Exception.Message)"
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = if ($schemaVersion -eq 3 -and [bool]$entry.Exists) {
                [string]$entry.OriginalName
            }
            else {
                [string]$entry.Name
            }
            $present = $false
            $actual = $null
            $actualType = $null
            if (Test-NoIDRegistryKey -LiteralPath $path) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $matchingNames = @($key.GetValueNames() | Where-Object {
                        ([string]$_).Equals($name, [StringComparison]::OrdinalIgnoreCase)
                    })
                $present = $matchingNames.Count -eq 1
                if ($present) {
                    if ($schemaVersion -eq 3 -and [string]$matchingNames[0] -cne $name) {
                        $result.Errors += "Security-template value-name casing verification failed: $path\$name"
                        continue
                    }
                    $actual = $key.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $actualType = $key.GetValueKind([string]$matchingNames[0]).ToString()
                }
            }
            if ($present -ne [bool]$entry.Exists) {
                $result.Errors += "Security-template value-existence verification failed: $path\$name"
                continue
            }
            if ($present) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actual) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    $result.Errors += "Security-template type/value verification failed: $path\$name"
                    continue
                }
            }
            $keyExists = Test-NoIDRegistryKey -LiteralPath $path
            $sharedKeyDeferred = $retainedKeys.Contains($path)
            if ($keyExists -and -not [bool]$entry.KeyExisted -and
                $path.Equals($sharedUacPolicyPath, [StringComparison]::OrdinalIgnoreCase)) {
                $sharedKeyCheck = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($sharedKeyCheck.SubKeyCount -eq 0 -and
                    @(@($sharedKeyCheck.GetValueNames()) | Where-Object {
                            -not $siblingOwnedUacPolicyValues.Contains([string]$_)
                        }).Count -eq 0) {
                    # Sibling-owned values still pending their own restore step;
                    # the last shared-key owner verifies final absence.
                    $sharedKeyDeferred = $true
                }
            }
            if (-not $sharedKeyDeferred -and $keyExists -ne [bool]$entry.KeyExisted) {
                $result.Errors += "Security-template key-existence verification failed: $path"
                continue
            }
            $result.ItemsVerified++
        }

        $result.Success = (@($result.Errors).Count -eq 0 -and $result.ItemsVerified -eq $entries.Count)
    }
    catch {
        $result.Errors += "Targeted security-template registry restore failed: $($_.Exception.Message)"
    }
    return $result
}
