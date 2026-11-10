function Restore-AdvancedSecurityRegistryState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [string]$FirewallPolicyBackupPath
    )

    $result = [PSCustomObject]@{
        Success  = $false
        Restored = 0
        Verified = 0
        Errors   = @()
        Warnings = @()
        RetainedKeys = @()
    }

    if (-not $PSCmdlet.ShouldProcess('AdvancedSecurity sealed firewall and managed registry state', 'Restore exact pre-state')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf -ErrorAction Stop)) {
            throw "AdvancedSecurity pre-state artifact not found: $BackupPath"
        }
        foreach ($dependency in @(
                @{ Command = 'Get-AdvancedSecuritySchema5RegistryTargets'; File = 'Get-AdvancedSecuritySchema5RegistryTargets.ps1' }
                @{ Command = 'Get-AdvancedSecuritySchema6RegistryTargets'; File = 'Get-AdvancedSecuritySchema6RegistryTargets.ps1' }
                @{ Command = 'Get-AdvancedSecuritySchema7RegistryTargets'; File = 'Get-AdvancedSecuritySchema7RegistryTargets.ps1' }
                @{ Command = 'Assert-AdvancedSecurityRegistrySnapshot'; File = 'Assert-AdvancedSecurityRegistrySnapshot.ps1' }
                @{ Command = 'Get-AdvancedSecurityInteractiveUser'; File = 'AdvancedSecurityWinInet.ps1' }
            )) {
            if (-not (Get-Command $dependency.Command -ErrorAction SilentlyContinue)) {
                $dependencyPath = Join-Path $PSScriptRoot $dependency.File
                if (-not (Test-Path -LiteralPath $dependencyPath -PathType Leaf -ErrorAction Stop)) {
                    throw "AdvancedSecurity registry restore dependency is missing: $dependencyPath"
                }
                . $dependencyPath
            }
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $validatedSnapshot = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $snapshot -RestoreOnly
        $entries = @($validatedSnapshot.Entries)
        $expectsFirewallPolicy = -not [bool]$snapshot.SkipFirewallLayer
        if ($expectsFirewallPolicy) {
            if ([string]::IsNullOrWhiteSpace($FirewallPolicyBackupPath) -or
                -not (Test-Path -LiteralPath $FirewallPolicyBackupPath -PathType Leaf -ErrorAction Stop)) {
                throw 'AdvancedSecurity exact restore requires its sealed firewall policy artifact'
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($FirewallPolicyBackupPath)) {
            throw 'AdvancedSecurity firewall artifact contradicts the sealed skipped-layer decision'
        }
        $seenTargets = @{}
        $keyExistence = @{}
        foreach ($entry in $entries) {
            foreach ($requiredProperty in @('Path', 'Name', 'KeyOnly', 'KeyExisted', 'Exists', 'Value', 'Type')) {
                if (-not $entry.PSObject.Properties[$requiredProperty]) {
                    throw "AdvancedSecurity pre-state entry is missing '$requiredProperty'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if (-not [bool]$entry.KeyOnly -and [string]::IsNullOrWhiteSpace($name)) {
                throw "AdvancedSecurity value entry has no name: $path"
            }
            $identity = "$path`0$name`0$([bool]$entry.KeyOnly)"
            if ($seenTargets.ContainsKey($identity)) {
                throw "Duplicate AdvancedSecurity restore target: $path\$name"
            }
            $seenTargets[$identity] = $true
            if (-not [bool]$entry.KeyOnly -and [bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
                throw "AdvancedSecurity entry claims an existing value in an originally absent key: $path\$name"
            }
            if (-not [bool]$entry.KeyOnly -and [bool]$entry.Exists -and [string]$entry.Type -notin @(
                    'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                )) {
                throw "Unsupported AdvancedSecurity registry type '$($entry.Type)' for $path\$name"
            }
            $pathIdentity = $path.ToLowerInvariant()
            if ($keyExistence.ContainsKey($pathIdentity) -and [bool]$keyExistence[$pathIdentity].Existed -ne [bool]$entry.KeyExisted) {
                throw "Inconsistent AdvancedSecurity key-existence prestate: $path"
            }
            if (-not $keyExistence.ContainsKey($pathIdentity)) {
                $keyExistence[$pathIdentity] = [PSCustomObject]@{ Path=$path; Existed=[bool]$entry.KeyExisted }
            }
        }

        # User-scope values need that user's loaded hive. Without it they are
        # reported and every machine-wide value is still restored.
        $unloadedHiveRoots = @($entries | ForEach-Object {
                if ([string]$_.Path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') { "HKU:\$($Matches[1])" }
            } | Sort-Object -Unique | Where-Object { -not (Test-NoIDRegistryKey -LiteralPath $_) })
        foreach ($hiveRoot in $unloadedHiveRoots) {
            $result.Errors += "AdvancedSecurity user values in $hiveRoot were not restored because that user is not signed in; sign in as that user and run Restore again."
            $userPrefix = "$hiveRoot\"
            $entries = @($entries | Where-Object {
                    -not ([string]$_.Path).StartsWith($userPrefix, [StringComparison]::OrdinalIgnoreCase)
                })
            foreach ($pathIdentity in @($keyExistence.Keys)) {
                if (([string]$keyExistence[$pathIdentity].Path).StartsWith($userPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $keyExistence.Remove($pathIdentity)
                }
            }
        }

        if ($expectsFirewallPolicy) {
            foreach ($dependency in @(
                    @{ Command = 'Assert-AdvancedSecurityFirewallPolicyEquivalent'; File = 'AdvancedSecurityFirewallPolicyState.ps1' }
                    @{ Command = 'Restore-FirewallPolicy'; File = '../Public/Restore-AdvancedSecuritySettings.ps1' }
                )) {
                if (-not (Get-Command $dependency.Command -ErrorAction SilentlyContinue)) {
                    . (Join-Path $PSScriptRoot $dependency.File)
                }
            }
            # Synchronize the native engine before restoring exact raw values.
            # Writing a saved DWORD first can make Set-NetFirewallProfile a
            # no-op while ActiveStore still has the hardened value. Conversely,
            # native policy import can normalize historical raw DWORDs (e.g. 2
            # to 1), so the saved typed registry state must be restored afterward.
            # Both artifacts already exist in sealed 2.2.5 schema-5 sessions.
            $firewallRestore = @{ BackupFilePath=$FirewallPolicyBackupPath; Confirm=$false }
            if ($snapshot.PSObject.Properties['FirewallGpoEditorRegistered']) {
                $firewallRestore.SealedEditorRegistration = [bool]$snapshot.FirewallGpoEditorRegistered
            }
            # The registry values below do not depend on the firewall import.
            try {
                if (-not (Restore-FirewallPolicy @firewallRestore)) {
                    throw 'AdvancedSecurity sealed firewall policy import or verification failed'
                }
            }
            catch {
                $result.Errors += $_.Exception.Message
            }
        }

        # Each owned value is written on its own: one failing value is
        # reported and never keeps the remaining values from their prestate.
        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and -not (Test-NoIDRegistryKey -LiteralPath ([string]$keyState.Path))) {
                try {
                    New-NoIDRegistryKey -LiteralPath ([string]$keyState.Path) | Out-Null
                    $result.Restored++
                }
                catch {
                    $result.Errors += "Could not recreate originally existing key $($keyState.Path): $($_.Exception.Message)"
                }
            }
        }

        foreach ($entry in @($entries | Where-Object { -not [bool]$_.KeyOnly })) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            try {
                if ([bool]$entry.Exists) {
                    $value = switch ([string]$entry.Type) {
                        'DWord'       { [int]$entry.Value }
                        'QWord'       { [long]$entry.Value }
                        'Binary'      { [byte[]]@($entry.Value) }
                        'MultiString' { [string[]]@($entry.Value) }
                        default       { [string]$entry.Value }
                    }
                    New-ItemProperty -LiteralPath $path -Name $name -PropertyType ([string]$entry.Type) `
                        -Value $value -Force -ErrorAction Stop | Out-Null
                    $result.Restored++
                }
                elseif (Test-Path -LiteralPath $path -ErrorAction Stop) {
                    $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
                    if ($registryKey.GetValueNames() -contains $name) {
                        Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                        $result.Restored++
                    }
                }
            }
            catch {
                $result.Errors += "Could not restore $path\$name`: $($_.Exception.Message)"
            }
        }

        # An originally absent key is removed once it is empty. If it now holds
        # data this snapshot does not own (another program's policy, a value the
        # user added), it is kept and reported instead of destroying that data.
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cleanupPaths = @($entries | Where-Object { -not [bool]$_.KeyExisted } |
                ForEach-Object { [string]$_.Path } | Select-Object -Unique |
                Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            try {
                if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { continue }
                $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
                $remainingValues = @($registryKey.GetValueNames())
                if ($remainingValues.Count -eq 0 -and $registryKey.SubKeyCount -eq 0) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    continue
                }
                $foreignSubKeys = @($registryKey.GetSubKeyNames() | Where-Object { -not $retainedKeys.Contains("$path\$_") })
                $null = $retainedKeys.Add($path)
                $result.RetainedKeys += $path
                if ($remainingValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                    $result.Warnings += (Format-NoIDRetainedKeyNotice -Path $path `
                            -Values ([string[]]$remainingValues) -SubKeys ([string[]]$foreignSubKeys))
                }
            }
            catch {
                $result.Errors += "Could not remove originally absent AdvancedSecurity key $path`: $($_.Exception.Message)"
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            if ([bool]$entry.KeyOnly) {
                $keyExists = Test-NoIDRegistryKey -LiteralPath $path
                if ($keyExists -ne [bool]$entry.KeyExisted -and -not $retainedKeys.Contains($path)) {
                    $result.Errors += "AdvancedSecurity key-existence verification failed: $path"
                    continue
                }
                $result.Verified++
                continue
            }

            $name = [string]$entry.Name
            $valueExists = $false
            $actualValue = $null
            $actualType = $null
            if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
                $valueExists = $registryKey.GetValueNames() -contains $name
                if ($valueExists) {
                    $actualValue = $registryKey.GetValue(
                        $name,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $actualType = $registryKey.GetValueKind($name).ToString()
                }
            }
            if ($valueExists -ne [bool]$entry.Exists) {
                $result.Errors += "AdvancedSecurity existence verification failed: $path\$name"
                continue
            }
            if ($valueExists) {
                if ($actualType -ne [string]$entry.Type) {
                    $result.Errors += "AdvancedSecurity type verification failed: $path\$name"
                    continue
                }
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($expectedJson -cne $actualJson) {
                    $result.Errors += "AdvancedSecurity value verification failed: $path\$name"
                    continue
                }
            }
            if ([bool]$entry.KeyExisted -and -not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
                $result.Errors += "Originally existing AdvancedSecurity key is missing: $path"
                continue
            }
            if (-not [bool]$entry.KeyExisted -and (Test-NoIDRegistryKey -LiteralPath $path) -and
                -not $retainedKeys.Contains($path)) {
                $result.Errors += "Originally absent AdvancedSecurity key remains after restore: $path"
                continue
            }
            $result.Verified++
        }

        # Restore only the module-owned PROXY_TYPE_AUTO_DETECT bit through the
        # documented API. Other current proxy flags remain untouched. A saved
        # interactive-user target cannot be claimed restored while that user is
        # offline, because a raw connection-blob write would be undocumented and
        # could overwrite unrelated proxy state.
        $activeUser = Get-AdvancedSecurityInteractiveUser -AllowNone
        foreach ($savedUser in @($validatedSnapshot.WinInetUsers)) {
            # The user-side AutoDetect bit can only be restored through the
            # documented per-user WinINet API while that exact user is the active
            # Explorer session. When the backed-up user is offline or a different
            # admin runs the restore, leave AutoDetect in its current more-secure
            # state, but fail the exact Restore contract. A sealed Apply target is
            # not an Apply-side NotApplicable target: publishing a successful
            # receipt while it remains unresolved would make BAVR evidence false.
            if ($null -eq $activeUser -or [string]$activeUser.Sid -cne [string]$savedUser.Sid) {
                $unresolvedMessage = "WinINet AutoDetect pre-state not restored for SID $($savedUser.Sid): the backed-up Explorer user is not the active session. Re-run the restore as that user to reinstate their AutoDetect preference."
                $result.Errors += $unresolvedMessage
                Write-Log -Level ERROR -Message $unresolvedMessage -Module 'AdvancedSecurity'
                continue
            }
            try {
                $restoredState = Invoke-AdvancedSecurityWinInetUserState `
                    -User $activeUser `
                    -Operation SetAutoDetect `
                    -AutoDetectEnabled:([bool]$savedUser.AutoDetectEnabled)
                if ([bool]$restoredState.AutoDetectEnabled -ne [bool]$savedUser.AutoDetectEnabled) {
                    throw "WinINet AutoDetect restore verification failed for SID $($savedUser.Sid)"
                }
                Write-Log -Level SUCCESS -Message "Proxy auto-detection restored and verified" -Module 'AdvancedSecurity'
            }
            catch {
                $result.Errors += $_.Exception.Message
            }
        }

        if ($result.Errors.Count -eq 0) {
            $result.Success = $true
            Write-Log -Level SUCCESS -Message "AdvancedSecurity settings restored and verified ($($result.Verified) values)" -Module 'AdvancedSecurity'
        }
        else {
            Write-Log -Level ERROR -Message "AdvancedSecurity registry pre-state restore is incomplete: $($result.Errors.Count) sealed target(s) remain unresolved" -Module 'AdvancedSecurity'
        }
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-Log -Level ERROR -Message "AdvancedSecurity registry pre-state restore failed: $($_.Exception.Message)" -Module 'AdvancedSecurity'
    }
    finally {
        $registryKey = $null
    }

    return $result
}
