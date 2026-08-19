function Restore-AdvancedSecurityRegistryState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success  = $false
        Restored = 0
        Verified = 0
        Errors   = @()
    }

    if (-not $PSCmdlet.ShouldProcess('AdvancedSecurity managed registry values', 'Restore exact pre-state')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "AdvancedSecurity pre-state artifact not found: $BackupPath"
        }
        foreach ($dependency in @(
                @{ Command = 'Get-AdvancedSecuritySchema5RegistryTargets'; File = 'Get-AdvancedSecuritySchema5RegistryTargets.ps1' }
                @{ Command = 'Assert-AdvancedSecurityRegistrySnapshot'; File = 'Assert-AdvancedSecurityRegistrySnapshot.ps1' }
                @{ Command = 'Get-AdvancedSecurityInteractiveUser'; File = 'AdvancedSecurityWinInet.ps1' }
            )) {
            if (-not (Get-Command $dependency.Command -ErrorAction SilentlyContinue)) {
                $dependencyPath = Join-Path $PSScriptRoot $dependency.File
                if (-not (Test-Path -LiteralPath $dependencyPath -PathType Leaf)) {
                    throw "AdvancedSecurity registry restore dependency is missing: $dependencyPath"
                }
                . $dependencyPath
            }
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $validatedSnapshot = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $snapshot -RestoreOnly
        $entries = @($validatedSnapshot.Entries)
        $shieldsUpEntries = @($entries | Where-Object {
                -not [bool]$_.KeyOnly -and
                [string]$_.Path -ceq 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -and
                [string]$_.Name -ceq 'DoNotAllowExceptions'
            })
        if ($shieldsUpEntries.Count -gt 1) {
            throw 'AdvancedSecurity snapshot contains duplicate Shields Up state'
        }
        $shieldsUpEntry = if ($shieldsUpEntries.Count -eq 1) { $shieldsUpEntries[0] } else { $null }
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
            if ($path -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') {
                $hiveRoot = "HKU:\$($Matches[1])"
                if (-not (Test-Path -LiteralPath $hiveRoot -PathType Container)) {
                    throw "Original AdvancedSecurity user hive is not loaded: $hiveRoot"
                }
            }
        }

        foreach ($keyState in @($keyExistence.Values | Where-Object { -not [bool]$_.Existed })) {
            $path = [string]$keyState.Path
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            $ownedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in @($entries | Where-Object {
                        [string]$_.Path -eq $path -and -not [bool]$_.KeyOnly
                    })) {
                $null = $ownedNames.Add([string]$entry.Name)
            }
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            $unownedValues = @($key.GetValueNames() | Where-Object { -not $ownedNames.Contains([string]$_) })
            $managedPaths = @($keyExistence.Values | ForEach-Object { [string]$_.Path })
            $unownedSubKeys = @(Get-ChildItem -LiteralPath $path -ErrorAction Stop | Where-Object {
                    $childPath = "$path\$([string]$_.PSChildName)"
                    @($managedPaths | Where-Object {
                            $_.Equals($childPath, [StringComparison]::OrdinalIgnoreCase) -or
                            $_.StartsWith("$childPath\", [StringComparison]::OrdinalIgnoreCase)
                        }).Count -eq 0
                })
            if ($unownedValues.Count -gt 0 -or $unownedSubKeys.Count -gt 0) {
                throw "Originally absent AdvancedSecurity key contains unowned state; refusing destructive restore: $path"
            }
        }

        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and -not (Test-Path -LiteralPath ([string]$keyState.Path) -PathType Container)) {
                New-Item -Path ([string]$keyState.Path) -Force -ErrorAction Stop | Out-Null
                $result.Restored++
            }
        }

        foreach ($entry in @($entries | Where-Object { -not [bool]$_.KeyOnly })) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
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
            elseif (Test-Path -LiteralPath $path) {
                $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($registryKey.GetValueNames() -contains $name) {
                    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                    $result.Restored++
                }
            }
        }

        if ($shieldsUpEntry) {
            $savedShieldsUpValue = if ([bool]$shieldsUpEntry.Exists) {
                [int]$shieldsUpEntry.Value
            }
            else { 0 }
            if ($savedShieldsUpValue -notin @(0, 1)) {
                throw 'AdvancedSecurity Shields Up prestate is not a Boolean DWORD'
            }
            # Set-NetFirewallProfile binds this parameter to NetSecurity's
            # GpoBoolean enum. A System.Boolean variable is not convertible to
            # that generated enum on Windows PowerShell 5.1, whereas the
            # canonical True/False tokens used by the Apply helper are.
            $allowInboundRules = if ($savedShieldsUpValue -eq 0) { 'True' } else { 'False' }
            # Restore through the documented NetSecurity API so the effective
            # firewall engine observes the same state as the exact registry
            # prestate. If the value was originally absent, remove the API's
            # materialized zero again below; the effective default remains True.
            Set-NetFirewallProfile -Profile Public `
                -AllowInboundRules $allowInboundRules -ErrorAction Stop
            if (-not [bool]$shieldsUpEntry.Exists) {
                $shieldPath = [string]$shieldsUpEntry.Path
                if (Test-Path -LiteralPath $shieldPath) {
                    $shieldKey = Get-Item -LiteralPath $shieldPath -ErrorAction Stop
                    if ($shieldKey.GetValueNames() -contains 'DoNotAllowExceptions') {
                        Remove-ItemProperty -LiteralPath $shieldPath `
                            -Name 'DoNotAllowExceptions' -ErrorAction Stop
                    }
                }
            }
        }

        $cleanupPaths = @($entries | Where-Object { -not [bool]$_.KeyExisted } |
                ForEach-Object { [string]$_.Path } | Select-Object -Unique |
                Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($registryKey.GetValueNames().Count -eq 0 -and $registryKey.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            if ([bool]$entry.KeyOnly) {
                $keyExists = Test-Path -LiteralPath $path -PathType Container
                if ($keyExists -ne [bool]$entry.KeyExisted) {
                    throw "AdvancedSecurity key-existence verification failed: $path"
                }
                $result.Verified++
                continue
            }

            $name = [string]$entry.Name
            $valueExists = $false
            $actualValue = $null
            $actualType = $null
            if (Test-Path -LiteralPath $path) {
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
                throw "AdvancedSecurity existence verification failed: $path\$name"
            }
            if ($valueExists) {
                if ($actualType -ne [string]$entry.Type) {
                    throw "AdvancedSecurity type verification failed: $path\$name"
                }
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($expectedJson -cne $actualJson) {
                    throw "AdvancedSecurity value verification failed: $path\$name"
                }
            }
            if ([bool]$entry.KeyExisted -and -not (Test-Path -LiteralPath $path)) {
                throw "Originally existing AdvancedSecurity key is missing: $path"
            }
            if (-not [bool]$entry.KeyExisted -and (Test-Path -LiteralPath $path -PathType Container)) {
                throw "Originally absent AdvancedSecurity key remains after restore: $path"
            }
            $result.Verified++
        }

        if ($shieldsUpEntry) {
            $expectedAllowInboundRules = -not (
                [bool]$shieldsUpEntry.Exists -and [int]$shieldsUpEntry.Value -eq 1
            )
            $effectiveProfile = @(Get-NetFirewallProfile `
                    -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
            if ($effectiveProfile.Count -ne 1 -or
                [bool]::Parse([string]$effectiveProfile[0].AllowInboundRules) -ne
                    $expectedAllowInboundRules) {
                throw 'AdvancedSecurity Shields Up effective firewall restore verification failed'
            }
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
            # admin runs the restore, skip this single sub-target with a warning
            # instead of failing the whole rollback: the machine-wide registry
            # pre-state is already restored and verified above, and leaving
            # AutoDetect disabled is the more-secure state. Mirrors the Apply-side
            # NotApplicable handling in Disable-WPAD.
            if ($null -eq $activeUser -or [string]$activeUser.Sid -cne [string]$savedUser.Sid) {
                Write-Log -Level WARNING -Message "WinINet AutoDetect pre-state not restored for SID $($savedUser.Sid): the backed-up Explorer user is not the active session. Re-run the restore as that user to reinstate their AutoDetect preference." -Module 'AdvancedSecurity'
                continue
            }
            $restoredState = Invoke-AdvancedSecurityWinInetUserState `
                -User $activeUser `
                -Operation SetAutoDetect `
                -AutoDetectEnabled:([bool]$savedUser.AutoDetectEnabled)
            if ([bool]$restoredState.AutoDetectEnabled -ne [bool]$savedUser.AutoDetectEnabled) {
                throw "WinINet AutoDetect restore verification failed for SID $($savedUser.Sid)"
            }
            Write-Log -Level SUCCESS -Message "WinINet AutoDetect restored through the user API for SID $($savedUser.Sid): $($savedUser.AutoDetectEnabled)" -Module 'AdvancedSecurity'
        }

        $result.Success = $true
        Write-Log -Level SUCCESS -Message "AdvancedSecurity registry pre-state restored and verified ($($result.Verified) targets)" -Module 'AdvancedSecurity'
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-Log -Level ERROR -Message "AdvancedSecurity registry pre-state restore failed: $($_.Exception.Message)" -Module 'AdvancedSecurity'
    }
    finally {
        $registryKey = $null
        $key = $null
    }

    return $result
}
