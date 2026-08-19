#Requires -Version 5.1

function Restore-AntiAIRegistryState {
    <#
    .SYNOPSIS
        Restores and verifies the exact AntiAI registry prestate.

    .DESCRIPTION
        Restores value existence, type and unexpanded data as well as registry
        key existence. An originally absent key is removed only when no
        unowned state remains; otherwise restore fails instead of deleting a
        later third-party or administrator change.
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
            -not (Get-Command 'Mount-UserRegistryHiveForRestore' -ErrorAction SilentlyContinue)) {
            throw 'Core user-hive restore helper is unavailable'
        }
        foreach ($sid in $snapshotUserSids) {
            $mountedUserHives.Add((Mount-UserRegistryHiveForRestore -Sid $sid))
        }

        $allowedMachinePaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
            'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint',
            'HKLM:\SOFTWARE\Policies\WindowsNotepad'
        )
        $allowedUserSuffixes = @(
            'SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
            'Software\Policies\Microsoft\Windows\WindowsCopilot',
            'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
            'Software\Policies\Microsoft\Windows\CopilotKey'
        )
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $keyExistence = @{}
        $preparedValues = @{}

        # Validate the complete document before the first registry mutation.
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
                if (-not (Test-Path -LiteralPath $hiveRoot -PathType Container -ErrorAction Stop)) {
                    throw "Original interactive user hive is not loaded for AntiAI restore: $hiveRoot"
                }
                $allowed = $Matches[2] -in $allowedUserSuffixes
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

        foreach ($keyState in @($keyExistence.Values | Where-Object { -not [bool]$_.Existed })) {
            $path = [string]$keyState.Path
            if (-not (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)) { continue }
            $ownedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in @($entries | Where-Object { [string]$_.Path -eq $path })) {
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
                throw "Originally absent AntiAI key contains unowned state; refusing destructive restore: $path"
            }
        }

        # Recreate keys that existed even when they contained none of the owned
        # values. This preserves an originally empty key exactly.
        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-Path -LiteralPath ([string]$keyState.Path) -PathType Container -ErrorAction Stop)) {
                New-Item -Path ([string]$keyState.Path) -Force -ErrorAction Stop | Out-Null
                $result.Restored++
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([bool]$entry.Exists) {
                $prepared = $preparedValues["$path`0$name"]
                New-ItemProperty -LiteralPath $path -Name $name -PropertyType $prepared.Type `
                    -Value $prepared.Value -Force -ErrorAction Stop | Out-Null
                $result.Restored++
            }
            elseif (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($key.GetValueNames() -contains $name) {
                    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                    $result.Restored++
                }
            }
        }

        # Remove originally absent keys only when every remaining item is owned
        # and already removed. Concurrent unowned state makes exact restore fail.
        $absentPaths = @($keyExistence.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $absentPaths) {
            if (-not (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)) { continue }
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($key.GetValueNames().Count -eq 0 -and $key.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                $result.Restored++
            }
            if (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
                throw "Originally absent AntiAI key contains unowned state; refusing destructive deletion: $path"
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            $valueExists = $false
            $actualValue = $null
            $actualType = $null
            if (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
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
                throw "AntiAI value-existence verification failed: $path::$name"
            }
            if ($valueExists) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    throw "AntiAI type/value verification failed: $path::$name"
                }
            }
            $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
            if ($keyExists -ne [bool]$entry.KeyExisted) {
                throw "AntiAI key-existence verification failed: $path"
            }
            $result.Verified++
        }

        $result.Success = ($result.Verified -eq $entries.Count)
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
