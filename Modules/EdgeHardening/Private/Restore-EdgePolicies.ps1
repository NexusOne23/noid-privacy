<#
.SYNOPSIS
    Restore and verify the exact Edge policy prestate captured by BAVR.
#>

function Restore-EdgePolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success        = $false
        ValuesRestored = 0
        ValuesVerified = 0
        Errors         = @()
    }

    if (-not $PSCmdlet.ShouldProcess('HKLM:\Software\Policies\Microsoft\Edge', 'Restore selected Edge policy pre-state')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf -ErrorAction Stop)) {
            throw "Edge pre-state artifact not found: $BackupPath"
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-EdgePolicySnapshot -Snapshot $snapshot -RestoreOnly
        $entries = @($snapshot.Entries)

        $seenTargets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $keyExistence = @{}
        $preparedValues = @{}

        # Validate the complete sealed document before changing the registry.
        foreach ($entry in $entries) {
            foreach ($requiredProperty in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
                if (-not $entry.PSObject.Properties[$requiredProperty]) {
                    throw "Edge pre-state entry is missing '$requiredProperty'"
                }
            }
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([string]::IsNullOrWhiteSpace($name) -or -not $seenTargets.Add("$path`0$name")) {
                throw "Edge pre-state contains an invalid or duplicate target: $path\$name"
            }
            if ([bool]$entry.Exists -and -not [bool]$entry.KeyExisted) {
                throw "Edge entry claims an existing value in an originally absent key: $path\$name"
            }
            if ([bool]$entry.Exists -and [string]$entry.Type -notin @(
                    'DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary'
                )) {
                throw "Unsupported Edge registry type '$($entry.Type)' for $path\$name"
            }
            $pathIdentity = $path.ToLowerInvariant()
            if ($keyExistence.ContainsKey($pathIdentity) -and
                [bool]$keyExistence[$pathIdentity].Existed -ne [bool]$entry.KeyExisted) {
                throw "Inconsistent Edge key-existence prestate: $path"
            }
            if (-not $keyExistence.ContainsKey($pathIdentity)) {
                $keyExistence[$pathIdentity] = [PSCustomObject]@{ Path = $path; Existed = [bool]$entry.KeyExisted }
            }
            if ([bool]$entry.Exists) {
                $preparedValues["$path`0$name"] = [PSCustomObject]@{
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

        # Refuse before any mutation if an originally absent key now contains
        # data not owned by this snapshot.
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
                throw "Originally absent Edge key contains unowned state; refusing destructive restore: $path"
            }
        }

        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-Path -LiteralPath ([string]$keyState.Path) -PathType Container -ErrorAction Stop)) {
                New-Item -Path ([string]$keyState.Path) -Force -ErrorAction Stop | Out-Null
                $result.ValuesRestored++
            }
        }

        foreach ($entry in $entries) {
            $path = [string]$entry.Path
            $name = [string]$entry.Name
            if ([bool]$entry.Exists) {
                $prepared = $preparedValues["$path`0$name"]
                New-ItemProperty -LiteralPath $path -Name $name -PropertyType $prepared.Type `
                    -Value $prepared.Value -Force -ErrorAction Stop | Out-Null
                $result.ValuesRestored++
            }
            elseif (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($key.GetValueNames() -contains $name) {
                    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                    $result.ValuesRestored++
                }
            }
        }

        $cleanupPaths = @($keyExistence.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            if (-not (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)) { continue }
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($key.GetValueNames().Count -eq 0 -and $key.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                $result.ValuesRestored++
            }
            if (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
                throw "Originally absent Edge key remains after restore: $path"
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
                    $actualValue = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $actualType = $key.GetValueKind($name).ToString()
                }
            }
            if ($valueExists -ne [bool]$entry.Exists) {
                throw "Edge value-existence verification failed: $path\$name"
            }
            if ($valueExists) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    throw "Edge type/value verification failed: $path\$name"
                }
            }
            $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
            if ($keyExists -ne [bool]$entry.KeyExisted) {
                throw "Edge key-existence verification failed: $path"
            }
            $result.ValuesVerified++
        }

        $result.Success = ($result.ValuesVerified -eq $entries.Count)
        Write-Log -Level SUCCESS -Message "Edge pre-state restored and verified for $($result.ValuesVerified) selected values" -Module 'EdgeHardening'
    }
    catch {
        $result.Errors += "Restore failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Edge policy restore failed: $($_.Exception.Message)" -Module 'EdgeHardening'
    }

    return $result
}
