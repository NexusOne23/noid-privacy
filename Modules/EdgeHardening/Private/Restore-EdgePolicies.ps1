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
        Warnings       = @()
        RetainedKeys   = @()
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

        # Each owned value is written on its own: one failing value is
        # reported and never keeps the remaining values from their prestate.
        foreach ($keyState in $keyExistence.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-NoIDRegistryKey -LiteralPath ([string]$keyState.Path))) {
                try {
                    New-NoIDRegistryKey -LiteralPath ([string]$keyState.Path) | Out-Null
                    $result.ValuesRestored++
                }
                catch {
                    $result.Errors += "Could not recreate originally existing key $($keyState.Path): $($_.Exception.Message)"
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
                    $result.ValuesRestored++
                }
                elseif (Test-NoIDRegistryKey -LiteralPath $path) {
                    $key = Get-Item -LiteralPath $path -ErrorAction Stop
                    if ($key.GetValueNames() -contains $name) {
                        Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                        $result.ValuesRestored++
                    }
                }
            }
            catch {
                $result.Errors += "Could not restore $path\$name`: $($_.Exception.Message)"
            }
        }

        # An originally absent key is removed once it is empty. If it now holds
        # data this snapshot does not own (an extension allowlist the user added
        # as the lockdown prompt advises, another tool's Edge policy), deleting
        # it would destroy that data: the key is kept and reported instead.
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
                    $result.ValuesRestored++
                    if (Test-NoIDRegistryKey -LiteralPath $path) {
                        throw 'the key still exists after removal'
                    }
                    continue
                }
                $foreignSubKeys = @($key.GetSubKeyNames() | Where-Object {
                        -not $retainedKeys.Contains("$path\$_")
                    })
                $null = $retainedKeys.Add($path)
                $result.RetainedKeys += $path
                if ($remainingValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                    $result.Warnings += (Format-NoIDRetainedKeyNotice -Path $path `
                            -Values ([string[]]$remainingValues) -SubKeys ([string[]]$foreignSubKeys))
                }
            }
            catch {
                $result.Errors += "Could not remove originally absent Edge key $path`: $($_.Exception.Message)"
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
                $result.Errors += "Edge value-existence verification failed: $path\$name"
                continue
            }
            if ($valueExists) {
                $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -ne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                    $result.Errors += "Edge type/value verification failed: $path\$name"
                    continue
                }
            }
            $keyExists = Test-NoIDRegistryKey -LiteralPath $path
            if ($keyExists -ne [bool]$entry.KeyExisted -and -not $retainedKeys.Contains($path)) {
                $result.Errors += "Edge key-existence verification failed: $path"
                continue
            }
            $result.ValuesVerified++
        }

        $result.Success = (@($result.Errors).Count -eq 0 -and $result.ValuesVerified -eq $entries.Count)
        Write-Log -Level DEBUG -Message "Edge pre-state restored and verified for $($result.ValuesVerified) selected values" -Module 'EdgeHardening'
    }
    catch {
        $result.Errors += "Restore failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Edge policy restore failed: $($_.Exception.Message)" -Module 'EdgeHardening'
    }

    return $result
}
