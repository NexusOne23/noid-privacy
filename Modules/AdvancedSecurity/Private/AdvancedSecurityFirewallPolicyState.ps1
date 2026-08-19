#Requires -Version 5.1

function Invoke-AdvancedSecurityRegistryTool {
    <#
    .SYNOPSIS
        Invoke the inbox registry tool without PowerShell native-command rewriting.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Load', 'Unload')]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^NoIDFirewall_[0-9a-f]{32}$')]
        [string]$MountName,

        [string]$HivePath
    )

    if ($Operation -eq 'Load' -and
        [string]::IsNullOrWhiteSpace($HivePath)) {
        throw 'A hive path is required for reg load'
    }
    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    if (-not (Test-Path -LiteralPath $regExe -PathType Leaf)) {
        throw "Windows registry tool is unavailable: $regExe"
    }

    $target = "HKLM\$MountName"
    # Both values are locally generated Windows paths. Windows path syntax
    # forbids embedded double quotes, so exact quoting is unambiguous here.
    $arguments = if ($Operation -eq 'Load') {
        "load `"$target`" `"$HivePath`""
    }
    else {
        "unload `"$target`""
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $regExe
    $startInfo.Arguments = $arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Unable to start Windows registry tool: $regExe"
        }
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [PSCustomObject]@{
            ExitCode = [int]$process.ExitCode
            Output = (@($standardOutput.Trim(), $standardError.Trim()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
        }
    }
    finally {
        $process.Dispose()
    }
}

function Test-AdvancedSecurityTemporaryFirewallHive {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^NoIDFirewall_[0-9a-f]{32}$')]
        [string]$MountName
    )

    $baseKey = $null
    $mountedKey = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $mountedKey = $baseKey.OpenSubKey($MountName, $false)
        return $null -ne $mountedKey
    }
    finally {
        if ($null -ne $mountedKey) { $mountedKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Get-AdvancedSecurityFirewallPolicyState {
    <#
    .SYNOPSIS
        Read the complete semantic policy state from a netsh .wfw export.

    .DESCRIPTION
        A .wfw file is a registry hive. Windows rewrites non-policy hive
        metadata on every export, so file hashes are not stable even when the
        represented policy is unchanged. This function mounts the hive under a
        unique temporary HKLM key and captures every key plus every typed value
        in deterministic order. No live firewall store is read or modified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyFilePath
    )

    if (-not (Test-Path -LiteralPath $PolicyFilePath -PathType Leaf)) {
        throw "Firewall policy file not found: $PolicyFilePath"
    }
    if ([System.IO.Path]::GetExtension($PolicyFilePath) -ine '.wfw') {
        throw "Firewall policy file does not use the expected .wfw format: $PolicyFilePath"
    }

    $resolvedPath = (Resolve-Path -LiteralPath $PolicyFilePath -ErrorAction Stop).ProviderPath
    $mountName = 'NoIDFirewall_' + [Guid]::NewGuid().ToString('N')
    $workingDirectory = Join-Path ([IO.Path]::GetTempPath()) $mountName
    $workingCopyPath = Join-Path $workingDirectory 'policy.wfw'
    $mountLoaded = $false
    $baseKey = $null
    $rootKey = $null
    try {
        $null = New-Item -ItemType Directory -Path $workingDirectory -Force -ErrorAction Stop
        Copy-Item -LiteralPath $resolvedPath -Destination $workingCopyPath -Force -ErrorAction Stop

        # reg.exe may create transaction-log sidecars and update hive metadata
        # even for a read-only RegistryKey handle. Always mount a disposable
        # copy so a sealed backup artifact remains byte-for-byte immutable.
        $loadResult = Invoke-AdvancedSecurityRegistryTool `
            -Operation Load -MountName $mountName -HivePath $workingCopyPath
        if ([int]$loadResult.ExitCode -ne 0) {
            throw "Unable to mount firewall policy hive (reg.exe exit $($loadResult.ExitCode)): $($loadResult.Output)"
        }
        $mountLoaded = $true

        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $rootKey = $baseKey.OpenSubKey($mountName, $false)
        if ($null -eq $rootKey) {
            throw "Mounted firewall policy hive is unavailable: HKLM\$mountName"
        }

        $entries = [System.Collections.Generic.List[object]]::new()
        function Read-FirewallPolicyKey {
            param(
                [Parameter(Mandatory = $true)]
                [Microsoft.Win32.RegistryKey]$Key,
                [AllowEmptyString()]
                [string]$RelativePath
            )

            try {
                $entries.Add([PSCustomObject]@{
                        Kind = 'Key'
                        Path = $RelativePath
                        Name = ''
                        Type = ''
                        Data = ''
                    })

                [string[]]$valueNames = @($Key.GetValueNames())
                [Array]::Sort($valueNames, [StringComparer]::Ordinal)
                foreach ($valueName in $valueNames) {
                    $valueKind = $Key.GetValueKind($valueName).ToString()
                    $rawValue = $Key.GetValue(
                        $valueName,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $canonicalData = switch ($valueKind) {
                        'Binary' {
                            [Convert]::ToBase64String([byte[]]$rawValue)
                            break
                        }
                        'Unknown' {
                            [Convert]::ToBase64String([byte[]]$rawValue)
                            break
                        }
                        'MultiString' {
                            ConvertTo-Json -InputObject @([string[]]$rawValue) -Compress
                            break
                        }
                        'DWord' {
                            $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$rawValue), 0)
                            $unsigned.ToString([Globalization.CultureInfo]::InvariantCulture)
                            break
                        }
                        'QWord' {
                            $unsigned = [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$rawValue), 0)
                            $unsigned.ToString([Globalization.CultureInfo]::InvariantCulture)
                            break
                        }
                        default { [string]$rawValue }
                    }
                    $entries.Add([PSCustomObject]@{
                            Kind = 'Value'
                            Path = $RelativePath
                            Name = [string]$valueName
                            Type = $valueKind
                            Data = [string]$canonicalData
                        })
                }

                [string[]]$subKeyNames = @($Key.GetSubKeyNames())
                [Array]::Sort($subKeyNames, [StringComparer]::Ordinal)
                foreach ($subKeyName in $subKeyNames) {
                    $subKey = $Key.OpenSubKey($subKeyName, $false)
                    if ($null -eq $subKey) {
                        throw "Unable to open firewall policy subkey: $RelativePath\$subKeyName"
                    }
                    $subPath = if ([string]::IsNullOrEmpty($RelativePath)) {
                        $subKeyName
                    }
                    else {
                        "$RelativePath\$subKeyName"
                    }
                    Read-FirewallPolicyKey -Key $subKey -RelativePath $subPath
                }
            }
            finally {
                if ($Key -ne $rootKey) { $Key.Dispose() }
            }
        }

        Read-FirewallPolicyKey -Key $rootKey -RelativePath ''
        return [PSCustomObject]@{
            SchemaVersion = 1
            EntryCount    = $entries.Count
            Entries       = @($entries)
        }
    }
    finally {
        if ($null -ne $rootKey) { $rootKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
        $rootKey = $null
        $baseKey = $null

        $unloadFailures = [System.Collections.Generic.List[string]]::new()
        if ($mountLoaded) {
            foreach ($attempt in 1..5) {
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
                $unloadResult = Invoke-AdvancedSecurityRegistryTool `
                    -Operation Unload -MountName $mountName
                if ([int]$unloadResult.ExitCode -eq 0 -and
                    -not (Test-AdvancedSecurityTemporaryFirewallHive -MountName $mountName)) {
                    $mountLoaded = $false
                    break
                }
                $failureText = if ([int]$unloadResult.ExitCode -eq 0) {
                    'reg.exe returned success but the mount is still present'
                }
                else {
                    "reg.exe exit $($unloadResult.ExitCode): $($unloadResult.Output)"
                }
                $unloadFailures.Add("attempt $attempt/5: $failureText")
                if ($attempt -lt 5) {
                    Start-Sleep -Milliseconds (200 * $attempt)
                }
            }
        }
        if (-not $mountLoaded -and (Test-Path -LiteralPath $workingDirectory)) {
            Remove-Item -LiteralPath $workingDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($mountLoaded) {
            throw "Unable to unload temporary firewall policy hive HKLM\$mountName after 5 attempts; " +
                "the recovery copy remains at '$workingDirectory'. $($unloadFailures -join ' | ')"
        }
    }
}

function Assert-AdvancedSecurityFirewallPolicyEquivalent {
    <#
    .SYNOPSIS
        Prove that two .wfw files represent the same complete firewall policy.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReferenceFilePath,
        [Parameter(Mandatory = $true)]
        [string]$CandidateFilePath,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Context = 'Firewall policy'
    )

    $reference = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $ReferenceFilePath
    $candidate = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $CandidateFilePath
    if ([int]$reference.SchemaVersion -ne 1 -or [int]$candidate.SchemaVersion -ne 1) {
        throw "$Context semantic snapshot schema is unsupported"
    }

    $referenceEntries = @($reference.Entries)
    $candidateEntries = @($candidate.Entries)
    if ([int]$reference.EntryCount -ne $referenceEntries.Count -or
        [int]$candidate.EntryCount -ne $candidateEntries.Count) {
        throw "$Context semantic snapshot count is internally inconsistent"
    }
    if ($referenceEntries.Count -ne $candidateEntries.Count) {
        throw "$Context entry count changed: expected $($referenceEntries.Count), got $($candidateEntries.Count)"
    }

    for ($index = 0; $index -lt $referenceEntries.Count; $index++) {
        $expected = $referenceEntries[$index]
        $actual = $candidateEntries[$index]
        foreach ($property in @('Kind', 'Path', 'Name', 'Type', 'Data')) {
            if ([string]$expected.$property -cne [string]$actual.$property) {
                $identity = "$([string]$expected.Path)::$([string]$expected.Name)"
                throw "$Context differs at entry $index ($identity), property $property"
            }
        }
    }
    return $true
}
