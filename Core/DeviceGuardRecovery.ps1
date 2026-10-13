#Requires -Version 5.1

<#
    The first native Device Guard Apply introduces state that 2.2.5 never
    captured. Retain its real prestate before mutation, independently of backup
    folder names, timestamps, receipts and verification intent. This immutable
    machine-local supplement undoes only that introduced boundary for historical
    restores; the requested backup still supplies all its own recorded values.
    Callers hold the framework mutation mutex. Ordinary new sessions continue
    to restore their own complete prestate, without consulting this supplement.
#>

function Get-NoIDDeviceGuardRecoveryPath {
    [CmdletBinding()]
    param()
    return (Join-Path (Split-Path (Get-NoIDIntentStatePath) -Parent) 'deviceguard-legacy-recovery.json')
}

function Get-NoIDDeviceGuardRecoveryByteHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-NoIDDeviceGuardRecoveryTextHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    return (Get-NoIDDeviceGuardRecoveryByteHash -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Text)))
}

function Assert-NoIDDeviceGuardRecoverySize {
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$ByteCount)
    if ($ByteCount -lt 0 -or $ByteCount -gt 134217728) {
        throw 'Device Guard recovery supplement exceeds the supported size'
    }
}

function Read-NoIDDeviceGuardRecovery {
    [CmdletBinding()]
    param()

    $path = Get-NoIDDeviceGuardRecoveryPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    # Reuse the reviewed EngineState ACL boundary, not the Apply-intent record.
    # Never repair an untrusted recovery file's permissions while reading it.
    $null = Assert-NoIDIntentStateAcl -StatePath $path
    Assert-NoIDDeviceGuardRecoverySize -ByteCount (Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length
    $record = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $null = Assert-NoIDIntentExactProperties -Object $record -Label 'Device Guard recovery' -Expected @(
        'SchemaVersion', 'Target', 'SourceManifestSha256', 'SourceRegistrySha256', 'SourceGpoSha256',
        'RegistryJson', 'RegistryJsonSha256', 'GpoJson', 'GpoJsonSha256'
    )
    if (($record.SchemaVersion -isnot [int] -and $record.SchemaVersion -isnot [long]) -or
        $record.SchemaVersion -ne 1 -or $record.Target -isnot [string] -or
        $record.Target -cne 'SecurityBaselineDeviceGuardLegacyRecovery') {
        throw 'Unsupported Device Guard recovery supplement contract'
    }
    foreach ($name in @('SourceManifestSha256', 'SourceRegistrySha256', 'SourceGpoSha256', 'RegistryJsonSha256', 'GpoJsonSha256')) {
        if ($record.$name -isnot [string] -or $record.$name -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Device Guard recovery supplement has an invalid evidence hash'
        }
    }
    foreach ($name in @('RegistryJson', 'GpoJson')) {
        $hashProperty = $name + 'Sha256'
        if ($record.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($record.$name) -or
            (Get-NoIDDeviceGuardRecoveryTextHash -Text $record.$name) -cne $record.$hashProperty) {
            throw 'Device Guard recovery supplement content hash differs'
        }
    }
    return $record
}

function Invoke-NoIDDeviceGuardRecoveryRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Record, [switch]$ValidateOnly)

    $private = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private'
    if (-not (Get-Command 'ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot' -ErrorAction SilentlyContinue)) {
        . (Join-Path $private 'SecurityBaselineDeviceGuardGpoStore.ps1')
    }
    if (-not (Get-Command 'Restore-RegistryPolicies' -ErrorAction SilentlyContinue)) {
        . (Join-Path $private 'Restore-RegistryPolicies.ps1')
    }
    $gpo = $Record.GpoJson | ConvertFrom-Json -ErrorAction Stop
    $nativeGpo = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $gpo
    if ($nativeGpo.RegistryEditorPresent -or $nativeGpo.DeviceGuardEditorPresent) {
        throw 'First Device Guard recovery prestate already contains NoID editor registrations'
    }

    # Existing exact-prestate readers remain the only replay implementation.
    # Scratch files inherit the protected EngineState ACL and are never treated
    # as recovery authority. A crash leaves only non-authoritative scratch data.
    $directory = Split-Path (Get-NoIDDeviceGuardRecoveryPath) -Parent
    $paths = [Collections.Generic.List[string]]::new()
    try {
        foreach ($name in @('Registry', 'Gpo')) {
            $path = Join-Path $directory ('deviceguard-replay-' + [Guid]::NewGuid().ToString('N') + '.tmp')
            $jsonProperty = $name + 'Json'
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Record.$jsonProperty)
            $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $paths.Add($path)
            try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
            finally { $stream.Dispose() }
            Set-NoIDIntentPathSecurity -Path $path -IsDirectory $false
            $null = Assert-NoIDIntentStateAcl -StatePath $path
        }
        $validation = Restore-RegistryPolicies -BackupPath $paths[0] -DeviceGuardLocalOnly -ValidateOnly
        if (-not $validation.Success) {
            throw "Device Guard recovery registry contract is invalid: $($validation.Errors -join '; ')"
        }
        if ($ValidateOnly) { return }
        if ($PSCmdlet.ShouldProcess('Device Guard changes introduced after historical backups', 'Restore recorded GPO and twenty local controls')) {
            $null = Restore-SecurityBaselineDeviceGuardGpo -BackupPath $paths[1] -Confirm:$false
            $recovery = Restore-RegistryPolicies -BackupPath $paths[0] -DeviceGuardLocalOnly -Confirm:$false
            if (-not $recovery.Success -or $recovery.ItemsVerified -ne 20) {
                throw "Device Guard local recovery failed: $($recovery.Errors -join '; ')"
            }
        }
    }
    finally {
        # A leftover scratch file is never recovery authority, so a failed
        # cleanup must not turn a verified replay (or its real error) into a
        # different failure.
        foreach ($path in $paths) {
            try { [IO.File]::Delete($path) }
            catch { Write-Warning "Device Guard replay scratch file could not be removed: $path ($($_.Exception.Message))" }
        }
    }
}

function Initialize-NoIDDeviceGuardRecovery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SessionPath)

    $existing = Read-NoIDDeviceGuardRecovery
    if ($existing) {
        Invoke-NoIDDeviceGuardRecoveryRecord -Record $existing -ValidateOnly
        return
    }
    $manifest = Get-SessionManifest -SessionPath $SessionPath
    Assert-SessionManifest -SessionPath $SessionPath -Manifest $manifest -RequestedModules @('SecurityBaseline')
    $module = @($manifest.modules | Where-Object { $_.name -eq 'SecurityBaseline' })
    if ($module.Count -ne 1) { throw 'Device Guard recovery requires one sealed SecurityBaseline module' }
    $artifacts = @($module[0].artifacts)
    $source = @{}
    foreach ($name in @('RegistryPolicies', 'DeviceGuardGpo')) {
        $entry = @($artifacts | Where-Object { $_.type -eq 'SecurityBaseline' -and $_.name -eq $name })
        if ($entry.Count -ne 1) { throw "Device Guard recovery requires one sealed $name artifact" }
        $path = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath $entry[0].relativePath
        $bytes = [IO.File]::ReadAllBytes($path)
        if ((Get-NoIDDeviceGuardRecoveryByteHash -Bytes $bytes) -ine $entry[0].sha256) {
            throw 'Device Guard recovery source changed after session validation'
        }
        $source[$name] = ([Text.UTF8Encoding]::new($false, $true).GetString($bytes)).TrimStart([char]0xfeff)
        $source[$name + 'Sha256'] = ([string]$entry[0].sha256).ToLowerInvariant()
    }
    . (Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Get-SecurityBaselineDeviceGuardPlan.ps1')
    $local = Select-SecurityBaselineDeviceGuardLocalRestoreSnapshot -RegistrySnapshot ($source.RegistryPolicies | ConvertFrom-Json -ErrorAction Stop)
    $registryJson = ConvertTo-Json -InputObject $local -Depth 20
    $record = [pscustomobject]@{
        SchemaVersion = 1
        Target = 'SecurityBaselineDeviceGuardLegacyRecovery'
        SourceManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $SessionPath 'manifest.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        SourceRegistrySha256 = $source.RegistryPoliciesSha256
        SourceGpoSha256 = $source.DeviceGuardGpoSha256
        RegistryJson = $registryJson
        RegistryJsonSha256 = Get-NoIDDeviceGuardRecoveryTextHash -Text $registryJson
        GpoJson = $source.DeviceGuardGpo
        GpoJsonSha256 = Get-NoIDDeviceGuardRecoveryTextHash -Text $source.DeviceGuardGpo
    }
    # The immutable record must satisfy the reader's byte limit before any
    # publication. Count the exact BOM-less UTF-8 content written below.
    $content = ConvertTo-Json -InputObject $record -Depth 6
    Assert-NoIDDeviceGuardRecoverySize -ByteCount ([Text.UTF8Encoding]::new($false).GetByteCount($content))
    $null = Initialize-NoIDIntentStateDirectory
    Invoke-NoIDDeviceGuardRecoveryRecord -Record $record -ValidateOnly
    $path = Get-NoIDDeviceGuardRecoveryPath
    if (Test-Path -LiteralPath $path) { throw 'Device Guard recovery supplement appeared during initialization' }
    $staging = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $null = Write-AtomicUtf8File -Path $staging -Content $content
        Set-NoIDIntentPathSecurity -Path $staging -IsDirectory $false
        $null = Assert-NoIDIntentStateAcl -StatePath $staging
        # Create-only publication: even a racing writer cannot replace the
        # first successful supplement. No later Apply refreshes its prestate.
        [IO.File]::Move($staging, $path)
    }
    finally { if ([IO.File]::Exists($staging)) { [IO.File]::Delete($staging) } }
    $published = Read-NoIDDeviceGuardRecovery
    if ($null -eq $published -or
        (ConvertTo-Json -InputObject $published -Depth 6 -Compress) -cne
        (ConvertTo-Json -InputObject $record -Depth 6 -Compress)) {
        throw 'Device Guard recovery supplement publication differs'
    }
}

function Restore-NoIDLegacyDeviceGuard {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $record = Read-NoIDDeviceGuardRecovery
    if (-not $record) {
        if (-not (Get-Command 'Get-SecurityBaselineDeviceGuardGpoSnapshot' -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\SecurityBaselineDeviceGuardGpoStore.ps1')
        }
        $current = Get-SecurityBaselineDeviceGuardGpoSnapshot
        if ($current.RegistryEditorPresent -or $current.DeviceGuardEditorPresent) {
            throw 'Recorded Device Guard recovery supplement is missing. Restore the complete newer SecurityBaseline backup first; historical backup files have not been changed.'
        }
        return $false
    }
    if ($PSCmdlet.ShouldProcess('Historical SecurityBaseline restore', 'Undo the introduced native Device Guard boundary')) {
        Invoke-NoIDDeviceGuardRecoveryRecord -Record $record -Confirm:$false
        return $true
    }
    return $false
}
