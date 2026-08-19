<#
.SYNOPSIS
    Backup and rollback functionality for NoID Privacy Framework

.DESCRIPTION
    Implements the BACKUP/APPLY/VERIFY/RESTORE pattern for safe system modifications.
    Creates backups before changes and provides rollback capabilities.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+
#>

# Global backup tracking (MUST be $global: for cross-module session sharing)
# Using $script: would create separate sessions per Import-Module call!
# IMPORTANT: Only initialize if not already set - prevents reset on re-load!
# NOTE: Must use Get-Variable to check existence (direct access fails in Strict Mode)
if (-not (Get-Variable -Name 'BackupIndex' -Scope Global -ErrorAction SilentlyContinue)) { $global:BackupIndex = @() }
if (-not (Get-Variable -Name 'BackupBasePath' -Scope Global -ErrorAction SilentlyContinue)) { $global:BackupBasePath = "" }
if (-not (Get-Variable -Name 'SessionManifest' -Scope Global -ErrorAction SilentlyContinue)) { $global:SessionManifest = @{} }
if (-not (Get-Variable -Name 'CurrentModule' -Scope Global -ErrorAction SilentlyContinue)) { $global:CurrentModule = "" }

function ConvertFrom-NoIDRoundtripTimestamp {
    [CmdletBinding()]
    [OutputType([DateTime])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    # Windows PowerShell 5.1 keeps JSON timestamps as strings. PowerShell
    # 7.5+ may materialize the same JSON token as DateTime before validation.
    # Accept those two representations only; never parse using current culture.
    if ($Value -is [DateTime]) { return [DateTime]$Value }
    try {
        return [DateTime]::ParseExact(
            [string]$Value,
            'o',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch { throw "$Context timestamp is invalid: $Value" }
}

function Get-NoIDSecurityBaselineOverlapModule {
    <#
    .SYNOPSIS
        Modules that write into registry keys SecurityBaseline also owns.
    .DESCRIPTION
        Single source of truth for the two places that must agree: the partial-restore
        LIFO guard in Assert-SessionManifest and the combined-prestate reconstruction
        in Restore-Session. They disagreed - the guard named only ASR while the
        prestate logic enumerated ASR and DNS - so restoring SecurityBaseline without
        a later DNS module passed validation and then failed mid-restore on
        HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient, which both modules
        write. Adding a third overlapping module here now updates both sites at once.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return [string[]]@('ASR', 'DNS')
}

function Assert-NoIDSecurityBaselineOverlapRestore {
    <#
    .SYNOPSIS
        Enforce LIFO ownership for a partial restore that includes SecurityBaseline.
    .DESCRIPTION
        Pure decision, kept separate from Assert-SessionManifest so it can be
        asserted by value instead of by searching Rollback.ps1 for a literal error
        string - a check a comment satisfies just as well as a working guard.
    .PARAMETER SessionModuleNames
        Module names sealed in the manifest, in sealed order.
    .PARAMETER RequestedModules
        Modules the caller asked to restore. Empty means "the whole session",
        which can never be a partial restore and is always allowed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$SessionModuleNames,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$RequestedModules
    )

    if ($RequestedModules.Count -eq 0 -or 'SecurityBaseline' -notin $RequestedModules) {
        return
    }
    if ('SecurityBaseline' -notin $SessionModuleNames) {
        return
    }

    foreach ($overlapModule in (Get-NoIDSecurityBaselineOverlapModule)) {
        if ($overlapModule -in $SessionModuleNames -and $overlapModule -notin $RequestedModules) {
            throw "SecurityBaseline overlaps the later $overlapModule module; restore $overlapModule with it or restore neither"
        }
    }
}

function ConvertTo-NativeRegistryPath {
    <#
    .SYNOPSIS
        Converts one exact PowerShell Registry-provider path to reg.exe syntax.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $match = [regex]::Match(
        $Path,
        '^(HKLM|HKCU|HKCR|HKU|HKCC):\\(.*)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw "Registry path is not a supported absolute PowerShell provider path: $Path"
    }

    $relativePath = [string]$match.Groups[2].Value
    if ($relativePath.Contains('\\') -or
        $relativePath.Contains('/') -or
        $relativePath.EndsWith('\', [StringComparison]::Ordinal) -or
        $relativePath.IndexOfAny([char[]]@('*', '?', '[', ']')) -ge 0) {
        throw "Registry path is not one exact canonical key path: $Path"
    }

    $nativeRoot = switch ($match.Groups[1].Value.ToUpperInvariant()) {
        'HKLM' { 'HKEY_LOCAL_MACHINE' }
        'HKCU' { 'HKEY_CURRENT_USER' }
        'HKCR' { 'HKEY_CLASSES_ROOT' }
        'HKU'  { 'HKEY_USERS' }
        'HKCC' { 'HKEY_CURRENT_CONFIG' }
        default { throw "Unsupported Registry-provider drive: $($match.Groups[1].Value)" }
    }
    if ([string]::IsNullOrEmpty($relativePath)) { return $nativeRoot }
    return "$nativeRoot\$relativePath"
}

function ConvertFrom-NativeRegistryPath {
    <#
    .SYNOPSIS
        Converts one exact reg.exe registry path to PowerShell provider syntax.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $match = [regex]::Match(
        $Path,
        '^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(?:\\(.*))?$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw "Registry path is not a supported absolute reg.exe path: $Path"
    }

    $relativePath = [string]$match.Groups[2].Value
    if ($relativePath.Contains('\\') -or
        $relativePath.Contains('/') -or
        $relativePath.EndsWith('\', [StringComparison]::Ordinal) -or
        $relativePath.IndexOfAny([char[]]@('*', '?', '[', ']')) -ge 0) {
        throw "Registry path is not one exact canonical key path: $Path"
    }

    $providerDrive = switch ($match.Groups[1].Value.ToUpperInvariant()) {
        'HKEY_LOCAL_MACHINE'  { 'HKLM' }
        'HKEY_CURRENT_USER'   { 'HKCU' }
        'HKEY_CLASSES_ROOT'   { 'HKCR' }
        'HKEY_USERS'          { 'HKU' }
        'HKEY_CURRENT_CONFIG' { 'HKCC' }
        default { throw "Unsupported native registry hive: $($match.Groups[1].Value)" }
    }
    if ([string]::IsNullOrEmpty($relativePath)) { return "$($providerDrive):\" }
    return "$($providerDrive):\$relativePath"
}

function Initialize-BackupSystem {
    <#
    .SYNOPSIS
        Initialize the backup system

    .PARAMETER BackupDirectory
        Directory path for storing backups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = (Join-Path $PSScriptRoot "..\Backups")
    )

    # Create backup directory if it doesn't exist
    if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force -ErrorAction Stop | Out-Null
    }

    # Reuse existing session if already initialized
    if ($global:BackupBasePath -and (Test-Path -LiteralPath $global:BackupBasePath -PathType Container)) {
        $activeSessionLeaf = Split-Path ([System.IO.Path]::GetFullPath($global:BackupBasePath).TrimEnd('\', '/')) -Leaf
        if (-not $global:SessionManifest -or
            [int]$global:SessionManifest.schemaVersion -ne 2 -or
            [string]$global:SessionManifest.sessionId -ne $activeSessionLeaf -or
            -not [bool]$global:SessionManifest.restorable) {
            throw 'Active backup session state is inconsistent and cannot be reused'
        }
        Write-Log -Level DEBUG -Message "Backup system already initialized, reusing session: $global:BackupBasePath" -Module "Rollback"
        return $true
    }

    # Create session-specific backup folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $sessionNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $sessionId = "Session_${timestamp}_$sessionNonce"
    $sessionBackupPath = Join-Path $BackupDirectory $sessionId
    New-Item -ItemType Directory -Path $sessionBackupPath -ErrorAction Stop | Out-Null

    # Normalize path for clean log output (removes ..\)
    $global:BackupBasePath = [System.IO.Path]::GetFullPath($sessionBackupPath)
    $global:BackupIndex = @()
    $global:CurrentModule = ''

    # Read framework version via the canonical single-source helper
    # (Get-FrameworkVersion in Core/Config.ps1, loaded before this file in
    # Framework.ps1's module chain) so the VERSION file is validated
    # identically everywhere instead of via a second, divergent regex.
    $frameworkVersionValue = Get-FrameworkVersion

    # Initialize session manifest
    $global:SessionManifest = @{
        schemaVersion    = 2
        sessionId        = $sessionId
        displayName      = ""                    # Auto-generated based on modules
        sessionType      = "unknown"             # wizard | advanced | manual
        timestamp        = Get-Date -Format "o"
        frameworkVersion = $frameworkVersionValue
        modules          = @()
        sharedArtifacts  = @()
        totalItems       = 0
        restorable       = $true
    }

    Write-Log -Level INFO -Message "Backup system initialized: $global:BackupBasePath" -Module "Rollback"

    return $true
}

function Mount-UserRegistryHiveForRestore {
    <#
    .SYNOPSIS
        Makes an original user's NTUSER.DAT available under HKEY_USERS\SID.

    .DESCRIPTION
        A BAVR session may be restored after the original desktop user signed
        out. In that case Windows has unloaded HKEY_USERS\SID even though the
        sealed backup still owns values in that hive. This helper resolves the
        OS-maintained ProfileList entry and temporarily loads that exact hive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    if ($Sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') {
        throw "Refusing invalid user SID for registry-hive restore: $Sid"
    }
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        # A drive created in this function's local scope disappears on return,
        # while the restore consumers deliberately use HKU:\ paths afterwards.
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction Stop
    }

    $nativeRoot = "Registry::HKEY_USERS\$Sid"
    if (Test-Path -LiteralPath $nativeRoot -PathType Container) {
        return [PSCustomObject]@{ Sid=$Sid; Temporary=$false; Root="HKU:\$Sid" }
    }

    $profileListPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    if (-not (Test-Path -LiteralPath $profileListPath -PathType Container)) {
        throw "Windows ProfileList has no profile for original restore SID $Sid"
    }
    $profileKey = Get-Item -LiteralPath $profileListPath -ErrorAction Stop
    try {
        if ($profileKey.GetValueNames() -notcontains 'ProfileImagePath') {
            throw "Windows ProfileList entry has no ProfileImagePath for original restore SID $Sid"
        }
        $rawProfilePath = [string]$profileKey.GetValue(
            'ProfileImagePath',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    finally {
        if ($profileKey -is [System.IDisposable]) { $profileKey.Dispose() }
    }
    $profilePath = [Environment]::ExpandEnvironmentVariables($rawProfilePath)
    if ([string]::IsNullOrWhiteSpace($profilePath)) {
        throw "Windows ProfileList contains an empty profile path for original restore SID $Sid"
    }
    $hiveFile = Join-Path $profilePath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $hiveFile -PathType Leaf)) {
        throw "NTUSER.DAT is unavailable for original restore SID $Sid"
    }

    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    if (-not (Test-Path -LiteralPath $regExe -PathType Leaf)) {
        throw 'Windows reg.exe is unavailable for temporary user-hive loading'
    }
    $nativeOutput = @(& $regExe load "HKU\$Sid" $hiveFile 2>&1)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $nativeRoot -PathType Container)) {
        $detail = ($nativeOutput | ForEach-Object { [string]$_ }) -join ' '
        throw "Temporary user-hive load failed for SID $Sid (exit $LASTEXITCODE): $detail"
    }

    return [PSCustomObject]@{ Sid=$Sid; Temporary=$true; Root="HKU:\$Sid" }
}

function Dismount-UserRegistryHiveAfterRestore {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Mount
    )

    if (-not [bool]$Mount.Temporary) { return $true }
    $sid = [string]$Mount.Sid
    if ($sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') { return $false }

    # Release transient RegistryKey objects before asking Configuration Manager
    # to unload the hive. A still-open handle must fail the restore explicitly.
    if (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name HKU -Force -ErrorAction SilentlyContinue
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    $nativeOutput = @(& $regExe unload "HKU\$sid" 2>&1)
    $exitCode = $LASTEXITCODE
    $stillLoaded = Test-Path -LiteralPath "Registry::HKEY_USERS\$sid" -PathType Container
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0 -or $stillLoaded) {
        $detail = ($nativeOutput | ForEach-Object { [string]$_ }) -join ' '
        Write-Log -Level ERROR -Message "Temporary user-hive unload failed for SID $sid (exit $exitCode): $detail" -Module 'Rollback'
        return $false
    }
    return $true
}

function Set-SessionType {
    <#
    .SYNOPSIS
        Set the session type for better identification in restore UI

    .PARAMETER SessionType
        Type of session: wizard, advanced, manual, or unknown
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("wizard", "advanced", "manual", "unknown")]
        [string]$SessionType
    )

    if (-not $PSCmdlet.ShouldProcess('SessionManifest', "Set sessionType=$SessionType")) {
        return
    }

    if ($global:SessionManifest) {
        $global:SessionManifest.sessionType = $SessionType
        Write-Log -Level DEBUG -Message "Session type set to: $SessionType" -Module "Rollback"
    }
}

function Update-SessionDisplayName {
    <#
    .SYNOPSIS
        Auto-generate a user-friendly display name based on session type and modules
        Should be called after all modules are backed up
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param()

    if (-not $PSCmdlet.ShouldProcess('SessionManifest', 'Update displayName from module list')) {
        return
    }

    if (-not $global:SessionManifest) { return }

    $displayName = Get-SessionDisplayNameValue -Manifest $global:SessionManifest

    $global:SessionManifest.displayName = $displayName
    Write-Log -Level INFO -Message "Session display name: $displayName" -Module "Rollback"

    # Update manifest file
    $manifestPath = Join-Path $global:BackupBasePath "manifest.json"
    if (Test-Path $manifestPath) {
        if (-not (Write-ActiveSessionManifest)) {
            throw 'Failed to persist session display name'
        }
    }
}

function Get-SessionDisplayNameValue {
    <#
    .SYNOPSIS
        Derive a stable, human-readable identity from the sealed module set.

    .DESCRIPTION
        This helper is deliberately side-effect free so Complete-ModuleBackup can
        put the name into the same atomic manifest write that seals the module.
        Every valid session therefore has both its collision-resistant session ID
        and a description of what the backup actually contains.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    $moduleNames = @($Manifest.modules | ForEach-Object { [string]$_.name })
    $moduleCount = $moduleNames.Count
    $sessionType = if ($Manifest -is [System.Collections.IDictionary] -and $Manifest.Contains('sessionType')) {
        [string]$Manifest['sessionType']
    }
    elseif ($Manifest.PSObject.Properties['sessionType']) {
        [string]$Manifest.sessionType
    }
    else {
        'unknown'
    }

    # Declared setting counts are deliberately excluded: optional or
    # NotApplicable targets would make such a number look like an artifact count.
    if ($moduleCount -eq 0) {
        return 'Empty session (not restorable)'
    }
    if ($sessionType -eq 'wizard') {
        if ($moduleCount -ge 7) {
            return "Full hardening backup ($moduleCount modules)"
        }
        if ($moduleCount -ge 4) {
            return "Wizard backup: $moduleCount modules"
        }
        return "Wizard backup: $(($moduleNames | Select-Object -First 3) -join ', ')"
    }
    if ($sessionType -eq 'advanced') {
        if ($moduleCount -gt 3) {
            return "Advanced backup: $moduleCount modules"
        }
        return "Advanced backup: $($moduleNames -join ', ')"
    }

    $short = ($moduleNames | Select-Object -First 3) -join ', '
    if ($moduleCount -gt 3) { $short += ', ...' }
    return "Backup: $short"
}

function Write-AtomicUtf8File {
    <#
    .SYNOPSIS
        Durably write a UTF-8 file and atomically publish it in the same directory.

    .DESCRIPTION
        Session manifests and incomplete-retention records are trust anchors.
        The temporary file is flushed to stable storage before an atomic rename
        or replace, so interruption cannot expose a partially written JSON file.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path $fullPath -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Atomic-file parent directory does not exist: $parent"
    }

    $temporaryPath = "$fullPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $replacementBackupPath = $null
    $stream = $null
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if ([System.IO.File]::Exists($fullPath)) {
            # File.Replace requires a non-empty backup path on Unix .NET, while
            # Windows PowerShell accepts null. Use one deterministic contract on
            # both runtimes and remove the transient replacement backup below.
            $replacementBackupPath = "$fullPath.$([Guid]::NewGuid().ToString('N')).replace-backup"
            [System.IO.File]::Replace($temporaryPath, $fullPath, $replacementBackupPath, $true)
            [System.IO.File]::Delete($replacementBackupPath)
            $replacementBackupPath = $null
        }
        else {
            [System.IO.File]::Move($temporaryPath, $fullPath)
        }
        $temporaryPath = $null
        return $true
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($temporaryPath -and [System.IO.File]::Exists($temporaryPath)) {
            try {
                [System.IO.File]::Delete($temporaryPath)
            }
            catch {
                Write-Log -Level WARNING -Message "Temporary atomic file could not be removed: $($_.Exception.Message)" -Module 'Rollback'
            }
        }
        if ($replacementBackupPath -and [System.IO.File]::Exists($replacementBackupPath)) {
            try {
                [System.IO.File]::Delete($replacementBackupPath)
            }
            catch {
                Write-Log -Level WARNING -Message "Temporary replacement backup could not be removed: $($_.Exception.Message)" -Module 'Rollback'
            }
        }
    }
}

function Start-ModuleBackup {
    <#
    .SYNOPSIS
        Start backup for a specific module

    .PARAMETER ModuleName
        Name of the module (e.g., SecurityBaseline, ASR)

    .OUTPUTS
        String - Path to the module backup folder
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity")]
        [string]$ModuleName
    )

    if (-not $PSCmdlet.ShouldProcess($ModuleName, 'Start backup folder + register in session')) {
        return $null
    }

    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:CurrentModule)) {
        throw "Cannot start $ModuleName backup while $global:CurrentModule backup is still active"
    }
    if (@($global:SessionManifest.modules | Where-Object { $_.name -eq $ModuleName }).Count -gt 0) {
        throw "Module backup is already sealed in this session: $ModuleName"
    }

    # Create module subfolder
    $moduleBackupPath = Join-Path $global:BackupBasePath $ModuleName
    if (-not (Test-Path -LiteralPath $moduleBackupPath -PathType Container)) {
        New-Item -ItemType Directory -Path $moduleBackupPath -ErrorAction Stop | Out-Null
    }

    $global:CurrentModule = $ModuleName

    Write-Log -Level INFO -Message "Started backup for module: $ModuleName" -Module "Rollback"

    # Return the module backup path
    return $moduleBackupPath
}

function Complete-ModuleBackup {
    <#
    .SYNOPSIS
        Complete backup for a module and update session manifest

    .DESCRIPTION
        Finalizes the backup process for the current module.
        Updates the session manifest.json with module statistics.
        This is CRITICAL for the Restore-Session function to work.

    .PARAMETER ItemsBackedUp
        Number of items successfully backed up

    .PARAMETER Status
        Status of the backup. Only a successfully sealed module may be added
        to the active restorable session; incomplete modules are detached by
        Save-IncompleteModuleBackup.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ItemsBackedUp,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Success")]
        [string]$Status
    )

    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }

    if ([string]::IsNullOrEmpty($global:CurrentModule)) {
        Write-Log -Level WARNING -Message "No active module backup to complete" -Module "Rollback"
        return $false
    }

    $completedModule = $global:CurrentModule
    $sessionRoot = [System.IO.Path]::GetFullPath($global:BackupBasePath).TrimEnd('\', '/')
    $sessionPrefix = $sessionRoot + [System.IO.Path]::DirectorySeparatorChar
    $moduleArtifacts = @()

    foreach ($entry in @($global:BackupIndex | Where-Object { $_.Module -eq $completedModule })) {
        $artifactPath = [System.IO.Path]::GetFullPath([string]$entry.BackupFile)
        if (-not $artifactPath.StartsWith($sessionPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Log -Level ERROR -Message "Refusing to register backup artifact outside session: $artifactPath" -Module "Rollback"
            return $false
        }
        $artifactInfo = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
        if ($artifactInfo.PSIsContainer -or
            [bool]($artifactInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Write-Log -Level ERROR -Message "Refusing non-file or reparse-point backup artifact: $artifactPath" -Module 'Rollback'
            return $false
        }

        $relativePath = $artifactPath.Substring($sessionPrefix.Length)
        $target = if ($entry.PSObject.Properties['Path']) { [string]$entry.Path }
            elseif ($entry.PSObject.Properties['ServiceName']) { [string]$entry.ServiceName }
            elseif ($entry.PSObject.Properties['TaskPath']) {
                $taskFolder = [string]$entry.TaskPath
                if (-not $taskFolder.EndsWith('\')) { $taskFolder += '\' }
                $taskFolder + [string]$entry.TaskName
            }
            else { $null }
        $moduleArtifacts += [PSCustomObject]@{
            type         = [string]$entry.Type
            name         = [string]$entry.Name
            relativePath = $relativePath
            target       = $target
            sha256       = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
    }

    if ($ItemsBackedUp -lt 1 -or $moduleArtifacts.Count -ne $ItemsBackedUp) {
        Write-Log -Level ERROR -Message "Cannot seal $completedModule backup: declared items=$ItemsBackedUp, artifacts=$($moduleArtifacts.Count)" -Module 'Rollback'
        return $false
    }
    if (@($global:SessionManifest.modules | Where-Object { $_.name -eq $completedModule }).Count -gt 0) {
        Write-Log -Level ERROR -Message "Cannot seal duplicate module record: $completedModule" -Module 'Rollback'
        return $false
    }
    $duplicatePaths = @($moduleArtifacts | Group-Object relativePath | Where-Object { $_.Count -gt 1 })
    if ($duplicatePaths.Count -gt 0) {
        Write-Log -Level ERROR -Message "Cannot seal $completedModule backup: duplicate artifact paths" -Module 'Rollback'
        return $false
    }

    # Update Manifest Object
    $moduleData = @{
        name          = $completedModule
        backupPath    = $completedModule
        itemsBackedUp = $ItemsBackedUp
        status        = $Status
        timestamp     = Get-Date -Format "o"
        artifacts     = $moduleArtifacts
    }

    $previousModules = @($global:SessionManifest.modules)
    $previousTotalItems = [int]$global:SessionManifest.totalItems
    $previousRestorable = [bool]$global:SessionManifest.restorable
    $previousDisplayName = [string]$global:SessionManifest.displayName
    $global:SessionManifest.modules = @($previousModules + $moduleData)
    $global:SessionManifest.totalItems = $previousTotalItems + $ItemsBackedUp
    $global:SessionManifest.displayName = Get-SessionDisplayNameValue -Manifest $global:SessionManifest

    # Write Manifest to Disk (robust against transient file locks)
    $manifestPath = Join-Path $global:BackupBasePath "manifest.json"
    $maxAttempts = 5
    $attempt = 0
    $delayMs = 200
    $manifestWritten = $false
    while ($attempt -lt $maxAttempts) {
        try {
            $attempt++
            $json = $global:SessionManifest | ConvertTo-Json -Depth 10
            $null = Write-AtomicUtf8File -Path $manifestPath -Content $json
            $manifestWritten = $true
            Write-Log -Level INFO -Message "Completed backup for $completedModule (Items: $ItemsBackedUp, Status: $Status). Manifest updated." -Module "Rollback"
            break
        }
        catch [System.IO.IOException] {
            if ($attempt -ge $maxAttempts) {
                Write-Log -Level ERROR -Message "Failed to write session manifest after $maxAttempts attempts: $_" -Module "Rollback"
                break
            }
            Start-Sleep -Milliseconds $delayMs
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to write session manifest: $_" -Module "Rollback"
            break
        }
    }
    if (-not $manifestWritten) {
        $global:SessionManifest.modules = $previousModules
        $global:SessionManifest.totalItems = $previousTotalItems
        $global:SessionManifest.restorable = $previousRestorable
        $global:SessionManifest.displayName = $previousDisplayName
        return $false
    }

    $global:CurrentModule = ""
    return $true
}

function Write-ActiveSessionManifest {
    <#
    .SYNOPSIS
        Atomically persist the current in-memory sealed-session manifest.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ([string]::IsNullOrWhiteSpace([string]$global:BackupBasePath) -or -not $global:SessionManifest) {
        return $false
    }
    $manifestPath = Join-Path $global:BackupBasePath 'manifest.json'
    try {
        $json = $global:SessionManifest | ConvertTo-Json -Depth 10
        $null = Write-AtomicUtf8File -Path $manifestPath -Content $json
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to persist active session manifest: $($_.Exception.Message)" -Module 'Rollback'
        return $false
    }
}

function Save-IncompleteModuleBackup {
    <#
    .SYNOPSIS
        Retain an active, unsealed module backup after Backup failed before Apply.

    .DESCRIPTION
        A failed Backup phase must never silently erase artifacts that were
        already captured. The incomplete module directory is detached from the
        still-usable active session, sealed with an informational hash inventory,
        and retained as its own visible, explicitly non-restorable session.

        Detaching is important: one failed module must not invalidate earlier
        successfully sealed modules in the active BAVR session.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity")]
        [string]$ModuleName
    )

    if ([string]$global:CurrentModule -ne $ModuleName) {
        return $true
    }
    if (@($global:SessionManifest.modules | Where-Object { [string]$_.name -eq $ModuleName }).Count -gt 0) {
        Write-Log -Level ERROR -Message "Refusing to detach a sealed module backup: $ModuleName" -Module 'Rollback'
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($ModuleName, 'Retain incomplete backup as a separate non-restorable session')) {
        return $false
    }

    $detachedSessionPath = $null
    $moduleDetached = $false
    try {
        $activeSessionPath = [System.IO.Path]::GetFullPath([string]$global:BackupBasePath).TrimEnd('\', '/')
        if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Container)) {
            throw 'Active backup session directory is unavailable'
        }
        $sourceSessionId = Split-Path $activeSessionPath -Leaf
        $backupDirectory = Split-Path $activeSessionPath -Parent
        $modulePath = Resolve-SessionChildPath -SessionPath $activeSessionPath -RelativePath $ModuleName

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
        $sessionNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $detachedSessionId = "Session_${timestamp}_${sessionNonce}_Incomplete_$ModuleName"
        $detachedSessionPath = Join-Path $backupDirectory $detachedSessionId
        $detachedModulePath = Join-Path $detachedSessionPath $ModuleName
        New-Item -ItemType Directory -Path $detachedSessionPath -ErrorAction Stop | Out-Null

        if (Test-Path -LiteralPath $modulePath -PathType Container) {
            Move-Item -LiteralPath $modulePath -Destination $detachedModulePath -ErrorAction Stop
        }
        else {
            New-Item -ItemType Directory -Path $detachedModulePath -ErrorAction Stop | Out-Null
        }
        $moduleDetached = $true

        $detachedPrefix = $detachedSessionPath.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $files = @()
        $pendingDirectories = [System.Collections.Generic.Queue[string]]::new()
        $pendingDirectories.Enqueue($detachedModulePath)
        while ($pendingDirectories.Count -gt 0) {
            $currentDirectory = $pendingDirectories.Dequeue()
            foreach ($file in @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)) {
                if ([bool]($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw "Retained incomplete backup contains a reparse point: $($file.FullName)"
                }
                if ($file.PSIsContainer) {
                    $pendingDirectories.Enqueue($file.FullName)
                    continue
                }
                $fullPath = [System.IO.Path]::GetFullPath($file.FullName)
                if (-not $fullPath.StartsWith($detachedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Detached backup file escapes retained session: $fullPath"
                }
                $files += [PSCustomObject]@{
                    relativePath = $fullPath.Substring($detachedPrefix.Length)
                    length       = [long]$file.Length
                    sha256       = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                }
            }
        }

        $retentionRecord = [ordered]@{
            schemaVersion = 1
            recordType    = 'IncompleteModuleBackup'
            sessionId     = $detachedSessionId
            displayName   = "Incomplete backup: $ModuleName"
            moduleName    = $ModuleName
            timestamp     = Get-Date -Format 'o'
            status        = 'IncompleteNonRestorable'
            reason        = 'Backup did not complete before Apply. Captured files were retained, but this record cannot authorize Restore.'
            sourceSessionId = $sourceSessionId
            fileCount     = $files.Count
            files         = $files
        }
        $markerPath = Join-Path $detachedSessionPath 'incomplete-backup.json'
        $json = $retentionRecord | ConvertTo-Json -Depth 8
        $null = Write-AtomicUtf8File -Path $markerPath -Content $json

        # The detached record owns these failed-module entries now. The active
        # session continues to own only its successfully sealed modules.
        $global:BackupIndex = @($global:BackupIndex | Where-Object { [string]$_.Module -ne $ModuleName })
        $global:CurrentModule = ''
        Write-Log -Level WARNING -Message "Retained incomplete $ModuleName backup as visible non-restorable session: $detachedSessionPath" -Module 'Rollback'
        return $true
    }
    catch {
        # Never undo the retention move. If marker creation failed after the
        # module was detached, the directory still remains visible as invalid.
        if ($moduleDetached) {
            $global:BackupIndex = @($global:BackupIndex | Where-Object { [string]$_.Module -ne $ModuleName })
            $global:CurrentModule = ''
        }
        Write-Log -Level ERROR -Message "Could not fully classify retained incomplete backup for ${ModuleName}: $($_.Exception.Message). Files were not deleted; retained path: $detachedSessionPath" -Module 'Rollback'
        return $false
    }
}

function Backup-RegistryKey {
    <#
    .SYNOPSIS
        Backup a registry key before modification

    .PARAMETER KeyPath
        Registry key path (e.g., "HKLM:\SOFTWARE\Policies\Microsoft\Windows")

    .PARAMETER BackupName
        Descriptive name for this backup

    .OUTPUTS
        System.String. Returns the exact .reg backup path, or the exact
        absent-key marker path. Returns null on a query/export/marker failure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupName
    )

    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }

    try {
        # Sanitize backup name for filename
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'

        # Save to current module folder if active, otherwise root
        $backupFolder = if ($global:CurrentModule) {
            Join-Path $global:BackupBasePath $global:CurrentModule
        }
        else {
            $global:BackupBasePath
        }

        $backupFile = Join-Path $backupFolder "$safeBackupName`_Registry.reg"

        # Convert the exact PowerShell provider target to reg.exe format.
        $regPath = ConvertTo-NativeRegistryPath -Path $KeyPath

        # Pre-flight: locale-independent key-existence check (avoids reg.exe stderr regex)
        $keyExistsBeforeExport = $true
        try {
            $keyExistsBeforeExport = Test-Path -LiteralPath $KeyPath -ErrorAction Stop
        }
        catch {
            # Test-Path itself failed (rare); fall through to reg.exe and let exit-code path handle it
            Write-Log -Level DEBUG -Message "Test-Path probe failed for ${KeyPath}: $($_.Exception.Message)" -Module "Rollback"
        }

        # Use unique temp files to prevent race conditions
        $guid = [Guid]::NewGuid().ToString()
        $stdoutFile = Join-Path $env:TEMP "reg_export_stdout_$guid.txt"
        $stderrFile = Join-Path $env:TEMP "reg_export_stderr_$guid.txt"

        # Export registry key using Start-Process for better error handling
        $process = Start-Process -FilePath "reg.exe" `
            -ArgumentList "export", "`"$regPath`"", "`"$backupFile`"", "/y" `
            -Wait `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        # Cleanup temp files
        $errorOutput = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue

        if ($process.ExitCode -eq 0) {
            $exportContent = Get-Content -LiteralPath $backupFile -Raw -ErrorAction Stop
            $exportHeaders = @([regex]::Matches($exportContent, '(?m)^\[(HKEY[^\]]+)\]\s*$') |
                ForEach-Object { [string]$_.Groups[1].Value })
            if ($exportHeaders.Count -eq 0 -or
                -not $exportHeaders[0].Equals($regPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Registry export root does not match requested target: expected '$regPath'"
            }
            foreach ($exportHeader in $exportHeaders) {
                if (-not ($exportHeader.Equals($regPath, [StringComparison]::OrdinalIgnoreCase) -or
                        $exportHeader.StartsWith("$regPath\", [StringComparison]::OrdinalIgnoreCase))) {
                    throw "Registry export contains a key outside requested target: $exportHeader"
                }
            }
            Write-Log -Level SUCCESS -Message "Registry backup created: $BackupName" -Module "Rollback"

            # Add to backup index
            $global:BackupIndex += [PSCustomObject]@{
                Type       = "Registry"
                Name       = $BackupName
                Module     = $global:CurrentModule
                Path       = $KeyPath
                BackupFile = $backupFile
                Timestamp  = Get-Date
            }

            return $backupFile
        }
        else {
            # Key simply doesn't exist (normal when creating new keys). Test-Path is locale-independent;
            # the legacy English/German stderr regex remains as a safety net for edge cases where Test-Path failed.
            if (-not $keyExistsBeforeExport -or $errorOutput -match "nicht gefunden|cannot find|not found|introuvable|no se encuentra|impossibile trovare|\u898b\u3064\u304b") {
                # Key doesn't exist - CREATE EMPTY MARKER so restore knows to DELETE this key
                Write-Log -Level INFO -Message "Registry key does not exist (will create empty marker): $BackupName" -Module "Rollback"

                try {
                    $emptyMarker = @{
                        SchemaVersion = 2
                        KeyPath    = $KeyPath
                        BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        State      = "NotExisted"
                        Message    = "Registry key did not exist before hardening - must be deleted during restore"
                    } | ConvertTo-Json

                    $markerFile = Join-Path $backupFolder "$safeBackupName`_EMPTY.json"
                    [System.IO.File]::WriteAllText($markerFile, $emptyMarker, [System.Text.UTF8Encoding]::new($false))
                    $markerRoundTrip = Get-Content -LiteralPath $markerFile -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    if ([int]$markerRoundTrip.SchemaVersion -ne 2 -or
                        [string]$markerRoundTrip.State -ne 'NotExisted' -or
                        [string]$markerRoundTrip.KeyPath -cne $KeyPath) {
                        throw "Empty-marker backup failed round-trip validation: $KeyPath"
                    }

                    Write-Log -Level SUCCESS -Message "Empty marker created for non-existent key: $BackupName" -Module "Rollback"

                    # Add to backup index
                    $global:BackupIndex += [PSCustomObject]@{
                        Type       = "EmptyMarker"
                        Name       = $BackupName
                        Module     = $global:CurrentModule
                        Path       = $KeyPath
                        BackupFile = $markerFile
                        Timestamp  = Get-Date
                    }

                    return $markerFile
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not create empty marker for ${BackupName}: $($_.Exception.Message)" -Module "Rollback"
                    return $null
                }
            }
            else {
                # Actual error
                Write-Log -Level WARNING -Message "Registry backup may have failed: $errorOutput" -Module "Rollback"
                return $null
            }
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to backup registry key: $KeyPath" -Module "Rollback" -ErrorRecord $_
        return $null
    }
}

function Backup-ServiceConfiguration {
    <#
    .SYNOPSIS
        Backup service configuration before modification

    .PARAMETER ServiceName
        Name of the service

    .PARAMETER BackupName
        Optional descriptive name for this backup. If not provided, uses ServiceName.

    .OUTPUTS
        Structured Success/Exists/BackupFile result. Query or backup errors
        are distinct from legitimate target absence.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $false)]
        [string]$BackupName,

        [Parameter(Mandatory = $false)]
        [switch]$StartupOnly
    )

    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }

    # Use ServiceName as BackupName if not provided
    if ([string]::IsNullOrEmpty($BackupName)) {
        $BackupName = $ServiceName
    }

    try {
        # Enumerating the provider once distinguishes a legitimate absent
        # service from a provider/query failure. Get-Service -Name conflates
        # those two outcomes in its exception contract.
        $serviceMatches = @(Get-Service -ErrorAction Stop | Where-Object {
                [string]$_.Name -ceq $ServiceName
            })
        if ($serviceMatches.Count -gt 1) {
            throw "Service identity is ambiguous during backup: $ServiceName"
        }
        if ($serviceMatches.Count -eq 0) {
            Write-Log -Level DEBUG -Message "Service is not installed; no backup or mutation required: $ServiceName" -Module 'Rollback'
            return [PSCustomObject]@{
                Success = $true
                Exists = $false
                BackupFile = ''
                Error = ''
            }
        }
        $service = $serviceMatches[0]
        $stableServiceStates = @('Running', 'Stopped', 'Paused')
        if ([string]$service.Status -notin $stableServiceStates) {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            do {
                Start-Sleep -Milliseconds 200
                $service.Refresh()
            } while ([string]$service.Status -notin $stableServiceStates -and [DateTime]::UtcNow -lt $deadline)
            if ([string]$service.Status -notin $stableServiceStates) {
                throw "Service remained in transient state '$($service.Status)' and cannot be backed up exactly: $ServiceName"
            }
        }

        # A service found by Get-Service must also resolve to exactly one CIM
        # record. Query failure or ambiguity is not a valid exact backup.
        $serviceConfigs = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop)
        if ($serviceConfigs.Count -ne 1) {
            throw "Expected exactly one Win32_Service record for $ServiceName; found $($serviceConfigs.Count)"
        }
        $serviceConfig = $serviceConfigs[0]
        $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        if (-not (Test-Path -LiteralPath $serviceRegistryPath)) {
            throw "Service registry key not found: $serviceRegistryPath"
        }
        $serviceRegistryKey = Get-Item -LiteralPath $serviceRegistryPath -ErrorAction Stop
        $delayedAutoStartExists = $serviceRegistryKey.GetValueNames() -contains 'DelayedAutoStart'

        $backupData = [PSCustomObject]@{
            SchemaVersion = 2
            Name        = $service.Name
            DisplayName = $service.DisplayName
            # Enum values must be serialized by their stable names. Otherwise
            # ConvertTo-Json writes numeric values (for example 1/3), which do
            # not satisfy the sealed restore contract after round-trip.
            Status      = [string]$service.Status
            StartType   = [string]$service.StartType
            StartMode   = $serviceConfig.StartMode
            PathName    = $serviceConfig.PathName
            Description = $serviceConfig.Description
            RestoreRuntimeState = -not [bool]$StartupOnly
            DelayedAutoStartExists = $delayedAutoStartExists
            DelayedAutoStart = if ($delayedAutoStartExists) { $serviceRegistryKey.GetValue('DelayedAutoStart') } else { $null }
            DelayedAutoStartType = if ($delayedAutoStartExists) { $serviceRegistryKey.GetValueKind('DelayedAutoStart').ToString() } else { $null }
        }

        # Save to JSON
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'

        # Save to current module folder if active, otherwise root
        $backupFolder = if ($global:CurrentModule) {
            Join-Path $global:BackupBasePath $global:CurrentModule
        }
        else {
            $global:BackupBasePath
        }

        $backupFile = Join-Path $backupFolder "$safeBackupName`_Service.json"
        [System.IO.File]::WriteAllText($backupFile, ($backupData | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
        $serviceRoundTrip = Get-Content -LiteralPath $backupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$serviceRoundTrip.SchemaVersion -ne 2 -or
            [string]$serviceRoundTrip.Name -ne $ServiceName -or
            [string]$serviceRoundTrip.Status -notin $stableServiceStates -or
            [string]$serviceRoundTrip.StartType -notin @('Automatic', 'Manual', 'Disabled') -or
            -not $serviceRoundTrip.PSObject.Properties['RestoreRuntimeState'] -or
            $serviceRoundTrip.RestoreRuntimeState -isnot [bool] -or
            -not $serviceRoundTrip.PSObject.Properties['DelayedAutoStartExists']) {
            throw "Service backup failed round-trip validation: $ServiceName"
        }

        Write-Log -Level SUCCESS -Message "Service backup created: $BackupName ($ServiceName)" -Module "Rollback"

        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type        = "Service"
            Name        = $BackupName
            Module      = $global:CurrentModule
            ServiceName = $ServiceName
            BackupFile  = $backupFile
            Timestamp   = Get-Date
        }

        return [PSCustomObject]@{
            Success = $true
            Exists = $true
            BackupFile = $backupFile
            Error = ''
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to backup service: $ServiceName" -Module "Rollback" -Exception $_.Exception
        return [PSCustomObject]@{
            Success = $false
            Exists = $null
            BackupFile = ''
            Error = $_.Exception.Message
        }
    }
}

function Backup-ScheduledTask {
    <#
    .SYNOPSIS
        Backup scheduled task configuration before modification

    .PARAMETER TaskPath
        Full path of the scheduled task (e.g., "\Microsoft\Windows\AppID\TaskName")
        Can be either full path or just folder path if TaskName is provided separately.

    .PARAMETER TaskName
        Optional - Name of the scheduled task if TaskPath is just the folder

    .PARAMETER BackupName
        Optional descriptive name for this backup. Auto-generated if not provided.

    .OUTPUTS
        Structured Success/Exists/BackupFile result. Query or backup errors
        are distinct from legitimate target absence.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskPath,

        [Parameter(Mandatory = $false)]
        [string]$TaskName,

        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )

    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }

    try {
        # Parse TaskPath - if it contains task name, split it
        if ([string]::IsNullOrEmpty($TaskName)) {
            # TaskPath is full path like "\Microsoft\Windows\AppID\TaskName"
            $TaskName = Split-Path $TaskPath -Leaf
            $actualTaskPath = Split-Path $TaskPath -Parent
            if ([string]::IsNullOrEmpty($actualTaskPath)) {
                $actualTaskPath = "\"
            }
        }
        else {
            $actualTaskPath = $TaskPath
        }

        # ScheduledTasks requires a root-qualified folder path. Normalize to
        # exactly "\" or "\Folder\" so lookup, export, and later restore use
        # the same task identity on Windows 11.
        $taskFolderName = $actualTaskPath.Trim([char]'\')
        $actualTaskPath = if ([string]::IsNullOrWhiteSpace($taskFolderName)) {
            '\'
        }
        else {
            '\' + $taskFolderName + '\'
        }

        # Generate BackupName if not provided
        if ([string]::IsNullOrEmpty($BackupName)) {
            $BackupName = $TaskName -replace '\s', '_'
        }

        # Check if task exists first
        $taskMatches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                [string]$_.TaskPath -eq $actualTaskPath -and [string]$_.TaskName -eq $TaskName
            })
        if ($taskMatches.Count -gt 1) {
            throw "Scheduled-task identity is ambiguous: $actualTaskPath$TaskName"
        }
        $task = if ($taskMatches.Count -eq 1) { $taskMatches[0] } else { $null }

        if (-not $task) {
            # Task doesn't exist - this is normal for many telemetry tasks on Win11
            Write-Log -Level DEBUG -Message "Scheduled task not found (already disabled/removed): $actualTaskPath\$TaskName" -Module "Rollback"
            return [PSCustomObject]@{
                Success = $true
                Exists = $false
                BackupFile = ''
                Error = ''
            }
        }

        # Export task to XML
        $taskXml = Export-ScheduledTask -TaskPath $actualTaskPath -TaskName $TaskName -ErrorAction Stop
        [xml]$parsedTaskXml = [string]$taskXml
        $exportedTaskUri = [string]$parsedTaskXml.Task.RegistrationInfo.URI
        $expectedTaskUri = "$actualTaskPath$TaskName"
        if ([string]::IsNullOrWhiteSpace($exportedTaskUri) -or $exportedTaskUri -cne $expectedTaskUri) {
            throw "Scheduled-task export identity mismatch: expected '$expectedTaskUri', got '$exportedTaskUri'"
        }

        # Save to file
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'

        # Save to current module folder if active, otherwise root
        $backupFolder = if ($global:CurrentModule) {
            Join-Path $global:BackupBasePath $global:CurrentModule
        }
        else {
            $global:BackupBasePath
        }

        $backupFile = Join-Path $backupFolder "$safeBackupName`_Task.json"
        $taskBackup = [PSCustomObject]@{
            SchemaVersion = 2
            TaskPath       = $actualTaskPath
            TaskName       = $TaskName
            Enabled        = ([string]$task.State -ne 'Disabled')
            CapturedState  = [string]$task.State
            XmlDefinition  = [string]$taskXml
        }
        [System.IO.File]::WriteAllText(
            $backupFile,
            ($taskBackup | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false)
        )
        $taskRoundTrip = Get-Content -LiteralPath $backupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$taskRoundTrip.SchemaVersion -ne 2 -or
            [string]$taskRoundTrip.TaskPath -cne $actualTaskPath -or
            [string]$taskRoundTrip.TaskName -cne $TaskName -or
            [string]::IsNullOrWhiteSpace([string]$taskRoundTrip.XmlDefinition)) {
            throw "Scheduled-task backup failed round-trip validation: $expectedTaskUri"
        }

        Write-Log -Level SUCCESS -Message "Scheduled task backup created: $BackupName" -Module "Rollback"

        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type       = "ScheduledTask"
            Name       = $BackupName
            Module     = $global:CurrentModule
            TaskPath   = $actualTaskPath
            TaskName   = $TaskName
            BackupFile = $backupFile
            Timestamp  = Get-Date
        }

        return [PSCustomObject]@{
            Success = $true
            Exists = $true
            BackupFile = $backupFile
            Error = ''
        }
    }
    catch {
        # Only log as ERROR if task exists but backup failed (real error)
        Write-Log -Level ERROR -Message "Failed to backup scheduled task: $actualTaskPath\$TaskName" -Module "Rollback" -Exception $_.Exception
        return [PSCustomObject]@{
            Success = $false
            Exists = $null
            BackupFile = ''
            Error = $_.Exception.Message
        }
    }
}

function Register-Backup {
    <#
    .SYNOPSIS
        Register a generic backup with custom data

    .DESCRIPTION
        Allows modules to register custom backup data (e.g., DNS settings, firewall rules).
        The data is stored as JSON and can be restored using module-specific restore logic.

    .PARAMETER Type
        Type of backup (e.g., "DNS", "Firewall", "Custom")

    .PARAMETER Data
        Backup data as JSON string or PowerShell object

    .PARAMETER Name
        Optional descriptive name for the backup

    .OUTPUTS
        Path to backup file or $null if failed

    .EXAMPLE
        Register-Backup -Type "DNS" -Data $dnsBackupJson -Name "DNS_Settings"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        $Data,

        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    try {
        if (-not $global:BackupBasePath) {
            Write-Log -Level ERROR -Message "Backup system not initialized" -Module "Rollback"
            return $null
        }

        # Generate backup name if not provided
        if (-not $Name) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
            $backupNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
            $Name = "$Type`_${timestamp}_$backupNonce"
        }

        # Sanitize backup name
        $safeName = $Name -replace '[\\/:*?"<>|]', '_'

        # A sealed module owns every artifact it creates. Keep generic JSON
        # backups inside that module folder; Type remains metadata, not a path
        # escape into a session-root side directory.
        $typeFolder = if ($global:CurrentModule) {
            Join-Path $global:BackupBasePath $global:CurrentModule
        }
        else {
            Join-Path $global:BackupBasePath $Type
        }
        if (-not (Test-Path $typeFolder)) {
            New-Item -ItemType Directory -Path $typeFolder -Force | Out-Null
        }

        $backupFile = Join-Path $typeFolder "$safeName.json"

        # Convert data to JSON if not already. UTF-8 NO-BOM: PS 5.1 `Set-Content -Encoding UTF8` emits a BOM.
        $utf8NoBomEnc = [System.Text.UTF8Encoding]::new($false)
        if ($Data -is [string]) {
            [System.IO.File]::WriteAllText($backupFile, $Data, $utf8NoBomEnc)
        }
        else {
            [System.IO.File]::WriteAllText($backupFile, ($Data | ConvertTo-Json -Depth 10), $utf8NoBomEnc)
        }

        Write-Log -Level SUCCESS -Message "Backup registered: $Type - $Name" -Module "Rollback"

        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type       = $Type
            Name       = $Name
            Module     = $global:CurrentModule
            BackupFile = $backupFile
            Timestamp  = Get-Date
        }

        return $backupFile
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to register backup: $Type - $Name" -Module "Rollback" -Exception $_.Exception
        return $null
    }
}

function Register-BackupFile {
    <#
    .SYNOPSIS
        Register an existing non-JSON backup artifact in the active module.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($global:CurrentModule)) {
        throw "A module backup must be active before registering a file artifact"
    }
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "Backup artifact does not exist: $FilePath"
    }

    $sessionRoot = [System.IO.Path]::GetFullPath($global:BackupBasePath).TrimEnd('\', '/')
    $artifactPath = [System.IO.Path]::GetFullPath($FilePath)
    $sessionPrefix = $sessionRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $artifactPath.StartsWith($sessionPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Backup artifact must already be inside the active session: $artifactPath"
    }

    $global:BackupIndex += [PSCustomObject]@{
        Type       = $Type
        Name       = $Name
        Module     = $global:CurrentModule
        Path       = $Target
        BackupFile = $artifactPath
        Timestamp  = Get-Date
    }
    return $artifactPath
}

# New-SystemRestorePoint was removed: it had no caller in any product path
# (the 2.2.4 call site only existed in Framework.ps1's standalone main block,
# which is gone). The sealed BAVR backup is the restore mechanism; a system
# restore point stays a recommended manual pre-step, never an implied one.

function Get-BackupIndex {
    <#
    .SYNOPSIS
        Get list of all backups created in current session

    .OUTPUTS
        Array of backup objects
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    return $global:BackupIndex
}

function Restore-FromBackup {
    <#
    .SYNOPSIS
        Restore a specific backup

    .PARAMETER BackupFile
        Path to backup file

    .PARAMETER Type
        Type of backup (Registry, Service, ScheduledTask)

    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Registry", "Service", "ScheduledTask")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedTarget
    )

    if (-not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
        Write-Log -Level ERROR -Message "Backup file not found: $BackupFile" -Module "Rollback"
        return $false
    }

    try {
        switch ($Type) {
            "Registry" {
                Write-Log -Level INFO -Message "Restoring registry from: $BackupFile" -Module "Rollback"

                # A valid reg.exe export can legitimately describe an existing,
                # empty key and therefore be very small. Absence is represented
                # only by a sealed EmptyMarker artifact; never infer it from file
                # length and accidentally delete a key that originally existed.
                $backupContent = Get-Content -LiteralPath $BackupFile -Raw -ErrorAction SilentlyContinue
                $hasContent = $backupContent -and
                    ($backupContent -match '(?im)^Windows Registry Editor Version 5\.00\s*$') -and
                    ($backupContent -match '(?m)^\[HKEY[^\]]+\]\s*$')

                if (-not $hasContent) {
                    Write-Log -Level ERROR -Message "Registry backup is malformed; schema-v2 sessions require a valid reg.exe export or explicit EmptyMarker artifact" -Module "Rollback"
                    return $false
                }

                $registryHeaders = @([regex]::Matches($backupContent, '(?m)^\[(HKEY[^\]]+)\]\s*$') |
                    ForEach-Object { [string]$_.Groups[1].Value })
                if ($registryHeaders.Count -eq 0) {
                    Write-Log -Level ERROR -Message "Registry backup has no root key declaration: $BackupFile" -Module "Rollback"
                    return $false
                }
                $expectedNativeTarget = ConvertTo-NativeRegistryPath -Path $ExpectedTarget
                $keyPathToRestore = $registryHeaders[0]
                if (-not $keyPathToRestore.Equals($expectedNativeTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    Write-Log -Level ERROR -Message "Registry artifact root does not match manifest target: expected '$expectedNativeTarget', got '$keyPathToRestore'" -Module 'Rollback'
                    return $false
                }
                foreach ($registryHeader in $registryHeaders) {
                    if (-not ($registryHeader.Equals($expectedNativeTarget, [StringComparison]::OrdinalIgnoreCase) -or
                            $registryHeader.StartsWith("$expectedNativeTarget\", [StringComparison]::OrdinalIgnoreCase))) {
                        Write-Log -Level ERROR -Message "Registry artifact contains a key outside its manifest target: $registryHeader" -Module 'Rollback'
                        return $false
                    }
                }

                # A successful reg.exe exit code proves only that the import was
                # accepted. Re-export the restored subtree and require a byte-for-
                # byte match with the sealed reg.exe export before reporting BAVR
                # success. Any extra value/subkey therefore fails closed.
                $verifyRegistryImport = {
                    param([string]$NativeKeyPath, [string]$ExpectedFile)
                    $verifyGuid = [Guid]::NewGuid().ToString('N')
                    $verifyFile = Join-Path $env:TEMP "reg_verify_$verifyGuid.reg"
                    $verifyStdout = Join-Path $env:TEMP "reg_verify_stdout_$verifyGuid.txt"
                    $verifyStderr = Join-Path $env:TEMP "reg_verify_stderr_$verifyGuid.txt"
                    try {
                        $verifyProcess = Start-Process -FilePath 'reg.exe' `
                            -ArgumentList 'export', "`"$NativeKeyPath`"", "`"$verifyFile`"", '/y' `
                            -Wait -NoNewWindow -PassThru `
                            -RedirectStandardOutput $verifyStdout -RedirectStandardError $verifyStderr
                        if ($verifyProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verifyFile -PathType Leaf)) {
                            $verifyError = Get-Content -LiteralPath $verifyStderr -Raw -ErrorAction SilentlyContinue
                            throw "post-restore registry export failed with exit code $($verifyProcess.ExitCode): $verifyError"
                        }
                        $expectedHash = (Get-FileHash -LiteralPath $ExpectedFile -Algorithm SHA256 -ErrorAction Stop).Hash
                        $actualHash = (Get-FileHash -LiteralPath $verifyFile -Algorithm SHA256 -ErrorAction Stop).Hash
                        if ($actualHash -cne $expectedHash) {
                            throw "post-restore registry subtree differs from sealed backup (expected $expectedHash, actual $actualHash)"
                        }
                        return $true
                    }
                    finally {
                        Remove-Item -LiteralPath $verifyFile, $verifyStdout, $verifyStderr -Force -ErrorAction SilentlyContinue
                    }
                }

                # Use unique temp files to prevent race conditions
                $guid = [Guid]::NewGuid().ToString()
                $stdoutFile = Join-Path $env:TEMP "reg_import_stdout_$guid.txt"
                $stderrFile = Join-Path $env:TEMP "reg_import_stderr_$guid.txt"

                # Use Start-Process to properly handle reg.exe output
                $process = Start-Process -FilePath "reg.exe" `
                    -ArgumentList "import", "`"$BackupFile`"" `
                    -Wait `
                    -NoNewWindow `
                    -PassThru `
                    -RedirectStandardOutput $stdoutFile `
                    -RedirectStandardError $stderrFile

                # Cleanup temp files
                $errorOutput = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue

                if ($process.ExitCode -eq 0) {
                    try {
                        $null = & $verifyRegistryImport $keyPathToRestore $BackupFile
                        Write-Log -Level SUCCESS -Message "Registry restored and exact subtree verified" -Module "Rollback"
                        return $true
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Registry import verification failed: $($_.Exception.Message)" -Module "Rollback"
                        return $false
                    }
                }
                else {
                    $errorMessage = $errorOutput
                    # Check for Access Denied error across common Windows UI languages.
                    # reg.exe is a native executable -- CurrentUICulture cannot force English output.
                    if ($errorMessage -match "Zugriff verweigert|Access is denied|Fehler beim Zugriff auf die Registrierung|Acc(\u00e8|e)s refus\u00e9|Acceso denegado|Accesso negato|\u30a2\u30af\u30bb\u30b9\u304c\u62d2\u5426|\u041e\u0442\u043a\u0430\u0437\u0430\u043d\u043e \u0432 \u0434\u043e\u0441\u0442\u0443\u043f\u0435|Acesso negado|\u62d2\u7edd\u8bbf\u95ee") {
                        Write-Log -Level WARNING -Message "Access Denied during registry restore for $BackupFile. Attempting to delete key and retry import..." -Module "Rollback"

                        if (-not [string]::IsNullOrEmpty($keyPathToRestore)) {
                            try {
                                # Convert the exact reg.exe target back to one
                                # canonical PowerShell provider path.
                                $psKeyPath = ConvertFrom-NativeRegistryPath -Path $keyPathToRestore

                                if (Test-Path $psKeyPath) {
                                    Write-Log -Level INFO -Message "Deleting existing protected key: $psKeyPath before re-import." -Module "Rollback"
                                    Remove-Item -Path $psKeyPath -Recurse -Force -ErrorAction Stop
                                }

                                # Retry import
                                $process = Start-Process -FilePath "reg.exe" `
                                    -ArgumentList "import", "`"$BackupFile`"" `
                                    -Wait `
                                    -NoNewWindow `
                                    -PassThru `
                                    -RedirectStandardOutput $stdoutFile `
                                    -RedirectStandardError $stderrFile

                                $errorOutput = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                                Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue

                                if ($process.ExitCode -eq 0) {
                                    $null = & $verifyRegistryImport $keyPathToRestore $BackupFile
                                    Write-Log -Level SUCCESS -Message "Registry restored and exact subtree verified after retry" -Module "Rollback"
                                    return $true
                                }
                                else {
                                    Write-Log -Level ERROR -Message "Registry restore failed even after deleting key (Exit Code: $($process.ExitCode)): $errorOutput" -Module "Rollback"
                                    return $false
                                }
                            }
                            catch {
                                Write-Log -Level ERROR -Message "Failed to delete key or retry import for ${keyPathToRestore}: $($_.Exception.Message)" -Module "Rollback"
                                return $false
                            }
                        }
                    }
                    Write-Log -Level ERROR -Message "Registry restore failed (Exit Code: $($process.ExitCode)): $errorMessage" -Module "Rollback"
                    return $false
                }
            }

            "Service" {
                Write-Log -Level INFO -Message "Restoring service from: $BackupFile" -Module "Rollback"
                $serviceConfig = Get-Content -LiteralPath $BackupFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ([int]$serviceConfig.SchemaVersion -ne 2 -or
                    [string]::IsNullOrWhiteSpace([string]$serviceConfig.Name) -or
                    -not ([string]$serviceConfig.Name).Equals($ExpectedTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Service backup schema/name does not match the sealed manifest target'
                }

                $desiredStartType = [string]$serviceConfig.StartType
                $desiredStatus = [string]$serviceConfig.Status
                $restoreRuntimeState = if ($serviceConfig.PSObject.Properties['RestoreRuntimeState']) {
                    if ($serviceConfig.RestoreRuntimeState -isnot [bool]) {
                        throw 'Service backup has an invalid RestoreRuntimeState flag'
                    }
                    [bool]$serviceConfig.RestoreRuntimeState
                }
                else {
                    # Backward-compatible interpretation of sealed schema-2
                    # artifacts created before startup-only snapshots existed.
                    $true
                }
                if ($desiredStartType -notin @('Automatic', 'Manual', 'Disabled') -or
                    $desiredStatus -notin @('Running', 'Stopped', 'Paused') -or
                    -not $serviceConfig.PSObject.Properties['DelayedAutoStartExists']) {
                    throw 'Service backup contains an unsupported startup/runtime state or lacks delayed-start state'
                }
                if ([bool]$serviceConfig.DelayedAutoStartExists -and
                    ([string]$serviceConfig.DelayedAutoStartType -ne 'DWord' -or
                        [int]$serviceConfig.DelayedAutoStart -notin @(0, 1))) {
                    throw 'Service backup contains an invalid DelayedAutoStart state'
                }
                $service = Get-Service -Name $serviceConfig.Name -ErrorAction Stop

                if ($restoreRuntimeState) {
                    # A running service with a disabled saved start type must be
                    # started before Disabled is reinstated.
                    if ($desiredStatus -in @('Running', 'Paused') -and $service.Status -eq 'Stopped') {
                        Set-Service -Name $serviceConfig.Name -StartupType Manual -ErrorAction Stop
                        Start-Service -Name $serviceConfig.Name -ErrorAction Stop
                        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
                    }

                    $service.Refresh()
                    switch ($desiredStatus) {
                        'Running' {
                            if ($service.Status -eq 'Paused') {
                                Resume-Service -Name $serviceConfig.Name -ErrorAction Stop
                            }
                            elseif ($service.Status -ne 'Running') {
                                Start-Service -Name $serviceConfig.Name -ErrorAction Stop
                            }
                            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
                        }
                        'Stopped' {
                            if ($service.Status -ne 'Stopped') {
                                # Do not force-stop dependent services whose runtime
                                # state is outside this sealed service artifact.
                                Stop-Service -Name $serviceConfig.Name -ErrorAction Stop
                            }
                            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
                        }
                        'Paused' {
                            if ($service.Status -ne 'Paused') {
                                Suspend-Service -Name $serviceConfig.Name -ErrorAction Stop
                            }
                            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Paused, [TimeSpan]::FromSeconds(15))
                        }
                        default {
                            throw "Unsupported service runtime state in backup: $desiredStatus"
                        }
                    }
                }

                Set-Service -Name $serviceConfig.Name -StartupType $desiredStartType -ErrorAction Stop

                $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($serviceConfig.Name)"
                if ($serviceConfig.PSObject.Properties['DelayedAutoStartExists']) {
                    if ([bool]$serviceConfig.DelayedAutoStartExists) {
                        if ([string]$serviceConfig.DelayedAutoStartType -ne 'DWord') {
                            throw "Unsupported DelayedAutoStart type: $($serviceConfig.DelayedAutoStartType)"
                        }
                        Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name 'DelayedAutoStart' -ErrorAction SilentlyContinue
                        New-ItemProperty -Path $serviceRegistryPath -Name 'DelayedAutoStart' -Value ([int]$serviceConfig.DelayedAutoStart) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    }
                    else {
                        Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name 'DelayedAutoStart' -ErrorAction SilentlyContinue
                    }
                }

                $service = Get-Service -Name $serviceConfig.Name -ErrorAction Stop
                $service.Refresh()
                if ($service.StartType.ToString() -ne $desiredStartType -or
                    ($restoreRuntimeState -and $service.Status.ToString() -ne $desiredStatus)) {
                    $expectedRuntime = if ($restoreRuntimeState) { $desiredStatus } else { '<not owned>' }
                    throw "Service post-restore mismatch: expected $desiredStartType/$expectedRuntime, got $($service.StartType)/$($service.Status)"
                }
                if ($serviceConfig.PSObject.Properties['DelayedAutoStartExists']) {
                    $serviceRegistryKey = Get-Item -LiteralPath $serviceRegistryPath -ErrorAction Stop
                    $delayedExists = $serviceRegistryKey.GetValueNames() -contains 'DelayedAutoStart'
                    if ($delayedExists -ne [bool]$serviceConfig.DelayedAutoStartExists) {
                        throw 'DelayedAutoStart existence mismatch after restore'
                    }
                    if ($delayedExists -and
                        ([int]$serviceRegistryKey.GetValue('DelayedAutoStart') -ne [int]$serviceConfig.DelayedAutoStart -or
                         $serviceRegistryKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord')) {
                        throw 'DelayedAutoStart value/type mismatch after restore'
                    }
                }

                Write-Log -Level SUCCESS -Message "Service restored and verified: $($serviceConfig.Name)" -Module "Rollback"
                Write-RestoreLog -Level SUCCESS -Message "Service restored and verified: $($serviceConfig.Name)"
                return $true
            }

            "ScheduledTask" {
                Write-Log -Level INFO -Message "Restoring scheduled task from: $BackupFile" -Module "Rollback"

                try {
                    $taskData = $null
                    if ([System.IO.Path]::GetExtension($BackupFile) -ieq '.xml') {
                        $xmlDefinition = Get-Content -LiteralPath $BackupFile -Raw -ErrorAction Stop
                        [xml]$legacyTaskXml = $xmlDefinition
                        $taskUri = [string]$legacyTaskXml.Task.RegistrationInfo.URI
                        if ([string]::IsNullOrWhiteSpace($taskUri)) {
                            throw "Legacy task backup does not contain RegistrationInfo/URI"
                        }
                        $taskName = Split-Path $taskUri -Leaf
                        $taskPath = Split-Path $taskUri -Parent
                        if ([string]::IsNullOrWhiteSpace($taskPath)) { $taskPath = '\' }
                    }
                    else {
                        $taskData = Get-Content -LiteralPath $BackupFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        if ([int]$taskData.SchemaVersion -notin @(1, 2)) {
                            throw "Unsupported scheduled-task backup schema: $($taskData.SchemaVersion)"
                        }
                        $xmlDefinition = [string]$taskData.XmlDefinition
                        $taskName = [string]$taskData.TaskName
                        $taskPath = [string]$taskData.TaskPath
                    }

                    $taskFolderName = $taskPath.Trim([char]'\')
                    $taskPath = if ([string]::IsNullOrWhiteSpace($taskFolderName)) {
                        '\'
                    }
                    else {
                        '\' + $taskFolderName + '\'
                    }

                    $sealedTaskIdentity = "$taskPath$taskName"
                    if (-not $sealedTaskIdentity.Equals($ExpectedTarget, [StringComparison]::OrdinalIgnoreCase)) {
                        throw "Scheduled-task backup identity does not match manifest target: expected '$ExpectedTarget', got '$sealedTaskIdentity'"
                    }
                    if ([string]::IsNullOrWhiteSpace($xmlDefinition)) {
                        throw 'Scheduled-task backup contains no XML definition'
                    }
                    [xml]$identityXml = $xmlDefinition
                    $xmlTaskUri = [string]$identityXml.Task.RegistrationInfo.URI
                    if ([string]::IsNullOrWhiteSpace($xmlTaskUri) -or
                        -not $xmlTaskUri.Equals($sealedTaskIdentity, [StringComparison]::OrdinalIgnoreCase)) {
                        throw "Scheduled-task XML identity mismatch: expected '$sealedTaskIdentity', got '$xmlTaskUri'"
                    }

                    # Import task XML if exists
                    if (-not [string]::IsNullOrWhiteSpace($xmlDefinition) -and -not [string]::IsNullOrWhiteSpace($taskName)) {
                        # Register-ScheduledTask requires TaskName and Xml (string)
                        # Force overwrite if exists
                        Register-ScheduledTask -Xml $xmlDefinition -TaskName $taskName -TaskPath $taskPath -Force -ErrorAction Stop | Out-Null
                        $restoredTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
                        $restoredXml = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
                        [xml]$expectedTaskXml = $xmlDefinition
                        [xml]$actualTaskXml = [string]$restoredXml
                        if ($expectedTaskXml.OuterXml -cne $actualTaskXml.OuterXml) {
                            throw "Scheduled-task XML differs after restore: $taskPath$taskName"
                        }
                        if ($taskData -and [int]$taskData.SchemaVersion -eq 2) {
                            $enabledNow = [string]$restoredTask.State -ne 'Disabled'
                            if ($enabledNow -ne [bool]$taskData.Enabled) {
                                throw "Scheduled-task enabled-state mismatch: expected $($taskData.Enabled), actual $enabledNow"
                            }
                        }
                        Write-Log -Level SUCCESS -Message "Scheduled task definition and enabled state restored and verified: $taskPath$taskName" -Module "Rollback"
                        return $true
                    }
                    else {
                        Write-Log -Level ERROR -Message "Task backup is missing XML or task identity: $BackupFile" -Module "Rollback"
                        return $false
                    }
                }
                catch {
                    Write-ErrorLog -Message "Failed to restore scheduled task" -Module "Rollback" -ErrorRecord $_
                    return $false
                }
            }

            default {
                Write-Log -Level ERROR -Message "Unknown backup type: $Type" -Module "Rollback"
                return $false
            }
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to restore from backup file: $BackupFile" -Module "Rollback" -ErrorRecord $_
        return $false
    }
}

function Invoke-RestoreRebootPrompt {
    <#
    .SYNOPSIS
        Prompt user for system reboot after restore

    .DESCRIPTION
        Offers immediate or deferred reboot with countdown.
        Uses validation loop for consistent behavior.

    .PARAMETER NoReboot
        Skip the reboot prompt entirely (for automation/GUI usage)

    .PARAMETER ForceReboot
        Automatically reboot without prompting (for automation)

    .OUTPUTS
        None
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$NoReboot,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReboot,

        [Parameter(Mandatory = $false)]
        [string[]]$Reasons = @()
    )

    if (@($Reasons).Count -eq 0) {
        Write-Log -Level INFO -Message 'Restore completed without a system-restart requirement' -Module 'Rollback'
        return
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SYSTEM REBOOT RECOMMENDED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "RECOMMENDED: Reboot after restore" -ForegroundColor White
    Write-Host ""
    Write-Host "The restored session includes restart-sensitive state:" -ForegroundColor Gray
    Write-Host ""
    foreach ($reason in @($Reasons | Select-Object -Unique)) {
        Write-Host "  - $reason" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "A restart completes activation of those restored settings." -ForegroundColor Gray
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check if running in NonInteractive mode (e.g., from GUI).
    # Prefer Test-NonInteractiveMode (env-var + config-aware) when it is available; fall back to
    # the command-line probe only if NonInteractive.ps1 has not been dot-sourced.
    $isNonInteractive = if (Get-Command Test-NonInteractiveMode -ErrorAction SilentlyContinue) {
        Test-NonInteractiveMode
    } else {
        [Environment]::GetCommandLineArgs() -contains '-NonInteractive'
    }

    # Handle -ForceReboot: immediately reboot without prompt
    if ($ForceReboot) {
        Write-Host ""
        Write-Host "[>] ForceReboot specified - rebooting system now..." -ForegroundColor Yellow
        Write-Host ""
        Restart-Computer -Force
        return
    }

    # Handle -NoReboot or NonInteractive mode: skip the prompt
    if ($NoReboot -or $isNonInteractive) {
        Write-Host ""
        if ($NoReboot) {
            Write-Host "[!] NoReboot specified - reboot prompt skipped" -ForegroundColor Yellow
        }
        else {
            Write-Host "[!] Running in NonInteractive mode - reboot prompt skipped" -ForegroundColor Yellow
        }
        Write-Host "    Please reboot manually to complete the restore." -ForegroundColor Gray
        Write-Host ""
        return
    }

    # Interactive mode: prompt user
    Write-Host "  [Y] YES - Reboot now (Recommended)" -ForegroundColor Green
    Write-Host "      - Restored restart-dependent settings take effect immediately" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [N] NO - Reboot later" -ForegroundColor Cyan
    Write-Host "      - Some restored settings stay inactive until the next reboot" -ForegroundColor Gray
    Write-Host ""

    do {
        Write-Host "Reboot now? [Y/N] (default: Y): " -ForegroundColor Yellow -NoNewline
        $choice = Read-Host
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "Y" }
        $choice = $choice.Trim().ToUpperInvariant()

        if ($choice -notin @('Y', 'N')) {
            Write-Host ""
            Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
            Write-Host ""
        }
    } while ($choice -notin @('Y', 'N'))

    if ($choice -eq 'Y') {
        Write-Host ""
        Write-Host "[>] Initiating system reboot in 10 seconds..." -ForegroundColor Yellow
        Write-Host "    Press Ctrl+C to cancel" -ForegroundColor Gray
        Write-Host ""

        # Countdown from 10
        for ($i = 10; $i -gt 0; $i--) {
            Write-Host "    Rebooting in $i seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }

        Write-Host ""
        Write-Host "[+] Rebooting system now..." -ForegroundColor Green
        Write-Host ""

        # Reboot
        Restart-Computer -Force
    }
    else {
        Write-Host ""
        Write-Host "[!] Reboot deferred" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "IMPORTANT: Please reboot manually at your earliest convenience." -ForegroundColor White
        Write-Host "Some restored settings may not be fully active until after reboot." -ForegroundColor Gray
        Write-Host ""
    }
}

function Restore-AllBackups {
    <#
    .SYNOPSIS
        Restore all backups from current session (full rollback)

    .OUTPUTS
        Boolean indicating overall success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$NoReboot,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReboot
    )

    # There is one authoritative restore engine: the sealed session workflow.
    # Replaying the in-memory BackupIndex cannot handle custom artifacts,
    # shared ASR prestate, hashes, module ordering, or manifest validation.
    if ([string]::IsNullOrWhiteSpace([string]$global:BackupBasePath) -or
        -not (Test-Path -LiteralPath $global:BackupBasePath -PathType Container)) {
        Write-Log -Level ERROR -Message 'No active sealed backup session is available for Restore-AllBackups' -Module 'Rollback'
        return $false
    }
    return Restore-Session -SessionPath $global:BackupBasePath -NoReboot:$NoReboot -ForceReboot:$ForceReboot
}

function Get-IncompleteBackupRecord {
    <#
    .SYNOPSIS
        Validate the informational inventory of a retained incomplete backup.

    .DESCRIPTION
        This record never authorizes Restore. Validation exists only so listing
        can identify the retained files clearly and detect later corruption.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $sessionRoot = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')
    $sessionId = Split-Path $sessionRoot -Leaf
    $markerPath = Join-Path $sessionRoot 'incomplete-backup.json'
    $sessionDirectory = Get-Item -LiteralPath $sessionRoot -Force -ErrorAction Stop
    if (-not $sessionDirectory.PSIsContainer -or
        [bool]($sessionDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Incomplete-backup session must be a real directory, not a reparse point'
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'incomplete-backup.json is missing'
    }
    $markerFile = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
    if ([bool]($markerFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        $markerFile.Length -lt 2 -or $markerFile.Length -gt 1048576) {
        throw 'incomplete-backup.json has an invalid size'
    }
    $record = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $requiredFields = @(
        'schemaVersion', 'recordType', 'sessionId', 'displayName', 'moduleName',
        'timestamp', 'status', 'reason', 'sourceSessionId', 'fileCount', 'files'
    )
    $actualFields = @($record.PSObject.Properties.Name)
    if ($actualFields.Count -ne $requiredFields.Count -or
        @(Compare-Object -ReferenceObject $requiredFields -DifferenceObject $actualFields).Count -ne 0) {
        throw 'Incomplete-backup record has an unexpected field set'
    }
    $allowedModules = @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')
    $canonicalReason = 'Backup did not complete before Apply. Captured files were retained, but this record cannot authorize Restore.'
    if ([int]$record.schemaVersion -ne 1 -or
        [string]$record.recordType -ne 'IncompleteModuleBackup' -or
        [string]$record.sessionId -ne $sessionId -or
        [string]$record.status -ne 'IncompleteNonRestorable' -or
        [string]$record.moduleName -notin $allowedModules -or
        [string]::IsNullOrWhiteSpace([string]$record.sourceSessionId) -or
        [string]$record.displayName -ne "Incomplete backup: $([string]$record.moduleName)" -or
        [string]$record.reason -cne $canonicalReason) {
        throw 'Incomplete-backup record identity is invalid'
    }
    $timestamp = ConvertFrom-NoIDRoundtripTimestamp `
        -Value $record.timestamp `
        -Context 'Incomplete-backup'

    $files = @($record.files)
    if ([int]$record.fileCount -lt 0 -or $files.Count -ne [int]$record.fileCount) {
        throw 'Incomplete-backup file count is invalid'
    }
    $seenPaths = @{}
    $sessionPrefix = $sessionRoot + [System.IO.Path]::DirectorySeparatorChar
    $modulePrefixPattern = '^' + [regex]::Escape([string]$record.moduleName) + '[\\/]'
    $allowedFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allowedDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $allowedFiles.Add([System.IO.Path]::GetFullPath($markerPath))
    $null = $allowedDirectories.Add($sessionRoot)
    $moduleDirectoryPath = Resolve-SessionChildPath -SessionPath $sessionRoot -RelativePath ([string]$record.moduleName)
    $moduleDirectory = Get-Item -LiteralPath $moduleDirectoryPath -Force -ErrorAction Stop
    if (-not $moduleDirectory.PSIsContainer -or
        [bool]($moduleDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Incomplete-backup module path must be a real directory'
    }
    $null = $allowedDirectories.Add([System.IO.Path]::GetFullPath($moduleDirectoryPath))
    foreach ($file in $files) {
        $fields = @($file.PSObject.Properties.Name)
        if ($fields.Count -ne 3 -or
            @(Compare-Object -ReferenceObject @('relativePath', 'length', 'sha256') -DifferenceObject $fields).Count -ne 0) {
            throw 'Incomplete-backup file record has an unexpected field set'
        }
        $relativePath = [string]$file.relativePath
        $expectedHash = [string]$file.sha256
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            $relativePath -notmatch $modulePrefixPattern -or
            $seenPaths.ContainsKey($relativePath.ToUpperInvariant()) -or
            [long]$file.length -lt 0 -or
            $expectedHash -notmatch '^[0-9a-f]{64}$') {
            throw "Incomplete-backup file identity is invalid: $relativePath"
        }
        $seenPaths[$relativePath.ToUpperInvariant()] = $true
        $filePath = Resolve-SessionChildPath -SessionPath $sessionRoot -RelativePath $relativePath
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            throw "Retained incomplete-backup file is missing: $relativePath"
        }
        $actualFile = Get-Item -LiteralPath $filePath -Force -ErrorAction Stop
        if ([bool]($actualFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Retained incomplete-backup file is a reparse point: $relativePath"
        }
        if ([long]$actualFile.Length -ne [long]$file.length) {
            throw "Retained incomplete-backup file length changed: $relativePath"
        }
        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            throw "Retained incomplete-backup file hash changed: $relativePath"
        }
        $fullFilePath = [System.IO.Path]::GetFullPath($filePath)
        $null = $allowedFiles.Add($fullFilePath)
        $parent = [System.IO.Directory]::GetParent($fullFilePath)
        while ($null -ne $parent -and
            $parent.FullName.StartsWith($sessionPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $null = $allowedDirectories.Add($parent.FullName)
            $parent = $parent.Parent
        }
    }

    # The record must describe the complete retained file set, not merely a
    # subset whose hashes happen to match. Enumerate without following links;
    # hidden/system entries and empty directories are part of the closed set.
    $discoveredFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pendingDirectories = [System.Collections.Generic.Queue[string]]::new()
    $pendingDirectories.Enqueue($sessionRoot)
    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Dequeue()
        foreach ($entry in @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)) {
            $actualPath = [System.IO.Path]::GetFullPath($entry.FullName)
            if (-not $actualPath.StartsWith($sessionPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Retained incomplete-backup entry escapes its session: $actualPath"
            }
            if ([bool]($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Incomplete-backup contains a reparse point: $actualPath"
            }
            if ($entry.PSIsContainer) {
                if (-not $allowedDirectories.Contains($actualPath)) {
                    throw "Incomplete-backup contains an undeclared directory: $actualPath"
                }
                $pendingDirectories.Enqueue($actualPath)
            }
            else {
                if (-not $allowedFiles.Contains($actualPath)) {
                    throw "Incomplete-backup directory contains an undeclared retained file: $actualPath"
                }
                $null = $discoveredFiles.Add($actualPath)
            }
        }
    }
    if (-not $discoveredFiles.SetEquals($allowedFiles)) {
        throw 'Incomplete-backup directory contains an undeclared or missing retained file'
    }

    return [PSCustomObject]@{
        SessionId  = $sessionId
        DisplayName = [string]$record.displayName
        Timestamp  = $timestamp
        ModuleName = [string]$record.moduleName
        FileCount  = [int]$record.fileCount
        Reason     = [string]$record.reason
    }
}

function Get-BackupSessions {
    <#
    .SYNOPSIS
        Get list of all backup-session folders, including damaged or unsealed
        sessions. Invalid sessions remain visible but are explicitly marked as
        non-restorable so that a listing failure can never make user data appear
        to have vanished.

    .PARAMETER BackupDirectory
        Directory containing backup sessions

    .OUTPUTS
        Array of session objects with manifest data and validation status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = (Join-Path $PSScriptRoot "..\Backups")
    )

    if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
        return @()
    }

    $backupRoot = Get-Item -LiteralPath $BackupDirectory -Force -ErrorAction Stop
    if ([bool]($backupRoot.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Backup root is a reparse point and cannot be traversed safely: $($backupRoot.FullName)"
    }

    $sessions = @()
    # Backup sessions are retained indefinitely. Listing is intentionally not a
    # retention/cleanup mechanism: every directory remains visible, including
    # legacy, renamed, damaged, hidden, or unsealed session folders. Anything
    # outside the closed manifest contract is shown as non-restorable.
    $sessionFolders = @(Get-ChildItem -LiteralPath $BackupDirectory -Directory -Force -ErrorAction Stop)

    foreach ($folder in $sessionFolders) {
        $manifestPath = Join-Path $folder.FullName "manifest.json"
        $isReparsePoint = $false
        $manifest = $null

        try {
            $isReparsePoint = [bool]($folder.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
            if ($isReparsePoint) {
                throw 'backup session directory is a reparse point and is not a self-contained session'
            }
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
                throw 'manifest.json is missing'
            }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop

            $isQuickActionSession = (
                $manifest.PSObject.Properties['schemaVersion'] -and
                [int]$manifest.schemaVersion -eq 3 -and
                $manifest.PSObject.Properties['recordType'] -and
                [string]$manifest.recordType -ceq 'QuickActionSession'
            )
            $receipt = $null
            $quickActionDocument = $null
            if ($isQuickActionSession) {
                $quickActionDocument = Get-QuickActionSessionDocument `
                    -SessionPath $folder.FullName `
                    -Manifest $manifest
                $receipt = Get-SessionRestoreReceipt `
                    -SessionPath $folder.FullName `
                    -Manifest $manifest
            }
            else {
                Assert-SessionManifest -SessionPath $folder.FullName -Manifest $manifest
                $receiptPath = Join-Path $folder.FullName 'restore-receipt.json'
                if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
                    $receipt = Get-SessionRestoreReceipt `
                        -SessionPath $folder.FullName `
                        -Manifest $manifest
                }
            }

            # Get-SessionRestoreReceipt already validated this as round-trip ISO 8601,
            # so the parse below cannot fail for a receipt that was returned.
            $receiptCompletedAt = $null
            if ($receipt) {
                $receiptCompletedAt = ConvertFrom-NoIDRoundtripTimestamp `
                    -Value $receipt.completedAt `
                    -Context 'Restore receipt'
            }

            # Manifest timestamps are written with `Get-Date -Format "o"` (ISO 8601 round-trip).
            # Use ParseExact + InvariantCulture so parsing is independent of the running system's
            # culture (which can otherwise reject ISO 8601 on cultures with unusual default formats).
            $parsedTimestamp = ConvertFrom-NoIDRoundtripTimestamp `
                -Value $manifest.timestamp `
                -Context 'Session manifest'

            if ($isQuickActionSession) {
                $actionScope = "action:$([string]$manifest.actionId)"
                $alreadyRestored = [bool](
                    $receipt -and $actionScope -in @($receipt.restoredScopes)
                )
                $quickActionLiveState = $null
                $quickActionLiveProbeError = ''
                if (-not $alreadyRestored) {
                    try {
                        $quickActionLiveState = Get-QuickActionState `
                            -ActionId ([string]$manifest.actionId)
                    }
                    catch {
                        $quickActionLiveProbeError = $_.Exception.Message
                    }
                }
                $quickActionMatchesPost = $false
                $quickActionMatchesPre = $false
                if ($quickActionLiveState) {
                    $postComparable = Get-QuickActionSessionComparableState `
                        -LiveState $quickActionLiveState -SealedState $quickActionDocument.PostState
                    $preComparable = Get-QuickActionSessionComparableState `
                        -LiveState $quickActionLiveState -SealedState $quickActionDocument.PreState
                    $quickActionMatchesPost = [string]$postComparable.fingerprint -ceq [string]$quickActionDocument.PostState.fingerprint
                    $quickActionMatchesPre = [string]$preComparable.fingerprint -ceq [string]$quickActionDocument.PreState.fingerprint
                }
                $quickActionRestorable = -not $alreadyRestored -and ($quickActionMatchesPost -or $quickActionMatchesPre)
                $quickActionValidationStatus = if ($alreadyRestored) { 'RestoredAndValidated' }
                    elseif ($quickActionMatchesPost) { 'SealedAndLivePoststateValidated' }
                    elseif ($quickActionMatchesPre) { 'RestoreReceiptRepairAvailable' }
                    elseif (-not [string]::IsNullOrWhiteSpace($quickActionLiveProbeError)) { 'LiveStateUnavailable' }
                    else { 'LiveStateDrifted' }
                $quickActionValidationError = if ($alreadyRestored) { 'This Quick Action session has already been restored.' }
                    elseif ($quickActionMatchesPost) { '' }
                    elseif ($quickActionMatchesPre) { 'Live state already equals the sealed prestate; restore will reconcile the missing receipt.' }
                    elseif (-not [string]::IsNullOrWhiteSpace($quickActionLiveProbeError)) { "Live state could not be read; restore availability is unproven: $quickActionLiveProbeError" }
                    else { 'Live state differs from both the sealed prestate and poststate; restore will refuse to overwrite it.' }
                $sessions += [PSCustomObject]@{
                    SessionId        = [string]$manifest.sessionId
                    DisplayName      = [string]$manifest.displayName
                    Timestamp        = $parsedTimestamp
                    FrameworkVersion = [string]$manifest.frameworkVersion
                    SessionType      = 'quickAction'
                    Modules          = @([PSCustomObject]@{
                        name          = [string]$manifest.owningModule
                        status        = $(if ($alreadyRestored) { 'Restored' } else { 'Applied' })
                        itemsBackedUp = @($manifest.targetIds).Count
                        actionId      = [string]$manifest.actionId
                        desiredState  = [string]$manifest.desiredState
                    })
                    TotalItems       = @($manifest.targetIds).Count
                    # Unlike a module session, a Quick Action really is one-way:
                    # Restore-QuickActionSession only runs while the live state
                    # still equals the sealed post-Apply fingerprint, which a
                    # completed restore has already replaced with the prestate.
                    Restorable       = $quickActionRestorable
                    ValidationStatus = $quickActionValidationStatus
                    ValidationError  = $quickActionValidationError
                    LastRestoredAt   = $receiptCompletedAt
                    RestoredModules  = @(if ($alreadyRestored) { [string]$manifest.owningModule })
                    RetentionKind    = $(if ($alreadyRestored) { 'QuickActionRestored' } else { 'QuickActionSealed' })
                    SessionPath      = $folder.FullName
                    FolderPath       = $folder.FullName
                }
            }
            else {
                $restoredModuleNames = @(
                    if ($receipt) {
                        @($receipt.restoredScopes) |
                            Where-Object { [string]$_ -like 'module:*' } |
                            ForEach-Object { ([string]$_).Substring(7) }
                    }
                )
                $remainingModuleNames = @(
                    @($manifest.modules.name) |
                        Where-Object { [string]$_ -notin $restoredModuleNames }
                )
                $partiallyRestored = (
                    $restoredModuleNames.Count -gt 0 -and
                    $remainingModuleNames.Count -gt 0
                )
                $fullyRestored = (
                    $restoredModuleNames.Count -gt 0 -and
                    $remainingModuleNames.Count -eq 0
                )
                $sessions += [PSCustomObject]@{
                    SessionId        = [string]$manifest.sessionId
                    DisplayName      = [string]$manifest.displayName
                    Timestamp        = $parsedTimestamp
                    FrameworkVersion = [string]$manifest.frameworkVersion
                    SessionType      = [string]$manifest.sessionType
                    Modules          = @($manifest.modules)
                    TotalItems       = [int]$manifest.totalItems
                    # A sealed module session is a state snapshot, not a one-way
                    # ticket: restoring it never consumes it. The receipt records
                    # restore history for the operator; it never gates a repeat.
                    Restorable       = $true
                    ValidationStatus = $(if ($fullyRestored) {
                            'RestoredAndValidated'
                        }
                        elseif ($partiallyRestored) {
                            'PartiallyRestoredAndValidated'
                        }
                        else {
                            'SealedAndValidated'
                        })
                    ValidationError  = ''
                    LastRestoredAt   = $receiptCompletedAt
                    RestoredModules  = $restoredModuleNames
                    RetentionKind    = $(if ($fullyRestored) {
                            'SealedRestored'
                        }
                        elseif ($partiallyRestored) {
                            'SealedPartiallyRestored'
                        }
                        else {
                            'Sealed'
                        })
                    SessionPath      = $folder.FullName
                    FolderPath       = $folder.FullName
                }
            }
        }
        catch {
            $validationError = $_.Exception.Message
            $displayName = 'Invalid or unsealed backup session'
            try {
                $timestamp = $folder.CreationTime
            }
            catch {
                $timestamp = [DateTime]::MinValue
                $validationError = "$validationError; folder timestamp unavailable: $($_.Exception.Message)"
            }
            $modules = @()
            $totalItems = 0
            $retentionKind = 'InvalidOrUnsealed'
            $sessionType = ''
            if ($manifest -and
                $manifest.PSObject.Properties['recordType'] -and
                [string]$manifest.recordType -ceq 'QuickActionSession') {
                $sessionType = 'quickAction'
                if ($manifest.PSObject.Properties['displayName'] -and
                    -not [string]::IsNullOrWhiteSpace([string]$manifest.displayName)) {
                    $displayName = [string]$manifest.displayName
                }
                if ($manifest.PSObject.Properties['timestamp']) {
                    try {
                        $timestamp = ConvertFrom-NoIDRoundtripTimestamp `
                            -Value $manifest.timestamp `
                            -Context 'Quick Action session'
                    }
                    catch {
                        Write-Verbose 'Quick Action session timestamp is invalid; using the directory timestamp.'
                    }
                }
                if ($manifest.PSObject.Properties['owningModule']) {
                    $modules = @([PSCustomObject]@{
                        name          = [string]$manifest.owningModule
                        status        = $(if ($manifest.PSObject.Properties['status']) {
                                [string]$manifest.status
                            }
                            else {
                                'Invalid'
                            })
                        itemsBackedUp = $(if ($manifest.PSObject.Properties['targetIds']) {
                                @($manifest.targetIds).Count
                            }
                            else {
                                0
                            })
                        actionId      = $(if ($manifest.PSObject.Properties['actionId']) {
                                [string]$manifest.actionId
                            }
                            else {
                                ''
                            })
                    })
                }
                if ($manifest.PSObject.Properties['targetIds']) {
                    $totalItems = @($manifest.targetIds).Count
                }
                $retentionKind = 'QuickActionInvalidOrUnsealed'
            }
            if (-not $isReparsePoint) {
                try {
                    $folderEntries = @(Get-ChildItem -LiteralPath $folder.FullName -Force -ErrorAction Stop)
                    if ($folderEntries.Count -eq 0) {
                        $displayName = 'Empty session - no backup captured'
                        $retentionKind = 'EmptySession'
                        $validationError = 'Session was initialized, but no module completed Backup (for example cancellation, skip, or preflight failure). No backup artifact is hidden or restorable.'
                    }
                }
                catch {
                    $validationError = "$validationError; folder contents unavailable: $($_.Exception.Message)"
                }
            }
            $incompleteMarker = Join-Path $folder.FullName 'incomplete-backup.json'
            if (-not $isReparsePoint -and (Test-Path -LiteralPath $incompleteMarker -PathType Leaf)) {
                try {
                    $incomplete = Get-IncompleteBackupRecord -SessionPath $folder.FullName
                    $displayName = $incomplete.DisplayName
                    $timestamp = $incomplete.Timestamp
                    $modules = @([PSCustomObject]@{
                        name          = $incomplete.ModuleName
                        status        = 'IncompleteNonRestorable'
                        itemsBackedUp = $incomplete.FileCount
                    })
                    $totalItems = $incomplete.FileCount
                    $retentionKind = 'IncompleteRetained'
                    $validationError = $incomplete.Reason
                }
                catch {
                    $validationError = "$validationError; incomplete retention record invalid: $($_.Exception.Message)"
                }
            }
            # The session list itself is the user-facing surface and already
            # shows the non-restorable status with this exact reason; a
            # console-visible warning on every listing call would duplicate it
            # and read as a live failure instead of historical session state.
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level DEBUG -Message "Backup session remains listed but is not restorable: $($folder.Name) - $validationError" -Module 'Rollback'
            }
            else {
                Write-Verbose "Backup session remains listed but is not restorable: $($folder.Name) - $validationError"
            }
            $sessions += [PSCustomObject]@{
                SessionId        = $folder.Name
                DisplayName      = $displayName
                Timestamp        = $timestamp
                FrameworkVersion = ''
                SessionType      = $sessionType
                Modules          = $modules
                TotalItems       = $totalItems
                Restorable       = $false
                ValidationStatus = 'NotRestorable'
                ValidationError  = $validationError
                LastRestoredAt   = $null
                RestoredModules  = @()
                RetentionKind    = $retentionKind
                SessionPath      = $folder.FullName
                FolderPath       = $folder.FullName
            }
        }
    }

    # Ensure we return an array (Sort-Object can return single object unwrapped)
    $sorted = @($sessions | Sort-Object -Property Timestamp -Descending)
    return $sorted
}

function Get-SessionRestoreHistoryText {
    <#
    .SYNOPSIS
        Formats when a session was last restored, or '' when it never was.
    .DESCRIPTION
        Restore history is information, not a verdict: a restored session stays
        restorable. Both console front-ends render this value under the status so
        the operator sees when the session was last used and for which modules.
        Callers supply their own label; this returns the value only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Session
    )

    if (-not $Session -or -not $Session.LastRestoredAt) { return '' }
    $when = ([DateTime]$Session.LastRestoredAt).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $restoredModules = @(@($Session.RestoredModules) | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
    if ($restoredModules.Count -gt 0) {
        return "$when ($($restoredModules -join ', '))"
    }
    return $when
}

function Get-SessionManifest {
    <#
    .SYNOPSIS
        Get manifest for a specific session

    .PARAMETER SessionPath
        Path to the session folder

    .OUTPUTS
        Session manifest object
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $manifestPath = Join-Path $SessionPath "manifest.json"

    if (-not (Test-Path $manifestPath)) {
        throw "Session manifest not found: $manifestPath"
    }

    return Get-Content $manifestPath -Raw | ConvertFrom-Json
}

function Resolve-SessionChildPath {
    <#
    .SYNOPSIS
        Resolve a relative backup path and prove that it remains inside the session.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [System.IO.Path]::IsPathRooted($RelativePath)) {
        throw "Backup path must be a non-empty relative path: '$RelativePath'"
    }

    $root = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Backup path escapes the selected session: '$RelativePath'"
    }

    return $candidate
}

function Assert-AllowedModuleArtifact {
    <#
    .SYNOPSIS
        Reject artifact identities that the selected module restore does not own.

    .DESCRIPTION
        Integrity hashes prove that an artifact was not modified after sealing;
        they do not prove that Restore has a handler for it. This semantic
        allowlist makes every accepted module artifact an explicit part of the
        restore contract instead of relying on a filename glob.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Artifact
    )

    $type = [string]$Artifact.type
    $name = [string]$Artifact.name
    $target = [string]$Artifact.target
    $allowed = $false

    switch ($ModuleName) {
        'SecurityBaseline' {
            $baselineTargets = @{
                'RegistryPolicies'              = 'RegistryPolicies'
                'SecurityTemplate'              = 'SecurityTemplate'
                'UACStandardUserElevation'      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'
                'SecurityTemplateRegistryState' = 'SecurityTemplateRegistryValues'
                'AuditPolicies'                 = 'AuditPolicies'
                'XboxTask'                      = 'XboxTask'
            }
            if ($type -eq 'SecurityBaseline' -and
                $baselineTargets.ContainsKey($name) -and
                $target -eq $baselineTargets[$name]) {
                $allowed = $true
            }
            elseif ($type -eq 'Service' -and $name -in @(
                    'XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc'
                ) -and $target -eq $name) {
                $allowed = $true
            }
        }
        'ASR' {
            $allowed = ($type -eq 'ASR' -and $name -eq 'ASR_ActiveConfiguration' -and
                $target -eq 'DefenderASR')
        }
        'DNS' {
            $allowed = ($type -eq 'DNS' -and $name -eq 'DNS_PreState')
        }
        'Privacy' {
            if ($type -eq 'Privacy' -and $name -eq 'Privacy_PreState') {
                $allowed = $true
            }
            elseif ($type -eq 'Privacy' -and $name -eq 'Privacy_BloatwareActions') {
                # Tier 2 classic bloatware removal: a pre-removal action LOG, class
                # NonExactRestore. The restore engine reports it skipped-by-design
                # (see the Privacy restore block below) and never replays it.
                $allowed = $true
            }
            elseif ($type -eq 'Privacy' -and $name -eq 'Privacy_Tier1AppInventory') {
                # Tier 1 policy removal can remove apps asynchronously. This is
                # the sealed original-user inventory for the separate non-exact
                # app recovery step; it is never replayed as exact BAVR state.
                $allowed = $true
            }
            elseif ($type -eq 'Service' -and $name -in @('DiagTrack', 'dmwappushservice', 'WerSvc') -and $target -eq $name) {
                $allowed = $true
            }
            else {
                $privacyTaskFolders = @{
                    'Microsoft_Compatibility_Appraiser'             = '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
                    'ProgramDataUpdater'                             = '\Microsoft\Windows\Application Experience\ProgramDataUpdater'
                    'StartupAppTask'                                 = '\Microsoft\Windows\Application Experience\StartupAppTask'
                    'Consolidator'                                   = '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
                    'UsbCeip'                                        = '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
                    'Microsoft-Windows-DiskDiagnosticDataCollector' = '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
                }
                if ($type -eq 'ScheduledTask' -and
                    $privacyTaskFolders.ContainsKey($name) -and
                    $target -eq $privacyTaskFolders[$name]) {
                    $allowed = $true
                }
            }
        }
        'AntiAI' {
            if ($type -eq 'AntiAI' -and $name -eq 'AntiAI_PreState') {
                $allowed = $true
            }
            else {
                $uriTargets = @{
                    'URI_HKLM_ms-copilot'      = 'HKLM:\SOFTWARE\Classes\ms-copilot'
                    'URI_HKLM_ms-edge-copilot' = 'HKLM:\SOFTWARE\Classes\ms-edge-copilot'
                }
                if ($type -in @('Registry', 'EmptyMarker') -and $uriTargets.ContainsKey($name) -and $target -eq $uriTargets[$name]) {
                    $allowed = $true
                }
                elseif ($type -in @('Registry', 'EmptyMarker') -and
                    $name -in @('URI_HKU_ms-copilot', 'URI_HKU_ms-edge-copilot') -and
                    $target -match '(?i)^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\Software\\Classes\\ms-(?:edge-)?copilot$') {
                    $allowed = $true
                }
            }
        }
        'EdgeHardening' {
            $allowed = ($type -eq 'EdgeHardening' -and $name -eq 'EdgeHardening_PreState')
        }
        'AdvancedSecurity' {
            if ($type -eq 'AdvancedSecurity' -and $name -in @(
                    'AdvancedSecurity_PreState', 'WiFiDirect_Adapters', 'NetBIOS_Adapters'
                )) {
                $allowed = $true
            }
            elseif ($type -eq 'WindowsFeature' -and $name -eq 'PowerShellV2') {
                $allowed = $true
            }
            elseif ($type -eq 'FirewallPolicy' -and
                $name -eq 'AdvancedSecurity_FirewallPolicy' -and
                $target -eq 'LocalFirewallPolicy') {
                $allowed = $true
            }
            elseif ($type -eq 'Service' -and $name -in @(
                    'SSDPSRV', 'upnphost', 'lmhosts', 'WFDSConMgrSvc', 'FDResPub', 'fdPHost'
                ) -and $target -eq $name) {
                $allowed = $true
            }
        }
    }

    if (-not $allowed) {
        throw "Module '$ModuleName' contains an artifact without an explicit restore contract: type='$type', name='$name', target='$target'"
    }

    $extension = [System.IO.Path]::GetExtension([string]$Artifact.relativePath).ToLowerInvariant()
    $expectedExtension = switch ($type) {
        'Registry'         { '.reg' }
        'EmptyMarker'      { '.json' }
        'Service'          { '.json' }
        'ScheduledTask'    { '.json' }
        'ASR'              { '.json' }
        'DNS'              { '.json' }
        'Privacy'          { '.json' }
        'AntiAI'           { '.json' }
        'EdgeHardening'    { '.json' }
        'AdvancedSecurity' { '.json' }
        'WindowsFeature'   { '.json' }
        'FirewallPolicy'   { '.wfw' }
        'SecurityBaseline' {
            switch ($name) {
                'SecurityTemplate' { '.inf' }
                'AuditPolicies'    { '.json' }
                default            { '.json' }
            }
        }
    }
    if ($extension -ne $expectedExtension) {
        throw "Module '$ModuleName' artifact '$name' has format '$extension'; expected '$expectedExtension'"
    }
}

function Assert-ArtifactContentBinding {
    <#
    .SYNOPSIS
        Validate artifact structure and bind its embedded identity to the manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Artifact,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath
    )

    $type = [string]$Artifact.type
    $target = [string]$Artifact.target
    switch ($type) {
        'Registry' {
            $content = Get-Content -LiteralPath $ArtifactPath -Raw -ErrorAction Stop
            $headers = @([regex]::Matches($content, '(?m)^\[(HKEY[^\]]+)\]\s*$') |
                ForEach-Object { [string]$_.Groups[1].Value })
            $nativeTarget = ConvertTo-NativeRegistryPath -Path $target
            if ($headers.Count -eq 0 -or -not $headers[0].Equals($nativeTarget, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Registry artifact root does not match manifest target '$target'"
            }
            foreach ($header in $headers) {
                if (-not ($header.Equals($nativeTarget, [StringComparison]::OrdinalIgnoreCase) -or
                        $header.StartsWith("$nativeTarget\", [StringComparison]::OrdinalIgnoreCase))) {
                    throw "Registry artifact contains a key outside manifest target '$target': $header"
                }
            }
        }
        'EmptyMarker' {
            $marker = Get-Content -LiteralPath $ArtifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([int]$marker.SchemaVersion -ne 2 -or
                [string]$marker.State -ne 'NotExisted' -or
                [string]$marker.KeyPath -cne $target) {
                throw "Empty-marker content does not match manifest target '$target'"
            }
        }
        'Service' {
            $service = Get-Content -LiteralPath $ArtifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([int]$service.SchemaVersion -ne 2 -or
                -not ([string]$service.Name).Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$service.StartType -notin @('Automatic', 'Manual', 'Disabled') -or
                [string]$service.Status -notin @('Running', 'Stopped', 'Paused') -or
                ($service.PSObject.Properties['RestoreRuntimeState'] -and
                    $service.RestoreRuntimeState -isnot [bool]) -or
                -not $service.PSObject.Properties['DelayedAutoStartExists'] -or
                ([bool]$service.DelayedAutoStartExists -and
                    ([string]$service.DelayedAutoStartType -ne 'DWord' -or [int]$service.DelayedAutoStart -notin @(0, 1)))) {
                throw "Service artifact content does not match manifest target '$target'"
            }
        }
        'ScheduledTask' {
            $task = Get-Content -LiteralPath $ArtifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $taskFolderName = ([string]$task.TaskPath).Trim([char]'\')
            $taskFolder = if ([string]::IsNullOrWhiteSpace($taskFolderName)) { '\' } else { '\' + $taskFolderName + '\' }
            $identity = "$taskFolder$([string]$task.TaskName)"
            if ([int]$task.SchemaVersion -ne 2 -or
                [string]::IsNullOrWhiteSpace([string]$task.XmlDefinition) -or
                -not $identity.Equals($target, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Scheduled-task artifact content does not match manifest target '$target'"
            }
            [xml]$taskXml = [string]$task.XmlDefinition
            $xmlIdentity = [string]$taskXml.Task.RegistrationInfo.URI
            if ([string]::IsNullOrWhiteSpace($xmlIdentity) -or
                -not $xmlIdentity.Equals($identity, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Scheduled-task XML identity does not match manifest target '$target'"
            }
        }
        { $_ -in @('ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity', 'WindowsFeature') } {
            $json = Get-Content -LiteralPath $ArtifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            switch ($type) {
                'ASR' {
                    $asrValidatorPath = Join-Path $PSScriptRoot '..\Modules\ASR\Private\Assert-ASRSnapshot.ps1'
                    if (-not (Test-Path -LiteralPath $asrValidatorPath -PathType Leaf)) {
                        throw "ASR snapshot validator is missing: $asrValidatorPath"
                    }
                    . $asrValidatorPath
                    $null = Assert-ASRSnapshot -Snapshot $json
                }
                'DNS' {
                    $dnsValidatorPath = Join-Path $PSScriptRoot '..\Modules\DNS\Private\Assert-DNSBackupSnapshot.ps1'
                    if (-not (Test-Path -LiteralPath $dnsValidatorPath -PathType Leaf)) {
                        throw "DNS backup validator is missing: $dnsValidatorPath"
                    }
                    . $dnsValidatorPath
                    $null = Assert-DNSBackupSnapshot -Snapshot $json
                }
                'Privacy' {
                    if ([string]$Artifact.name -eq 'Privacy_BloatwareActions') {
                        $privacyPrivateRoot = Join-Path $PSScriptRoot '..\Modules\Privacy\Private'
                        foreach ($dependency in @(
                                'Get-PrivacyBloatwareConfig.ps1',
                                'Get-PrivacyBloatwareInventoryFingerprint.ps1',
                                'Assert-PrivacyBloatwareActionLog.ps1'
                            )) {
                            $dependencyPath = Join-Path $privacyPrivateRoot $dependency
                            if (-not (Test-Path -LiteralPath $dependencyPath -PathType Leaf)) {
                                throw "Privacy bloatware validation dependency is missing: $dependencyPath"
                            }
                            . $dependencyPath
                        }
                        # Schema 1 is accepted only so a 6dc0b4d-era session can
                        # restore its exact registry/service/task state while this
                        # non-replayed artifact is skipped. The public reinstall
                        # command requires a catalog-bound schema 2 (legacy fixed
                        # set) or schema 3 (selected Weather/Widgets scope).
                        $null = Assert-PrivacyBloatwareActionLog -ActionLog $json -AllowLegacyNonReplayable
                    }
                    elseif ([string]$Artifact.name -eq 'Privacy_Tier1AppInventory') {
                        $privacyPrivateRoot = Join-Path $PSScriptRoot '..\Modules\Privacy\Private'
                        foreach ($dependency in @(
                                'Get-PrivacyTier1PolicyDefinition.ps1',
                                'Get-PrivacyBloatwareConfig.ps1',
                                'Get-PrivacyBloatwareInventoryFingerprint.ps1',
                                'Get-PrivacyTier1AppCatalog.ps1',
                                'Assert-PrivacyTier1AppInventory.ps1'
                            )) {
                            $dependencyPath = Join-Path $privacyPrivateRoot $dependency
                            if (-not (Test-Path -LiteralPath $dependencyPath -PathType Leaf)) {
                                throw "Privacy Tier 1 app validation dependency is missing: $dependencyPath"
                            }
                            . $dependencyPath
                        }
                        $null = Assert-PrivacyTier1AppInventory -Inventory $json
                    }
                    else {
                        $privacyRestoreContractPath = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Get-PrivacyTier1RestorePolicyDefinitions.ps1'
                        $privacyValidatorPath = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Assert-PrivacyRegistrySnapshot.ps1'
                        foreach ($privacyValidationDependency in @($privacyRestoreContractPath, $privacyValidatorPath)) {
                            if (-not (Test-Path -LiteralPath $privacyValidationDependency -PathType Leaf)) {
                                throw "Privacy backup validation dependency is missing: $privacyValidationDependency"
                            }
                            . $privacyValidationDependency
                        }
                        $null = Assert-PrivacyRegistrySnapshot -Snapshot $json -RestoreOnly
                    }
                }
                'AntiAI' {
                    $antiAIValidatorPath = Join-Path $PSScriptRoot '..\Modules\AntiAI\Private\Assert-AntiAIRegistrySnapshot.ps1'
                    if (-not (Test-Path -LiteralPath $antiAIValidatorPath -PathType Leaf)) {
                        throw "AntiAI backup validator is missing: $antiAIValidatorPath"
                    }
                    . $antiAIValidatorPath
                    $null = Assert-AntiAIRegistrySnapshot -Snapshot $json -RestoreOnly
                }
                'EdgeHardening' {
                    $edgeValidatorPath = Join-Path $PSScriptRoot '..\Modules\EdgeHardening\Private\Assert-EdgePolicySnapshot.ps1'
                    foreach ($requiredPath in @($edgeValidatorPath)) {
                        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
                            throw "Edge backup validation dependency is missing: $requiredPath"
                        }
                        . $requiredPath
                    }
                    $null = Assert-EdgePolicySnapshot -Snapshot $json -RestoreOnly
                }
                'WindowsFeature' {
                    if ([string]$json.FeatureName -ne 'MicrosoftWindowsPowerShellV2Root' -or [string]$json.State -ne 'Enabled') {
                        throw 'PowerShell v2 feature artifact has an invalid state'
                    }
                }
                'AdvancedSecurity' {
                    switch ([string]$Artifact.name) {
                        'AdvancedSecurity_PreState' {
                            $targetHelper = Join-Path $PSScriptRoot '..\Modules\AdvancedSecurity\Private\Get-AdvancedSecuritySchema5RegistryTargets.ps1'
                            $snapshotValidator = Join-Path $PSScriptRoot '..\Modules\AdvancedSecurity\Private\Assert-AdvancedSecurityRegistrySnapshot.ps1'
                            foreach ($dependency in @($targetHelper, $snapshotValidator)) {
                                if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) {
                                    throw "AdvancedSecurity prestate validator dependency is missing: $dependency"
                                }
                                . $dependency
                            }
                            $null = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $json -RestoreOnly
                        }
                        'WiFiDirect_Adapters' {
                            if (-not $json.PSObject.Properties['Adapters']) {
                                throw 'Wi-Fi Direct adapter artifact has no Adapters collection'
                            }
                            $wifiAdapters = @($json.Adapters)
                            if (@($wifiAdapters | Where-Object {
                                        [string]::IsNullOrWhiteSpace([string]$_.InterfaceGuid) -or
                                        [string]::IsNullOrWhiteSpace([string]$_.InterfaceDescription) -or
                                        ([string]$_.AdminStatus -notin @('Up', 'Down'))
                                    }).Count -gt 0 -or
                                @($wifiAdapters | Group-Object { ([string]$_.InterfaceGuid).ToLowerInvariant() } |
                                    Where-Object { $_.Count -gt 1 }).Count -gt 0) {
                                throw 'Wi-Fi Direct adapter artifact has invalid or duplicate stable identities'
                            }
                        }
                        'NetBIOS_Adapters' {
                            if ($json.PSObject.Properties['SchemaVersion']) {
                                if ([int]$json.SchemaVersion -ne 2) {
                                    throw 'NetBIOS adapter artifact has an unsupported schema version'
                                }
                                $netbiosValidator = Join-Path $PSScriptRoot '..\Modules\AdvancedSecurity\Private\AdvancedSecurityNetBIOS.ps1'
                                if (-not (Test-Path -LiteralPath $netbiosValidator -PathType Leaf)) {
                                    throw "NetBIOS snapshot validator is missing: $netbiosValidator"
                                }
                                . $netbiosValidator
                                $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $json
                            }
                            elseif (@($json).Count -eq 0 -or @($json | Where-Object {
                                            [string]::IsNullOrWhiteSpace([string]$_.SettingID) -or
                                            $null -eq $_.TcpipNetbiosOptions -or
                                            [int]$_.TcpipNetbiosOptions -notin @(0, 1, 2)
                                        }).Count -gt 0 -or
                                    @($json | Group-Object { ([string]$_.SettingID).ToLowerInvariant() } |
                                        Where-Object { $_.Count -gt 1 }).Count -gt 0) {
                                throw 'NetBIOS adapter artifact has invalid or incomplete entries'
                            }
                        }
                    }
                }
            }
        }
        'SecurityBaseline' {
            if ([System.IO.Path]::GetExtension($ArtifactPath) -ieq '.json') {
                $baselineJson = Get-Content -LiteralPath $ArtifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                if ([string]$Artifact.name -eq 'RegistryPolicies') {
                    $directiveCount = @($baselineJson.Computer).Count + @($baselineJson.User).Count +
                        @($baselineJson.ComputerClearKeys).Count + @($baselineJson.UserClearKeys).Count
                    if ([int]$baselineJson.SchemaVersion -notin @(3, 4) -or
                        [string]$baselineJson.UserRegistryRoot -notmatch '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+$' -or
                        [int]$baselineJson.DirectiveCount -ne $directiveCount) {
                        throw 'SecurityBaseline RegistryPolicies artifact has an invalid schema, user target or directive count'
                    }
                    if ([int]$baselineJson.SchemaVersion -eq 4 -and
                        -not $baselineJson.PSObject.Properties['AbsentAncestorKeys']) {
                        throw 'SecurityBaseline RegistryPolicies artifact has no absent-ancestor inventory'
                    }
                }
                elseif ([string]$Artifact.name -eq 'SecurityTemplateRegistryState') {
                    if ([int]$baselineJson.SchemaVersion -notin @(2, 3) -or
                        [int]$baselineJson.TargetCount -ne @($baselineJson.Values).Count -or
                        @($baselineJson.Values).Count -eq 0) {
                        throw 'Security-template registry-state artifact has an invalid schema or target count'
                    }
                    if ([int]$baselineJson.SchemaVersion -eq 3 -and
                        -not $baselineJson.PSObject.Properties['AbsentAncestorKeys']) {
                        throw 'Security-template registry-state artifact has no absent-ancestor inventory'
                    }
                }
                elseif ([string]$Artifact.name -eq 'UACStandardUserElevation') {
                    if ([int]$baselineJson.SchemaVersion -notin @(2, 3) -or
                        [string]$baselineJson.Path -ne 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -or
                        [string]$baselineJson.Name -ne 'ConsentPromptBehaviorUser' -or
                        $baselineJson.KeyExisted -isnot [bool] -or $baselineJson.Exists -isnot [bool] -or
                        ([bool]$baselineJson.Exists -and (-not [bool]$baselineJson.KeyExisted -or
                                [string]$baselineJson.Type -cne 'DWord' -or $null -eq $baselineJson.Value)) -or
                        (-not [bool]$baselineJson.Exists -and ($null -ne $baselineJson.Type -or $null -ne $baselineJson.Value))) {
                        throw 'UAC standard-user elevation artifact has an invalid schema or target'
                    }
                    if ([int]$baselineJson.SchemaVersion -eq 3 -and
                        (-not $baselineJson.PSObject.Properties['OriginalName'] -or
                         -not $baselineJson.PSObject.Properties['AbsentAncestorKeys'])) {
                        throw 'UAC standard-user elevation artifact has no exact name or absent-ancestor inventory'
                    }
                }
                elseif ([string]$Artifact.name -eq 'AuditPolicies') {
                    $auditPolicies = @($baselineJson.Policies)
                    if ([int]$baselineJson.SchemaVersion -ne 2 -or
                        [string]$baselineJson.Target -cne 'SecurityBaselineAuditPolicies' -or
                        [int]$baselineJson.PolicyCount -ne $auditPolicies.Count -or
                        $auditPolicies.Count -eq 0) {
                        throw 'Audit-policy artifact has an invalid schema, target or count'
                    }
                    $seenAuditPolicies = [System.Collections.Generic.HashSet[Guid]]::new()
                    foreach ($auditPolicy in $auditPolicies) {
                        $auditGuid = [Guid]::Empty
                        if (-not [Guid]::TryParseExact([string]$auditPolicy.SubcategoryGuid, 'D', [ref]$auditGuid) -or
                            [string]$auditPolicy.SubcategoryGuid -cne $auditGuid.ToString('D').ToLowerInvariant() -or
                            -not $seenAuditPolicies.Add($auditGuid) -or
                            [uint32]$auditPolicy.AuditingInformation -notin [uint32[]]@(1, 2, 3, 4)) {
                            throw "Audit-policy artifact contains an invalid or duplicate entry: $($auditPolicy.SubcategoryGuid)"
                        }
                    }
                    $auditTargetPath = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\ParsedSettings\AuditPolicies.json'
                    $auditTargets = Get-Content -LiteralPath $auditTargetPath -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    $expectedAuditPolicies = [System.Collections.Generic.HashSet[Guid]]::new()
                    foreach ($auditTarget in $auditTargets) {
                        $targetGuid = [Guid]::Empty
                        if (-not [Guid]::TryParse([string]$auditTarget.SubcategoryGUID, [ref]$targetGuid) -or
                            -not $expectedAuditPolicies.Add($targetGuid)) {
                            throw 'Canonical audit-policy target inventory is invalid or duplicated'
                        }
                    }
                    if ($seenAuditPolicies.Count -ne $expectedAuditPolicies.Count) {
                        throw "Audit-policy artifact target count differs from the canonical inventory"
                    }
                    foreach ($expectedAuditGuid in $expectedAuditPolicies) {
                        if (-not $seenAuditPolicies.Contains($expectedAuditGuid)) {
                            throw "Audit-policy artifact is missing canonical GUID $expectedAuditGuid"
                        }
                    }
                }
                elseif ([string]$Artifact.name -eq 'XboxTask') {
                    if ([int]$baselineJson.SchemaVersion -ne 2 -or
                        [string]$baselineJson.TaskPath -ne '\Microsoft\XblGameSave\' -or
                        [string]$baselineJson.TaskName -ne 'XblGameSaveTask') {
                        throw 'Xbox task artifact has an invalid schema or target'
                    }
                }
            }
            elseif ((Get-Item -LiteralPath $ArtifactPath -ErrorAction Stop).Length -lt 1) {
                throw "SecurityBaseline artifact is empty: $ArtifactPath"
            }
            elseif ([string]$Artifact.name -eq 'SecurityTemplate') {
                $securityInf = Get-Content -LiteralPath $ArtifactPath -Raw -ErrorAction Stop
                foreach ($requiredSection in @('System Access', 'Privilege Rights')) {
                    if ($securityInf -notmatch "(?m)^\[$([regex]::Escape($requiredSection))\]\s*$") {
                        throw "SecurityTemplate artifact is missing required section [$requiredSection]"
                    }
                }
                foreach ($forbiddenSection in @('Registry Values', 'Service General Setting')) {
                    if ($securityInf -match "(?m)^\[$([regex]::Escape($forbiddenSection))\]\s*$") {
                        throw "SecurityTemplate artifact contains non-owned restore section [$forbiddenSection]"
                    }
                }
                $securityHeaders = @([regex]::Matches($securityInf, '(?m)^\[([^\]]+)\]\s*$') |
                    ForEach-Object { $_.Groups[1].Value })
                $unexpectedHeaders = @($securityHeaders | Where-Object {
                        $_ -notin @('Unicode', 'Version', 'System Access', 'Privilege Rights')
                    })
                if ($unexpectedHeaders.Count -gt 0) {
                    throw "SecurityTemplate artifact contains an unexpected section [$($unexpectedHeaders[0])]"
                }

                $infNames = @{
                    'System Access' = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    'Privilege Rights' = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
                $currentInfSection = ''
                foreach ($line in Get-Content -LiteralPath $ArtifactPath -ErrorAction Stop) {
                    $trimmed = $line.Trim()
                    if ($trimmed -match '^\[(.+)\]$') { $currentInfSection = $Matches[1]; continue }
                    if ($currentInfSection -in $infNames.Keys -and $trimmed -match '^([^=]+?)\s*=') {
                        $name = $Matches[1].Trim()
                        if (-not $infNames[$currentInfSection].Add($name)) {
                            throw "SecurityTemplate artifact contains duplicate [$currentInfSection] $name"
                        }
                    }
                }
                $securityTemplateTargetsPath = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\ParsedSettings\SecurityTemplates.json'
                $securityTemplateTargets = Get-Content -LiteralPath $securityTemplateTargetsPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                foreach ($sectionName in $infNames.Keys) {
                    $expectedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($gpoProperty in $securityTemplateTargets.PSObject.Properties) {
                        $sectionProperty = $gpoProperty.Value.PSObject.Properties[$sectionName]
                        if ($null -eq $sectionProperty) { continue }
                        $section = $sectionProperty.Value
                        foreach ($name in $section.PSObject.Properties.Name) { $null = $expectedNames.Add([string]$name) }
                    }
                    if ($infNames[$sectionName].Count -ne $expectedNames.Count) {
                        throw "SecurityTemplate artifact [$sectionName] target count differs from the canonical inventory"
                    }
                    foreach ($expectedName in $expectedNames) {
                        if (-not $infNames[$sectionName].Contains($expectedName)) {
                            throw "SecurityTemplate artifact is missing canonical [$sectionName] $expectedName"
                        }
                    }
                }
            }
        }
        'FirewallPolicy' {
            if ((Get-Item -LiteralPath $ArtifactPath -ErrorAction Stop).Length -lt 1) {
                throw 'Firewall policy artifact is empty'
            }
        }
        default { throw "No content validator exists for artifact type '$type'" }
    }
}

function Assert-SessionManifest {
    <#
    .SYNOPSIS
        Validate the session manifest and all declared artifacts before elevated restore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Manifest,

        [Parameter(Mandatory = $false)]
        [string[]]$RequestedModules
    )

    $allowedModules = @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')

    # Pre-BAVR-v2 sessions (NoID Privacy <= 2.2.4) carry no schemaVersion and
    # are structurally incompatible with the sealed v2 restore engine (new
    # per-artifact SHA-256 manifest, target-scoped prestates, renamed module
    # restores). They are rejected here with an explicit, actionable message
    # BEFORE the generic malformed-manifest gates so users understand the
    # version boundary instead of seeing a schema error. Nothing is modified;
    # the old backup stays intact and restorable by its matching release.
    if (-not $Manifest.PSObject.Properties['schemaVersion'] -and
        $Manifest.PSObject.Properties['sessionId'] -and
        $Manifest.PSObject.Properties['frameworkVersion'] -and
        $Manifest.PSObject.Properties['modules']) {
        $legacyVersionText = if ([string]::IsNullOrWhiteSpace([string]$Manifest.frameworkVersion)) { 'unknown version' } else { "v$($Manifest.frameworkVersion)" }
        throw ("This backup was created by an older NoID Privacy release ($legacyVersionText, pre-BAVR-v2, 2.2.4 or earlier) " +
            'and cannot be restored by this version. Restore it with the matching older release; after upgrading, create a fresh backup with this version.')
    }

    foreach ($requiredProperty in @(
            'schemaVersion', 'sessionId', 'displayName', 'sessionType', 'timestamp',
            'frameworkVersion', 'modules', 'sharedArtifacts', 'totalItems', 'restorable'
        )) {
        if (-not $Manifest.PSObject.Properties[$requiredProperty]) {
            throw "Session manifest is missing required property '$requiredProperty'"
        }
    }

    $sessionDirectory = Get-Item -LiteralPath $SessionPath -Force -ErrorAction Stop
    if (-not $sessionDirectory.PSIsContainer -or
        [bool]($sessionDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Session path must be a real directory, not a reparse point'
    }

    $sessionLeaf = Split-Path ([System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')) -Leaf
    if ([string]$Manifest.sessionId -ne $sessionLeaf) {
        throw "Manifest sessionId '$($Manifest.sessionId)' does not match folder '$sessionLeaf'"
    }
    if (-not [bool]$Manifest.restorable) {
        throw "Session manifest is marked non-restorable"
    }
    if ([string]::IsNullOrWhiteSpace([string]$Manifest.displayName)) {
        throw 'Session manifest has no human-readable display name'
    }
    if ([string]$Manifest.sessionType -notin @('wizard', 'advanced', 'manual', 'unknown')) {
        throw "Session manifest has invalid sessionType '$($Manifest.sessionType)'"
    }

    $modules = @($Manifest.modules)
    if ($modules.Count -eq 0) {
        throw "Session manifest contains no module backups"
    }

    $schemaVersion = if ($Manifest.PSObject.Properties['schemaVersion']) { [int]$Manifest.schemaVersion } else { 1 }
    if ($schemaVersion -ne 2) {
        throw "Session manifest schema $schemaVersion is not a sealed BAVR v2 session"
    }

    $null = ConvertFrom-NoIDRoundtripTimestamp `
        -Value $Manifest.timestamp `
        -Context 'Manifest'

    if (@($modules.name | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) {
        throw 'Session manifest contains duplicate module records'
    }

    $sharedArtifacts = @($Manifest.sharedArtifacts)
    if ($sharedArtifacts.Count -ne 0) {
        throw 'Shared pre-framework artifacts are obsolete; current sealed sessions require module-owned target-scoped prestates'
    }
    $declaredTotal = 0

    foreach ($moduleInfo in $modules) {
        if ([string]$moduleInfo.name -notin $allowedModules) {
            throw "Manifest contains unsupported module '$($moduleInfo.name)'"
        }
        if ([string]$moduleInfo.backupPath -ne [string]$moduleInfo.name) {
            throw "Manifest backupPath must equal the module name for '$($moduleInfo.name)'"
        }
        if ([string]$moduleInfo.status -ne 'Success') {
            throw "Module '$($moduleInfo.name)' does not have a complete successful backup"
        }
        if ([int]$moduleInfo.itemsBackedUp -lt 1) {
            throw "Module '$($moduleInfo.name)' has no successfully backed-up items"
        }
        $declaredTotal += [int]$moduleInfo.itemsBackedUp
        $null = ConvertFrom-NoIDRoundtripTimestamp `
            -Value $moduleInfo.timestamp `
            -Context "Module '$($moduleInfo.name)'"

        $modulePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$moduleInfo.backupPath)
        if (-not (Test-Path -LiteralPath $modulePath -PathType Container)) {
            throw "Module backup folder does not exist: $modulePath"
        }
        $moduleDirectory = Get-Item -LiteralPath $modulePath -Force -ErrorAction Stop
        if ([bool]($moduleDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Module backup folder is a reparse point: $modulePath"
        }

        # Inventory without following reparse points. Hidden/system artifacts are
        # included so they cannot bypass the sealed manifest's closed file set.
        $actualModuleFiles = @()
        $pendingDirectories = [System.Collections.Generic.Queue[string]]::new()
        $pendingDirectories.Enqueue($modulePath)
        while ($pendingDirectories.Count -gt 0) {
            $currentDirectory = $pendingDirectories.Dequeue()
            foreach ($entry in @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)) {
                if ([bool]($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw "Module backup contains a reparse point: $($entry.FullName)"
                }
                if ($entry.PSIsContainer) {
                    $pendingDirectories.Enqueue($entry.FullName)
                }
                else {
                    $actualModuleFiles += $entry.FullName
                }
            }
        }

        if (-not $moduleInfo.PSObject.Properties['artifacts']) {
            throw "Module '$($moduleInfo.name)' has no artifact inventory"
        }
        $artifacts = @($moduleInfo.artifacts)
        if ($artifacts.Count -ne [int]$moduleInfo.itemsBackedUp) {
            throw "Module '$($moduleInfo.name)' item count does not match its artifact inventory"
        }
        if (@($artifacts.relativePath | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) {
            throw "Module '$($moduleInfo.name)' contains duplicate artifact paths"
        }
        if (@($artifacts.name | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) {
            throw "Module '$($moduleInfo.name)' contains duplicate artifact names"
        }
        $declaredPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($artifact in $artifacts) {
            foreach ($requiredArtifactProperty in @('type', 'name', 'relativePath', 'sha256')) {
                if (-not $artifact.PSObject.Properties[$requiredArtifactProperty] -or
                    [string]::IsNullOrWhiteSpace([string]$artifact.$requiredArtifactProperty)) {
                    throw "Module '$($moduleInfo.name)' contains an invalid artifact record"
                }
            }
            if (-not $artifact.PSObject.Properties['target']) {
                throw "Module '$($moduleInfo.name)' artifact '$($artifact.name)' has no target field"
            }
            if ([string]$artifact.relativePath -notmatch ('^' + [regex]::Escape([string]$moduleInfo.name) + '[\\/]')) {
                throw "Artifact is not inside its declared module folder: $($artifact.relativePath)"
            }
            if ([string]$artifact.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
                throw "Artifact has an invalid SHA-256 value: $($artifact.relativePath)"
            }
            Assert-AllowedModuleArtifact -ModuleName ([string]$moduleInfo.name) -Artifact $artifact
            $artifactPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$artifact.relativePath)
            if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
                throw "Declared backup artifact does not exist: $artifactPath"
            }
            $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            if ($actualHash -ne ([string]$artifact.sha256).ToLowerInvariant()) {
                throw "Backup artifact integrity check failed: $artifactPath"
            }
            Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $artifactPath
            $null = $declaredPaths.Add([System.IO.Path]::GetFullPath($artifactPath))
        }

        $requiredArtifactNames = switch ([string]$moduleInfo.name) {
            'SecurityBaseline' { @('RegistryPolicies', 'SecurityTemplate', 'UACStandardUserElevation', 'SecurityTemplateRegistryState', 'AuditPolicies', 'XboxTask') }
            'ASR'              { @('ASR_ActiveConfiguration') }
            'DNS'              { @('DNS_PreState') }
            'Privacy'          { @('Privacy_PreState') }
            'AntiAI'           { @('AntiAI_PreState', 'URI_HKLM_ms-copilot', 'URI_HKU_ms-copilot', 'URI_HKLM_ms-edge-copilot', 'URI_HKU_ms-edge-copilot') }
            'EdgeHardening'    { @('EdgeHardening_PreState') }
            'AdvancedSecurity' { @('AdvancedSecurity_PreState', 'NetBIOS_Adapters') }
        }
        foreach ($requiredArtifactName in $requiredArtifactNames) {
            if (@($artifacts | Where-Object { [string]$_.name -eq $requiredArtifactName }).Count -ne 1) {
                throw "Module '$($moduleInfo.name)' does not contain exactly one required artifact '$requiredArtifactName'"
            }
        }

        if ([string]$moduleInfo.name -eq 'Privacy') {
            $privacyPreStateRecord = @($artifacts | Where-Object { [string]$_.name -eq 'Privacy_PreState' })[0]
            $privacyPreStatePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$privacyPreStateRecord.relativePath)
            $privacyPreState = Get-Content -LiteralPath $privacyPreStatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([int]$privacyPreState.SchemaVersion -in @(3, 4, 5, 6, 7)) {
                $sealedServiceTargets = @($artifacts | Where-Object { [string]$_.type -eq 'Service' } |
                    ForEach-Object { ([string]$_.target).ToLowerInvariant() } | Sort-Object)
                $expectedServiceTargets = @($privacyPreState.ApplicableServiceNames |
                    ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
                if (($sealedServiceTargets -join "`0") -cne ($expectedServiceTargets -join "`0")) {
                    throw 'Privacy service artifacts do not match the sealed applicability inventory'
                }
                $sealedTaskTargets = @($artifacts | Where-Object { [string]$_.type -eq 'ScheduledTask' } |
                    ForEach-Object { ([string]$_.target).ToLowerInvariant() } | Sort-Object)
                $expectedTaskTargets = @($privacyPreState.ApplicableScheduledTaskPaths |
                    ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
                if (($sealedTaskTargets -join "`0") -cne ($expectedTaskTargets -join "`0")) {
                    throw 'Privacy scheduled-task artifacts do not match the sealed applicability inventory'
                }
                if ([int]$privacyPreState.SchemaVersion -in @(4, 5, 6, 7)) {
                    $bloatwareArtifacts = @($artifacts | Where-Object {
                            [string]$_.type -eq 'Privacy' -and [string]$_.name -eq 'Privacy_BloatwareActions'
                        })
                    $bloatwareArtifactCount = $bloatwareArtifacts.Count
                    $expectedBloatwareArtifactCount = if ([bool]$privacyPreState.Tier2BloatwareRemovalSelected) { 1 } else { 0 }
                    if ($bloatwareArtifactCount -ne $expectedBloatwareArtifactCount) {
                        throw 'Privacy Tier 2 artifact does not match the sealed schema-4/5/6/7 decision'
                    }
                    if ($bloatwareArtifactCount -eq 1) {
                        $bloatwarePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$bloatwareArtifacts[0].relativePath)
                        $bloatwareState = Get-Content -LiteralPath $bloatwarePath -Raw -Encoding UTF8 -ErrorAction Stop |
                            ConvertFrom-Json -ErrorAction Stop
                        $expectedBloatwareSchema = if ([int]$privacyPreState.SchemaVersion -in @(6, 7)) { 3 } else { 2 }
                        if ([int]$bloatwareState.SchemaVersion -ne $expectedBloatwareSchema) {
                            throw "Privacy schema-$($privacyPreState.SchemaVersion) Tier 2 decision requires a catalog-bound schema-$expectedBloatwareSchema action inventory"
                        }
                        if ([int]$privacyPreState.SchemaVersion -in @(6, 7) -and
                            [bool]$bloatwareState.WeatherWidgetRemovalSelected -ne [bool]$privacyPreState.WeatherWidgetRemovalSelected) {
                            throw 'Privacy Weather Widget decision differs between prestate and action inventory'
                        }
                        if ([int]$privacyPreState.SchemaVersion -eq 7) {
                            $sealedFamilySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                            foreach ($family in @($bloatwareState.Entries | Where-Object { [bool]$_.Present } |
                                    ForEach-Object { [string]$_.PackageFamilyName })) {
                                $null = $sealedFamilySet.Add($family)
                            }
                            [string[]]$sealedFamilies = @($sealedFamilySet)
                            [Array]::Sort($sealedFamilies, [StringComparer]::Ordinal)
                            [string[]]$firewallFamilies = @($privacyPreState.AppxFirewallState.PackageFamilyNames |
                                ForEach-Object { [string]$_ })
                            if (($sealedFamilies -join ([char]31)) -cne ($firewallFamilies -join ([char]31))) {
                                throw 'Privacy AppX firewall collateral state differs from the sealed Tier 2 package inventory'
                            }
                        }
                    }
                }
                $tier1AppArtifacts = @($artifacts | Where-Object {
                        [string]$_.type -eq 'Privacy' -and [string]$_.name -eq 'Privacy_Tier1AppInventory'
                    })
                $expectedTier1AppArtifactCount = if ([int]$privacyPreState.SchemaVersion -in @(5, 6, 7) -and [bool]$privacyPreState.Tier1PolicyRemovalSelected) { 1 } else { 0 }
                if ($tier1AppArtifacts.Count -ne $expectedTier1AppArtifactCount) {
                    throw 'Privacy Tier 1 app artifact does not match the sealed schema/version decision'
                }
                if ($tier1AppArtifacts.Count -eq 1) {
                    $tier1AppPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$tier1AppArtifacts[0].relativePath)
                    $tier1AppState = Get-Content -LiteralPath $tier1AppPath -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    if ([int]$tier1AppState.SchemaVersion -ne 1 -or [string]$tier1AppState.Mode -cne 'tier1-policy') {
                        throw 'Privacy schema-5/6/7 Tier 1 decision requires a schema-1 tier1-policy app inventory'
                    }
                }
            }
        }

        if ([string]$moduleInfo.name -eq 'AdvancedSecurity') {
            $advancedPreStateRecord = @($artifacts | Where-Object { [string]$_.name -eq 'AdvancedSecurity_PreState' })[0]
            $advancedPreStatePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$advancedPreStateRecord.relativePath)
            $advancedPreState = Get-Content -LiteralPath $advancedPreStatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([int]$advancedPreState.SchemaVersion -ne 5) {
                throw "AdvancedSecurity pre-state has unsupported schema $($advancedPreState.SchemaVersion)"
            }
            foreach ($decisionProperty in @(
                    'SkipFirewallLayer', 'DisableRDP', 'AdminSharesDisabled', 'DisableUPnP',
                    'DisableWirelessDisplayCompletely', 'DisableDiscoveryProtocolsCompletely',
                    'DisableIPv6Completely', 'EnableFirewallShieldsUp',
                    'RdpHostSupported', 'ManagedPolicySupported', 'WirelessDisplaySupported'
                )) {
                if (-not $advancedPreState.PSObject.Properties[$decisionProperty]) {
                    throw "AdvancedSecurity pre-state is missing decision '$decisionProperty'"
                }
            }

            $expectsFirewallPolicy = -not [bool]$advancedPreState.SkipFirewallLayer
            $expectsWiFiAdapters = [bool]$advancedPreState.WirelessDisplaySupported -and
                [bool]$advancedPreState.DisableWirelessDisplayCompletely
            $firewallPolicyCount = @($artifacts | Where-Object { [string]$_.name -eq 'AdvancedSecurity_FirewallPolicy' }).Count
            $wifiAdapterCount = @($artifacts | Where-Object { [string]$_.name -eq 'WiFiDirect_Adapters' }).Count
            if ($firewallPolicyCount -ne $(if ($expectsFirewallPolicy) { 1 } else { 0 })) {
                throw 'AdvancedSecurity firewall artifact does not match the sealed firewall-layer decision'
            }
            if ($wifiAdapterCount -ne $(if ($expectsWiFiAdapters) { 1 } else { 0 })) {
                throw 'AdvancedSecurity Wi-Fi Direct artifact does not match the sealed Wireless Display decision'
            }
            $allowedServiceArtifacts = @('lmhosts')
            if ([bool]$advancedPreState.DisableUPnP) { $allowedServiceArtifacts += @('SSDPSRV', 'upnphost') }
            if ([bool]$advancedPreState.WirelessDisplaySupported -and [bool]$advancedPreState.DisableWirelessDisplayCompletely) {
                $allowedServiceArtifacts += 'WFDSConMgrSvc'
            }
            if ([bool]$advancedPreState.DisableDiscoveryProtocolsCompletely) { $allowedServiceArtifacts += @('FDResPub', 'fdPHost') }
            $unexpectedServiceArtifacts = @($artifacts | Where-Object {
                    [string]$_.type -eq 'Service' -and [string]$_.name -notin $allowedServiceArtifacts
                })
            if ($unexpectedServiceArtifacts.Count -gt 0) {
                throw "AdvancedSecurity contains a service artifact outside its sealed decision set: $($unexpectedServiceArtifacts[0].name)"
            }
        }

        foreach ($actualFile in $actualModuleFiles) {
            if (-not $declaredPaths.Contains([System.IO.Path]::GetFullPath($actualFile))) {
                throw "Module '$($moduleInfo.name)' contains an undeclared artifact: $actualFile"
            }
        }
    }

    if ($declaredTotal -ne [int]$Manifest.totalItems) {
        throw "Manifest totalItems does not match module item counts"
    }

    $allowedRootFiles = @('manifest.json', 'restore-receipt.json')
    foreach ($rootFile in Get-ChildItem -LiteralPath $SessionPath -File -Force -ErrorAction Stop) {
        if ([bool]($rootFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Session root contains a reparse-point file: $($rootFile.FullName)"
        }
        if ($rootFile.Name -notin $allowedRootFiles) {
            throw "Session root contains an undeclared file: $($rootFile.FullName)"
        }
    }
    $receiptPath = Join-Path $SessionPath 'restore-receipt.json'
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        if (-not (Get-Command Get-SessionRestoreReceipt -ErrorAction SilentlyContinue)) {
            throw 'Restore receipt validation is unavailable'
        }
        $receipt = Get-SessionRestoreReceipt -SessionPath $SessionPath -Manifest $Manifest
        $allowedReceiptScopes = @($modules | ForEach-Object { "module:$([string]$_.name)" })
        if (@($receipt.restoredScopes | Where-Object {
                    [string]$_ -notin $allowedReceiptScopes
                }).Count -gt 0) {
            throw 'Restore receipt contains a scope outside this module session'
        }
    }
    $allowedRootDirectories = @($modules.name)
    foreach ($rootDirectory in Get-ChildItem -LiteralPath $SessionPath -Directory -Force -ErrorAction Stop) {
        if ([bool]($rootDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Session root contains a reparse-point directory: $($rootDirectory.FullName)"
        }
        if ($rootDirectory.Name -notin $allowedRootDirectories) {
            throw "Session root contains an undeclared directory: $($rootDirectory.FullName)"
        }
    }

    # Windows PowerShell 5.1 + StrictMode treats @($null).Count as a member
    # access on the null expression in this context. Materialize the optional
    # filter as a real collection so an unfiltered full-session restore remains
    # valid and countable.
    $requestedModuleList = [System.Collections.Generic.List[string]]::new()
    foreach ($requestedModule in $RequestedModules) {
        $requestedModuleList.Add([string]$requestedModule)
        if ($requestedModule -notin $allowedModules -or $requestedModule -notin @($modules.name)) {
            throw "Requested module is not present in this session: '$requestedModule'"
        }
    }

    # SecurityBaseline owns declared policy values before the later overlapping
    # modules apply their narrower overrides: ASR under the Exploit Guard rules
    # key, DNS under HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient, which
    # SecurityBaseline creates (EnableMulticast/EnableNetbios) and DNS then writes
    # DoHPolicy into. Preserve LIFO ownership for a partial restore: the earlier
    # baseline cannot be restored while a later overlapping module stays applied.
    # The set comes from the same helper the combined-prestate reconstruction uses,
    # so the guard can no longer cover fewer modules than the restore itself.
    Assert-NoIDSecurityBaselineOverlapRestore `
        -SessionModuleNames ([string[]]@($modules.name)) `
        -RequestedModules ([string[]]@($requestedModuleList))

    Assert-NoIDEdgePolicyOverlapRestore `
        -SessionModuleNames ([string[]]@($modules.name)) `
        -RequestedModules ([string[]]@($requestedModuleList))
}

function Assert-NoIDEdgePolicyOverlapRestore {
    <#
    .SYNOPSIS
        Enforce LIFO ordering for the AntiAI/EdgeHardening Edge-policy-key overlap.
    .DESCRIPTION
        AntiAI and EdgeHardening own disjoint values under the same Edge policy
        key. The earlier module's exact key-existence prestate can only be restored
        after the later module has been rolled back. Sealed manifest order decides
        which is earlier, not assumed framework priority, so custom module
        sequences remain safe. Pure decision, kept separate from
        Assert-SessionManifest so it is asserted by value; the previous coverage
        was a source grep for the error string, which a comment satisfies as
        readily as a working guard.
    .PARAMETER SessionModuleNames
        Module names sealed in the manifest, in sealed order.
    .PARAMETER RequestedModules
        Modules the caller asked to restore. Empty means the whole session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$SessionModuleNames,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$RequestedModules
    )

    if ($RequestedModules.Count -eq 0 -or
        'AntiAI' -notin $SessionModuleNames -or
        'EdgeHardening' -notin $SessionModuleNames) {
        return
    }

    $antiAIIndex = [array]::IndexOf($SessionModuleNames, 'AntiAI')
    $edgeIndex = [array]::IndexOf($SessionModuleNames, 'EdgeHardening')
    $earlierOverlapModule = if ($antiAIIndex -lt $edgeIndex) { 'AntiAI' } else { 'EdgeHardening' }
    $laterOverlapModule = if ($earlierOverlapModule -eq 'AntiAI') { 'EdgeHardening' } else { 'AntiAI' }
    if ($earlierOverlapModule -in $RequestedModules -and
        $laterOverlapModule -notin $RequestedModules) {
        throw "$earlierOverlapModule overlaps the later $laterOverlapModule module under the Edge policy key; restore $laterOverlapModule with it or restore neither"
    }
}

function Test-AllowedEmptyMarkerTarget {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$KeyPath
    )

    $allowedPrefixes = switch ($ModuleName) {
        'SecurityBaseline' {
            @('HKLM:\SOFTWARE\Policies\Microsoft', 'HKCU:\SOFTWARE\Policies\Microsoft')
        }
        'ASR' {
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR')
        }
        'DNS' {
            @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
                'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
            )
        }
        'Privacy' {
            @(
                'HKLM:\SOFTWARE\Policies\Microsoft',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
                'HKCU:\Software\Policies\Microsoft',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion'
            )
        }
        'AntiAI' {
            @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
                'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
                'HKLM:\SOFTWARE\Classes\ms-copilot',
                'HKLM:\SOFTWARE\Classes\ms-edge-copilot'
            )
        }
        'EdgeHardening' {
            @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge')
        }
        'AdvancedSecurity' {
            @(
                'HKLM:\SOFTWARE\Policies\Microsoft',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
                'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
                'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            )
        }
        default { @() }
    }

    if ($ModuleName -eq 'AntiAI' -and
        $KeyPath -match '(?i)^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\Software\\Classes\\ms-(?:edge-)?copilot$') {
        return $true
    }

    foreach ($prefix in $allowedPrefixes) {
        if ($KeyPath.Equals($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            $KeyPath.StartsWith($prefix + '\', [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Initialize-RestoreLog {
    <#
    .SYNOPSIS
        Initialize separate detailed log file for restore operations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $script:RestoreErrorCount = 0
    $script:RestoreLogWriteFailed = $false
    try {
        $logsDir = Join-Path (Split-Path $PSScriptRoot -Parent) "Logs"
        if (-not (Test-Path $logsDir)) {
            New-Item -ItemType Directory -Path $logsDir -Force -ErrorAction Stop | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
        $restoreNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $sessionId = Split-Path $SessionPath -Leaf
        $restoreLogFile = "RESTORE_$($sessionId)_${timestamp}_$restoreNonce.log"
        $script:RestoreLogPath = Join-Path $logsDir $restoreLogFile

        # Initialize restore log file via .NET WriteAllText with UTF-8 NO-BOM
        # for cross-version consistency.
        $header = @(
            "================================================================"
            "  NoID Privacy - RESTORE LOG"
            "  Session: $sessionId"
            "  Restore Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "================================================================"
            ""
        )
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($script:RestoreLogPath, ($header -join "`r`n") + "`r`n", $utf8NoBom)

        Write-Log -Level INFO -Message "Restore log initialized: $script:RestoreLogPath" -Module "Rollback"
        return $true
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to initialize restore log: $_" -Module "Rollback"
        $script:RestoreLogPath = $null
        return $false
    }
}

function Write-RestoreLog {
    <#
    .SYNOPSIS
        Write to restore-specific log (in addition to main log)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    if ($Level -eq 'ERROR') {
        $script:RestoreErrorCount = [int]$script:RestoreErrorCount + 1
    }
    if (-not $script:RestoreLogPath) {
        $script:RestoreLogWriteFailed = $true
        return
    }

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        # .NET AppendAllText with UTF-8 NO-BOM (matches Initialize-RestoreLog).
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::AppendAllText($script:RestoreLogPath, $logEntry + "`r`n", $utf8NoBom)
    }
    catch {
        $script:RestoreLogWriteFailed = $true
        Write-Warning "Restore log write failed: $($_.Exception.Message)"
    }
}

function Get-ServiceArtifactsInRestoreOrder {
    <#
    .SYNOPSIS
        Orders sealed service artifacts so in-session dependencies are restored first.

    .DESCRIPTION
        A service that was running before hardening cannot be restarted until its
        dependencies have been restored. The manifest order is an integrity
        inventory, not a valid SCM dependency order, so derive a deterministic
        topological order from the live service definitions and fail closed on
        missing, ambiguous, duplicate, or cyclic identities.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Artifacts
    )

    if ($Artifacts.Count -eq 0) {
        return @()
    }

    $artifactsByTarget = @{}
    foreach ($artifact in $Artifacts) {
        $target = [string]$artifact.target
        if ([string]::IsNullOrWhiteSpace($target)) {
            throw 'Service artifact has no sealed target identity'
        }
        $key = $target.ToUpperInvariant()
        if ($artifactsByTarget.ContainsKey($key)) {
            throw "Duplicate sealed service target in restore inventory: $target"
        }
        $artifactsByTarget[$key] = $artifact
    }

    $ordered = [System.Collections.Generic.List[object]]::new()
    $visiting = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $visit = {
        param([object]$Artifact)

        $target = [string]$Artifact.target
        if ($visited.Contains($target)) {
            return
        }
        if (-not $visiting.Add($target)) {
            throw "Cyclic sealed service dependency detected while restoring: $target"
        }

        $services = @(Get-Service -Name $target -ErrorAction Stop)
        if ($services.Count -ne 1) {
            throw "Expected exactly one service while ordering restore target '$target'; found $($services.Count)"
        }
        foreach ($dependency in @($services[0].ServicesDependedOn)) {
            $dependencyName = [string]$dependency.Name
            if ([string]::IsNullOrWhiteSpace($dependencyName)) {
                throw "Service dependency identity is empty while ordering restore target: $target"
            }
            $dependencyKey = $dependencyName.ToUpperInvariant()
            if ($artifactsByTarget.ContainsKey($dependencyKey)) {
                & $visit $artifactsByTarget[$dependencyKey]
            }
        }

        $null = $visiting.Remove($target)
        $null = $visited.Add($target)
        $ordered.Add($Artifact)
    }

    foreach ($artifact in $Artifacts) {
        & $visit $artifact
    }

    return @($ordered.ToArray())
}

function Get-RestoreRebootReasons {
    <#
    .SYNOPSIS
        Restart-sensitivity reasons for a restored module set

    .DESCRIPTION
        Shared by the internal restore flow and by interactive callers that
        defer the reboot prompt until after their own follow-up steps (e.g.
        the separate Tier-2 Store reinstall offer). An empty result means the
        restored set owns no restart-sensitive state.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$ModuleNames
    )

    $rebootReasons = [System.Collections.Generic.List[string]]::new()
    if ('SecurityBaseline' -in @($ModuleNames)) {
        $rebootReasons.Add('Security template and user-right assignments can require a new boot/sign-in cycle')
    }
    if ('AntiAI' -in @($ModuleNames)) {
        $rebootReasons.Add('Recall availability policies are completed by Windows during restart')
    }
    if ('AdvancedSecurity' -in @($ModuleNames)) {
        $rebootReasons.Add('Boot-time networking, credential and optional-feature state may require restart')
    }
    return @($rebootReasons)
}

function Invoke-RestoreBloatwareReinstallOffer {
    <#
    .SYNOPSIS
        Offers the separate best-effort app recovery after Privacy restore.

    .DESCRIPTION
        This hook belongs to the canonical Restore-Session flow so direct
        interactive callers cannot bypass the offer. Sealed Tier 1/Tier 2 app
        inventories are only recovery inputs; the result remains outside the
        exact BAVR verdict. Automation, GUI and forced-reboot callers can suppress
        the prompt while retaining an actionable log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Manifest,

        [Parameter(Mandatory = $false)]
        [string[]]$RestoredModuleNames,

        [Parameter(Mandatory = $false)]
        [switch]$SuppressPrompt
    )

    if ('Privacy' -notin @($RestoredModuleNames)) { return }

    try {
        $privacyModules = @($Manifest.modules | Where-Object { [string]$_.name -eq 'Privacy' })
        if ($privacyModules.Count -ne 1) {
            throw "Expected exactly one restored Privacy module record; found $($privacyModules.Count)"
        }

        $actionArtifacts = @($privacyModules[0].artifacts | Where-Object {
                [string]$_.type -eq 'Privacy' -and
                [string]$_.name -in @('Privacy_Tier1AppInventory','Privacy_BloatwareActions')
            })
        if ($actionArtifacts.Count -eq 0) { return }
        foreach ($inventoryName in @('Privacy_Tier1AppInventory','Privacy_BloatwareActions')) {
            $inventoryCount = @($actionArtifacts | Where-Object { [string]$_.name -eq $inventoryName }).Count
            if ($inventoryCount -gt 1) {
                throw "Expected at most one $inventoryName artifact; found $inventoryCount"
            }
        }

        $escapedSessionPath = $SessionPath.Replace("'", "''")
        $manualCommand = "Import-Module '.\Modules\Privacy\Privacy.psd1'; Restore-BloatwareApps -SessionPath '$escapedSessionPath'"
        if ($SuppressPrompt) {
            Write-Log -Level INFO -Message "Privacy app-recovery offer suppressed for automation. Optional best-effort command: $manualCommand" -Module 'Rollback'
            Write-RestoreLog -Level INFO -Message "Privacy app-recovery offer suppressed for automation. Optional best-effort command: $manualCommand"
            return
        }

        $privacyModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\Privacy\Privacy.psd1'
        if (-not (Test-Path -LiteralPath $privacyModulePath -PathType Leaf)) {
            throw "Privacy module not found: $privacyModulePath"
        }
        Import-Module $privacyModulePath -Force -ErrorAction Stop
        $assessment = Get-BloatwareRestoreAssessment -SessionPath $SessionPath
        $assessmentSummary = "recorded=$($assessment.RecordedPresent), restorable=$($assessment.Mapped), local=$($assessment.LocalRegisterable), Store=$($assessment.StoreMapped), missing=$($assessment.Missing), already present=$($assessment.AlreadyPresent), no route=$($assessment.Unmapped)"
        if (-not [bool]$assessment.Success) {
            Write-Log -Level WARNING -Message "Privacy app-recovery need could not be assessed ($($assessment.Status)): $($assessment.Error). Manual command: $manualCommand" -Module 'Rollback'
            Write-RestoreLog -Level WARNING -Message "Privacy app-recovery need could not be assessed ($($assessment.Status)): $($assessment.Error). Manual command: $manualCommand"
            Write-Host "App reinstall need could not be assessed: $($assessment.Error)" -ForegroundColor Yellow
            Write-Host "Run later as the original user if needed:" -ForegroundColor Gray
            Write-Host "  $manualCommand" -ForegroundColor Gray
            return
        }
        if ([string]$assessment.Status -eq 'NothingToDo') {
            Write-Log -Level INFO -Message "Privacy app-recovery prompt skipped because no restorable recorded app is currently missing ($assessmentSummary)" -Module 'Rollback'
            Write-RestoreLog -Level INFO -Message "Privacy app-recovery prompt skipped because no restorable recorded app is currently missing ($assessmentSummary)"
            Write-Host "No app recovery is needed; every restorable app recorded by Privacy is already present." -ForegroundColor Gray
            return
        }
        if ([string]$assessment.Status -eq 'UnmappedOnly') {
            Write-Log -Level WARNING -Message "Privacy app-recovery prompt skipped because only apps without a local/Store route are absent ($assessmentSummary)" -Module 'Rollback'
            Write-RestoreLog -Level WARNING -Message "Privacy app-recovery prompt skipped because only apps without a local/Store route are absent ($assessmentSummary)"
            Write-Host "No local package-family or verified Store recovery is available for the recorded missing app(s)." -ForegroundColor Yellow
            return
        }
        if ([string]$assessment.Status -ne 'Needed' -or [int]$assessment.Missing -lt 1) {
            throw "Privacy app-recovery assessment returned an inconsistent status: $($assessment.Status)"
        }

        Write-Host ""
        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host "  Optional Best-Effort App Recovery" -ForegroundColor Cyan
        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "This session has $($assessment.Missing) currently-missing Tier 1/Tier 2 app(s)." -ForegroundColor White
        Write-Host "The exact restore above never reinstalls apps; separate app recovery is" -ForegroundColor White
        Write-Host "best-effort only" -ForegroundColor White
        Write-Host "(recorded local package first, current Store fallback; app data is not recovered)." -ForegroundColor White
        Write-Host ""
        Write-Host "Attempt the best-effort app recovery now?" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [N] NO - Skip app recovery (default)" -ForegroundColor Green
        Write-Host "      - You can run it any time later as the original user" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [Y] YES - Attempt the best-effort app recovery now" -ForegroundColor Cyan
        Write-Host "      - Recorded local package first, current Store fallback" -ForegroundColor Gray
        Write-Host "      - App data is not recovered" -ForegroundColor Gray
        Write-Host ""

        do {
            Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
            $answer = Read-Host
            if ([string]::IsNullOrWhiteSpace($answer)) { $answer = 'N' }
            $answer = $answer.Trim().ToUpperInvariant()
            if ($answer -notin @('Y', 'N')) {
                Write-Host ""
                Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                Write-Host ""
            }
        } while ($answer -notin @('Y', 'N'))

        if ($answer -eq 'N') {
            Write-Host "Skipped. Run it any time as the original user:" -ForegroundColor Gray
            Write-Host "  $manualCommand" -ForegroundColor Gray
            Write-Log -Level INFO -Message "User declined the optional Privacy app recovery. Manual command: $manualCommand" -Module 'Rollback'
            return
        }

        $reinstallResult = Restore-BloatwareApps -SessionPath $SessionPath -Confirm:$false

        Write-Host ""
        $resultColor = if ($reinstallResult.Status -eq 'Completed' -or $reinstallResult.Status -eq 'NothingToDo') { 'Green' } else { 'Yellow' }
        Write-Host "Best-effort app recovery: $($reinstallResult.Status) (recovered: $($reinstallResult.Reinstalled), local: $($reinstallResult.RegisteredLocally), Store: $($reinstallResult.InstalledFromStore), already present: $($reinstallResult.AlreadyPresent), failed: $($reinstallResult.Failed), skipped: $($reinstallResult.Skipped))" -ForegroundColor $resultColor
        foreach ($detail in @($reinstallResult.Details)) {
            Write-Host "  - $detail" -ForegroundColor Gray
        }
        if (-not [bool]$reinstallResult.Success) {
            Write-Host "If app recovery fails in this elevated session, run later as the original user non-elevated:" -ForegroundColor DarkGray
            Write-Host "  $manualCommand" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Optional Privacy app recovery could not start: $($_.Exception.Message)" -Module 'Rollback'
        Write-RestoreLog -Level WARNING -Message "Optional Privacy app recovery could not start: $($_.Exception.Message)"
        Write-Host "Best-effort app recovery could not start: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Restore-Session {
    [CmdletBinding()]
    [OutputType([bool], [PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ModuleNames,

        [Parameter(Mandatory = $false)]
        [switch]$NoReboot,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReboot,

        # Skips the interactive reboot prompt SILENTLY so the calling UI can
        # run follow-up steps first (Tier-2 Store reinstall offer) and then
        # prompt itself via Invoke-RestoreRebootPrompt/Get-RestoreRebootReasons.
        [Parameter(Mandatory = $false)]
        [switch]$SuppressRebootPrompt,

        # Machine-readable engine-authoritative operation result for the Pro
        # wrapper. The default Boolean return remains backward compatible for
        # the interactive Shell and public restore entry points.
        [Parameter(Mandatory = $false)]
        [switch]$PassThruContract
    )

    $script:LastRestoreOperationContract = $null
    $contractSessionPath = [string]$SessionPath
    try {
        $contractSessionPath = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)
    }
    catch {
        # A failed contract still reports the supplied path as data. The
        # success path below is always canonical and therefore authoritative.
        $contractSessionPath = [string]$SessionPath
    }
    $dispatchError = ''
    try {
        $isQuickActionSession = $false
        $manifestPath = Join-Path $SessionPath 'manifest.json'
        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $isQuickActionSession = (
                $manifest.PSObject.Properties['schemaVersion'] -and
                [int]$manifest.schemaVersion -eq 3 -and
                $manifest.PSObject.Properties['recordType'] -and
                [string]$manifest.recordType -ceq 'QuickActionSession'
            )
        }
        if ($isQuickActionSession) {
            if ($ModuleNames -or $ForceReboot) {
                throw 'Quick Action restore does not accept module filtering or forced reboot'
            }
            $restoreOutput = @(Restore-QuickActionSession -SessionPath $SessionPath -Confirm:$false)
        }
        else {
            $internalParameters = @{
                SessionPath = $SessionPath
                NoReboot = [bool]$NoReboot
                ForceReboot = [bool]$ForceReboot
                SuppressRebootPrompt = [bool]$SuppressRebootPrompt
            }
            if ($PSBoundParameters.ContainsKey('ModuleNames')) {
                $internalParameters.ModuleNames = @($ModuleNames)
            }
            $restoreOutput = @(Invoke-RestoreSessionInternal @internalParameters)
        }
    }
    catch {
        $dispatchError = $_.Exception.Message
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Restore dispatch failed: $dispatchError" -Module 'Rollback'
        }
        if ($PassThruContract) {
            return [PSCustomObject][ordered]@{
                schemaVersion = 1; success = $false; sessionId = ''; sessionType = ''
                sessionPath = $contractSessionPath
                restoredScopes = @(); restoredModules = @(); manifestSha256 = ''; receiptSha256 = ''
                error = $dispatchError
            }
        }
        return $false
    }
    $booleanResults = @($restoreOutput | Where-Object { $_ -is [bool] })
    if ($booleanResults.Count -ne 1) {
        $null = Write-Log -Level ERROR -Message "Restore returned $($booleanResults.Count) Boolean results instead of exactly one authoritative result" -Module "Rollback"
        if ($PassThruContract) {
            return [PSCustomObject][ordered]@{
                schemaVersion = 1; success = $false; sessionId = ''; sessionType = ''
                sessionPath = $contractSessionPath
                restoredScopes = @(); restoredModules = @(); manifestSha256 = ''; receiptSha256 = ''
                error = 'Engine restore did not return exactly one Boolean result'
            }
        }
        return $false
    }

    $restoreSucceeded = [bool]$booleanResults[-1]
    if (-not $PassThruContract) { return $restoreSucceeded }
    if (-not $restoreSucceeded) {
        return [PSCustomObject][ordered]@{
            schemaVersion = 1; success = $false; sessionId = ''; sessionType = ''
            sessionPath = $contractSessionPath
            restoredScopes = @(); restoredModules = @(); manifestSha256 = ''; receiptSha256 = ''
            error = 'Restore failed; no completed scope was published'
        }
    }

    try {
        if ($isQuickActionSession) {
            $document = Get-QuickActionSessionDocument -SessionPath $SessionPath
            $validatedReceipt = Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest
            $actionScope = "action:$([string]$document.Manifest.actionId)"
            if (-not $validatedReceipt -or $actionScope -notin @($validatedReceipt.restoredScopes)) {
                throw 'Successful Quick Action restore has no matching validated receipt scope'
            }
            $script:LastRestoreOperationContract = [PSCustomObject][ordered]@{
                schemaVersion = 1
                success = $true
                sessionId = [string]$document.Manifest.sessionId
                sessionType = 'quickAction'
                sessionPath = [System.IO.Path]::GetFullPath($document.SessionPath).TrimEnd(
                    [System.IO.Path]::DirectorySeparatorChar,
                    [System.IO.Path]::AltDirectorySeparatorChar)
                restoredScopes = @($actionScope)
                restoredModules = @()
                manifestSha256 = (Get-FileHash -LiteralPath (Join-Path $document.SessionPath 'manifest.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                receiptSha256 = (Get-FileHash -LiteralPath (Join-Path $document.SessionPath 'restore-receipt.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                error = ''
            }
        }
        if (-not $script:LastRestoreOperationContract) {
            throw 'Successful restore did not publish an engine-authoritative operation contract'
        }
        return $script:LastRestoreOperationContract
    }
    catch {
        return [PSCustomObject][ordered]@{
            schemaVersion = 1; success = $false; sessionId = ''; sessionType = ''
            sessionPath = $contractSessionPath
            restoredScopes = @(); restoredModules = @(); manifestSha256 = ''; receiptSha256 = ''
            error = "Restore completed but its engine-authoritative contract could not be validated: $($_.Exception.Message)"
        }
    }
}

function Write-NewerModuleSessionNotice {
    <#
    .SYNOPSIS
        Report newer sessions that already touched the modules about to be restored.

    .DESCRIPTION
        Restoring an older session is legitimate and stays permitted: every module
        writes its own sealed pre-state, and the reverse-order (LIFO) restore makes
        the result deterministic. It is worth surfacing though, because the modules
        do not own disjoint target sets -- the ASR rules for example also appear in
        the Security Baseline registry policies. Applying or restoring one of those
        modules after this session was sealed changes shared values, so the operator
        should know which later session is in play before judging the outcome.

        This is informational only. It never blocks and never mutates. An unreadable
        or malformed neighbour session is skipped rather than failing the restore.
        Quick Action overlap is handled separately and fails closed; see
        Assert-NoNewerQuickActionOverlapForModuleRestore.

    .PARAMETER SessionPath
        Path of the session being restored.

    .PARAMETER Manifest
        Manifest of the session being restored.

    .PARAMETER ModuleNames
        Modules that are about to be restored.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames
    )

    $selectedTime = $null
    try {
        $selectedTime = [DateTime]::Parse(
            [string]$Manifest.timestamp,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch {
        Write-Verbose "Newer-session notice skipped: selected session timestamp is unparsable."
        return
    }

    $backupRoot = Split-Path $SessionPath -Parent
    $overlaps = [System.Collections.Generic.List[object]]::new()

    foreach ($folder in @(Get-ChildItem -LiteralPath $backupRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($folder.FullName -eq $SessionPath) { continue }
        $candidatePath = Join-Path $folder.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) { continue }
        try {
            $candidate = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            # Probe through PSObject: module manifests carry no 'recordType', and
            # NoIDPrivacy.ps1 runs under Set-StrictMode -Version Latest, where a
            # direct read of an absent property throws into the catch below and
            # would silently drop every module neighbour.
            if ($candidate.PSObject.Properties['recordType'] -and
                [string]$candidate.recordType -eq 'QuickActionSession') { continue }
            if (-not $candidate.PSObject.Properties['modules']) { continue }
            if (-not $candidate.PSObject.Properties['timestamp'] -or
                -not $candidate.PSObject.Properties['sessionId']) { continue }

            $candidateTime = [DateTime]::Parse(
                [string]$candidate.timestamp,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            $isNewer = if ($candidateTime -gt $selectedTime) { $true }
            elseif ($candidateTime -lt $selectedTime) { $false }
            else {
                [string]::CompareOrdinal([string]$candidate.sessionId, [string]$Manifest.sessionId) -gt 0
            }
            if (-not $isNewer) { continue }

            $shared = @(@($candidate.modules | ForEach-Object { [string]$_.name }) |
                Where-Object { $ModuleNames -contains $_ } | Sort-Object -Unique)
            if ($shared.Count -eq 0) { continue }

            $receipt = Get-SessionRestoreReceipt -SessionPath $folder.FullName -Manifest $candidate
            $restoredHere = @(if ($receipt) {
                @($shared | Where-Object { "module:$_" -in @($receipt.restoredScopes) })
            })
            $overlaps.Add([PSCustomObject]@{
                SessionId = [string]$candidate.sessionId
                Modules   = $shared
                Restored  = $restoredHere
            })
        }
        catch {
            Write-Verbose "Newer-session notice skipped for '$($folder.Name)': $($_.Exception.Message)"
        }
    }

    if ($overlaps.Count -eq 0) { return }

    # INFO, not WARNING: nothing here is wrong or at risk. Restoring an older
    # session is a supported operation and stays exact for every sealed target;
    # this only tells the operator which later sessions are still in effect.
    $header = "This session is older than $($overlaps.Count) session(s) that touched the same module(s). Restoring it is still exact for every sealed target; later sessions may have changed values that more than one module owns."
    Write-Log -Level INFO -Message $header -Module 'Rollback'
    Write-RestoreLog -Level INFO -Message $header
    foreach ($item in $overlaps) {
        $detail = "  Newer session $($item.SessionId): $($item.Modules -join ', ')" +
            $(if ($item.Restored.Count -gt 0) { " (already restored: $($item.Restored -join ', '))" } else { '' })
        Write-Log -Level INFO -Message $detail -Module 'Rollback'
        Write-RestoreLog -Level INFO -Message $detail
    }
}

function Invoke-RestoreSessionInternal {
    <#
    .SYNOPSIS
        Restore complete session (all modules)

    .PARAMETER SessionPath
        Path to the session folder

    .PARAMETER ModuleNames
        Optional array of specific module names to restore (restores all if not specified)

    .PARAMETER NoReboot
        Skip the reboot prompt entirely (for automation/GUI usage)

    .PARAMETER ForceReboot
        Automatically reboot without prompting (for automation)

    .OUTPUTS
        Boolean indicating overall success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ModuleNames,

        [Parameter(Mandatory = $false)]
        [switch]$NoReboot,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReboot,

        # Silent prompt deferral for interactive callers (see Restore-Session)
        [Parameter(Mandatory = $false)]
        [switch]$SuppressRebootPrompt
    )

    if (-not (Test-Path $SessionPath)) {
        Write-Log -Level ERROR -Message "Session path not found: $SessionPath" -Module "Rollback"
        return $false
    }

    # Track restore duration
    $startTime = Get-Date

    # CRITICAL: Initialize separate restore log (ONLY for restore operations)
    if (-not (Initialize-RestoreLog -SessionPath $SessionPath)) {
        Write-Log -Level ERROR -Message 'Restore aborted because the dedicated restore log could not be initialized' -Module 'Rollback'
        return $false
    }
    Write-RestoreLog -Level INFO -Message "========================================"
    Write-RestoreLog -Level INFO -Message "RESTORE SESSION START"
    Write-RestoreLog -Level INFO -Message "Session Path: $SessionPath"
    if ($ModuleNames) {
        Write-RestoreLog -Level INFO -Message "Specific Modules: $($ModuleNames -join ', ')"
    }
    else {
        Write-RestoreLog -Level INFO -Message "Restoring: ALL modules"
    }
    Write-RestoreLog -Level INFO -Message "========================================"
    Write-RestoreLog -Level INFO -Message " "

    $mutationMutex = $null
    $mutationMutexHeld = $false
    try {
        $manifest = Get-SessionManifest -SessionPath $SessionPath
        Assert-SessionManifest -SessionPath $SessionPath -Manifest $manifest -RequestedModules $ModuleNames

        $mutationMutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
        try {
            $mutationMutexHeld = $mutationMutex.WaitOne(0, $false)
        }
        catch [Threading.AbandonedMutexException] {
            $mutationMutexHeld = $true
        }
        if (-not $mutationMutexHeld) {
            throw 'Another NoID Privacy Apply or Restore operation is already running.'
        }

        Write-Log -Level INFO -Message "Starting session restore: $($manifest.sessionId)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Session ID: $($manifest.sessionId)"

        Write-Log -Level INFO -Message "Session created: $($manifest.timestamp)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Session Created: $($manifest.timestamp)"

        Write-Log -Level INFO -Message "Total items: $($manifest.totalItems)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Total Items Backed Up: $($manifest.totalItems)"
        Write-RestoreLog -Level INFO -Message " "

        $allSucceeded = $true
        $modulesToRestore = @(if ($ModuleNames) {
            $manifest.modules | Where-Object { $ModuleNames -contains $_.name }
        }
        else {
            $manifest.modules
        })
        # A sealed session stays restorable for as long as it exists. The restore
        # receipt is audit history ("this session was restored, and when"), and it
        # keeps ordering Quick Action restores, but it never consumes the backup:
        # going back to a known state twice is the normal case, not an anomaly.
        # Every per-target guard below still refuses to overwrite foreign drift.
        if ($modulesToRestore.Count -eq 0) {
            throw 'This session contains no modules to restore.'
        }
        $securityBaselineRegistryPrestatePath = $null
        if ('SecurityBaseline' -in @($modulesToRestore.name) -and
            @((Get-NoIDSecurityBaselineOverlapModule) | Where-Object { $_ -in @($modulesToRestore.name) }).Count -gt 0) {
            $securityBaselineModule = @($modulesToRestore | Where-Object {
                    [string]$_.name -eq 'SecurityBaseline'
                })
            $registryPrestateArtifacts = @($securityBaselineModule[0].artifacts | Where-Object {
                    [string]$_.type -eq 'SecurityBaseline' -and
                    [string]$_.name -eq 'RegistryPolicies'
                })
            if ($registryPrestateArtifacts.Count -ne 1) {
                throw "Expected exactly one SecurityBaseline RegistryPolicies artifact for combined ASR restore; found $($registryPrestateArtifacts.Count)"
            }
            $securityBaselineRegistryPrestatePath = Resolve-SessionChildPath `
                -SessionPath $SessionPath `
                -RelativePath ([string]$registryPrestateArtifacts[0].relativePath)
        }
        Assert-NoNewerQuickActionOverlapForModuleRestore `
            -SessionPath $SessionPath `
            -Manifest $manifest `
            -ModuleNames @($modulesToRestore.name)

        # Informational only: a newer module session may have rewritten values that
        # more than one module owns. Never blocks the restore.
        Write-NewerModuleSessionNotice `
            -SessionPath $SessionPath `
            -Manifest $manifest `
            -ModuleNames @($modulesToRestore.name)

        # Restore in exact reverse sealed-manifest order (LIFO). Timestamps are
        # audit metadata and are not used as an ordering key, avoiding ties and
        # clock anomalies.
        $reversedModules = @($modulesToRestore)
        [array]::Reverse($reversedModules)

        foreach ($moduleInfo in $reversedModules) {
            Write-Log -Level INFO -Message "Restoring module: $($moduleInfo.name) ($($moduleInfo.itemsBackedUp) items)" -Module "Rollback"
            Write-RestoreLog -Level INFO -Message "========================================"
            Write-RestoreLog -Level INFO -Message "MODULE: $($moduleInfo.name)"
            Write-RestoreLog -Level INFO -Message "Items Backed Up: $($moduleInfo.itemsBackedUp)"
            Write-RestoreLog -Level INFO -Message "Backup Path: $($moduleInfo.backupPath)"
            Write-RestoreLog -Level INFO -Message "Timestamp: $($moduleInfo.timestamp)"
            Write-RestoreLog -Level INFO -Message "========================================"

            $moduleBackupPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$moduleInfo.backupPath)

            if (-not (Test-Path $moduleBackupPath)) {
                Write-Log -Level ERROR -Message "Module backup path not found: $moduleBackupPath" -Module "Rollback"
                Write-RestoreLog -Level ERROR -Message "CRITICAL: Module backup path not found: $moduleBackupPath"
                $allSucceeded = $false
                continue
            }
            Write-RestoreLog -Level DEBUG -Message "Backup path verified: $moduleBackupPath"
            $artifactInventory = @($moduleInfo.artifacts)

            # Pre-restore cleanup: Clear active policies BEFORE restoring backups
            # This ensures hardened settings don't interfere with backup restore

            if ($moduleInfo.name -eq "SecurityBaseline") {
                # Apply writes effective registry values directly and never edits
                # %WinDir%\System32\GroupPolicy. Replacing that unrelated folder
                # during restore would clobber later local/domain policy changes.
                # The targeted snapshot below is the sole registry restore owner.
                Write-RestoreLog -Level INFO -Message "[STEP 1] Registry Policies Restore (exact targeted prestate)"
                $registryPolicyArtifacts = @($artifactInventory | Where-Object {
                        [string]$_.type -eq 'SecurityBaseline' -and [string]$_.name -eq 'RegistryPolicies'
                    })
                $regBackupJson = if ($registryPolicyArtifacts.Count -eq 1) {
                    Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$registryPolicyArtifacts[0].relativePath)
                }
                else { $null }
                Write-RestoreLog -Level DEBUG -Message "Registry backup JSON: $regBackupJson"
                if ($regBackupJson -and (Test-Path -LiteralPath $regBackupJson -PathType Leaf)) {
                    Write-Log -Level INFO -Message "Restoring registry policies from JSON backup (countering GPO tattooing)..." -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "Registry backup found - restoring original values"

                    try {
                        # Load restore function if not in scope
                        if (-not (Get-Command "Restore-RegistryPolicies" -ErrorAction SilentlyContinue)) {
                            Write-RestoreLog -Level DEBUG -Message "Loading Restore-RegistryPolicies function..."
                            $funcPath = Join-Path $PSScriptRoot "..\Modules\SecurityBaseline\Private\Restore-RegistryPolicies.ps1"
                            Write-RestoreLog -Level DEBUG -Message "Function path: $funcPath"
                            if (Test-Path $funcPath) {
                                . $funcPath
                                Write-Log -Level DEBUG -Message "Loaded Restore-RegistryPolicies function" -Module "Rollback"
                                Write-RestoreLog -Level DEBUG -Message "Function loaded successfully"
                            }
                            else {
                                throw "Restore-RegistryPolicies.ps1 not found: $funcPath"
                            }
                        }
                        else {
                            Write-RestoreLog -Level DEBUG -Message "Restore-RegistryPolicies function already loaded"
                        }

                        if (Get-Command "Restore-RegistryPolicies" -ErrorAction SilentlyContinue) {
                            Write-RestoreLog -Level DEBUG -Message "Calling Restore-RegistryPolicies..."
                            # Call restore function directly with combined JSON backup
                            $restoreResult = Restore-RegistryPolicies -BackupPath $regBackupJson
                            Write-RestoreLog -Level DEBUG -Message "Restore function returned - Success: $($restoreResult.Success)"

                            if ($restoreResult.Success) {
                                Write-Log -Level SUCCESS -Message "Registry policies restored: $($restoreResult.ItemsRestored) items (GPO tattooing countered)" -Module "Rollback"
                                Write-RestoreLog -Level SUCCESS -Message "Registry policies restored: $($restoreResult.ItemsRestored) items"
                            }
                            else {
                                Write-Log -Level WARNING -Message "Registry restore had errors: $($restoreResult.Errors.Count) errors" -Module "Rollback"
                                Write-RestoreLog -Level WARNING -Message "Registry restore had $($restoreResult.Errors.Count) errors:"
                                foreach ($err in $restoreResult.Errors) {
                                    Write-Log -Level DEBUG -Message "  - $err" -Module "Rollback"
                                    Write-RestoreLog -Level ERROR -Message "  - $err"
                                }
                                $allSucceeded = $false
                            }

                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore registry policies from JSON: $($_.Exception.Message)" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "Registry restore exception: $($_.Exception.Message)"
                        Write-RestoreLog -Level ERROR -Message "Stack trace: $($_.ScriptStackTrace)"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed RegistryPolicies artifact; found $($registryPolicyArtifacts.Count)" -Module "Rollback"
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed RegistryPolicies artifact; found $($registryPolicyArtifacts.Count)"
                    $allSucceeded = $false
                }

                # STEP 2: Restore and native-query-verify only the sealed audit
                # subcategories. Unrelated audit policy remains untouched.
                Write-RestoreLog -Level INFO -Message '[STEP 2] Audit Policies Restore'
                try {
                    $auditArtifacts = @($moduleInfo.artifacts | Where-Object {
                            [string]$_.name -eq 'AuditPolicies' -and
                            [string]$_.type -eq 'SecurityBaseline'
                        })
                    if ($auditArtifacts.Count -ne 1) {
                        throw "Expected exactly one sealed AuditPolicies artifact; found $($auditArtifacts.Count)"
                    }
                    $auditBackupFile = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$auditArtifacts[0].relativePath)
                    if (-not (Get-Command 'Restore-AuditPolicies' -ErrorAction SilentlyContinue)) {
                        $auditRestoreFunction = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Restore-AuditPolicies.ps1'
                        if (-not (Test-Path -LiteralPath $auditRestoreFunction -PathType Leaf)) {
                            throw "Restore-AuditPolicies.ps1 not found: $auditRestoreFunction"
                        }
                        . $auditRestoreFunction
                    }
                    $auditRestore = Restore-AuditPolicies -BackupPath $auditBackupFile -Confirm:$false
                    if (-not $auditRestore.Success) {
                        throw ($auditRestore.Errors -join '; ')
                    }
                    Write-Log -Level SUCCESS -Message 'Audit policies restored and verified against the sealed backup' -Module 'Rollback'
                    Write-RestoreLog -Level SUCCESS -Message 'Audit policies restored and verified exactly'
                }
                catch {
                    Write-Log -Level ERROR -Message "Audit policy restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Audit policy restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }

                # STEP 3: Restore Security Template
                Write-RestoreLog -Level INFO -Message "[STEP 3] Security Template Restore"

                $secTemplatResult = $null
                try {
                    $securityTemplateArtifacts = @($moduleInfo.artifacts | Where-Object {
                            [string]$_.name -eq 'SecurityTemplate' -and
                            [string]$_.type -eq 'SecurityBaseline'
                        })
                    if ($securityTemplateArtifacts.Count -ne 1) {
                        throw "Expected exactly one sealed SecurityTemplate artifact; found $($securityTemplateArtifacts.Count)"
                    }
                    $secPolicyBackupFile = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$securityTemplateArtifacts[0].relativePath)
                    if (-not (Get-Command 'Restore-SecurityTemplate' -ErrorAction SilentlyContinue)) {
                        $securityTemplateRestoreFunction = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Restore-SecurityTemplate.ps1'
                        if (-not (Test-Path -LiteralPath $securityTemplateRestoreFunction -PathType Leaf)) {
                            throw "Restore-SecurityTemplate.ps1 not found: $securityTemplateRestoreFunction"
                        }
                        . $securityTemplateRestoreFunction
                    }
                    $secTemplatResult = Restore-SecurityTemplate -BackupPath $secPolicyBackupFile
                    if (-not $secTemplatResult.Success) {
                        throw ($secTemplatResult.Errors -join '; ')
                    }
                    Write-RestoreLog -Level SUCCESS -Message 'Security template restored and verified'
                }
                catch {
                    Write-Log -Level ERROR -Message "Security template restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Security template restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }

                if (-not $secTemplatResult -or -not $secTemplatResult.Success) {
                    Write-Log -Level ERROR -Message "Security template restore had errors" -Module "Rollback"
                    $allSucceeded = $false
                }

                $templateRegistryArtifacts = @($artifactInventory | Where-Object {
                        [string]$_.type -eq 'SecurityBaseline' -and [string]$_.name -eq 'SecurityTemplateRegistryState'
                    })
                $templateRegistryBackupFile = if ($templateRegistryArtifacts.Count -eq 1) {
                    Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$templateRegistryArtifacts[0].relativePath)
                }
                else { $null }
                if ($templateRegistryBackupFile -and (Test-Path -LiteralPath $templateRegistryBackupFile -PathType Leaf)) {
                    try {
                        if (-not (Get-Command 'Restore-SecurityTemplateRegistryState' -ErrorAction SilentlyContinue)) {
                            $templateRegistryRestoreFunction = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Restore-SecurityTemplateRegistryState.ps1'
                            if (-not (Test-Path -LiteralPath $templateRegistryRestoreFunction -PathType Leaf)) {
                                throw "Security-template registry restore function not found: $templateRegistryRestoreFunction"
                            }
                            . $templateRegistryRestoreFunction
                        }
                        $templateRegistryRestore = Restore-SecurityTemplateRegistryState -BackupPath $templateRegistryBackupFile
                        if (-not $templateRegistryRestore.Success) {
                            throw ($templateRegistryRestore.Errors -join '; ')
                        }
                        Write-Log -Level SUCCESS -Message "Security-template registry prestate restored and verified ($($templateRegistryRestore.ItemsRestored) values)" -Module 'Rollback'
                        Write-RestoreLog -Level SUCCESS -Message "Security-template registry prestate restored ($($templateRegistryRestore.ItemsRestored) values)"
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Security-template registry prestate restore failed: $_" -Module 'Rollback'
                        Write-RestoreLog -Level ERROR -Message "Security-template registry prestate restore failed: $_"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed SecurityTemplateRegistryState artifact; found $($templateRegistryArtifacts.Count)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed SecurityTemplateRegistryState artifact; found $($templateRegistryArtifacts.Count)"
                    $allSucceeded = $false
                }

                # Targeted UAC restore runs after secedit because effective
                # defaults may be omitted from SecurityTemplate.inf.
                $uacArtifacts = @($artifactInventory | Where-Object {
                        [string]$_.type -eq 'SecurityBaseline' -and [string]$_.name -eq 'UACStandardUserElevation'
                    })
                $uacBackupFile = if ($uacArtifacts.Count -eq 1) {
                    Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$uacArtifacts[0].relativePath)
                }
                else { $null }
                if ($uacBackupFile -and (Test-Path -LiteralPath $uacBackupFile -PathType Leaf)) {
                    try {
                        if (-not (Get-Command 'Restore-UACStandardUserElevation' -ErrorAction SilentlyContinue)) {
                            $uacRestoreFunction = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Restore-UACStandardUserElevation.ps1'
                            if (-not (Test-Path -LiteralPath $uacRestoreFunction -PathType Leaf)) {
                                throw "UAC restore function not found: $uacRestoreFunction"
                            }
                            . $uacRestoreFunction
                        }
                        $uacRestoreResult = Restore-UACStandardUserElevation -BackupPath $uacBackupFile
                        if (-not $uacRestoreResult.Success) {
                            throw ($uacRestoreResult.Errors -join '; ')
                        }
                        Write-Log -Level SUCCESS -Message 'Standard-user UAC elevation behavior restored and verified' -Module 'Rollback'
                        Write-RestoreLog -Level SUCCESS -Message 'ConsentPromptBehaviorUser targeted restore passed'
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Targeted UAC restore failed: $_" -Module 'Rollback'
                        Write-RestoreLog -Level ERROR -Message "Targeted UAC restore failed: $_"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed UACStandardUserElevation artifact; found $($uacArtifacts.Count)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed UACStandardUserElevation artifact; found $($uacArtifacts.Count)"
                    $allSucceeded = $false
                }

                # STEP 4: Restore Xbox Task if it was disabled
                $xboxArtifacts = @($artifactInventory | Where-Object {
                        [string]$_.type -eq 'SecurityBaseline' -and [string]$_.name -eq 'XboxTask'
                    })
                $xboxTaskBackup = if ($xboxArtifacts.Count -eq 1) {
                    Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$xboxArtifacts[0].relativePath)
                }
                else { $null }
                if ($xboxTaskBackup -and (Test-Path -LiteralPath $xboxTaskBackup -PathType Leaf)) {
                    try {
                        if (-not (Get-Command 'Restore-XboxTask' -ErrorAction SilentlyContinue)) {
                            $xboxRestoreFunction = Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\Private\Restore-XboxTask.ps1'
                            if (-not (Test-Path -LiteralPath $xboxRestoreFunction -PathType Leaf)) {
                                throw "Xbox task restore function not found: $xboxRestoreFunction"
                            }
                            . $xboxRestoreFunction
                        }
                        $xboxRestore = Restore-XboxTask -BackupPath $xboxTaskBackup
                        if (-not $xboxRestore.Success) {
                            throw ($xboxRestore.Errors -join '; ')
                        }
                        Write-Log -Level SUCCESS -Message 'Xbox task state restored and verified' -Module 'Rollback'
                        Write-RestoreLog -Level SUCCESS -Message 'Xbox task state restored and verified'
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restore Xbox task state: $_" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "Xbox task restore failed: $_"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed XboxTask artifact; found $($xboxArtifacts.Count)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed XboxTask artifact; found $($xboxArtifacts.Count)"
                    $allSucceeded = $false
                }
            }

            if ($moduleInfo.name -eq 'ASR') {
                try {
                    $asrArtifacts = @($artifactInventory | Where-Object {
                            [string]$_.type -eq 'ASR' -and
                            [string]$_.name -eq 'ASR_ActiveConfiguration'
                        })
                    if ($asrArtifacts.Count -ne 1) {
                        throw "Expected exactly one sealed ASR prestate artifact; found $($asrArtifacts.Count)"
                    }
                    $asrBackupPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$asrArtifacts[0].relativePath)
                    $asrValidatorPath = Join-Path $PSScriptRoot '..\Modules\ASR\Private\Assert-ASRSnapshot.ps1'
                    $asrPreferenceNormalizerPath = Join-Path $PSScriptRoot '..\Modules\ASR\Private\ConvertFrom-ASRPreference.ps1'
                    $asrRestorePath = Join-Path $PSScriptRoot '..\Modules\ASR\Private\Restore-ASRState.ps1'
                    foreach ($requiredASRHelper in @($asrValidatorPath, $asrPreferenceNormalizerPath, $asrRestorePath)) {
                        if (-not (Test-Path -LiteralPath $requiredASRHelper -PathType Leaf)) {
                            throw "Required ASR restore helper is missing: $requiredASRHelper"
                        }
                        . $requiredASRHelper
                    }
                    $asrRestore = if ($securityBaselineRegistryPrestatePath) {
                        Restore-ASRState `
                            -BackupPath $asrBackupPath `
                            -SecurityBaselineRegistryBackupPath $securityBaselineRegistryPrestatePath `
                            -Confirm:$false
                    }
                    else {
                        Restore-ASRState -BackupPath $asrBackupPath -Confirm:$false
                    }
                    if (-not $asrRestore.Success) {
                        throw ($asrRestore.Errors -join '; ')
                    }
                    if ([bool]$asrRestore.AlreadyAtCombinedSessionPrestate) {
                        Write-Log -Level SUCCESS -Message "ASR targets already hold the combined session prestate; repeat restore verified as a no-op ($($asrRestore.Restored) targets)" -Module 'Rollback'
                        Write-RestoreLog -Level SUCCESS -Message "ASR combined session prestate already present ($($asrRestore.Restored) targets)"
                    }
                    else {
                        Write-Log -Level SUCCESS -Message "ASR target prestate restored and verified ($($asrRestore.Restored) targets)" -Module 'Rollback'
                        Write-RestoreLog -Level SUCCESS -Message "ASR target prestate restored and verified ($($asrRestore.Restored) targets)"
                    }
                }
                catch {
                    Write-Log -Level ERROR -Message "ASR target-scoped restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "ASR target-scoped restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }
            }
            # Restore every sealed Registry artifact declared by this module.
            # Artifact identity comes from the trusted manifest, never a filename glob.
            $registryArtifacts = @($artifactInventory | Where-Object { [string]$_.type -eq 'Registry' })
            foreach ($registryArtifact in $registryArtifacts) {
                $uriHiveMount = $null
                $registryArtifactPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$registryArtifact.relativePath)
                # URI handlers are complete owned subtrees. Remove any state created
                # after Apply before importing the exact source-hive backup; a merge
                # would otherwise leave post-backup values behind.
                if ($moduleInfo.name -eq 'AntiAI' -and [string]$registryArtifact.name -match '^URI_(HKLM|HKU)_ms-(edge-)?copilot$') {
                    try {
                        if ([string]::IsNullOrWhiteSpace([string]$registryArtifact.target)) {
                            throw "URI registry artifact has no declared target: $($registryArtifact.relativePath)"
                        }
                        $uriTarget = [string]$registryArtifact.target
                        if (-not (Test-AllowedEmptyMarkerTarget -ModuleName 'AntiAI' -KeyPath $uriTarget)) {
                            throw "URI registry target is outside the AntiAI allowlist: $uriTarget"
                        }
                        if ($uriTarget -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') {
                            $uriHiveMount = Mount-UserRegistryHiveForRestore -Sid $Matches[1]
                        }
                        if (Test-Path -LiteralPath $uriTarget) {
                            Remove-Item -LiteralPath $uriTarget -Recurse -Force -ErrorAction Stop
                        }
                    }
                    catch {
                        if ($uriHiveMount -and -not (Dismount-UserRegistryHiveAfterRestore -Mount $uriHiveMount)) {
                            Write-RestoreLog -Level ERROR -Message "Temporary URI-handler user hive could not be unloaded: $($uriHiveMount.Sid)"
                        }
                        Write-Log -Level ERROR -Message "Failed to prepare exact URI-handler restore: $($_.Exception.Message)" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "Failed to prepare exact URI-handler restore: $($_.Exception.Message)"
                        $allSucceeded = $false
                        continue
                    }
                }

                $success = $false
                try {
                    $success = Restore-FromBackup `
                        -BackupFile $registryArtifactPath `
                        -Type 'Registry' `
                        -ExpectedTarget ([string]$registryArtifact.target)
                }
                catch {
                    Write-Log -Level ERROR -Message "Registry restore threw for sealed artifact $($registryArtifact.name): $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Registry restore threw for sealed artifact $($registryArtifact.name): $($_.Exception.Message)"
                    $success = $false
                }
                finally {
                    if ($uriHiveMount -and -not (Dismount-UserRegistryHiveAfterRestore -Mount $uriHiveMount)) {
                        Write-RestoreLog -Level ERROR -Message "Temporary URI-handler user hive could not be unloaded: $($uriHiveMount.Sid)"
                        $success = $false
                    }
                }
                if (-not $success) {
                    Write-Log -Level ERROR -Message "Registry restore failed for sealed artifact: $($registryArtifact.name)" -Module "Rollback"
                    Write-RestoreLog -Level ERROR -Message "Registry restore failed for sealed artifact: $($registryArtifact.name)"
                    $allSucceeded = $false
                }
            }

            if ($moduleInfo.name -eq "AntiAI") {
                # Apply the exact targeted AntiAI policy prestate from the sealed manifest.
                $antiAIPreStateArtifacts = @($artifactInventory | Where-Object {
                        [string]$_.type -eq 'AntiAI' -and [string]$_.name -eq 'AntiAI_PreState'
                    })
                $antiAIPreStatePath = if ($antiAIPreStateArtifacts.Count -eq 1) {
                    Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$antiAIPreStateArtifacts[0].relativePath)
                }
                else { $null }
                if ($antiAIPreStatePath -and (Test-Path -LiteralPath $antiAIPreStatePath -PathType Leaf)) {
                    Write-Log -Level INFO -Message "Restoring AntiAI pre-state snapshot..." -Module "Rollback"
                    try {
                        if (-not (Get-Command 'Restore-AntiAIRegistryState' -ErrorAction SilentlyContinue)) {
                            $antiAIValidatorFunction = Join-Path $PSScriptRoot '..\Modules\AntiAI\Private\Assert-AntiAIRegistrySnapshot.ps1'
                            $antiAIRestoreFunction = Join-Path $PSScriptRoot '..\Modules\AntiAI\Private\Restore-AntiAIRegistryState.ps1'
                            if (-not (Test-Path -LiteralPath $antiAIValidatorFunction -PathType Leaf)) {
                                throw "Assert-AntiAIRegistrySnapshot.ps1 not found: $antiAIValidatorFunction"
                            }
                            if (-not (Test-Path -LiteralPath $antiAIRestoreFunction -PathType Leaf)) {
                                throw "Restore-AntiAIRegistryState.ps1 not found: $antiAIRestoreFunction"
                            }
                            . $antiAIValidatorFunction
                            . $antiAIRestoreFunction
                        }
                        $antiAIRestore = Restore-AntiAIRegistryState -BackupPath $antiAIPreStatePath
                        if (-not $antiAIRestore.Success) {
                            throw ($antiAIRestore.Errors -join '; ')
                        }
                        Write-Log -Level SUCCESS -Message "AntiAI pre-state restored and verified ($($antiAIRestore.Verified) values)" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to apply AntiAI pre-state snapshot: $($_.Exception.Message)" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "AntiAI pre-state restore failed: $($_.Exception.Message)"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed AntiAI_PreState artifact; found $($antiAIPreStateArtifacts.Count)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed AntiAI_PreState artifact; found $($antiAIPreStateArtifacts.Count)"
                    $allSucceeded = $false
                }
            }

            # Handle every sealed EmptyMarker artifact from the manifest.
            $emptyMarkerArtifacts = @($artifactInventory | Where-Object { [string]$_.type -eq 'EmptyMarker' })
            foreach ($declaredArtifact in $emptyMarkerArtifacts) {
                $emptyMarkerMount = $null
                $markerPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$declaredArtifact.relativePath)
                try {
                    $markerData = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ([int]$markerData.SchemaVersion -ne 2 -or
                        [string]$markerData.State -ne 'NotExisted' -or
                        [string]::IsNullOrWhiteSpace([string]$markerData.KeyPath)) {
                        throw 'Empty marker has an invalid state or missing key path'
                    }
                    if ([string]$declaredArtifact.target -ne [string]$markerData.KeyPath) {
                        throw "Empty marker target does not match the manifest artifact target"
                    }
                    if (-not (Test-AllowedEmptyMarkerTarget -ModuleName ([string]$moduleInfo.name) -KeyPath ([string]$markerData.KeyPath))) {
                        throw "Empty marker target is outside the module restore allowlist: $($markerData.KeyPath)"
                    }
                    if ([string]$markerData.KeyPath -match '(?i)^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)\\') {
                        $emptyMarkerMount = Mount-UserRegistryHiveForRestore -Sid $Matches[1]
                    }
                    Write-Log -Level INFO -Message "Processing empty marker: enforcing original absence for '$($markerData.KeyPath)'" -Module "Rollback"

                    $isAntiAIUriMarker = ([string]$moduleInfo.name -eq 'AntiAI' -and
                        [string]$markerData.KeyPath -match '(?i)^(?:HKLM:\\SOFTWARE|HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\Software)\\Classes\\ms-(?:edge-)?copilot$')
                    if ($isAntiAIUriMarker -and (Test-Path -LiteralPath $markerData.KeyPath)) {
                        throw "Originally absent AntiAI URI source was created after Apply; refusing to delete later unowned state: $($markerData.KeyPath)"
                    }
                    if (-not $isAntiAIUriMarker -and (Test-Path -LiteralPath $markerData.KeyPath)) {
                        Remove-Item -LiteralPath $markerData.KeyPath -Recurse -Force -ErrorAction Stop
                    }
                    if (Test-Path -LiteralPath $markerData.KeyPath) {
                        throw "Registry key still exists after empty-marker restore: $($markerData.KeyPath)"
                    }
                    Write-Log -Level SUCCESS -Message "Registry key verified absent: $($markerData.KeyPath)" -Module "Rollback"
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to process empty marker $($declaredArtifact.name): $_" -Module "Rollback"
                    Write-RestoreLog -Level ERROR -Message "Empty-marker restore failed for $($declaredArtifact.name): $_"
                    $allSucceeded = $false
                }
                finally {
                    if ($emptyMarkerMount -and -not (Dismount-UserRegistryHiveAfterRestore -Mount $emptyMarkerMount)) {
                        Write-Log -Level ERROR -Message "Temporary empty-marker user hive could not be unloaded: $($emptyMarkerMount.Sid)" -Module 'Rollback'
                        Write-RestoreLog -Level ERROR -Message "Temporary empty-marker user hive could not be unloaded: $($emptyMarkerMount.Sid)"
                        $allSucceeded = $false
                    }
                }
            }

            # Restore every sealed service backup declared in the manifest.
            $serviceArtifacts = @(Get-ServiceArtifactsInRestoreOrder -Artifacts @(
                    $artifactInventory | Where-Object { [string]$_.type -eq 'Service' }
                ))
            foreach ($serviceArtifact in $serviceArtifacts) {
                $serviceArtifactPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$serviceArtifact.relativePath)
                $success = Restore-FromBackup `
                    -BackupFile $serviceArtifactPath `
                    -Type 'Service' `
                    -ExpectedTarget ([string]$serviceArtifact.target)
                if (-not $success) {
                    Write-RestoreLog -Level ERROR -Message "Service restore failed: $($serviceArtifact.name)"
                    $allSucceeded = $false
                }
            }

            # Restore every sealed scheduled-task backup declared in the manifest.
            $taskArtifacts = @($artifactInventory | Where-Object { [string]$_.type -eq 'ScheduledTask' })
            foreach ($taskArtifact in $taskArtifacts) {
                $taskArtifactPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$taskArtifact.relativePath)
                $success = Restore-FromBackup `
                    -BackupFile $taskArtifactPath `
                    -Type 'ScheduledTask' `
                    -ExpectedTarget ([string]$taskArtifact.target)
                if (-not $success) {
                    Write-RestoreLog -Level ERROR -Message "Scheduled-task restore failed: $($taskArtifact.name)"
                    $allSucceeded = $false
                }
            }

            # Special handling for DNS: Restore DNS settings from backup
            if ($moduleInfo.name -eq "DNS") {
                Write-Log -Level INFO -Message "Restoring DNS settings from backup..." -Module "Rollback"

                $dnsArtifacts = @($moduleInfo.artifacts | Where-Object {
                        [string]$_.name -eq 'DNS_PreState' -and [string]$_.type -eq 'DNS'
                    })
                if ($dnsArtifacts.Count -eq 1) {
                    $dnsBackupFilePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$dnsArtifacts[0].relativePath)
                    Write-Log -Level INFO -Message "Found sealed DNS backup: $([System.IO.Path]::GetFileName($dnsBackupFilePath))" -Module "Rollback"

                    # Load only the exact side-effect-free validator,
                    # canonicalizer, and restore function required by the
                    # sealed-session restore path.
                    $dnsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\DNS'
                    $dnsRestoreHelpers = @(
                        (Join-Path $dnsRoot 'Private\Assert-DNSBackupSnapshot.ps1'),
                        (Join-Path $dnsRoot 'Private\ConvertTo-DnsCanonicalAddress.ps1'),
                        (Join-Path $dnsRoot 'Private\DnsInterfaceDoh.ps1'),
                        (Join-Path $dnsRoot 'Public\Restore-DNSSettings.ps1')
                    )
                    $missingDnsRestoreHelpers = @($dnsRestoreHelpers | Where-Object {
                            -not (Test-Path -LiteralPath $_ -PathType Leaf)
                        })
                    if ($missingDnsRestoreHelpers.Count -eq 0) {
                        try {
                            foreach ($dnsRestoreHelper in $dnsRestoreHelpers) {
                                Write-Log -Level INFO -Message "Loading DNS restore helper: $([System.IO.Path]::GetFileName($dnsRestoreHelper))" -Module 'Rollback'
                                . $dnsRestoreHelper
                            }
                            Write-Log -Level INFO -Message 'DNS restore helpers loaded' -Module 'Rollback'

                            # Call DNS module's restore function
                            Write-Log -Level INFO -Message 'Invoking exact DNS restore function' -Module 'Rollback'
                            $restoreResult = if ($securityBaselineRegistryPrestatePath) {
                                Restore-DNSSettings `
                                    -BackupFilePath $dnsBackupFilePath `
                                    -SecurityBaselineRegistryBackupPath $securityBaselineRegistryPrestatePath `
                                    -Confirm:$false
                            }
                            else {
                                Restore-DNSSettings -BackupFilePath $dnsBackupFilePath -Confirm:$false
                            }

                            if ($restoreResult) {
                                Write-Log -Level SUCCESS -Message "DNS settings restored successfully" -Module "Rollback"
                            }
                            else {
                                Write-Log -Level WARNING -Message "DNS restore had issues - check logs" -Module "Rollback"
                                Write-RestoreLog -Level ERROR -Message "DNS restore reported failure: $([System.IO.Path]::GetFileName($dnsBackupFilePath))"
                                $allSucceeded = $false
                            }

                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to restore DNS settings: $_" -Module "Rollback"
                            Write-RestoreLog -Level ERROR -Message "DNS restore exception: $_"
                            $allSucceeded = $false
                        }
                    }
                    else {
                        Write-Log -Level WARNING -Message "DNS restore helper missing: $($missingDnsRestoreHelpers -join ', ')" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "DNS restore helper missing: $($missingDnsRestoreHelpers -join ', ')"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level ERROR -Message "Expected exactly one sealed DNS_PreState artifact; found $($dnsArtifacts.Count)" -Module "Rollback"
                    Write-RestoreLog -Level ERROR -Message "Expected exactly one sealed DNS_PreState artifact; found $($dnsArtifacts.Count)"
                    $allSucceeded = $false
                }
            }

            # Edge owns only the selected policy values it wrote. Restore those
            # exact value states from the sealed artifact and verify type/value;
            # never clear the entire Edge policy tree or merge an untrusted file.
            if ($moduleInfo.name -eq 'EdgeHardening') {
                try {
                    $edgeArtifacts = @($moduleInfo.artifacts | Where-Object {
                            [string]$_.name -eq 'EdgeHardening_PreState' -and
                            [string]$_.type -eq 'EdgeHardening'
                        })
                    if ($edgeArtifacts.Count -ne 1) {
                        throw "Expected exactly one sealed EdgeHardening_PreState artifact; found $($edgeArtifacts.Count)"
                    }
                    $edgePreStatePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$edgeArtifacts[0].relativePath)
                    if (-not (Get-Command 'Restore-EdgePolicies' -ErrorAction SilentlyContinue)) {
                        $edgeValidatorFunction = Join-Path $PSScriptRoot '..\Modules\EdgeHardening\Private\Assert-EdgePolicySnapshot.ps1'
                        $edgeRestoreFunction = Join-Path $PSScriptRoot '..\Modules\EdgeHardening\Private\Restore-EdgePolicies.ps1'
                        foreach ($requiredEdgeFunction in @($edgeValidatorFunction, $edgeRestoreFunction)) {
                            if (-not (Test-Path -LiteralPath $requiredEdgeFunction -PathType Leaf)) {
                                throw "Required Edge restore function not found: $requiredEdgeFunction"
                            }
                            . $requiredEdgeFunction
                        }
                    }
                    $edgeRestore = Restore-EdgePolicies -BackupPath $edgePreStatePath
                    if (-not $edgeRestore.Success) {
                        throw ($edgeRestore.Errors -join '; ')
                    }
                    Write-Log -Level SUCCESS -Message "Edge pre-state restored and verified ($($edgeRestore.ValuesVerified) values)" -Module 'Rollback'
                    Write-RestoreLog -Level SUCCESS -Message "Edge pre-state restored and verified ($($edgeRestore.ValuesVerified) values)"
                }
                catch {
                    Write-Log -Level ERROR -Message "EdgeHardening pre-state restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "EdgeHardening pre-state restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }
            }

            # Privacy restores selected registry/service/task state exactly.
            # Its optional Tier 1/Tier 2 app inventories are integrity-checked but
            # deliberately not replayed as exact state because app recovery cannot
            # reproduce deleted data, licensing, or every obsolete package version.
            if ($moduleInfo.name -eq 'Privacy') {
                try {
                    $privacyArtifacts = @($moduleInfo.artifacts | Where-Object {
                            [string]$_.name -eq 'Privacy_PreState' -and [string]$_.type -eq 'Privacy'
                        })
                    if ($privacyArtifacts.Count -ne 1) {
                        throw "Expected exactly one sealed Privacy_PreState artifact; found $($privacyArtifacts.Count)"
                    }
                    $privacyPreStatePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$privacyArtifacts[0].relativePath)
                    if (-not (Get-Command 'Assert-PrivacyRegistrySnapshot' -ErrorAction SilentlyContinue) -or
                        -not (Get-Command 'Get-PrivacyUserContext' -ErrorAction SilentlyContinue) -or
                        -not (Get-Command 'Invoke-PrivacyWindowsSearchUserState' -ErrorAction SilentlyContinue) -or
                        -not (Get-Command 'Send-PrivacySearchPolicyChangeNotification' -ErrorAction SilentlyContinue) -or
                        -not (Get-Command 'Restore-PrivacyRegistryState' -ErrorAction SilentlyContinue)) {
                        $privacyTier1RestoreDefinitionFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Get-PrivacyTier1RestorePolicyDefinitions.ps1'
                        $privacyUserContextFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Get-PrivacyUserContext.ps1'
                        $privacyValidatorFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Assert-PrivacyRegistrySnapshot.ps1'
                        $privacyWindowsSearchFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacyWindowsSearch.ps1'
                        $privacySearchNotificationFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacySearchPolicyNotification.ps1'
                        $privacyRestoreFunction = Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Restore-PrivacyRegistryState.ps1'
                        foreach ($privacyFunction in @(
                                $privacyTier1RestoreDefinitionFunction,
                                $privacyUserContextFunction,
                                $privacyValidatorFunction,
                                $privacyWindowsSearchFunction,
                                $privacySearchNotificationFunction,
                                $privacyRestoreFunction
                            )) {
                            if (-not (Test-Path -LiteralPath $privacyFunction -PathType Leaf)) {
                                throw "Privacy restore helper not found: $privacyFunction"
                            }
                            . $privacyFunction
                        }
                    }
                    $privacyRestore = Restore-PrivacyRegistryState -BackupPath $privacyPreStatePath
                    if (-not $privacyRestore.Success) { throw ($privacyRestore.Errors -join '; ') }
                    Write-Log -Level SUCCESS -Message "Privacy prestate restored and verified ($($privacyRestore.Verified) registry values, $($privacyRestore.FirewallVerified) AppX firewall rules)" -Module 'Rollback'
                    Write-RestoreLog -Level SUCCESS -Message "Privacy prestate restored and verified ($($privacyRestore.Verified) registry values, $($privacyRestore.FirewallVerified) AppX firewall rules)"
                }
                catch {
                    Write-Log -Level ERROR -Message "Privacy prestate restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "Privacy prestate restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }

                # App-removal tiers seal pre-removal inventories (class
                # NonExactRestore), never automatic exact-restore targets. Report
                # the separate recovery command and continue.
                $bloatwareActionArtifacts = @($moduleInfo.artifacts | Where-Object {
                        [string]$_.name -in @('Privacy_Tier1AppInventory','Privacy_BloatwareActions') -and
                        [string]$_.type -eq 'Privacy'
                    })
                if ($bloatwareActionArtifacts.Count -gt 0) {
                    $duplicateAppInventories = @($bloatwareActionArtifacts | Group-Object name | Where-Object Count -gt 1)
                    if ($duplicateAppInventories.Count -gt 0) {
                        throw 'Privacy app inventory artifact is duplicated in the sealed manifest'
                    }
                    $bloatwareReinstallHint = "Privacy Tier 1/Tier 2 app actions: skipped by design as exact state. Best-effort local package re-registration with verified Store fallback: Import-Module '.\Modules\Privacy\Privacy.psd1'; Restore-BloatwareApps -SessionPath '$SessionPath'"
                    Write-Log -Level INFO -Message $bloatwareReinstallHint -Module 'Rollback'
                    Write-RestoreLog -Level INFO -Message $bloatwareReinstallHint
                }
            }

            # AdvancedSecurity restores only explicitly declared, sealed artifacts.
            # Legacy root-folder discovery and broad RDP/WPAD fallbacks are rejected.
            if ($moduleInfo.name -eq 'AdvancedSecurity') {
                Write-RestoreLog -Level INFO -Message '[ADVANCEDSECURITY] Restoring sealed module artifacts'
                $advancedModuleLoaded = $false
                try {
                    $preStateArtifacts = @($moduleInfo.artifacts | Where-Object {
                            [string]$_.name -eq 'AdvancedSecurity_PreState' -and
                            [string]$_.type -eq 'AdvancedSecurity'
                        })
                    if ($preStateArtifacts.Count -ne 1) {
                        throw "Expected exactly one AdvancedSecurity_PreState artifact; found $($preStateArtifacts.Count)"
                    }
                    $advSecPreStatePath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$preStateArtifacts[0].relativePath)
                    $advancedPreStateDocument = Get-Content -LiteralPath $advSecPreStatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    if ([int]$advancedPreStateDocument.SchemaVersion -ne 5 -or
                        [int]$advancedPreStateDocument.TargetCount -ne @($advancedPreStateDocument.Entries).Count) {
                        throw 'AdvancedSecurity prestate does not satisfy the current exact schema-v5 contract'
                    }
                    $firewallArtifacts = @($artifactInventory | Where-Object {
                            [string]$_.type -eq 'FirewallPolicy' -and
                            [string]$_.name -eq 'AdvancedSecurity_FirewallPolicy'
                        })
                    $expectedFirewallArtifactCount = if ([bool]$advancedPreStateDocument.SkipFirewallLayer) { 0 } else { 1 }
                    if ($firewallArtifacts.Count -ne $expectedFirewallArtifactCount) {
                        throw "AdvancedSecurity firewall artifact/prestate mismatch: expected $expectedFirewallArtifactCount, found $($firewallArtifacts.Count)"
                    }
                    $advancedRegistryRestorePath = Join-Path $PSScriptRoot '..\Modules\AdvancedSecurity\Private\Restore-AdvancedSecurityRegistryState.ps1'
                    if (-not (Test-Path -LiteralPath $advancedRegistryRestorePath -PathType Leaf)) {
                        throw "AdvancedSecurity registry restore helper not found: $advancedRegistryRestorePath"
                    }
                    . $advancedRegistryRestorePath
                    $registryRestore = Restore-AdvancedSecurityRegistryState `
                        -BackupPath $advSecPreStatePath `
                        -Confirm:$false
                    if (-not $registryRestore.Success) {
                        throw ($registryRestore.Errors -join '; ')
                    }
                    Write-RestoreLog -Level SUCCESS -Message "AdvancedSecurity registry state verified ($($registryRestore.Verified) targets)"

                    $customDefinitions = @{
                        'AdvancedSecurity_FirewallPolicy' = 'FirewallPolicy'
                        'PowerShellV2'                    = 'WindowsFeature'
                        'WiFiDirect_Adapters'             = 'AdvancedSecurity'
                        'NetBIOS_Adapters'                = 'AdvancedSecurity'
                    }
                    $customArtifacts = @($moduleInfo.artifacts | Where-Object {
                            $customDefinitions.ContainsKey([string]$_.name)
                        })
                    foreach ($artifact in $customArtifacts) {
                        $expectedType = [string]$customDefinitions[[string]$artifact.name]
                        if ([string]$artifact.type -ne $expectedType) {
                            throw "AdvancedSecurity artifact type mismatch for $($artifact.name): expected $expectedType, got $($artifact.type)"
                        }
                    }

                    if ($customArtifacts.Count -gt 0) {
                        $advSecModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\AdvancedSecurity\AdvancedSecurity.psd1'
                        if (-not (Test-Path -LiteralPath $advSecModulePath -PathType Leaf)) {
                            throw "AdvancedSecurity module not found: $advSecModulePath"
                        }
                        Import-Module $advSecModulePath -Force -ErrorAction Stop
                        $advancedModuleLoaded = $true
                        Initialize-NoIDModuleDependencyBridge `
                            -ImportedModule (Get-Module -Name AdvancedSecurity -ErrorAction Stop)

                        foreach ($artifact in $customArtifacts) {
                            $artifactPath = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$artifact.relativePath)
                            Write-RestoreLog -Level INFO -Message "Restoring sealed AdvancedSecurity artifact: $($artifact.name)"
                            if (-not (Restore-AdvancedSecuritySettings `
                                    -BackupFilePath $artifactPath `
                                    -ArtifactName ([string]$artifact.name) `
                                    -Confirm:$false)) {
                                throw "AdvancedSecurity artifact restore failed: $($artifact.name)"
                            }
                            Write-RestoreLog -Level SUCCESS -Message "Restored sealed AdvancedSecurity artifact: $($artifact.name)"
                        }
                    }
                }
                catch {
                    Write-Log -Level ERROR -Message "AdvancedSecurity restore failed: $($_.Exception.Message)" -Module 'Rollback'
                    Write-RestoreLog -Level ERROR -Message "AdvancedSecurity restore failed: $($_.Exception.Message)"
                    $allSucceeded = $false
                }
                finally {
                    if ($advancedModuleLoaded) {
                        Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
                    }
                }
            }

            # Do not derive restore truth from log side effects. The invocation
            # writes one manifest-bound receipt only after the complete selected
            # scope has succeeded; any module failure leaves that scope
            # unclaimed instead of publishing partial or false evidence.
            Write-Log -Level INFO -Message "Completed restore processing for module: $($moduleInfo.name)" -Module "Rollback"
            Write-RestoreLog -Level INFO -Message "Module $($moduleInfo.name) restore processing completed"
            Write-RestoreLog -Level INFO -Message " "
        }

        if ($script:RestoreLogWriteFailed) {
            $allSucceeded = $false
            Write-Log -Level ERROR -Message 'Dedicated restore log became unavailable during restore' -Module 'Rollback'
        }

        if ($allSucceeded) {
            try {
                $restoredModuleNames = @($reversedModules | ForEach-Object { [string]$_.name })
                if (-not (Remove-NoIDApplyIntentModules -ModuleNames $restoredModuleNames)) {
                    throw 'Apply-intent invalidation returned failure'
                }
                Write-Log -Level INFO -Message "Invalidated durable Apply intent for restored modules: $($restoredModuleNames -join ', ')" -Module 'Rollback'
            }
            catch {
                # Intent is only a future comparison label. Exact live restore
                # truth and its receipt must never be revoked by label-storage
                # failure; standalone verification will ignore unreadable state.
                Write-Log -Level WARNING -Message "Restored live state but could not invalidate its optional Apply-intent label: $($_.Exception.Message)" -Module 'Rollback'
                Write-RestoreLog -Level WARNING -Message "Optional Apply-intent invalidation failed after exact restore: $($_.Exception.Message)"
            }
        }

        # The receipt is the last durable publication step. It may claim a
        # completed scope only after live state verification has succeeded.
        # Optional intent-label maintenance never controls restore truth. A failure before this point leaves
        # the session safely retryable and never publishes stale success.
        if ($allSucceeded) {
            try {
                $restoreScopes = @($reversedModules | ForEach-Object {
                        "module:$([string]$_.name)"
                    })
                $null = Write-SessionRestoreReceipt `
                    -SessionPath $SessionPath `
                    -Manifest $manifest `
                    -Scopes $restoreScopes `
                    -Confirm:$false
                $validatedReceipt = Get-SessionRestoreReceipt -SessionPath $SessionPath -Manifest $manifest
                foreach ($restoreScope in $restoreScopes) {
                    if ($restoreScope -notin @($validatedReceipt.restoredScopes)) {
                        throw "Restore receipt is missing the completed operation scope: $restoreScope"
                    }
                }
                $script:LastRestoreOperationContract = [PSCustomObject][ordered]@{
                    schemaVersion = 1
                    success = $true
                    sessionId = [string]$manifest.sessionId
                    sessionType = 'moduleSession'
                    sessionPath = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd(
                        [System.IO.Path]::DirectorySeparatorChar,
                        [System.IO.Path]::AltDirectorySeparatorChar)
                    restoredScopes = @($restoreScopes)
                    restoredModules = @($reversedModules | ForEach-Object { [string]$_.name })
                    manifestSha256 = (Get-FileHash -LiteralPath (Join-Path $SessionPath 'manifest.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    receiptSha256 = (Get-FileHash -LiteralPath (Join-Path $SessionPath 'restore-receipt.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    error = ''
                }
            }
            catch {
                $allSucceeded = $false
                Write-Log -Level ERROR -Message "Restore receipt failed for completed session scope: $($_.Exception.Message)" -Module 'Rollback'
                Write-RestoreLog -Level ERROR -Message "Restore receipt failed for completed session scope: $($_.Exception.Message)"
            }
        }

        if ($allSucceeded) {
            Write-Log -Level SUCCESS -Message "Session restore completed successfully" -Module "Rollback"
            Write-RestoreLog -Level SUCCESS -Message "========================================"
            Write-RestoreLog -Level SUCCESS -Message "RESTORE COMPLETED SUCCESSFULLY"
            Write-RestoreLog -Level SUCCESS -Message "All modules restored without errors"
            Write-RestoreLog -Level SUCCESS -Message "========================================"
        }
        else {
            Write-Log -Level WARNING -Message "Session restore completed with some failures" -Module "Rollback"
            Write-RestoreLog -Level WARNING -Message "========================================"
            Write-RestoreLog -Level WARNING -Message "RESTORE COMPLETED WITH FAILURES"
            Write-RestoreLog -Level WARNING -Message "Check log above for error details"
            Write-RestoreLog -Level WARNING -Message "========================================"
        }

        Write-Host ""
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host "============================================================================" -ForegroundColor Cyan
        if ($allSucceeded) {
            Write-Host ""
            Write-Host "                    RESTORE COMPLETED SUCCESSFULLY                       " -ForegroundColor Green
            Write-Host ""
            Write-Host "  Every sealed NoID Privacy-owned target in the selected session passed restore verification" -ForegroundColor White
            Write-Host "  Modules restored: $($reversedModules.Count) | Total items: $($manifest.totalItems)" -ForegroundColor Gray
            Write-Host ""
        }
        else {
            Write-Host ""
            Write-Host "                    RESTORE COMPLETED WITH ISSUES                        " -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Some items could not be restored - check logs for details" -ForegroundColor Gray
            Write-Host "  Modules processed: $($reversedModules.Count) | Total items: $($manifest.totalItems)" -ForegroundColor Gray
            Write-Host ""
        }
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ""

        # Final restore log entry
        $endTime = Get-Date
        $duration = $endTime - $startTime
        Write-RestoreLog -Level INFO -Message " "
        Write-RestoreLog -Level INFO -Message "========================================"
        Write-RestoreLog -Level INFO -Message "RESTORE SESSION END"
        Write-RestoreLog -Level INFO -Message "Duration: $($duration.ToString('mm\:ss'))"
        Write-RestoreLog -Level INFO -Message "Final Status: $(if ($allSucceeded) {'SUCCESS'} else {'PARTIAL FAILURE'})"
        Write-RestoreLog -Level INFO -Message "Restore Log: $script:RestoreLogPath"
        Write-RestoreLog -Level INFO -Message "========================================"

        # Never reboot after a failed/partial restore. For a successful restore,
        # prompt only when the restored module set owns restart-sensitive state.
        if ($allSucceeded) {
            # The app-reinstall offer is part of the canonical Restore-Session
            # follow-up flow. This covers direct interactive Restore-Session
            # calls as well as both menu wrappers. -NoReboot, -ForceReboot and
            # noninteractive hosts are automation contracts and never prompt.
            $suppressAppReinstallPrompt = [bool]($NoReboot -or $ForceReboot)
            if (-not $suppressAppReinstallPrompt) {
                $suppressAppReinstallPrompt = if (Get-Command Test-NonInteractiveMode -ErrorAction SilentlyContinue) {
                    [bool](Test-NonInteractiveMode)
                }
                else {
                    [Environment]::GetCommandLineArgs() -contains '-NonInteractive'
                }
            }
            $null = Invoke-RestoreBloatwareReinstallOffer `
                -SessionPath $SessionPath `
                -Manifest $manifest `
                -RestoredModuleNames @($reversedModules.name) `
                -SuppressPrompt:$suppressAppReinstallPrompt

            if ($SuppressRebootPrompt) {
                # The interactive caller runs follow-up steps first (e.g. the
                # reboot decision) and prompts afterwards via
                # Invoke-RestoreRebootPrompt + Get-RestoreRebootReasons.
                Write-Log -Level INFO -Message 'Reboot prompt deferred to the calling UI' -Module 'Rollback'
            }
            else {
                Invoke-RestoreRebootPrompt `
                    -NoReboot:$NoReboot `
                    -ForceReboot:$ForceReboot `
                    -Reasons @(Get-RestoreRebootReasons -ModuleNames @($reversedModules.name))
            }
        }
        else {
            Write-Log -Level WARNING -Message 'Reboot prompt suppressed because restore did not complete successfully' -Module 'Rollback'
        }

        return $allSucceeded
    }
    catch {
        Write-ErrorLog -Message "Failed to restore hardening session: $SessionPath" -Module "Rollback" -ErrorRecord $_
        Write-RestoreLog -Level ERROR -Message "CRITICAL FAILURE: $_"
        Write-RestoreLog -Level ERROR -Message "Restore aborted with exception"
        return $false
    }
    finally {
        if ($mutationMutexHeld) {
            try { $mutationMutex.ReleaseMutex() }
            catch {
                Write-Verbose "Mutation mutex release failed: $($_.Exception.Message)"
            }
        }
        if ($mutationMutex) {
            $mutationMutex.Dispose()
        }
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
