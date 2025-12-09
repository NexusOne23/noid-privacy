<#
.SYNOPSIS
    Backup and rollback functionality for NoID Privacy Framework
    
.DESCRIPTION
    Implements the BACKUP/APPLY/VERIFY/RESTORE pattern for safe system modifications.
    Creates backups before changes and provides rollback capabilities.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: PowerShell 5.1+
#>

# Global backup tracking (MUST be $global: for cross-module session sharing)
# Using $script: would create separate sessions per Import-Module call!
# IMPORTANT: Only initialize if not already set - prevents reset on re-load!
# NOTE: Must use Get-Variable to check existence (direct access fails in Strict Mode)
if (-not (Get-Variable -Name 'BackupIndex' -Scope Global -ErrorAction SilentlyContinue)) { $global:BackupIndex = @() }
if (-not (Get-Variable -Name 'BackupBasePath' -Scope Global -ErrorAction SilentlyContinue)) { $global:BackupBasePath = "" }
if (-not (Get-Variable -Name 'NewlyCreatedKeys' -Scope Global -ErrorAction SilentlyContinue)) { $global:NewlyCreatedKeys = @() }
if (-not (Get-Variable -Name 'SessionManifest' -Scope Global -ErrorAction SilentlyContinue)) { $global:SessionManifest = @{} }
if (-not (Get-Variable -Name 'CurrentModule' -Scope Global -ErrorAction SilentlyContinue)) { $global:CurrentModule = "" }

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
    if (-not (Test-Path -Path $BackupDirectory)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    }
    
    # Reuse existing session if already initialized
    if ($global:BackupBasePath -and (Test-Path -Path $global:BackupBasePath)) {
        Write-Log -Level DEBUG -Message "Backup system already initialized, reusing session: $global:BackupBasePath" -Module "Rollback"
        return $true
    }
    
    # Create session-specific backup folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sessionId = "Session_$timestamp"
    $sessionBackupPath = Join-Path $BackupDirectory $sessionId
    New-Item -ItemType Directory -Path $sessionBackupPath -Force | Out-Null
    
    # Normalize path for clean log output (removes ..\)
    $global:BackupBasePath = [System.IO.Path]::GetFullPath($sessionBackupPath)
    $global:BackupIndex = @()
    $global:NewlyCreatedKeys = @()
    
    # Initialize session manifest
    $global:SessionManifest = @{
        sessionId        = $sessionId
        displayName      = ""                    # Auto-generated based on modules
        sessionType      = "unknown"             # wizard | advanced | manual
        timestamp        = Get-Date -Format "o"
        frameworkVersion = "2.2.0"
        modules          = @()
        totalItems       = 0
        restorable       = $true
        sessionPath      = $global:BackupBasePath
    }
    
    Write-Log -Level INFO -Message "Backup system initialized: $global:BackupBasePath" -Module "Rollback"
    
    return $true
}

function Set-SessionType {
    <#
    .SYNOPSIS
        Set the session type for better identification in restore UI
        
    .PARAMETER SessionType
        Type of session: wizard, advanced, or manual
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("wizard", "advanced", "manual")]
        [string]$SessionType
    )
    
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
    [CmdletBinding()]
    param()
    
    if (-not $global:SessionManifest) { return }
    
    # Force arrays to prevent single-element string issues
    $moduleCount = @($global:SessionManifest.modules).Count
    $moduleNames = @($global:SessionManifest.modules | ForEach-Object { $_.name })
    $sessionType = $global:SessionManifest.sessionType
    
    # Calculate ACTUAL settings count (not backup items!)
    # Each module applies a specific number of settings (Paranoid mode = max):
    $settingsPerModule = @{
        "SecurityBaseline"  = 425  # 335 Registry + 67 Security Template + 23 Audit
        "ASR"               = 19   # 19 ASR Rules
        "DNS"               = 5    # 5 DNS Settings
        "Privacy"           = 78   # 54 Registry (MSRecommended) + 24 Bloatware
        "AntiAI"            = 32   # 32 Registry Policies (15 features)
        "EdgeHardening"     = 24   # 24 Edge Policies (22-23 applied depending on extensions)
        "AdvancedSecurity"  = 50   # 50 Advanced Settings (15 features incl. Discovery Protocols + IPv6)
    }
    
    $totalSettings = 0
    foreach ($moduleName in $moduleNames) {
        if ($settingsPerModule.ContainsKey($moduleName)) {
            $totalSettings += $settingsPerModule[$moduleName]
        }
    }
    
    # Generate display name based on context
    if ($moduleCount -eq 0) {
        $displayName = "Empty Session"
    }
    elseif ($sessionType -eq "wizard") {
        if ($moduleCount -ge 7) {
            $displayName = "Full Hardening ($totalSettings Settings)"
        }
        elseif ($moduleCount -ge 4) {
            $displayName = "Wizard: $moduleCount Modules ($totalSettings Settings)"
        }
        else {
            # Few modules - list them
            $short = ($moduleNames | Select-Object -First 3) -join ", "
            $displayName = "Wizard: $short ($totalSettings Settings)"
        }
    }
    elseif ($sessionType -eq "advanced") {
        # Advanced mode = always single module
        $displayName = "$($moduleNames[0]) Only ($totalSettings Settings)"
    }
    else {
        # manual or unknown - just list modules
        $short = ($moduleNames | Select-Object -First 2) -join ", "
        if ($moduleCount -gt 2) { $short += "..." }
        $displayName = "$short ($totalSettings Settings)"
    }
    
    $global:SessionManifest.displayName = $displayName
    Write-Log -Level INFO -Message "Session display name: $displayName" -Module "Rollback"
    
    # Update manifest file
    $manifestPath = Join-Path $global:BackupBasePath "manifest.json"
    if (Test-Path $manifestPath) {
        try {
            $encoding = New-Object System.Text.UTF8Encoding($false)
            $json = $global:SessionManifest | ConvertTo-Json -Depth 5
            [System.IO.File]::WriteAllText($manifestPath, $json, $encoding)
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to update manifest with display name: $_" -Module "Rollback"
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
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("SecurityBaseline", "ASR", "DNS", "Privacy", "AntiAI", "EdgeHardening", "AdvancedSecurity")]
        [string]$ModuleName
    )
    
    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Create module subfolder
    $moduleBackupPath = Join-Path $global:BackupBasePath $ModuleName
    if (-not (Test-Path $moduleBackupPath)) {
        New-Item -ItemType Directory -Path $moduleBackupPath -Force | Out-Null
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
        Status of the backup (Success, Failed, Skipped)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ItemsBackedUp,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Success", "Failed", "Skipped")]
        [string]$Status
    )
    
    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    if ([string]::IsNullOrEmpty($global:CurrentModule)) {
        Write-Log -Level WARNING -Message "No active module backup to complete" -Module "Rollback"
        return
    }
    
    # Update Manifest Object
    $moduleData = @{
        name          = $global:CurrentModule
        backupPath    = $global:CurrentModule
        itemsBackedUp = $ItemsBackedUp
        status        = $Status
        timestamp     = Get-Date -Format "o"
    }
    
    $global:SessionManifest.modules += $moduleData
    $global:SessionManifest.totalItems += $ItemsBackedUp
    
    # Write Manifest to Disk (robust against transient file locks)
    $manifestPath = Join-Path $global:BackupBasePath "manifest.json"
    $maxAttempts = 5
    $attempt = 0
    $delayMs = 200
    $encoding = New-Object System.Text.UTF8Encoding($false)
    
    while ($attempt -lt $maxAttempts) {
        try {
            $attempt++
            $json = $global:SessionManifest | ConvertTo-Json -Depth 5
            [System.IO.File]::WriteAllText($manifestPath, $json, $encoding)
            Write-Log -Level INFO -Message "Completed backup for $($global:CurrentModule) (Items: $ItemsBackedUp). Manifest updated." -Module "Rollback"
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
    
    # Reset Current Module
    $global:CurrentModule = ""
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
        String containing backup file path
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
        
        # Convert PowerShell path to reg.exe format
        $regPath = $KeyPath -replace 'HKLM:\\', 'HKEY_LOCAL_MACHINE\' `
            -replace 'HKCU:\\', 'HKEY_CURRENT_USER\' `
            -replace 'HKCR:\\', 'HKEY_CLASSES_ROOT\' `
            -replace 'HKU:\\', 'HKEY_USERS\' `
            -replace 'HKCC:\\', 'HKEY_CURRENT_CONFIG\'
        
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
            Write-Log -Level SUCCESS -Message "Registry backup created: $BackupName" -Module "Rollback"
            
            # Add to backup index
            $global:BackupIndex += [PSCustomObject]@{
                Type       = "Registry"
                Name       = $BackupName
                Path       = $KeyPath
                BackupFile = $backupFile
                Timestamp  = Get-Date
            }
            
            return $backupFile
        }
        else {
            # Check if key simply doesn't exist yet (normal when creating new keys)
            if ($errorOutput -match "nicht gefunden|cannot find|not found") {
                # Key doesn't exist - CREATE EMPTY MARKER so restore knows to DELETE this key
                Write-Log -Level INFO -Message "Registry key does not exist (will create empty marker): $BackupName" -Module "Rollback"
                
                try {
                    $emptyMarker = @{
                        KeyPath = $KeyPath
                        BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        State = "NotExisted"
                        Message = "Registry key did not exist before hardening - must be deleted during restore"
                    } | ConvertTo-Json
                    
                    $markerFile = Join-Path $backupFolder "$safeBackupName`_EMPTY.json"
                    $emptyMarker | Set-Content -Path $markerFile -Encoding UTF8 -Force
                    
                    Write-Log -Level SUCCESS -Message "Empty marker created for non-existent key: $BackupName" -Module "Rollback"
                    
                    # Add to backup index
                    $global:BackupIndex += [PSCustomObject]@{
                        Type       = "EmptyMarker"
                        Name       = $BackupName
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

function Register-NewRegistryKey {
    <#
    .SYNOPSIS
        Track a newly created registry key for proper restore
        
    .DESCRIPTION
        When a registry key is created that didn't exist before, it must be tracked
        so it can be deleted (not just restored) during rollback.
        
    .PARAMETER KeyPath
        PowerShell-style registry path (e.g., HKLM:\SOFTWARE\...)
        
    .EXAMPLE
        Register-NewRegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NewKey"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath
    )
    
    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Add to tracking list (avoid duplicates)
    if ($global:NewlyCreatedKeys -notcontains $KeyPath) {
        $global:NewlyCreatedKeys += $KeyPath
        Write-Log -Level DEBUG -Message "Tracking new registry key for rollback: $KeyPath" -Module "Rollback"
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
        String containing backup file path
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    if ([string]::IsNullOrEmpty($global:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Use ServiceName as BackupName if not provided
    if ([string]::IsNullOrEmpty($BackupName)) {
        $BackupName = $ServiceName
    }
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        # Get detailed service configuration (may not exist for some services)
        $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        
        $backupData = [PSCustomObject]@{
            Name        = $service.Name
            DisplayName = $service.DisplayName
            Status      = $service.Status
            StartType   = $service.StartType
            StartMode   = if ($serviceConfig) { $serviceConfig.StartMode } else { $service.StartType.ToString() }
            PathName    = if ($serviceConfig) { $serviceConfig.PathName } else { "" }
            Description = if ($serviceConfig) { $serviceConfig.Description } else { "" }
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
        $backupData | ConvertTo-Json | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        
        Write-Log -Level SUCCESS -Message "Service backup created: $BackupName ($ServiceName)" -Module "Rollback"
        
        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type        = "Service"
            Name        = $BackupName
            ServiceName = $ServiceName
            BackupFile  = $backupFile
            Timestamp   = Get-Date
        }
        
        return $backupFile
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to backup service: $ServiceName" -Module "Rollback" -Exception $_.Exception
        return $null
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
        String containing backup file path
    #>
    [CmdletBinding()]
    [OutputType([string])]
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
        
        # Generate BackupName if not provided
        if ([string]::IsNullOrEmpty($BackupName)) {
            $BackupName = $TaskName -replace '\s', '_'
        }
        
        # Check if task exists first
        $task = Get-ScheduledTask -TaskPath $actualTaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        
        if (-not $task) {
            # Task doesn't exist - this is normal for many telemetry tasks on Win11
            Write-Log -Level DEBUG -Message "Scheduled task not found (already disabled/removed): $actualTaskPath\$TaskName" -Module "Rollback"
            return $null
        }
        
        # Export task to XML
        $taskXml = Export-ScheduledTask -TaskPath $actualTaskPath -TaskName $TaskName
        
        # Save to file
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'
        
        # Save to current module folder if active, otherwise root
        $backupFolder = if ($global:CurrentModule) {
            Join-Path $global:BackupBasePath $global:CurrentModule
        }
        else {
            $global:BackupBasePath
        }
        
        $backupFile = Join-Path $backupFolder "$safeBackupName`_Task.xml"
        $taskXml | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        
        Write-Log -Level SUCCESS -Message "Scheduled task backup created: $BackupName" -Module "Rollback"
        
        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type       = "ScheduledTask"
            Name       = $BackupName
            TaskPath   = $TaskPath
            TaskName   = $TaskName
            BackupFile = $backupFile
            Timestamp  = Get-Date
        }
        
        return $backupFile
    }
    catch {
        # Only log as ERROR if task exists but backup failed (real error)
        Write-Log -Level ERROR -Message "Failed to backup scheduled task: $actualTaskPath\$TaskName" -Module "Rollback" -Exception $_.Exception
        return $null
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
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $Name = "$Type`_$timestamp"
        }
        
        # Sanitize backup name
        $safeName = $Name -replace '[\\/:*?"<>|]', '_'
        
        # Create type-specific folder
        $typeFolder = Join-Path $global:BackupBasePath $Type
        if (-not (Test-Path $typeFolder)) {
            New-Item -ItemType Directory -Path $typeFolder -Force | Out-Null
        }
        
        $backupFile = Join-Path $typeFolder "$safeName.json"
        
        # Convert data to JSON if not already
        if ($Data -is [string]) {
            $Data | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        }
        else {
            $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        }
        
        Write-Log -Level SUCCESS -Message "Backup registered: $Type - $Name" -Module "Rollback"
        
        # Add to backup index
        $global:BackupIndex += [PSCustomObject]@{
            Type       = $Type
            Name       = $Name
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

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Create a system restore point
        
    .PARAMETER Description
        Description for the restore point
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Description = "NoID Privacy - Before Hardening"
    )
    
    try {
        # Check if System Restore is enabled
        $restoreEnabled = $null -ne (Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        
        if ($restoreEnabled) {
            Write-Log -Level INFO -Message "Creating system restore point..." -Module "Rollback"
            
            Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS"
            
            Write-Log -Level SUCCESS -Message "System restore point created" -Module "Rollback"
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "System Restore is not enabled on this system" -Module "Rollback"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create system restore point" -Module "Rollback" -Exception $_.Exception
        return $false
    }
}

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
        [string]$Type
    )
    
    if (-not (Test-Path -Path $BackupFile)) {
        Write-Log -Level ERROR -Message "Backup file not found: $BackupFile" -Module "Rollback"
        return $false
    }
    
    try {
        switch ($Type) {
            "Registry" {
                Write-Log -Level INFO -Message "Restoring registry from: $BackupFile" -Module "Rollback"
                
                # Check if backup file has content (more than just header)
                $backupContent = Get-Content -Path $BackupFile -Raw -ErrorAction SilentlyContinue
                $hasContent = $backupContent -and ($backupContent.Length -gt 100) -and ($backupContent -match '\[HKEY')
                
                if (-not $hasContent) {
                    # Backup is empty - the key didn't exist before hardening
                    # Extract key path from filename and delete it
                    Write-Log -Level INFO -Message "Empty backup detected - key did not exist before hardening" -Module "Rollback"
                    
                    # Try to extract key path from backup content if available
                    if ($backupContent -match '\[HKEY[^\]]+\]') {
                        $keyPath = $matches[0] -replace '^\[' -replace '\]$'
                        
                        # Use [regex]::Escape to prevent unintended matches
                        $keyPath = $keyPath -replace [regex]::Escape('HKEY_LOCAL_MACHINE'), 'HKLM:' `
                            -replace [regex]::Escape('HKEY_CURRENT_USER'), 'HKCU:' `
                            -replace [regex]::Escape('HKEY_CLASSES_ROOT'), 'HKCR:' `
                            -replace [regex]::Escape('HKEY_USERS'), 'HKU:' `
                            -replace [regex]::Escape('HKEY_CURRENT_CONFIG'), 'HKCC:'
                        
                        # CRITICAL: Validate key path is within expected scope!
                        $allowedPrefixes = @(
                            'HKLM:\\SOFTWARE\\Policies',
                            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
                            'HKCU:\\SOFTWARE\\Policies',
                            'HKLM:\\SYSTEM\\CurrentControlSet\\Services',
                            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                            'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
                        )
                        
                        $isAllowed = $false
                        foreach ($prefix in $allowedPrefixes) {
                            if ($keyPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                                $isAllowed = $true
                                break
                            }
                        }
                        
                        if (-not $isAllowed) {
                            Write-Log -Level WARNING -Message "Refusing to delete key outside allowed scope: $keyPath" -Module "Rollback"
                            return $true
                        }
                        
                        if (Test-Path $keyPath) {
                            try {
                                Remove-Item -Path $keyPath -Recurse -Force -ErrorAction Stop
                                Write-Log -Level SUCCESS -Message "Deleted non-existent key: $keyPath" -Module "Rollback"
                                return $true
                            }
                            catch {
                                Write-Log -Level WARNING -Message "Could not delete key: $keyPath - $_" -Module "Rollback"
                                return $false
                            }
                        }
                    }
                    
                    Write-Log -Level INFO -Message "Backup empty - nothing to restore" -Module "Rollback"
                    return $true
                }
                
                # PRE-CHECK: Extract key path from .reg file and check if it's a protected key
                # This prevents unnecessary WARNING/ERROR messages for known protected keys
                $keyPathToRestore = ""
                $backupContent = Get-Content -Path $BackupFile -Raw -ErrorAction SilentlyContinue
                if ($backupContent -match '\[(HKEY[^\]]+)\]') {
                    $keyPathToRestore = $matches[1]
                }
                
                # List of known protected keys (Windows system protection prevents reg.exe import)
                $knownProtectedKeys = @(
                    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server',
                    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings',
                    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
                )
                
                $isKnownProtected = $false
                foreach ($protectedKey in $knownProtectedKeys) {
                    if ($keyPathToRestore -match [regex]::Escape($protectedKey)) {
                        $isKnownProtected = $true
                        break
                    }
                }
                
                # If this is a known protected key, skip reg.exe import and use JSON-Fallback instead
                if ($isKnownProtected) {
                    Write-Log -Level INFO -Message "Standard registry import skipped for protected key (will use Smart JSON-Fallback)." -Module "Rollback"
                    return $true  # Success - JSON backup will handle this key via Smart Fallback
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
                    Write-Log -Level SUCCESS -Message "Registry restored successfully" -Module "Rollback"
                    return $true
                }
                else {
                    $errorMessage = $errorOutput
                    # Check for Access Denied error (English and German variants)
                    if ($errorMessage -match "Zugriff verweigert|Access is denied|Fehler beim Zugriff auf die Registrierung") {
                        Write-Log -Level WARNING -Message "Access Denied during registry restore for $BackupFile. Attempting to delete key and retry import..." -Module "Rollback"
                        
                        if (-not [string]::IsNullOrEmpty($keyPathToRestore)) {
                            try {
                                # Convert reg.exe path to PowerShell path
                                $psKeyPath = $keyPathToRestore -replace 'HKEY_LOCAL_MACHINE', 'HKLM:' `
                                                                -replace 'HKEY_CURRENT_USER', 'HKCU:' `
                                                                -replace 'HKEY_CLASSES_ROOT', 'HKCR:' `
                                                                -replace 'HKEY_USERS', 'HKU:' `
                                                                -replace 'HKEY_CURRENT_CONFIG', 'HKCC:'
                                
                                if (Test-Path $psKeyPath) {
                                    Write-Log -Level INFO -Message "Deleting existing protected key: $psKeyPath before re-import." -Module "Rollback"
                                    Remove-Item -Path $psKeyPath -Recurse -Force -ErrorAction SilentlyContinue # SilentlyContinue to avoid error if it's truly protected
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
                                    Write-Log -Level SUCCESS -Message "Registry restored successfully after deleting key and retrying" -Module "Rollback"
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
                $serviceConfig = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
                
                Set-Service -Name $serviceConfig.Name -StartupType $serviceConfig.StartType -ErrorAction Stop
                
                Write-Log -Level SUCCESS -Message "Service restored: $($serviceConfig.Name)" -Module "Rollback"
                return $true
            }
            
            "ScheduledTask" {
                Write-Log -Level INFO -Message "Restoring scheduled task from: $BackupFile" -Module "Rollback"
                
                try {
                    $taskData = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
                    
                    # Import task XML if exists
                    if ($taskData.XmlDefinition) {
                        # Register-ScheduledTask requires TaskName and Xml (string)
                        # Force overwrite if exists
                        Register-ScheduledTask -Xml $taskData.XmlDefinition -TaskName $taskData.TaskName -Force | Out-Null
                        Write-Log -Level SUCCESS -Message "Scheduled task restored: $($taskData.TaskName)" -Module "Rollback"
                        return $true
                    }
                    else {
                        Write-Log -Level WARNING -Message "No XML definition found in backup for task: $($taskData.TaskName)" -Module "Rollback"
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
        Write-ErrorLog -Message "Failed to restore from backup file: $BackupFilePath" -Module "Rollback" -ErrorRecord $_
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
        
    .OUTPUTS
        None
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SYSTEM REBOOT RECOMMENDED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check if Privacy module was restored with non-restorable apps
    if ($script:PrivacyNonRestorableApps -and $script:PrivacyNonRestorableApps.Count -gt 0) {
        Write-Host "MANUAL ACTION REQUIRED:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The following apps were removed during hardening but cannot be" -ForegroundColor Gray
        Write-Host "automatically restored via winget (not available in catalog):" -ForegroundColor Gray
        Write-Host ""
        foreach ($app in $script:PrivacyNonRestorableApps) {
            Write-Host "  - $app" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "Please reinstall these apps manually from the Microsoft Store" -ForegroundColor Gray
        Write-Host "after the reboot if you need them." -ForegroundColor Gray
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
    }
    
    Write-Host "RECOMMENDED: Reboot after restore" -ForegroundColor White
    Write-Host ""
    Write-Host "Some security settings require a reboot to be fully activated:" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  - Group Policy changes (processed but not fully active)" -ForegroundColor Gray
    Write-Host "  - Security Template settings (user rights, audit)" -ForegroundColor Gray
    Write-Host "  - Registry policies affecting boot-time services" -ForegroundColor Gray
    Write-Host ""
    Write-Host "While gpupdate has processed the restored policies, a reboot" -ForegroundColor Gray
    Write-Host "ensures complete activation of all security settings." -ForegroundColor Gray
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Prompt user with validation loop
    do {
        Write-Host "Reboot now? [Y/N] (default: Y): " -NoNewline -ForegroundColor White
        $choice = Read-Host
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "Y" }
        $choice = $choice.Trim().ToUpper()
        
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
    param()
    
    Write-Log -Level WARNING -Message "Starting full rollback of all changes" -Module "Rollback"
    
    $allSucceeded = $true
    
    # Restore in reverse order (LIFO)
    $reversedIndex = $global:BackupIndex | Sort-Object -Property Timestamp -Descending
    
    foreach ($backup in $reversedIndex) {
        $success = Restore-FromBackup -BackupFile $backup.BackupFile -Type $backup.Type
        
        if (-not $success) {
            $allSucceeded = $false
        }
    }
    
    # Delete newly created registry keys (they didn't exist before)
    if ($global:NewlyCreatedKeys.Count -gt 0) {
        Write-Log -Level INFO -Message "Removing $($global:NewlyCreatedKeys.Count) newly created registry keys..." -Module "Rollback"
        
        # Sort in reverse order (deepest keys first) to avoid errors
        $sortedKeys = $global:NewlyCreatedKeys | Sort-Object -Property Length -Descending
        
        foreach ($keyPath in $sortedKeys) {
            try {
                if (Test-Path -Path $keyPath) {
                    Remove-Item -Path $keyPath -Recurse -Force -ErrorAction Stop
                    Write-Log -Level INFO -Message "Deleted newly created key: $keyPath" -Module "Rollback"
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to delete newly created key: $keyPath - $_" -Module "Rollback"
                $allSucceeded = $false
            }
        }
    }
    
    if ($allSucceeded) {
        Write-Log -Level SUCCESS -Message "Full rollback completed successfully" -Module "Rollback"
    }
    else {
        Write-Log -Level WARNING -Message "Full rollback completed with some failures" -Module "Rollback"
    }
    
    # Prompt for reboot after restore
    Invoke-RestoreRebootPrompt
    
    return $allSucceeded
}

function Get-BackupSessions {
    <#
    .SYNOPSIS
        Get list of all backup sessions
        
    .PARAMETER BackupDirectory
        Directory containing backup sessions
        
    .OUTPUTS
        Array of session objects with manifest data
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = (Join-Path $PSScriptRoot "..\Backups")
    )
    
    if (-not (Test-Path $BackupDirectory)) {
        return @()
    }
    
    $sessions = @()
    $sessionFolders = Get-ChildItem -Path $BackupDirectory -Directory | Where-Object { $_.Name -match '^Session_\d{8}_\d{6}$' }
    
    foreach ($folder in $sessionFolders) {
        $manifestPath = Join-Path $folder.FullName "manifest.json"
        
        if (Test-Path $manifestPath) {
            try {
                $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                
                $sessions += [PSCustomObject]@{
                    SessionId        = $manifest.sessionId
                    Timestamp        = [DateTime]::Parse($manifest.timestamp)
                    FrameworkVersion = $manifest.frameworkVersion
                    Modules          = $manifest.modules
                    TotalItems       = $manifest.totalItems
                    Restorable       = $manifest.restorable
                    SessionPath      = $manifest.sessionPath
                    FolderPath       = $folder.FullName
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to read manifest for session: $($folder.Name)" -Module "Rollback"
            }
        }
    }
    
    # Ensure we return an array (Sort-Object can return single object unwrapped)
    $sorted = @($sessions | Sort-Object -Property Timestamp -Descending)
    return $sorted
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
    
    try {
        $logsDir = Join-Path (Split-Path $PSScriptRoot -Parent) "Logs"
        if (-not (Test-Path $logsDir)) {
            New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $sessionId = Split-Path $SessionPath -Leaf
        $restoreLogFile = "RESTORE_$($sessionId)_$timestamp.log"
        $script:RestoreLogPath = Join-Path $logsDir $restoreLogFile
        
        # Initialize restore log file
        $header = @(
            "================================================================"
            "  NoID Privacy - RESTORE LOG"
            "  Session: $sessionId"
            "  Restore Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "================================================================"
            ""
        )
        $header | Out-File -FilePath $script:RestoreLogPath -Encoding UTF8
        
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
    
    if (-not $script:RestoreLogPath) { return }
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        $logEntry | Out-File -FilePath $script:RestoreLogPath -Append -Encoding UTF8
    }
    catch {
        # Silently fail to avoid breaking restore operation
        $null = $null
    }
}

function Restore-Session {
    <#
    .SYNOPSIS
        Restore complete session (all modules)
        
    .PARAMETER SessionPath
        Path to the session folder
        
    .PARAMETER ModuleNames
        Optional array of specific module names to restore (restores all if not specified)
        
    .OUTPUTS
        Boolean indicating overall success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ModuleNames
    )
    
    if (-not (Test-Path $SessionPath)) {
        Write-Log -Level ERROR -Message "Session path not found: $SessionPath" -Module "Rollback"
        return $false
    }
    
    # Track restore duration
    $startTime = Get-Date
    
    # CRITICAL: Initialize separate restore log (ONLY for restore operations)
    Initialize-RestoreLog -SessionPath $SessionPath
    Write-RestoreLog -Level INFO -Message "========================================"
    Write-RestoreLog -Level INFO -Message "RESTORE SESSION START"
    Write-RestoreLog -Level INFO -Message "Session Path: $SessionPath"
    if ($ModuleNames) {
        Write-RestoreLog -Level INFO -Message "Specific Modules: $($ModuleNames -join ', ')"
    } else {
        Write-RestoreLog -Level INFO -Message "Restoring: ALL modules"
    }
    Write-RestoreLog -Level INFO -Message "========================================"
    Write-RestoreLog -Level INFO -Message " "
    
    try {
        $manifest = Get-SessionManifest -SessionPath $SessionPath
        
        Write-Log -Level INFO -Message "Starting session restore: $($manifest.sessionId)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Session ID: $($manifest.sessionId)"
        
        Write-Log -Level INFO -Message "Session created: $($manifest.timestamp)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Session Created: $($manifest.timestamp)"
        
        Write-Log -Level INFO -Message "Total items: $($manifest.totalItems)" -Module "Rollback"
        Write-RestoreLog -Level INFO -Message "Total Items Backed Up: $($manifest.totalItems)"
        Write-RestoreLog -Level INFO -Message " "
        
        $allSucceeded = $true
        $modulesToRestore = if ($ModuleNames) {
            $manifest.modules | Where-Object { $ModuleNames -contains $_.name }
        }
        else {
            $manifest.modules
        }
        
        # Restore in reverse order (LIFO - last applied, first restored)
        $reversedModules = $modulesToRestore | Sort-Object -Property timestamp -Descending
        
        foreach ($moduleInfo in $reversedModules) {
            Write-Log -Level INFO -Message "Restoring module: $($moduleInfo.name) ($($moduleInfo.itemsBackedUp) items)" -Module "Rollback"
            Write-RestoreLog -Level INFO -Message "========================================" 
            Write-RestoreLog -Level INFO -Message "MODULE: $($moduleInfo.name)"
            Write-RestoreLog -Level INFO -Message "Items Backed Up: $($moduleInfo.itemsBackedUp)"
            Write-RestoreLog -Level INFO -Message "Backup Path: $($moduleInfo.backupPath)"
            Write-RestoreLog -Level INFO -Message "Timestamp: $($moduleInfo.timestamp)"
            Write-RestoreLog -Level INFO -Message "========================================"
            
            $moduleBackupPath = Join-Path $SessionPath $moduleInfo.backupPath
            
            if (-not (Test-Path $moduleBackupPath)) {
                Write-Log -Level ERROR -Message "Module backup path not found: $moduleBackupPath" -Module "Rollback"
                Write-RestoreLog -Level ERROR -Message "CRITICAL: Module backup path not found: $moduleBackupPath"
                $allSucceeded = $false
                continue
            }
            Write-RestoreLog -Level DEBUG -Message "Backup path verified: $moduleBackupPath"
            
            # Pre-restore cleanup: Clear active policies BEFORE restoring backups
            # This ensures hardened settings don't interfere with backup restore
            
            if ($moduleInfo.name -eq "SecurityBaseline") {
                # Detect domain-joined systems to avoid disrupting domain GPO cache
                $isDomainJoined = $false
                try {
                    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                    $isDomainJoined = $cs.PartOfDomain
                }
                catch {
                    $isDomainJoined = $false
                }
                Write-Log -Level INFO -Message "Restoring SecurityBaseline from LocalGPO backup..." -Module "Rollback"
                Write-RestoreLog -Level INFO -Message "[STEP 1] LocalGPO Restore"
                
                # STEP 1: Restore full LocalGPO directory from backup
                # This is the official MS method to restore ALL GPO settings at once
                # More reliable than Clear + Restore-RegistryPolicies (avoids permission issues)
                $localGPOBackup = Join-Path $moduleBackupPath "LocalGPO"
                $localGPOPath = "C:\Windows\System32\GroupPolicy"
                Write-RestoreLog -Level DEBUG -Message "LocalGPO backup path: $localGPOBackup"
                Write-RestoreLog -Level DEBUG -Message "LocalGPO target path: $localGPOPath"
                
                if ($isDomainJoined) {
                    Write-Log -Level WARNING -Message "Domain-joined system detected - skipping LocalGPO delete/restore to avoid interfering with domain GPO cache" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "Domain-joined system - Local Group Policy folder will NOT be modified. Please restore via domain GPO if required."
                }
                elseif (Test-Path $localGPOBackup) {
                    Write-Log -Level INFO -Message "Restoring LocalGPO directory from backup..." -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "LocalGPO backup found - restoring full directory"
                    
                    try {
                        # Delete current GPO directory if it exists
                        if (-not $isDomainJoined -and (Test-Path $localGPOPath)) {
                            Write-RestoreLog -Level DEBUG -Message "Removing current LocalGPO directory..."
                            Remove-Item -Path $localGPOPath -Recurse -Force -ErrorAction Stop
                            Write-Log -Level INFO -Message "Removed current LocalGPO directory" -Module "Rollback"
                            Write-RestoreLog -Level SUCCESS -Message "Current LocalGPO removed"
                        }
                        else {
                            Write-RestoreLog -Level DEBUG -Message "No current LocalGPO directory to remove"
                        }
                        
                        # Restore backup
                        Write-RestoreLog -Level DEBUG -Message "Copying LocalGPO backup to system..."
                        Copy-Item -Path $localGPOBackup -Destination $localGPOPath -Recurse -Force -ErrorAction Stop
                        Write-Log -Level SUCCESS -Message "LocalGPO directory restored from backup" -Module "Rollback"
                        Write-RestoreLog -Level SUCCESS -Message "LocalGPO directory restored successfully"
                        
                        # Force Group Policy update to apply restored settings
                        Write-Log -Level INFO -Message "Applying restored Group Policy settings (gpupdate)..." -Module "Rollback"
                        Write-RestoreLog -Level INFO -Message "[STEP 1.1] Running gpupdate /force..."
                        $gpupdateProcess = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow -PassThru
                        Write-RestoreLog -Level DEBUG -Message "gpupdate exit code: $($gpupdateProcess.ExitCode)"
                        
                        if ($gpupdateProcess.ExitCode -eq 0) {
                            Write-Log -Level SUCCESS -Message "Group Policy settings applied successfully" -Module "Rollback"
                            Write-RestoreLog -Level SUCCESS -Message "gpupdate completed successfully"
                        }
                        else {
                            Write-Log -Level WARNING -Message "gpupdate returned exit code $($gpupdateProcess.ExitCode) - continuing" -Module "Rollback"
                            Write-RestoreLog -Level WARNING -Message "gpupdate returned non-zero exit code: $($gpupdateProcess.ExitCode)"
                        }
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restore LocalGPO directory: $($_.Exception.Message)" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "LocalGPO restore FAILED: $($_.Exception.Message)"
                        Write-RestoreLog -Level ERROR -Message "Stack trace: $($_.ScriptStackTrace)"
                    }
                }
                else {
                    Write-Log -Level INFO -Message "No LocalGPO backup found (system was clean before hardening) - clearing current GPO" -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "No LocalGPO backup found - system was clean before hardening"
                    
                    # System had no GPO before hardening - just clear current GPO
                    if (Test-Path $localGPOPath) {
                        try {
                            Write-RestoreLog -Level DEBUG -Message "Removing current LocalGPO (cleanup)..."
                            Remove-Item -Path $localGPOPath -Recurse -Force -ErrorAction Stop
                            Write-Log -Level SUCCESS -Message "Cleared LocalGPO directory (system was clean)" -Module "Rollback"
                            Write-RestoreLog -Level SUCCESS -Message "LocalGPO cleared successfully"
                        }
                        catch {
                            Write-Log -Level WARNING -Message "Could not clear LocalGPO: $_" -Module "Rollback"
                            Write-RestoreLog -Level WARNING -Message "LocalGPO cleanup failed: $_"
                        }
                    }
                    else {
                        Write-RestoreLog -Level DEBUG -Message "No LocalGPO directory exists (correct state)"
                    }
                }
                
                # STEP 1.5: Explicitly restore registry policies from JSON backup (counter GPO tattooing)
                # GPO tattooing: When GPO sets registry values and is then removed, values persist
                # Solution: Explicitly restore original values from JSON backup using Restore-RegistryPolicies
                Write-RestoreLog -Level INFO -Message "[STEP 2] Registry Policies Restore (counter GPO tattooing)"
                $regBackupJson = Join-Path $moduleBackupPath "RegistryPolicies.json"
                Write-RestoreLog -Level DEBUG -Message "Registry backup JSON: $regBackupJson"
                if (Test-Path $regBackupJson) {
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
                                Write-Log -Level WARNING -Message "Restore-RegistryPolicies.ps1 not found - skipping explicit registry restore" -Module "Rollback"
                                Write-RestoreLog -Level ERROR -Message "Restore-RegistryPolicies.ps1 NOT FOUND - registry restore skipped!"
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
                            }
                            
                            # CRITICAL FIX: Terminal Services GPO Cleanup
                            # After restore, the Terminal Services key may exist but be empty (all values deleted).
                            # Verify checks expect the key to NOT exist if system was clean before apply.
                            # Solution: Remove the key if it's completely empty after restore.
                            Write-RestoreLog -Level INFO -Message "[FIX 2/3] Checking Terminal Services GPO cleanup..."
                            $tsKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
                            if (Test-Path $tsKey) {
                                Write-RestoreLog -Level DEBUG -Message "Terminal Services key exists: $tsKey"
                                try {
                                    $tsProps = Get-ItemProperty -Path $tsKey -ErrorAction SilentlyContinue
                                    $propNames = @()
                                    if ($tsProps) {
                                        $propNames = $tsProps.PSObject.Properties.Name | Where-Object { 
                                            $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') 
                                        }
                                    }
                                    Write-RestoreLog -Level DEBUG -Message "Terminal Services key value count: $($propNames.Count)"
                                    
                                    if ($propNames.Count -eq 0) {
                                        Remove-Item -Path $tsKey -Recurse -Force -ErrorAction SilentlyContinue
                                        Write-Log -Level INFO -Message "Removed empty Terminal Services policy key (GPO cleanup - system was clean before hardening)" -Module "Rollback"
                                        Write-RestoreLog -Level SUCCESS -Message "Terminal Services key removed (was empty - system was clean)"
                                    }
                                    else {
                                        Write-Log -Level DEBUG -Message "Terminal Services key has $($propNames.Count) values - keeping key" -Module "Rollback"
                                        Write-RestoreLog -Level INFO -Message "Terminal Services key has $($propNames.Count) values - keeping key"
                                        Write-RestoreLog -Level DEBUG -Message "Values: $($propNames -join ', ')"
                                    }
                                }
                                catch {
                                    Write-Log -Level DEBUG -Message "Could not check/clean Terminal Services key: $_" -Module "Rollback"
                                    Write-RestoreLog -Level WARNING -Message "Terminal Services cleanup failed: $_"
                                }
                            }
                            else {
                                Write-RestoreLog -Level DEBUG -Message "Terminal Services key does not exist (correct state)"
                            }
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore registry policies from JSON: $($_.Exception.Message)" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "Registry restore exception: $($_.Exception.Message)"
                        Write-RestoreLog -Level ERROR -Message "Stack trace: $($_.ScriptStackTrace)"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No RegistryPolicies.json backup found - GPO restore only (tattooing may occur)" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "No RegistryPolicies.json backup found - GPO tattooing may occur!"
                }
                
                # STEP 3: Restore Audit Policies from pre-hardening backup
                Write-RestoreLog -Level INFO -Message "[STEP 3] Audit Policies Restore"
                $auditBackupFile = Join-Path $moduleBackupPath "AuditPolicies.csv"
                Write-RestoreLog -Level DEBUG -Message "Audit backup file: $auditBackupFile"
                if (Test-Path $auditBackupFile) {
                    Write-Log -Level INFO -Message "Found audit policy backup" -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "Audit backup found - restoring..."
                    Write-Log -Level INFO -Message "Restoring audit policies from backup..." -Module "Rollback"
                    
                    try {
                        $auditRestoreProcess = Start-Process -FilePath "auditpol.exe" `
                            -ArgumentList "/restore", "/file:`"$auditBackupFile`"" `
                            -Wait `
                            -NoNewWindow `
                            -PassThru
                        
                        if ($auditRestoreProcess.ExitCode -eq 0) {
                            Write-Log -Level SUCCESS -Message "Audit policies restored from pre-hardening backup" -Module "Rollback"
                            Write-RestoreLog -Level SUCCESS -Message "Audit policies restored successfully"
                        }
                        else {
                            Write-Log -Level WARNING -Message "Audit policy restore had errors (Exit: $($auditRestoreProcess.ExitCode)) - continuing" -Module "Rollback"
                            Write-RestoreLog -Level WARNING -Message "Audit restore had errors (Exit: $($auditRestoreProcess.ExitCode))"
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Audit policy restore failed: $_ - continuing" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "Audit restore exception: $_"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No pre-hardening audit policy backup found - skipping audit restore (keeping current state)" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "No audit backup found - skipping"
                }
                
                # STEP 3.5: Clear Security Template Registry Values not in secedit export
                # CRITICAL FIX: secedit /export only exports values explicitly set in Security DB.
                # Values on Windows-Default are NOT exported, so they won't be restored by secedit /configure.
                # These 8 values are set by SecurityBaseline but may not exist in backup INF:
                Write-RestoreLog -Level INFO -Message "[STEP 3.5] Clearing Security Template Registry Values (secedit gap fix)"
                $secTemplateRegValues = @(
                    @{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "RequireSecuritySignature" },
                    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "allownullsessionfallback" },
                    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel" },
                    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy" },
                    @{ Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"; Name = "requiresecuritysignature" },
                    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "RestrictRemoteSAM" },
                    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "FilterAdministratorToken" },
                    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "InactivityTimeoutSecs" }
                )
                
                $clearedSecTemplateValues = 0
                foreach ($regVal in $secTemplateRegValues) {
                    try {
                        if (Test-Path $regVal.Path) {
                            $existingVal = Get-ItemProperty -Path $regVal.Path -Name $regVal.Name -ErrorAction SilentlyContinue
                            if ($existingVal) {
                                Remove-ItemProperty -Path $regVal.Path -Name $regVal.Name -Force -ErrorAction Stop
                                $clearedSecTemplateValues++
                                Write-RestoreLog -Level DEBUG -Message "Cleared: $($regVal.Path)\$($regVal.Name)"
                            }
                        }
                    }
                    catch {
                        Write-RestoreLog -Level DEBUG -Message "Could not clear $($regVal.Path)\$($regVal.Name): $_"
                    }
                }
                Write-RestoreLog -Level SUCCESS -Message "Cleared $clearedSecTemplateValues Security Template registry values (secedit gap)"
                
                # STEP 4: Restore Security Template
                Write-RestoreLog -Level INFO -Message "[STEP 4] Security Template Restore"
                
                # Fail-Safe for Restore-SecurityTemplate (Module Scope Fix)
                if (-not (Get-Command "Restore-SecurityTemplate" -ErrorAction SilentlyContinue)) {
                    $funcPath = Join-Path $PSScriptRoot "..\Modules\SecurityBaseline\Private\Restore-SecurityTemplate.ps1"
                    if (Test-Path $funcPath) { . $funcPath }
                }

                $rollbackTemplateFile = Join-Path $moduleBackupPath "StandaloneDelta_Rollback.inf"
                if (Test-Path $rollbackTemplateFile) {
                    Write-Log -Level INFO -Message "Found rollback template for standalone delta" -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "Using StandaloneDelta_Rollback.inf"
                    $secTemplatResult = Restore-SecurityTemplate -BackupPath $rollbackTemplateFile
                }
                else {
                    Write-Log -Level INFO -Message "No rollback template found - using full security policy backup (expected)" -Module "Rollback"
                    Write-RestoreLog -Level DEBUG -Message "No StandaloneDelta - using SecurityTemplate.inf"
                    $secPolicyBackupFile = Join-Path $moduleBackupPath "SecurityTemplate.inf"
                    if (Test-Path $secPolicyBackupFile) {
                        Write-Log -Level INFO -Message "Found security template backup" -Module "Rollback"
                        Write-RestoreLog -Level INFO -Message "Security template backup found - restoring via secedit..."
                        $secTemplatResult = Restore-SecurityTemplate -BackupPath $secPolicyBackupFile
                        Write-RestoreLog -Level SUCCESS -Message "Security template restored"
                    }
                    else {
                        Write-Log -Level WARNING -Message "No security policy backups found - skipping secedit restore" -Module "Rollback"
                        Write-RestoreLog -Level WARNING -Message "No security template backup found - skipping"
                        $secTemplatResult = $true
                    }
                }
                
                if (-not $secTemplatResult) {
                    Write-Log -Level WARNING -Message "Security template restore had errors - continuing" -Module "Rollback"
                }
                
                # STEP 5: Restore Xbox Task if it was disabled
                $xboxTaskBackup = Join-Path $moduleBackupPath "XboxTask.json"
                if (Test-Path $xboxTaskBackup) {
                    try {
                        $taskData = Get-Content $xboxTaskBackup -Raw | ConvertFrom-Json
                        
                        if ($taskData.TaskExists -and $taskData.WasEnabled) {
                            Write-Log -Level INFO -Message "Re-enabling Xbox scheduled task (was enabled before hardening)..." -Module "Rollback"
                            
                            Enable-ScheduledTask -TaskName $taskData.TaskName -TaskPath $taskData.TaskPath -ErrorAction Stop | Out-Null
                            Write-Log -Level SUCCESS -Message "Xbox task re-enabled: $($taskData.TaskName)" -Module "Rollback"
                        }
                        else {
                            Write-Log -Level INFO -Message "Xbox task was not enabled before hardening - leaving disabled" -Module "Rollback"
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore Xbox task state: $_" -Module "Rollback"
                    }
                }
            }
            
            if ($moduleInfo.name -eq "ASR") {
                Write-Log -Level INFO -Message "Clearing ASR configuration before restore..." -Module "Rollback"
                Write-RestoreLog -Level INFO -Message "[ASR] Clearing all ASR configurations..."
                
                # Clear MpPreference-based ASR rules
                $asrClearResult = Clear-ASRRules
                if (-not $asrClearResult) {
                    Write-Log -Level WARNING -Message "ASR rules clear had errors - continuing" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "MpPreference ASR clear had errors"
                }
                else {
                    Write-RestoreLog -Level SUCCESS -Message "MpPreference ASR rules cleared"
                }
                
                # CRITICAL: Also clear Registry-based ASR rules (set by SecurityBaseline via GPO)
                # These are in: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules
                $asrPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
                $asrRulesPath = "$asrPolicyPath\Rules"
                try {
                    if (Test-Path $asrRulesPath) {
                        Remove-Item -Path $asrRulesPath -Recurse -Force -ErrorAction Stop
                        Write-Log -Level SUCCESS -Message "Cleared Registry-based ASR rules (GPO path)" -Module "Rollback"
                        Write-RestoreLog -Level SUCCESS -Message "Registry ASR rules cleared (GPO path)"
                    }
                    if (Test-Path $asrPolicyPath) {
                        # Also remove the ExploitGuard_ASR_Rules flag from the parent key
                        Remove-ItemProperty -Path $asrPolicyPath -Name "ExploitGuard_ASR_Rules" -ErrorAction SilentlyContinue
                        Write-RestoreLog -Level DEBUG -Message "Removed ExploitGuard_ASR_Rules flag"
                    }
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not clear Registry ASR rules: $_" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "Registry ASR clear error: $_"
                }

                # CRITICAL FIX: In multi-module sessions, SecurityBaseline applies 15 ASR rules BEFORE
                # the ASR module runs. This means ASR_ActiveConfiguration.json captures the WRONG state
                # (post-SecurityBaseline, not pre-hardening). PreFramework_Snapshot.json is created
                # BEFORE any module runs and has the TRUE pre-hardening state.
                # 
                # Priority order:
                # 1. PreFramework_Snapshot.json (if exists) - TRUE pre-hardening state
                # 2. ASR_ActiveConfiguration.json (fallback) - only correct for single-module ASR runs
                
                $preFrameworkPath = Join-Path $SessionPath "PreFramework_Snapshot.json"
                $usePreFramework = $false
                $asrRulesToRestore = @()
                
                if (Test-Path $preFrameworkPath) {
                    Write-Log -Level INFO -Message "Found PreFramework_Snapshot.json - using TRUE pre-hardening ASR state" -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "Using PreFramework_Snapshot.json for TRUE pre-hardening state"
                    try {
                        $preFramework = Get-Content $preFrameworkPath -Raw | ConvertFrom-Json
                        if ($preFramework.ASR) {
                            $usePreFramework = $true
                            # Build rules array from PreFramework snapshot
                            if ($preFramework.ASR.RuleIds -and $preFramework.ASR.RuleIds.Count -gt 0) {
                                for ($i = 0; $i -lt $preFramework.ASR.RuleIds.Count; $i++) {
                                    if ($preFramework.ASR.RuleActions[$i] -ne 0) {
                                        $asrRulesToRestore += @{
                                            GUID = $preFramework.ASR.RuleIds[$i]
                                            Action = $preFramework.ASR.RuleActions[$i]
                                        }
                                    }
                                }
                            }
                            Write-Log -Level DEBUG -Message "PreFramework snapshot: $($preFramework.ASR.RuleCount) total rules, $($asrRulesToRestore.Count) active" -Module "Rollback"
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to parse PreFramework_Snapshot.json: $_ - falling back to module backup" -Module "Rollback"
                        $usePreFramework = $false
                    }
                }
                
                # Fallback to module-level backup if PreFramework not available
                if (-not $usePreFramework) {
                    $asrMpPrefBackup = Get-ChildItem -Path $moduleBackupPath -Filter "ASR_ActiveConfiguration.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    
                    if ($asrMpPrefBackup) {
                        Write-Log -Level INFO -Message "Using ASR_ActiveConfiguration.json (single-module or legacy backup)" -Module "Rollback"
                        try {
                            $asrBackupData = Get-Content $asrMpPrefBackup.FullName -Raw | ConvertFrom-Json
                            if ($asrBackupData.Rules) {
                                $asrRulesToRestore = $asrBackupData.Rules | Where-Object { $_.Action -ne 0 }
                            }
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to parse ASR_ActiveConfiguration.json: $_" -Module "Rollback"
                        }
                    }
                    else {
                        Write-Log -Level WARNING -Message "No ASR backup found - ASR rules will remain cleared" -Module "Rollback"
                    }
                }
                
                # Apply the rules (from either source)
                if ($asrRulesToRestore.Count -gt 0) {
                    try {
                        $ruleIds = $asrRulesToRestore | ForEach-Object { $_.GUID }
                        $ruleActions = $asrRulesToRestore | ForEach-Object { $_.Action }
                        
                        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds `
                                        -AttackSurfaceReductionRules_Actions $ruleActions `
                                        -ErrorAction Stop
                        
                        $sourceDesc = if ($usePreFramework) { "PreFramework snapshot (TRUE pre-hardening)" } else { "ASR_ActiveConfiguration.json" }
                        Write-Log -Level SUCCESS -Message "ASR rules restored via Set-MpPreference ($($asrRulesToRestore.Count) active rules from $sourceDesc)" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restore ASR via Set-MpPreference: $_" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                else {
                    # System had 0 active ASR rules before hardening (Clean State)
                    # Clear-ASRRules already did the job, and Registry rules were also cleared.
                    $sourceDesc = if ($usePreFramework) { "PreFramework snapshot" } else { "ASR backup" }
                    Write-Log -Level SUCCESS -Message "ASR: $sourceDesc contains 0 active rules. System restored to clean state (0/19 ASR rules)." -Module "Rollback"
                    Write-RestoreLog -Level SUCCESS -Message "ASR restored to clean state (0 rules) from $sourceDesc"
                }
            }
            
            # Restore all registry backups for this module
            $regFiles = Get-ChildItem -Path $moduleBackupPath -Filter "*_Registry.reg" -ErrorAction SilentlyContinue
            foreach ($regFile in $regFiles) {
                # Special handling for AuditPolicy registry - just delete the value instead of importing
                if ($regFile.Name -match "AuditPolicy_SCENoApplyLegacyAuditPolicy") {
                    try {
                        Write-Log -Level INFO -Message "Removing SCENoApplyLegacyAuditPolicy registry value..." -Module "Rollback"
                        Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
                        Write-Log -Level SUCCESS -Message "SCENoApplyLegacyAuditPolicy removed" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Could not remove SCENoApplyLegacyAuditPolicy (may not exist)" -Module "Rollback"
                    }
                }
                else {
                    $success = Restore-FromBackup -BackupFile $regFile.FullName -Type "Registry"
                    if (-not $success) {
                        # Check if we have a JSON fallback (Smart Warning Suppression)
                        $isProtectedKey = $false
                        if ($moduleInfo.name -eq "AntiAI" -and $regFile.Name -match "Explorer_Advanced_Device_Registry") { $isProtectedKey = $true }
                        if ($moduleInfo.name -eq "AdvancedSecurity" -and ($regFile.Name -match "RDP_Settings" -or $regFile.Name -match "WPAD_")) { $isProtectedKey = $true }

                        if ($isProtectedKey) {
                            Write-Log -Level INFO -Message "Standard registry import skipped for protected key (will use Smart JSON-Fallback)." -Module "Rollback"
                        }
                        else {
                            Write-Log -Level WARNING -Message "Registry restore failed for: $($regFile.Name) - continuing..." -Module "Rollback"
                        }
                        # Don't fail entire restore for registry errors - continue with other restores
                    }
                }
            }
            
            # Special handling for protected registry keys (RDP, WPAD) that fail with reg.exe import
            # These keys require PowerShell-based restore from JSON backups
            if ($moduleInfo.name -eq "AntiAI") {
                # Explorer Advanced Settings - use JSON backup if .reg import failed
                $expJsonBackup = Get-ChildItem -Path $moduleBackupPath -Filter "Explorer_Advanced_Device_JSON.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($expJsonBackup) {
                    Write-Log -Level INFO -Message "Restoring Explorer Advanced settings via PowerShell (protected key)..." -Module "Rollback"
                    try {
                        $expData = Get-Content $expJsonBackup.FullName -Raw | ConvertFrom-Json
                        if ($null -ne $expData.ShowCopilotButton) {
                            $expPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                            if (Test-Path $expPath) {
                                Set-ItemProperty -Path $expPath -Name "ShowCopilotButton" -Value $expData.ShowCopilotButton -Force -ErrorAction Stop
                                Write-Log -Level SUCCESS -Message "Explorer Advanced settings restored via PowerShell" -Module "Rollback"
                            }
                        }
                    } catch {
                        Write-Log -Level WARNING -Message "PowerShell-based Explorer restore failed: $($_.Exception.Message)" -Module "Rollback"
                    }
                }

                # Apply AntiAI pre-state snapshot (32 policies) if available
                $antiAIPreStatePath = Join-Path $moduleBackupPath "AntiAI_PreState.json"
                if (Test-Path $antiAIPreStatePath) {
                    Write-Log -Level INFO -Message "Restoring AntiAI pre-state snapshot (32 policies)..." -Module "Rollback"
                    try {
                        $preEntries = Get-Content $antiAIPreStatePath -Raw | ConvertFrom-Json

                        foreach ($entry in $preEntries) {
                            if (-not $entry.Path -or -not $entry.Name) { continue }

                            if ($entry.Exists) {
                                # Value existed before hardening - restore original value/type
                                $keyPath = $entry.Path
                                try {
                                    if (-not (Test-Path $keyPath)) {
                                        New-Item -Path $keyPath -Force | Out-Null
                                    }

                                    $regType = switch ($entry.Type) {
                                        "DWord"       { "DWord" }
                                        "String"      { "String" }
                                        "MultiString" { "MultiString" }
                                        default        { "String" }
                                    }

                                    $existing = Get-ItemProperty -Path $keyPath -Name $entry.Name -ErrorAction SilentlyContinue
                                    if ($null -ne $existing) {
                                        Set-ItemProperty -Path $keyPath -Name $entry.Name -Value $entry.Value -Force -ErrorAction SilentlyContinue
                                    }
                                    else {
                                        New-ItemProperty -Path $keyPath -Name $entry.Name -Value $entry.Value -PropertyType $regType -Force -ErrorAction SilentlyContinue | Out-Null
                                    }
                                }
                                catch {
                                    Write-Log -Level WARNING -Message "Failed to restore AntiAI value $($entry.Path)\$($entry.Name): $($_.Exception.Message)" -Module "Rollback"
                                }
                            }
                            else {
                                # Value did not exist before hardening - was created during hardening, so remove it
                                try {
                                    if (Test-Path $entry.Path) {
                                        Remove-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                                    }
                                }
                                catch {
                                    Write-Log -Level DEBUG -Message "AntiAI pre-state cleanup: could not remove $($entry.Path)\$($entry.Name) - $($_.Exception.Message)" -Module "Rollback"
                                }
                            }
                        }

                        Write-Log -Level SUCCESS -Message "AntiAI pre-state snapshot applied successfully" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to apply AntiAI pre-state snapshot: $($_.Exception.Message)" -Module "Rollback"
                    }
                }
            }

            if ($moduleInfo.name -eq "AdvancedSecurity") {
                # RDP Settings - use JSON backup if .reg import failed
                $rdpJsonBackup = Get-ChildItem -Path $moduleBackupPath -Filter "RDP_Hardening.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($rdpJsonBackup) {
                    Write-Log -Level INFO -Message "Restoring RDP settings via PowerShell (protected key)..." -Module "Rollback"
                    try {
                        $rdpData = Get-Content $rdpJsonBackup.FullName -Raw | ConvertFrom-Json
                        
                        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                        $systemPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                        
                        # Restore Policy settings (if backed up)
                        if ($null -ne $rdpData.Policy_UserAuthentication) {
                            if (Test-Path $policyPath) {
                                Set-ItemProperty -Path $policyPath -Name "UserAuthentication" -Value $rdpData.Policy_UserAuthentication -Force -ErrorAction Stop
                            }
                        }
                        if ($null -ne $rdpData.Policy_SecurityLayer) {
                            if (Test-Path $policyPath) {
                                Set-ItemProperty -Path $policyPath -Name "SecurityLayer" -Value $rdpData.Policy_SecurityLayer -Force -ErrorAction Stop
                            }
                        }
                        
                        # Restore System settings (if backed up)
                        if ($null -ne $rdpData.System_fDenyTSConnections) {
                            if (Test-Path $systemPath) {
                                Set-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -Value $rdpData.System_fDenyTSConnections -Force -ErrorAction Stop
                            }
                        }
                        
                        Write-Log -Level SUCCESS -Message "RDP settings restored via PowerShell" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "PowerShell-based RDP restore failed: $($_.Exception.Message)" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level INFO -Message "RDP_Hardening.json backup not found (backup created before JSON feature was added)" -Module "Rollback"
                    Write-Log -Level INFO -Message "RDP settings cannot be fully restored from this backup - create new backup for complete restore" -Module "Rollback"
                }
                
                # WPAD Settings - use JSON backup if .reg import failed
                $wpadJsonBackup = Get-ChildItem -Path $moduleBackupPath -Filter "WPAD.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($wpadJsonBackup) {
                    Write-Log -Level INFO -Message "Restoring WPAD settings via PowerShell (protected key)..." -Module "Rollback"
                    try {
                        $wpadData = Get-Content $wpadJsonBackup.FullName -Raw | ConvertFrom-Json
                        
                        # WPAD JSON format: { "FullPath\\ValueName": value }
                        foreach ($property in $wpadData.PSObject.Properties) {
                            $fullPath = $property.Name
                            $lastBackslash = $fullPath.LastIndexOf('\')
                            
                            if ($lastBackslash -gt 0) {
                                $keyPath = $fullPath.Substring(0, $lastBackslash)
                                $valueName = $fullPath.Substring($lastBackslash + 1)
                                
                                if ($null -ne $property.Value -and (Test-Path $keyPath)) {
                                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $property.Value -Force -ErrorAction Stop
                                }
                            }
                        }
                        
                        Write-Log -Level SUCCESS -Message "WPAD settings restored via PowerShell" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "PowerShell-based WPAD restore failed: $($_.Exception.Message)" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level INFO -Message "WPAD.json backup not found (backup created before JSON feature was added)" -Module "Rollback"
                    Write-Log -Level INFO -Message "WPAD settings cannot be fully restored from this backup - create new backup for complete restore" -Module "Rollback"
                }
            }
            
            # Handle Empty Markers: Delete registry keys that didn't exist before hardening
            $emptyMarkers = Get-ChildItem -Path $moduleBackupPath -Filter "*_EMPTY.json" -ErrorAction SilentlyContinue
            foreach ($marker in $emptyMarkers) {
                try {
                    $markerData = Get-Content $marker.FullName -Raw | ConvertFrom-Json
                    
                    if ($markerData.State -eq "NotExisted" -and $markerData.KeyPath) {
                        Write-Log -Level INFO -Message "Processing empty marker: Registry key '$($markerData.KeyPath)' did not exist before hardening - deleting..." -Module "Rollback"
                        
                        if (Test-Path $markerData.KeyPath) {
                            Remove-Item -Path $markerData.KeyPath -Recurse -Force -ErrorAction Stop
                            Write-Log -Level SUCCESS -Message "Deleted registry key (did not exist before hardening): $($markerData.KeyPath)" -Module "Rollback"
                        }
                        else {
                            Write-Log -Level INFO -Message "Registry key already doesn't exist: $($markerData.KeyPath)" -Module "Rollback"
                        }
                    }
                }
                catch {
                    Write-Log -Level WARNING -Message "Failed to process empty marker $($marker.Name): $_" -Module "Rollback"
                }
            }
            
            # Restore all service backups for this module
            $serviceFiles = Get-ChildItem -Path $moduleBackupPath -Filter "*_Service.json" -ErrorAction SilentlyContinue
            foreach ($serviceFile in $serviceFiles) {
                $success = Restore-FromBackup -BackupFile $serviceFile.FullName -Type "Service"
                if (-not $success) {
                    $allSucceeded = $false
                }
            }
            
            # Restore all task backups for this module
            $taskFiles = Get-ChildItem -Path $moduleBackupPath -Filter "*_Task.xml" -ErrorAction SilentlyContinue
            foreach ($taskFile in $taskFiles) {
                $success = Restore-FromBackup -BackupFile $taskFile.FullName -Type "ScheduledTask"
                if (-not $success) {
                    $allSucceeded = $false
                }
            }
            
            # Special handling for DNS: Restore DNS settings from backup
            if ($moduleInfo.name -eq "DNS") {
                Write-Log -Level INFO -Message "Restoring DNS settings from backup..." -Module "Rollback"
                
                # Find DNS backup file
                $dnsBackupFile = Get-ChildItem -Path $moduleBackupPath -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                
                if ($dnsBackupFile) {
                    Write-Log -Level INFO -Message "Found DNS backup: $($dnsBackupFile.Name)" -Module "Rollback"
                    
                    # Load DNS module for restore
                    $dnsModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\DNS\DNS.psd1"
                    if (Test-Path $dnsModulePath) {
                        try {
                            Import-Module $dnsModulePath -Force -ErrorAction Stop
                            
                            # Call DNS module's restore function
                            $restoreResult = Restore-DNSSettings -BackupFilePath $dnsBackupFile.FullName
                            
                            if ($restoreResult) {
                                Write-Log -Level SUCCESS -Message "DNS settings restored successfully" -Module "Rollback"
                            }
                            else {
                                Write-Log -Level WARNING -Message "DNS restore had issues - check logs" -Module "Rollback"
                                $allSucceeded = $false
                            }
                            
                            Remove-Module DNS -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to restore DNS settings: $_" -Module "Rollback"
                            $allSucceeded = $false
                        }
                    }
                    else {
                        Write-Log -Level WARNING -Message "DNS module not found - cannot restore DNS settings" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No DNS backup file found in: $moduleBackupPath" -Module "Rollback"
                }
            }

            # Special handling for EdgeHardening: Restore Edge policy pre-state snapshot
            if ($moduleInfo.name -eq "EdgeHardening") {
                $edgePreStatePath = Join-Path $moduleBackupPath "EdgeHardening_PreState.json"
                if (Test-Path $edgePreStatePath) {
                    Write-Log -Level INFO -Message "Restoring Edge policy pre-state snapshot..." -Module "Rollback"
                    try {
                        $preEntries = Get-Content $edgePreStatePath -Raw | ConvertFrom-Json

                        $edgeRoot = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge"
                        if (Test-Path $edgeRoot) {
                            $keysToProcess = @()
                            $keysToProcess += $edgeRoot
                            $childKeys = Get-ChildItem -Path $edgeRoot -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
                            foreach ($child in $childKeys) {
                                $keysToProcess += $child.PSPath
                            }

                            foreach ($keyPath in $keysToProcess) {
                                try {
                                    $currentProps = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                                    if ($currentProps) {
                                        $propNames = $currentProps.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') }
                                        foreach ($prop in $propNames) {
                                            Remove-ItemProperty -Path $keyPath -Name $prop -ErrorAction SilentlyContinue
                                        }
                                    }
                                }
                                catch {
                                    Write-Log -Level DEBUG -Message "Could not clear $keyPath : $_" -Module "Rollback"
                                }
                            }
                        }

                        $restoredCount = 0
                        foreach ($entry in $preEntries) {
                            if (-not $entry.Path -or -not $entry.Name) { continue }

                            try {
                                if (-not (Test-Path $entry.Path)) {
                                    New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                                }

                                $regType = switch ($entry.Type) {
                                    "DWord"       { "DWord" }
                                    "String"      { "String" }
                                    "MultiString" { "MultiString" }
                                    "ExpandString" { "ExpandString" }
                                    "Binary"      { "Binary" }
                                    "QWord"       { "QWord" }
                                    default        { "String" }
                                }

                                New-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.Value -PropertyType $regType -Force -ErrorAction Stop | Out-Null
                                $restoredCount++
                            }
                            catch {
                                Write-Log -Level DEBUG -Message "Failed to restore Edge policy value $($entry.Path)\\$($entry.Name): $_" -Module "Rollback"
                            }
                        }

                        Write-Log -Level SUCCESS -Message "Edge policy pre-state restored ($restoredCount values)" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore EdgeHardening pre-state snapshot: $_" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level INFO -Message "No EdgeHardening pre-state snapshot found - using .reg restore + empty markers only" -Module "Rollback"
                }
            }

            # Special handling for Privacy: Restore registry snapshot + removed apps
            if ($moduleInfo.name -eq "Privacy") {
                # STEP 1: Restore Privacy registry pre-state snapshot (counters GPO tattooing)
                $privacyPreStatePath = Join-Path $moduleBackupPath "Privacy_PreState.json"
                if (Test-Path $privacyPreStatePath) {
                    Write-Log -Level INFO -Message "Restoring Privacy registry pre-state snapshot..." -Module "Rollback"
                    try {
                        $preEntries = Get-Content $privacyPreStatePath -Raw | ConvertFrom-Json
                        
                        # Build list of all keys to clear first (must match Backup-PrivacySettings list)
                        # CRITICAL: Include ALL keys that Privacy module modifies, including HKCU user settings!
                        $keysToProcess = @(
                            # HKLM Policy keys
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
                            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
                            "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
                            "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Dsh",
                            "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics",
                            # HKCU Policy keys
                            "HKCU:\Software\Policies\Microsoft\Windows\Explorer",
                            # HKCU User settings (FIX: these were missing, causing restore incomplete!)
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings",
                            "HKCU:\Control Panel\International\User Profile",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
                            "HKCU:\SOFTWARE\Microsoft\Personalization\Settings",
                            # NEW: Input Personalization Settings (v2.2.0 - FIX missing HKCU restore)
                            "HKCU:\SOFTWARE\Microsoft\InputPersonalization",
                            "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
                        )
                        
                        # Clear all current values in Privacy keys (prepare clean slate)
                        foreach ($keyPath in $keysToProcess) {
                            if (Test-Path $keyPath) {
                                try {
                                    $currentProps = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                                    if ($currentProps) {
                                        $propNames = $currentProps.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider') }
                                        foreach ($prop in $propNames) {
                                            Remove-ItemProperty -Path $keyPath -Name $prop -ErrorAction SilentlyContinue
                                        }
                                    }
                                } catch {
                                    Write-Log -Level DEBUG -Message "Could not clear $keyPath : $_" -Module "Rollback"
                                }
                            }
                        }
                        
                        # Restore original values from snapshot
                        $restoredCount = 0
                        foreach ($entry in $preEntries) {
                            if (-not $entry.Path -or -not $entry.Name) { continue }
                            
                            try {
                                if (-not (Test-Path $entry.Path)) {
                                    New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                                }
                                
                                $regType = switch ($entry.Type) {
                                    "DWord"       { "DWord" }
                                    "String"      { "String" }
                                    "MultiString" { "MultiString" }
                                    "ExpandString" { "ExpandString" }
                                    "Binary"      { "Binary" }
                                    default        { "String" }
                                }
                                
                                New-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.Value -PropertyType $regType -Force -ErrorAction Stop | Out-Null
                                $restoredCount++
                            }
                            catch {
                                Write-Log -Level DEBUG -Message "Failed to restore Privacy value $($entry.Path)\$($entry.Name): $_" -Module "Rollback"
                            }
                        }
                        
                        Write-Log -Level SUCCESS -Message "Privacy registry pre-state restored ($restoredCount values)" -Module "Rollback"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore Privacy pre-state snapshot: $_" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No Privacy pre-state snapshot found - using .reg restore only (tattooing may occur)" -Module "Rollback"
                }
                
                # STEP 2: Restore removed apps via winget (if metadata exists)
                Write-Log -Level INFO -Message "Restoring removed apps for Privacy module (winget) if applicable..." -Module "Rollback"

                $privacyModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\Privacy\Privacy.psd1"
                if (Test-Path $privacyModulePath) {
                    try {
                        Import-Module $privacyModulePath -Force -ErrorAction Stop

                        if (Get-Command Restore-Bloatware -ErrorAction SilentlyContinue) {
                            $restoreAppsResult = Restore-Bloatware -BackupPath $moduleBackupPath
                            
                            # Restore-Bloatware now returns PSCustomObject with Success and NonRestorableApps properties
                            if ($restoreAppsResult.Success) {
                                Write-Log -Level SUCCESS -Message "Privacy apps restore (winget) completed" -Module "Rollback"
                            }
                            else {
                                Write-Log -Level WARNING -Message "Privacy apps restore (winget) reported issues - check logs" -Module "Rollback"
                                $allSucceeded = $false
                            }
                            
                            # Track non-restorable apps for user notification before reboot
                            if ($restoreAppsResult.NonRestorableApps -and $restoreAppsResult.NonRestorableApps.Count -gt 0) {
                                $script:PrivacyNonRestorableApps = $restoreAppsResult.NonRestorableApps
                            }
                        }
                        else {
                            Write-Log -Level WARNING -Message "Restore-Bloatware function not found in Privacy module - skipping app restore" -Module "Rollback"
                        }

                        Remove-Module Privacy -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restore Privacy apps via winget: $_" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "Privacy module not found - cannot restore removed apps" -Module "Rollback"
                }
            }
            
            # Special handling for SecurityBaseline: Restore LocalGPO after clearing
            if ($moduleInfo.name -eq "SecurityBaseline") {
                $gpoBackupPath = Join-Path $moduleBackupPath "LocalGPO"
                if (Test-Path $gpoBackupPath) {
                    Write-Log -Level INFO -Message "Restoring Local Group Policy from: $gpoBackupPath" -Module "Rollback"
                    
                    try {
                        $gpoTargetPath = "C:\Windows\System32\GroupPolicy"
                        
                        # Check if backup directory has content (not empty)
                        $backupContent = Get-ChildItem -Path $gpoBackupPath -Recurse -ErrorAction SilentlyContinue
                        
                        if ($backupContent -and $backupContent.Count -gt 0) {
                            # Copy all contents from LocalGPO backup to GroupPolicy directory
                            Copy-Item -Path "$gpoBackupPath\*" -Destination $gpoTargetPath -Recurse -Force -ErrorAction Stop
                            
                            Write-Log -Level SUCCESS -Message "Local Group Policy restored successfully from backup" -Module "Rollback"
                        }
                        else {
                            # Empty backup = system had no LocalGPO before hardening
                            Write-Log -Level INFO -Message "LocalGPO backup is empty (system was clean before hardening) - no restore needed" -Module "Rollback"
                        }
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Exception restoring Local Group Policy: $($_.Exception.Message)" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No LocalGPO backup found for SecurityBaseline - policies remain cleared" -Module "Rollback"
                }
            }
            
            # Special handling for AdvancedSecurity: Restore custom settings
            if ($moduleInfo.name -eq "AdvancedSecurity") {
                Write-Log -Level INFO -Message "Restoring Advanced Security settings..." -Module "Rollback"
                Write-RestoreLog -Level INFO -Message "[ADVANCEDSECURITY] Starting restore..."
                
                # STEP 1: Restore AdvancedSecurity registry pre-state snapshot (counters GPO tattooing)
                $advSecPreStatePath = Join-Path $moduleBackupPath "AdvancedSecurity_PreState.json"
                Write-RestoreLog -Level DEBUG -Message "PreState snapshot path: $advSecPreStatePath"
                if (Test-Path $advSecPreStatePath) {
                    Write-Log -Level INFO -Message "Restoring AdvancedSecurity registry pre-state snapshot..." -Module "Rollback"
                    Write-RestoreLog -Level INFO -Message "[STEP 1] AdvancedSecurity Registry PreState Restore"
                    try {
                        Write-RestoreLog -Level DEBUG -Message "Loading PreState JSON..."
                        $preEntries = Get-Content $advSecPreStatePath -Raw | ConvertFrom-Json
                        Write-RestoreLog -Level DEBUG -Message "PreState entries loaded: $($preEntries.Count) values"
                        
                        # Build list of all keys to clear first
                        $keysToProcess = @(
                            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
                            "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",  # mDNS / Discovery Protocols
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",  # Official MS DisableWpad key
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",     # Legacy WpadOverride
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",          # AutoDetect
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                            "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect",  # Wireless Display / Miracast
                            "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",  # Firewall Shields Up
                            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"  # IPv6 disable (mitm6 mitigation)
                        )
                        
                        # Clear all current values in AdvancedSecurity keys (prepare clean slate)
                        Write-RestoreLog -Level DEBUG -Message "Clearing current AdvancedSecurity keys (preparing clean slate)..."
                        Write-RestoreLog -Level DEBUG -Message "Keys to process: $($keysToProcess.Count)"
                        $clearedCount = 0
                        foreach ($keyPath in $keysToProcess) {
                            if (Test-Path $keyPath) {
                                try {
                                    $currentProps = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                                    if ($currentProps) {
                                        $propNames = $currentProps.PSObject.Properties.Name | Where-Object { 
                                            $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') 
                                        }
                                        foreach ($prop in $propNames) {
                                            # Skip system-critical RDP values that should never be deleted
                                            if ($keyPath -like "*Terminal Server*" -and $prop -in @("fSingleSessionPerUser", "TSEnabled", "TSUserEnabled")) {
                                                continue
                                            }
                                            Remove-ItemProperty -Path $keyPath -Name $prop -ErrorAction SilentlyContinue
                                            $clearedCount++
                                        }
                                    }
                                }
                                catch {
                                    Write-Log -Level DEBUG -Message "Could not clear $keyPath : $_" -Module "Rollback"
                                    Write-RestoreLog -Level WARNING -Message "Could not clear $keyPath : $_"
                                }
                            }
                        }
                        Write-RestoreLog -Level DEBUG -Message "Cleared $clearedCount values from AdvancedSecurity keys"
                        
                        # Restore original values from snapshot
                        Write-RestoreLog -Level DEBUG -Message "Restoring original values from PreState snapshot..."
                        $restoredCount = 0
                        $failedCount = 0
                        foreach ($entry in $preEntries) {
                            if (-not $entry.Path -or -not $entry.Name) { continue }
                            
                            try {
                                if (-not (Test-Path $entry.Path)) {
                                    New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                                }
                                
                                $regType = switch ($entry.Type) {
                                    "DWord"       { "DWord" }
                                    "String"      { "String" }
                                    "MultiString" { "MultiString" }
                                    "ExpandString" { "ExpandString" }
                                    "Binary"      { "Binary" }
                                    "QWord"       { "QWord" }
                                    default        { "String" }
                                }
                                
                                New-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.Value -PropertyType $regType -Force -ErrorAction Stop | Out-Null
                                $restoredCount++
                            }
                            catch {
                                Write-Log -Level DEBUG -Message "Failed to restore AdvancedSecurity value $($entry.Path)\$($entry.Name): $_" -Module "Rollback"
                                Write-RestoreLog -Level WARNING -Message "Failed to restore: $($entry.Path)\$($entry.Name) - $_"
                                $failedCount++
                            }
                        }
                        
                        Write-Log -Level SUCCESS -Message "AdvancedSecurity registry pre-state restored ($restoredCount values)" -Module "Rollback"
                        Write-RestoreLog -Level SUCCESS -Message "PreState restored: $restoredCount values restored, $failedCount failed"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to restore AdvancedSecurity pre-state snapshot: $_" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "PreState restore FAILED: $($_.Exception.Message)"
                        Write-RestoreLog -Level ERROR -Message "Stack trace: $($_.ScriptStackTrace)"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No AdvancedSecurity pre-state snapshot found - using .reg restore only (tattooing may occur)" -Module "Rollback"
                    Write-RestoreLog -Level WARNING -Message "No PreState snapshot found - using .reg restore only (tattooing may occur)"
                }
                
                # STEP 2: Find all AdvancedSecurity custom backup files (RiskyPorts, PowerShellV2, AdminShares)
                $advSecBackups = Get-ChildItem -Path $moduleBackupPath -Filter "*_*.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "_Service.json" -and $_.Name -ne "AdvancedSecurity_PreState.json" }
                
                if ($advSecBackups) {
                    # Load AdvancedSecurity module for restore
                    $advSecModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\AdvancedSecurity\AdvancedSecurity.psd1"
                    
                    if (Test-Path $advSecModulePath) {
                        try {
                            Import-Module $advSecModulePath -Force -ErrorAction Stop
                            
                            foreach ($backupFile in $advSecBackups) {
                                Write-Log -Level INFO -Message "Restoring Advanced Security backup: $($backupFile.Name)" -Module "Rollback"
                                
                                # Call AdvancedSecurity module's restore function
                                $restoreResult = Restore-AdvancedSecuritySettings -BackupFilePath $backupFile.FullName
                                
                                if ($restoreResult) {
                                    Write-Log -Level SUCCESS -Message "Restored: $($backupFile.Name)" -Module "Rollback"
                                }
                                else {
                                    Write-Log -Level WARNING -Message "Failed to restore: $($backupFile.Name)" -Module "Rollback"
                                    $allSucceeded = $false
                                }
                            }
                            
                            Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to restore Advanced Security settings: $_" -Module "Rollback"
                            $allSucceeded = $false
                        }
                    }
                    else {
                        Write-Log -Level WARNING -Message "AdvancedSecurity module not found - cannot restore settings" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                
                # CRITICAL FIX: Restore Firewall_Rules and SMB_Shares from session root
                # Bug: These backups are stored in separate folders (Firewall_Rules/, SMB_Shares/)
                # in the session root, not under AdvancedSecurity/, so they were never restored.
                # This caused Finger Protocol rule and Admin Shares to remain active after restore.
                Write-RestoreLog -Level INFO -Message "[FIX 3a/3] Restoring Firewall_Rules and SMB_Shares from session root..."
                $firewallBackupDir = Join-Path $SessionPath "Firewall_Rules"
                $smbBackupDir = Join-Path $SessionPath "SMB_Shares"
                Write-RestoreLog -Level DEBUG -Message "Firewall backup dir: $firewallBackupDir"
                Write-RestoreLog -Level DEBUG -Message "SMB backup dir: $smbBackupDir"
                
                foreach ($backupDir in @($firewallBackupDir, $smbBackupDir)) {
                    if (Test-Path $backupDir) {
                        Write-RestoreLog -Level DEBUG -Message "Processing backup directory: $backupDir"
                        $backupFiles = Get-ChildItem -Path $backupDir -Filter "*.json" -ErrorAction SilentlyContinue
                        Write-RestoreLog -Level DEBUG -Message "Found $($backupFiles.Count) backup file(s)"
                        
                        if ($backupFiles) {
                            $advSecModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\AdvancedSecurity\AdvancedSecurity.psd1"
                            
                            if (Test-Path $advSecModulePath) {
                                try {
                                    Import-Module $advSecModulePath -Force -ErrorAction Stop
                                    
                                    foreach ($backupFile in $backupFiles) {
                                        Write-Log -Level INFO -Message "Restoring $(Split-Path $backupDir -Leaf) backup: $($backupFile.Name)" -Module "Rollback"
                                        Write-RestoreLog -Level INFO -Message "Restoring: $(Split-Path $backupDir -Leaf)\$($backupFile.Name)"
                                        
                                        $restoreResult = Restore-AdvancedSecuritySettings -BackupFilePath $backupFile.FullName
                                        
                                        if ($restoreResult) {
                                            Write-Log -Level SUCCESS -Message "Restored: $($backupFile.Name)" -Module "Rollback"
                                            Write-RestoreLog -Level SUCCESS -Message "Successfully restored: $($backupFile.Name)"
                                        }
                                        else {
                                            Write-Log -Level WARNING -Message "Failed to restore: $($backupFile.Name)" -Module "Rollback"
                                            Write-RestoreLog -Level ERROR -Message "FAILED to restore: $($backupFile.Name)"
                                            $allSucceeded = $false
                                        }
                                    }
                                    
                                    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
                                }
                                catch {
                                    Write-Log -Level ERROR -Message "Failed to restore $(Split-Path $backupDir -Leaf): $_" -Module "Rollback"
                                    $allSucceeded = $false
                                }
                            }
                        }
                    }
                }
                
                # CRITICAL FIX: Clean up SRP subkeys if system was clean before hardening
                # Bug: PreState-Restore only clears values in root key, not the \0\Paths subkeys
                # where actual SRP rules live. This caused "Block LNK" rules to remain after restore.
                Write-RestoreLog -Level INFO -Message "[FIX 3b/3] Checking SRP subkey cleanup..."
                $srpRootKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
                if (Test-Path $srpRootKey) {
                    Write-RestoreLog -Level DEBUG -Message "SRP root key exists: $srpRootKey"
                    try {
                        # Check if PreState had ANY SRP-related entries
                        $hadSRPInPreState = $false
                        if (Test-Path $advSecPreStatePath) {
                            Write-RestoreLog -Level DEBUG -Message "Reading PreState from: $advSecPreStatePath"
                            $preEntries = Get-Content $advSecPreStatePath -Raw | ConvertFrom-Json
                            $srpEntries = $preEntries | Where-Object { $_.Path -like "*Safer\CodeIdentifiers*" }
                            $hadSRPInPreState = $srpEntries.Count -gt 0
                            Write-RestoreLog -Level DEBUG -Message "SRP entries in PreState: $($srpEntries.Count)"
                        }
                        else {
                            Write-RestoreLog -Level WARNING -Message "PreState file not found: $advSecPreStatePath"
                        }
                        
                        if (-not $hadSRPInPreState) {
                            Write-RestoreLog -Level INFO -Message "System had NO SRP rules before hardening - removing SRP subkeys"
                            # System had NO SRP rules before hardening - clean up all SRP subkeys
                            $srpPathsKey = "$srpRootKey\0\Paths"
                            if (Test-Path $srpPathsKey) {
                                Write-RestoreLog -Level DEBUG -Message "Removing SRP Paths subkey: $srpPathsKey"
                                Remove-Item -Path $srpPathsKey -Recurse -Force -ErrorAction Stop
                                Write-Log -Level INFO -Message "Removed SRP Paths subkeys (system had no SRP rules before hardening)" -Module "Rollback"
                                Write-RestoreLog -Level SUCCESS -Message "SRP Paths subkeys removed successfully"
                            }
                            else {
                                Write-RestoreLog -Level DEBUG -Message "SRP Paths subkey does not exist (correct state)"
                            }
                        }
                        else {
                            Write-Log -Level DEBUG -Message "System had SRP rules in PreState - keeping SRP structure" -Module "Rollback"
                            Write-RestoreLog -Level INFO -Message "System had $($srpEntries.Count) SRP rules in PreState - keeping SRP structure"
                        }
                    }
                    catch {
                        Write-Log -Level DEBUG -Message "Could not clean SRP subkeys: $_" -Module "Rollback"
                        Write-RestoreLog -Level ERROR -Message "SRP cleanup failed: $_"
                    }
                }
                else {
                    Write-RestoreLog -Level DEBUG -Message "SRP root key does not exist (correct state)"
                }
            }
            
            Write-Log -Level SUCCESS -Message "Completed restore for module: $($moduleInfo.name)" -Module "Rollback"
            Write-RestoreLog -Level SUCCESS -Message "Module $($moduleInfo.name) restore completed"
            Write-RestoreLog -Level INFO -Message " "
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
        
        # NOTE: Pre-Framework Snapshot processing for ASR has been moved to the module-level
        # restore section (see "if ($moduleInfo.name -eq "ASR")" block above).
        # 
        # The module-level ASR restore now correctly prioritizes:
        # 1. PreFramework_Snapshot.json - TRUE pre-hardening state (before SecurityBaseline runs)
        # 2. ASR_ActiveConfiguration.json - fallback for single-module ASR runs
        #
        # This section is reserved for future non-ASR shared resources if needed.
        # Currently, PreFramework_Snapshot only contains ASR data, so no action needed here.
        
        Write-Host ""
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host "============================================================================" -ForegroundColor Cyan
        if ($allSucceeded) {
            Write-Host ""
            Write-Host "                    RESTORE COMPLETED SUCCESSFULLY                       " -ForegroundColor Green
            Write-Host ""
            Write-Host "  All security settings have been reverted to backup state" -ForegroundColor White
            Write-Host "  Modules restored: $($reversedModules.Count) | Total items: $($manifest.totalItems)" -ForegroundColor Gray
            Write-Host ""
        } else {
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

        # Prompt for reboot after restore
        Invoke-RestoreRebootPrompt
        
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
        
        return $allSucceeded
    }
    catch {
        Write-ErrorLog -Message "Failed to restore hardening session: $SessionName" -Module "Rollback" -ErrorRecord $_
        Write-RestoreLog -Level ERROR -Message "CRITICAL FAILURE: $_"
        Write-RestoreLog -Level ERROR -Message "Restore aborted with exception"
        return $false
    }
}

function Clear-AuditPolicies {
    <#
    .SYNOPSIS
        Clear all audit policies to disabled state
        
    .DESCRIPTION
        Uses auditpol.exe /clear to reset all audit policies to system defaults.
        This is the official Microsoft method to clear audit policies.
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        Write-Log -Level INFO -Message "Clearing all audit policies..." -Module "Rollback"
        
        # Use auditpol /clear /y (official MS command)
        # /clear: Deletes per-user policy, resets system policy, disables all auditing
        # /y: Suppress confirmation prompt
        $process = Start-Process -FilePath "auditpol.exe" `
            -ArgumentList "/clear", "/y" `
            -Wait `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput (Join-Path $env:TEMP "auditpol_clear_stdout.txt") `
            -RedirectStandardError (Join-Path $env:TEMP "auditpol_clear_stderr.txt")
        
        if ($process.ExitCode -eq 0) {
            Write-Log -Level SUCCESS -Message "Audit policies cleared successfully" -Module "Rollback"
            return $true
        }
        else {
            $errorOutput = Get-Content (Join-Path $env:TEMP "auditpol_clear_stderr.txt") -Raw -ErrorAction SilentlyContinue
            Write-Log -Level ERROR -Message "Failed to clear audit policies: $errorOutput" -Module "Rollback"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Exception clearing audit policies" -Module "Rollback" -Exception $_.Exception
        return $false
    }
}

function Clear-ASRRules {
    <#
    .SYNOPSIS
        Clear all ASR rules to Not Configured state
        
    .DESCRIPTION
        Uses Remove-MpPreference to remove all ASR rule configurations.
        This sets all rules back to "Not configured" state.
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        Write-Log -Level INFO -Message "Clearing all ASR rules..." -Module "Rollback"
        
        # Get current ASR rules
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        if ($mpPref.AttackSurfaceReductionRules_Ids -and $mpPref.AttackSurfaceReductionRules_Ids.Count -gt 0) {
            # Remove all ASR rule IDs and Actions
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $mpPref.AttackSurfaceReductionRules_Ids -ErrorAction Stop
            Remove-MpPreference -AttackSurfaceReductionRules_Actions $mpPref.AttackSurfaceReductionRules_Actions -ErrorAction Stop
            
            Write-Log -Level SUCCESS -Message "Cleared $($mpPref.AttackSurfaceReductionRules_Ids.Count) ASR rules" -Module "Rollback"
            return $true
        }
        else {
            Write-Log -Level INFO -Message "No ASR rules configured - nothing to clear" -Module "Rollback"
            return $true
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to clear ASR rules" -Module "Rollback" -Exception $_.Exception
        return $false
    }
}

function Reset-SecurityTemplate {
    <#
    .SYNOPSIS
        Restore security template settings from pre-hardening backup
        
    .DESCRIPTION
        Uses secedit.exe to restore security template settings from the backed up state.
        This includes password policies, user rights assignments, and other security settings.
        Falls back to defltbase.inf if no backup exists (with warning about limitations).
        
    .PARAMETER BackupFile
        Path to the pre-hardening security policy .inf backup file
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupFile
    )
    
    try {
        $templateToUse = $null
        $database = Join-Path $env:TEMP "secedit_restore.sdb"
        $logFile = Join-Path $env:TEMP "secedit_restore.log"
        
        # Check if backup file exists and use it
        if ($BackupFile -and (Test-Path $BackupFile)) {
            Write-Log -Level INFO -Message "Restoring security template from pre-hardening backup..." -Module "Rollback"
            $templateToUse = $BackupFile
        }
        else {
            # Fallback to defltbase.inf with warning
            Write-Log -Level WARNING -Message "No pre-hardening backup found. Using defltbase.inf (may not reset all settings)" -Module "Rollback"
            Write-Log -Level WARNING -Message "Microsoft KB 313222: defltbase.inf is no longer capable of resetting all security defaults" -Module "Rollback"
            
            $defaultTemplate = "$env:WINDIR\inf\defltbase.inf"
            
            if (-not (Test-Path $defaultTemplate)) {
                Write-Log -Level ERROR -Message "Default security template not found: $defaultTemplate" -Module "Rollback"
                return $false
            }
            
            $templateToUse = $defaultTemplate
        }
        
        # STEP 1: Import .inf file into database (required before configure)
        # Import only securitypolicy and user_rights areas (we handle audit policies separately with auditpol)
        Write-Log -Level INFO -Message "Importing security template into database..." -Module "Rollback"
        $importProcess = Start-Process -FilePath "secedit.exe" `
            -ArgumentList "/import", "/db", "`"$database`"", "/cfg", "`"$templateToUse`"", "/overwrite", "/areas", "securitypolicy", "user_rights", "/log", "`"$logFile`"", "/quiet" `
            -Wait `
            -NoNewWindow `
            -PassThru
        
        if ($importProcess.ExitCode -ne 0) {
            $errorLog = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            Write-Log -Level ERROR -Message "Failed to import security template (Exit: $($importProcess.ExitCode)): $errorLog" -Module "Rollback"
            Write-Log -Level ERROR -Message "Template file: $templateToUse" -Module "Rollback"
            return $false
        }
        
        Write-Log -Level SUCCESS -Message "Security template imported successfully" -Module "Rollback"
        
        # STEP 2: Configure system from database (only securitypolicy and user_rights)
        Write-Log -Level INFO -Message "Applying security template to system..." -Module "Rollback"
        $process = Start-Process -FilePath "secedit.exe" `
            -ArgumentList "/configure", "/db", "`"$database`"", "/areas", "securitypolicy", "user_rights", "/log", "`"$logFile`"", "/quiet" `
            -Wait `
            -NoNewWindow `
            -PassThru
        
        $errorLog = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        
        # Exit code evaluation:
        # 0 = success
        # 3 = success with warnings
        # 1 = error, BUT if it's only SID-mapping issues, treat as success with warning
        $isSidMappingOnly = $errorLog -match 'Zuordnungen von Kontennamen.*Sicherheitskennungen|account name.*security identifier'
        
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3 -or ($process.ExitCode -eq 1 -and $isSidMappingOnly)) {
            if ($process.ExitCode -eq 1) {
                Write-Log -Level WARNING -Message "Security template restored with SID-mapping warnings (non-fatal, most settings applied)" -Module "Rollback"
            }
            
            if ($BackupFile) {
                Write-Log -Level SUCCESS -Message "Security template restored from pre-hardening backup" -Module "Rollback"
            }
            else {
                Write-Log -Level SUCCESS -Message "Security template reset using defltbase.inf (partial reset)" -Module "Rollback"
            }
            return $true
        }
        else {
            Write-Log -Level ERROR -Message "Failed to restore security template (Exit: $($process.ExitCode)): $errorLog" -Module "Rollback"
            return $false
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to restore security template from backup" -Module "Rollback" -ErrorRecord $_
        return $false
    }
}

function Clear-LocalGPO {
    <#
    .SYNOPSIS
        Clear all local Group Policy settings to "Not Configured"
        
    .DESCRIPTION
        Deletes the registry.pol files which store local GPO settings.
        This is the official Microsoft method to reset all GPO settings to default.
        After deletion, gpupdate will recreate empty directories and all settings
        will be "Not Configured".
        
        Reference: https://woshub.com/reset-local-group-policies-settings-in-windows/
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        Write-Log -Level INFO -Message "Clearing all local Group Policy settings..." -Module "Rollback"
        
        # Paths to local GPO registry.pol files
        $gpoPaths = @(
            "$env:WinDir\System32\GroupPolicyUsers",
            "$env:WinDir\System32\GroupPolicy"
        )
        
        $clearedCount = 0
        
        foreach ($path in $gpoPaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Log -Level INFO -Message "Deleted GPO directory: $path" -Module "Rollback"
                    $clearedCount++
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not delete GPO directory: $path - $_" -Module "Rollback"
                }
            }
        }
        
        if ($clearedCount -gt 0) {
            Write-Log -Level SUCCESS -Message "Local Group Policy cleared successfully" -Module "Rollback"
            return $true
        }
        else {
            Write-Log -Level INFO -Message "No local GPO directories found to clear" -Module "Rollback"
            return $true
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to clear local Group Policy Objects" -Module "Rollback" -ErrorRecord $_
        return $false
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
