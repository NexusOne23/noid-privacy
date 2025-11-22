<#
.SYNOPSIS
    Backup and rollback functionality for NoID Privacy Pro Framework
    
.DESCRIPTION
    Implements the BACKUP/APPLY/VERIFY/RESTORE pattern for safe system modifications.
    Creates backups before changes and provides rollback capabilities.
    
.NOTES
    Author: NexusOne23
    Version: 2.1.0
    Requires: PowerShell 5.1+
#>

# Global backup tracking
$script:BackupIndex = @()
$script:BackupBasePath = ""
$script:NewlyCreatedKeys = @()  # Track newly created registry keys for proper restore
$script:SessionManifest = @{}  # Session metadata
$script:CurrentModule = ""  # Current module being backed up

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
    if ($script:BackupBasePath -and (Test-Path -Path $script:BackupBasePath)) {
        Write-Log -Level DEBUG -Message "Backup system already initialized, reusing session: $script:BackupBasePath" -Module "Rollback"
        return $true
    }
    
    # Create session-specific backup folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sessionId = "Session_$timestamp"
    $sessionBackupPath = Join-Path $BackupDirectory $sessionId
    New-Item -ItemType Directory -Path $sessionBackupPath -Force | Out-Null
    
    $script:BackupBasePath = $sessionBackupPath
    $script:BackupIndex = @()
    $script:NewlyCreatedKeys = @()
    
    # Initialize session manifest
    $script:SessionManifest = @{
        sessionId        = $sessionId
        timestamp        = Get-Date -Format "o"
        frameworkVersion = "2.1.0"
        modules          = @()
        totalItems       = 0
        restorable       = $true
        sessionPath      = $sessionBackupPath
    }
    
    Write-Log -Level INFO -Message "Backup system initialized: $sessionBackupPath" -Module "Rollback"
    
    return $true
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Create module subfolder
    $moduleBackupPath = Join-Path $script:BackupBasePath $ModuleName
    if (-not (Test-Path $moduleBackupPath)) {
        New-Item -ItemType Directory -Path $moduleBackupPath -Force | Out-Null
    }
    
    $script:CurrentModule = $ModuleName
    
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    if ([string]::IsNullOrEmpty($script:CurrentModule)) {
        Write-Log -Level WARNING -Message "No active module backup to complete" -Module "Rollback"
        return
    }
    
    # Update Manifest Object
    $moduleData = @{
        name          = $script:CurrentModule
        backupPath    = $script:CurrentModule
        itemsBackedUp = $ItemsBackedUp
        status        = $Status
        timestamp     = Get-Date -Format "o"
    }
    
    $script:SessionManifest.modules += $moduleData
    $script:SessionManifest.totalItems += $ItemsBackedUp
    
    # Write Manifest to Disk (robust against transient file locks)
    $manifestPath = Join-Path $script:BackupBasePath "manifest.json"
    $maxAttempts = 5
    $attempt = 0
    $delayMs = 200
    $encoding = New-Object System.Text.UTF8Encoding($false)
    
    while ($attempt -lt $maxAttempts) {
        try {
            $attempt++
            $json = $script:SessionManifest | ConvertTo-Json -Depth 5
            [System.IO.File]::WriteAllText($manifestPath, $json, $encoding)
            Write-Log -Level INFO -Message "Completed backup for $($script:CurrentModule) (Items: $ItemsBackedUp). Manifest updated." -Module "Rollback"
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
    $script:CurrentModule = ""
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    try {
        # Sanitize backup name for filename
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'
        
        # Save to current module folder if active, otherwise root
        $backupFolder = if ($script:CurrentModule) {
            Join-Path $script:BackupBasePath $script:CurrentModule
        }
        else {
            $script:BackupBasePath
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
            $script:BackupIndex += [PSCustomObject]@{
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
                    $script:BackupIndex += [PSCustomObject]@{
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Add to tracking list (avoid duplicates)
    if ($script:NewlyCreatedKeys -notcontains $KeyPath) {
        $script:NewlyCreatedKeys += $KeyPath
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
        throw "Backup system not initialized. Call Initialize-BackupSystem first."
    }
    
    # Use ServiceName as BackupName if not provided
    if ([string]::IsNullOrEmpty($BackupName)) {
        $BackupName = $ServiceName
    }
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        # Get detailed service configuration
        $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        
        $backupData = [PSCustomObject]@{
            Name        = $service.Name
            DisplayName = $service.DisplayName
            Status      = $service.Status
            StartType   = $service.StartType
            StartMode   = $serviceConfig.StartMode
            PathName    = $serviceConfig.PathName
            Description = $serviceConfig.Description
        }
        
        # Save to JSON
        $safeBackupName = $BackupName -replace '[\\/:*?"<>|]', '_'
        
        # Save to current module folder if active, otherwise root
        $backupFolder = if ($script:CurrentModule) {
            Join-Path $script:BackupBasePath $script:CurrentModule
        }
        else {
            $script:BackupBasePath
        }
        
        $backupFile = Join-Path $backupFolder "$safeBackupName`_Service.json"
        $backupData | ConvertTo-Json | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        
        Write-Log -Level SUCCESS -Message "Service backup created: $BackupName ($ServiceName)" -Module "Rollback"
        
        # Add to backup index
        $script:BackupIndex += [PSCustomObject]@{
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
    
    if ([string]::IsNullOrEmpty($script:BackupBasePath)) {
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
        $backupFolder = if ($script:CurrentModule) {
            Join-Path $script:BackupBasePath $script:CurrentModule
        }
        else {
            $script:BackupBasePath
        }
        
        $backupFile = Join-Path $backupFolder "$safeBackupName`_Task.xml"
        $taskXml | Set-Content -Path $backupFile -Encoding UTF8 | Out-Null
        
        Write-Log -Level SUCCESS -Message "Scheduled task backup created: $BackupName" -Module "Rollback"
        
        # Add to backup index
        $script:BackupIndex += [PSCustomObject]@{
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
        if (-not $script:BackupBasePath) {
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
        $typeFolder = Join-Path $script:BackupBasePath $Type
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
        $script:BackupIndex += [PSCustomObject]@{
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
        [string]$Description = "NoID Privacy Pro - Before Hardening"
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
    
    return $script:BackupIndex
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
    $reversedIndex = $script:BackupIndex | Sort-Object -Property Timestamp -Descending
    
    foreach ($backup in $reversedIndex) {
        $success = Restore-FromBackup -BackupFile $backup.BackupFile -Type $backup.Type
        
        if (-not $success) {
            $allSucceeded = $false
        }
    }
    
    # Delete newly created registry keys (they didn't exist before)
    if ($script:NewlyCreatedKeys.Count -gt 0) {
        Write-Log -Level INFO -Message "Removing $($script:NewlyCreatedKeys.Count) newly created registry keys..." -Module "Rollback"
        
        # Sort in reverse order (deepest keys first) to avoid errors
        $sortedKeys = $script:NewlyCreatedKeys | Sort-Object -Property Length -Descending
        
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
    
    try {
        $manifest = Get-SessionManifest -SessionPath $SessionPath
        
        Write-Log -Level INFO -Message "Starting session restore: $($manifest.sessionId)" -Module "Rollback"
        Write-Log -Level INFO -Message "Session created: $($manifest.timestamp)" -Module "Rollback"
        Write-Log -Level INFO -Message "Total items: $($manifest.totalItems)" -Module "Rollback"
        
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
            
            $moduleBackupPath = Join-Path $SessionPath $moduleInfo.backupPath
            
            if (-not (Test-Path $moduleBackupPath)) {
                Write-Log -Level ERROR -Message "Module backup path not found: $moduleBackupPath" -Module "Rollback"
                $allSucceeded = $false
                continue
            }
            
            # Pre-restore cleanup: Clear active policies BEFORE restoring backups
            # This ensures hardened settings don't interfere with backup restore
            
            if ($moduleInfo.name -eq "SecurityBaseline") {
                Write-Log -Level INFO -Message "Clearing SecurityBaseline policies before restore..." -Module "Rollback"
                
                # STEP 1: Clear all local GPO settings to "Not Configured"
                # This deletes registry.pol files (official MS method)
                # All GPO settings will be reset to default "Not Configured" state
                $gpoClearResult = Clear-LocalGPO
                if (-not $gpoClearResult) {
                    Write-Log -Level WARNING -Message "Local GPO clear had errors - continuing" -Module "Rollback"
                }
                
                # STEP 1.5: Restore Registry Policies (GPO) from backup
                # This restores the Machine/User Registry.pol files
                $regPolBackup = Join-Path $moduleBackupPath "RegistryPolicies.json"
                if (Test-Path $regPolBackup) {
                    Write-Log -Level INFO -Message "Restoring Registry Policies (GPO) from backup..." -Module "Rollback"
                    
                    # Fail-Safe: Manually load function if missing (Module scope fix)
                    if (-not (Get-Command "Restore-RegistryPolicies" -ErrorAction SilentlyContinue)) {
                        $funcPath = Join-Path $PSScriptRoot "..\Modules\SecurityBaseline\Private\Restore-RegistryPolicies.ps1"
                        if (Test-Path $funcPath) { . $funcPath }
                    }

                    $regPolResult = Restore-RegistryPolicies -BackupPath $regPolBackup
                    if ($regPolResult.Success) {
                        Write-Log -Level SUCCESS -Message "Registry Policies restored ($($regPolResult.ItemsRestored) items)" -Module "Rollback"
                    }
                    else {
                        Write-Log -Level WARNING -Message "Registry Policies restore had errors: $($regPolResult.Errors -join '; ')" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No RegistryPolicies.json backup found - skipping GPO restore" -Module "Rollback"
                }
                
                # STEP 2: Restore Audit Policies from pre-hardening backup (1:1 restore)
                $auditBackupFile = Join-Path $moduleBackupPath "AuditPolicies.csv"
                if (Test-Path $auditBackupFile) {
                    Write-Log -Level INFO -Message "Found audit policy backup" -Module "Rollback"
                    Write-Log -Level INFO -Message "Restoring audit policies from backup..." -Module "Rollback"
                    
                    try {
                        $auditRestoreProcess = Start-Process -FilePath "auditpol.exe" `
                            -ArgumentList "/restore", "/file:`"$auditBackupFile`"" `
                            -Wait `
                            -NoNewWindow `
                            -PassThru
                        
                        if ($auditRestoreProcess.ExitCode -eq 0) {
                            Write-Log -Level SUCCESS -Message "Audit policies restored from pre-hardening backup" -Module "Rollback"
                        }
                        else {
                            Write-Log -Level WARNING -Message "Audit policy restore had errors (Exit: $($auditRestoreProcess.ExitCode)) - continuing" -Module "Rollback"
                        }
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Audit policy restore failed: $_ - continuing" -Module "Rollback"
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No pre-hardening audit policy backup found - skipping audit restore (keeping current state)" -Module "Rollback"
                }
                
                # Fail-Safe for Restore-SecurityTemplate (Module Scope Fix)
                if (-not (Get-Command "Restore-SecurityTemplate" -ErrorAction SilentlyContinue)) {
                    $funcPath = Join-Path $PSScriptRoot "..\Modules\SecurityBaseline\Private\Restore-SecurityTemplate.ps1"
                    if (Test-Path $funcPath) { . $funcPath }
                }

                # STEP 3: Restore Security Template from rollback template (1:1 restore)
                # This restores only the settings that were changed by standalone delta
                $rollbackTemplateFile = Join-Path $moduleBackupPath "StandaloneDelta_Rollback.inf"
                if (Test-Path $rollbackTemplateFile) {
                    Write-Log -Level INFO -Message "Found rollback template for standalone delta" -Module "Rollback"
                    $secTemplatResult = Restore-SecurityTemplate -BackupPath $rollbackTemplateFile
                }
                else {
                    Write-Log -Level INFO -Message "No rollback template found - using full security policy backup (expected)" -Module "Rollback"
                    $secPolicyBackupFile = Join-Path $moduleBackupPath "SecurityTemplate.inf"
                    if (Test-Path $secPolicyBackupFile) {
                        Write-Log -Level INFO -Message "Found security template backup" -Module "Rollback"
                        $secTemplatResult = Restore-SecurityTemplate -BackupPath $secPolicyBackupFile
                    }
                    else {
                        Write-Log -Level WARNING -Message "No security policy backups found - skipping secedit restore" -Module "Rollback"
                        $secTemplatResult = $true
                    }
                }
                
                if (-not $secTemplatResult) {
                    Write-Log -Level WARNING -Message "Security template restore had errors - continuing" -Module "Rollback"
                }
                
                # STEP 4: Restore Xbox Task if it was disabled
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
                
                # STEP 5: Final GPO refresh
                # Force group policy update to apply all restored settings
            }
            
            if ($moduleInfo.name -eq "ASR") {
                Write-Log -Level INFO -Message "Clearing ASR configuration before restore..." -Module "Rollback"
                
                # Clear all ASR rules via Windows Defender
                $asrClearResult = Clear-ASRRules
                if (-not $asrClearResult) {
                    Write-Log -Level WARNING -Message "ASR rules clear had errors - continuing" -Module "Rollback"
                }
                
                # CRITICAL: Restore ASR via Set-MpPreference, NOT registry
                # Registry-only restore doesn't work after Clear-ASRRules
                $asrMpPrefBackup = Get-ChildItem -Path $moduleBackupPath -Filter "ASR_ActiveConfiguration.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                
                if ($asrMpPrefBackup) {
                    Write-Log -Level INFO -Message "Restoring ASR rules via Set-MpPreference (proper method)..." -Module "Rollback"
                    
                    try {
                        $asrBackupData = Get-Content $asrMpPrefBackup.FullName -Raw | ConvertFrom-Json
                        
                        # Filter for active rules only (Action 1=Block, 2=Audit)
                        # If backup contains rules with Action 0 (Off), we don't need to apply them
                        # because Clear-ASRRules already reset everything to default.
                        # Applying Action 0 might unexpectedly trigger Defender defaults.
                        $activeRulesToRestore = @()
                        if ($asrBackupData.Rules) {
                            $activeRulesToRestore = $asrBackupData.Rules | Where-Object { $_.Action -ne 0 }
                        }

                        if ($activeRulesToRestore.Count -gt 0) {
                            $ruleIds = $activeRulesToRestore | ForEach-Object { $_.GUID }
                            $ruleActions = $activeRulesToRestore | ForEach-Object { $_.Action }
                            
                            Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds `
                                            -AttackSurfaceReductionRules_Actions $ruleActions `
                                            -ErrorAction Stop
                            
                            Write-Log -Level SUCCESS -Message "ASR rules restored via Set-MpPreference ($($activeRulesToRestore.Count) active rules)" -Module "Rollback"
                        }
                        else {
                            # System had 0 active ASR rules before hardening (Clean State)
                            # Clear-ASRRules already did the job.
                            Write-Log -Level SUCCESS -Message "ASR backup contains 0 active rules. System kept at clean state (Clear-ASRRules)." -Module "Rollback"
                        }
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restore ASR via Set-MpPreference: $_" -Module "Rollback"
                        $allSucceeded = $false
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "No ASR_ActiveConfiguration.json backup found - ASR rules will remain cleared" -Module "Rollback"
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
                        if ($moduleInfo.name -eq "AdvancedSecurity" -and ($regFile.Name -match "RDP_Settings" -or $regFile.Name -match "WPAD_Settings")) { $isProtectedKey = $true }

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

            # Special handling for Privacy: Restore removed apps via winget (if metadata exists)
            if ($moduleInfo.name -eq "Privacy") {
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
                
                # Find all AdvancedSecurity backup files (RiskyPorts, PowerShellV2, AdminShares)
                $advSecBackups = Get-ChildItem -Path $moduleBackupPath -Filter "*_*.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "_Service.json" }
                
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
            }
            
            Write-Log -Level SUCCESS -Message "Completed restore for module: $($moduleInfo.name)" -Module "Rollback"
        }
        
        if ($allSucceeded) {
            Write-Log -Level SUCCESS -Message "Session restore completed successfully" -Module "Rollback"
        }
        else {
            Write-Log -Level WARNING -Message "Session restore completed with some failures" -Module "Rollback"
        }
        
        # Apply Pre-Framework Snapshot if exists (for multi-module shared resource conflicts)
        # This must happen AFTER all module restores to act as final override
        $preFrameworkSnapshotPath = Join-Path $SessionPath "PreFramework_Snapshot.json"
        if (Test-Path $preFrameworkSnapshotPath) {
            try {
                $snapshot = Get-Content $preFrameworkSnapshotPath -Raw | ConvertFrom-Json
                
                # Check if snapshot applies to any of the restored modules
                $restoredModuleNames = $manifest.modules.name
                $snapshotAppliesToModules = $snapshot.AppliesTo
                
                $shouldApplySnapshot = $false
                foreach ($targetModule in $snapshotAppliesToModules) {
                    if ($ModuleNames) {
                        # Selective restore - only apply if target module was explicitly restored
                        if ($ModuleNames -contains $targetModule) {
                            $shouldApplySnapshot = $true
                            break
                        }
                    }
                    else {
                        # Full restore - only apply if target module was in original session
                        if ($restoredModuleNames -contains $targetModule) {
                            $shouldApplySnapshot = $true
                            break
                        }
                    }
                }
                
                if ($shouldApplySnapshot) {
                    Write-Log -Level INFO -Message "Applying Pre-Framework ASR snapshot (original system state before any module applied)" -Module "Rollback"
                    
                    # Clear all ASR rules first
                    Write-Log -Level INFO -Message "Clearing all ASR rules before applying Pre-Framework snapshot..." -Module "Rollback"
                    $allRuleGuids = @(
                        "56a863a9-875e-4185-98a7-b882c64b5ce5", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
                        "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
                        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "01443614-cd74-433a-b99e-2ecdc07bfc25",
                        "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "d3e037e1-3eb8-44c8-a917-57927947596d",
                        "3b576869-a4ec-4529-8536-b80a7769e899", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
                        "26190899-1602-49e8-8b27-eb1d0a1ce869", "e6db77e5-3df2-4cf1-b95a-636979351e5b",
                        "d1e49aac-8f56-4280-b9ba-993a6d77406c", "33ddedf1-c6e0-47cb-833e-de6133960387",
                        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
                        "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
                        "c1db55ab-c21a-4637-bb3f-a12568109d35"
                    )
                    
                    foreach ($guid in $allRuleGuids) {
                        Set-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions 0 -ErrorAction SilentlyContinue
                    }
                    
                    # Apply snapshot rules
                    $snapshotRules = $snapshot.ASR
                    if ($snapshotRules.RuleIds -and $snapshotRules.RuleIds.Count -gt 0) {
                         # Only restore ACTIVE rules (Action != 0) from snapshot
                         $activeIndices = @()
                         for ($i = 0; $i -lt $snapshotRules.RuleIds.Count; $i++) {
                            if ($snapshotRules.RuleActions[$i] -ne 0) {
                                $activeIndices += $i
                            }
                         }
                         
                         if ($activeIndices.Count -gt 0) {
                             $finalIds = @()
                             $finalActions = @()
                             foreach ($idx in $activeIndices) {
                                 $finalIds += $snapshotRules.RuleIds[$idx]
                                 $finalActions += $snapshotRules.RuleActions[$idx]
                             }
                             
                             Set-MpPreference -AttackSurfaceReductionRules_Ids $finalIds -AttackSurfaceReductionRules_Actions $finalActions -ErrorAction Stop
                             Write-Log -Level SUCCESS -Message "Restored $($activeIndices.Count) active ASR rules from Pre-Framework snapshot" -Module "Rollback"
                         }
                         else {
                             Write-Log -Level SUCCESS -Message "Pre-Framework snapshot contained 0 active rules - System left clean (0/19)" -Module "Rollback"
                         }
                    }
                    else {
                        Write-Log -Level SUCCESS -Message "Pre-Framework snapshot empty - System left clean (0/19)" -Module "Rollback"
                    }
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Failed to apply Pre-Framework snapshot: $_" -Module "Rollback"
            }
        }
        
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
        
        return $allSucceeded
    }
    catch {
        Write-ErrorLog -Message "Failed to restore hardening session: $SessionName" -Module "Rollback" -ErrorRecord $_
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
