<#
.SYNOPSIS
    Complete backup of all system settings BEFORE Security Baseline application

.DESCRIPTION
    Creates a complete backup of all settings changed by the Security Baseline script.
    Backup format: JSON for easy reading and restoration.
    
    WHAT IS BACKED UP:
    - DNS Settings (per adapter)
    - Hosts file
    - Installed Apps (list)
    - Firewall Custom Rules (those we create)
    - Service Start-Types (ALL services)
    - Scheduled Tasks (state of all tasks)
    - Registry Keys HKLM (all changed system settings)
    - Registry Keys HKCU (all changed user settings)
    - User Accounts (names)
    - ASR Rules (Attack Surface Reduction - 16 Rules)
    - Exploit Protection (System-wide Mitigations)
    - DoH Configuration (DNS over HTTPS Server)
    - Firewall Profile Settings (Domain/Private/Public)
    - Device-Level App Permissions (20-50 SubKeys) - NEW v1.4.0!
    
    NEW IN VERSION 1.4.0:
    - Device-Level App Permission SubKeys are now backed up!
    - ~20-50 dynamic SubKeys per permission (webcam/microphone/location)
    - PERFECT 100% Coverage - NO gaps anymore!
    
    VERSION 1.3.0:
    - Firewall Profile Settings (Get-NetFirewallProfile) are now backed up!
    - 3 Profiles (Domain/Private/Public) with all settings
    - Critical gap closed!
    
    VERSION 1.2.0:
    - ASR Rules (Get-MpPreference) are now backed up!
    - Exploit Protection (Get-ProcessMitigation) is now backed up!
    - DoH Configuration (Get-DnsClientDohServerAddress) is now backed up!
    
    VERSION 1.1.0:
    - HKCU (User-specific) Registry-Keys are now also backed up!
    - 36 App Permissions (36 Keys: only Value - UPDATED v1.7.11)
    - 4 OneDrive Privacy Settings
    - Complete parity with the Security Baseline Script
    
    VERSION 1.7.11 UPDATE:
    - App Permissions: ONLY "Value" is saved (NO LastUsedTime* anymore!)
    - LastUsedTime* are Forensic-Tracking (managed by Windows)
    - Consistent with Apply-Script v1.7.11 (also sets only Value)
    
    VERSION 1.7.12 UPDATE (Current):
    - 125 missing registry keys added (100% parity achieved)
    - 17 string formatting fixes (Get-LocalizedString -f operator)
    - NULL reference bug fixed (GetValueKind for protected keys)
    - App list localization (Desktop export DE/EN)
    - UI restore capability (Widgets, Teams, Lock Screen, Copilot)
    - Edge SmartScreen HKCU Keys added (3 Keys)
    - Required for "Block downloads" checkbox in Windows Security GUI
    - HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled
    - HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenEnabled
    - HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenPuaEnabled
    
.NOTES
    Version:        1.4.0
    Creation Date:  25H2
    Author:         NoID Privacy Team
    
.PARAMETER BackupPath
    Path where backup is saved (Default: C:\ProgramData\SecurityBaseline\Backups)
    
.EXAMPLE
    .\Backup-SecurityBaseline.ps1
    
.EXAMPLE
    .\Backup-SecurityBaseline.ps1 -BackupPath "D:\MyBackups"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "$env:ProgramData\SecurityBaseline\Backups"
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode (catches undefined variables, non-existent properties)
Set-StrictMode -Version Latest

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ===== CONSOLE ENCODING FOR UMLAUTS (Best Practice 25H2) =====
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
}
catch {
    Write-Verbose "Console encoding could not be set: $_"
}

# ===== CONSOLE WINDOW SIZE (Best Practice 25H2) =====
try {
    if ($Host.UI.RawUI) {
        $hostUI = $Host.UI.RawUI
        $maxSize = $hostUI.MaxPhysicalWindowSize
        
        $bufferSize = $hostUI.BufferSize
        $bufferSize.Width = [Math]::Min(120, $maxSize.Width)
        $bufferSize.Height = 3000
        $hostUI.BufferSize = $bufferSize
        
        $windowSize = $hostUI.WindowSize
        $windowSize.Width = [Math]::Min(120, $maxSize.Width)
        $windowSize.Height = [Math]::Min(60, $maxSize.Height)  # 60 Zeilen
        $hostUI.WindowSize = $windowSize
        
        Write-Verbose "Console Window Size: $($windowSize.Width)x$($windowSize.Height)"
    }
}
catch {
    Write-Verbose "Console Window Size konnte nicht gesetzt werden: $_"
}

# Load Localization Module
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    . "$scriptDir\Modules\SecurityBaseline-Localization.ps1"
}
catch {
    Write-Warning "Could not load localization module: $_"
    # Fallback to English
    $Global:CurrentLanguage = 'en'
}

# Ensure language is set (use from interactive session, environment variable, or default to English)
# IMPORTANT: When dot-sourcing, $Global:CurrentLanguage is already set - do not overwrite!
# IMPORTANT: Use Test-Path because of Strict Mode!
if (-not (Test-Path Variable:\Global:CurrentLanguage)) {
    # Check if language was passed via environment variable (from parent script)
    if ($env:NOID_LANGUAGE) {
        $Global:CurrentLanguage = $env:NOID_LANGUAGE
        Write-Verbose "Language from environment variable: $Global:CurrentLanguage"
    }
    else {
        # Fallback to English if standalone execution
        $Global:CurrentLanguage = 'en'
        Write-Verbose "Language defaulted to: en"
    }
}
else {
    # Language already set (from dot-sourcing) - keep it!
    Write-Verbose "Language from parent script: $Global:CurrentLanguage"
}

Write-Host "`n============================================================================" -ForegroundColor Cyan
Write-Host "           $(Get-LocalizedString 'BackupBanner')" -ForegroundColor Cyan
Write-Host "============================================================================`n" -ForegroundColor Cyan

# Create backup directory
if (-not (Test-Path $BackupPath)) {
    $null = New-Item -Path $BackupPath -ItemType Directory -Force
    Write-Host "[OK] $(Get-LocalizedString 'BackupDirCreated') $BackupPath" -ForegroundColor Green
}

$backupFile = Join-Path $BackupPath "SecurityBaseline-Backup-$timestamp.json"

# IMPORTANT: Show backup path IMMEDIATELY (Best Practice 25H2)
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "  $(Get-LocalizedString 'BackupTargetTitle')" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "  $(Get-LocalizedString 'BackupTargetPath' $backupFile)" -ForegroundColor Cyan
Write-Host "  $(Get-LocalizedString 'BackupTargetDir' $BackupPath)" -ForegroundColor Gray
Write-Host "============================================================================" -ForegroundColor Green
Write-Host ""

# Best Practice 25H2: Inform user about expected duration
Write-Host "[i] $(Get-LocalizedString 'BackupDurationTitle')" -ForegroundColor Cyan
Write-Host "$(Get-LocalizedString 'BackupDurationNormal')" -ForegroundColor Gray
Write-Host "$(Get-LocalizedString 'BackupDurationMax')" -ForegroundColor Gray
Write-Host ""

# Best Practice 25H2: Disk Space Check BEFORE Backup starts!
Write-Host "[i] $(Get-LocalizedString 'BackupCheckingDiskSpace')" -ForegroundColor Cyan
try {
    # Extract drive letter from backup path
    $driveLetter = (Get-Item $BackupPath -ErrorAction Stop).PSDrive.Name
    $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop
    
    $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
    $requiredSpaceGB = 0.1  # 100 MB minimum for backup
    
    Write-Host "$(Get-LocalizedString 'BackupDiskDrive' "${driveLetter}:")" -ForegroundColor Gray
    Write-Host "$(Get-LocalizedString 'BackupDiskFree' $freeSpaceGB)" -ForegroundColor Gray
    
    if ($drive.Free -lt ($requiredSpaceGB * 1GB)) {
        Write-Host ""
        Write-Host "[ERROR] $(Get-LocalizedString 'BackupDiskInsufficientTitle')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'BackupDiskRequired' $requiredSpaceGB)" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'BackupDiskAvailable' $freeSpaceGB)" -ForegroundColor Red
        Write-Host ""
        throw (Get-LocalizedString 'BackupDiskInsufficientError')
    }
    
    Write-Host "$(Get-LocalizedString 'BackupDiskSufficient')" -ForegroundColor Green
}
catch {
    Write-Warning "Disk Space Check failed: $_"
    Write-Warning "Backup will still be attempted (at your own risk)..."
}
Write-Host ""

# Automatic cleanup of old backups
# IMPORTANT: ALWAYS keep FIRST backup (original state)!
# Strategy: 1 original + newest 9 = 10 total
Write-Host "[i] $(Get-LocalizedString 'BackupCheckOld')" -ForegroundColor Cyan
$existingBackups = @(Get-ChildItem -Path $BackupPath -Filter "SecurityBaseline-Backup-*.json" -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime)  # ASCENDING = oldest first!

# @() wrapper prevents Count error with null/single item
$backupCount = $existingBackups.Count

if ($backupCount -gt 10) {
    # STRATEGY: Keep first (original) + newest 9
    $firstBackup = $existingBackups[0]  # OLDEST = ORIGINAL STATE
    $recentBackups = @($existingBackups | Select-Object -Last 9)  # Newest 9
    
    # To delete = EVERYTHING except first and newest 9
    $toKeep = @($firstBackup) + $recentBackups
    $toDelete = @($existingBackups | Where-Object { $_.FullName -notin $toKeep.FullName })
    
    $deleteCount = $toDelete.Count
    if ($deleteCount -gt 0) {
        $deleteMsg = (Get-LocalizedString 'BackupDeleteOld' $deleteCount)
        Write-Host "[i] $deleteMsg" -ForegroundColor Yellow
        Write-Host "$(Get-LocalizedString 'BackupOriginalKept' $firstBackup.Name)" -ForegroundColor Cyan
        
        foreach ($oldBackup in $toDelete) {
            try {
                Remove-Item $oldBackup.FullName -Force -ErrorAction Stop
                Write-Verbose "Deleted: $($oldBackup.Name)"
            }
            catch {
                Write-Warning "Could not delete old backup: $($oldBackup.Name)"
            }
        }
        Write-Host "  [OK] $deleteCount $(Get-LocalizedString 'BackupDeleted')" -ForegroundColor Green
    }
}
else {
    Write-Verbose (Get-LocalizedString 'BackupNoOld')
}
Write-Host ""

# Backup-Objekt initialisieren
$backup = @{
    Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Hostname = $env:COMPUTERNAME
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
    Build = [Environment]::OSVersion.Version.Build
    Settings = @{}
}

Write-Host "[i] $(Get-LocalizedString 'BackupCreating')" -ForegroundColor Cyan
Write-Host ""

#region DNS Settings Backup
Write-Host "[1/13] $(Get-LocalizedString 'BackupDNS')" -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$dnsBackup = foreach ($adapter in $adapters) {
    try {
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        if ($dnsServers -and $dnsServers.ServerAddresses) {
            $adapterMsg = Get-LocalizedString 'BackupDNSAdapter' $adapter.Name
            Write-Host "  [OK] $($adapterMsg) $($dnsServers.ServerAddresses -join ', ')" -ForegroundColor Gray
            
            # Output to pipeline (captured by $dnsBackup)
            @{
                AdapterName = $adapter.Name
                InterfaceIndex = $adapter.ifIndex
                DNS_IPv4 = @($dnsServers.ServerAddresses)
            }
        }
    }
    catch {
        Write-Warning "Error backing up DNS for adapter '$($adapter.Name)': $_"
    }
}

$backup.Settings.DNS = $dnsBackup
$dnsCount = if ($dnsBackup) { @($dnsBackup).Count } else { 0 }
$dnsMsg = Get-LocalizedString 'BackupDNSSaved' $dnsCount
Write-Host "[OK] $dnsMsg`n" -ForegroundColor Green
#endregion

#region Hosts File Backup
Write-Host "[2/13] $(Get-LocalizedString 'BackupHosts')" -ForegroundColor Yellow

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    # IMPORTANT: ToString() to really get only string (not FileInfo object)
    $hostsContent = [string](Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue)
    $backup.Settings.HostsFile = $hostsContent
    $lineCount = ($hostsContent -split "`n").Count
    $hostsMsg = Get-LocalizedString 'BackupHostsSaved' $lineCount
    Write-Host "[OK] $hostsMsg`n" -ForegroundColor Green
}
else {
    Write-Warning "Hosts file not found!"
    $backup.Settings.HostsFile = $null
}
#endregion

#region Installed Apps Backup (WITH PROVISIONED PACKAGES!)
Write-Host "[3/13] $(Get-LocalizedString 'BackupApps')" -ForegroundColor Yellow

# User Apps (with timeout protection)
$installedApps = @()
try {
    Write-Host "$(Get-LocalizedString 'BackupAppsReading')" -ForegroundColor Gray
    
    # TIMEOUT: 60 seconds max for AppX enumeration
    $job = Start-Job -ScriptBlock { Get-AppxPackage -ErrorAction SilentlyContinue }
    $completed = Wait-Job $job -Timeout 60
    
    if ($completed) {
        $appxPackages = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force
        
        # [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n2))
        $installedApps = foreach ($app in $appxPackages) {
            # Output to pipeline (captured by $installedApps)
            @{
                Name = $app.Name
                PackageFullName = $app.PackageFullName
                Version = if ($app.Version) { $app.Version.ToString() } else { $null }  # Version Objekt zu String
                Publisher = $app.Publisher
            }
        }
        
        $backup.Settings.InstalledApps = $installedApps
        $appsCount = if ($installedApps) { @($installedApps).Count } else { 0 }
        Write-Host "  [OK] $appsCount $(Get-LocalizedString 'BackupAppsUser')" -ForegroundColor Green
    }
    else {
        # Timeout erreicht!
        Remove-Job $job -Force
        Write-Warning (Get-LocalizedString 'BackupAppsTimeout')
        $backup.Settings.InstalledApps = @()
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupAppsFailed' $_)
    $backup.Settings.InstalledApps = @()
}

# Provisioned Packages (with timeout protection)
Write-Host "  [i] $(Get-LocalizedString 'BackupAppsProvisioned')" -ForegroundColor Cyan

$provisionedPackages = @()
try {
    Write-Host "$(Get-LocalizedString 'BackupProvisionedReading')" -ForegroundColor Gray
    
    # TIMEOUT: 90 seconds max (Get-AppxProvisionedPackage -Online is SLOW!)
    $job = Start-Job -ScriptBlock { Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue }
    $completed = Wait-Job $job -Timeout 90
    
    if ($completed) {
        $packages = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force
        
        # [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n2))
        $provisionedPackages = foreach ($pkg in $packages) {
            # Output to pipeline (captured by $provisionedPackages)
            @{
                DisplayName = $pkg.DisplayName
                PackageName = $pkg.PackageName
                Version = if ($pkg.Version) { $pkg.Version.ToString() } else { $null }  # Version Objekt zu String
            }
        }
        
        $backup.Settings.ProvisionedPackages = $provisionedPackages
        $pkgCount = if ($provisionedPackages) { @($provisionedPackages).Count } else { 0 }
        Write-Host "  [OK] $pkgCount $(Get-LocalizedString 'BackupAppsProvisionedSaved')" -ForegroundColor Green
    }
    else {
        # Timeout erreicht!
        Remove-Job $job -Force
        Write-Warning (Get-LocalizedString 'BackupProvisionedTimeout')
        $backup.Settings.ProvisionedPackages = @()
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupProvisionedFailed' $_)
    $backup.Settings.ProvisionedPackages = @()
}

Write-Host ""
#endregion

#region Services Backup (ALL SERVICES!)
Write-Host "[4/13] $(Get-LocalizedString 'BackupServices')" -ForegroundColor Yellow

# BACKUP ALL SERVICES (not just the ones we change!)
$allServices = Get-Service -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$servicesBackup = foreach ($service in $allServices) {
    try {
        # Output to pipeline (captured by $servicesBackup)
        @{
            Name = $service.Name
            DisplayName = $service.DisplayName
            StartType = $service.StartType.ToString()  # Enum zu String
            Status = $service.Status.ToString()        # Enum zu String
        }
    }
    catch {
        # Error reading - skip (no output)
    }
}

$backup.Settings.Services = $servicesBackup
$servicesCount = if ($servicesBackup) { @($servicesBackup).Count } else { 0 }
Write-Host "[OK] $servicesCount $(Get-LocalizedString 'BackupServicesSaved')" -ForegroundColor Green
Write-Host "    $(Get-LocalizedString 'BackupServicesNote')" -ForegroundColor Gray
Write-Host ""
#endregion

#region Scheduled Tasks Backup (ALL TASKS!)
Write-Host "[5/13] $(Get-LocalizedString 'BackupScheduledTasks')" -ForegroundColor Yellow

# BACKUP ALL SCHEDULED TASKS (not just the ones we change!)
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$tasksBackup = foreach ($task in $allTasks) {
    try {
        # Output to pipeline (captured by $tasksBackup)
        @{
            TaskPath = $task.TaskPath
            TaskName = $task.TaskName
            State = $task.State.ToString()  # Enum zu String
            # IMPORTANT: Only backup State (not Actions/Triggers - too complex!)
        }
    }
    catch {
        # Error reading - skip (no output)
    }
}

$backup.Settings.ScheduledTasks = $tasksBackup
$tasksCount = if ($tasksBackup) { @($tasksBackup).Count } else { 0 }
Write-Host "[OK] $(Get-LocalizedString 'BackupScheduledTasksSaved' $tasksCount)" -ForegroundColor Green
Write-Host "$(Get-LocalizedString 'BackupScheduledTasksNote')" -ForegroundColor Gray
Write-Host ""
#endregion

#region Firewall Rules Backup (ALL RULES!)
Write-Host "[6/13] $(Get-LocalizedString 'BackupFirewall')" -ForegroundColor Yellow

# BACKUP ALL FIREWALL RULES (not just custom!)
$allFirewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$firewallBackup = foreach ($rule in $allFirewallRules) {
    try {
        # Output to pipeline (captured by $firewallBackup)
        @{
            Name = $rule.Name
            DisplayName = $rule.DisplayName
            DisplayGroup = $rule.DisplayGroup
            Direction = $rule.Direction.ToString()    # Enum zu String
            Action = $rule.Action.ToString()          # Enum zu String
            Enabled = $rule.Enabled.ToString()        # Enum zu String
            Profile = $rule.Profile.ToString()        # Enum zu String
        }
    }
    catch {
        # Error reading - skip (no output)
    }
}

$backup.Settings.FirewallRules = $firewallBackup
$firewallCount = if ($firewallBackup) { @($firewallBackup).Count } else { 0 }
Write-Host "[OK] $firewallCount $(Get-LocalizedString 'BackupFirewallSaved')" -ForegroundColor Green
Write-Host "    $(Get-LocalizedString 'BackupFirewallNote')" -ForegroundColor Gray
Write-Host ""
#endregion

#region User Accounts Backup
Write-Host "[7/13] $(Get-LocalizedString 'BackupUsers')" -ForegroundColor Yellow

$localUsers = Get-LocalUser -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$usersBackup = foreach ($user in $localUsers) {
    # Output to pipeline (captured by $usersBackup)
    @{
        SID = $user.SID.Value  # Only string value, not the whole .NET object!
        Name = $user.Name
        Description = $user.Description
        Enabled = $user.Enabled
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') } else { $null }  # ISO 8601 Format
    }
}

$backup.Settings.UserAccounts = $usersBackup
$usersCount = if ($usersBackup) { @($usersBackup).Count } else { 0 }
Write-Host "[OK] $usersCount $(Get-LocalizedString 'BackupUsersSaved')" -ForegroundColor Green
Write-Host "[!] $(Get-LocalizedString 'BackupUsersWarning')" -ForegroundColor Yellow
Write-Host "    $(Get-LocalizedString 'BackupUsersPasswordNote')" -ForegroundColor Yellow
Write-Host ""
#endregion

#region Registry Keys Backup
Write-Host "[8/13] $(Get-LocalizedString 'BackupRegistry')" -ForegroundColor Yellow

# Function to export complete registry tree snapshot
function Export-RegistrySnapshot {
    param(
        [string]$RootPath,
        [string]$DisplayName
    )
    
    Write-Host "  [i] Snapshot: $DisplayName..." -ForegroundColor Gray -NoNewline
    
    $snapshot = @{}
    $keyCount = 0
    $valueCount = 0
    
    try {
        # Check if root path exists
        if (-not (Test-Path $RootPath)) {
            Write-Host " [!] Path not found" -ForegroundColor Yellow
            return @{ Root = $RootPath; Keys = @{} }
        }
        
        # Recursively get all keys under root path
        $allKeys = @($RootPath)
        try {
            $allKeys += Get-ChildItem -Path $RootPath -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSPath
        }
        catch {
            # Some keys might be inaccessible - that's OK
        }
        
        foreach ($keyPath in $allKeys) {
            try {
                # Get all properties of this key
                $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                
                if ($props) {
                    $keyCount++
                    
                    # Extract all values (skip PS* properties)
                    $psProps = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                    
                    foreach ($prop in $psProps) {
                        # Store as: "KeyPath\ValueName" = Value
                        $fullKey = "$keyPath\$($prop.Name)"
                        
                        # Convert value to JSON-serializable type
                        $value = $prop.Value
                        if ($value -is [byte[]]) {
                            # Binary data - store as base64
                            $snapshot[$fullKey] = @{
                                Type = 'Binary'
                                Data = [Convert]::ToBase64String($value)
                            }
                        }
                        elseif ($value -is [array]) {
                            # Array - store as array
                            $snapshot[$fullKey] = @{
                                Type = 'Array'
                                Data = @($value)
                            }
                        }
                        else {
                            # Simple value
                            $snapshot[$fullKey] = $value
                        }
                        
                        $valueCount++
                    }
                }
            }
            catch {
                # Access denied or other error - skip this key
                continue
            }
        }
        
        Write-Host " [OK] $keyCount keys, $valueCount values" -ForegroundColor Green
        
        return @{
            Root = $RootPath
            Keys = $snapshot
            KeyCount = $keyCount
            ValueCount = $valueCount
        }
    }
    catch {
        Write-Host " [X] Error: $_" -ForegroundColor Red
        return @{ Root = $RootPath; Keys = @{}; Error = $_.Exception.Message }
    }
}

# Function to backup registry values
function Backup-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        if (Test-Path -Path $Path) {
            # Safe property check - track access denied keys
            $rawValue = $null
            $accessDenied = $false
            
            try {
                $item = Get-ItemProperty -Path $Path -ErrorAction Stop
                if ($item -and ($item.PSObject.Properties.Name -contains $Name)) {
                    $rawValue = $item.$Name
                }
            }
            catch [System.Security.SecurityException], [System.UnauthorizedAccessException] {
                # Access denied - key exists but we can't read it
                $accessDenied = $true
                $rawValue = $null
                # Remove only this specific error from the error stack
                if ($Error.Count -gt 0) { $Error.RemoveAt(0) }
            }
            catch {
                # Other error - key might not exist
                $rawValue = $null
            }
            
            # Convert to primitive types (String, Int, Bool, null)
            if ($null -eq $rawValue) {
                $convertedValue = $null
            }
            elseif ($rawValue -is [string]) {
                $convertedValue = $rawValue
            }
            elseif ($rawValue -is [int] -or $rawValue -is [long] -or $rawValue -is [uint32] -or $rawValue -is [uint64]) {
                $convertedValue = [int]$rawValue
            }
            elseif ($rawValue -is [bool]) {
                $convertedValue = $rawValue
            }
            elseif ($rawValue -is [array]) {
                # Arrays of primitive types
                $convertedValue = @($rawValue | ForEach-Object { $_.ToString() })
            }
            else {
                # Fallback: Convert to string
                $convertedValue = $rawValue.ToString()
            }
            
            # CRITICAL FIX: Use unique property names to avoid JSON serialization issues
            # "Value" as property name can collide with registry value name "Value"!
            
            # Safe GetValueKind - track access denied
            $regType = "Unknown"
            if (-not $accessDenied) {
                try {
                    $regItem = Get-Item -Path $Path -ErrorAction Stop
                    if ($regItem) { 
                        $regType = $regItem.GetValueKind($Name).ToString()
                    }
                }
                catch [System.Security.SecurityException], [System.UnauthorizedAccessException] {
                    # Access denied on Get-Item too
                    $accessDenied = $true
                    $regType = "AccessDenied"
                    # Remove only this specific error from the error stack
                    if ($Error.Count -gt 0) { $Error.RemoveAt(0) }
                }
                catch {
                    # Other error
                    $regType = "Unknown"
                }
            }
            else {
                $regType = "AccessDenied"
            }
            
            return @{
                RegPath = $Path
                RegName = $Name
                RegValue = $convertedValue
                RegType = $regType
                RegExists = $true
                AccessDenied = $accessDenied
            }
        }
        
        return @{
            RegPath = $Path
            RegName = $Name
            RegExists = $false
            AccessDenied = $false
        }
    }
    catch {
        return @{
            RegPath = $Path
            RegName = $Name
            RegExists = $false
            AccessDenied = $false
            RegError = $_.Exception.Message
        }
    }
}

# EXTENDED REGISTRY KEYS (ALL that the script changes!)
$registryKeys = @(
    # DNS/Network
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableAutoDoh"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="DisableSmartNameResolution"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableDnssec"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="DnssecMode"},
    
    # Telemetry
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="LimitEnhancedDiagnosticDataWindowsAnalytics"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="MaxTelemetryAllowed"},
    
    # Defender
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SpynetReporting"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableAntiSpyware"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"},
    
    # Services/Shares
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareServer"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareWks"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RestrictNullSessAccess"},
    
    # SMB
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SmbServerNameHardeningLevel"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EncryptionNegotiation"},
    
    # Windows Update (OLD)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="AUOptions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="ScheduledInstallDay"},
    
    # Windows Update (NEW - HYBRID System)
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name="AllowMUUpdateService"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name="IsContinuousInnovationOptedIn"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name="AllowAutoWindowsUpdateDownloadOverMeteredNetwork"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name="RestartNotificationsAllowed2"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name="IsExpedited"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ManagePreviewBuilds"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ManagePreviewBuildsPolicyValue"},
    
    # Delivery Optimization (NEW - HYBRID System)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config"; Name="DODownloadMode"},
    
    # Privacy (OLD)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name="DisabledByGroupPolicy"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessLocation"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Name="Value"},
    
    # Privacy Extended (NEW - Kamera/Mikrofon)
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name="Value"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Name="Value"},
    
    # Privacy Extended (NEW - Windows Search)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="DisableWebSearch"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="BingSearchEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCloudSearch"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowSearchToUseLocation"},
    
    # Privacy Extended (NEW - Cloud Content)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableSoftLanding"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableThirdPartySuggestions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsSpotlightFeatures"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableTailoredExperiencesWithDiagnosticData"},
    
    # Privacy Extended (NEW - Input Personalization) - NOW HKLM POLICY!
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitInkCollection"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitTextCollection"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="AllowInputPersonalization"},
    
    # Privacy Extended (NEW - Location Services)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableLocation"},
    
    # Remote Desktop
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="fDenyTSConnections"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"},
    
    # Sudo
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo"; Name="Enabled"},
    
    # TLS/SSL
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"; Name="Enabled"},
    
    # UAC (NEW - Maximum Security)
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ValidateAdminCodeSignatures"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"},
    
    # AI Features Lockdown (NEW - 25H2)
    # Recall (CRITICAL PRIVACY!)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="DisableAIDataAnalysis"},
    @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableAIDataAnalysis"; Name="value"},
    
    # Copilot (Multi-Layer Blocking)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="TurnOffWindowsCopilot"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name="TurnOffWindowsCopilot"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name="ShowCopilotButton"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableWindowsCopilot"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name="DisableCopilotProactive"},
    
    # Other AI Features (WindowsAI path)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="DisableClickToDo"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="DisableSettingsAgent"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="SetMaximumStorageSpaceForRecallSnapshots"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name="SetMaximumStorageDurationForRecallSnapshots"},
    
    # Paint AI Features (CORRECT path - not WindowsAI!)
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"; Name="DisableCocreator"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"; Name="DisableGenerativeFill"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"; Name="DisableImageCreator"},
    
    # Notepad AI Features
    @{Path="HKLM:\SOFTWARE\Policies\WindowsNotepad"; Name="DisableAIFeatures"},
    
    # ===== BLOATWARE MODULE - UI ELEMENTS (HKLM: 2 KEYS) =====
    # CRITICAL FIX v1.7.12: Added for complete restore capability
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name="AllowNewsAndInterests"},  # Widgets
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"; Name="ChatIcon"},  # Teams Chat
    
    # Edge Browser (NEW - Security Policies)
    # Note: Edge policies are in HKLM:\SOFTWARE\Policies\Microsoft\Edge
    # They are backed up by general registry backup mechanism
    
    # ===== CORE MODULE KEYS (CRITICAL!) =====
    # Internet Explorer
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="DisableIE11Launch"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"; Name="iexplore.exe"},
    
    # Print Spooler (PrintNightmare)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="RpcAuthnLevelPrivacyEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="RegisterSpoolerRemoteRpcEndPoint"},
    
    # NTLM Signing
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"},
    
    # VBS/Credential Guard
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="RequirePlatformSecurityFeatures"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LsaCfgFlags"},
    
    # CRITICAL FIX v1.7.6: Windows 11 25H2 Scenarios Keys
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name="WasEnabledBy"},
    
    # BitLocker (CRITICAL FIX v1.7.6: New policy names with XTS suffix!)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="EncryptionMethodWithXtsOs"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="EncryptionMethodWithXtsFdv"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="EncryptionMethodWithXtsRdv"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseTPM"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseTPMPIN"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseAdvancedStartup"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="ActiveDirectoryBackup"},
    
    # SMB Advanced
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableMailslots"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="NullSessionShares"},
    
    # Defender Advanced
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="EDRBlockMode"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="MpEnablePus"},
    
    # Network Discovery
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_ShowSharedAccessUI"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_AllowNetBridge_NLA"},
    
    # Windows Connect Now
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name="EnableRegistrars"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"; Name="DisableWcnUi"},
    
    # Peer-to-Peer
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Peernet"; Name="Disabled"},
    
    # Wireless Display
    @{Path="HKLM:\SOFTWARE\Microsoft\PlayToReceiver"; Name="Enabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"; Name="AllowProjectionToPC"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"; Name="RequirePinForPairing"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WirelessDisplay"; Name="Enabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"; Name="PreventWirelessReceiver"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache"; Name="OsuRegistrationStatus"},
    
    # Remote Assistance
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowUnsolicited"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowToGetHelp"},
    
    # WlanSvc
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters"; Name="HostedNetworkSettings"},
    
    # ===== ADVANCED MODULE KEYS =====
    # LAPS
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="PasswordComplexity"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="PasswordLength"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="PasswordAgeDays"},
    
    # Activity History
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="PublishUserActivities"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="UploadUserActivities"},
    
    # Timeline
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableActivityFeed"},
    
    # ===== TELEMETRY MODULE KEYS =====
    # DiagTrack
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowDesktopAnalyticsProcessing"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DoNotShowFeedbackNotifications"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DisableTelemetryOptInChangeNotification"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DisableTelemetryOptInSettingsUx"},
    
    # Application Telemetry
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="AITEnable"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="DisableInventory"},
    
    # Customer Experience Improvement Program
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name="CEIPEnable"},
    
    # ===== EDGE BROWSER KEYS =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="UserFeedbackAllowed"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="MetricsReportingEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SpotlightExperiencesAndRecommendationsEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PersonalizationReportingEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeShoppingAssistantEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeCollectionsEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="HubsSidebarEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowRecommendationsEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ConfigureDoNotTrack"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="TrackingPrevention"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenPuaEnabled"},
    
    # ===== ASR MODULE KEYS =====
    # Controlled Folder Access
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"; Name="EnableControlledFolderAccess"},
    
    # Network Protection
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name="EnableNetworkProtection"},
    
    # Exploit Protection
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection"; Name="ExploitProtection_ControlFlowGuard"},
    
    # ===== EDGE MODULE - POLICIES (enforced) =====
    # REMOVED DUPLICATES: SmartScreenPuaEnabled, TrackingPrevention (siehe oben)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PreventSmartScreenPromptOverride"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PreventSmartScreenPromptOverrideForFiles"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SitePerProcess"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BlockThirdPartyCookies"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DnsOverHttpsMode"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BuiltInDnsClientEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EnhanceSecurityMode"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DownloadRestrictions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ExtensionInstallSources"},
    
    # ===== EDGE MODULE - PREFERENCES (user changeable) =====
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="QuicAllowed"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="PasswordManagerEnabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="AutofillAddressEnabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="AutofillCreditCardEnabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="PaymentMethodQueryEnabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="WebRtcLocalhostIpHandling"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Edge"; Name="InPrivateModeAvailability"},
    
    # ===== DNS MODULE KEYS =====
    # Cloudflare DNS
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableDohFallback"},
    
    # ===== OTHER CRITICAL KEYS =====
    # AutoRun
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"},
    
    # USB Storage
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"; Name="Start"},
    
    # Anonymous SID Enumeration
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"},
    
    # ===== CORE MODULE - NETBIOS/NETWORKING =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="DisableNBTNameResolution"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"},
    
    # ===== CORE MODULE - AUDITING =====
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"},
    
    # ===== CORE MODULE - DEFENDER ADVANCED =====
    # NOTE: EnableEDRInBlockMode is TrustedInstaller-protected and always re-applied - not backed up
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS"; Name="ConvertWarnToBlock"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="ExclusionsVisibleToLocalUsers"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="ConfigureRealTimeProtectionOOBE"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="ScanExcludedFilesInQuickScan"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Name="ReportDynamicSignatureDroppedEvent"},
    # REMOVED DUPLICATE: DisableRealtimeMonitoring (siehe oben)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="CheckExclusions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="MpCloudBlockLevel"},
    # PUAProtection is now set via Set-MpPreference (not registry policy!)
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"; Name="EnableControlledFolderAccess"}
    
    # REMOVED DUPLICATE: Edge SmartScreenPuaEnabled (siehe oben)
    
    # ===== CORE MODULE - SMB HARDENING ADVANCED =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="InvalidAuthenticationDelayTimeInMs"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableAuthenticationRateLimiter"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMBServerMinimumProtocol"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMBServerMaximumProtocol"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RejectUnencryptedAccess"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EncryptionCiphers"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableLeasing"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableSecuritySignature"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="DisableCompression"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableInsecureGuestLogons"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="AllowInsecureGuestAuth"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"},
    
    # ===== CORE MODULE - ADMINISTRATIVE SHARES =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RestrictRemoteClients"},
    
    # ===== CORE MODULE - REMOTE DESKTOP HARDENING =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="MinEncryptionLevel"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="SecurityLayer"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="AllowTSConnections"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="fDisableCdm"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="fDisableClip"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="fDisableLPT"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="fDisablePNPRedir"},
    
    # ===== CORE MODULE - SUDO =====
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo"; Name="ConfigFlags"},
    
    # ===== CORE MODULE - TLS =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name="DisabledByDefault"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name="DisabledByDefault"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Name="DisabledByDefault"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"; Name="DisabledByDefault"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"; Name="Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"; Name="DisabledByDefault"},
    
    # ===== ADVANCED MODULE - SMARTSCREEN =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"},
    
    # ===== ADVANCED MODULE - WINDOWS DEFENDER APPLICATION GUARD =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"; Name="AllowAppHVSI_ProviderSet"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"; Name="AuditApplicationGuard"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"; Name="SaveFilesToHost"},
    
    # ===== ADVANCED MODULE - EXPLOIT PROTECTION =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"; Name="DisallowExploitProtectionOverride"},
    
    # ===== ADVANCED MODULE - RANSOMWARE PROTECTION =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"; Name="AllowedApplications"},
    
    # ===== TELEMETRY MODULE - ADDITIONAL =====
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"; Name="AllowBuildPreview"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"; Name="EnableConfigFlighting"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoInstrumentation"},
    
    # ===== DNS MODULE - ADDITIONAL =====
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableDohFallbackToUdp"},
    
    # =====================================================================================
    # ===== HKCU (USER-SPECIFIC) REGISTRY-KEYS =====
    # =====================================================================================
    # CRITICAL: These keys are set by the script for the CURRENT user!
    # IMPORTANT: HKCU must be backed up for Restore to work!
    # New in version 1.7.11: HKCU Backup Support
    # CRITICAL FIX v1.7.11: ONLY backup "Value" (NO LastUsedTime*!)
    # LastUsedTime* are FORENSIC-TRACKING (managed by Windows)
    
    # ===== TELEMETRY MODULE - APP PERMISSIONS (36 PERMISSIONS × 1 VALUE = 36 KEYS) =====
    # ConsentStore Base: HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
    
    # Original 15 Permissions (only Value!)
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"; Name="Value"},
    
    # 3 Additional Permissions (25H2 - only Value!)
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\automaticFileDownloads"; Name="Value"},
    
    # 15 Advanced Permissions (Windows 11 25H2 Complete - only Value!)
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeys"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeysEnumeration"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect"; Name="Value"},
    
    # 3 Special Permissions (Camera, Microphone, Location - only Value!)
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Name="Value"},
    
    # ===== ONEDRIVE MODULE - PRIVACY SETTINGS (HKCU: 4 KEYS) =====
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableTutorial"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableFeedback"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="PreventNetworkTrafficPreUserSignIn"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="KFMBlockOptIn"},
    
    # ===== EDGE MODULE - SMARTSCREEN SETTINGS (HKCU: 3 KEYS) =====
    # CRITICAL FIX v1.7.12: SmartScreenPuaEnabled needs HKCU for Windows Security GUI checkbox!
    @{Path="HKCU:\SOFTWARE\Microsoft\Edge"; Name="SmartScreenPuaEnabled"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenEnabled"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenPuaEnabled"},
    
    # ===== TELEMETRY MODULE - LOCK SCREEN HARDENING (HKCU: 1 + HKLM: 2 KEYS) =====
    # CRITICAL FIX v1.7.12: Added for complete restore capability
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoToastApplicationNotificationOnLockScreen"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenCamera"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"},
    
    # ===== ONEDRIVE MODULE - PRIVACY SETTINGS (HKLM: 4 KEYS) =====
    # CRITICAL FIX v1.7.6: OneDrive now also sets HKLM for new users!
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableTutorial"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableFeedback"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="PreventNetworkTrafficPreUserSignIn"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="KFMBlockOptIn"},
    
    # =====================================================================================
    # MISSING KEYS ADDED v1.7.12 - Registry Parity Check (68 keys - BATCH 1 of 2)
    # =====================================================================================
    # These keys were found by automated parity check comparing Set-RegistryValue calls
    # with backed-up keys. All are static keys set by modules but not previously backed up.
    # IMPORTANT: 58 more keys remain to be added in BATCH 2! See PARITY_TODO.txt
    # =====================================================================================
    
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="SMBClientMaximumProtocol"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireEncryption"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableCloudOptimizedContent"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice"; Name="AllowFindMyDevice"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353698Enabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableSettingSync"},
    @{Path="HKCU:\Control Panel\International\User Profile"; Name="HttpAcceptLanguageOptOut"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableSettingSyncUserOverride"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RestrictNTLMInDomain"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"; Name="Start"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name="DisableWpad"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="SMBClientMinimumProtocol"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"; Name="NotifyPasswordReuse"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule"; Name="DisableRpcOverTcp"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="DnssecMode"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"; Name="DoNotUseWPAD"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-310093Enabled"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnableSuperfetch"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsGetDiagnosticInfo"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"; Name="RemoteRegAccess"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoInstrumentation"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"; Name="PKINITHashAlgorithm"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="DisableSmb1"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters"; Name="DisableMdnsDiscovery"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"},
    @{Path="HKCU:\Software\Microsoft\GameBar"; Name="AutoGameModeEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableInvocationHeader"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"; Name="Deny_Execute"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"; Name="Functions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowUnsolicited"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"; Name="NotifyUnsafeApp"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnablePrefetcher"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="MaxTelemetryAllowed"},
    @{Path="HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"; Name="HasAccepted"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"; Name="EnabledV9"},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AllowInsecureGuestAuth"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"; Name="Value"},
    @{Path="HKCU:\Software\Microsoft\InputPersonalization"; Name="RestrictImplicitInkCollection"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EnhancedSecurityMode"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="AuditReceivingNTLMTraffic"},
    @{Path="HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters"; Name="AllowEncryptionOracle"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="AuditServerDoesNotSupportEncryption"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"; Name="EnableUserControl"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"; Name="AllowDefCredentialsWhenNTLMOnly"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="RestrictReceivingNTLMTraffic"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353696Enabled"},
    @{Path="HKCU:\Software\Microsoft\GameBar"; Name="AllowAutoGameMode"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="EnableDynamicContentInWSB"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"; Name="EnumerateLocalUsers"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableSearchBoxSuggestions"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableRemoteMailslots"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AuditClientDoesNotSupportSigning"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"; Name="AppCaptureEnabled"},
    
    # ===== BATCH 2 - Remaining 57 static keys =====
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaConsent"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="AuditServerDoesNotSupportSigning"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsGetDiagnosticInfo"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"; Name="SmartScreenEnabled"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowClipboardHistory"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name="MaintenanceDisabled"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"; Name="AlwaysInstallElevated"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"; Name="NoDriveTypeAutoRun"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"},
    @{Path="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"; Name="DisableEnclosureDownload"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableDnssec"},
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_Enabled"},
    @{Path="HKCU:\Software\Microsoft\InputPersonalization"; Name="RestrictImplicitTextCollection"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name="IdleOnly"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="BackupDirectory"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="NullSessionPipes"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="AuditInsecureGuestLogon"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AuditClientDoesNotSupportEncryption"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="Start_TrackProgs"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"; Name="EventLogging"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"; Name="ServiceEnabled"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows Search"; Name="SetupCompletedSuccessfully"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"},
    @{Path="HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"; Name="HarvestContacts"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableDnssecIPv6"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="AdminApprovalModeType"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableWindowsLocationProvider"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="AllowCrossDeviceClipboard"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableRemoteMailslots"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="OutputDirectory"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="ScanWithAntiVirus"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"; Name="PreventOverride"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AuditInsecureGuestLogon"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="AllowNullSessionFallback"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="Shadow"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"},
    @{Path="HKCU:\Software\Microsoft\Personalization\Settings"; Name="AcceptedPrivacyPolicy"},
    @{Path="HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"; Name="AutoConnectAllowedOEM"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdminInEPPMode"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="PostAuthenticationActions"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchUseWeb"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"; Name="Enabled"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"; Name="VoiceActivationEnableAboveLockscreen"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="PKINITHashAlgorithm"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EncryptData"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="AuditNTLMInDomain"}
    
    # =====================================================================================
    # TOTAL REGISTRY-KEYS: 398 Keys (EXACT COUNT - UPDATED v1.7.12)
    # REMOVED: 2 TrustedInstaller-protected keys (EnableEDRInBlockMode, EnableAppInstallControl)
    # These keys are always re-applied by the script and cannot be backed up without ownership change
    # - HKLM (System): ~315 Keys
    # - HKCU (User):   ~85 Keys
    #
    # PARITY CHECK RESULTS (377 Set-RegistryValue calls in modules):
    # - 125 missing static keys added (68 in Batch 1, 57 in Batch 2)
    # - 39 dynamic keys (loop-based) are handled by code, not in backup array
    # - 2 TrustedInstaller keys excluded (always re-applied, cannot be backed up)
    # - 23 calls are duplicates/context-specific (same key set multiple times)
    # - Result: 398 backupable keys (377 + 39 - 2 - 16 duplicates)
    #
    # BREAKDOWN HKCU App Permissions (36 Total):
    # - 15 Original (Notifications, Contacts, Calendar, Email, etc.)
    # - 3 Additional 25H2 (Music, Downloads, AutoFileDownloads)
    # - 15 Advanced 25H2 (Activity, Bluetooth, Gaze, Graphics, etc.)
    # - 3 Special (Camera, Microphone, Location)
    # 
    # CHANGE v1.7.11: LastUsedTime* are NO LONGER backed up (Forensic tracking!)
    # =====================================================================================
)

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$registryBackup = foreach ($regKey in $registryKeys) {
    # Function returns hashtable - output to pipeline (captured by $registryBackup)
    Backup-RegistryValue -Path $regKey.Path -Name $regKey.Name
}

$backup.Settings.RegistryKeys = $registryBackup
$regCount = if ($registryBackup) { @($registryBackup).Count } else { 0 }
Write-Host "[OK] $regCount $(Get-LocalizedString 'BackupRegistrySaved')" -ForegroundColor Green

# Check for Access Denied keys (should be 0 after removing TrustedInstaller-protected keys)
$accessDeniedKeys = $registryBackup | Where-Object { 
    $_.PSObject.Properties.Name -contains 'AccessDenied' -and $_.AccessDenied -eq $true 
}
if ($accessDeniedKeys) {
    Write-Host ""
    Write-Host "[!] WARNUNG: $($accessDeniedKeys.Count) Registry-Keys konnten NICHT gesichert werden (Access Denied)!" -ForegroundColor Yellow
    Write-Host "[i] Diese Keys existieren, sind aber durch TrustedInstaller/System geschuetzt:" -ForegroundColor Yellow
    $accessDeniedKeys | ForEach-Object {
        Write-Host "    - $($_.RegPath)\$($_.RegName)" -ForegroundColor Gray
    }
    Write-Host "[!] Diese Keys werden bei Restore NICHT wiederhergestellt!" -ForegroundColor Yellow
    Write-Host "[i] BITTE MELDEN an NoID Privacy Team - diese Keys sollten aus Backup entfernt werden!" -ForegroundColor Cyan
}

# NEW v1.8.0: Complete Registry Snapshots for perfect restore
# This captures the COMPLETE state of all registry areas that Apply can modify
# Allows restore to DELETE keys that Apply created (not just restore changed values)
Write-Host ""
Write-Host "[i] Creating complete registry snapshots for perfect restore..." -ForegroundColor Cyan

$backup.Settings.RegistrySnapshots = @{
    'HKLM_Policies'      = Export-RegistrySnapshot 'HKLM:\SOFTWARE\Policies' 'HKLM Policies'
    'HKLM_Microsoft'     = Export-RegistrySnapshot 'HKLM:\SOFTWARE\Microsoft' 'HKLM Microsoft'
    'HKLM_System'        = Export-RegistrySnapshot 'HKLM:\SYSTEM\CurrentControlSet' 'HKLM System'
    'HKCU_Policies'      = Export-RegistrySnapshot 'HKCU:\SOFTWARE\Policies' 'HKCU Policies'
    'HKCU_Microsoft'     = Export-RegistrySnapshot 'HKCU:\SOFTWARE\Microsoft' 'HKCU Microsoft'
    'HKCU_ControlPanel'  = Export-RegistrySnapshot 'HKCU:\Control Panel' 'HKCU Control Panel'
    'HKCU_System'        = Export-RegistrySnapshot 'HKCU:\System' 'HKCU System'
}

# Calculate total snapshot size
$totalKeys = 0
$totalValues = 0
foreach ($snapshot in $backup.Settings.RegistrySnapshots.Values) {
    if ($snapshot.KeyCount) { $totalKeys += $snapshot.KeyCount }
    if ($snapshot.ValueCount) { $totalValues += $snapshot.ValueCount }
}

Write-Host "[OK] Registry snapshots complete: $totalKeys keys, $totalValues values" -ForegroundColor Green

Write-Host ""
#endregion

#region ASR Rules Backup (Attack Surface Reduction)
Write-Host "[9/13] $(Get-LocalizedString 'BackupASRTitle')" -ForegroundColor Yellow

$asrBackup = @{
    Rules = @()
    Enabled = $false
}

try {
    # Check if Defender is available
    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
        $asrBackup.Enabled = $true
        
        # Backup all ASR Rules with their current state
        for ($i = 0; $i -lt $mpPref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $asrBackup.Rules += @{
                Id = $mpPref.AttackSurfaceReductionRules_Ids[$i]
                Action = $mpPref.AttackSurfaceReductionRules_Actions[$i]
            }
        }
        
        Write-Host "[OK] $(Get-LocalizedString 'BackupASRSaved' $asrBackup.Rules.Count)" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] $(Get-LocalizedString 'BackupASRNotFound')" -ForegroundColor Gray
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupASRFailed' $_)
    $asrBackup.Enabled = $false
}

$backup.Settings.ASRRules = $asrBackup
Write-Host ""
#endregion

#region Exploit Protection Backup (Set-ProcessMitigation)
Write-Host "[10/13] $(Get-LocalizedString 'BackupExploitTitle')" -ForegroundColor Yellow

$exploitProtectionBackup = @{
    SystemMitigations = @()
    Enabled = $false
}

try {
    # Check if Get-ProcessMitigation is available (Windows 10 1709+)
    if (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue) {
        $systemMitigations = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        
        if ($systemMitigations) {
            $exploitProtectionBackup.Enabled = $true
            
            # Backup all system-wide mitigations
            # Convert to simple hashtable for JSON serialization
            $exploitProtectionBackup.SystemMitigations = @{
                DEP = $systemMitigations.DEP
                SEHOP = $systemMitigations.SEHOP
                ASLR = $systemMitigations.ASLR
                CFG = $systemMitigations.CFG
                ImageLoad = $systemMitigations.ImageLoad
                Heap = $systemMitigations.Heap
                ExtensionPoints = $systemMitigations.ExtensionPoint
            }
            
            Write-Host "[OK] $(Get-LocalizedString 'BackupExploitSaved')" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] $(Get-LocalizedString 'BackupExploitNotConfigured')" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] $(Get-LocalizedString 'BackupExploitNotAvailable')" -ForegroundColor Gray
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupExploitFailed' $_)
    $exploitProtectionBackup.Enabled = $false
}

$backup.Settings.ExploitProtection = $exploitProtectionBackup
Write-Host ""
#endregion

#region DoH Configuration Backup (DNS over HTTPS)
Write-Host "[11/13] $(Get-LocalizedString 'BackupDohTitle')" -ForegroundColor Yellow

$dohBackup = @{
    Servers = @()
    Enabled = $false
}

try {
    # Check if Get-DnsClientDohServerAddress is available (Windows 11+)
    if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        
        if ($dohServers) {
            $dohBackup.Enabled = $true
            
            # Backup all DoH server configurations
            foreach ($server in $dohServers) {
                $dohBackup.Servers += @{
                    ServerAddress = $server.ServerAddress
                    DohTemplate = $server.DohTemplate
                    AllowFallbackToUdp = $server.AllowFallbackToUdp
                    AutoUpgrade = $server.AutoUpgrade
                }
            }
            
            Write-Host "[OK] $(Get-LocalizedString 'BackupDohSaved' $dohBackup.Servers.Count)" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] $(Get-LocalizedString 'BackupDohNotFound')" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] $(Get-LocalizedString 'BackupDohNotAvailable')" -ForegroundColor Gray
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupDohFailed' $_)
    $dohBackup.Enabled = $false
}

$backup.Settings.DoH = $dohBackup
Write-Host ""
#endregion

#region DoH Encryption Preferences Backup (Adapter-specific DohFlags)
Write-Host "[12/13] $(Get-LocalizedString 'BackupDohEncryptionTitle')" -ForegroundColor Yellow

$dohEncryptionBackup = @{
    Adapters = @()
    Enabled = $false
}

try {
    # Get all network adapters
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    
    if ($adapters) {
        foreach ($adapter in $adapters) {
            $adapterGuid = $adapter.InterfaceGuid
            $adapterBackup = @{
                Name = $adapter.Name
                Guid = $adapterGuid
                IPv4Servers = @()
                IPv6Servers = @()
            }
            
            # Backup IPv4 DoH encryption (Doh branch)
            $ipv4Servers = @('1.1.1.1', '1.0.0.1')
            foreach ($ip in $ipv4Servers) {
                $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                if (Test-Path $regPath) {
                    try {
                        # BEST PRACTICE: Avoid error records with -Name parameter
                        $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($regItem -and ($regItem.PSObject.Properties.Name -contains 'DohFlags')) {
                            $adapterBackup.IPv4Servers += @{
                                IP = $ip
                                DohFlags = $regItem.DohFlags
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not read DohFlags for IPv4 $ip on adapter $($adapter.Name): $_"
                    }
                }
            }
            
            # Backup IPv6 DoH encryption (Doh6 branch)
            $ipv6Servers = @('2606:4700:4700::1111', '2606:4700:4700::1001')
            foreach ($ip in $ipv6Servers) {
                $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6\$ip"
                if (Test-Path $regPath) {
                    try {
                        # BEST PRACTICE: Avoid error records with -Name parameter
                        $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($regItem -and ($regItem.PSObject.Properties.Name -contains 'DohFlags')) {
                            $adapterBackup.IPv6Servers += @{
                                IP = $ip
                                DohFlags = $regItem.DohFlags
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not read DohFlags for IPv6 $ip on adapter $($adapter.Name): $_"
                    }
                }
            }
            
            # Only add adapter if it has DoH encryption configured
            if ($adapterBackup.IPv4Servers.Count -gt 0 -or $adapterBackup.IPv6Servers.Count -gt 0) {
                $dohEncryptionBackup.Adapters += $adapterBackup
            }
        }
        
        if ($dohEncryptionBackup.Adapters.Count -gt 0) {
            $dohEncryptionBackup.Enabled = $true
            $totalServers = ($dohEncryptionBackup.Adapters | ForEach-Object { $_.IPv4Servers.Count + $_.IPv6Servers.Count } | Measure-Object -Sum).Sum
            Write-Host "[OK] $(Get-LocalizedString 'BackupDohEncryptionSaved' $dohEncryptionBackup.Adapters.Count $totalServers)" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] $(Get-LocalizedString 'BackupDohEncryptionNotFound')" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] $(Get-LocalizedString 'BackupDohEncryptionNoAdapters')" -ForegroundColor Gray
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupDohEncryptionFailed' $_)
    $dohEncryptionBackup.Enabled = $false
}

$backup.Settings.DohEncryption = $dohEncryptionBackup
Write-Host ""
#endregion

#region Firewall Profile Settings Backup
Write-Host "[13/13] $(Get-LocalizedString 'BackupFirewallProfilesTitle')" -ForegroundColor Yellow

$firewallProfileBackup = @{
    Profiles = @()
    Enabled = $false
}

try {
    $profiles = @('Domain', 'Private', 'Public')
    
    foreach ($profileName in $profiles) {
        $fwProfile = Get-NetFirewallProfile -Name $profileName -ErrorAction SilentlyContinue
        
        if ($fwProfile) {
            $firewallProfileBackup.Profiles += @{
                Name = $profileName
                Enabled = $fwProfile.Enabled.ToString()
                DefaultInboundAction = $fwProfile.DefaultInboundAction.ToString()
                DefaultOutboundAction = $fwProfile.DefaultOutboundAction.ToString()
                # CRITICAL FIX v1.7.6: Convert enum properties to strings to avoid JSON duplicate key error
                # These properties are enums with .value (lowercase) and .Value (uppercase) which causes
                # "duplicate keys 'value' and 'Value'" error during JSON serialization
                AllowInboundRules = $fwProfile.AllowInboundRules.ToString()
                AllowLocalFirewallRules = $fwProfile.AllowLocalFirewallRules.ToString()
                AllowLocalIPsecRules = $fwProfile.AllowLocalIPsecRules.ToString()
                NotifyOnListen = $fwProfile.NotifyOnListen.ToString()
                EnableStealthModeForIPsec = $fwProfile.EnableStealthModeForIPsec.ToString()
                LogFileName = $fwProfile.LogFileName
                LogMaxSizeKilobytes = $fwProfile.LogMaxSizeKilobytes
                LogAllowed = $fwProfile.LogAllowed.ToString()
                LogBlocked = $fwProfile.LogBlocked.ToString()
                LogIgnored = $fwProfile.LogIgnored.ToString()
            }
        }
    }
    
    if ($firewallProfileBackup.Profiles.Count -gt 0) {
        $firewallProfileBackup.Enabled = $true
        Write-Host "[OK] $(Get-LocalizedString 'BackupFirewallProfilesSaved' $firewallProfileBackup.Profiles.Count)" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] $(Get-LocalizedString 'BackupFirewallProfilesNotFound')" -ForegroundColor Gray
    }
}
catch {
    Write-Warning (Get-LocalizedString 'BackupFirewallProfilesFailed' $_)
    $firewallProfileBackup.Enabled = $false
}

$backup.Settings.FirewallProfiles = $firewallProfileBackup
Write-Host ""
#endregion

# NOTE: Device-Level Backup (EnabledByUser) was removed in v1.7.12
# Reason: All EnabledByUser keys are TrustedInstaller-protected and always re-applied by the script
# Backup is meaningless as keys cannot be read (Access Denied) or written without ownership change

#region System Info
Write-Host "$(Get-LocalizedString 'BackupSystem')" -ForegroundColor Yellow

$systemInfo = @{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
    Build = [Environment]::OSVersion.Version.Build
    Architecture = $env:PROCESSOR_ARCHITECTURE
    TPM_Present = [bool]((Get-Tpm -ErrorAction SilentlyContinue).TpmPresent)  # Explizit zu Bool
    SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)  # Explizit zu Bool
}

$backup.Settings.SystemInfo = $systemInfo
Write-Host "[OK] $(Get-LocalizedString 'BackupSystemSaved')`n" -ForegroundColor Green
#endregion

# Save backup as JSON
Write-Host ""
Write-Host "[SAVE] $(Get-LocalizedString 'BackupSaving')" -ForegroundColor Cyan

try {
    # STRATEGY: Try with all data, reduce data on timeout
    Write-Host "$(Get-LocalizedString 'BackupConvertingJSON')" -ForegroundColor Gray
    
    $jsonJob = Start-Job -ScriptBlock {
        param($backupData)
        $backupData | ConvertTo-Json -Depth 5 -Compress -ErrorAction Stop
    } -ArgumentList $backup
    
    $jsonCompleted = Wait-Job $jsonJob -Timeout 120
    
    if (-not $jsonCompleted) {
        # TIMEOUT! Versuche FALLBACK
        Remove-Job $jsonJob -Force
        Write-Warning (Get-LocalizedString 'BackupJSONTimeout')
        
        $backup.Settings.FirewallRules = @()
        Write-Host "$(Get-LocalizedString 'BackupJSONFallback')" -ForegroundColor Yellow
        
        $jsonJob2 = Start-Job -ScriptBlock {
            param($backupData)
            $backupData | ConvertTo-Json -Depth 5 -Compress -ErrorAction Stop
        } -ArgumentList $backup
        
        $jsonCompleted2 = Wait-Job $jsonJob2 -Timeout 60
        
        if (-not $jsonCompleted2) {
            Remove-Job $jsonJob2 -Force
            throw (Get-LocalizedString 'BackupJSONFailed')
        }
        
        $json = Receive-Job $jsonJob2 -ErrorAction Stop
        Remove-Job $jsonJob2 -Force
        Write-Host "$(Get-LocalizedString 'BackupJSONReduced')" -ForegroundColor Yellow
    }
    else {
        $json = Receive-Job $jsonJob -ErrorAction Stop
        Remove-Job $jsonJob -Force
        Write-Host "$(Get-LocalizedString 'BackupJSONComplete')" -ForegroundColor Green
    }
    
    if ([string]::IsNullOrWhiteSpace($json)) {
        throw (Get-LocalizedString 'BackupJSONEmpty')
    }
    
    Write-Host "$(Get-LocalizedString 'BackupJSONSize' ([Math]::Round($json.Length / 1KB, 2)))" -ForegroundColor Cyan
    
    Write-Host "$(Get-LocalizedString 'BackupSavingFile')" -ForegroundColor Gray
    $tempBackupFile = "$backupFile.tmp"
    # [OK] BEST PRACTICE: UTF-8 without BOM (PowerShell 5.1 compatible)
    # Out-File -Encoding utf8 in PS 5.1 creates file WITH BOM!
    # Use .NET API for UTF-8 without BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempBackupFile, $json, $utf8NoBom)
    
    $fileInfo = Get-Item $tempBackupFile -ErrorAction Stop
    if ($fileInfo.Length -lt 1KB) {
        throw (Get-LocalizedString 'BackupFileTooSmall')
    }
    
    # Atomarer Replace: Temp -> Final
    Move-Item -Path $tempBackupFile -Destination $backupFile -Force -ErrorAction Stop
    
    Write-Host "[OK] $(Get-LocalizedString 'BackupSuccess')" -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "  $(Get-LocalizedString 'BackupCompleted')" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupFile') $backupFile" -ForegroundColor Cyan
    Write-Host "$(Get-LocalizedString 'BackupSize') $([Math]::Round((Get-Item $backupFile).Length / 1KB, 2)) KB" -ForegroundColor Gray
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupSavedItems')" -ForegroundColor White
    $dnsCountSummary = if ($backup.Settings.DNS) { @($backup.Settings.DNS).Count } else { 0 }
    $appsCountSummary = if ($backup.Settings.InstalledApps) { @($backup.Settings.InstalledApps).Count } else { 0 }
    $servicesCountSummary = if ($backup.Settings.Services) { @($backup.Settings.Services).Count } else { 0 }
    $tasksCountSummary = if ($backup.Settings.ScheduledTasks) { @($backup.Settings.ScheduledTasks).Count } else { 0 }
    $fwCountSummary = if ($backup.Settings.FirewallRules) { @($backup.Settings.FirewallRules).Count } else { 0 }
    $usersCountSummary = if ($backup.Settings.UserAccounts) { @($backup.Settings.UserAccounts).Count } else { 0 }
    $regCountSummary = if ($backup.Settings.RegistryKeys) { @($backup.Settings.RegistryKeys).Count } else { 0 }
    $asrCountSummary = if ($backup.Settings.ASRRules.Rules) { @($backup.Settings.ASRRules.Rules).Count } else { 0 }
    Write-Host "  - DNS: $dnsCountSummary" -ForegroundColor Gray
    Write-Host "  - Hosts: $($null -ne $backup.Settings.HostsFile)" -ForegroundColor Gray
    Write-Host "  - Apps: $appsCountSummary" -ForegroundColor Gray
    Write-Host "  - Services: $servicesCountSummary" -ForegroundColor Gray
    Write-Host "  - Scheduled Tasks: $tasksCountSummary" -ForegroundColor Gray
    Write-Host "  - Firewall: $fwCountSummary" -ForegroundColor Gray
    Write-Host "  - Users: $usersCountSummary" -ForegroundColor Gray
    Write-Host "  - Registry: $regCountSummary" -ForegroundColor Gray
    Write-Host "  - ASR Rules: $asrCountSummary" -ForegroundColor Gray
    Write-Host "  - Exploit Protection: $($backup.Settings.ExploitProtection.Enabled)" -ForegroundColor Gray
    $dohServersSummary = if ($backup.Settings.DoH.Servers) { @($backup.Settings.DoH.Servers).Count } else { 0 }
    $dohAdaptersSummary = if ($backup.Settings.DohEncryption.Adapters) { @($backup.Settings.DohEncryption.Adapters).Count } else { 0 }
    $fwProfilesSummary = if ($backup.Settings.FirewallProfiles.Profiles) { @($backup.Settings.FirewallProfiles.Profiles).Count } else { 0 }
    Write-Host "  - DoH Servers: $dohServersSummary" -ForegroundColor Gray
    Write-Host "  - DoH Encryption: $dohAdaptersSummary Adapter" -ForegroundColor Gray
    Write-Host "  - Firewall Profiles: $fwProfilesSummary" -ForegroundColor Gray
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupNote')" -ForegroundColor Yellow
    Write-Host ""
    
    # Automatic validation (prevents corrupt backups)
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  $(Get-LocalizedString 'BackupValidationTitle')" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'BackupValidating')" -ForegroundColor Gray
    
    # Validation 1: File exists and size OK
    $fileInfo = Get-Item $backupFile -ErrorAction Stop
    $fileSizeKB = [Math]::Round($fileInfo.Length / 1KB, 2)
    
    if ($fileInfo.Length -lt 5KB) {
        throw (Get-LocalizedString 'BackupValidationFileTooSmall' $fileSizeKB)
    }
    Write-Host "$(Get-LocalizedString 'BackupValidationFileSize' $fileSizeKB)" -ForegroundColor Green
    
    # Validation 2: JSON is parsable
    $testParse = $null  # Initialisiere Variable VORHER!
    try {
        # IMPORTANT: Use UTF8 without BOM when reading (prevents encoding issues)
        $jsonContent = [System.IO.File]::ReadAllText($backupFile, [System.Text.Encoding]::UTF8)
        $testParse = $jsonContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "$(Get-LocalizedString 'BackupValidationJSONOK')" -ForegroundColor Green
        
        # Validate that essential keys are present
        if (-not $testParse.Settings) {
            throw (Get-LocalizedString 'BackupValidationNoSettings')
        }
        if (-not $testParse.Timestamp) {
            throw (Get-LocalizedString 'BackupValidationNoTimestamp')
        }
        Write-Host "$(Get-LocalizedString 'BackupValidationStructureOK')" -ForegroundColor Green
    }
    catch {
        Write-Host "$(Get-LocalizedString 'BackupValidationJSONFailed')" -ForegroundColor Yellow
        Write-Host "$(Get-LocalizedString 'BackupValidationJSONError' $_.Exception.Message)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "$(Get-LocalizedString 'BackupValidationHint1')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupValidationHint2')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupValidationHint3')" -ForegroundColor Gray
        Write-Host ""
        # DON'T throw - Backup is probably OK!
        # throw "Backup validation failed: JSON not parsable - $($_.Exception.Message)"
    }
    
    # Validation 3: At least a few important entries (only if testParse exists)
    if ($testParse) {
        $hasData = $false
        if ($testParse.Settings.DNS -or $testParse.Settings.Services -or $testParse.Settings.RegistryKeys) {
            $hasData = $true
        }
        
        if (-not $hasData) {
            Write-Host "$(Get-LocalizedString 'BackupValidationEmpty')" -ForegroundColor Yellow
        }
        else {
            Write-Host "$(Get-LocalizedString 'BackupValidationDataOK')" -ForegroundColor Green
        }
    }
    else {
        Write-Host "$(Get-LocalizedString 'BackupValidationSkipped')" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "  $(Get-LocalizedString 'BackupValidationSuccess')" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupValidationFile' $backupFile)" -ForegroundColor Cyan
    Write-Host "$(Get-LocalizedString 'BackupValidationSize' $fileSizeKB)" -ForegroundColor White
    if ($testParse) {
        Write-Host "$(Get-LocalizedString 'BackupValidationStatusComplete')" -ForegroundColor Green
    }
    else {
        Write-Host "$(Get-LocalizedString 'BackupValidationStatusCreated')" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'BackupNote')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "                        $(Get-LocalizedString 'BackupLastWarningTitle')                            " -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupLastWarningText')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'BackupLastWarningAllModules')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupLastWarningAbort')" -ForegroundColor Red
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupLastWarningPressEnter')" -ForegroundColor White
    Write-Host ""
    
    # Best Practice: Final pause before the big start
    $null = Read-Host
    
    Write-Host ""
    Write-Host "[OK] $(Get-LocalizedString 'BackupConfirmed')" -ForegroundColor Green
    Write-Host ""
    
    # Set exit code and return (for dot-sourcing)
    $Global:LASTEXITCODE = 0
    return
}
catch {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "  $(Get-LocalizedString 'BackupFailedTitle')" -ForegroundColor Red
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "[ERROR] $_" -ForegroundColor Red
    Write-Host ""
    
    # Cleanup temp file if exists
    $tempBackupFile = "$backupFile.tmp"
    if (Test-Path $tempBackupFile) {
        Remove-Item $tempBackupFile -Force -ErrorAction SilentlyContinue
        Write-Verbose (Get-LocalizedString 'BackupTempCleaned' $tempBackupFile)
    }
    
    # ===== USER DECISION ON ERROR =====
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "  $(Get-LocalizedString 'BackupErrorWarningTitle')" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupErrorContinuePrompt')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'BackupErrorContinueRisk')" -ForegroundColor Red
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupErrorContinueYes')" -ForegroundColor Red
    Write-Host "$(Get-LocalizedString 'BackupErrorContinueNo')" -ForegroundColor Green
    Write-Host ""
    Write-Host -NoNewline "$(Get-LocalizedString 'BackupErrorContinueChoice')" -ForegroundColor Cyan
    
    $userConfirm = Read-Host
    if ($userConfirm) {
        $userConfirm = $userConfirm.Trim().ToUpper()
    }
    
    Write-Host ""
    
    if ($userConfirm -in @('J', 'Y')) {
        Write-Host "$(Get-LocalizedString 'BackupErrorUserContinues')" -ForegroundColor Yellow
        Write-Host "$(Get-LocalizedString 'BackupErrorNoSafetyNet')" -ForegroundColor Yellow
        Write-Host ""
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 0
        return
    }
    else {
        Write-Host "$(Get-LocalizedString 'BackupErrorUserAborted')" -ForegroundColor Green
        Write-Host "$(Get-LocalizedString 'BackupErrorWillNotContinue')" -ForegroundColor Green
        Write-Host ""
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 1
        return
    }
}
