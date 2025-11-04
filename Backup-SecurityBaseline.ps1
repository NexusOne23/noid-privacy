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
    - Device-Level App Permissions (webcam/microphone) - RE-ADDED v1.7.17!
    
    NEW IN VERSION 1.7.17:
    - Device-Level App Permissions backup RE-ADDED with proper error handling!
    - Previous v1.7.13 removed it (TrustedInstaller protection issue)
    - NOW: Graceful degradation - skips Access Denied, backs up readable entries
    - CRITICAL: Without this backup, Restore cannot restore original state!
    - PERFECT 100% Backup/Restore Coverage restored!
    
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
    
    VERSION 1.7.13 UPDATE (Current):
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
    Version:        1.5.0
    Last Updated:   November 2, 2025
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

# Initialize script-scope variable (defensive programming)
$script:RegistryChanges = @()

# Load Registry Changes Definition (v2.0 - 391 specific keys)
# IMPORTANT: Temporarily bypass execution policy for unsigned modules
$savedExecutionPolicy = Get-ExecutionPolicy -Scope Process
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
    . "$scriptDir\Modules\RegistryChanges-Definition.ps1"
    Write-Verbose "Loaded $($script:RegistryChanges.Count) registry change definitions"
}
catch {
    Write-Error "CRITICAL: Could not load Registry Changes Definition: $_"
    Write-Error "File: $scriptDir\Modules\RegistryChanges-Definition.ps1"
    exit 1
}
finally {
    # Restore original execution policy
    if ($savedExecutionPolicy) {
        Set-ExecutionPolicy -ExecutionPolicy $savedExecutionPolicy -Scope Process -Force -ErrorAction SilentlyContinue
    }
}

# Load Optimized Registry Backup Functions (v2.0)
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
    . "$scriptDir\Modules\SecurityBaseline-RegistryBackup-Optimized.ps1"
    Write-Verbose "Loaded optimized registry backup functions"
}
catch {
    Write-Error "CRITICAL: Could not load Registry Backup functions: $_"
    Write-Error "File: $scriptDir\Modules\SecurityBaseline-RegistryBackup-Optimized.ps1"
    exit 1
}
finally {
    # Restore original execution policy
    if ($savedExecutionPolicy) {
        Set-ExecutionPolicy -ExecutionPolicy $savedExecutionPolicy -Scope Process -Force -ErrorAction SilentlyContinue
    }
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

# ===== START TRANSCRIPT LOGGING (Best Practice 25H2) =====
$script:transcriptPath = ""
$script:transcriptStarted = $false

$logDir = "$env:ProgramData\SecurityBaseline\Logs"
if (-not (Test-Path $logDir)) {
    $null = New-Item -Path $logDir -ItemType Directory -Force
}

$script:transcriptPath = Join-Path $logDir "Backup-$timestamp.log"

try {
    Start-Transcript -Path $script:transcriptPath -Force -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "$(Get-LocalizedString 'VerboseTranscriptStarted' $script:transcriptPath)"
}
catch {
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptFailed' $_)"
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptContinue')"
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
Write-Host "[1/16] $(Get-LocalizedString 'BackupDNS')" -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) instead of O(n^2))
$dnsBackup = foreach ($adapter in $adapters) {
    try {
        # Get IPv4 DNS servers
        $dnsIPv4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        # Get IPv6 DNS servers
        $dnsIPv6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        
        # Only backup if at least one address family has DNS configured
        if (($dnsIPv4 -and $dnsIPv4.ServerAddresses) -or ($dnsIPv6 -and $dnsIPv6.ServerAddresses)) {
            $adapterMsg = Get-LocalizedString 'BackupDNSAdapter' $adapter.Name
            
            $ipv4Addrs = if ($dnsIPv4 -and $dnsIPv4.ServerAddresses) { @($dnsIPv4.ServerAddresses) } else { @() }
            $ipv6Addrs = if ($dnsIPv6 -and $dnsIPv6.ServerAddresses) { @($dnsIPv6.ServerAddresses) } else { @() }
            
            $allAddrs = @($ipv4Addrs) + @($ipv6Addrs)
            Write-Host "  [OK] $($adapterMsg) $($allAddrs -join ', ')" -ForegroundColor Gray
            
            # Output to pipeline (captured by $dnsBackup)
            # CRITICAL: InterfaceGuid is stable across reboots (IfIndex can change!)
            @{
                AdapterName = $adapter.Name
                InterfaceGuid = $adapter.InterfaceGuid
                InterfaceIndex = $adapter.ifIndex
                DNS_IPv4 = $ipv4Addrs
                DNS_IPv6 = $ipv6Addrs
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
Write-Host "[2/16] $(Get-LocalizedString 'BackupHosts')" -ForegroundColor Yellow

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
Write-Host "[3/16] $(Get-LocalizedString 'BackupApps')" -ForegroundColor Yellow

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
Write-Host "[4/16] $(Get-LocalizedString 'BackupServices')" -ForegroundColor Yellow

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

#region Windows Optional Features Backup
Write-Host "[5/16] Backing up Windows Optional Features..." -ForegroundColor Yellow

$windowsFeaturesBackup = @()
try {
    Write-Host "  [i] Reading Windows Optional Features..." -ForegroundColor Gray
    
    # Get all Windows Optional Features (not just enabled ones)
    $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue
    
    if ($features) {
        # [OK] BEST PRACTICE: Capture foreach output directly
        $windowsFeaturesBackup = foreach ($feature in $features) {
            # CRITICAL: Check property existence first (PSObject.Properties pattern)
            # ROOT CAUSE: Some Windows Features don't have Description property
            # SOLUTION: Check if property exists before accessing it
            $props = $feature.PSObject.Properties.Name
            
            # Output to pipeline (captured by $windowsFeaturesBackup)
            @{
                FeatureName = $feature.FeatureName
                State = $feature.State.ToString()
                Description = if ('Description' -in $props -and $feature.Description) { $feature.Description } else { $null }
            }
        }
        
        $backup.Settings.WindowsFeatures = $windowsFeaturesBackup
        $featuresCount = if ($windowsFeaturesBackup) { @($windowsFeaturesBackup).Count } else { 0 }
        Write-Host "  [OK] $featuresCount Windows Features saved" -ForegroundColor Green
        Write-Host "      (Includes state: Enabled/Disabled/DisabledWithPayloadRemoved)" -ForegroundColor Gray
    }
    else {
        Write-Warning "No Windows Features found"
        $backup.Settings.WindowsFeatures = @()
    }
}
catch {
    Write-Warning "Could not backup Windows Features: $_"
    $backup.Settings.WindowsFeatures = @()
}

Write-Host ""
#endregion

#region Scheduled Tasks Backup (ALL TASKS!)
Write-Host "[6/16] $(Get-LocalizedString 'BackupScheduledTasks')" -ForegroundColor Yellow

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
Write-Host "[7/16] $(Get-LocalizedString 'BackupFirewall')" -ForegroundColor Yellow

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
Write-Host "[8/16] $(Get-LocalizedString 'BackupUsers')" -ForegroundColor Yellow

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

#region Registry Keys Backup (v2.0 - OPTIMIZED)
Write-Host "[9/16] $(Get-LocalizedString 'BackupRegistry')" -ForegroundColor Yellow

# NEW v2.0: Specific registry backup (20-30x faster!)
# Only backs up the 391 registry keys that Apply actually modifies
# Previous version: Complete snapshots (5-15 minutes, 50,000+ keys, 5MB)
# New version: Specific backup (30 seconds, 391 keys, 100KB)

Write-Host "[i] Creating specific registry backup (391 keys)..." -ForegroundColor Cyan
$startTime = Get-Date

try {
    $backup.Settings.RegistryBackup = Backup-SpecificRegistryKeys -RegistryChanges $script:RegistryChanges
    
    $elapsed = ((Get-Date) - $startTime).TotalSeconds
    $backedUpCount = ($backup.Settings.RegistryBackup | Where-Object { $_.Exists }).Count
    $notExistCount = $backup.Settings.RegistryBackup.Count - $backedUpCount
    
    Write-Host "[OK] Registry backup complete in $([Math]::Round($elapsed, 1))s" -ForegroundColor Green
    Write-Host "  - $backedUpCount keys backed up (existed before)" -ForegroundColor Gray
    Write-Host "  - $notExistCount keys tracked (will be created by Apply)" -ForegroundColor Gray
}
catch {
    Write-Host "[ERROR] Registry backup failed: $_" -ForegroundColor Red
    $backup.Settings.RegistryBackup = @()
}

Write-Host ""
#endregion

#region ASR Rules Backup (Attack Surface Reduction)
Write-Host "[10/16] $(Get-LocalizedString 'BackupASRTitle')" -ForegroundColor Yellow

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
Write-Host "[11/16] $(Get-LocalizedString 'BackupExploitTitle')" -ForegroundColor Yellow

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
Write-Host "[12/16] $(Get-LocalizedString 'BackupDohTitle')" -ForegroundColor Yellow

$dohBackup = @{
    Servers = @()
    Enabled = $false
    EnableAutoDoh = $null  # Registry value (0/1/2)
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
        
        # CRITICAL: Also backup EnableAutoDoh registry value
        # IMPORTANT: Use PSObject.Properties pattern to avoid error records!
        # Get-ItemProperty with -Name creates error even with -ErrorAction SilentlyContinue
        $dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        try {
            $dnsRegItem = Get-ItemProperty -Path $dnsRegPath -ErrorAction SilentlyContinue
            if ($dnsRegItem -and ($dnsRegItem.PSObject.Properties.Name -contains 'EnableAutoDoh')) {
                $dohBackup.EnableAutoDoh = $dnsRegItem.EnableAutoDoh
                Write-Verbose "Backed up EnableAutoDoh = $($dnsRegItem.EnableAutoDoh)"
            }
            else {
                Write-Verbose "EnableAutoDoh registry value not found (will use default on restore)"
            }
        }
        catch {
            Write-Verbose "Could not access DNS registry path: $_"
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
Write-Host "[13/16] $(Get-LocalizedString 'BackupDohEncryptionTitle')" -ForegroundColor Yellow

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
            # CRITICAL: Include ALL 4 DNS providers (not just Cloudflare!)
            $ipv4Servers = @(
                '1.1.1.1', '1.0.0.1',              # Cloudflare
                '94.140.14.14', '94.140.15.15',    # AdGuard
                '45.90.28.0', '45.90.30.0',        # NextDNS
                '9.9.9.9', '149.112.112.112'       # Quad9
            )
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
            # CRITICAL: Include ALL 4 DNS providers (not just Cloudflare!)
            $ipv6Servers = @(
                '2606:4700:4700::1111', '2606:4700:4700::1001',  # Cloudflare
                '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff',        # AdGuard
                '2a07:a8c0::', '2a07:a8c1::',                    # NextDNS
                '2620:fe::fe', '2620:fe::9'                       # Quad9
            )
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
Write-Host "[14/16] $(Get-LocalizedString 'BackupFirewallProfilesTitle')" -ForegroundColor Yellow

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

#region Device-Level App Permissions Backup
Write-Host "[15/16] Backing up Device-Level App Permissions..." -ForegroundColor Yellow

# CRITICAL FIX v1.7.17: Re-add Device-Level backup WITH ownership management
# Previous version removed this backup claiming "TrustedInstaller-protected"
# BUT: Restore script expects this data! Without backup, Restore cannot restore original state!
# SOLUTION: Backup with graceful degradation (skip Access Denied entries)

$deviceLevelBackup = @{
    Apps = @()
    Enabled = $false
}

try {
    # Permissions we modify (only these need backup)
    $permissions = @('webcam', 'microphone')
    
    foreach ($permission in $permissions) {
        $capabilityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\$permission\Apps"
        
        if (Test-Path $capabilityPath) {
            $apps = Get-ChildItem -Path $capabilityPath -ErrorAction SilentlyContinue
            
            foreach ($app in $apps) {
                try {
                    # Try to read EnabledByUser value
                    $item = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
                    
                    # Check if EnabledByUser exists using PSObject.Properties pattern
                    if ($item -and ($item.PSObject.Properties.Name -contains 'EnabledByUser')) {
                        $deviceLevelBackup.Apps += @{
                            Permission = $permission
                            AppName = $app.PSChildName
                            EnabledByUser = $item.EnabledByUser
                            Exists = $true
                        }
                        Write-Verbose "  [OK] Backed up: $permission/$($app.PSChildName) = $($item.EnabledByUser)"
                    }
                }
                catch {
                    # Access Denied (TrustedInstaller) - skip silently
                    Write-Verbose "  [SKIP] $permission/$($app.PSChildName) - Access Denied (protected)"
                }
            }
        }
    }
    
    if ($deviceLevelBackup.Apps.Count -gt 0) {
        $deviceLevelBackup.Enabled = $true
        Write-Host "  [OK] $($deviceLevelBackup.Apps.Count) device-level app permissions backed up" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] No device-level app permissions found (or all Access Denied)" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "Could not backup device-level app permissions: $_"
    $deviceLevelBackup.Enabled = $false
}

$backup.Settings.DeviceLevelApps = $deviceLevelBackup
Write-Host ""
#endregion

#region Power Management Settings Backup
Write-Host "[16/16] Backing up Power Management Settings..." -ForegroundColor Yellow

$powerBackup = @{
    Settings = @{}
    Enabled = $false
}

try {
    # Get current active power scheme GUID
    $activeScheme = powercfg /getactivescheme
    if ($activeScheme -match '([0-9a-f-]{36})') {
        $powerBackup.Settings.ActiveSchemeGUID = $matches[1]
        
        # Query detailed settings for the active scheme
        $query = powercfg /query $($powerBackup.Settings.ActiveSchemeGUID)
        
        # Parse Monitor Timeout (AC) - Support both English and German
        if ($query -match '(Turn off display after|Bildschirm ausschalten nach)[\s\S]*?Current AC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.MonitorTimeoutAC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse Monitor Timeout (DC/Battery) - Support both English and German
        if ($query -match '(Turn off display after|Bildschirm ausschalten nach)[\s\S]*?Current DC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.MonitorTimeoutDC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse Sleep/Standby Timeout (AC) - Support both English and German
        if ($query -match '(Sleep after|Energie sparen nach|Standbymodus nach)[\s\S]*?Current AC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.StandbyTimeoutAC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse Sleep/Standby Timeout (DC) - Support both English and German
        if ($query -match '(Sleep after|Energie sparen nach|Standbymodus nach)[\s\S]*?Current DC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.StandbyTimeoutDC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse Hibernate Timeout (AC) - Support both English and German
        if ($query -match '(Hibernate after|Ruhezustand nach)[\s\S]*?Current AC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.HibernateTimeoutAC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse Hibernate Timeout (DC) - Support both English and German
        if ($query -match '(Hibernate after|Ruhezustand nach)[\s\S]*?Current DC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.HibernateTimeoutDC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse CONSOLELOCK (Require password on wake) - AC - Support both English and German
        if ($query -match '(Require a password on wakeup|Kennwort beim Aufwachen anfordern)[\s\S]*?Current AC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.ConsoleLockAC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Parse CONSOLELOCK (Require password on wake) - DC - Support both English and German
        if ($query -match '(Require a password on wakeup|Kennwort beim Aufwachen anfordern)[\s\S]*?Current DC Power Setting Index: 0x([0-9a-f]+)') {
            $powerBackup.Settings.ConsoleLockDC = [Convert]::ToInt32($matches[2], 16)
        }
        
        # Check if Hibernate is enabled
        $hibernateStatus = powercfg /availablesleepstates
        $powerBackup.Settings.HibernateEnabled = $hibernateStatus -match 'Hibernate'
        
        $powerBackup.Enabled = $true
        Write-Host "  [OK] Power settings backed up (Scheme: $($powerBackup.Settings.ActiveSchemeGUID))" -ForegroundColor Green
        
        # Safe property access for verbose output
        $props = $powerBackup.Settings.PSObject.Properties.Name
        if ('MonitorTimeoutAC' -in $props) {
            Write-Verbose "    Monitor Timeout AC: $($powerBackup.Settings.MonitorTimeoutAC) min"
        }
        if ('HibernateTimeoutAC' -in $props) {
            Write-Verbose "    Hibernate Timeout AC: $($powerBackup.Settings.HibernateTimeoutAC) min"
        }
    }
    else {
        Write-Host "  [WARNING] Could not detect active power scheme" -ForegroundColor Yellow
        $powerBackup.Enabled = $false
    }
}
catch {
    Write-Warning "Could not backup power settings: $_"
    $powerBackup.Enabled = $false
}

$backup.Settings.PowerManagement = $powerBackup
Write-Host ""
#endregion

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
    $regBackupCount = if ($backup.Settings.RegistryBackup) { $backup.Settings.RegistryBackup.Count } else { 0 }
    $asrCountSummary = if ($backup.Settings.ASRRules.Rules) { @($backup.Settings.ASRRules.Rules).Count } else { 0 }
    Write-Host "  - DNS: $dnsCountSummary" -ForegroundColor Gray
    Write-Host "  - Hosts: $($null -ne $backup.Settings.HostsFile)" -ForegroundColor Gray
    Write-Host "  - Apps: $appsCountSummary" -ForegroundColor Gray
    Write-Host "  - Services: $servicesCountSummary" -ForegroundColor Gray
    Write-Host "  - Scheduled Tasks: $tasksCountSummary" -ForegroundColor Gray
    Write-Host "  - Firewall: $fwCountSummary" -ForegroundColor Gray
    Write-Host "  - Users: $usersCountSummary" -ForegroundColor Gray
    Write-Host "  - Registry Backup: $regBackupCount specific keys" -ForegroundColor Gray
    Write-Host "  - ASR Rules: $asrCountSummary" -ForegroundColor Gray
    Write-Host "  - Exploit Protection: $($backup.Settings.ExploitProtection.Enabled)" -ForegroundColor Gray
    $dohServersSummary = if ($backup.Settings.DoH.Servers) { @($backup.Settings.DoH.Servers).Count } else { 0 }
    $dohAdaptersSummary = if ($backup.Settings.DohEncryption.Adapters) { @($backup.Settings.DohEncryption.Adapters).Count } else { 0 }
    $fwProfilesSummary = if ($backup.Settings.FirewallProfiles.Profiles) { @($backup.Settings.FirewallProfiles.Profiles).Count } else { 0 }
    Write-Host "  - DoH Servers: $dohServersSummary" -ForegroundColor Gray
    Write-Host "  - DoH Encryption: $dohAdaptersSummary Adapter" -ForegroundColor Gray
    Write-Host "  - Firewall Profiles: $fwProfilesSummary" -ForegroundColor Gray
    Write-Host "  - Power Management: $($backup.Settings.PowerManagement.Enabled)" -ForegroundColor Gray
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
        if ($testParse.Settings.DNS -or $testParse.Settings.Services -or $testParse.Settings.RegistryBackup) {
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
    
    # Stop transcript logging
    if ($script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[i] Log saved: $script:transcriptPath" -ForegroundColor Cyan
        }
        catch {
            # Ignore transcript stop errors
        }
    }
    
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
        
        # Stop transcript logging
        if ($script:transcriptStarted) {
            try {
                Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[i] Log saved: $script:transcriptPath" -ForegroundColor Cyan
            }
            catch {
                # Ignore transcript stop errors
            }
        }
        
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 0
        return
    }
    else {
        Write-Host "$(Get-LocalizedString 'BackupErrorUserAborted')" -ForegroundColor Green
        Write-Host "$(Get-LocalizedString 'BackupErrorWillNotContinue')" -ForegroundColor Green
        Write-Host ""
        
        # Stop transcript logging
        if ($script:transcriptStarted) {
            try {
                Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[i] Log saved: $script:transcriptPath" -ForegroundColor Cyan
            }
            catch {
                # Ignore transcript stop errors
            }
        }
        
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 1
        return
    }
}
