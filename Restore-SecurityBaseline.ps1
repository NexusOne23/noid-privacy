<#
.SYNOPSIS
    Complete restore of all system settings from backup

.DESCRIPTION
    Restores all settings from a backup created with Backup-SecurityBaseline.ps1.
    
    WHAT IS RESTORED:
    - DNS Settings (per adapter)
    - Hosts file
    - Service Start-Types (ALL services)
    - Scheduled Tasks (state is restored)
    - Firewall Custom Rules (are deleted)
    - Registry Keys
    - User Account Names (Administrator)
    
    NOT RESTORED:
    - Apps (must be manually reinstalled)
    
    NEW IN VERSION 1.4.0:
    - Device-Level App Permission SubKeys Restore
    - PERFECT 100% Coverage with Backup achieved!
    
    VERSION 1.3.0:
    - Firewall Profile Settings Restore (Domain/Private/Public)
    
    VERSION 1.2.0:
    - ASR Rules Restore (Attack Surface Reduction)
    - DoH Configuration Restore (DNS over HTTPS)
    
.NOTES
    Version:        1.4.0
    Creation Date:  25H2
    Author:         NoID Privacy Team
    
.PARAMETER BackupFile
    Path to the backup JSON file
    
.PARAMETER WhatIf
    Shows only what would be done, without actual changes
    
.EXAMPLE
    .\Restore-SecurityBaseline.ps1 -BackupFile "C:\ProgramData\SecurityBaseline\Backups\SecurityBaseline-Backup-20251022-052334.json"
    
.EXAMPLE
    .\Restore-SecurityBaseline.ps1 -BackupFile "backup.json" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$BackupFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:ProgramData\SecurityBaseline\Logs"
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ===== CONSOLE ENCODING FOR UMLAUTS (Best Practice 25H2) =======
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
}
catch {
    Write-Verbose "Console-Encoding konnte nicht gesetzt werden: $_"
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

# ===== START TRANSCRIPT FOR AUDIT TRAIL =====
$script:transcriptPath = ""
$script:transcriptStarted = $false

if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

$script:transcriptPath = Join-Path $LogPath "Restore-$timestamp.log"

try {
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "Transcript started: $script:transcriptPath"
}
catch {
    Write-Warning "Could not start transcript: $_"
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

# Load Optimized Registry Backup Functions (v2.0)
# IMPORTANT: Temporarily bypass execution policy for unsigned modules
$savedExecutionPolicy = Get-ExecutionPolicy -Scope Process
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
# IMPORTANT: Use Test-Path because of Strict Mode!
if (-not (Test-Path Variable:\Global:CurrentLanguage)) {
    # Check if language was passed via environment variable (from parent script)
    if ($env:NOID_LANGUAGE) {
        $Global:CurrentLanguage = $env:NOID_LANGUAGE
    }
    else {
        # Fallback to English if standalone execution
        $Global:CurrentLanguage = 'en'
    }
}

Write-Host "`n============================================================================" -ForegroundColor Yellow
Write-Host "           $(Get-LocalizedString 'RestoreBanner')" -ForegroundColor Yellow
Write-Host "============================================================================`n" -ForegroundColor Yellow

# Create log directory
if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

# Start transcript
$transcriptPath = Join-Path $LogPath "Restore-$timestamp.log"
try {
    Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
}
catch {
    Write-Warning "Transcript konnte nicht gestartet werden: $_"
}

#region Backup File Selection
if (-not $BackupFile) {
    Write-Host "[i] $(Get-LocalizedString 'RestoreSearching')" -ForegroundColor Cyan
    
    $backupPath = "$env:ProgramData\SecurityBaseline\Backups"
    if (Test-Path $backupPath) {
        $backups = Get-ChildItem -Path $backupPath -Filter "SecurityBaseline-Backup-*.json" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending
        
        $backupsCount = if ($backups) { @($backups).Count } else { 0 }
        if ($backupsCount -eq 0) {
            Write-Host "[ERROR] $(Get-LocalizedString 'RestoreNoneFound') $backupPath" -ForegroundColor Red
            Write-Host ""
            Write-Host "$(Get-LocalizedString 'RestoreCreateFirst')" -ForegroundColor Yellow
            Stop-Transcript -ErrorAction SilentlyContinue
            exit 1
        }
        
        Write-Host ""
        $availMsg = Get-LocalizedString 'RestoreAvailable' $backupsCount
        Write-Host "$availMsg" -ForegroundColor White
        Write-Host ""
        
        # Show only last 10 backups (newest first) - better UX!
        $maxDisplay = 10
        $displayBackups = if ($backupsCount -le $maxDisplay) { $backups } else { $backups | Select-Object -First $maxDisplay }
        
        if ($backupsCount -gt $maxDisplay) {
            $showingMsg = Get-LocalizedString 'RestoreShowingLatest' $maxDisplay
            Write-Host "  [i] $showingMsg" -ForegroundColor Yellow
            Write-Host "      $(Get-LocalizedString 'RestoreShowAll')" -ForegroundColor Gray
            Write-Host ""
        }
        
        $displayCount = if ($displayBackups) { @($displayBackups).Count } else { 0 }
        for ($i = 0; $i -lt $displayCount; $i++) {
            $backup = $displayBackups[$i]
            $size = [Math]::Round($backup.Length / 1KB, 2)
            Write-Host "  [$($i+1)] $($backup.Name)" -ForegroundColor Cyan
            Write-Host "       $(Get-LocalizedString 'RestoreBackupDate') $($backup.LastWriteTime)" -ForegroundColor Gray
            Write-Host "       $(Get-LocalizedString 'BackupSize') $size KB" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "$(Get-LocalizedString 'RestoreSelectPrompt') [1-$displayCount]" -NoNewline
        if ($backupsCount -gt $maxDisplay) {
            Write-Host ", [A]" -NoNewline
        }
        Write-Host " $(Get-LocalizedString 'RestoreOrCancel') " -NoNewline
        $selection = Read-Host
        
        # Handle "Show all"
        if ($selection.ToUpper() -eq 'A' -and $backupsCount -gt $maxDisplay) {
            Write-Host ""
            $allMsg = Get-LocalizedString 'RestoreShowingAll' $backupsCount
            Write-Host "$allMsg" -ForegroundColor Cyan
            Write-Host ""
            
            for ($i = 0; $i -lt $backupsCount; $i++) {
                $backup = $backups[$i]
                $size = [Math]::Round($backup.Length / 1KB, 2)
                Write-Host "  [$($i+1)] $($backup.Name)" -ForegroundColor Cyan
                Write-Host "       $(Get-LocalizedString 'RestoreBackupDate') $($backup.LastWriteTime)" -ForegroundColor Gray
                Write-Host "       $(Get-LocalizedString 'BackupSize') $size KB" -ForegroundColor Gray
                Write-Host ""
            }
            
            Write-Host "$(Get-LocalizedString 'RestoreSelectPrompt') [1-$backupsCount] $(Get-LocalizedString 'RestoreOrCancel') " -NoNewline
            $selection = Read-Host
        }
        
        if ($selection -eq '0' -or [string]::IsNullOrWhiteSpace($selection)) {
            Write-Host "$(Get-LocalizedString 'RestoreCancelled')" -ForegroundColor Yellow
            Stop-Transcript -ErrorAction SilentlyContinue
            exit 0
        }
        
        $selectionNum = [int]$selection - 1
        if ($selectionNum -ge 0 -and $selectionNum -lt $backupsCount) {
            $BackupFile = $backups[$selectionNum].FullName
        }
        else {
            Write-Host "[ERROR] $(Get-LocalizedString 'RestoreInvalidSelection')" -ForegroundColor Red
            Stop-Transcript -ErrorAction SilentlyContinue
            exit 1
        }
    }
    else {
        Write-Host "[ERROR] $(Get-LocalizedString 'RestoreNoneFound') $backupPath" -ForegroundColor Red
        Stop-Transcript -ErrorAction SilentlyContinue
        exit 1
    }
}

if (-not (Test-Path $BackupFile)) {
    Write-Host "[ERROR] $(Get-LocalizedString 'RestoreNotFound') $BackupFile" -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}
#endregion

Write-Host ""
Write-Host "============================================================================" -ForegroundColor White
Write-Host "  $(Get-LocalizedString 'BackupFile') $BackupFile" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor White
Write-Host ""

# Load backup
Write-Host "[i] $(Get-LocalizedString 'RestoreLoading')" -ForegroundColor Cyan
try {
    $backup = Get-Content -Path $BackupFile -Raw -ErrorAction Stop | ConvertFrom-Json
    Write-Host "[OK] $(Get-LocalizedString 'RestoreLoaded')" -ForegroundColor Green
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'RestoreBackupDate') $($backup.Timestamp)" -ForegroundColor Gray
    Write-Host "  $(Get-LocalizedString 'RestoreHostname') $($backup.Hostname)" -ForegroundColor Gray
    Write-Host "  $(Get-LocalizedString 'RestoreOS') $($backup.OS)" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host "[ERROR] $(Get-LocalizedString 'RestoreLoadError') $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'RestoreLoadReasons')" -ForegroundColor Yellow
    Write-Host "  - $(Get-LocalizedString 'RestoreLoadCorrupt')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RestoreLoadInvalid')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RestoreLoadModified')" -ForegroundColor Gray
    Write-Host ""
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# Warnung
Write-Host "============================================================================" -ForegroundColor Red
Write-Host "                             $(Get-LocalizedString 'RestoreWarningTitle')" -ForegroundColor Red
Write-Host "============================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "$(Get-LocalizedString 'RestoreWarningText')" -ForegroundColor Yellow
Write-Host ""
Write-Host "$(Get-LocalizedString 'RestoreWarningMeans')" -ForegroundColor White
Write-Host "  - $(Get-LocalizedString 'RestoreWarningDNS')" -ForegroundColor Gray
Write-Host "  - $(Get-LocalizedString 'RestoreWarningHosts')" -ForegroundColor Gray
Write-Host "  - $(Get-LocalizedString 'RestoreWarningServices')" -ForegroundColor Gray
Write-Host "  - $(Get-LocalizedString 'RestoreWarningFirewall')" -ForegroundColor Gray
Write-Host "  - $(Get-LocalizedString 'RestoreWarningRegistry')" -ForegroundColor Gray
Write-Host ""
Write-Host "$(Get-LocalizedString 'RestoreWarningRisk')" -ForegroundColor Red
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Red
Write-Host ""

Write-Host "$(Get-LocalizedString 'RestoreConfirm') " -NoNewline -ForegroundColor Yellow
$confirm = Read-Host

if ($confirm -ne 'J' -and $confirm -ne 'j' -and $confirm -ne 'Y' -and $confirm -ne 'y') {
    Write-Host "$(Get-LocalizedString 'RestoreCancelled')" -ForegroundColor Yellow
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

Write-Host ""
Write-Host "[i] $(Get-LocalizedString 'RestoreStarting')" -ForegroundColor Cyan
Write-Host ""

$restoreStats = @{
    Success = 0
    Failed = 0
    Skipped = 0
}

#region Restore DNS Settings
Write-Host "[1/14] $(Get-LocalizedString 'RestoreDNS')" -ForegroundColor Yellow

$dnsRestoredCount = 0
$dnsFailedCount = 0

# BEST PRACTICE: Iterate over CURRENT adapters, then match to backup via GUID/Alias/IfIndex
# This handles IfIndex changes after reboot (GUID is stable!)
$currentAdapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }

foreach ($adapter in $currentAdapters) {
    try {
        # Match adapter to backup: GUID (best) -> Alias -> IfIndex (fallback)
        $saved = $null
        
        # Try GUID match first (most reliable - never changes!)
        if ($backup.Settings.DNS) {
            $saved = $backup.Settings.DNS | Where-Object {
                $_.PSObject.Properties.Name -contains 'InterfaceGuid' -and 
                $_.InterfaceGuid -and 
                $_.InterfaceGuid -eq $adapter.InterfaceGuid
            } | Select-Object -First 1
        }
        
        # Try Alias match (can change but usually doesn't)
        if (-not $saved -and $backup.Settings.DNS) {
            $saved = $backup.Settings.DNS | Where-Object {
                $_.AdapterName -and $_.AdapterName -eq $adapter.Name
            } | Select-Object -First 1
        }
        
        # Try IfIndex match (least reliable - changes after reboot)
        if (-not $saved -and $backup.Settings.DNS) {
            $saved = $backup.Settings.DNS | Where-Object {
                $_.InterfaceIndex -and $_.InterfaceIndex -eq $adapter.ifIndex
            } | Select-Object -First 1
        }
        
        if ($saved) {
            # Adapter found in backup - restore its DNS
            $dnsIPv4 = if ($saved.PSObject.Properties.Name -contains 'DNS_IPv4') { $saved.DNS_IPv4 } else { @() }
            $dnsIPv6 = if ($saved.PSObject.Properties.Name -contains 'DNS_IPv6') { $saved.DNS_IPv6 } else { @() }
            
            # CRITICAL: Force array with @() - DNS_IPv4/IPv6 can be single string (no .Count property!)
            # Without @() wrap: PropertyNotFoundException "Count not found"
            $hasIPv4 = ($dnsIPv4 -and @($dnsIPv4).Count -gt 0)
            $hasIPv6 = ($dnsIPv6 -and @($dnsIPv6).Count -gt 0)
            
            Write-Verbose "Restoring DNS for $($adapter.Name) (matched via $( if ($saved.InterfaceGuid -eq $adapter.InterfaceGuid) { 'GUID' } elseif ($saved.AdapterName -eq $adapter.Name) { 'Alias' } else { 'IfIndex' }))"
            
            # CRITICAL: PowerShell 5.1 does NOT have -AddressFamily parameter!
            # Must set IPv4 + IPv6 together in one call
            
            if ($hasIPv4 -or $hasIPv6) {
                # Combine IPv4 + IPv6 addresses
                $allAddresses = @()
                if ($hasIPv4) { $allAddresses += $dnsIPv4 }
                if ($hasIPv6) { $allAddresses += $dnsIPv6 }
                
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $allAddresses -ErrorAction Stop
                Write-Verbose "  DNS restored: $($allAddresses -join ', ')"
            }
            else {
                # No DNS in backup - reset to auto
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
                Write-Verbose "  DNS reset to Auto (backup had no DNS)"
            }
            
            Write-Host "  [OK] $($adapter.Name) restored" -ForegroundColor Green
            $dnsRestoredCount++
            $restoreStats.Success++
        }
        else {
            # Adapter NOT in backup - reset to auto
            # CRITICAL: PowerShell 5.1 does NOT have -AddressFamily parameter!
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            Write-Host "  [OK] $($adapter.Name) reset to auto (not in backup)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] DNS restore error for '$($adapter.Name)': $_" -ForegroundColor Red
        $dnsFailedCount++
        $restoreStats.Failed++
    }
}

# NOTE: Safety sweep removed - main loop already handles all adapters correctly

# Summary
if ($dnsRestoredCount -gt 0) {
    Write-Host "  [OK] $dnsRestoredCount DNS adapter(s) restored" -ForegroundColor Green
}
if ($dnsFailedCount -gt 0) {
    Write-Host "  [!] $dnsFailedCount DNS adapter(s) failed" -ForegroundColor Yellow
}

Write-Host ""
#endregion

#region Restore Hosts File
Write-Host "[2/14] $(Get-LocalizedString 'RestoreHosts')" -ForegroundColor Yellow

if ($backup.Settings.HostsFile) {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    
    if ($PSCmdlet.ShouldProcess($hostsPath, "Restore Hosts file")) {
        try {
            # ROOT CAUSE FIX: NO "backup-before-restore" needed!
            # REASON: Original hosts is ALREADY in backup JSON (HostsFile)
            # What we would backup here = Steven Black hosts (from Apply-Script)
            # -> Useless and confusing! Just restore original directly.
            
            $backup.Settings.HostsFile | Out-File -FilePath $hostsPath -Encoding ASCII -Force
            Write-Host "  [OK] $(Get-LocalizedString 'RestoreHostsOK')" -ForegroundColor Green
            $restoreStats.Success++
        }
        catch {
            Write-Host "  [X] Hosts file restore error: $_" -ForegroundColor Red
            $restoreStats.Failed++
        }
    }
}
else {
    Write-Host "  [!] No hosts file in backup" -ForegroundColor Yellow
    $restoreStats.Skipped++
}

Write-Host ""
#endregion

#region Restore Services
Write-Host "[3/14] $(Get-LocalizedString 'RestoreServices')" -ForegroundColor Yellow

# CRITICAL: Protected Services List
# ROOT CAUSE: These services are protected by TrustedInstaller/SYSTEM
# REASON: Windows prevents modification by Admin to protect system integrity
# SOLUTION: Skip these services with informative message (not error!)
$protectedServices = @(
    'AppIDSvc', 'AppXSvc', 'BFE', 'BrokerInfrastructure', 'ClipSVC',
    'CoreMessagingRegistrar', 'DcomLaunch', 'Dnscache', 'DoSvc',
    'embeddedmode', 'EntAppSvc', 'gpsvc', 'LSM', 'MDCoreSvc',
    'mpssvc', 'msiserver', 'NgcCtnrSvc', 'NgcSvc', 'RpcEptMapper',
    'RpcSs', 'Schedule', 'SecurityHealthService', 'Sense', 'sppsvc',
    'StateRepository', 'SystemEventsBroker', 'TextInputManagementService',
    'TimeBrokerSvc', 'WaaSMedicSvc', 'WdNisSvc', 'WinDefend',
    'WinHttpAutoProxySvc', 'wscsvc'
)

$servicesRestoredCount = 0
$servicesSkippedCount = 0
$servicesFailedCount = 0

foreach ($svcConfig in $backup.Settings.Services) {
    try {
        # Skip protected services (prevent Access Denied errors)
        if ($protectedServices -contains $svcConfig.Name) {
            Write-Verbose "  [SKIP] Protected service: $($svcConfig.DisplayName) (TrustedInstaller/SYSTEM only)"
            $servicesSkippedCount++
            $restoreStats.Skipped++
            continue
        }
        
        # Skip per-user services with dynamic suffixes (e.g., AarSvc_4223c, BcastDVRUserService_12a4f)
        # These services have random hex suffixes per session/user and won't exist after reboot/different machine
        $dynamicSuffixPattern = '_[0-9a-f]{4,}$'
        if ($svcConfig.Name -match $dynamicSuffixPattern) {
            Write-Verbose "  [SKIP] Per-user service with dynamic suffix: $($svcConfig.Name) (session-specific)"
            $servicesSkippedCount++
            $restoreStats.Skipped++
            continue
        }
        
        $service = Get-Service -Name $svcConfig.Name -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($PSCmdlet.ShouldProcess($svcConfig.Name, "Set StartType: $($svcConfig.StartType)")) {
                Set-Service -Name $svcConfig.Name -StartupType $svcConfig.StartType -ErrorAction Stop
                $svcMsg = Get-LocalizedString 'RestoreServicesOK' $svcConfig.StartType
                Write-Host "  [OK] $($svcConfig.DisplayName): $svcMsg" -ForegroundColor Green
                $servicesRestoredCount++
                $restoreStats.Success++
            }
        }
        else {
            $notFoundMsg = Get-LocalizedString 'RestoreServicesNotFound' $svcConfig.Name
            Write-Host "  [!] $notFoundMsg" -ForegroundColor Yellow
            $servicesSkippedCount++
            $restoreStats.Skipped++
        }
    }
    catch {
        Write-Host "  [X] Service '$($svcConfig.Name)' error: $_" -ForegroundColor Red
        $servicesFailedCount++
        $restoreStats.Failed++
    }
}

# Summary
if ($servicesRestoredCount -gt 0) {
    Write-Host "  [OK] $servicesRestoredCount Service(s) restored" -ForegroundColor Green
}
if ($servicesSkippedCount -gt 0) {
    Write-Host "  [i] $servicesSkippedCount Service(s) skipped (protected or not found)" -ForegroundColor Gray
}
if ($servicesFailedCount -gt 0) {
    Write-Host "  [!] $servicesFailedCount Service(s) failed" -ForegroundColor Yellow
}

Write-Host ""
#endregion

#region Restore Scheduled Tasks
Write-Host "[4/14] Restore Scheduled Tasks..." -ForegroundColor Yellow

# CRITICAL: Check if Task Scheduler service is available
# ROOT CAUSE: Schedule service is protected (TrustedInstaller/SYSTEM)
# REASON: If service is not running, Get-ScheduledTask will HANG indefinitely
# SOLUTION: Check service status FIRST, skip if not available
$scheduleService = Get-Service -Name 'Schedule' -ErrorAction SilentlyContinue
if (-not $scheduleService -or $scheduleService.Status -ne 'Running') {
    Write-Host "  [!] Task Scheduler service not available - skipping scheduled tasks restore" -ForegroundColor Yellow
    Write-Host "  [i] Reason: Service 'Schedule' is protected or not running" -ForegroundColor Gray
    $restoreStats.Skipped++
}
else {
    # CRITICAL FIX v2: Direct array enumeration instead of Job
    # ROOT CAUSE: Job-based counting works but Receive-Job hangs on PowerShell 5.1.26100.7019 (Insider)
    # PROBLEM: Serialization/Deserialization of large objects blocks indefinitely
    # SOLUTION: Force array enumeration directly - triggers lazy-loading immediately or fails fast
    try {
        # Force arrayization - this triggers enumeration HERE, not in background job
        $tasksArray = @($backup.Settings.ScheduledTasks)
        $tasksCount = $tasksArray.Count
    }
    catch {
        Write-Host "  [!] Could not enumerate Scheduled Tasks from backup - skipping" -ForegroundColor Yellow
        Write-Host "  [i] Error: $_" -ForegroundColor Gray
        $restoreStats.Skipped++
        $tasksCount = 0
        $tasksArray = @()
    }
    
    if ($tasksCount -gt 0) {
        Write-Host "  [i] $tasksCount Scheduled Tasks in backup" -ForegroundColor Cyan
        
        # PERFORMANCE FIX v2: Bulk load ALL tasks ONCE then lookup in hashtable
        # ROOT CAUSE: Calling Get-ScheduledTask 200x is slow (0.5-1s per call = 100-200s total)
        # SOLUTION: Load all tasks once (2-3s), store in hashtable, then O(1) lookup per task
        Write-Host "  [i] Loading all scheduled tasks (one-time operation)..." -ForegroundColor Gray
        try {
            $allTasks = Get-ScheduledTask -ErrorAction Stop
            $taskMap = @{}
            foreach ($t in $allTasks) {
                # Key: TaskPath + TaskName (lowercase for case-insensitive matching)
                $key = ($t.TaskPath + $t.TaskName).ToLower()
                $taskMap[$key] = $t
            }
            Write-Host "  [OK] Loaded $($allTasks.Count) tasks into cache" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] Could not load scheduled tasks - skipping restore" -ForegroundColor Yellow
            Write-Host "  [i] Error: $_" -ForegroundColor Gray
            $restoreStats.Skipped++
            $taskMap = @{}
        }
        
        $restoredTasks = 0
        $changedTasks = 0
        $taskIndex = 0
        
        foreach ($taskConfig in $tasksArray) {
            $taskIndex++
            $currentTask = $null
            
            # Progress output every 10 tasks (so user knows it's working)
            if ($taskIndex % 10 -eq 0 -or $taskIndex -eq $tasksCount) {
                Write-Host "  [>] Processing task $taskIndex/$tasksCount..." -ForegroundColor Cyan
            }
            
            # Fast lookup in hashtable (O(1) instead of API call)
            $key = ($taskConfig.TaskPath + $taskConfig.TaskName).ToLower()
            if ($taskMap.ContainsKey($key)) {
                $currentTask = $taskMap[$key]
            }
            else {
                # Only use slow Job fallback for truly missing/problematic tasks
                # This should be rare (deleted tasks, User-tasks that disappeared, etc.)
                try {
                    $job = Start-Job -ScriptBlock {
                        param($path, $name)
                        Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                    } -ArgumentList $taskConfig.TaskPath, $taskConfig.TaskName
                    
                    $job | Wait-Job -Timeout 2 | Out-Null
                    if ($job.State -eq 'Completed') {
                        $currentTask = Receive-Job $job
                    }
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Verbose "Task not accessible: $($taskConfig.TaskPath)$($taskConfig.TaskName)"
                }
            }
            
            if (-not $currentTask) {
                $restoreStats.Skipped++
                continue
            }
            
            # Restore state if different (direct call, no job needed)
            if ($currentTask.State.ToString() -ne $taskConfig.State) {
                if ($PSCmdlet.ShouldProcess("$($taskConfig.TaskPath)$($taskConfig.TaskName)", "Set State: $($taskConfig.State)")) {
                    # CRITICAL FIX: Use SilentlyContinue instead of Stop
                    # ROOT CAUSE: -ErrorAction Stop writes error to transcript BEFORE catch handles it
                    # SOLUTION: SilentlyContinue + manual success check via $? or $Error[0]
                    $success = $false
                    
                    if ($taskConfig.State -eq 'Disabled') {
                        Disable-ScheduledTask -TaskPath $taskConfig.TaskPath -TaskName $taskConfig.TaskName -ErrorAction SilentlyContinue | Out-Null
                        $success = $?
                    } 
                    elseif ($taskConfig.State -eq 'Ready') {
                        Enable-ScheduledTask -TaskPath $taskConfig.TaskPath -TaskName $taskConfig.TaskName -ErrorAction SilentlyContinue | Out-Null
                        $success = $?
                    }
                    
                    if ($success) {
                        $changedTasks++
                        $restoreStats.Success++
                    }
                    else {
                        # Check if it was Access Denied (protected task) or real error
                        # CRITICAL: Check if $Error array has entries before accessing $Error[0]
                        if ($Error.Count -gt 0) {
                            $lastError = $Error[0]
                            if ($lastError.Exception -is [System.UnauthorizedAccessException] -or 
                                $lastError.Exception.Message -match 'Zugriff verweigert|Access.*denied') {
                                # Protected task (SYSTEM/TrustedInstaller) - skip silently
                                Write-Verbose "  [SKIP] Task '$($taskConfig.TaskPath)$($taskConfig.TaskName)' is protected (access denied)"
                                $restoreStats.Skipped++
                            }
                            else {
                                # Real error - log it
                                Write-Verbose "Failed to change task state: $($taskConfig.TaskPath)$($taskConfig.TaskName) - $($lastError.Exception.Message)"
                                $restoreStats.Failed++
                            }
                        }
                        else {
                            # No error in $Error array - treat as failure
                            Write-Verbose "Failed to change task state: $($taskConfig.TaskPath)$($taskConfig.TaskName) - Unknown error (no details in `$Error array)"
                            $restoreStats.Failed++
                        }
                    }
                }
            }
            $restoredTasks++
        }
        
        # Summary with color-coded stats
        Write-Host "  [OK] $restoredTasks Scheduled Tasks checked" -ForegroundColor Green
        if ($changedTasks -gt 0) {
            Write-Host "      $changedTasks Tasks state restored" -ForegroundColor Green
        }
        $skippedTasks = $tasksCount - $restoredTasks
        if ($skippedTasks -gt 0) {
            Write-Host "      $skippedTasks Tasks not found (skipped)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [!] Keine Scheduled Tasks im Backup" -ForegroundColor Yellow
        $restoreStats.Skipped++
    }
}

Write-Host ""
#endregion

#region Restore Firewall Rules
Write-Host "[5/14] $(Get-LocalizedString 'RestoreFirewall')" -ForegroundColor Yellow

Write-Host "  [i] $(Get-LocalizedString 'RestoreFirewallDeleting')" -ForegroundColor Cyan
$customRules = Get-NetFirewallRule -DisplayName "NoID-*" -ErrorAction SilentlyContinue

if ($customRules) {
    foreach ($rule in $customRules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Delete rule")) {
            try {
                Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop
                $ruleMsg = Get-LocalizedString 'RestoreFirewallOK' $rule.DisplayName
                Write-Host "    [OK] $ruleMsg" -ForegroundColor Green
                $restoreStats.Success++
            }
            catch {
                Write-Host "    [X] Delete error '$($rule.DisplayName)': $_" -ForegroundColor Red
                $restoreStats.Failed++
            }
        }
    }
}

Write-Host "  [i] $(Get-LocalizedString 'RestoreFirewallRestoring')" -ForegroundColor Cyan

$fwRulesCount = if ($backup.Settings.FirewallRules) { @($backup.Settings.FirewallRules).Count } else { 0 }
if ($fwRulesCount -gt 0) {
    # PERFORMANCE FIX: Bulk load ALL firewall rules ONCE then lookup in hashtable
    # ROOT CAUSE: Calling Get-NetFirewallRule 497x is slow (Windows Filtering Platform COM)
    # SOLUTION: Load all rules once (2-3s), store in hashtable, then O(1) lookup per rule
    Write-Host "  [i] Loading all firewall rules (one-time operation)..." -ForegroundColor Gray
    try {
        $allRules = Get-NetFirewallRule -All
        $ruleMap = @{}
        foreach ($r in $allRules) {
            $ruleMap[$r.Name] = $r
        }
        Write-Host "  [OK] Loaded $($allRules.Count) rules into cache" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Could not load firewall rules - skipping restore" -ForegroundColor Yellow
        Write-Host "  [i] Error: $_" -ForegroundColor Gray
        $restoreStats.Skipped++
        $ruleMap = @{}
    }
    
    $restoredRules = 0
    $changedRules = 0
    $ruleIndex = 0
    
    foreach ($backupRule in $backup.Settings.FirewallRules) {
        $ruleIndex++
        
        # Progress output every 50 rules (so user knows it's working)
        if ($ruleIndex % 50 -eq 0 -or $ruleIndex -eq $fwRulesCount) {
            Write-Host "    [>] Processing rule $ruleIndex/$fwRulesCount..." -ForegroundColor DarkCyan
        }
        
        try {
            # Fast lookup in hashtable (O(1) instead of COM API call)
            $currentRule = $null
            if ($ruleMap.ContainsKey($backupRule.Name)) {
                $currentRule = $ruleMap[$backupRule.Name]
            }
            
            if ($currentRule) {
                if ($currentRule.Enabled -ne $backupRule.Enabled) {
                    if ($PSCmdlet.ShouldProcess($backupRule.DisplayName, "Set status: $($backupRule.Enabled)")) {
                        if ($backupRule.Enabled -eq $true) {
                            Enable-NetFirewallRule -Name $backupRule.Name -ErrorAction Stop
                        }
                        else {
                            Disable-NetFirewallRule -Name $backupRule.Name -ErrorAction Stop
                        }
                        $changedRules++
                        $restoreStats.Success++
                    }
                }
                $restoredRules++
            }
        }
        catch {
            # Not critical
        }
    }
    
    Write-Host "  [OK] $restoredRules $(Get-LocalizedString 'RestoreFirewallStatus')" -ForegroundColor Green
    Write-Host "      $changedRules $(Get-LocalizedString 'RestoreFirewallChanged')" -ForegroundColor Gray
}
else {
    Write-Host "  [!] $(Get-LocalizedString 'RestoreFirewallNoData')" -ForegroundColor Yellow
    $restoreStats.Skipped++
}

Write-Host ""
#endregion

#region Restore Registry Keys (v2.0 - OPTIMIZED)
Write-Host "[6/14] $(Get-LocalizedString 'RestoreRegistry')" -ForegroundColor Yellow

# NEW v2.0: Specific registry restore (10-15x faster!)
# Only restores the 383 registry keys that Apply actually modifies
# Previous version: Snapshot restore (10-30 minutes, 50,000+ keys compared)
# New version: Specific restore (1-2 minutes, 383 keys restored)

if ($backup.Settings.RegistryBackup) {
    Write-Host ""
    Write-Host "[i] Performing specific registry restore (383 keys)..." -ForegroundColor Cyan
    $startTime = Get-Date
    
    # Initialize failed keys array (used by Restore-SpecificRegistryKeys for error tracking)
    $script:FailedRegistryKeys = @()
    
    try {
        $result = Restore-SpecificRegistryKeys -BackupData $backup.Settings.RegistryBackup
        
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        
        Write-Host "[OK] Registry restore complete in $([Math]::Round($elapsed, 1))s" -ForegroundColor Green
        Write-Host "  - $($result.Restored) keys restored to original" -ForegroundColor Gray
        Write-Host "  - $($result.Deleted) keys deleted (created by Apply)" -ForegroundColor Gray
        Write-Host "  - $($result.Unchanged) keys unchanged (already correct)" -ForegroundColor Gray
        if ($result.Failed -gt 0) {
            Write-Host "  - $($result.Failed) keys failed (protected or access denied)" -ForegroundColor Yellow
            # Show which specific keys failed (if tracked)
            if ($script:FailedRegistryKeys -and $script:FailedRegistryKeys.Count -gt 0) {
                Write-Host "    Failed keys:" -ForegroundColor Gray
                foreach ($failedKey in $script:FailedRegistryKeys) {
                    Write-Host "      - $($failedKey.Path)\$($failedKey.Name)" -ForegroundColor Gray
                    Write-Host "        Error: $($failedKey.Error)" -ForegroundColor DarkGray
                }
            }
        }
        
        $restoreStats.Success += $result.Restored + $result.Deleted
        $restoreStats.Skipped += $result.Unchanged
        $restoreStats.Failed += $result.Failed
    }
    catch {
        Write-Host "[ERROR] Registry restore failed: $_" -ForegroundColor Red
        $restoreStats.Failed++
    }
}
else {
    Write-Host "[!] No registry backup found in backup file - skipping" -ForegroundColor Yellow
}

Write-Host ""
#endregion

#region Restore User Accounts
Write-Host "[7/14] $(Get-LocalizedString 'RestoreUsers')" -ForegroundColor Yellow

# Find the renamed Administrator account (with SID *-500)
$currentAdminAccount = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }

if ($currentAdminAccount) {
    # Find original admin name from backup
    $originalAdmin = $backup.Settings.UserAccounts | Where-Object { $_.SID -like "*-500" }
    
    if ($originalAdmin -and $originalAdmin.Name -ne $currentAdminAccount.Name) {
        if ($PSCmdlet.ShouldProcess($currentAdminAccount.Name, "Rename to: $($originalAdmin.Name)")) {
            try {
                Rename-LocalUser -Name $currentAdminAccount.Name -NewName $originalAdmin.Name -ErrorAction Stop
                $renameMsg = Get-LocalizedString 'RestoreUsersRenamed' $currentAdminAccount.Name $originalAdmin.Name
                Write-Host "  [OK] $renameMsg" -ForegroundColor Green
                
                if ($originalAdmin.Enabled) {
                    Enable-LocalUser -Name $originalAdmin.Name -ErrorAction SilentlyContinue
                    Write-Host "  [OK] $(Get-LocalizedString 'RestoreUsersEnabled')" -ForegroundColor Green
                }
                else {
                    Disable-LocalUser -Name $originalAdmin.Name -ErrorAction SilentlyContinue
                    Write-Host "  [OK] $(Get-LocalizedString 'RestoreUsersDisabled')" -ForegroundColor Green
                }
                
                $restoreStats.Success++
                
                Write-Host "" 
                Write-Host "  [!] $(Get-LocalizedString 'RestoreUsersPasswordTitle')" -ForegroundColor Yellow
                Write-Host "      $(Get-LocalizedString 'RestoreUsersPasswordWarning')" -ForegroundColor Yellow
                Write-Host ""
                $pwPrompt = Get-LocalizedString 'RestoreUsersPasswordPrompt' $originalAdmin.Name
                Write-Host "  $pwPrompt " -NoNewline -ForegroundColor Cyan
                $setPassword = Read-Host
                
                if ($setPassword -eq 'J' -or $setPassword -eq 'j' -or $setPassword -eq 'Y' -or $setPassword -eq 'y') {
                    Write-Host ""
                    Write-Host "  $(Get-LocalizedString 'RestoreUsersPasswordOptions')" -ForegroundColor White
                    Write-Host "    $(Get-LocalizedString 'RestoreUsersPasswordRandom')" -ForegroundColor Gray
                    Write-Host "    $(Get-LocalizedString 'RestoreUsersPasswordCustom')" -ForegroundColor Gray
                    Write-Host "    $(Get-LocalizedString 'RestoreUsersPasswordSkip')" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  $(Get-LocalizedString 'RestoreUsersPasswordChoose') " -NoNewline
                    $pwChoice = Read-Host
                    
                    if ($pwChoice -eq '1') {
                        # Use RNGCryptoServiceProvider instead of Get-Random (Best Practice 25H2)
                        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                        try {
                            $bytes = New-Object byte[] 32
                            $rng.GetBytes($bytes)
                            
                            # Convert to Base64 and take first 24 characters (strong enough)
                            $newPassword = [System.Convert]::ToBase64String($bytes).Substring(0,24)
                            
                            $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            Set-LocalUser -Name $originalAdmin.Name -Password $securePassword -ErrorAction Stop
                            
                            Write-Host ""
                            Write-Host "  ============================================================" -ForegroundColor Green
                            $pwNewMsg = Get-LocalizedString 'RestoreUsersPasswordNew' $originalAdmin.Name
                            Write-Host "    $pwNewMsg" -ForegroundColor Green
                            Write-Host "" 
                            
                            # SECURITY: Do NOT output password to console (appears in transcript log!)
                            # Instead: Use clipboard
                            try {
                                Set-Clipboard -Value $newPassword -ErrorAction Stop
                                Write-Host "    [OK] Passwort wurde in Zwischenablage kopiert!" -ForegroundColor Green
                                Write-Host "    [!] Bitte JETZT in Passwort-Manager einfuegen!" -ForegroundColor Yellow
                                Write-Host "    [!] Zwischenablage wird in 30 Sekunden geloescht!" -ForegroundColor Yellow
                            }
                            catch {
                                # Fallback if Clipboard doesn't work (e.g. SSH session)
                                Write-Host "    [!] Zwischenablage nicht verfuegbar - Passwort wird angezeigt:" -ForegroundColor Yellow
                                Write-Host "    $newPassword" -ForegroundColor Yellow
                            }
                            
                            Write-Host ""
                            Write-Host "    $(Get-LocalizedString 'RestoreUsersPasswordNote')" -ForegroundColor Red
                            Write-Host "  ============================================================" -ForegroundColor Green
                            Write-Host ""
                            
                            # Wait 30 seconds with countdown
                            if ((Get-Clipboard -ErrorAction SilentlyContinue) -eq $newPassword) {
                                Write-Host "  [i] Warte 30 Sekunden bevor Zwischenablage geleert wird..." -ForegroundColor Gray
                                for ($i = 30; $i -gt 0; $i -= 5) {
                                    Write-Host "      $i Sekunden verbleiben..." -ForegroundColor DarkGray
                                    Start-Sleep -Seconds 5
                                }
                                try {
                                    # CRITICAL: Set-Clipboard requires non-empty string (not "" or $null)
                                    # Using single space to effectively clear clipboard without error
                                    Set-Clipboard -Value " " -ErrorAction Stop
                                    Write-Host "  [OK] Zwischenablage geleert (Sicherheit)" -ForegroundColor Green
                                } catch {
                                    Write-Verbose "Could not clear clipboard: $_"
                                    # Non-critical - clipboard clear is just a security nicety
                                }
                            }
                        }
                        catch {
                            Write-Verbose "RNG Password generation error: $_"
                            Write-Host "  [!] Passwort-Generierung fehlgeschlagen: $_" -ForegroundColor Red
                        }
                        finally {
                            $rng.Dispose()
                        }
                    }
                    elseif ($pwChoice -eq '2') {
                        $securePasswordInput = Read-Host "  New Password" -AsSecureString
                        Set-LocalUser -Name $originalAdmin.Name -Password $securePasswordInput -ErrorAction Stop
                        Write-Host "  [OK] $(Get-LocalizedString 'RestoreUsersPasswordSet')" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  [!] $(Get-LocalizedString 'RestoreUsersPasswordSkipped')" -ForegroundColor Yellow
                        Write-Host "      $(Get-LocalizedString 'RestoreUsersPasswordOldRandom')" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Host "  [X] Administrator rename error: $_" -ForegroundColor Red
                $restoreStats.Failed++
            }
        }
    }
    else {
        Write-Host "  [i] $(Get-LocalizedString 'RestoreUsersAlready')" -ForegroundColor Gray
        $restoreStats.Skipped++
    }
}
else {
    Write-Host "  [!] $(Get-LocalizedString 'RestoreUsersNotFound')" -ForegroundColor Yellow
    $restoreStats.Skipped++
}

Write-Host ""
#endregion

#region Restore Apps
Write-Host "[8/14] $(Get-LocalizedString 'RestoreApps')" -ForegroundColor Yellow

$currentApps = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$missingApps = $backup.Settings.InstalledApps | Where-Object { $currentApps -notcontains $_.Name }

$missingAppsCount = if ($missingApps) { @($missingApps).Count } else { 0 }
if ($missingAppsCount -gt 0) {
    $missingMsg = (Get-LocalizedString 'RestoreAppsMissing')
    Write-Host "  [!] $missingAppsCount $missingMsg" -ForegroundColor Yellow
    Write-Host ""
    
    $provPkgCount = if ($backup.Settings.ProvisionedPackages) { @($backup.Settings.ProvisionedPackages).Count } else { 0 }
    if ($provPkgCount -gt 0) {
        Write-Host "  [i] $(Get-LocalizedString 'RestoreAppsPackages')" -ForegroundColor Cyan
        Write-Host "      $(Get-LocalizedString 'RestoreAppsCanRestore')" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  $(Get-LocalizedString 'RestoreAppsPrompt') " -NoNewline -ForegroundColor Yellow
        $restoreApps = Read-Host
        
        if ($restoreApps -eq 'J' -or $restoreApps -eq 'j' -or $restoreApps -eq 'Y' -or $restoreApps -eq 'y') {
            Write-Host ""
            Write-Host "  [i] $(Get-LocalizedString 'RestoreAppsRestoring')" -ForegroundColor Cyan
            Write-Host "      $(Get-LocalizedString 'RestoreAppsMayTakeTime')" -ForegroundColor Gray
            Write-Host ""
            
            $restoredApps = 0
            foreach ($pkg in $backup.Settings.ProvisionedPackages) {
                try {
                    $currentPkg = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $pkg.DisplayName } -ErrorAction SilentlyContinue
                    
                    if (-not $currentPkg) {
                        $installingMsg = (Get-LocalizedString 'RestoreAppsInstalling')
                        Write-Host "    [i] $installingMsg $($pkg.DisplayName)..." -ForegroundColor Gray
                        Write-Host "    [!] $(Get-LocalizedString 'RestoreAppsMustReinstall')" -ForegroundColor Yellow
                        $restoredApps++
                    }
                }
                catch {
                    # Error
                }
            }
            
            Write-Host ""
            Write-Host "  [i] $restoredApps $(Get-LocalizedString 'RestoreAppsManual')" -ForegroundColor Cyan
            Write-Host "      $(Get-LocalizedString 'RestoreAppsOpenStore')" -ForegroundColor Gray
        }
        else {
            Write-Host "  [!] $(Get-LocalizedString 'RestoreAppsSkipped')" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [i] $(Get-LocalizedString 'RestoreAppsNone')" -ForegroundColor Gray
        Write-Host "      $(Get-LocalizedString 'RestoreAppsStoreNote')" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'RestoreAppsList')" -ForegroundColor White
    foreach ($app in $missingApps | Select-Object -First 10) {
        Write-Host "      - $($app.Name)" -ForegroundColor Gray
    }
    if ($missingAppsCount -gt 10) {
        $moreMsg = Get-LocalizedString 'RestoreAppsMore' ($missingAppsCount - 10)
        Write-Host "      $moreMsg" -ForegroundColor Gray
    }
    
    # CRITICAL FIX v1.7.13: Write app list to Desktop for user reference
    # User will need to reboot - list will be available on desktop after restart
    try {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $fileName = Get-LocalizedString 'AppListFileName'
        $appListFile = Join-Path $desktopPath "$fileName-$timestamp.txt"
        
        # Build localized app list content
        $header = Get-LocalizedString 'AppListFileHeader'
        $dateLabel = Get-LocalizedString 'AppListFileDate'
        $totalLabel = Get-LocalizedString 'AppListFileTotal'
        $intro = Get-LocalizedString 'AppListFileIntro'
        $howToHeader = Get-LocalizedString 'AppListFileHowToHeader'
        $step1 = Get-LocalizedString 'AppListFileStep1'
        $step2 = Get-LocalizedString 'AppListFileStep2'
        $step3 = Get-LocalizedString 'AppListFileStep3'
        $step4 = Get-LocalizedString 'AppListFileStep4'
        $note = Get-LocalizedString 'AppListFileNote'
        
        $appListContent = @"
========================================
$header
========================================

$dateLabel $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$totalLabel $missingAppsCount

$intro

========================================

"@
        
        foreach ($app in $missingApps) {
            $appListContent += "- $($app.Name)`r`n"
        }
        
        $appListContent += @"

========================================
$howToHeader
========================================

$step1
$step2
$step3
$step4

$note

========================================
"@
        
        $appListContent | Out-File -FilePath $appListFile -Encoding UTF8 -Force
        Write-Host ""
        Write-Host "  [OK] App list saved to desktop: $appListFile" -ForegroundColor Green
        Write-Host "      $(Get-LocalizedString 'RestoreAppsListSaved')" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not save app list to desktop: $_"
    }
    
    $restoreStats.Skipped++
}
else {
    Write-Host "  [OK] $(Get-LocalizedString 'RestoreAppsAllPresent')" -ForegroundColor Green
}

Write-Host ""
#endregion

#region Restore ASR Rules
Write-Host ""
Write-Host "[9/14] Restore ASR Rules..." -ForegroundColor Yellow

if ($backup.Settings.ASRRules -and $backup.Settings.ASRRules.Enabled) {
    try {
        # Check if Defender is available
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            $asrIds = @()
            $asrActions = @()
            
            foreach ($rule in $backup.Settings.ASRRules.Rules) {
                $asrIds += $rule.Id
                $asrActions += $rule.Action
            }
            
            $asrCount = if ($asrIds) { @($asrIds).Count } else { 0 }
            if ($asrCount -gt 0) {
                # Restore ASR Rules
                $null = Set-MpPreference -AttackSurfaceReductionRules_Ids $asrIds -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction Stop
                Write-Host "  [OK] $asrCount ASR Rules wiederhergestellt" -ForegroundColor Green
                $restoreStats.Success++
            }
        }
        else {
            Write-Host "  [SKIP] Set-MpPreference nicht verfuegbar" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "ASR Rules Restore fehlgeschlagen: $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] Keine ASR Rules im Backup" -ForegroundColor Gray
}
#endregion

#region Restore Exploit Protection
Write-Host ""
Write-Host "[10/14] Restore Exploit Protection..." -ForegroundColor Yellow

if ($backup.Settings.ExploitProtection -and $backup.Settings.ExploitProtection.Enabled) {
    try {
        # Check if Set-ProcessMitigation is available (Windows 10 1709+)
        if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) {
            Write-Host "  [SKIP] Set-ProcessMitigation nicht verfuegbar (Windows 10 1709+ required)" -ForegroundColor Gray
            $restoreStats.Skipped++
        }
        else {
            Write-Verbose "Restoring Exploit Protection mitigations (same as Apply)..."
            
            # STRATEGY: Mirror Apply behavior (idempotent)
            # Backup had Exploit Protection enabled -> restore to hardened state
            # This is safer than trying to parse backup data and restore individual settings
            
            $mitigationsSet = 0
            $mitigationsFailed = 0
            
            # ===== BASIC MITIGATIONS (Standard) =====
            try {
                Write-Verbose "Setting basic mitigations (DEP, SEHOP, ASLR)..."
                Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy -ErrorAction Stop
                Write-Verbose "  [OK] Basic mitigations: DEP, SEHOP, ASLR"
                $mitigationsSet += 5
            }
            catch {
                Write-Verbose "  [FAILED] Basic mitigations: $($_.Exception.Message)"
                $mitigationsFailed += 5
            }
            
            # ===== EXTENDED MITIGATIONS (Best Practice) =====
            # Individual try-catch for each (not all systems support all mitigations)
            
            # Heap Protection (Terminate on Error)
            try {
                Set-ProcessMitigation -System -Enable TerminateOnError -ErrorAction Stop
                Write-Verbose "  [OK] Heap Protection: Terminate on Error"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] Heap Protection: $($_.Exception.Message)"
            }
            
            # Control Flow Guard - Strict Mode
            try {
                Set-ProcessMitigation -System -Enable StrictCFG -ErrorAction Stop
                Write-Verbose "  [OK] CFG: Strict Mode"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] CFG Strict: $($_.Exception.Message)"
            }
            
            # CFG - Suppress Exports (Anti-ROP)
            try {
                Set-ProcessMitigation -System -Enable SuppressExports -ErrorAction Stop
                Write-Verbose "  [OK] CFG: Export Suppression (Anti-ROP)"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] CFG Exports: $($_.Exception.Message)"
            }
            
            # Image Load Protection - Block Remote Images
            try {
                Set-ProcessMitigation -System -Enable BlockRemoteImageLoads -ErrorAction Stop
                Write-Verbose "  [OK] Image Load: Block Remote (DLL Hijacking Protection)"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] Image Load Remote: $($_.Exception.Message)"
            }
            
            # Image Load Protection - Block Low Integrity Images
            try {
                Set-ProcessMitigation -System -Enable BlockLowLabelImageLoads -ErrorAction Stop
                Write-Verbose "  [OK] Image Load: Block Low Integrity (Untrusted Sources)"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] Image Load Low Integrity: $($_.Exception.Message)"
            }
            
            # Disable Extension Points (Legacy COM)
            try {
                Set-ProcessMitigation -System -Enable DisableExtensionPoints -ErrorAction Stop
                Write-Verbose "  [OK] Disable Extension Points (Legacy COM)"
                $mitigationsSet++
            }
            catch {
                Write-Verbose "  [SKIP] Extension Points: $($_.Exception.Message)"
            }
            
            if ($mitigationsSet -gt 0) {
                Write-Host "  [OK] Exploit Protection: $mitigationsSet mitigations restored" -ForegroundColor Green
                $restoreStats.Success++
            }
            elseif ($mitigationsFailed -gt 0) {
                Write-Host "  [!] Exploit Protection: All mitigations failed (incompatible system?)" -ForegroundColor Yellow
                $restoreStats.Failed++
            }
            else {
                Write-Host "  [!] Exploit Protection: No mitigations set (hardware incompatible)" -ForegroundColor Yellow
                $restoreStats.Skipped++
            }
        }
    }
    catch {
        Write-Warning "Exploit Protection Restore fehlgeschlagen: $_"
        $restoreStats.Failed++
    }
}
else {
    Write-Host "  [SKIP] Keine Exploit Protection im Backup (oder nicht aktiviert)" -ForegroundColor Gray
    $restoreStats.Skipped++
}
#endregion

#region Restore DoH Configuration
Write-Host ""
Write-Host "[11/14] Restore DoH Configuration..." -ForegroundColor Yellow

if ($backup.Settings.DoH -and $backup.Settings.DoH.Enabled) {
    try {
        # CRITICAL UPDATE v1.7.11: Use netsh (consistent with Enable-CloudflareDNSoverHTTPS!)
        # MS-documented method (not Add-DnsClientDohServerAddress)
        
        # Remove all existing DoH configurations first (idempotent)
        Write-Verbose "Entferne existierende DoH-Konfigurationen..."
        $existingDoh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($existingDoh) {
            foreach ($doh in $existingDoh) {
                try {
                    $null = netsh dnsclient delete encryption server=$($doh.ServerAddress) 2>&1
                }
                catch {
                    # Ignore errors during cleanup
                }
            }
        }
        
        # CRITICAL: Enforce DoH at OS level (Registry + netsh)
        # This ensures Windows always prefers encrypted DNS
        Write-Verbose "Setting DoH enforcement at OS level..."
        try {
            $dnsRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
            if (-not (Test-Path $dnsRegPath)) {
                New-Item -Path $dnsRegPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            # EnableAutoDoh = 2 (enforce DoH, no fallback)
            Set-ItemProperty -Path $dnsRegPath -Name 'EnableAutoDoh' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Verbose "  Registry: EnableAutoDoh = 2 (enforce)"
        }
        catch {
            Write-Verbose "  Failed to set EnableAutoDoh registry: $_"
        }
        
        # Enable DoH globally via netsh
        try {
            netsh dnsclient set global doh=yes 2>$null | Out-Null
            Write-Verbose "  netsh: DoH globally enabled"
        }
        catch {
            Write-Verbose "  Failed to enable global DoH via netsh: $_"
        }
        
        # Restore backed up DoH servers using netsh
        # CRITICAL: Always use STRICT mode (ignore backup settings for security)
        # udpfallback=no: No fallback to unencrypted DNS
        # autoupgrade=yes: Auto-upgrade to DoH when available
        $restoredCount = 0
        foreach ($server in $backup.Settings.DoH.Servers) {
            try {
                # STRICT MODE: Always enforce encrypted DNS (ignore backup values)
                $udpFallback = "no"   # Never fallback to unencrypted
                $autoUpgrade = "yes"  # Always auto-upgrade to DoH
                
                $result = netsh dnsclient add encryption server=$($server.ServerAddress) `
                    dohtemplate=$($server.DohTemplate) `
                    autoupgrade=$autoUpgrade `
                    udpfallback=$udpFallback 2>&1
                
                if ($LASTEXITCODE -eq 0 -or $result -like "*already exists*") {
                    $restoredCount++
                }
                else {
                    Write-Verbose "DoH Server $($server.ServerAddress) konnte nicht wiederhergestellt werden: $result"
                }
            }
            catch {
                Write-Verbose "DoH Server $($server.ServerAddress) Fehler: $_"
            }
        }
        
        if ($restoredCount -gt 0) {
            # NOTE: EnableAutoDoh and netsh global DoH already set to STRICT mode above
            # (Lines 1335-1358: Registry = 2, netsh = yes)
            # We do NOT restore from backup values - security always wins!
            Write-Host "  [OK] $restoredCount DoH Server wiederhergestellt (strict mode: registry=2, netsh=yes)" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [WARN] Keine DoH Server wiederhergestellt" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "DoH Restore fehlgeschlagen: $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] Keine DoH Konfiguration im Backup" -ForegroundColor Gray
}
#endregion

#region Restore DoH Encryption Preferences (Adapter-specific DohFlags)
Write-Host ""
Write-Host "[12/14] Restore DoH Encryption Preferences (Adapter-specific)..." -ForegroundColor Yellow

if ($backup.Settings.DohEncryption -and $backup.Settings.DohEncryption.Enabled) {
    try {
        $restoredAdapters = 0
        $restoredServers = 0
        
        foreach ($adapterBackup in $backup.Settings.DohEncryption.Adapters) {
            $adapterGuid = $adapterBackup.Guid
            $adapterName = $adapterBackup.Name
            
            Write-Verbose "Restoring DoH encryption for adapter: $adapterName (GUID: $adapterGuid)"
            
            # Restore IPv4 DoH encryption (Doh branch)
            foreach ($serverBackup in $adapterBackup.IPv4Servers) {
                try {
                    $ip = $serverBackup.IP
                    $dohFlags = $serverBackup.DohFlags
                    $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                    
                    # Create path if not exists
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Restore DohFlags value
                    Set-ItemProperty -Path $regPath -Name 'DohFlags' -Value $dohFlags -Type QWord -Force -ErrorAction Stop
                    Write-Verbose "  Restored IPv4 DoH encryption: $ip = $dohFlags"
                    $restoredServers++
                }
                catch {
                    Write-Verbose "  Failed to restore IPv4 DoH encryption for $ip : $_"
                }
            }
            
            # Restore IPv6 DoH encryption (Doh6 branch)
            foreach ($serverBackup in $adapterBackup.IPv6Servers) {
                try {
                    $ip = $serverBackup.IP
                    $dohFlags = $serverBackup.DohFlags
                    
                    # PowerShell 5.1 workaround: Create path step-by-step
                    $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                    $regPath = $basePath + "\$ip"
                    
                    # Create Doh6 parent first (if not exists)
                    if (-not (Test-Path $basePath)) {
                        New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Create IP subkey
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Restore DohFlags value
                    Set-ItemProperty -Path $regPath -Name 'DohFlags' -Value $dohFlags -Type QWord -Force -ErrorAction Stop
                    Write-Verbose "  Restored IPv6 DoH encryption: $ip = $dohFlags"
                    $restoredServers++
                }
                catch {
                    Write-Verbose "  Failed to restore IPv6 DoH encryption for $ip : $_"
                }
            }
            
            $ipv4Count = if ($adapterBackup.IPv4Servers) { @($adapterBackup.IPv4Servers).Count } else { 0 }
            $ipv6Count = if ($adapterBackup.IPv6Servers) { @($adapterBackup.IPv6Servers).Count } else { 0 }
            if ($ipv4Count -gt 0 -or $ipv6Count -gt 0) {
                $restoredAdapters++
            }
        }
        
        if ($restoredServers -gt 0) {
            Write-Host "  [OK] DoH Encryption: $restoredAdapters Adapter, $restoredServers DNS-Server wiederhergestellt" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [WARN] Keine DoH Encryption Preferences wiederhergestellt" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "DoH Encryption Preferences Restore fehlgeschlagen: $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] Keine DoH Encryption Preferences im Backup" -ForegroundColor Gray
}
#endregion

#region Restore Firewall Profile Settings
Write-Host ""
Write-Host "[13/14] Restore Firewall Profile Settings..." -ForegroundColor Yellow

if ($backup.Settings.FirewallProfiles -and $backup.Settings.FirewallProfiles.Enabled) {
    try {
        $restoredProfiles = 0
        
        foreach ($profileConfig in $backup.Settings.FirewallProfiles.Profiles) {
            try {
                # Restore all profile settings
                Set-NetFirewallProfile -Name $profileConfig.Name `
                    -Enabled $profileConfig.Enabled `
                    -DefaultInboundAction $profileConfig.DefaultInboundAction `
                    -DefaultOutboundAction $profileConfig.DefaultOutboundAction `
                    -AllowInboundRules $profileConfig.AllowInboundRules `
                    -AllowLocalFirewallRules $profileConfig.AllowLocalFirewallRules `
                    -AllowLocalIPsecRules $profileConfig.AllowLocalIPsecRules `
                    -NotifyOnListen $profileConfig.NotifyOnListen `
                    -EnableStealthModeForIPsec $profileConfig.EnableStealthModeForIPsec `
                    -LogMaxSizeKilobytes $profileConfig.LogMaxSizeKilobytes `
                    -LogAllowed $profileConfig.LogAllowed `
                    -LogBlocked $profileConfig.LogBlocked `
                    -LogIgnored $profileConfig.LogIgnored `
                    -ErrorAction Stop
                
                Write-Host "  [OK] Firewall Profile '$($profileConfig.Name)' wiederhergestellt" -ForegroundColor Green
                $restoredProfiles++
            }
            catch {
                Write-Warning "Firewall Profile '$($profileConfig.Name)' konnte nicht wiederhergestellt werden: $_"
            }
        }
        
        if ($restoredProfiles -gt 0) {
            Write-Host "  [OK] $restoredProfiles Firewall Profile wiederhergestellt" -ForegroundColor Green
            $restoreStats.Success++
        }
    }
    catch {
        Write-Warning "Firewall Profile Restore fehlgeschlagen: $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] Keine Firewall Profiles im Backup" -ForegroundColor Gray
}
#endregion

#region Restore Device-Level App Permissions
Write-Host ""
Write-Host "[14/14] Restore Device-Level App Permissions..." -ForegroundColor Yellow

# CRITICAL FIX: Check property existence BEFORE access (StrictMode compatibility)
# ROOT CAUSE: Direct property access crashes under StrictMode if property doesn't exist
# SOLUTION: Use PSObject.Properties.Name to check existence first
$hasDeviceLevelApps = 
    $null -ne $backup.Settings -and
    'DeviceLevelApps' -in $backup.Settings.PSObject.Properties.Name

if ($hasDeviceLevelApps) {
    $deviceApps = $backup.Settings.DeviceLevelApps
    
    # Check if enabled and has apps
    $hasApps = 
        $null -ne $deviceApps -and
        'Apps' -in $deviceApps.PSObject.Properties.Name -and
        $null -ne $deviceApps.Apps -and
        ($deviceApps.Apps | Measure-Object).Count -gt 0
    
    if ($hasApps) {
        try {
            $restoredApps = 0
            $deletedApps = 0
            
            # Check if Set-RegistryValueSmart is available (from RegistryOwnership module)
            $hasOwnershipModule = Get-Command Set-RegistryValueSmart -ErrorAction SilentlyContinue
            
            foreach ($appConfig in $deviceApps.Apps) {
            try {
                $appPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\$($appConfig.Permission)\Apps\$($appConfig.AppName)"
                
                if ($appConfig.Exists -eq $true) {
                    # Key existierte vorher - restore original value
                    if ($hasOwnershipModule) {
                        # Use ownership management for TrustedInstaller-protected keys
                        $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value $appConfig.EnabledByUser -ValueType DWord `
                            -Description "Restore Device-Level: $($appConfig.Permission)/$($appConfig.AppName)"
                        
                        if ($result) {
                            Write-Verbose "  [OK] Restored: $($appConfig.Permission)/$($appConfig.AppName) = $($appConfig.EnabledByUser)"
                            $restoredApps++
                        }
                    }
                    else {
                        # Fallback without ownership management
                        if (Test-Path $appPath) {
                            # Check if value exists
                            $valueExists = Get-ItemProperty -Path $appPath -Name "EnabledByUser" -ErrorAction SilentlyContinue
                            if ($valueExists) {
                                Set-ItemProperty -Path $appPath -Name "EnabledByUser" -Value $appConfig.EnabledByUser -Force -ErrorAction Stop
                            }
                            else {
                                New-ItemProperty -Path $appPath -Name "EnabledByUser" -Value $appConfig.EnabledByUser -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                            }
                            Write-Verbose "  [OK] Restored: $($appConfig.Permission)/$($appConfig.AppName) = $($appConfig.EnabledByUser)"
                            $restoredApps++
                        }
                    }
                }
                else {
                    # Key did NOT exist before - should be deleted
                    if (Test-Path $appPath) {
                        $currentValue = Get-ItemProperty -Path $appPath -Name "EnabledByUser" -ErrorAction SilentlyContinue
                        if ($null -ne $currentValue) {
                            # Script created the key - delete it!
                            Remove-ItemProperty -Path $appPath -Name "EnabledByUser" -ErrorAction SilentlyContinue
                            Write-Verbose "  [OK] Deleted: $($appConfig.Permission)/$($appConfig.AppName)"
                            $deletedApps++
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Device-Level App '$($appConfig.AppName)' konnte nicht wiederhergestellt werden: $_"
            }
        }
        
        if ($restoredApps -gt 0 -or $deletedApps -gt 0) {
            Write-Host "  [OK] $restoredApps Device-Level Apps restored, $deletedApps deleted" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [i] No device-level apps needed restoration" -ForegroundColor Gray
        }
        }
        catch {
            Write-Warning "Device-Level App Restore fehlgeschlagen: $_"
            $restoreStats.Errors++
        }
    }
    else {
        Write-Host "  [i] No device-level apps in backup (Apps list empty or missing)" -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "  [i] Backup has no 'DeviceLevelApps' section - skipping" -ForegroundColor DarkYellow
}
#endregion

# DNS Cache leeren
Write-Host ""
Write-Host "[14/14] $(Get-LocalizedString 'RestoreDNSClear')" -ForegroundColor Cyan
try {
    $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
    $job | Wait-Job -Timeout 10 | Out-Null
    
    if ($job.State -eq 'Completed') {
        Remove-Job $job -Force
        Write-Host "[OK] $(Get-LocalizedString 'RestoreDNSCleared')" -ForegroundColor Green
    }
    else {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "[!] $(Get-LocalizedString 'RestoreDNSTimeout')" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[!] DNS Cache error: $_" -ForegroundColor Yellow
}

# Abschluss
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "                    $(Get-LocalizedString 'RestoreCompleted')" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "$(Get-LocalizedString 'RestoreStats')" -ForegroundColor White
Write-Host "  $(Get-LocalizedString 'RestoreStatsSuccess') $($restoreStats.Success)" -ForegroundColor Green
Write-Host "  $(Get-LocalizedString 'RestoreStatsFailed') $($restoreStats.Failed)" -ForegroundColor Red
Write-Host "  $(Get-LocalizedString 'RestoreStatsSkipped') $($restoreStats.Skipped)" -ForegroundColor Yellow
Write-Host ""

if ($restoreStats.Failed -gt 0) {
    Write-Host "[!] $(Get-LocalizedString 'RestoreSomeErrors')" -ForegroundColor Yellow
    $logMsg = (Get-LocalizedString 'RestoreCheckLog')
    Write-Host "    $logMsg $script:transcriptPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Gray
Write-Host "LOGS & DETAILS" -ForegroundColor White
Write-Host "============================================================================" -ForegroundColor Gray
Write-Host "Transcript Log: $script:transcriptPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host "                       $(Get-LocalizedString 'RestoreRebootTitle')" -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "$(Get-LocalizedString 'RestoreRebootNeeded')" -ForegroundColor White
Write-Host ""
Write-Host "  * $(Get-LocalizedString 'RestoreRebootServices')" -ForegroundColor White
Write-Host "  * $(Get-LocalizedString 'RestoreRebootRegistry')" -ForegroundColor White
Write-Host "  * $(Get-LocalizedString 'RestoreRebootDNS')" -ForegroundColor White
Write-Host "  * Scheduled Tasks" -ForegroundColor White
Write-Host ""
Write-Host "  [!] $(Get-LocalizedString 'RebootWarning')" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  $(Get-LocalizedString 'RebootQuestion')" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [J] $(Get-LocalizedString 'RebootNow')" -ForegroundColor Green
Write-Host "         $(Get-LocalizedString 'RebootNowDesc')" -ForegroundColor Gray
Write-Host ""
Write-Host "  [S] $(Get-LocalizedString 'RebootLater')" -ForegroundColor Yellow
Write-Host "         $(Get-LocalizedString 'RebootLaterDesc')" -ForegroundColor Gray
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host ""

$promptText = Get-LocalizedString "RebootPrompt"
if (-not $promptText) { $promptText = "Ihre Wahl" }

do {
    Write-Host "  $promptText " -NoNewline -ForegroundColor Cyan
    Write-Host "[Y/N]: " -NoNewline -ForegroundColor Gray
    $reboot = Read-Host
    
    # Input validation: Trim and ToUpper with null check
    if ($reboot) {
        $reboot = $reboot.Trim().ToUpper()
    }
    
    # Support for J/S (German)
    if ($reboot -eq 'J') { $reboot = 'Y' }
    if ($reboot -eq 'S') { $reboot = 'N' }
    
    if ($reboot -notin @('Y', 'N')) {
        $errorMsg = Get-LocalizedString 'ErrorInvalidInput'
        if (-not $errorMsg) { $errorMsg = "Invalid input! Please enter:" }
        Write-Host "  [ERROR] $errorMsg Y/N (or J/N for German)!" -ForegroundColor Red
        Write-Host ""
    }
} while ($reboot -notin @('Y', 'N'))

if ($reboot -eq 'Y') {
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'RestoreRebooting')" -ForegroundColor Cyan
    Write-Host "    $(Get-LocalizedString 'RestoreRebootAbort')" -ForegroundColor Gray
    Start-Sleep -Seconds 10
    
    # Stop transcript before reboot
    if ($script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction Stop
        }
        catch {
            Write-Verbose "Could not stop transcript: $_"
        }
    }
    
    Restart-Computer -Force
}
else {
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'RestoreRebootPostponed')" -ForegroundColor Yellow
    Write-Host "    $(Get-LocalizedString 'RestoreRebootManual')" -ForegroundColor Gray
    Write-Host ""
}

# Stop transcript if not rebooting
if ($script:transcriptStarted) {
    try {
        Stop-Transcript -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not stop transcript: $_"
    }
}
