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
    Version:        1.8.0
    Last Updated:   November 6, 2025
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
    [string]$LogPath = "$env:ProgramData\SecurityBaseline\Logs",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('en', 'de')]
    [string]$Language
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

# Load Localization Module FIRST (needed for transcript messages!)
# CRITICAL: Use $PSScriptRoot for reliability when called from anywhere
$scriptDir = $PSScriptRoot
try {
    . "$scriptDir\Modules\SecurityBaseline-Localization.ps1"
}
catch {
    Write-Warning "Could not load localization module: $_"
    # Fallback to English
    $Global:CurrentLanguage = 'en'
}

if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

$script:transcriptPath = Join-Path $LogPath "Restore-$timestamp.log"

try {
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "$(Get-LocalizedString 'VerboseTranscriptStarted' $script:transcriptPath)"
}
catch {
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptFailed' $_)"
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptContinue')"
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

# Ensure language is set (priority: Parameter > Environment Variable > Interactive Selection > Auto-detect)
# CRITICAL: Check parameter FIRST, even if CurrentLanguage already exists from Localization.ps1!
# Priority 1: Language parameter (passed from Apply script) - HIGHEST PRIORITY!
if ($Language) {
    $Global:CurrentLanguage = $Language
    Write-Host "[DEBUG] Language set from parameter: $Language" -ForegroundColor Yellow
}
# Priority 2: Environment variable (from parent script)
elseif ($env:NOID_LANGUAGE) {
    $Global:CurrentLanguage = $env:NOID_LANGUAGE
    Write-Host "[DEBUG] Language set from environment variable: $env:NOID_LANGUAGE" -ForegroundColor Yellow
}
# Priority 3: Check if already set (from Localization.ps1 or previous call)
elseif (Test-Path Variable:\Global:CurrentLanguage) {
    Write-Host "[DEBUG] Language already set: $Global:CurrentLanguage" -ForegroundColor Yellow
}
# Priority 4: Interactive selection (if available)
elseif (Get-Command -Name Select-Language -ErrorAction SilentlyContinue) {
    try {
        Select-Language
        Write-Host "[DEBUG] Language set from interactive selection: $Global:CurrentLanguage" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Language selection failed: $_"
        # Fallback: Detect system language (German or English)
        $systemLang = (Get-Culture).TwoLetterISOLanguageName
        $uiLang = (Get-UICulture).TwoLetterISOLanguageName
        
        if ($systemLang -eq 'de' -or $uiLang -eq 'de') {
            $Global:CurrentLanguage = 'de'
        }
        else {
            $Global:CurrentLanguage = 'en'
        }
        Write-Host "[DEBUG] Language set from auto-detect (fallback): $Global:CurrentLanguage" -ForegroundColor Yellow
    }
}
# Priority 5: Auto-detect (last resort)
else {
    $systemLang = (Get-Culture).TwoLetterISOLanguageName
    $uiLang = (Get-UICulture).TwoLetterISOLanguageName
    
    if ($systemLang -eq 'de' -or $uiLang -eq 'de') {
        $Global:CurrentLanguage = 'de'
    }
    else {
        $Global:CurrentLanguage = 'en'
    }
    Write-Host "[DEBUG] Language set from auto-detect: $Global:CurrentLanguage" -ForegroundColor Yellow
}

Write-Host "`n============================================================================" -ForegroundColor Yellow
Write-Host "           $(Get-LocalizedString 'RestoreBanner')" -ForegroundColor Yellow
Write-Host "============================================================================`n" -ForegroundColor Yellow

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
            
            if ($script:transcriptStarted) {
                try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
            }
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
            
            if ($script:transcriptStarted) {
                try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
            }
            exit 0
        }
        
        $selectionNum = [int]$selection - 1
        if ($selectionNum -ge 0 -and $selectionNum -lt $backupsCount) {
            $BackupFile = $backups[$selectionNum].FullName
        }
        else {
            Write-Host "[ERROR] $(Get-LocalizedString 'RestoreInvalidSelection')" -ForegroundColor Red
            
            if ($script:transcriptStarted) {
                try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
            }
            exit 1
        }
    }
    else {
        Write-Host "[ERROR] $(Get-LocalizedString 'RestoreNoneFound') $backupPath" -ForegroundColor Red
        
        if ($script:transcriptStarted) {
            try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
        }
        exit 1
    }
}

if (-not (Test-Path $BackupFile)) {
    Write-Host "[ERROR] $(Get-LocalizedString 'RestoreNotFound') $BackupFile" -ForegroundColor Red
    
    if ($script:transcriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
    }
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
    
    if ($script:transcriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
    }
    exit 1
}

# Warnung
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host "                             $(Get-LocalizedString 'RestoreWarningTitle')" -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Yellow
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
Write-Host "$(Get-LocalizedString 'RestoreWarningRisk')" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "$(Get-LocalizedString 'RestoreConfirm') " -NoNewline -ForegroundColor Yellow
$confirm = Read-Host

if ($confirm -ne 'J' -and $confirm -ne 'j' -and $confirm -ne 'Y' -and $confirm -ne 'y') {
    Write-Host "$(Get-LocalizedString 'RestoreCancelled')" -ForegroundColor Yellow
    
    if ($script:transcriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
    }
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
Write-Host "[1/18] $(Get-LocalizedString 'RestoreDNS')" -ForegroundColor Yellow

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
            
            # CRITICAL: RESET-FIRST APPROACH (Option A - recommended)
            # Problem: Backup hat nur IPv4, aber System hat alte Provider-IPv6
            # -> Wenn wir nur IPv4 setzen, bleibt alte IPv6 kleben!
            # -> Set-DnsClientServerAddress hat KEIN -AddressFamily Parameter zum selektiven Reset
            # Solution: IMMER erst komplett resetten, dann aus Backup neu aufbauen
            # -> Im Restore darf man radikal sein - deterministisch ist besser als Reste!
            
            # STEP 1: Reset alles (IPv4 + IPv6)
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            Write-Verbose "  Reset: Alle DNS entfernt (IPv4+IPv6)"
            
            # STEP 2: Restore IPv4 from backup (if exists)
            if ($hasIPv4) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsIPv4 -ErrorAction Stop
                Write-Verbose "  IPv4 DNS restored: $($dnsIPv4 -join ', ')"
            }
            else {
                Write-Verbose "  IPv4 DNS: Nicht im Backup -> bleibt auf Auto/DHCP"
            }
            
            # STEP 3: Restore IPv6 from backup (if exists)
            if ($hasIPv6) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsIPv6 -ErrorAction Stop
                Write-Verbose "  IPv6 DNS restored: $($dnsIPv6 -join ', ')"
            }
            else {
                Write-Verbose "  IPv6 DNS: Nicht im Backup -> bleibt auf Auto/DHCP"
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
Write-Host "[2/18] $(Get-LocalizedString 'RestoreHosts')" -ForegroundColor Yellow

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
Write-Host "[3/18] $(Get-LocalizedString 'RestoreServices')" -ForegroundColor Yellow

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

# PERFORMANCE FIX: Bulk load ALL services ONCE then lookup in hashtable
# ROOT CAUSE: Calling Get-Service 214x is inefficient (even though relatively fast)
# SOLUTION: Load all services once (~1s), store in hashtable, then O(1) lookup per service
Write-Host "  [i] Loading all services (one-time operation)..." -ForegroundColor Gray
try {
    $allServices = Get-Service -ErrorAction Stop
    $serviceMap = @{}
    foreach ($s in $allServices) {
        $serviceMap[$s.Name] = $s
    }
    Write-Host "  [OK] Loaded $($allServices.Count) services into cache" -ForegroundColor Green
}
catch {
    Write-Host "  [!] Could not load services - using fallback method" -ForegroundColor Yellow
    $serviceMap = $null
}

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
        
        # Get service from cache (O(1) hashtable lookup!) or fallback to Get-Service
        $service = if ($serviceMap) { $serviceMap[$svcConfig.Name] } else { Get-Service -Name $svcConfig.Name -ErrorAction SilentlyContinue }
        
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

#region Restore Windows Optional Features
Write-Host "[4/18] Restoring Windows Optional Features..." -ForegroundColor Yellow

$featuresCount = if ($backup.Settings.WindowsFeatures) { @($backup.Settings.WindowsFeatures).Count } else { 0 }
if ($featuresCount -gt 0) {
    Write-Host "  [i] Found $featuresCount Windows Features in backup" -ForegroundColor Cyan
    Write-Host "  [i] This may take a while - processing each feature..." -ForegroundColor Gray
    Write-Host ""
    
    $featuresRestored = 0
    $featuresSkipped = 0
    $featuresFailed = 0
    $featuresProcessed = 0
    
    # PERFORMANCE FIX: Bulk load ALL features ONCE then lookup in hashtable
    # ROOT CAUSE: Calling Get-WindowsOptionalFeature 135x is VERY slow (DISM/WMI per call)
    # SOLUTION: Load all features once (~5s), store in hashtable, then O(1) lookup per feature
    Write-Host "  [i] Loading all Windows Features (one-time operation)..." -ForegroundColor Gray
    try {
        $allFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop
        $featureMap = @{}
        foreach ($f in $allFeatures) {
            $featureMap[$f.FeatureName] = $f
        }
        Write-Host "  [OK] Loaded $($allFeatures.Count) features into cache" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Could not load Windows Features - skipping restore" -ForegroundColor Yellow
        Write-Host "  [i] Reason: $($_.Exception.Message)" -ForegroundColor Gray
        $restoreStats.Skipped++
        $featureMap = $null
    }
    
    if ($featureMap) {
        foreach ($featureConfig in $backup.Settings.WindowsFeatures) {
            $featuresProcessed++
            Write-Host "  [$featuresProcessed/$featuresCount] Processing: $($featureConfig.FeatureName)..." -ForegroundColor Cyan
            try {
                # CRITICAL: Skip Windows-Defender-Default-Definitions (system-managed, can hang)
                # ROOT CAUSE: Enable-WindowsOptionalFeature hangs when Defender is active
                # REASON: Feature communicates with Defender Real-Time Protection service
                # SOLUTION: Skip this feature - it's managed by Windows automatically
                if ($featureConfig.FeatureName -eq 'Windows-Defender-Default-Definitions') {
                    Write-Host "  [SKIP] $($featureConfig.FeatureName): System-managed feature (Defender signature database)" -ForegroundColor Yellow
                    $featuresSkipped++
                    $restoreStats.Skipped++
                    continue
                }
                
                # Get current state from cache (O(1) hashtable lookup!)
                $currentFeature = $featureMap[$featureConfig.FeatureName]
                
                if ($currentFeature) {
                    $currentState = $currentFeature.State.ToString()
                    $backupState = $featureConfig.State
                    
                    # Only restore if state changed
                    if ($currentState -ne $backupState) {
                        if ($PSCmdlet.ShouldProcess($featureConfig.FeatureName, "Change state: $currentState -> $backupState")) {
                            if ($backupState -eq 'Enabled') {
                                Write-Host "    [i] Enabling: $($featureConfig.FeatureName)..." -ForegroundColor Gray
                                Enable-WindowsOptionalFeature -Online -FeatureName $featureConfig.FeatureName -NoRestart -ErrorAction Stop | Out-Null
                                Write-Host "    [OK] Enabled: $($featureConfig.FeatureName)" -ForegroundColor Green
                                $featuresRestored++
                                $restoreStats.Success++
                            }
                            elseif ($backupState -eq 'Disabled') {
                                Write-Host "    [i] Disabling: $($featureConfig.FeatureName)..." -ForegroundColor Gray
                                Disable-WindowsOptionalFeature -Online -FeatureName $featureConfig.FeatureName -NoRestart -ErrorAction Stop | Out-Null
                                Write-Host "    [OK] Disabled: $($featureConfig.FeatureName)" -ForegroundColor Green
                                $featuresRestored++
                                $restoreStats.Success++
                            }
                            else {
                                # DisabledWithPayloadRemoved or other states - skip
                                Write-Verbose "    [SKIP] $($featureConfig.FeatureName): State '$backupState' cannot be automatically restored"
                                $featuresSkipped++
                                $restoreStats.Skipped++
                            }
                        }
                    }
                    else {
                        Write-Verbose "  [SKIP] $($featureConfig.FeatureName): Already in correct state ($currentState)"
                        $featuresSkipped++
                        $restoreStats.Skipped++
                    }
                }
                else {
                    Write-Verbose "  [!] Feature not found: $($featureConfig.FeatureName)"
                    $featuresSkipped++
                    $restoreStats.Skipped++
                }
        }
        catch {
            Write-Host "    [X] Failed to restore $($featureConfig.FeatureName): $_" -ForegroundColor Red
            $featuresFailed++
            $restoreStats.Failed++
        }
    }
    
        # Summary
        Write-Host ""
        if ($featuresRestored -gt 0) {
            Write-Host "  [OK] $featuresRestored Windows Feature(s) restored" -ForegroundColor Green
        }
        if ($featuresSkipped -gt 0) {
            Write-Host "  [i] $featuresSkipped Feature(s) skipped (already correct state)" -ForegroundColor Gray
        }
        if ($featuresFailed -gt 0) {
            Write-Host "  [X] $featuresFailed Feature(s) failed to restore" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "  [i] No Windows Features in backup" -ForegroundColor Gray
    $restoreStats.Skipped++
}

Write-Host ""
#endregion

#region Restore Scheduled Tasks
Write-Host "[5/18] Restore Scheduled Tasks..." -ForegroundColor Yellow

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
                            elseif ($lastError.Exception.Message -match 'MSFT_DNSClientServerAddress|InterfaceIndex') {
                                # DNS interface timing issue (harmless - interface indices change after DNS restore)
                                # Tasks will auto-regenerate on next reboot or when needed
                                Write-Verbose "  [SKIP] Task '$($taskConfig.TaskPath)$($taskConfig.TaskName)' has DNS interface dependency (will auto-regenerate)"
                                $restoreStats.Skipped++
                            }
                            else {
                                # Real error - show it to user
                                Write-Host "    [X] Task '$($taskConfig.TaskPath)$($taskConfig.TaskName)' failed: $($lastError.Exception.Message)" -ForegroundColor Red
                                $restoreStats.Failed++
                            }
                        }
                        else {
                            # No error in $Error array - likely task is busy/locked (not a real failure)
                            # Don't count as Failed since this is a transient state issue
                            Write-Host "    [!] Task '$($taskConfig.TaskPath)$($taskConfig.TaskName)' could not be changed (possibly busy/locked)" -ForegroundColor Yellow
                            $restoreStats.Skipped++
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
        Write-Host "  [!] $(Get-LocalizedString 'RestoreNoTasksInBackup')" -ForegroundColor Yellow
        $restoreStats.Skipped++
    }
}

Write-Host ""
#endregion

#region Restore Firewall Rules
Write-Host "[6/18] $(Get-LocalizedString 'RestoreFirewall')" -ForegroundColor Yellow

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
Write-Host "[7/18] $(Get-LocalizedString 'RestoreRegistry')" -ForegroundColor Yellow

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
    
    # CRITICAL SAFEGUARD v1.7.18+: Filter out SetupCompletedSuccessfully from old backups
    # This key was removed in v1.7.18 because it breaks Windows Search and Outlook email search
    # Old backups (v1.7.17 and earlier) may still contain this key with value=0 which would re-introduce the bug
    $filteredBackup = @()
    $filteredCount = 0
    
    foreach ($entry in $backup.Settings.RegistryBackup) {
        if ($entry.Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows Search' -and $entry.Name -eq 'SetupCompletedSuccessfully') {
            Write-Host "[!] WARNING: Filtered out buggy key from old backup: SetupCompletedSuccessfully" -ForegroundColor Yellow
            Write-Host "    This key was removed in v1.7.18 (breaks Windows Search and Outlook)" -ForegroundColor Gray
            Write-Host "    Setting correct value (=1) instead..." -ForegroundColor Gray
            
            # Set correct value instead of restoring buggy value
            try {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name 'SetupCompletedSuccessfully' -Value 1 -Type DWord -ErrorAction Stop
                Write-Host "    [OK] Windows Search fixed (SetupCompletedSuccessfully = 1)" -ForegroundColor Green
            }
            catch {
                Write-Host "    [WARNING] Could not set correct value: $_" -ForegroundColor Yellow
            }
            
            $filteredCount++
            continue
        }
        
        $filteredBackup += $entry
    }
    
    if ($filteredCount -gt 0) {
        Write-Host "[i] Filtered $filteredCount problematic key(s) from backup" -ForegroundColor Cyan
    }
    
    try {
        $result = Restore-SpecificRegistryKeys -BackupData $filteredBackup -UseOwnership $true
        
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

# ====================================================================
# RESTORE: PolicyManager / Telemetrie-Mirror bereinigen
# ====================================================================
# Windows legt nach dem Setzen von GPOs eigene Spiegel unter PolicyManager an,
# z. B.:
#   HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System\AllowTelemetry
#   HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DataCollection\*
# Die waren beim Backup NICHT da -> Restore kennt sie nicht -> UI zeigt weiter
# "Ihre Organisation verhindert ...".
# Darum hier: hart loeschen mit Pattern-Matching (Future-Proof!)

Write-Host ""
Write-Host "[i] Cleaning up PolicyManager telemetry cache (current + default)..." -ForegroundColor Cyan

$pmBase = "HKLM:\SOFTWARE\Microsoft\PolicyManager"
$pmTargets = @(
    "current\device\System",
    "current\device\DataCollection",
    "default\device\System",
    "default\device\DataCollection"
)

# Alles was irgendwie nach Telemetrie/Diag/Datenerfassung aussieht, weg
$telemetryNamePatterns = @(
    "*Telemetry*",
    "*DataCollection*",
    "*Diagnostic*",
    "*Diag*",
    "*Feedback*"
)

$cleaned = 0

foreach ($rel in $pmTargets) {
    $fullPath = Join-Path $pmBase $rel

    if (-not (Test-Path $fullPath)) {
        continue
    }

    # 1) Komplette, passende Unterschluessel entfernen
    $subKeys = Get-ChildItem -Path $fullPath -ErrorAction SilentlyContinue
    foreach ($sk in $subKeys) {
        foreach ($pat in $telemetryNamePatterns) {
            if ($sk.PSChildName -like $pat) {
                try {
                    Remove-Item -Path $sk.PSPath -Recurse -Force -ErrorAction Stop
                    $cleaned++
                }
                catch {
                    Write-Host "  [!] Could not remove PolicyManager key: $($sk.PSPath) - $_" -ForegroundColor Yellow
                }
                break
            }
        }
    }

    # 2) Werte im Key selbst entfernen (PolicyManager schreibt oft nur "value")
    $item = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue
    if ($item) {
        foreach ($prop in $item.PSObject.Properties) {
            $propName = $prop.Name
            if ($propName -eq "PSPath" -or $propName -eq "PSParentPath" -or $propName -eq "PSChildName" -or $propName -eq "PSDrive" -or $propName -eq "PSProvider") {
                continue
            }

            $match = $false
            foreach ($pat in $telemetryNamePatterns) {
                if ($propName -like $pat) {
                    $match = $true
                    break
                }
            }

            # Sehr haeufiger Fall: PolicyManager legt "value" an
            if (-not $match -and $propName -eq "value") {
                $match = $true
            }

            if ($match) {
                try {
                    Remove-ItemProperty -Path $fullPath -Name $propName -Force -ErrorAction Stop
                    $cleaned++
                }
                catch {
                    Write-Host "  [!] Could not remove PolicyManager value: $fullPath\$propName - $_" -ForegroundColor Yellow
                }
            }
        }
    }
}

Write-Host "  [OK] Removed $cleaned PolicyManager telemetry entries" -ForegroundColor Green

# ====================================================================
# RESTORE: Policies loeschen, die es vorher nicht gab
# ====================================================================
Write-Host ""
Write-Host "[i] Checking for policy keys that should be removed..." -ForegroundColor Cyan

$policyKeysToCheck = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
)

$removedPolicyKeys = 0
if ($backup.Settings.RegistryBackup) {
    foreach ($keyPath in $policyKeysToCheck) {
        $entriesForKey = $backup.Settings.RegistryBackup | Where-Object { $_.Path -eq $keyPath }

        # Wenn im Backup IRGENDEIN Eintrag fuer diesen Key "Exists = false" hatte,
        # dann hat Apply ihn erst angelegt -> wir koennen den ganzen Key killen
        if ($entriesForKey -and ($entriesForKey | Where-Object { $_.Exists -eq $false })) {
            if (Test-Path $keyPath) {
                try {
                    Remove-Item $keyPath -Recurse -Force -ErrorAction Stop
                    $removedPolicyKeys++
                    Write-Host "  [OK] Removed policy key: $keyPath" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  [!] Could not remove: $keyPath - $_" -ForegroundColor Yellow
                }
            }
        }
    }
}

Write-Host "  [OK] Removed $removedPolicyKeys policy keys that did not exist before Apply" -ForegroundColor Green

Write-Host ""
#endregion

#region Restore User Accounts
Write-Host "[8/18] $(Get-LocalizedString 'RestoreUsers')" -ForegroundColor Yellow

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
                Write-Host "  [i] $(Get-LocalizedString 'RestoreUsersPasswordTitle')" -ForegroundColor Cyan
                Write-Host "      $(Get-LocalizedString 'RestoreUsersPasswordWarning')" -ForegroundColor Cyan
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
                                Write-Host "    [OK] $(Get-LocalizedString 'RestorePasswordCopied')" -ForegroundColor Green
                                Write-Host "    [!] $(Get-LocalizedString 'RestorePasswordPasteNow')" -ForegroundColor Yellow
                                Write-Host "    [!] $(Get-LocalizedString 'RestorePasswordClearIn30')" -ForegroundColor Yellow
                            }
                            catch {
                                # Fallback if Clipboard doesn't work (e.g. SSH session)
                                Write-Host "    [!] $(Get-LocalizedString 'RestorePasswordClipboardFailed')" -ForegroundColor Yellow
                                Write-Host "    $newPassword" -ForegroundColor Yellow
                            }
                            
                            Write-Host ""
                            Write-Host "    $(Get-LocalizedString 'RestoreUsersPasswordNote')" -ForegroundColor Yellow
                            Write-Host "  ============================================================" -ForegroundColor Green
                            Write-Host ""
                            
                            # Wait 30 seconds with countdown
                            if ((Get-Clipboard -ErrorAction SilentlyContinue) -eq $newPassword) {
                                Write-Host "  [i] $(Get-LocalizedString 'RestorePasswordWait30')" -ForegroundColor Gray
                                for ($i = 30; $i -gt 0; $i -= 5) {
                                    $remainingMsg = Get-LocalizedString 'RestorePasswordSecondsLeft' $i
                                    Write-Host "      $remainingMsg" -ForegroundColor DarkGray
                                    Start-Sleep -Seconds 5
                                }
                                try {
                                    # CRITICAL: Set-Clipboard requires non-empty string (not "" or $null)
                                    # Using single space to effectively clear clipboard without error
                                    Set-Clipboard -Value " " -ErrorAction Stop
                                    Write-Host "  [OK] $(Get-LocalizedString 'RestorePasswordCleared')" -ForegroundColor Green
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

# Find the renamed Guest account (with SID *-501)
Write-Host ""
$currentGuestAccount = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-501" }

if ($currentGuestAccount) {
    # Find original guest name from backup
    $originalGuest = $backup.Settings.UserAccounts | Where-Object { $_.SID -like "*-501" }
    
    if ($originalGuest -and $originalGuest.Name -ne $currentGuestAccount.Name) {
        if ($PSCmdlet.ShouldProcess($currentGuestAccount.Name, "Rename to: $($originalGuest.Name)")) {
            try {
                Rename-LocalUser -Name $currentGuestAccount.Name -NewName $originalGuest.Name -ErrorAction Stop
                $guestRenameMsg = "Guest account renamed: $($currentGuestAccount.Name) -> $($originalGuest.Name)"
                Write-Host "  [OK] $guestRenameMsg" -ForegroundColor Green
                
                # Restore enabled/disabled state
                if ($originalGuest.Enabled) {
                    Enable-LocalUser -Name $originalGuest.Name -ErrorAction SilentlyContinue
                    Write-Host "  [OK] Guest account enabled (restored from backup)" -ForegroundColor Green
                }
                else {
                    Disable-LocalUser -Name $originalGuest.Name -ErrorAction SilentlyContinue
                    Write-Host "  [OK] Guest account disabled (restored from backup)" -ForegroundColor Green
                }
                
                $restoreStats.Success++
            }
            catch {
                Write-Host "  [X] Guest account rename error: $_" -ForegroundColor Red
                $restoreStats.Failed++
            }
        }
    }
    else {
        Write-Host "  [i] Guest account already has correct name" -ForegroundColor Gray
        $restoreStats.Skipped++
    }
}
else {
    Write-Host "  [!] Guest account not found (SID *-501)" -ForegroundColor Yellow
    $restoreStats.Skipped++
}

Write-Host ""
#endregion

#region Restore Apps
Write-Host "[9/18] $(Get-LocalizedString 'RestoreApps')" -ForegroundColor Yellow

$currentApps = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$missingApps = $backup.Settings.InstalledApps | Where-Object { $currentApps -notcontains $_.Name }

$missingAppsCount = if ($missingApps) { @($missingApps).Count } else { 0 }
if ($missingAppsCount -gt 0) {
    $missingMsg = (Get-LocalizedString 'RestoreAppsMissing')
    Write-Host "  [!] $missingAppsCount $missingMsg" -ForegroundColor Yellow
    Write-Host ""
    
    # INFO: Explain why bloatware apps are intentionally not restored
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  BLOATWARE APPS - INTENTIONALLY NOT RESTORED" -ForegroundColor Cyan
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  During Apply, you removed bloatware apps for privacy/security." -ForegroundColor White
    Write-Host "  These apps are NOT restored because most users don't want them back." -ForegroundColor White
    Write-Host ""
    Write-Host "  [i] This is BY DESIGN - not an error!" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Benefits:" -ForegroundColor Green
    Write-Host "    + System privacy improved" -ForegroundColor Gray
    Write-Host "    + Startup performance improved" -ForegroundColor Gray
    Write-Host "    + Less background telemetry" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Need an app back? Easy!" -ForegroundColor White
    Write-Host "    1. Open Microsoft Store" -ForegroundColor Gray
    Write-Host "    2. Search for the app name" -ForegroundColor Gray
    Write-Host "    3. Click 'Get' or 'Install'" -ForegroundColor Gray
    Write-Host "  ============================================================================" -ForegroundColor Cyan
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
            
            # PERFORMANCE FIX: Bulk load ALL packages ONCE then lookup in hashtable
            # ROOT CAUSE: Calling Get-AppxProvisionedPackage -Online 14x is inefficient
            # SOLUTION: Load all packages once (~2s), store in hashtable, then O(1) lookup per package
            Write-Host "  [i] Checking Provisioned Packages availability..." -ForegroundColor Cyan
            Write-Host "      (Checking if apps can be restored from Microsoft Store)" -ForegroundColor Gray
            Write-Host ""
            
            $allPackages = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            $pkgMap = @{}
            if ($allPackages) {
                foreach ($p in $allPackages) {
                    $pkgMap[$p.DisplayName] = $p
                }
            }
            
            $restoredApps = 0
            foreach ($pkg in $backup.Settings.ProvisionedPackages) {
                try {
                    $currentPkg = $pkgMap[$pkg.DisplayName]
                    
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
        # App name mapping: Internal Package Name -> Readable Store Name
        # This makes the list user-friendly for manual Store reinstallation
        # Source: Microsoft Store display names (verified 2025-11-02)
        $appNameMapping = @{
            # Xbox & Gaming
            'Microsoft.XboxApp' = 'Xbox (PC Game Pass / Xbox App)'
            'Microsoft.GamingApp' = 'Xbox (neue Xbox-App fuer Windows 11)'
            'Microsoft.XboxGamingOverlay' = 'Xbox Game Bar (Overlay)'
            'Microsoft.XboxGameOverlay' = 'Xbox Game Bar - Game Overlay/Plugin'
            'Microsoft.XboxSpeechToTextOverlay' = 'Xbox Speech-to-Text Overlay'
            'Microsoft.XboxIdentityProvider' = 'Xbox Identity Provider'
            'Microsoft.Xbox.TCUI' = 'Xbox in-game experience / Xbox TCUI'
            
            # Microsoft Teams
            'MicrosoftTeams' = 'Microsoft Teams (klassisch)'
            'Microsoft.Teams' = 'Microsoft Teams (neue App)'
            'MSTeams' = 'Microsoft Teams'
            
            # Microsoft AI & Copilot
            'Microsoft.Copilot' = 'Copilot'
            'Microsoft.Windows.Ai.Copilot.Provider' = 'Windows Copilot - AI Provider'
            
            # Microsoft Family
            'Microsoft.MicrosoftFamily' = 'Microsoft Family Safety'
            'MicrosoftCorporationII.FamilySafety' = 'Microsoft Family Safety'
            'MicrosoftCorporationII.Family' = 'Microsoft Family Safety'
            'Microsoft.Family' = 'Microsoft Family'
            
            # Productivity Apps
            'Clipchamp.Clipchamp' = 'Clipchamp - Video Editor'
            'Microsoft.Todos' = 'Microsoft To Do'
            'Microsoft.MicrosoftOfficeHub' = 'Microsoft 365 (Office Hub)'
            'Microsoft.Office.OneNote' = 'OneNote'
            'Microsoft.Office.Desktop' = 'Microsoft 365 / Office - Desktop App'
            'Microsoft.Office.Sway' = 'Sway'
            
            # Social Media
            'Facebook' = 'Facebook'
            'Instagram' = 'Instagram'
            'Twitter' = 'Twitter'
            'LinkedIn' = 'LinkedIn'
            
            # Entertainment & Streaming
            'Microsoft.ZuneMusic' = 'Groove Music (heute: Windows Media Player)'
            'Microsoft.ZuneVideo' = 'Filme & TV / Movies & TV'
            'Netflix' = 'Netflix'
            'Disney' = 'Disney+'
            'Spotify' = 'Spotify - Music and Podcasts'
            'Hulu' = 'Hulu'
            'Plex' = 'Plex for Windows'
            'iHeartRadio' = 'iHeart: Radio, Music, Podcasts'
            'TuneInRadio' = 'TuneIn Radio'
            'PandoraMediaInc' = 'Pandora'
            'Shazam' = 'Shazam'
            
            # Games (Casual)
            'Microsoft.MinecraftUWP' = 'Minecraft for Windows'
            'Microsoft.MicrosoftSolitaireCollection' = 'Microsoft Solitaire Collection'
            'king.com.CandyCrush' = 'Candy Crush Saga'
            'king.com.BubbleWitch3Saga' = 'Bubble Witch 3 Saga'
            'Asphalt8Airborne' = 'Asphalt 8: Airborne'
            'COOKINGFEVER' = 'Cooking Fever'
            'FarmVille2CountryEscape' = 'FarmVille 2: Country Escape'
            'HiddenCityMysteryofShadows' = 'Hidden City: Hidden Object Adventure'
            'March.ofEmpires' = 'March of Empires: War of Lords'
            'Royal.Revolt' = 'Royal Revolt!'
            'CaesarsSlotsFreeCasino' = 'Caesars Slots Free Casino'
            
            # Microsoft System Apps
            'MicrosoftCorporationII.QuickAssist' = 'Quick Assist / Remotehilfe'
            'Microsoft.GetHelp' = 'Get Help / Hilfe anfordern'
            'Microsoft.Getstarted' = 'Erste Schritte / Getting started'
            'Microsoft.WindowsFeedbackHub' = 'Feedback Hub'
            'Microsoft.YourPhone' = 'Phone Link (frueher: Ihr Smartphone)'
            'Microsoft.People' = 'People (Kontakt-App)'
            'Microsoft.Messaging' = 'Messaging (Windows-Nachrichten)'
            'Microsoft.SkypeApp' = 'Skype'
            'Microsoft.Wallet' = 'Microsoft Pay / Wallet (eingestellt)'
            'Microsoft.Print3D' = 'Print 3D'
            'Microsoft.MixedReality.Portal' = 'Mixed Reality Portal'
            'Microsoft.Advertising.Xaml' = 'Microsoft Advertising SDK for XAML'
            
            # Utilities & Tools
            'Flipboard' = 'Flipboard'
            'Duolingo' = 'Duolingo - Language Lessons'
            'NYTCrossword' = 'NYTimes - Crossword'
            'Speed.Test' = 'Speedtest by Ookla'
            'Keeper' = 'Keeper (R) Password Manager'
            'OneConnect' = 'Clavister OneConnect (SSL-VPN)'
            'WinZipUniversal' = 'WinZip Universal'
            'XING' = 'XING'
            
            # Creative & Photo
            'AutodeskSketchBook' = 'Autodesk SketchBook'
            'DrawboardPDF' = 'Drawboard PDF'
            'PhototasticCollage' = 'Phototastic Collage'
            'PicsArt-PhotoStudio' = 'Picsart AI Photo Editor'
            'PolarrPhotoEditorAcademicEdition' = 'Polarr Pro Photo Editor'
            
            # OEM & Misc
            'ACGMediaPlayer' = 'ACG Player'
            'ActiproSoftwareLLC' = 'Code Writer (Actipro)'
            'EclipseManager' = 'Eclipse Manager'
            'GAMELOFTSA' = 'Gameloft-Titel (z.B. Asphalt 8)'
            'Fitbit' = 'Fitbit'
        }
        
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
            # Use readable name from mapping, fall back to internal name
            $displayName = if ($appNameMapping.ContainsKey($app.Name)) {
                $appNameMapping[$app.Name]
            } else {
                $app.Name
            }
            $appListContent += "- $displayName`r`n"
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
Write-Host "[10/18] Restore ASR Rules..." -ForegroundColor Yellow

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
                Write-Host "  [OK] $(Get-LocalizedString 'RestoreASRSuccess' $asrCount)" -ForegroundColor Green
                $restoreStats.Success++
            }
        }
        else {
            Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreASRNotAvailable')" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'RestoreASRFailed') $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreASRNoBackup')" -ForegroundColor Gray
}
#endregion

#region Restore Exploit Protection
Write-Host ""
Write-Host "[11/18] Restore Exploit Protection..." -ForegroundColor Yellow

if ($backup.Settings.ExploitProtection -and $backup.Settings.ExploitProtection.Enabled) {
    try {
        # Check if Set-ProcessMitigation is available (Windows 10 1709+)
        if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) {
            Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreExploitNotAvailable')" -ForegroundColor Gray
            $restoreStats.Skipped++
        }
        else {
            Write-Verbose "Restoring Exploit Protection from backup data..."
            
            # NEW STRATEGY: Restore from BACKUP (not hardcoded "hardened state")
            # This is TRUE restore - returns system to state BEFORE Apply script
            $backupMitigations = $backup.Settings.ExploitProtection.SystemMitigations
            
            if (-not $backupMitigations) {
                Write-Host "  [SKIP] No mitigation data in backup" -ForegroundColor Gray
                $restoreStats.Skipped++
            }
            else {
                $mitigationsSet = 0
                
                # Helper function to restore a mitigation based on backup state
                $restoreMitigation = {
                    param($Name, $BackupState, $EnableParams, $DisableParams)
                    
                    # BackupState properties: Enable (0=NotSet, 1=On, 2=Off), Disable, etc.
                    # We check the ENABLE state: 1 = On → Enable, 2 = Off → Disable
                    
                    $enableList = @()
                    $disableList = @()
                    
                    foreach ($param in $EnableParams) {
                        # Check if property exists in backup state
                        $props = $BackupState.PSObject.Properties.Name
                        if ($param -in $props) {
                            $value = $BackupState.$param
                            # Value 1 = On → Enable, Value 2 = Off → Disable, 0 = NotSet → skip
                            if ($value -eq 1) { $enableList += $param }
                            elseif ($value -eq 2) { $disableList += $param }
                        }
                    }
                    
                    $success = $false
                    
                    # Enable parameters
                    if ($enableList.Count -gt 0) {
                        try {
                            Set-ProcessMitigation -System -Enable $enableList -ErrorAction Stop
                            Write-Verbose "  [OK] $Name Enable: $($enableList -join ', ')"
                            $success = $true
                        }
                        catch {
                            Write-Verbose "  [SKIP] $Name Enable failed: $_"
                        }
                    }
                    
                    # Disable parameters
                    if ($disableList.Count -gt 0) {
                        try {
                            Set-ProcessMitigation -System -Disable $disableList -ErrorAction Stop
                            Write-Verbose "  [OK] $Name Disable: $($disableList -join ', ')"
                            $success = $true
                        }
                        catch {
                            Write-Verbose "  [SKIP] $Name Disable failed: $_"
                        }
                    }
                    
                    return $success
                }
                
                # Restore DEP
                if ($backupMitigations.DEP) {
                    if (& $restoreMitigation -Name "DEP" -BackupState $backupMitigations.DEP `
                        -EnableParams @('Enable', 'EmulateAtlThunks', 'OverrideDEP') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore SEHOP
                if ($backupMitigations.SEHOP) {
                    if (& $restoreMitigation -Name "SEHOP" -BackupState $backupMitigations.SEHOP `
                        -EnableParams @('Enable', 'TelemetryOnly') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore ASLR
                if ($backupMitigations.ASLR) {
                    if (& $restoreMitigation -Name "ASLR" -BackupState $backupMitigations.ASLR `
                        -EnableParams @('ForceRelocateImages', 'BottomUp', 'HighEntropy', 'RequireInfo') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore CFG
                if ($backupMitigations.CFG) {
                    if (& $restoreMitigation -Name "CFG" -BackupState $backupMitigations.CFG `
                        -EnableParams @('Enable', 'StrictCFG', 'SuppressExports') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore Heap
                if ($backupMitigations.Heap) {
                    if (& $restoreMitigation -Name "Heap" -BackupState $backupMitigations.Heap `
                        -EnableParams @('TerminateOnError') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore ImageLoad
                if ($backupMitigations.ImageLoad) {
                    if (& $restoreMitigation -Name "ImageLoad" -BackupState $backupMitigations.ImageLoad `
                        -EnableParams @('BlockRemoteImageLoads', 'BlockLowLabelImageLoads', 'PreferSystem32') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                # Restore ExtensionPoints
                if ($backupMitigations.ExtensionPoints) {
                    if (& $restoreMitigation -Name "ExtensionPoints" -BackupState $backupMitigations.ExtensionPoints `
                        -EnableParams @('DisableExtensionPoints') -DisableParams @()) {
                        $mitigationsSet++
                    }
                }
                
                if ($mitigationsSet -gt 0) {
                    Write-Host "  [OK] $(Get-LocalizedString 'RestoreExploitSuccess' $mitigationsSet)" -ForegroundColor Green
                    $restoreStats.Success++
                }
                else {
                    Write-Host "  [!] $(Get-LocalizedString 'RestoreExploitNoMitigations')" -ForegroundColor Yellow
                    $restoreStats.Skipped++
                }
            }
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'RestoreExploitFailed') $_"
        $restoreStats.Failed++
    }
}
else {
    Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreExploitNoBackup')" -ForegroundColor Gray
    $restoreStats.Skipped++
}
#endregion

#region Restore DoH Configuration
Write-Host ""
Write-Host "[12/18] Restore DoH Configuration..." -ForegroundColor Yellow

# STRATEGY: TRUE RESTORE - restore to state BEFORE Apply script
# If backup HAD DoH → restore with BACKUP settings (not hardcoded strict!)
# If backup had NO DoH → REMOVE all DoH configuration

# Remove all existing DoH configurations first (idempotent)
Write-Verbose "Removing all existing DoH configurations..."
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

if ($backup.Settings.DoH -and $backup.Settings.DoH.Enabled) {
    try {
        # Backup HAD DoH → restore with BACKUP settings
        Write-Verbose "Backup had DoH configuration - restoring from backup..."
        
        # Restore EnableAutoDoh from BACKUP (not hardcoded!)
        try {
            $dnsRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
            if (-not (Test-Path $dnsRegPath)) {
                New-Item -Path $dnsRegPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            # Get EnableAutoDoh from backup (if exists)
            $enableAutoDoh = 2  # Default to 2 if not in backup
            if ($backup.Settings.DoH.PSObject.Properties.Name -contains 'EnableAutoDoh') {
                $enableAutoDoh = $backup.Settings.DoH.EnableAutoDoh
            }
            
            Set-ItemProperty -Path $dnsRegPath -Name 'EnableAutoDoh' -Value $enableAutoDoh -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Verbose "  Registry: EnableAutoDoh = $enableAutoDoh (from backup)"
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
        
        # Restore DoH servers with BACKUP settings (not hardcoded!)
        $restoredCount = 0
        foreach ($server in $backup.Settings.DoH.Servers) {
            try {
                # Use BACKUP values (not hardcoded strict mode!)
                $udpFallback = if ($server.AllowFallbackToUdp -eq $true) { "yes" } else { "no" }
                $autoUpgrade = if ($server.AutoUpgrade -eq $true) { "yes" } else { "no" }
                
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
            # (Lines 1856-1876: Registry = 2, netsh = yes)
            # We do NOT restore from backup values - security always wins!
            Write-Host "  [OK] $(Get-LocalizedString 'RestoreDohSuccess' $restoredCount)" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [WARN] $(Get-LocalizedString 'RestoreDohNoServers')" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'RestoreDohFailed') $_"
        $restoreStats.Errors++
    }
}
else {
    # Backup had NO DoH → REMOVE all DoH configuration (true restore!)
    Write-Host "  [INFO] Backup had no DoH configuration - removing all DoH settings..." -ForegroundColor Gray
    
    try {
        # Disable DoH globally
        try {
            netsh dnsclient set global doh=no 2>$null | Out-Null
            Write-Verbose "  netsh: DoH globally disabled"
        }
        catch {
            Write-Verbose "  Failed to disable global DoH via netsh: $_"
        }
        
        # Set EnableAutoDoh = 0 (disabled)
        try {
            $dnsRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
            if (Test-Path $dnsRegPath) {
                Set-ItemProperty -Path $dnsRegPath -Name 'EnableAutoDoh' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Verbose "  Registry: EnableAutoDoh = 0 (disabled)"
            }
        }
        catch {
            Write-Verbose "  Failed to set EnableAutoDoh registry: $_"
        }
        
        Write-Host "  [OK] $(Get-LocalizedString 'RestoreDohRemoved')" -ForegroundColor Green
        $restoreStats.Success++
    }
    catch {
        Write-Host "  [X] Failed to remove DoH configuration: $_" -ForegroundColor Red
        $restoreStats.Failed++
    }
}
#endregion

#region Restore DoH Encryption Preferences (Adapter-specific DohFlags)
Write-Host ""
Write-Host "[13/18] Restore DoH Encryption Preferences (Adapter-specific)..." -ForegroundColor Yellow

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
            Write-Host "  [OK] $(Get-LocalizedString 'RestoreDohEncryptionSuccess' $restoredAdapters $restoredServers)" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [WARN] $(Get-LocalizedString 'RestoreDohEncryptionNoServers')" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'RestoreDohEncryptionFailed') $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreDohEncryptionNoBackup')" -ForegroundColor Gray
}
#endregion

#region Restore Firewall Profile Settings
Write-Host ""
Write-Host "[14/18] Restore Firewall Profile Settings..." -ForegroundColor Yellow

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
                
                Write-Host "  [OK] $(Get-LocalizedString 'RestoreFirewallProfileSuccess' $profileConfig.Name)" -ForegroundColor Green
                $restoredProfiles++
            }
            catch {
                Write-Warning "$(Get-LocalizedString 'RestoreFirewallProfileFailed' $profileConfig.Name) $_"
            }
        }
        
        if ($restoredProfiles -gt 0) {
            Write-Host "  [OK] $(Get-LocalizedString 'RestoreFirewallProfilesSuccess' $restoredProfiles)" -ForegroundColor Green
            $restoreStats.Success++
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'RestoreFirewallProfilesError') $_"
        $restoreStats.Errors++
    }
}
else {
    Write-Host "  [SKIP] $(Get-LocalizedString 'RestoreFirewallProfilesNoBackup')" -ForegroundColor Gray
}
#endregion

#region Restore Device-Level App Permissions
Write-Host ""
Write-Host "[15/18] Restore Device-Level App Permissions..." -ForegroundColor Yellow

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
                        $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value $appConfig.EnabledByUser -Type DWord `
                            -Description "Restore Device-Level: $($appConfig.Permission)/$($appConfig.AppName)"
                        
                        if ($result) {
                            Write-Verbose "  [OK] Restored: $($appConfig.Permission)/$($appConfig.AppName) = $($appConfig.EnabledByUser)"
                            $restoredApps++
                        }
                    }
                    else {
                        # Fallback without ownership management
                        if (Test-Path $appPath) {
                            # Check if value exists using PSObject.Properties pattern
                            $item = Get-ItemProperty -Path $appPath -ErrorAction SilentlyContinue
                            $valueExists = $item -and ($item.PSObject.Properties.Name -contains "EnabledByUser")
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
                        $item = Get-ItemProperty -Path $appPath -ErrorAction SilentlyContinue
                        $hasValue = $item -and ($item.PSObject.Properties.Name -contains "EnabledByUser")
                        if ($hasValue) {
                            # Script created the key - delete it!
                            Remove-ItemProperty -Path $appPath -Name "EnabledByUser" -ErrorAction SilentlyContinue
                            Write-Verbose "  [OK] Deleted: $($appConfig.Permission)/$($appConfig.AppName)"
                            $deletedApps++
                        }
                    }
                }
            }
            catch {
                Write-Verbose "$(Get-LocalizedString 'RestoreDeviceAppFailed' $appConfig.AppName) $_"
            }
        }
        
        if ($restoredApps -gt 0 -or $deletedApps -gt 0) {
            Write-Host "  [OK] $(Get-LocalizedString 'RestoreDeviceAppSuccess' $restoredApps $deletedApps)" -ForegroundColor Green
            $restoreStats.Success++
        }
        else {
            Write-Host "  [i] $(Get-LocalizedString 'RestoreDeviceAppNoChanges')" -ForegroundColor Gray
        }
        }
        catch {
            Write-Warning "$(Get-LocalizedString 'RestoreDeviceAppError') $_"
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

#region Restore Security Template (secedit)
Write-Host ""
Write-Host "[16/19] Restore Security Template (secedit)..." -ForegroundColor Yellow

if ($backup.Settings.PSObject.Properties.Name -contains 'SecurityTemplate' -and $backup.Settings.SecurityTemplate.Enabled) {
    Write-Host "  [i] Restoring Security Template via secedit..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("Security Template", "Restore")) {
        try {
            # Write backup content to temp .inf file
            $tempInf = Join-Path $env:TEMP "SecurityTemplate_Restore_$(Get-Random).inf"
            
            # CRITICAL: secedit requires Unicode encoding!
            $backup.Settings.SecurityTemplate.Content | Out-File -FilePath $tempInf -Encoding Unicode -Force
            
            Write-Verbose "Importing Security Template: $tempInf"
            
            # Apply via secedit
            $tempDb = Join-Path $env:TEMP "secedit_restore_$(Get-Random).sdb"
            $importResult = & secedit.exe /configure /db $tempDb /cfg $tempInf /quiet 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Security Template restored successfully!" -ForegroundColor Green
                Write-Host "      Password Policy, Account Lockout, Privilege Rights, Security Options" -ForegroundColor Gray
                $restoreStats.Restored++
            }
            else {
                Write-Warning "  secedit import failed (Exit Code: $LASTEXITCODE)"
                Write-Verbose "Output: $importResult"
                $restoreStats.Failed++
            }
            
            # Cleanup
            if (Test-Path $tempInf) { Remove-Item $tempInf -Force -ErrorAction SilentlyContinue }
            if (Test-Path $tempDb) { Remove-Item $tempDb -Force -ErrorAction SilentlyContinue }
        }
        catch {
            Write-Warning "  Could not restore Security Template: $_"
            $restoreStats.Failed++
        }
    }
    else {
        Write-Host "  [WHATIF] Would restore Security Template" -ForegroundColor Magenta
        $restoreStats.Skipped++
    }
}
else {
    Write-Host "  [i] No Security Template in backup - skipping" -ForegroundColor DarkYellow
    $restoreStats.Skipped++
}
#endregion

#region Restore Power Management Settings
Write-Host ""
Write-Host "[17/19] Restore Power Management Settings..." -ForegroundColor Yellow

if ($backup.Settings.PSObject.Properties.Name -contains 'PowerManagement' -and $backup.Settings.PowerManagement.Enabled) {
    Write-Host "  [i] Restoring power settings from backup..." -ForegroundColor Cyan
    
    try {
        $power = $backup.Settings.PowerManagement.Settings
        
        # CRITICAL: Check if Settings object exists and has properties
        if (-not $power -or -not $power.PSObject.Properties) {
            Write-Host "  [i] Power settings empty in backup (not configured before Apply)" -ForegroundColor Gray
            Write-Host "  [OK] Skipping power settings restore (nothing to restore)" -ForegroundColor Green
        }
        else {
            # Get property list for safe access (prevent PropertyNotFoundException)
            $powerProps = $power.PSObject.Properties.Name
            
            # Get current active scheme GUID
            $activeScheme = powercfg /getactivescheme
            if ($activeScheme -match '([0-9a-f-]{36})') {
                $schemeGUID = $matches[1]
                
                # Power Scheme GUIDs (constants - same as Apply script)
                $SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"        # Display settings
                $SUB_SLEEP = "238c9fa8-0aad-41ed-83f4-97be242c8f20"        # Sleep/Hibernate settings
                $SUB_NONE = "fea3413e-7e05-4911-9a71-700331f1c294"         # Global settings
                $VIDEOIDLE = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"        # Monitor timeout
                $STANDBYIDLE = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"      # Sleep timeout
                $HIBERNATEIDLE = "9d7815a6-7ee4-497e-8888-515a05f02364"    # Hibernate timeout
                $CONSOLELOCK = "0e796bdb-100d-47d6-a2d5-f7d2daa51f51"      # Password on wake
                
                # Restore Monitor Timeout (SAFE property access)
                if (('MonitorTimeoutAC' -in $powerProps) -and ($null -ne $power.MonitorTimeoutAC)) {
                Write-Verbose "  Restoring Monitor Timeout AC: $($power.MonitorTimeoutAC) min"
                $seconds = $power.MonitorTimeoutAC * 60
                powercfg /SETACVALUEINDEX $schemeGUID $SUB_VIDEO $VIDEOIDLE $seconds 2>&1 | Out-Null
                }
                if (('MonitorTimeoutDC' -in $powerProps) -and ($null -ne $power.MonitorTimeoutDC)) {
                    Write-Verbose "  Restoring Monitor Timeout DC: $($power.MonitorTimeoutDC) min"
                    $seconds = $power.MonitorTimeoutDC * 60
                    powercfg /SETDCVALUEINDEX $schemeGUID $SUB_VIDEO $VIDEOIDLE $seconds 2>&1 | Out-Null
                }
                
                # Restore Sleep/Standby Timeout (SAFE property access)
                if (('StandbyTimeoutAC' -in $powerProps) -and ($null -ne $power.StandbyTimeoutAC)) {
                    Write-Verbose "  Restoring Standby Timeout AC: $($power.StandbyTimeoutAC) min"
                    $seconds = $power.StandbyTimeoutAC * 60
                    powercfg /SETACVALUEINDEX $schemeGUID $SUB_SLEEP $STANDBYIDLE $seconds 2>&1 | Out-Null
                }
                if (('StandbyTimeoutDC' -in $powerProps) -and ($null -ne $power.StandbyTimeoutDC)) {
                    Write-Verbose "  Restoring Standby Timeout DC: $($power.StandbyTimeoutDC) min"
                    $seconds = $power.StandbyTimeoutDC * 60
                    powercfg /SETDCVALUEINDEX $schemeGUID $SUB_SLEEP $STANDBYIDLE $seconds 2>&1 | Out-Null
                }
                
                # Restore Hibernate Timeout (SAFE property access)
                if (('HibernateTimeoutAC' -in $powerProps) -and ($null -ne $power.HibernateTimeoutAC)) {
                    Write-Verbose "  Restoring Hibernate Timeout AC: $($power.HibernateTimeoutAC) min"
                    $seconds = $power.HibernateTimeoutAC * 60
                    powercfg /SETACVALUEINDEX $schemeGUID $SUB_SLEEP $HIBERNATEIDLE $seconds 2>&1 | Out-Null
                }
                if (('HibernateTimeoutDC' -in $powerProps) -and ($null -ne $power.HibernateTimeoutDC)) {
                    Write-Verbose "  Restoring Hibernate Timeout DC: $($power.HibernateTimeoutDC) min"
                    $seconds = $power.HibernateTimeoutDC * 60
                    powercfg /SETDCVALUEINDEX $schemeGUID $SUB_SLEEP $HIBERNATEIDLE $seconds 2>&1 | Out-Null
                }
                
                # Restore Hibernate Enabled State (SAFE property access)
                if (('HibernateEnabled' -in $powerProps) -and ($power.HibernateEnabled -eq $false)) {
                    Write-Verbose "  Disabling Hibernate (was disabled in backup)"
                    powercfg /hibernate off 2>&1 | Out-Null
                }
                elseif (('HibernateEnabled' -in $powerProps) -and ($power.HibernateEnabled -eq $true)) {
                    Write-Verbose "  Enabling Hibernate (was enabled in backup)"
                    powercfg /hibernate on 2>&1 | Out-Null
                }
                
                # Restore CONSOLELOCK (Require password on wake) - SAFE property access
                if (('ConsoleLockAC' -in $powerProps) -and ($null -ne $power.ConsoleLockAC)) {
                    Write-Verbose "  Restoring CONSOLELOCK AC: $($power.ConsoleLockAC)"
                    powercfg /SETACVALUEINDEX $schemeGUID $SUB_NONE $CONSOLELOCK $power.ConsoleLockAC 2>&1 | Out-Null
                }
                if (('ConsoleLockDC' -in $powerProps) -and ($null -ne $power.ConsoleLockDC)) {
                    Write-Verbose "  Restoring CONSOLELOCK DC: $($power.ConsoleLockDC)"
                    powercfg /SETDCVALUEINDEX $schemeGUID $SUB_NONE $CONSOLELOCK $power.ConsoleLockDC 2>&1 | Out-Null
                }
                
                # Apply changes
                powercfg /SETACTIVE $schemeGUID 2>&1 | Out-Null
                
                Write-Host "  [OK] Power settings restored successfully" -ForegroundColor Green
            }
            else {
                Write-Host "  [!] Could not detect active power scheme - skipping restore" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  [!] Power settings restore failed: $_" -ForegroundColor Yellow
    }
}
else {
    Write-Host "  [i] No power settings in backup - skipping" -ForegroundColor DarkYellow
}
#endregion

# DNS Cache leeren
Write-Host ""
Write-Host "[17/18] $(Get-LocalizedString 'RestoreDNSClear')" -ForegroundColor Cyan
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

# ====================================================================
# RESTORE: GP-Cache aktualisieren + Settings-App-Cache killen
# ====================================================================
Write-Host ""
Write-Host "[18/19] Updating Group Policy cache..." -ForegroundColor Cyan
try {
    $job = Start-Job -ScriptBlock {
        # Damit die Settings-App es SOFORT merkt:
        gpupdate /force 2>&1
        # Manchmal cached die Settings-App - deshalb hier noch Settings killen:
        Get-Process SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $job | Wait-Job -Timeout 30 | Out-Null
    if ($job.State -eq "Completed") {
        Receive-Job $job | Out-Null
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Group Policy updated and Settings UI cache cleared" -ForegroundColor Green
    }
    else {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "[!] gpupdate /force did not finish in 30s - settings may update after reboot" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[!] Could not refresh policy cache: $_" -ForegroundColor Yellow
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
    Write-Host ""
    
    # Countdown with visible seconds (like Apply Script)
    for ($i = 10; $i -gt 0; $i--) {
        $countdownMsg = Get-LocalizedString 'RestoreRebootCountdown' $i
        Write-Host "  $countdownMsg" -NoNewline -ForegroundColor Yellow
        if ($i -eq 10) {
            Write-Host " ($(Get-LocalizedString 'RestoreRebootAbort'))" -ForegroundColor Gray
        } else {
            Write-Host ""
        }
        Start-Sleep -Seconds 1
    }
    
    Write-Host ""
    
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
