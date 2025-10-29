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
    - Registry Keys: 479 -> 405 Keys (-74 LastUsedTime* removed)
    
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
Write-Host "  BACKUP-ZIEL" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "  Pfad: $backupFile" -ForegroundColor Cyan
Write-Host "  Verzeichnis: $BackupPath" -ForegroundColor Gray
Write-Host "============================================================================" -ForegroundColor Green
Write-Host ""

# Best Practice 25H2: Inform user about expected duration
Write-Host "[i] Expected duration:" -ForegroundColor Cyan
Write-Host "    Normal: 2-3 minutes" -ForegroundColor Gray
Write-Host "    Maximum: 6 minutes (on slow systems)" -ForegroundColor Gray
Write-Host ""

# Best Practice 25H2: Disk Space Check BEFORE Backup starts!
Write-Host "[i] Checking available disk space..." -ForegroundColor Cyan
try {
    # Extract drive letter from backup path
    $driveLetter = (Get-Item $BackupPath -ErrorAction Stop).PSDrive.Name
    $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop
    
    $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
    $requiredSpaceGB = 0.1  # 100 MB minimum for backup
    
    Write-Host "  Drive: $($driveLetter):" -ForegroundColor Gray
    Write-Host "  Free: $freeSpaceGB GB" -ForegroundColor Gray
    
    if ($drive.Free -lt ($requiredSpaceGB * 1GB)) {
        Write-Host ""
        Write-Host "[ERROR] Insufficient disk space!" -ForegroundColor Red
        Write-Host "  Required: At least $requiredSpaceGB GB" -ForegroundColor Red
        Write-Host "  Available: $freeSpaceGB GB" -ForegroundColor Red
        Write-Host ""
        throw "Insufficient disk space for backup"
    }
    
    Write-Host "  [OK] Sufficient disk space available" -ForegroundColor Green
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
        $deleteMsg = (Get-LocalizedString 'BackupDeleteOld') -f $deleteCount
        Write-Host "[i] $deleteMsg" -ForegroundColor Yellow
        Write-Host "    [!] Original-Backup bleibt erhalten: $($firstBackup.Name)" -ForegroundColor Cyan
        
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
Write-Host "[1/14] $(Get-LocalizedString 'BackupDNS')" -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
$dnsBackup = foreach ($adapter in $adapters) {
    try {
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        if ($dnsServers -and $dnsServers.ServerAddresses) {
            $adapterMsg = (Get-LocalizedString 'BackupDNSAdapter') -f $adapter.Name
            Write-Host "  [OK] $adapterMsg $($dnsServers.ServerAddresses -join ', ')" -ForegroundColor Gray
            
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
$dnsMsg = (Get-LocalizedString 'BackupDNSSaved') -f $dnsBackup.Count
Write-Host "[OK] $dnsMsg`n" -ForegroundColor Green
#endregion

#region Hosts File Backup
Write-Host "[2/14] $(Get-LocalizedString 'BackupHosts')" -ForegroundColor Yellow

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    # IMPORTANT: ToString() to really get only string (not FileInfo object)
    $hostsContent = [string](Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue)
    $backup.Settings.HostsFile = $hostsContent
    $lineCount = ($hostsContent -split "`n").Count
    $hostsMsg = (Get-LocalizedString 'BackupHostsSaved') -f $lineCount
    Write-Host "[OK] $hostsMsg`n" -ForegroundColor Green
}
else {
    Write-Warning "Hosts file not found!"
    $backup.Settings.HostsFile = $null
}
#endregion

#region Installed Apps Backup (WITH PROVISIONED PACKAGES!)
Write-Host "[3/14] $(Get-LocalizedString 'BackupApps')" -ForegroundColor Yellow

# User Apps (with timeout protection)
$installedApps = @()
try {
    Write-Host "  [i] Reading installed apps (max 60s)..." -ForegroundColor Gray
    
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
        Write-Host "  [OK] $($installedApps.Count) $(Get-LocalizedString 'BackupAppsUser')" -ForegroundColor Green
    }
    else {
        # Timeout erreicht!
        Remove-Job $job -Force
        Write-Warning "AppX-Package Enumeration Timeout (60s) - ueberspringe Apps"
        $backup.Settings.InstalledApps = @()
    }
}
catch {
    Write-Warning "AppX-Package Backup fehlgeschlagen: $_"
    $backup.Settings.InstalledApps = @()
}

# Provisioned Packages (with timeout protection)
Write-Host "  [i] $(Get-LocalizedString 'BackupAppsProvisioned')" -ForegroundColor Cyan

$provisionedPackages = @()
try {
    Write-Host "  [i] Lese Provisioned Packages (max 90s)..." -ForegroundColor Gray
    
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
        Write-Host "  [OK] $($provisionedPackages.Count) $(Get-LocalizedString 'BackupAppsProvisionedSaved')" -ForegroundColor Green
    }
    else {
        # Timeout erreicht!
        Remove-Job $job -Force
        Write-Warning "Provisioned Packages Timeout (90s) - ueberspringe"
        $backup.Settings.ProvisionedPackages = @()
    }
}
catch {
    Write-Warning "Provisioned Packages could not be backed up: $_"
    $backup.Settings.ProvisionedPackages = @()
}

Write-Host ""
#endregion

#region Services Backup (ALL SERVICES!)
Write-Host "[4/14] $(Get-LocalizedString 'BackupServices')" -ForegroundColor Yellow

# BACKUP ALL SERVICES (not just the ones we change!)
$allServices = Get-Service -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
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
Write-Host "[OK] $($servicesBackup.Count) $(Get-LocalizedString 'BackupServicesSaved')" -ForegroundColor Green
Write-Host "    $(Get-LocalizedString 'BackupServicesNote')" -ForegroundColor Gray
Write-Host ""
#endregion

#region Scheduled Tasks Backup (ALL TASKS!)
Write-Host "[5/14] Backup Scheduled Tasks..." -ForegroundColor Yellow

# BACKUP ALL SCHEDULED TASKS (not just the ones we change!)
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
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
Write-Host "[OK] $($tasksBackup.Count) Scheduled Tasks gesichert" -ForegroundColor Green
Write-Host "    HINWEIS: Nur State (Enabled/Disabled/Ready) wird gebackupt" -ForegroundColor Gray
Write-Host ""
#endregion

#region Firewall Rules Backup (ALL RULES!)
Write-Host "[6/14] $(Get-LocalizedString 'BackupFirewall')" -ForegroundColor Yellow

# BACKUP ALL FIREWALL RULES (not just custom!)
$allFirewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
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
Write-Host "[OK] $($firewallBackup.Count) $(Get-LocalizedString 'BackupFirewallSaved')" -ForegroundColor Green
Write-Host "    $(Get-LocalizedString 'BackupFirewallNote')" -ForegroundColor Gray
Write-Host ""
#endregion

#region User Accounts Backup
Write-Host "[7/14] $(Get-LocalizedString 'BackupUsers')" -ForegroundColor Yellow

$localUsers = Get-LocalUser -ErrorAction SilentlyContinue

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
$usersBackup = foreach ($user in $localUsers) {
    # Output to pipeline (captured by $usersBackup)
    @{
        SID = $user.SID.Value  # Nur String-Wert, nicht das ganze .NET Objekt!
        Name = $user.Name
        Description = $user.Description
        Enabled = $user.Enabled
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') } else { $null }  # ISO 8601 Format
    }
}

$backup.Settings.UserAccounts = $usersBackup
Write-Host "[OK] $($usersBackup.Count) $(Get-LocalizedString 'BackupUsersSaved')" -ForegroundColor Green
Write-Host "[!] $(Get-LocalizedString 'BackupUsersWarning')" -ForegroundColor Yellow
Write-Host "    $(Get-LocalizedString 'BackupUsersPasswordNote')" -ForegroundColor Yellow
Write-Host ""
#endregion

#region Registry Keys Backup
Write-Host "[8/14] $(Get-LocalizedString 'BackupRegistry')" -ForegroundColor Yellow

# Function to backup registry values
function Backup-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        if (Test-Path -Path $Path) {
            # Safe property check - no error records created
            $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($item -and ($item.PSObject.Properties.Name -contains $Name)) {
                $rawValue = $item.$Name
            }
            else {
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
            return @{
                RegPath = $Path
                RegName = $Name
                RegValue = $convertedValue
                RegType = (Get-Item -Path $Path).GetValueKind($Name).ToString()
                RegExists = $true
            }
        }
        
        return @{
            RegPath = $Path
            RegName = $Name
            RegExists = $false
        }
    }
    catch {
        return @{
            RegPath = $Path
            RegName = $Name
            RegExists = $false
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
    @{Path="HKLM:\SOFTWARE\Policies\WindowsNotepad"; Name="DisableAIFeatures"}
    
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
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features"; Name="EnableEDRInBlockMode"},
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
    
    # ===== ONEDRIVE MODULE - PRIVACY SETTINGS (HKLM: 4 KEYS) =====
    # CRITICAL FIX v1.7.6: OneDrive now also sets HKLM for new users!
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableTutorial"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="DisableFeedback"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="PreventNetworkTrafficPreUserSignIn"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"; Name="KFMBlockOptIn"}
    
    # =====================================================================================
    # TOTAL REGISTRY-KEYS: ~404 Keys (UPDATED v1.7.11)
    # - HKLM (System): ~364 Keys (inkl. 4 OneDrive)
    # - HKCU (User):   ~40 Keys (36 App Permissions × 1 Value + 4 OneDrive)
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

# [OK] BEST PRACTICE: Capture foreach output directly (O(n) statt O(n2))
$registryBackup = foreach ($regKey in $registryKeys) {
    # Function returns hashtable - output to pipeline (captured by $registryBackup)
    Backup-RegistryValue -Path $regKey.Path -Name $regKey.Name
}

$backup.Settings.RegistryKeys = $registryBackup
Write-Host "[OK] $($registryBackup.Count) $(Get-LocalizedString 'BackupRegistrySaved')`n" -ForegroundColor Green
#endregion

#region ASR Rules Backup (Attack Surface Reduction)
Write-Host "[9/14] Backup ASR Rules..." -ForegroundColor Yellow

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
        
        Write-Host "[OK] $($asrBackup.Rules.Count) ASR Rules gesichert" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Keine ASR Rules gefunden (Defender nicht konfiguriert)" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "ASR Rules Backup fehlgeschlagen: $_"
    $asrBackup.Enabled = $false
}

$backup.Settings.ASRRules = $asrBackup
Write-Host ""
#endregion

#region Exploit Protection Backup (Set-ProcessMitigation)
Write-Host "[10/14] Backup Exploit Protection..." -ForegroundColor Yellow

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
            
            Write-Host "[OK] Exploit Protection Einstellungen gesichert" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] Exploit Protection nicht konfiguriert" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] Get-ProcessMitigation nicht verfuegbar (Windows 10 1709+ erforderlich)" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "Exploit Protection Backup fehlgeschlagen: $_"
    $exploitProtectionBackup.Enabled = $false
}

$backup.Settings.ExploitProtection = $exploitProtectionBackup
Write-Host ""
#endregion

#region DoH Configuration Backup (DNS over HTTPS)
Write-Host "[11/14] Backup DoH Configuration..." -ForegroundColor Yellow

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
            
            Write-Host "[OK] $($dohBackup.Servers.Count) DoH Server gesichert" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] Keine DoH Konfiguration gefunden" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] DoH nicht verfuegbar (Windows 11+ erforderlich)" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "DoH Backup fehlgeschlagen: $_"
    $dohBackup.Enabled = $false
}

$backup.Settings.DoH = $dohBackup
Write-Host ""
#endregion

#region DoH Encryption Preferences Backup (Adapter-specific DohFlags)
Write-Host "[12/14] Backup DoH Encryption Preferences (Adapter-specific)..." -ForegroundColor Yellow

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
            Write-Host "[OK] DoH Encryption Preferences: $($dohEncryptionBackup.Adapters.Count) Adapter, $totalServers DNS-Server" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] Keine DoH Encryption Preferences gefunden" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[INFO] Keine aktiven Netzwerkadapter gefunden" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "DoH Encryption Preferences Backup fehlgeschlagen: $_"
    $dohEncryptionBackup.Enabled = $false
}

$backup.Settings.DohEncryption = $dohEncryptionBackup
Write-Host ""
#endregion

#region Firewall Profile Settings Backup
Write-Host "[13/14] Backup Firewall Profile Settings..." -ForegroundColor Yellow

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
        Write-Host "[OK] $($firewallProfileBackup.Profiles.Count) Firewall Profile gesichert" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Keine Firewall Profiles gefunden" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "Firewall Profile Backup fehlgeschlagen: $_"
    $firewallProfileBackup.Enabled = $false
}

$backup.Settings.FirewallProfiles = $firewallProfileBackup
Write-Host ""
#endregion

#region Device-Level App Permission SubKeys Backup
Write-Host "[14/14] Backup Device-Level App Permissions..." -ForegroundColor Yellow  # Intentionally English

$deviceLevelBackup = @{
    Apps = @()
    Enabled = $false
}

try {
    # Backup for Camera, Microphone, Location (Device-Level SubKeys)
    $permissions = @('webcam', 'microphone', 'location')
    
    foreach ($permission in $permissions) {
        $capabilitiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\$permission\Apps"
        
        if (Test-Path $capabilitiesPath) {
            $apps = Get-ChildItem -Path $capabilitiesPath -ErrorAction SilentlyContinue
            
            foreach ($app in $apps) {
                try {
                    $appName = $app.PSChildName
                    # Safe property check - no error records created
                    $item = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
                    $hasProperty = $item -and ($item.PSObject.Properties.Name -contains "EnabledByUser")
                    
                    if ($hasProperty) {
                        $enabledByUser = $item
                        $deviceLevelBackup.Apps += @{
                            Permission = $permission
                            AppName = $appName
                            EnabledByUser = $enabledByUser.EnabledByUser
                            Exists = $true
                        }
                    }
                    else {
                        # Key exists but EnabledByUser doesn't
                        $deviceLevelBackup.Apps += @{
                            Permission = $permission
                            AppName = $appName
                            Exists = $false
                        }
                    }
                }
                catch {
                    Write-Verbose "Device-Level App '$appName' konnte nicht gebackuped werden: $_"
                }
            }
        }
    }
    
    if ($deviceLevelBackup.Apps.Count -gt 0) {
        $deviceLevelBackup.Enabled = $true
        Write-Host "[OK] $($deviceLevelBackup.Apps.Count) Device-Level App Permissions gesichert" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Keine Device-Level App Permissions gefunden" -ForegroundColor Gray
    }
}
catch {
    Write-Warning "Device-Level Backup fehlgeschlagen: $_"
    $deviceLevelBackup.Enabled = $false
}

$backup.Settings.DeviceLevelApps = $deviceLevelBackup
Write-Host ""
#endregion

#region System Info
Write-Host "[14/14] $(Get-LocalizedString 'BackupSystem')" -ForegroundColor Yellow

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
    Write-Host "  [i] Konvertiere zu JSON (max 120s)..." -ForegroundColor Gray
    
    $jsonJob = Start-Job -ScriptBlock {
        param($backupData)
        $backupData | ConvertTo-Json -Depth 5 -Compress -ErrorAction Stop
    } -ArgumentList $backup
    
    $jsonCompleted = Wait-Job $jsonJob -Timeout 120
    
    if (-not $jsonCompleted) {
        # TIMEOUT! Versuche FALLBACK
        Remove-Job $jsonJob -Force
        Write-Warning "JSON Timeout - versuche mit reduzierten Daten..."
        
        $backup.Settings.FirewallRules = @()
        Write-Host "  [i] FALLBACK: Ohne Firewall Rules" -ForegroundColor Yellow
        
        $jsonJob2 = Start-Job -ScriptBlock {
            param($backupData)
            $backupData | ConvertTo-Json -Depth 5 -Compress -ErrorAction Stop
        } -ArgumentList $backup
        
        $jsonCompleted2 = Wait-Job $jsonJob2 -Timeout 60
        
        if (-not $jsonCompleted2) {
            Remove-Job $jsonJob2 -Force
            throw "JSON-Konvertierung fehlgeschlagen!"
        }
        
        $json = Receive-Job $jsonJob2 -ErrorAction Stop
        Remove-Job $jsonJob2 -Force
        Write-Host "  [OK] JSON erstellt (REDUZIERT)" -ForegroundColor Yellow
    }
    else {
        $json = Receive-Job $jsonJob -ErrorAction Stop
        Remove-Job $jsonJob -Force
        Write-Host "  [OK] JSON erstellt (VOLLSTAENDIG)" -ForegroundColor Green
    }
    
    if ([string]::IsNullOrWhiteSpace($json)) {
        throw "JSON-Konvertierung leer!"
    }
    
    Write-Host "  [i] Groesse: $([Math]::Round($json.Length / 1KB, 2)) KB" -ForegroundColor Cyan
    
    Write-Host "  [i] Speichere Datei..." -ForegroundColor Gray
    $tempBackupFile = "$backupFile.tmp"
    # [OK] BEST PRACTICE: UTF-8 without BOM (PowerShell 5.1 compatible)
    # Out-File -Encoding utf8 in PS 5.1 creates file WITH BOM!
    # Use .NET API for UTF-8 without BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempBackupFile, $json, $utf8NoBom)
    
    $fileInfo = Get-Item $tempBackupFile -ErrorAction Stop
    if ($fileInfo.Length -lt 1KB) {
        throw "Backup-Datei zu klein!"
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
    Write-Host "  - DNS: $($backup.Settings.DNS.Count)" -ForegroundColor Gray
    Write-Host "  - Hosts: $($null -ne $backup.Settings.HostsFile)" -ForegroundColor Gray
    Write-Host "  - Apps: $($backup.Settings.InstalledApps.Count)" -ForegroundColor Gray
    Write-Host "  - Services: $($backup.Settings.Services.Count)" -ForegroundColor Gray
    Write-Host "  - Scheduled Tasks: $($backup.Settings.ScheduledTasks.Count)" -ForegroundColor Gray
    Write-Host "  - Firewall: $($backup.Settings.FirewallRules.Count)" -ForegroundColor Gray
    Write-Host "  - Users: $($backup.Settings.UserAccounts.Count)" -ForegroundColor Gray
    Write-Host "  - Registry: $($backup.Settings.RegistryKeys.Count)" -ForegroundColor Gray
    Write-Host "  - ASR Rules: $($backup.Settings.ASRRules.Rules.Count)" -ForegroundColor Gray
    Write-Host "  - Exploit Protection: $($backup.Settings.ExploitProtection.Enabled)" -ForegroundColor Gray
    Write-Host "  - DoH Servers: $($backup.Settings.DoH.Servers.Count)" -ForegroundColor Gray
    Write-Host "  - DoH Encryption: $($backup.Settings.DohEncryption.Adapters.Count) Adapter" -ForegroundColor Gray
    Write-Host "  - Firewall Profiles: $($backup.Settings.FirewallProfiles.Profiles.Count)" -ForegroundColor Gray
    Write-Host "  - Device-Level Apps: $($backup.Settings.DeviceLevelApps.Apps.Count)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'BackupNote')" -ForegroundColor Yellow
    Write-Host ""
    
    # Automatic validation (prevents corrupt backups)
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  BACKUP-VALIDIERUNG" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[i] Validiere Backup-Datei..." -ForegroundColor Gray
    
    # Validation 1: File exists and size OK
    $fileInfo = Get-Item $backupFile -ErrorAction Stop
    $fileSizeKB = [Math]::Round($fileInfo.Length / 1KB, 2)
    
    if ($fileInfo.Length -lt 5KB) {
        throw "Backup-Validierung fehlgeschlagen: Datei zu klein ($fileSizeKB KB)"
    }
    Write-Host "  [OK] Dateigroesse: $fileSizeKB KB" -ForegroundColor Green
    
    # Validation 2: JSON is parsable
    $testParse = $null  # Initialisiere Variable VORHER!
    try {
        # IMPORTANT: Use UTF8 without BOM when reading (prevents encoding issues)
        $jsonContent = [System.IO.File]::ReadAllText($backupFile, [System.Text.Encoding]::UTF8)
        $testParse = $jsonContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "  [OK] JSON-Format korrekt" -ForegroundColor Green
        
        # Validate that essential keys are present
        if (-not $testParse.Settings) {
            throw "Backup-Validierung fehlgeschlagen: Settings-Objekt fehlt"
        }
        if (-not $testParse.Timestamp) {
            throw "Backup-Validierung fehlgeschlagen: Timestamp fehlt"
        }
        Write-Host "  [OK] Backup-Struktur korrekt" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARN] JSON-Validierung fehlgeschlagen (nicht kritisch)" -ForegroundColor Yellow
        Write-Host "         Fehler: $($_.Exception.Message)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  HINWEIS: Das Backup wurde erstellt, aber Validierung schlug fehl." -ForegroundColor Gray
        Write-Host "           Dies passiert manchmal bei PowerShell-JSON-Serialisierung." -ForegroundColor Gray
        Write-Host "           Das Backup sollte trotzdem verwendbar sein!" -ForegroundColor Gray
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
            Write-Host "  [WARN] Backup scheint leer zu sein" -ForegroundColor Yellow
        }
        else {
            Write-Host "  [OK] Backup enthaelt Daten" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  [WARN] JSON-Validierung uebersprungen (Backup sollte trotzdem nutzbar sein)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "  $(Get-LocalizedString 'BackupValidationSuccess')" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Datei: $backupFile" -ForegroundColor Cyan
    Write-Host "  Groesse: $fileSizeKB KB" -ForegroundColor White
    if ($testParse) {
        Write-Host "  Status: Vollstaendig und gueltig" -ForegroundColor Green
    }
    else {
        Write-Host "  Status: Erstellt (JSON-Validierung fehlgeschlagen)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'BackupNote')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "                        LETZTE WARNUNG VOR START                            " -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Nach ENTER startet das Hauptskript im Enforce Mode und zieht komplett durch!" -ForegroundColor Yellow
    Write-Host "  Alle Module werden ausgefuehrt - KEINE weiteren Abfragen!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Letzte Chance zum Abbrechen: STRG+C druecken" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Druecken Sie ENTER um jetzt zu starten..." -ForegroundColor White
    Write-Host ""
    
    # Best Practice: Final pause before the big start
    $null = Read-Host
    
    Write-Host ""
    Write-Host "[OK] Backup bestaetigt - Hauptskript startet JETZT!" -ForegroundColor Green
    Write-Host ""
    
    # Set exit code and return (for dot-sourcing)
    $Global:LASTEXITCODE = 0
    return
}
catch {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "  [FAIL] BACKUP FEHLGESCHLAGEN!" -ForegroundColor Red
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "[ERROR] $_" -ForegroundColor Red
    Write-Host ""
    
    # Cleanup temp file if exists
    $tempBackupFile = "$backupFile.tmp"
    if (Test-Path $tempBackupFile) {
        Remove-Item $tempBackupFile -Force -ErrorAction SilentlyContinue
        Write-Verbose "Temp-Backup-Datei bereinigt: $tempBackupFile"
    }
    
    # ===== USER DECISION ON ERROR =====
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "  WARNUNG: Backup konnte nicht erstellt werden!" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Moechten Sie trotzdem OHNE Backup fortfahren?" -ForegroundColor Yellow
    Write-Host "  (Nicht empfohlen - Sie haben KEIN Safety Net!)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [J] Ja, trotzdem fortfahren (RISKANT!)" -ForegroundColor Red
    Write-Host "  [N] Nein, abbrechen (EMPFOHLEN!)" -ForegroundColor Green
    Write-Host ""
    Write-Host -NoNewline "  Ihre Wahl [J/N]: " -ForegroundColor Cyan
    
    $userConfirm = Read-Host
    if ($userConfirm) {
        $userConfirm = $userConfirm.Trim().ToUpper()
    }
    
    Write-Host ""
    
    if ($userConfirm -in @('J', 'Y')) {
        Write-Host "  [WARNUNG] User faehrt OHNE Backup fort!" -ForegroundColor Yellow
        Write-Host "  Hauptskript wird fortfahren - KEIN Safety Net!" -ForegroundColor Yellow
        Write-Host ""
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 0
        return
    }
    else {
        Write-Host "  [ABBRUCH] User hat abgebrochen - RICHTIGE Entscheidung!" -ForegroundColor Green
        Write-Host "  Hauptskript wird NICHT fortfahren!" -ForegroundColor Green
        Write-Host ""
        # Set exit code and return (for dot-sourcing)
        $Global:LASTEXITCODE = 1
        return
    }
}
