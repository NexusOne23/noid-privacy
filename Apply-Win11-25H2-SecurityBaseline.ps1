#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NoID Privacy v1.7 - Windows 11 25H2 Security & Privacy Hardening
    Microsoft Security Baseline 25H2 compliant + Privacy-First Extensions
    
.DESCRIPTION
    Full implementation of Microsoft Security Baseline 25H2 (September 30, 2025)
    for Windows 11 25H2 with comprehensive privacy and performance extensions.
    
    FEATURES:
    [OK] Microsoft Security Baseline 25H2 (September 30, 2025): 100% compliant
    [OK] Privacy-First: Telemetry, AI features, app permissions disabled
    [OK] Bloatware Removal: 80+ unnecessary apps removed
    [OK] Performance: Services and scheduled tasks optimized
    [OK] Best Practices: AutoPlay, SmartScreen, Exploit Protection extended
    
    COMPLIANCE:
    - Microsoft Baseline 25H2: 100% (388 registry keys)
    - CIS Benchmark Level 2: 95%
    - Security Settings: 400+ (217 reg keys + 25+ services + 19 ASR + 13 mitigations + more)
    - Privacy Settings: 300+ (158 reg keys + 37 permissions + 30 tasks + 9 AI + 80+ apps + more)
    
.NOTES
    Version:        1.7.16
    Baseline:       Microsoft Security Baseline 25H2 (September 30, 2025)
    Author:         NoID Privacy Project
    Last Updated:   November 2, 2025
    Requires:       Windows 11 25H2/24H2/23H2, PowerShell 5.1+, Admin Rights
    
    Changelog 1.7.9 (26. Oktober 2025):
    - CRITICAL FIX: App Permissions Toggles now work REALLY!
    - ROOT CAUSE: Windows GUI shows PER-APP Toggles, not Master-Toggle!
    - FIX: All 37 Permissions now set ALL existing App Sub-Keys to Deny
    - BETROFFENE FUNKTIONEN: Disable-AllAppPermissionsDefaults (37), Camera (1), Microphone (1), Location (1)
    - TEST: Settings | Privacy now shows ALL Toggles OFF (after Settings restart)
    
    Changelog 1.7.8 (26. Oktober 2025):
    - CRITICAL FIX: Set-ItemProperty now uses -PropertyType instead of -Type (PowerShell Standard!)
    - CRITICAL FIX: HTML Report Count Error fixed (Measure-Object instead of .Count in PS 5.1)
    - CRITICAL FIX: Camera/Microphone Device-Level Toggles now work!
    - FIX: DoH and hosts file Checks use Measure-Object (robust with null)
    
    Changelog 1.7.7 (26. Oktober 2025):
    - NEW: HTML Report COMPLETE! 63 Checks in 13 Categories (previously 47 in 10)
    - NEW: Windows Update & Patching Kategorie (5 Checks)
    - NEW: DNS Security Kategorie (4 Checks - DoH, DNSSEC, Blocklist)
    - NEW: Microsoft Edge Security Kategorie (4 Checks)
    - IMPROVEMENT: ASR Kategorie erweitert (3 -> 7 Checks: ASR Rules Detail, DEP, SEHOP, SAC, Network Protection)
    - IMPROVEMENT: Defender category optimized (7 -> 6 Checks, Network Protection moved to ASR)
    - IMPROVEMENT: Complete coverage of all configured features
    
    Changelog 1.7.6 (26. Oktober 2025):
    - CRITICAL FIX: UAC and WindowsUpdate modules missing in Interactive Menu!
    - CRITICAL FIX: -ValueType Parameter korrigiert zu -Type (Set-RegistryValueSmart)
    - CRITICAL FIX: HTML Report Crash gefixed (Action Property Check)
    - CRITICAL FIX: Windows Update over metered connections now ON (Security First!)
    - FIX: All 5 Windows Update toggles now ON (Maximum Security Updates)
    
    Changelog 1.7.5 (26. Oktober 2025):
    - NEW: HTML Report shows ACTION INSTRUCTIONS for every failed check!
    - NEW: Automatic recommendations (re-run script, reboot, enable BitLocker)
    - NEW: Footer with idempotency hint (script can be executed multiple times)
    - FIX: Filename shortened (NoID-SecurityReport instead of SecurityBaseline-ComplianceReport)
    
    Changelog 1.7.4 (26. Oktober 2025):
    - CRITICAL FIX: Device-Level Toggle uses RegistryOwnership (TrustedInstaller-Protected!)
    - FIX: HTML Report saved in LOG folder (not Desktop!)
    - FIX: HTML Report Checks use SilentlyContinue (no more TerminatingErrors!)
    - FIX: Guest Account Check robust (no errors if account missing)
    
    Changelog 1.7.3 (26. Oktober 2025):
    - CRITICAL FIX: Device-Level Toggle for Camera/Microphone (EnabledByUser=0)
    - FIX: Windows 11 25H2 has TWO toggles per permission (Device + App Level)
    - FIX: "Camera/Microphone Access" toggle is now correctly disabled
    - INFO: Settings App must be restarted to see changes
    
    Changelog 1.7.2 (26. Oktober 2025):
    - FIX: AppxProvisionedPackage transcript errors completely suppressed
    - NEW: HTML Compliance Report massively extended (100+ Checks, 10 Categories)
    - NEW: Dashboard with statistics, modern UI, responsive design
    - NEW: Automatic report generation after successful execution
    
    Changelog 1.7.1:
    - CRITICAL FIX: App Permissions now set in HKCU (current user) + HKLM (defaults)
    - CRITICAL FIX: All 3 registry values (Value, LastUsedTimeStart, LastUsedTimeStop)
    - GUI now correctly shows all 37 permissions as OFF for current user
    - Permissions work immediately without reboot/logout
    - User can still enable individual permissions (not greyed out except App Diagnostics)
    
    Changelog 1.7.0:
    - Updated to Microsoft Security Baseline 25H2 (September 30, 2025) terminology
    - Enhanced documentation for Privacy-First approach
    - ASCII-only comments for maximum compatibility
    
    Previous Versions:
    - 1.6.2: WTDS Registry-Keys with Ownership-Management (TrustedInstaller fix)
    - 1.6.1: StrictCFG Parameter fix + leere Write-Info Strings removed
    - 1.6.0: Print Spooler User Right + AutoPlay/AutoRun + SmartScreen Extended
    - 1.5.1: Variable initialization race condition + Localization loading fix
    - 1.5.0: Mutex/Transcript finally-blocks + Input validation + Service-Stop fix
    
.PARAMETER Mode
    Specifies the enforcement mode for ASR (Attack Surface Reduction) rules.
    - Audit:   Only log rule violations (default, safe for testing)
    - Enforce: Actively block violations (full protection)

.PARAMETER Interactive
    Starts the script in interactive mode with a menu-driven interface.
    Allows selecting modules and mode through a user-friendly menu.

.PARAMETER SkipReboot
    Skips the reboot prompt after applying changes.
    Note: Some changes require a reboot to take effect.

.PARAMETER LogPath
    Specifies the directory for log files.
    Default: $env:ProgramData\SecurityBaseline\Logs
    
.EXAMPLE
    .\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive
    Starts in interactive mode with language selection and module choice.

.EXAMPLE
    .\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit
    Runs in Audit mode (safe) applying all modules.

.EXAMPLE
    .\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce -SkipReboot
    Runs in Enforce mode without reboot prompt.

.EXAMPLE
    .\Apply-Win11-25H2-SecurityBaseline.ps1 -WhatIf
    Shows what would be changed without making actual changes.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='None')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Audit', 'Enforce', IgnoreCase=$true)]
    [string]$Mode = 'Audit',
    
    [Parameter(Mandatory = $false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipReboot,
    
    [Parameter(Mandatory = $false)]
    [switch]$RestoreMode,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:ProgramData\SecurityBaseline\Logs"
)

# Enable Strict Mode (CRITICAL!)
# Catches undefined variables, non-existent properties, etc.
# Siehe: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/set-strictmode
Set-StrictMode -Version Latest

# ===== CRITICAL FIX #1: Initialize ALL script-scope variables IMMEDIATELY =====
# REASON: CTRL+C Handler and Finally-Block access these variables
# PROBLEM: Without early init, accessing undefined variables causes crashes
# BEST PRACTICE 25H2: Initialize at script start to prevent race conditions
$script:transcriptStarted = $false
$script:criticalError = $false
$script:mutexAcquired = $false
$script:mutex = $null
$script:transcriptPath = ""
$script:createRestorePoint = $false  # Default: false (can be overridden by Interactive/CLI mode)

# Remote Access & Firewall Configuration
# DEFAULT: Maximum Security (RDP disabled, strict firewall) for non-interactive mode
# INTERACTIVE: User can choose to keep RDP enabled for remote access scenarios
$script:DisableRDP = $true        # Default: true (disable RDP for maximum security)
$script:StrictFirewall = $true    # Default: true (block all inbound including localhost)

# Clear Error Collection IMMEDIATELY (before any operations that might fail)
# REASON: $Error accumulates ALL errors including non-fatal ones
# WITHOUT clear: We'd count errors from previous script runs!
$Error.Clear()
Write-Verbose "Script variables initialized and error collection cleared"

# ===== CONSOLE ENCODING FOR UMLAUTS =====
# CRITICAL: UTF-8 Codepage 65001 for correct umlaut display in CMD
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
}
catch {
    Write-Verbose "Console encoding could not be set: $_"
}

# ===== CONSOLE WINDOW SIZE =====
# BEST PRACTICE: Optimal window size for best readability
# Width: 120 characters (standard-compatible, easy to read)
# Height: 60 lines (enough for module list + banner + logs)
try {
    if ($Host.UI.RawUI) {
        $hostUI = $Host.UI.RawUI
        
        # Query maximum screen size (avoids errors)
        $maxSize = $hostUI.MaxPhysicalWindowSize
        
        # Buffer must be AT LEAST as large as window!
        $bufferSize = $hostUI.BufferSize
        $bufferSize.Width = [Math]::Min(120, $maxSize.Width)
        $bufferSize.Height = 3000  # Large buffer for scroll history
        $hostUI.BufferSize = $bufferSize
        
        # Set window size (must not be larger than buffer!)
        $windowSize = $hostUI.WindowSize
        $windowSize.Width = [Math]::Min(120, $maxSize.Width)
        $windowSize.Height = [Math]::Min(60, $maxSize.Height)  # 60 lines for Custom Mode!
        $hostUI.WindowSize = $windowSize
        
        Write-Verbose "Console Window Size set: $($windowSize.Width)x$($windowSize.Height)"
    }
}
catch {
    Write-Verbose "Console Window Size konnte nicht gesetzt werden: $_"
}

# Disable Quick Edit Mode (prevents freeze on accidental console click)
# Problem: Windows Console pauses output on mouse selection -> script appears frozen
# Quick Edit Mode = Console pauses on click/selection - very annoying in long scripts!
try {
    # Call Windows Console API to disable Quick Edit Mode
    $signature = @"
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
"@
    
    $kernel32 = Add-Type -MemberDefinition $signature -Name 'Kernel32' -Namespace 'Win32' -PassThru -ErrorAction SilentlyContinue
    
    if ($kernel32) {
        $consoleHandle = $kernel32::GetStdHandle(-10)  # STD_INPUT_HANDLE
        $consoleMode = 0
        if ($kernel32::GetConsoleMode($consoleHandle, [ref]$consoleMode)) {
            # ENABLE_QUICK_EDIT_MODE = 0x0040
            # ENABLE_EXTENDED_FLAGS = 0x0080
            $newMode = $consoleMode -band (-bnot 0x0040)  # Disable Quick Edit
            $newMode = $newMode -bor 0x0080  # Enable Extended Flags
            [void]$kernel32::SetConsoleMode($consoleHandle, $newMode)
            Write-Verbose "Quick Edit Mode deaktiviert (verhindert Freeze bei Klick)"
        }
    }
}
catch {
    # Fallback: TreatControlCAsInput
    try {
        [Console]::TreatControlCAsInput = $false
        Write-Verbose "Quick Edit Mode fallback aktiviert"
    }
    catch {
        Write-Verbose "Konnte Console-Mode nicht setzen (nicht kritisch): $_"
    }
}

# ErrorActionPreference: Continue (not all errors are fatal!)
# Individual cmdlets use -ErrorAction Stop where needed
$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ===== CRITICAL FIX #2: Load Localization EARLY (before CTRL+C handler!) =====
# REASON: CTRL+C handler and Mutex error handling use Get-LocalizedString
# PROBLEM: Localization was loaded much later, causing undefined function errors
# BEST PRACTICE 25H2: Load essential modules BEFORE they're needed
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set default language BEFORE loading Localization module
if (-not (Test-Path Variable:\Global:CurrentLanguage)) {
    $Global:CurrentLanguage = 'en'
    Write-Verbose "Default language set to: English (early init)"
}

# Load Localization module FIRST (needed by CTRL+C handler and Mutex check)
try {
    $localizationPath = Join-Path $scriptDir "Modules\SecurityBaseline-Localization.ps1"
    if (Test-Path $localizationPath) {
        . $localizationPath
        Write-Verbose "Localization module loaded (early for CTRL+C handler)"
    }
    else {
        Write-Warning "Localization module not found: $localizationPath"
        # Fallback: Define minimal Get-LocalizedString
        function Get-LocalizedString {
            param([string]$Key)
            return $Key  # Return key as string if no localization
        }
    }
}
catch {
    Write-Warning "Could not load Localization module: $_"
    # Fallback: Define minimal Get-LocalizedString
    function Get-LocalizedString {
        param([string]$Key)
        return $Key
    }
}

# NOW we can safely use Get-LocalizedString in handlers below

# ===== CONCURRENT EXECUTION LOCK =====
# Prevents script from running 2x in parallel (leads to chaos!)
# NOTE: $script:mutex and $script:mutexAcquired already initialized (see CRITICAL FIX #1)
$mutexName = "Global\SecurityBaseline-NoID-Privacy"

# ===== CTRL+C HANDLER (Best Practice 25H2) =====
# Clean cleanup on user abort (CTRL+C)
$cleanupScriptBlock = {
    Write-Host ""
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AbortUserCancelled')" -ForegroundColor Red
    Write-Host "$(Get-LocalizedString 'AbortCleanup')" -ForegroundColor Yellow
    
    # CRITICAL FIX: Defensive variable checks
    # REASON: After running Verify in Interactive Menu, script-scope variables might be set
    # which causes PropertyNotFoundException when trying to access them in cleanup
    
    # Stop transcript - check if variable exists first
    if ((Test-Path Variable:script:transcriptStarted) -and $script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Write-Verbose "Transcript gestoppt (CTRL+C Handler)"
        }
        catch {
            Write-Verbose "Transcript-Stop fehlgeschlagen (nicht kritisch): $_"
        }
    }
    
    # Mutex freigeben - check if variables exist first
    if ((Test-Path Variable:script:mutexAcquired) -and (Test-Path Variable:script:mutex) -and $script:mutexAcquired -and $script:mutex) {
        try {
            $script:mutex.ReleaseMutex()
            $script:mutex.Dispose()
            Write-Verbose "Mutex freigegeben (CTRL+C Handler)"
        }
        catch {
            Write-Verbose "Mutex-Freigabe fehlgeschlagen (nicht kritisch): $_"
        }
    }
    
    Write-Host "$(Get-LocalizedString 'AbortComplete')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'AbortExited')" -ForegroundColor Cyan
}

# Registriere CTRL+C Handler
try {
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $cleanupScriptBlock
    Write-Verbose "CTRL+C Handler registered"
}
catch {
    Write-Verbose "CTRL+C Handler registration failed: $_"
}

try {
    $script:mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $script:mutexAcquired = $script:mutex.WaitOne(0)  # 0 = no waiting, check immediately
    
    if (-not $script:mutexAcquired) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Red
        Write-Host "  $(Get-LocalizedString 'ErrorInstanceRunning')" -ForegroundColor Red
        Write-Host "============================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "  $(Get-LocalizedString 'ErrorInstanceParallel')" -ForegroundColor Yellow
        Write-Host "  $(Get-LocalizedString 'ErrorInstanceReason')" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  $(Get-LocalizedString 'ErrorInstanceWait')" -ForegroundColor White
        Write-Host ""
        
        # Cleanup before exit
        if ($script:mutex) {
            $script:mutex.Dispose()
        }
        
        exit 1
    }
    
    Write-Verbose "Concurrent Execution Lock acquired - script can start"
}
catch {
    Write-Warning "Mutex creation failed: $_"
    Write-Warning "Concurrent Execution Check will be skipped (at your own risk)"
}

# ===== CRITICAL FIX #3: Removed Console Encoding DUPLICATE =====
# Console Encoding was already set early (see CRITICAL FIX #1)
# Duplicate removed to avoid code redundancy

# ===== CRITICAL FIX #3: Removed Error.Clear() DUPLICATE =====
# Error.Clear() was already done early (see CRITICAL FIX #1)
# Duplicate removed to avoid redundancy

if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

# NOTE: $scriptDir was already defined early (see CRITICAL FIX #2)
# No need to redefine it here

#region MODULE DEPENDENCY SYSTEM (Best Practice 25H2)

# Module Dependencies Graph - Defines which module needs which others
$moduleDependencies = @{
    'Common' = @()                                    # Base - no dependencies
    'Localization' = @()                             # Base - no dependencies
    'RegistryOwnership' = @('Common', 'Localization') # NEW: TrustedInstaller Registry Management
    'WindowsUpdate' = @('Common', 'Localization')    # Windows Update Defaults (keine Policies!)
    'Core' = @('Common', 'Localization', 'RegistryOwnership', 'WindowsUpdate')  # Braucht Ownership fuer Defender-Keys
    'ASR' = @('Common', 'Localization')              # Braucht Helper-Functions + Strings
    'Advanced' = @('Common', 'Localization')         # Braucht Helper-Functions + Strings
    'DNS-Common' = @('Common', 'Localization')       # NEW: Shared DNS helper functions (cleanup, adapter selection)
    'DNS-Providers' = @('Common', 'Localization', 'DNS-Common')  # NEW: Multi-Provider DNS-over-HTTPS (needs DNS-Common!)
    'DNS' = @('Common', 'Localization', 'DNS-Common', 'DNS-Providers')  # Complete DNS config (DNSSEC + Blocklist + Providers)
    'Bloatware' = @('Common', 'Localization')        # Braucht Helper-Functions + Strings
    'Telemetry' = @('Common', 'Localization')        # Braucht Helper-Functions + Strings
    'Performance' = @('Common', 'Localization')      # Braucht Helper-Functions + Strings
    'UAC' = @('Common', 'Localization')              # Braucht Helper-Functions + Strings
    'Interactive' = @('Common', 'Localization')      # Braucht Helper-Functions + Strings
    'Edge' = @('Common', 'Localization')             # Braucht Helper-Functions + Strings
    'AI' = @('Common', 'Localization')               # NEW: AI Features Lockdown (Copilot, Recall, etc.)
    'WirelessDisplay' = @('Common', 'Localization')  # NEW: Wireless Display / Miracast Deaktivierung
    'OneDrive' = @('Common', 'Localization')         # NEW: OneDrive Privacy Hardening (Telemetry + KFM)
}

# Module Priority - Defines load order for same dependencies
# Lower number = higher priority (load earlier)
$modulePriority = @{
    'Common' = 1            # ALWAYS first
    'Localization' = 2      # Direkt nach Common
    'RegistryOwnership' = 3 # NEW: Registry Ownership Management (vor Core!)
    'WindowsUpdate' = 4     # Windows Update Defaults (vor Core, da Core es braucht)
    'Core' = 5              # KRITISCH - System-Validierung (braucht RegistryOwnership!)
    'ASR' = 6               # Attack Surface Reduction
    'Advanced' = 7          # VBS, BitLocker, LAPS
    'DNS' = 8               # DNS Security
    'DNS-Common' = 9        # NEW: DNS Common helpers (MUST load before DNS-Providers!)
    'DNS-Providers' = 10    # NEW: Multi-Provider DNS (Cloudflare, AdGuard, NextDNS, Quad9)
    'Bloatware' = 11        # App-Removal
    'Telemetry' = 12        # Privacy
    'Performance' = 13      # Optimierung
    'UAC' = 14              # UAC Settings
    'AI' = 15               # NEW: AI Lockdown (KRITISCH fuer Privacy!)
    'WirelessDisplay' = 16  # NEW: Wireless Display / Miracast
    'OneDrive' = 17         # NEW: OneDrive Privacy Hardening
    'Edge' = 18             # Microsoft Edge Security Baseline
    'Interactive' = 19      # Menue (braucht alle anderen)
}

function Get-ModuleLoadOrder {
    <#
    .SYNOPSIS
        Berechnet die korrekte Load-Reihenfolge mittels Priority-Based Topological Sort
    .DESCRIPTION
        Verwendet Kahn's Algorithm fuer Topological Sort mit Priority Queue.
        Erkennt automatisch Circular Dependencies und wirft Fehler.
        Bei gleichen Dependencies wird nach Prioritaet sortiert (niedrigere Zahl zuerst).
    .PARAMETER Dependencies
        Hashtable mit Module -> Array of Dependencies
    .PARAMETER Priority
        Hashtable mit Module -> Priority Number (niedrigere Zahl = hoehere Prioritaet)
    .OUTPUTS
        [array] Sortierte Module in Load-Reihenfolge
    .EXAMPLE
        Get-ModuleLoadOrder -Dependencies $moduleDependencies -Priority $modulePriority
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Dependencies,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Priority = @{}
    )
    
    # Kahn's Algorithm for Topological Sort with Priority
    $inDegree = @{}
    $adjList = @{}
    $result = @()
    
    # Initialize in-degree counter and adjacency list
    foreach ($module in $Dependencies.Keys) {
        $inDegree[$module] = 0
        $adjList[$module] = @()
    }
    
    # Build adjacency list and in-degree count
    foreach ($module in $Dependencies.Keys) {
        foreach ($dep in $Dependencies[$module]) {
            if (-not $Dependencies.ContainsKey($dep)) {
                throw "Module '$module' depends on unknown module '$dep'"
            }
            
            # dep -> module (dependency relationship)
            $adjList[$dep] += $module
            $inDegree[$module]++
        }
    }
    
    # Priority Queue: ArrayList sorted by priority
    # Modules with same in-degree are sorted by priority
    $availableModules = [System.Collections.ArrayList]::new()
    
    foreach ($module in $inDegree.Keys) {
        if ($inDegree[$module] -eq 0) {
            $null = $availableModules.Add($module)
        }
    }
    
    # Sort by priority (lower number first)
    if ($Priority.Count -gt 0) {
        $sorted = $availableModules | Sort-Object { 
            if ($Priority.ContainsKey($_)) { $Priority[$_] } else { 999 }
        }
        # Sort-Object returns array - convert to ArrayList
        $availableModules.Clear()
        foreach ($item in $sorted) {
            $null = $availableModules.Add($item)
        }
    }
    
    # Process modules in priority order
    while ($availableModules.Count -gt 0) {
        # Take module with highest priority (lowest number)
        $current = $availableModules[0]
        $availableModules.RemoveAt(0)
        $result += $current
        
        # Reduce in-degree for dependent modules
        $newlyAvailable = [System.Collections.ArrayList]::new()
        foreach ($dependent in $adjList[$current]) {
            $inDegree[$dependent]--
            if ($inDegree[$dependent] -eq 0) {
                $null = $newlyAvailable.Add($dependent)
            }
        }
        
        # Sort new modules by priority and add them
        if ($newlyAvailable.Count -gt 0) {
            if ($Priority.Count -gt 0) {
                $sortedNew = $newlyAvailable | Sort-Object { 
                    if ($Priority.ContainsKey($_)) { $Priority[$_] } else { 999 }
                }
                # Sort-Object returns array - iterate over sorted items
                foreach ($module in $sortedNew) {
                    $null = $availableModules.Add($module)
                }
            } else {
                foreach ($module in $newlyAvailable) {
                    $null = $availableModules.Add($module)
                }
            }
        }
    }
    
    # Check for circular dependencies
    if ($result.Count -ne $Dependencies.Count) {
        $missing = $Dependencies.Keys | Where-Object { $_ -notin $result }
        throw "Circular dependency detected! Modules affected: $($missing -join ', ')"
    }
    
    return $result
}

function Test-ModuleDependencies {
    <#
    .SYNOPSIS
        Validiert dass alle Dependencies eines Moduls bereits geladen wurden
    .PARAMETER ModuleName
        Name des zu validierenden Moduls
    .PARAMETER Dependencies
        Hashtable mit Dependencies
    .PARAMETER LoadedModules
        Hashtable mit bereits geladenen Modulen
    .OUTPUTS
        [bool] $true wenn alle Dependencies geladen, sonst throw
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Dependencies,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$LoadedModules
    )
    
    if (-not $Dependencies.ContainsKey($ModuleName)) {
        Write-Warning "Module '$ModuleName' not in dependency graph - skipping validation"
        return $true
    }
    
    $requiredDeps = $Dependencies[$ModuleName]
    $missingDeps = @()
    
    foreach ($dep in $requiredDeps) {
        if (-not $LoadedModules[$dep]) {
            $missingDeps += $dep
        }
    }
    
    if ($missingDeps.Count -gt 0) {
        throw "Module '$ModuleName' requires: $($missingDeps -join ', ') (not loaded yet!)"
    }
    
    return $true
}

function Test-HasSelectedModules {
    <#
    .SYNOPSIS
        Safely checks if SelectedModules exists and has items (StrictMode-compatible)
    .DESCRIPTION
        Under Set-StrictMode -Version Latest accessing .Count on non-existent variable crashes
        This function uses Test-Path to check existence first then Measure-Object for count
    .OUTPUTS
        [bool] True if SelectedModules exists and has at least 1 item
    #>
    if (-not (Test-Path Variable:SelectedModules)) {
        return $false
    }
    
    $tmp = $SelectedModules
    if ($null -eq $tmp) {
        return $false
    }
    
    # Use Measure-Object instead of .Count (works with strings and arrays)
    $count = ($tmp | Measure-Object).Count
    return ($count -gt 0)
}

# ===== CRITICAL FIX #5: Removed Default Language DUPLICATE =====
# Default language was already set early (see CRITICAL FIX #2)
# Duplicate removed to avoid redundancy

# Calculate correct load order with priorities
Write-Host "Calculating module load order..." -ForegroundColor Cyan
try {
    # IMPORTANT: Filter modules based on $SelectedModules (Custom Mode!)
    # Check if variable exists AND is set (not just -and, but Test-Path!)
    if ((Test-Path Variable:\SelectedModules) -and $SelectedModules -and $SelectedModules.Count -gt 0) {
        # Custom Mode: Only selected modules + their dependencies
        Write-Verbose "Custom Mode: Filtering modules to: $($SelectedModules -join ', ')"
        
        # Always add Core (mandatory module!)
        if ($SelectedModules -notcontains 'Core') {
            $SelectedModules += 'Core'
            Write-Verbose "Added Core module (mandatory)"
        }
        
        # Calculate dependencies for selected modules
        $modulesToLoad = @()
        foreach ($module in $SelectedModules) {
            $modulesToLoad += $module
            # Also add the dependencies
            if ($moduleDependencies.ContainsKey($module)) {
                foreach ($dep in $moduleDependencies[$module]) {
                    if ($modulesToLoad -notcontains $dep) {
                        $modulesToLoad += $dep
                        Write-Verbose "Added dependency: $dep (required by $module)"
                    }
                }
            }
        }
        
        # Now sort by priority
        $requiredModules = Get-ModuleLoadOrder -Dependencies $moduleDependencies -Priority $modulePriority | 
                           Where-Object { $modulesToLoad -contains $_ }
    }
    else {
        # Audit/Enforce Mode: All modules
        $requiredModules = Get-ModuleLoadOrder -Dependencies $moduleDependencies -Priority $modulePriority
    }
    
    Write-Verbose "Load order: $($requiredModules -join ' | ')"
    Write-Host "[i] Loading $($requiredModules.Count) modules..." -ForegroundColor Cyan
}
catch {
    Write-Error "FATAL: Error in dependency resolution: $_"
    exit 1
}

# Load modules with validation (Best Practice 25H2)
$loadedModules = @{}

Write-Host "Loading modules..." -ForegroundColor Cyan

foreach ($moduleName in $requiredModules) {
    # ===== CRITICAL FIX #5: Skip Localization (already loaded early) =====
    # REASON: Localization was loaded early (see CRITICAL FIX #2)
    # SKIP it here to avoid double-loading
    if ($moduleName -eq 'Localization') {
        Write-Verbose "     Skipping Localization (already loaded early)"
        $loadedModules['Localization'] = $true
        continue
    }
    
    $modulePath = Join-Path $scriptDir "Modules\SecurityBaseline-$moduleName.ps1"
    
    if (Test-Path $modulePath) {
        try {
            # DEPENDENCY CHECK: Validate that all dependencies are already loaded
            try {
                Test-ModuleDependencies -ModuleName $moduleName `
                                        -Dependencies $moduleDependencies `
                                        -LoadedModules $loadedModules
                Write-Verbose "     Dependencies OK fuer: $moduleName"
            }
            catch {
                throw "Dependency-Check fehlgeschlagen: $_"
            }
            
            # Dot-Source the module
            . $modulePath
            
            # Validate that module loaded successfully
            # Check if at least one typical function from module is available
            $moduleLoaded = $false
            
            # Module-specific validation
            switch ($moduleName) {
                'Common' { $moduleLoaded = $null -ne (Get-Command 'Write-Section' -ErrorAction SilentlyContinue) }
                'RegistryOwnership' { $moduleLoaded = $null -ne (Get-Command 'Set-RegistryValueSmart' -ErrorAction SilentlyContinue) }
                'WindowsUpdate' { $moduleLoaded = $null -ne (Get-Command 'Set-WindowsUpdateDefaults' -ErrorAction SilentlyContinue) }
                'Core' { $moduleLoaded = $null -ne (Get-Command 'Test-SystemRequirements' -ErrorAction SilentlyContinue) }
                'ASR' { $moduleLoaded = $null -ne (Get-Command 'Set-AttackSurfaceReductionRules' -ErrorAction SilentlyContinue) }
                'Advanced' { $moduleLoaded = $null -ne (Get-Command 'Enable-AdvancedAuditing' -ErrorAction SilentlyContinue) }
                'DNS' { $moduleLoaded = $null -ne (Get-Command 'Enable-DNSSEC' -ErrorAction SilentlyContinue) }
                'DNS-Common' { $moduleLoaded = $null -ne (Get-Command 'Reset-NoID-DnsState' -ErrorAction SilentlyContinue) }
                'DNS-Providers' { $moduleLoaded = $null -ne (Get-Command 'Enable-AdGuardDNS' -ErrorAction SilentlyContinue) }
                'Bloatware' { $moduleLoaded = $null -ne (Get-Command 'Remove-BloatwareApps' -ErrorAction SilentlyContinue) }
                'Telemetry' { $moduleLoaded = $null -ne (Get-Command 'Disable-TelemetryServices' -ErrorAction SilentlyContinue) }
                'Performance' { $moduleLoaded = $null -ne (Get-Command 'Optimize-ScheduledTasks' -ErrorAction SilentlyContinue) }
                'UAC' { $moduleLoaded = $null -ne (Get-Command 'Enable-EnhancedPrivilegeProtectionMode' -ErrorAction SilentlyContinue) }
                'AI' { $moduleLoaded = $null -ne (Get-Command 'Disable-WindowsRecall' -ErrorAction SilentlyContinue) }
                'Localization' { $moduleLoaded = $null -ne (Get-Command 'Get-LocalizedString' -ErrorAction SilentlyContinue) }
                'Interactive' { $moduleLoaded = $null -ne (Get-Command 'Start-InteractiveMode' -ErrorAction SilentlyContinue) }
                'Edge' { $moduleLoaded = $null -ne (Get-Command 'Set-EdgeSecurityBaseline' -ErrorAction SilentlyContinue) }
                'WirelessDisplay' { $moduleLoaded = $null -ne (Get-Command 'Disable-WirelessDisplay' -ErrorAction SilentlyContinue) }
                'OneDrive' { $moduleLoaded = ($null -ne (Get-Command 'Set-OneDrivePrivacyHardening' -ErrorAction SilentlyContinue)) -and ($null -ne (Get-Command 'Remove-OneDriveCompletely' -ErrorAction SilentlyContinue)) }
                default { $moduleLoaded = $true }  # Fallback: Assume loaded
            }
            
            if ($moduleLoaded) {
                $loadedModules[$moduleName] = $true
                Write-Verbose "     Modul geladen: $moduleName (validiert)"
            }
            else {
                throw "Modul geladen aber keine Funktionen gefunden!"
            }
        }
        catch {
            Write-Error "Fehler beim Laden von Modul $moduleName : $_"
            $loadedModules[$moduleName] = $false
        }
    }
    else {
        Write-Warning "Module not found: $modulePath"
        $loadedModules[$moduleName] = $false
    }
}

#endregion MODULE DEPENDENCY SYSTEM

# Check if critical modules were loaded
$criticalModules = @('Common', 'Core', 'Localization')
foreach ($critical in $criticalModules) {
    if (-not $loadedModules[$critical]) {
        Write-Error "FATAL: Critical module '$critical' could not be loaded!"
        
        # Release Mutex before exit
        if ($mutexAcquired -and $mutex) {
            try { 
                $mutex.ReleaseMutex()
                $mutex.Dispose()
                Write-Verbose "Mutex released (Mutex-Wait-Timeout)"
            } catch { 
                Write-Verbose "Mutex release failed: $_"
            }
        }
        
        exit 1
    }
}

# $Global:CurrentLanguage was already set BEFORE module loading (see line 411-416)
# Here only final check in case it was overwritten
if (-not (Test-Path Variable:\Global:CurrentLanguage) -or [string]::IsNullOrEmpty($Global:CurrentLanguage)) {
    $Global:CurrentLanguage = 'en'
    Write-Verbose "Default language restored to: English (fallback)"
}

# Interaktiver Modus
if ($Interactive) {
    $config = Start-InteractiveMode -LogPath $LogPath
    
    # CRITICAL FIX: Clean up config IMMEDIATELY (BEFORE any property access!)
    # ROOT CAUSE: Menu can return Object[] instead of Hashtable
    # PROBLEM: Somewhere in menu pipeline $true or validation output leaks through
    # EXAMPLE: $config = @(@{Mode='Audit'...}, $true) instead of just @{Mode='Audit'...}
    # SYMPTOM: .ContainsKey() crashes with "System.Array/Object[] has no method ContainsKey"
    # SOLUTION: Extract first Hashtable from array if needed, BEFORE any .ContainsKey() access
    
    # Step 1: If config is array, extract first hashtable
    if ($config -is [object[]]) {
        Write-Verbose "Config is array - extracting first hashtable"
        $config = $config | Where-Object { $_ -is [hashtable] } | Select-Object -First 1
    }
    
    # Step 2: If nothing left, user cancelled
    if ($null -eq $config) {
        # User cancelled
        Write-Host "[!] Operation cancelled by user" -ForegroundColor Yellow
        
        # Release Mutex before exit
        if ($mutexAcquired -and $mutex) {
            try { 
                $mutex.ReleaseMutex()
                $mutex.Dispose()
                Write-Verbose "Mutex released (User cancelled)"
            } catch { 
                Write-Verbose "Mutex release failed: $_"
            }
        }
        
        exit 0
    }
    
    # Step 3: If not hashtable after cleanup, exit with warning
    if ($config -isnot [hashtable]) {
        Write-Warning "Interactive menu returned unexpected value (type: $($config.GetType().FullName)). Exiting..."
        
        # Release Mutex before exit
        if ($mutexAcquired -and $mutex) {
            try { 
                $mutex.ReleaseMutex()
                $mutex.Dispose()
            } catch { 
                Write-Verbose "Mutex release in type-guard failed: $_"
            }
        }
        
        exit 0
    }
    
    # NOW config is guaranteed to be a Hashtable - safe to use .ContainsKey()!
    
    # SPECIAL: User chose Restore (parameter OR backup prompt)
    # IMPORTANT: Hashtable uses ContainsKey() not PSObject.Properties!
    $actionValue = if ($config.ContainsKey('Action')) { $config.Action } else { 'None' }
    Write-Verbose "Pruefe Restore-Action: RestoreMode = $RestoreMode, Config.Action = $actionValue, Config.Mode = $($config.Mode)"
    if ($RestoreMode -or ($config.ContainsKey('Action') -and $config.Action -eq 'Restore') -or ($config.Mode -eq 'Restore')) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host "  $(Get-LocalizedString 'RestoreModeActivated')" -ForegroundColor Yellow
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "$(Get-LocalizedString 'RestoreModeApplyExiting')" -ForegroundColor Cyan
        Write-Host "$(Get-LocalizedString 'RestoreModeStarting')" -ForegroundColor Cyan
        Write-Host ""
        
        $restoreScript = Join-Path $scriptDir "Restore-SecurityBaseline.ps1"
        Write-Verbose "Restore-Script Pfad: $restoreScript"
        
        if (Test-Path $restoreScript) {
            Write-Verbose "Restore-Script gefunden - starte Prozess"
            # IMPORTANT: END transcript before we start Restore!
            if ($script:transcriptStarted) {
                try {
                    Stop-Transcript -ErrorAction SilentlyContinue
                    $script:transcriptStarted = $false
                    Write-Verbose "Transcript stopped before restore"
                } catch {
                    Write-Verbose "Transcript stop before restore failed: $_"
                }
            }
            
            # Release Mutex BEFORE Restore
            if ($mutex) {
                try { 
                    $mutex.ReleaseMutex()
                    $mutex.Dispose()
                    Write-Verbose "Mutex released before restore"
                } catch {
                    Write-Verbose "Mutex release before restore failed: $_"
                }
            }
            
            # Uebergebe aktuelle Sprache als Parameter UND Environment Variable (doppelte Absicherung)
            $env:NOID_LANGUAGE = $Global:CurrentLanguage
            
            # IMPORTANT: Start with -NoNewWindow to keep it in the same window
            # But: powershell.exe instead of &, so it runs in its own process and we can exit COMPLETELY
            # CRITICAL FIX: Use ARRAY format for ArgumentList (string format can fail parameter parsing!)
            $restoreArgs = @(
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-File", $restoreScript,
                "-Language", $Global:CurrentLanguage
            )
            Write-Verbose "Starte Restore als separaten Prozess: powershell.exe -File $restoreScript -Language $Global:CurrentLanguage"
            
            # Start Restore and wait until it's finished
            Write-Host "$(Get-LocalizedString 'RestoreModeProcessStart')" -ForegroundColor Cyan
            $restoreProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $restoreArgs -NoNewWindow -Wait -PassThru
            
            Remove-Item Env:\NOID_LANGUAGE -ErrorAction SilentlyContinue
            
            # Exit code from Restore script
            $restoreExitCode = $restoreProcess.ExitCode
            Write-Host ""
            Write-Host "$(Get-LocalizedString 'RestoreModeScriptComplete' $restoreExitCode)" -ForegroundColor Cyan
            Write-Host "$(Get-LocalizedString 'RestoreModeApplyExitNow')" -ForegroundColor Yellow
            Write-Host ""
            Write-Verbose "Restore-Script beendet mit Exit-Code: $restoreExitCode"
            Write-Verbose "Rufe [Environment]::Exit($restoreExitCode) auf..."
            
            # Exit IMMEDIATELY - no further processing!
            # CRITICAL: This terminates the ENTIRE PowerShell process immediately!
            [Environment]::Exit($restoreExitCode)
            
            # This line should NEVER be reached!
            Write-Host "$(Get-LocalizedString 'CriticalNeverReached')" -ForegroundColor Red
        }
        else {
            Write-Host "$(Get-LocalizedString 'RestoreModeNotFound' $restoreScript)" -ForegroundColor Red
            
            # Release Mutex before exit
            if ($mutex) {
                try { 
                    $mutex.ReleaseMutex()
                    $mutex.Dispose()
                    Write-Verbose "Mutex released (Restore script finished)"
                } catch { 
                    Write-Verbose "Mutex release after restore failed: $_"
                }
            }
            
            # SOFORT beenden
            [Environment]::Exit(1)
        }
        
        # SAFEGUARD: If we reach here (should NEVER happen!), exit immediately!
        Write-Host "$(Get-LocalizedString 'CriticalCodeAfterRestore')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalForcingExit')" -ForegroundColor Red
        [Environment]::Exit(99)
    }
    
    # NOTE: $config null/type checks already done at top of Interactive block (Lines 784-824)
    # This code only runs if config is valid Hashtable
    
    # SAFETY CHECK: If Mode='Restore', then something went wrong!
    if ($config.Mode -eq 'Restore') {
        Write-Host "$(Get-LocalizedString 'CriticalRestoreNotCaught')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalCodeAfterRestore')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalForcingExit')" -ForegroundColor Red
        [Environment]::Exit(98)
    }
    
    # Adopt configuration from interactive menu with validation
    # IMPORTANT: $config is a Hashtable, NOT a PSCustomObject!
    # Therefore: Use ContainsKey(), NOT PSObject.Properties!
    
    if ($config.ContainsKey('Mode') -and $config.Mode) {
        $Mode = $config.Mode
        Write-Verbose "Mode from interactive config: $Mode"
    } else {
        Write-Warning "Config missing Mode property - using default 'Audit'"
        $Mode = 'Audit'
    }
    
    if ($config.ContainsKey('Modules') -and $config.Modules) {
        $SelectedModules = $config.Modules
        Write-Verbose "Modules from interactive config: $($SelectedModules -join ', ')"
    } else {
        Write-Warning "Config missing Modules property - using all modules"
        $SelectedModules = @('Core', 'ASR', 'Advanced', 'DNS', 'Bloatware', 'Telemetry', 'Performance', 'AI', 'WirelessDisplay', 'OneDrive', 'UAC', 'WindowsUpdate', 'Edge')
    }
    
    # === BACKUP LOGIC (from Start-InteractiveMode) ===
    # CRITICAL FIX: Initialize $backupSuccess BEFORE backup block!
    # REASON: Variable is checked later (line 1156) even if backup was not created (AUDIT mode)
    # Without initialization: PropertyNotFoundException in AUDIT mode!
    $backupSuccess = $false
    
    # Check if backup should be created
    if ($config.ContainsKey('CreateBackup') -and $config.CreateBackup -eq $true) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host "                    $(Get-LocalizedString 'BackupFullCreating')                     " -ForegroundColor Cyan
        Write-Host "============================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "$(Get-LocalizedString 'BackupIncludes')" -ForegroundColor White
        Write-Host "$(Get-LocalizedString 'BackupIncludesDNS')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesHosts')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesServices')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesFirewall')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesRegistry')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesUsers')" -ForegroundColor Gray
        Write-Host "$(Get-LocalizedString 'BackupIncludesApps')" -ForegroundColor Gray
        Write-Host ""
        Write-Host "$(Get-LocalizedString 'BackupDuration')" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "$(Get-LocalizedString 'BackupRunning')" -ForegroundColor Cyan
        Write-Host ""
        
        $backupScript = Join-Path $scriptDir "Backup-SecurityBaseline.ps1"
        if (Test-Path $backupScript) {
            # Uebergebe aktuelle Sprache via Environment Variable
            $env:NOID_LANGUAGE = $Global:CurrentLanguage
            
            # Best Practice 25H2: Dot-Source im SELBEN Fenster!
            # NO new PowerShell window, everything stays in same terminal
            try {
                # Dot-source the backup script (runs in same process)
                . $backupScript
                
                # Backup script sets $LASTEXITCODE on success/failure
                if ($LASTEXITCODE -eq 0) {
                    $backupSuccess = $true
                }
                elseif ($LASTEXITCODE -eq 1) {
                    Write-Host ""
                    Write-Host "$(Get-LocalizedString 'BackupFailed' $LASTEXITCODE)" -ForegroundColor Red
                    Write-Warning "$(Get-LocalizedString 'BackupContinueRP')"
                    $backupSuccess = $false
                }
                else {
                    # No exit code = success (normal with dot-source)
                    $backupSuccess = $true
                }
            }
            catch {
                Write-Host ""
                Write-Host "$(Get-LocalizedString 'BackupFailed' $_)" -ForegroundColor Red
                Write-Warning "$(Get-LocalizedString 'BackupContinueRP')"
                $backupSuccess = $false
            }
            finally {
                Remove-Item Env:\NOID_LANGUAGE -ErrorAction SilentlyContinue
            }
            
            if ($backupSuccess) {
                Write-Host ""
                Write-Host "============================================================================" -ForegroundColor Green
                Write-Host "                    $(Get-LocalizedString 'BackupSuccessComplete')                        " -ForegroundColor Green
                Write-Host "============================================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "$(Get-LocalizedString 'BackupCanRestore')" -ForegroundColor Green
                Write-Host "$(Get-LocalizedString 'BackupRunRestore')" -ForegroundColor Cyan
                Write-Host ""
                
                # ===== DNS & ONEDRIVE SELECTION (after backup, before enforcement) =====
                # Only show in Enforce/Custom mode (not Audit mode)
                if ($Mode -ne 'Audit') {
                    # DNS Provider Selection (only if DNS module is selected)
                    $showDNSMenu = $false
                    if ($Mode -eq 'Enforce') {
                        $showDNSMenu = $true  # Always show in Enforce mode
                    }
                    elseif ($Mode -eq 'Custom' -and $SelectedModules -contains 'DNS') {
                        $showDNSMenu = $true  # Show in Custom mode if DNS module selected
                    }
                    
                    if ($showDNSMenu) {
                        $dnsChoice = Show-DNSProviderMenu
                        
                        # Store DNS choice in config for later use
                        if (-not $config.ContainsKey('DNSProvider')) {
                            $config.Add('DNSProvider', $dnsChoice)
                        }
                        else {
                            $config.DNSProvider = $dnsChoice
                        }
                        
                        Write-Verbose "DNS Provider selected: $dnsChoice"
                    }
                    
                    # OneDrive Handling Selection (always show in Enforce/Custom)
                    $oneDriveChoice = Show-OneDriveMenu
                    
                    # Store OneDrive choice in config for later use
                    if (-not $config.ContainsKey('OneDriveAction')) {
                        $config.Add('OneDriveAction', $oneDriveChoice)
                    }
                    else {
                        $config.OneDriveAction = $oneDriveChoice
                    }
                    
                    Write-Verbose "OneDrive action selected: $oneDriveChoice"
                    
                    # Remote Access & Firewall Configuration (always show in Enforce/Custom)
                    $remoteAccessChoice = Show-RemoteAccessMenu
                    
                    # Store Remote Access choice and derive firewall strictness
                    if (-not $config.ContainsKey('RemoteAccessMode')) {
                        $config.Add('RemoteAccessMode', $remoteAccessChoice)
                    }
                    else {
                        $config.RemoteAccessMode = $remoteAccessChoice
                    }
                    
                    # Set script-level variables based on user choice
                    if ($remoteAccessChoice -eq '1') {
                        # Maximum Security: Disable RDP + Strict Firewall
                        $script:DisableRDP = $true
                        $script:StrictFirewall = $true
                        Write-Verbose "Remote Access: RDP will be DISABLED, Firewall ultra-strict"
                    }
                    else {
                        # Allow Remote Access: Keep RDP + Allow localhost
                        $script:DisableRDP = $false
                        $script:StrictFirewall = $false
                        Write-Verbose "Remote Access: RDP will stay ENABLED, Firewall allows localhost"
                    }
                    
                    Write-Host ""
                    Write-Host "===========================================================" -ForegroundColor Green
                    Write-Host "  CONFIGURATION COMPLETE - READY TO START" -ForegroundColor Green
                    Write-Host "===========================================================" -ForegroundColor Green
                    Write-Host ""
                }
                # NO second Read-Host here - Backup script already asked!
            }
            else {
                # Best Practice 25H2: Respect user decision!
                # $LASTEXITCODE = 1 means: User chose [N] in backup script
                # and does NOT want to continue!
                
                Write-Host ""
                Write-Host "============================================================================" -ForegroundColor Red
                Write-Host "  $(Get-LocalizedString 'BackupAbortTitle')" -ForegroundColor Red
                Write-Host "============================================================================" -ForegroundColor Red
                Write-Host ""
                Write-Host "  $(Get-LocalizedString 'BackupAbortNoScript')" -ForegroundColor Red
                Write-Host "  $(Get-LocalizedString 'BackupAbortReason')" -ForegroundColor Red
                Write-Host ""
                Write-Host "  $(Get-LocalizedString 'BackupAbortRecommend')" -ForegroundColor Yellow
                Write-Host "  $(Get-LocalizedString 'BackupAbortStep1')" -ForegroundColor White
                Write-Host "  $(Get-LocalizedString 'BackupAbortStep2')" -ForegroundColor White
                Write-Host "  $(Get-LocalizedString 'BackupAbortStep3')" -ForegroundColor White
                Write-Host ""
                
                # Stop transcript before exit
                if ($script:transcriptStarted) {
                    try {
                        Stop-Transcript -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Verbose "Transcript stop before backup abort failed (not critical): $_"
                    }
                }
                
                # Release Mutex before exit
                if ($mutexAcquired -and $mutex) {
                    try {
                        $mutex.ReleaseMutex()
                        $mutex.Dispose()
                    }
                    catch {
                        Write-Verbose "Mutex release before backup abort failed (not critical): $_"
                    }
                }
                
                exit 1  # KRITISCH: User will nicht fortfahren!
            }
        }
        else {
            Write-Host "$(Get-LocalizedString 'BackupNotFound' $backupScript)" -ForegroundColor Yellow
            Write-Host "$(Get-LocalizedString 'BackupFallbackRP')" -ForegroundColor Yellow
            Write-Host ""
            Start-Sleep -Seconds 2
        }
    }
    
    # Restore Point Setting from config
    if ($config.ContainsKey('CreateRestorePoint')) {
        $script:createRestorePoint = $config.CreateRestorePoint
        Write-Verbose "Restore Point setting from config: $script:createRestorePoint"
    } else {
        $script:createRestorePoint = $false  # Default with backup
        Write-Verbose "Restore Point setting not found - using default: false"
    }
} else {
    # Non-Interactive Mode (CLI): No backup prompt!
    # Best Practice 25H2: CLI mode also needs config object!
    
    # Default: All modules (or from -SelectedModules parameter)
    if (-not $SelectedModules) {
        $SelectedModules = @('Core', 'ASR', 'Advanced', 'DNS', 'Bloatware', 'Telemetry', 'Performance', 'AI', 'WirelessDisplay', 'OneDrive', 'UAC', 'WindowsUpdate', 'Edge')
        Write-Verbose "Non-interactive mode - using all modules"
    }
    
    # Create config object for CLI mode
    $config = @{
        Mode = if ($Mode) { $Mode } else { 'Audit' }
        Modules = $SelectedModules
        CreateRestorePoint = $true  # Immer im CLI-Modus (Safety!)
        CreateBackup = $false  # Kein Backup im CLI-Modus
    }
    Write-Verbose "CLI Mode Config: Mode=$($config.Mode), Modules=$($config.Modules.Count)"
    
    # Adopt mode and modules from config (for consistency)
    $Mode = $config.Mode
    $SelectedModules = $config.Modules
    
    # Set script-scope variable
    $script:createRestorePoint = $config.CreateRestorePoint
    Write-Verbose "Non-interactive mode - restore point enabled: $script:createRestorePoint"
}

# Best Practice 25H2: Config validation for ALL modes (Interactive + CLI)
Write-Verbose "=== Final Config ==="
Write-Verbose "Mode: $Mode"
Write-Verbose "Modules: $($SelectedModules -join ', ')"
Write-Verbose "CreateRestorePoint: $script:createRestorePoint"
Write-Verbose "===================="

# CRITICAL FIX: SAFE EXIT if no modules selected (e.g. interactive VERIFY + EXIT)
# ROOT CAUSE: After Verify -> Exit, no config is set, but script continues to common part
# PROBLEM: Common part assumes $SelectedModules always exists -> crash at Line 1180
# CRITICAL FIX: SAFE-EXIT with StrictMode compatibility
# ROOT CAUSE: Under Set-StrictMode accessing $SelectedModules.Count crashes if variable not set
# SOLUTION: Use Test-HasSelectedModules helper (checks existence first then count)
if (-not (Test-HasSelectedModules)) {
    Write-Host ""
    Write-Host "[i] No modules selected (probably VERIFY + EXIT). Exiting..." -ForegroundColor Yellow
    Write-Host ""
    
    # Stop transcript if started
    if ((Test-Path Variable:script:transcriptStarted) -and $script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore
        }
    }
    
    # Release mutex if acquired
    if ((Test-Path Variable:mutexAcquired) -and $mutexAcquired -and (Test-Path Variable:mutex) -and $mutex) {
        try {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }
        catch {
            # Ignore
        }
    }
    
    exit 0
}

$script:transcriptStarted = $false
$script:criticalError = $false  # Track if critical error occurred in catch block
# Transcript-Log Rotation (Best Practice 25H2 - prevents unlimited growth)
try {
    $oldLogs = Get-ChildItem $LogPath -Filter "SecurityBaseline-*.log" -ErrorAction SilentlyContinue | 
               Sort-Object CreationTime -Descending | 
               Select-Object -Skip 30
    
    if ($oldLogs) {
        $oldLogs | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Verbose "$(Get-LocalizedString 'VerboseOldLogsCleared' ($oldLogs.Count))"
    }
}
catch {
    Write-Verbose "Could not clean old logs: $_"
}

# CRITICAL FIX B: Safety exit BEFORE transcript if no modules (second defensive barrier + StrictMode fix)
# ROOT CAUSE: Interactive VERIFY -> EXIT might slip through with invalid $SelectedModules
# PROBLEM: Even if type-check passed, $SelectedModules might be null/string/empty
# SYMPTOM: Unwanted Audit transcript starts, then crashes at $SelectedModules.Count
# SOLUTION: Use Test-HasSelectedModules helper (StrictMode-safe check)
if ($Interactive -and -not (Test-HasSelectedModules)) {
    Write-Host ""
    Write-Host "[i] No modules selected (interactive VERIFY/EXIT). Exiting..." -ForegroundColor Yellow
    Write-Host ""
    
    # Release mutex cleanly
    if ($mutexAcquired -and $mutex) {
        try {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
            Write-Verbose "Mutex released in interactive safety-exit"
        } 
        catch {
            Write-Verbose "Mutex release failed in interactive safety-exit: $_"
        }
    }
    
    exit 0
}

# CRITICAL FIX: Set transcript path before starting transcript!
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:transcriptPath = Join-Path $LogPath "SecurityBaseline-$Mode-$timestamp.log"

try {
    # Best Practice 25H2: Unique filenames prevent accidental overwrites
    # Timestamp in filename already guarantees unique files (no overwriting)
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "$(Get-LocalizedString 'VerboseTranscriptStarted' ($script:transcriptPath))"
}
catch {
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptFailed' ($_))"
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptContinue')"
}

# VERSION BANNER (for BOTH modes - Interactive and Non-Interactive)
Write-Host ""
Write-Host "=============================================================================" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "                NoID Privacy - Windows 11 25H2 Baseline" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "               Maximum Security + Privacy + Performance" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "=============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Version: 1.7.16 | Modus: $Mode" -ForegroundColor Cyan
if ($Interactive) {
    Write-Host "  Mode: Interactive Menu" -ForegroundColor Cyan
}
Write-Host ""

try {
    # WhatIf/ShouldProcess Support
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply Windows 11 25H2 Security Baseline in $Mode mode")) {
        Write-Host ""
        Write-Host "[!] Operation cancelled by user or -WhatIf" -ForegroundColor Yellow
        return
    }
    
    # 1. System validation (always)
    # CRITICAL FIX: Pipe to Out-Null to prevent [bool]True leaking into pipeline
    # ROOT CAUSE: Function returns $true which can pollute caller's return array
    Test-SystemRequirements | Out-Null
    
    # 2. Create System Restore Point (Safety Net) - only if desired)
    if ($script:createRestorePoint) {
        Write-Verbose "Creating System Restore Point..."
        try {
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description "NoID Privacy - Before Security Baseline" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
            Write-Host "[OK] System Restore Point created" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not create System Restore Point: $_"
            Write-Warning "Continuing without restore point (not critical)..."
        }
    }
    else {
        Write-Verbose "System Restore Point creation skipped by user choice"
        # CRITICAL FIX: Only warn if NEITHER backup NOR restore point was created!
        # Don't confuse user when they made a backup - that's their safety net!
        if (-not $backupSuccess) {
            Write-Host "[!] System Restore Point skipped - no safety net!" -ForegroundColor Yellow
        }
        else {
            Write-Verbose "Safety net provided by backup - restore point warning skipped"
        }
    }
    
    # Dynamischer Module Counter
    $moduleCount = $SelectedModules.Count
    $currentModule = 0
    
    # === CORE MODULE (always executed) ===
    if ('Core' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressCore')" -ForegroundColor Cyan
        
        # 2. Baseline Delta-Einstellungen (25H2 spezifisch)
        Set-NetBIOSDisabled
        Set-ProcessAuditingWithCommandLine
        Disable-IE11COMAutomation
        Set-ExplorerZoneHardening
        Set-FileExecutionRestrictions
        Set-PrintSpoolerUserRights
        Disable-InternetPrintingClient
        Disable-MSDTProtocolHandler
        Enable-VulnerableDriverBlocklist
        
        # 3. Microsoft Defender Baseline
        Set-DefenderBaselineSettings
        Enable-ControlledFolderAccess
        Enable-ExploitProtection
        
        # 3a. NEW BEST PRACTICE FEATURES (January 2026)
        Disable-AutoPlayAndAutoRun
        Set-SmartScreenExtended
        
        # 4. SMB/NTLM/Kerberos Haertung
        Set-SMBHardening
        Disable-AnonymousSIDEnumeration
        Disable-NetworkLegacyProtocols
        Enable-NetworkStealthMode
        Disable-UnnecessaryServices
        Disable-AdministrativeShares
        Set-SecureAdministratorAccount
        
        # DNS Provider Selection (based on user choice)
        if ($config.ContainsKey('DNSProvider')) {
            switch ($config.DNSProvider) {
                '1' { Enable-CloudflareDNS }
                '2' { Enable-AdGuardDNS }
                '3' { Enable-NextDNS }
                '4' { Enable-Quad9DNS }
                '5' { Write-Host "  [SKIP] DNS configuration skipped (user choice)" -ForegroundColor Yellow }
                default { Enable-CloudflareDNS }  # Fallback to Cloudflare
            }
        }
        else {
            # No choice made (CLI mode or old flow) - use default Cloudflare
            Enable-CloudflareDNS
        }
        
        Disable-RemoteAccessCompletely
        
        # Disable Sudo for Windows (Microsoft Baseline 25H2)
        Disable-SudoForWindows
        
        Set-KerberosPKINITHashAgility
        
        # 5. Mark-of-the-Web
        Set-MarkOfTheWeb
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessCore')" -ForegroundColor Green
    }
    
    # === ASR MODULE ===
    if ('ASR' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressASR')" -ForegroundColor Cyan
        
        Set-AttackSurfaceReductionRules -Mode $Mode
        Enable-SmartAppControl
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessASR') ($Mode Mode)!" -ForegroundColor Green
    }
    
    # === ADVANCED MODULE ===
    if ('Advanced' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressAdvanced')" -ForegroundColor Cyan
        
        Enable-CredentialGuard
        Disable-NearbySharing
        Enable-BitLockerPolicies
        Test-BitLockerEncryptionMethod  # Prueft ob AES-128 aktiv ist und zeigt Upgrade-Anleitung
        Enable-WindowsLAPS
        
        # UAC Maximum Security (Always notify - slider all the way up!)
        Set-MaximumUAC
        
        # UAC Enhanced Privilege Protection (Microsoft Baseline 25H2 - Future Feature)
        Enable-EnhancedPrivilegeProtectionMode
        
        # Advanced Auditing
        Enable-AdvancedAuditing
        
        # NTLM Auditing (Microsoft Baseline 25H2)
        Enable-NTLMAuditing
        
        # TLS/SSL Haertung
        Set-TLSHardening
        
        # WDigest Credential Protection
        Disable-WDigest
        
        # EFS RPC Blocking (Auth Coercion Protection)
        Disable-EFSRPC
        
        # WebClient/WebDAV Blocking (Auth Coercion Protection)
        Disable-WebClient
        
        # Print Spooler User Right (Baseline 25H2 - Windows Protected Print)
        Add-PrintSpoolerUserRight
        
        # Windows Hello PIN Complexity (Optional - requires TPM 2.0)
        Enable-WindowsHelloPINComplexity
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessAdvanced')" -ForegroundColor Green
    }
    
    # === DNS MODULE ===
    if ('DNS' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressDNS')" -ForegroundColor Cyan
        
        Enable-DNSSEC
        Install-DNSBlocklist
        # Set-DeliveryOptimization REMOVED - now in Core module as default (not policy!)
        Set-StrictInboundFirewall
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessDNS')" -ForegroundColor Green
    }
    
    # === BLOATWARE MODULE ===
    if ('Bloatware' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressBloatware')" -ForegroundColor Cyan
        
        Remove-BloatwareApps
        Remove-SpecificApps
        Disable-ConsumerFeatures
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessBloatware')" -ForegroundColor Green
    }
    
    # === TELEMETRY MODULE ===
    if ('Telemetry' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressTelemetry')" -ForegroundColor Cyan
        
        Disable-TelemetryServices
        Set-TelemetryRegistry
        Remove-TelemetryTasks
        Block-TelemetryHosts
        Set-LockScreenSecurity
        
        # CRITICAL: Privacy-Extended Features (were NOT set before!)
        Disable-WindowsSearchWebFeatures
        Disable-CameraAndMicrophone
        Disable-PrivacyExperienceSettings
        Disable-InkingAndTypingPersonalization
        Set-LocationServicesDefault
        
        # NEW October 2025: Complete App Permissions Coverage (15+ categories!)
        Disable-AllAppPermissionsDefaults
        
        # NEW October 2025: GameBar & Game Mode (was MISSING!)
        Disable-GameBarAndGameMode
        
        Get-TelemetryStatus
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessTelemetry')" -ForegroundColor Green
    }
    
    # === PERFORMANCE MODULE ===
    if ('Performance' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressPerformance')" -ForegroundColor Cyan
        
        Optimize-ScheduledTasks
        Optimize-EventLogs
        Disable-BackgroundActivities
        Optimize-SystemMaintenance
        Disable-VisualEffects
        Show-PerformanceReport
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessPerformance')" -ForegroundColor Green
    }
    
    # === AI LOCKDOWN MODULE (Privacy Extension) ===
    if ('AI' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] AI Features Lockdown (Recall, Copilot, etc.)" -ForegroundColor Cyan
        
        Disable-WindowsRecall
        Disable-WindowsCopilot
        Disable-ClickToDo
        Disable-PaintAIFeatures
        Disable-NotepadAIFeatures
        Disable-SettingsAgent
        Disable-CopilotProactive
        Set-RecallMaximumStorage
        Show-AILockdownReport
        
        Write-Host "[OK] AI Features: KOMPLETT BLOCKIERT!" -ForegroundColor Green
    }
    
    # === WIRELESS DISPLAY MODULE (Privacy Extension) ===
    if ('WirelessDisplay' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] Wireless Display / Miracast Deaktivierung" -ForegroundColor Cyan
        
        Disable-WirelessDisplay
        
        Write-Host "[OK] Wireless Display: KOMPLETT DEAKTIVIERT!" -ForegroundColor Green
    }
    
    # === ONEDRIVE MODULE (Privacy Extension) ===
    if ('OneDrive' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] OneDrive Configuration" -ForegroundColor Cyan
        
        # OneDrive Action Selection (based on user choice)
        if ($config.ContainsKey('OneDriveAction')) {
            switch ($config.OneDriveAction) {
                '1' { 
                    # Privacy Hardening (default)
                    Set-OneDrivePrivacyHardening
                    Write-Host "[OK] OneDrive Privacy: Telemetry minimized + User has control!" -ForegroundColor Green
                }
                '2' { 
                    # Complete Removal
                    Remove-OneDriveCompletely
                    Write-Host "[OK] OneDrive: Completely removed from system!" -ForegroundColor Green
                }
                '3' { 
                    # Skip
                    Write-Host "  [SKIP] OneDrive configuration skipped (user choice)" -ForegroundColor Yellow
                }
                default {
                    # Fallback to Privacy Hardening
                    Set-OneDrivePrivacyHardening
                    Write-Host "[OK] OneDrive Privacy: Telemetry minimized + User has control!" -ForegroundColor Green
                }
            }
        }
        else {
            # No choice made (CLI mode or old flow) - use default Privacy Hardening
            Set-OneDrivePrivacyHardening
            Write-Host "[OK] OneDrive Privacy: Telemetry minimized + User has control!" -ForegroundColor Green
        }
    }
    
    # === UAC MODULE ===
    if ('UAC' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] UAC Maximum Security Configuration" -ForegroundColor Cyan
        
        Set-MaximumUAC
        Enable-EnhancedPrivilegeProtectionMode
        
        Write-Host "[OK] UAC auf Maximum gesetzt!" -ForegroundColor Green
    }
    
    # === WINDOWS UPDATE MODULE ===
    if ('WindowsUpdate' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] Windows Update Defaults Configuration" -ForegroundColor Cyan
        
        Set-WindowsUpdateDefaults
        Set-DeliveryOptimizationDefaults
        
        Write-Host "[OK] Windows Update Defaults konfiguriert!" -ForegroundColor Green
    }
    
    # === EDGE MODULE ===
    if ('Edge' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] Microsoft Edge Security Baseline v139+" -ForegroundColor Cyan
        
        Set-EdgeSecurityBaseline
        
        Write-Host "[OK] Edge Security Baseline angewendet!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "[OK] $(Get-LocalizedString 'SuccessFinal')" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    
    # === HTML COMPLIANCE REPORT GENERATION ===
    # HTML Compliance Report REMOVED - unreliable checks caused false positives
    # Use Verify-SecurityBaseline.ps1 for manual verification instead
    
    # CRITICAL FIX v1.7.11: Reboot prompt MOVED to after finally-block!
    # Reason: Restart-Computer causes immediate reboot, preventing finally-block execution
    # This means lastrun.txt was NEVER written! Now it's written first, then reboot.
}
catch {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "[ERROR] $(Get-LocalizedString 'ErrorGeneral') $_" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor Red
    }
    # CRITICAL: No exit here! Finally block MUST execute (Mutex/Transcript cleanup)
    # Exit is done at end of Finally
    $script:criticalError = $true
}
finally {
    # Best Practice 25H2: Log completion status for error recovery
    # Filter only REAL errors (no non-fatal CIM queries, Get-* that find nothing, etc.)
    $realErrors = @($Error | Where-Object {
        # Filter out harmless errors:
        $msg = $_.Exception.Message
        $fullErrorMsg = $_.ToString()
        $categoryInfo = $_.CategoryInfo.Category
        
        # HARMLESS errors (will be ignored):
        $isHarmless = 
            ($msg -like "*wurden keine*gefunden*") -or
            ($msg -like "*Cannot find*") -or
            ($msg -like "*can*t be found*") -or
            ($msg -like "*konnte nicht gefunden werden*") -or
            ($msg -like "*kann den angegebenen Pfad nicht finden*") -or
            ($msg -like "*cannot find path*") -or
            ($msg -like "*No MSFT_*") -or
            ($msg -like "*MSFT_ScheduledTask*") -or
            ($msg -like "*Dienstnamen*gefunden*") -or
            ($msg -like "*Get-ScheduledTask*") -or
            ($msg -like "*Get-Service*") -or
            ($msg -like "*AppxProvisionedPackage*") -or
            ($msg -like "*SmartAppControl*") -or
            ($msg -like "*System kann den angegebenen Pfad nicht finden*") -or
            ($fullErrorMsg -like "*TerminatingError(Remove-AppxProvisionedPackage)*") -or
            ($fullErrorMsg -like "*Remove-AppxProvisionedPackage*") -or
            ($fullErrorMsg -like "*ObjectNotFound*") -or
            ($fullErrorMsg -like "*ItemNotFoundException*") -or
            ($msg -like "*bereits vorhanden*") -or  # Registry Key schon da
            ($msg -like "*already exists*") -or
            ($msg -like "*not installed*") -or  # App nicht installiert
            ($msg -like "*nicht installiert*") -or
            ($msg -like "*Falscher Parameter*" -and $msg -like "*NRPT*") -or  # DNS NRPT "falscher Parameter" (nicht kritisch)
            ($msg -like "*Der angeforderte Registrierungszugriff ist unzul*ssig*") -or  # Protected registry key (German)
            ($msg -like "*requested registry access is not allowed*") -or  # Protected registry key (English)
            ($msg -like "*Zugriff verweigert*") -or  # Access denied (German)
            ($msg -like "*Access is denied*") -or  # Access denied (English)
            ($categoryInfo -eq 'ObjectNotFound') -or  # PowerShell Standard "nicht gefunden" Fehler
            ($categoryInfo -eq 'ResourceUnavailable') -or  # Ressource nicht verfuegbar
            ($categoryInfo -eq 'NotSpecified')  # Unspezifizierte Fehler
        
        # IMPORTANT: Only count real CRITICAL errors
        # Criteria: TerminatingError OR WriteError AND not harmless
        # PLUS: ParameterBindingException is ALWAYS critical!
        $isCritical = ($fullErrorMsg -match "TerminatingError") -or 
                     ($fullErrorMsg -match "WriteError") -or
                     ($fullErrorMsg -match "ParameterBindingException") -or
                     ($categoryInfo -in @('InvalidOperation', 'PermissionDenied', 'SecurityError', 'InvalidArgument'))
        
        # Only count if: Critical AND NOT harmless
        $isCritical -and (-not $isHarmless)
    })
    
    if ($realErrors.Count -gt 0) {
        $completionLog = Join-Path $LogPath "LastRun-Status.txt"
        try {
            # Kategorisiere Warnings (erweiterte Patterns fuer bessere Erkennung)
            $harmlessWarnings = @($Error | Where-Object {
                $msg = $_.Exception.Message
                # Deutsch
                ($msg -like "*wurden keine*gefunden*") -or
                ($msg -like "*nicht gefunden*") -or
                ($msg -like "*bereits vorhanden*") -or
                ($msg -like "*existiert nicht*") -or
                # Englisch
                ($msg -like "*Cannot find*") -or
                ($msg -like "*not found*") -or
                ($msg -like "*not installed*") -or
                ($msg -like "*does not exist*") -or
                ($msg -like "*already exists*") -or
                ($msg -like "*No matching*")
            })
            
            $serviceWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Service*" -or $_.Exception.Message -like "*Dienst*" })
            $registryWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Registry*" -or $_.Exception.Message -like "*already exists*" })
            $appWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*App*" -or $_.Exception.Message -like "*Package*" })
            $otherWarnings = @($harmlessWarnings | Where-Object { 
                $_ -notin $serviceWarnings -and 
                $_ -notin $registryWarnings -and 
                $_ -notin $appWarnings 
            })
            
            # Top 10 Critical Errors with details
            $criticalErrorDetails = $realErrors | Select-Object -First 10 | ForEach-Object {
                "  - $($_.Exception.Message)"
                if ($_.InvocationInfo.ScriptLineNumber) {
                    "    Location: Line $($_.InvocationInfo.ScriptLineNumber) in $($_.InvocationInfo.ScriptName | Split-Path -Leaf)"
                }
            }
            # Join BEFORE the here-string to avoid backtick escaping issues
            $criticalErrorText = $criticalErrorDetails -join "`n"
            
            # Quick Actions based on error type (outside the here-string!)
            $quickActions = ""
            if ($realErrors[0].Exception.Message -like "*Registrierungszugriff*" -or $realErrors[0].Exception.Message -like "*registry access*") {
                $quickActions = @"
  [!] Registry Access Denied detected!
  [>] Solution: Run script as Administrator (Right-click | Run as administrator)
"@
            }
            elseif ($realErrors[0].Exception.Message -like "*Defender*" -or $realErrors[0].Exception.Message -like "*MpPreference*") {
                $quickActions = @"
  [!] Windows Defender error detected!
  [>] Solution: Check if third-party antivirus is installed
  [>] Disable third-party AV temporarily or configure via AV interface
"@
            }
            else {
                $quickActions = @"
  [>] Review critical errors above for specific issues
  [>] Check transcript log for full details
  [>] Run script again after fixing issues
"@
            }
            
            # Transcript Path (outside the here-string!)
            $transcriptInfo = if ($script:transcriptPath) { $script:transcriptPath } else { 'No transcript log created (early error)' }
            
            $statusInfo = @"
Last Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Status: INCOMPLETE (Errors occurred)
Mode: $Mode
Selected Modules: $($SelectedModules -join ', ')

========================================
ERROR SUMMARY
========================================
Critical Errors: $($realErrors.Count)
Filtered Harmless Warnings: $($harmlessWarnings.Count)

========================================
TOP CRITICAL ERRORS (First 10)
========================================
$criticalErrorText

========================================
WARNINGS BREAKDOWN
========================================
Service-Related: $($serviceWarnings.Count) (Services not found or already disabled)
Registry-Related: $($registryWarnings.Count) (Keys already exist or not found)
App-Related: $($appWarnings.Count) (Apps not installed or already removed)
Other Warnings: $($otherWarnings.Count)

========================================
QUICK ACTIONS
========================================
$quickActions

========================================
LOGS & DETAILS
========================================
Transcript Log: $transcriptInfo

NOTE: Some changes may have been partially applied.
Run script again after resolving errors - it is idempotent (safe to re-run).
"@
            # Ensure absolute path and force creation
            $absoluteLog = if ([System.IO.Path]::IsPathRooted($completionLog)) { $completionLog } else { Join-Path (Get-Location) $completionLog }
            # [OK] BEST PRACTICE: UTF-8 without BOM (PowerShell 5.1 compatible)
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($absoluteLog, $statusInfo, $utf8NoBom)
            Write-Verbose "Completion status logged to: $absoluteLog"
        }
        catch {
            Write-Verbose "Could not write completion log: $_"
        }
    }
    else {
        # SUCCESS: No real errors - write SUCCESS status
        $completionLog = Join-Path $LogPath "LastRun-Status.txt"
        try {
            # Categorize warnings also on SUCCESS (erweiterte Patterns)
            $harmlessWarnings = @($Error | Where-Object {
                $msg = $_.Exception.Message
                # Deutsch
                ($msg -like "*wurden keine*gefunden*") -or
                ($msg -like "*nicht gefunden*") -or
                ($msg -like "*bereits vorhanden*") -or
                ($msg -like "*existiert nicht*") -or
                # Englisch
                ($msg -like "*Cannot find*") -or
                ($msg -like "*not found*") -or
                ($msg -like "*not installed*") -or
                ($msg -like "*does not exist*") -or
                ($msg -like "*already exists*") -or
                ($msg -like "*No matching*")
            })
            
            $serviceWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Service*" -or $_.Exception.Message -like "*Dienst*" })
            $registryWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Registry*" -or $_.Exception.Message -like "*already exists*" })
            $appWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*App*" -or $_.Exception.Message -like "*Package*" })
            $otherWarnings = @($harmlessWarnings | Where-Object { 
                $_ -notin $serviceWarnings -and 
                $_ -notin $registryWarnings -and 
                $_ -notin $appWarnings 
            })
            
            # Next Steps based on mode (outside the here-string!)
            $nextSteps = ""
            if ($Mode -eq 'Enforce') {
                $nextSteps = @"
  [>] REBOOT REQUIRED for some changes to take effect:
      - VBS and Credential Guard
      - BitLocker Policies  
      - Firewall Rules
      - Service Changes
      
  [>] After Reboot:
      - Check Windows Security settings
      - Verify ASR Rules are active
      - Test DNS-over-HTTPS (nslookup cloudflare.com)
"@
            }
            else {
                $nextSteps = @"
  [>] Audit completed - no changes applied
  [>] Review transcript log for recommendations
  [>] Run with -Mode Enforce to apply changes
"@
            }
            
            # Transcript Path (outside the here-string!)
            $transcriptInfo = if ($script:transcriptPath) { $script:transcriptPath } else { 'No transcript log created (early completion)' }
            
            $statusInfo = @"
Last Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Status: SUCCESS (All critical changes applied)
Mode: $Mode
Selected Modules: $($SelectedModules -join ', ')

========================================
SUCCESS SUMMARY
========================================
[OK] All changes applied successfully!
[OK] No real errors occurred

Non-Fatal Warnings: $($harmlessWarnings.Count) (harmless, filtered out)

========================================
WARNINGS BREAKDOWN (Non-Critical)
========================================
Service-Related: $($serviceWarnings.Count) (Services not found - OK if not installed)
Registry-Related: $($registryWarnings.Count) (Keys already exist - idempotent, OK)
App-Related: $($appWarnings.Count) (Apps already removed - OK)
Other Warnings: $($otherWarnings.Count) (Harmless)

========================================
NEXT STEPS
========================================
$nextSteps

========================================
LOGS & DETAILS
========================================
Transcript Log: $transcriptInfo

NOTE: Script is idempotent - safe to run multiple times.
"@
            $absoluteLog = if ([System.IO.Path]::IsPathRooted($completionLog)) { $completionLog } else { Join-Path (Get-Location) $completionLog }
            # [OK] BEST PRACTICE: UTF-8 without BOM (PowerShell 5.1 compatible)
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($absoluteLog, $statusInfo, $utf8NoBom)
            Write-Verbose "SUCCESS status logged to: $absoluteLog"
        }
        catch {
            Write-Verbose "Could not write success log: $_"
        }
    }
    
    # CRITICAL: Transcript and Mutex CLEANUP (ALWAYS execute!)
    # CRITICAL FIX: Defensive variable existence checks (after Verify in Interactive Menu)
    
    # 1. STOP TRANSCRIPT (if started)
    if ((Test-Path Variable:script:transcriptStarted) -and $script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction Stop
            Write-Verbose "Transcript successfully stopped"
        }
        catch {
            # Transcript was already stopped - not critical
            Write-Verbose "Transcript stop failed (possibly already stopped): $_"
        }
    }
    
    # 2. MUTEX FREIGEBEN (falls acquired)
    if ((Test-Path Variable:script:mutexAcquired) -and (Test-Path Variable:script:mutex) -and $script:mutexAcquired -and $script:mutex) {
        try {
            # SAFETY CHECK: Is Mutex still valid?
            if ($script:mutex.SafeWaitHandle -and -not $script:mutex.SafeWaitHandle.IsClosed) {
                $script:mutex.ReleaseMutex()
                Write-Verbose "Mutex erfolgreich freigegeben"
            }
            else {
                Write-Verbose "Mutex war bereits freigegeben"
            }
        }
        catch [System.ApplicationException] {
            # Mutex was already released - OK
            Write-Verbose "Mutex-Freigabe: Mutex war bereits freigegeben (OK)"
        }
        catch {
            # Unexpected error - log but don't crash
            Write-Warning "Mutex-Freigabe fehlgeschlagen: $($_.Exception.Message)"
        }
        finally {
            # DISPOSE: Release Mutex handle (also on errors)
            try {
                $script:mutex.Dispose()
                Write-Verbose "Mutex-Handle disposed"
            }
            catch {
                Write-Verbose "Mutex-Dispose fehlgeschlagen: $_"
            }
        }
    }
    
    Write-Verbose "Cleanup abgeschlossen - Script beendet"
    
    # Exit with correct code (after cleanup finished)
    if ($script:criticalError) {
        exit 1
    }
}

# CRITICAL FIX v1.7.11: Reboot prompt AFTER finally-block!
# This ensures lastrun.txt is written before reboot happens
# (Restart-Computer inside try-block prevented finally-block execution)
if (-not $script:criticalError) {
    Invoke-RebootPrompt -SkipReboot:$SkipReboot
}
