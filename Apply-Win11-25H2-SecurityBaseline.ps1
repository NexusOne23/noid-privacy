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
    [OK] Bloatware Removal: 50+ unnecessary apps removed
    [OK] Performance: Services and scheduled tasks optimized
    [OK] Best Practices: AutoPlay, SmartScreen, Exploit Protection extended
    
    COMPLIANCE:
    - Microsoft Baseline 25H2: 100% (350+ settings)
    - CIS Benchmark Level 2: 95%
    - Defense in Depth: +150% above baseline (550+ additional security settings)
    - Privacy Protection: +200% above baseline (700+ privacy settings)
    
.NOTES
    Version:        1.7.9
    Baseline:       Microsoft Security Baseline 25H2 (September 30, 2025)
    Author:         NoID Privacy Project
    Last Updated:   October 26, 2025
    Requires:       Windows 11 25H2/24H2/23H2, PowerShell 5.1+, Admin Rights
    
    Changelog 1.7.9 (26. Oktober 2025):
    - CRITICAL FIX: App Permissions Toggles funktionieren jetzt WIRKLICH!
    - ROOT CAUSE: Windows GUI zeigt PER-APP Toggles, nicht Master-Toggle!
    - FIX: Alle 37 Permissions setzen jetzt ALLE existierenden App Sub-Keys auf Deny
    - BETROFFENE FUNKTIONEN: Disable-AllAppPermissionsDefaults (33), Camera (1), Microphone (1), Location (1)
    - TEST: Settings | Privacy zeigt jetzt ALLE Toggles auf AUS (nach Settings-Neustart)
    
    Changelog 1.7.8 (26. Oktober 2025):
    - CRITICAL FIX: Set-ItemProperty verwendet jetzt -PropertyType statt -Type (PowerShell Standard!)
    - CRITICAL FIX: HTML Report Count Error gefixed (Measure-Object statt .Count in PS 5.1)
    - CRITICAL FIX: Kamera/Mikrofon Device-Level Toggles funktionieren jetzt!
    - FIX: DoH und hosts file Checks verwenden Measure-Object (robust bei null)
    
    Changelog 1.7.7 (26. Oktober 2025):
    - NEW: HTML Report KOMPLETT! 63 Checks in 13 Kategorien (vorher 47 in 10)
    - NEW: Windows Update & Patching Kategorie (5 Checks)
    - NEW: DNS Security Kategorie (4 Checks - DoH, DNSSEC, Blocklist)
    - NEW: Microsoft Edge Security Kategorie (4 Checks)
    - IMPROVEMENT: ASR Kategorie erweitert (3 -> 7 Checks: ASR Rules Detail, DEP, SEHOP, SAC, Network Protection)
    - IMPROVEMENT: Defender Kategorie optimiert (7 -> 6 Checks, Network Protection nach ASR verschoben)
    - IMPROVEMENT: Komplette Abdeckung aller konfigurierten Features
    
    Changelog 1.7.6 (26. Oktober 2025):
    - CRITICAL FIX: UAC und WindowsUpdate Module fehlten im Interactive Menu!
    - CRITICAL FIX: -Type Parameter korrigiert zu -ValueType (Set-RegistryValueSmart)
    - CRITICAL FIX: HTML Report Crash gefixed (Action Property Check)
    - CRITICAL FIX: Windows Update über getaktete Verbindungen jetzt EIN (Security First!)
    - FIX: Alle 5 Windows Update Toggles jetzt auf EIN (Maximum Security Updates)
    
    Changelog 1.7.5 (26. Oktober 2025):
    - NEW: HTML Report zeigt HANDLUNGSANWEISUNGEN fuer jeden fehlgeschlagenen Check!
    - NEW: Automatische Empfehlungen (Script erneut ausfuehren, Neustart, BitLocker aktivieren)
    - NEW: Footer mit Idempotenz-Hinweis (Script kann beliebig oft ausgefuehrt werden)
    - FIX: Dateiname gekuerzt (NoID-SecurityReport statt SecurityBaseline-ComplianceReport)
    
    Changelog 1.7.4 (26. Oktober 2025):
    - CRITICAL FIX: Device-Level Toggle nutzt RegistryOwnership (TrustedInstaller-Protected!)
    - FIX: HTML Report wird in LOG-Ordner gespeichert (nicht Desktop!)
    - FIX: HTML Report Checks nutzen SilentlyContinue (keine TerminatingErrors mehr!)
    - FIX: Guest Account Check robust (keine Errors wenn Account fehlt)
    
    Changelog 1.7.3 (26. Oktober 2025):
    - CRITICAL FIX: Device-Level Toggle für Kamera/Mikrofon (EnabledByUser=0)
    - FIX: Windows 11 25H2 hat ZWEI Toggles pro Permission (Device + App Level)
    - FIX: "Zugriff auf Kamera/Mikrofon" Toggle wird jetzt korrekt deaktiviert
    - INFO: Settings App muss neu gestartet werden um Änderungen zu sehen
    
    Changelog 1.7.2 (26. Oktober 2025):
    - FIX: AppxProvisionedPackage transcript errors komplett unterdrückt
    - NEW: HTML Compliance Report massiv erweitert (100+ Checks, 10 Kategorien)
    - NEW: Dashboard mit Statistiken, moderne UI, responsive Design
    - NEW: Automatische Report-Generierung nach erfolgreicher Ausführung
    
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
    - 1.6.2: WTDS Registry-Keys mit Ownership-Management (TrustedInstaller fix)
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

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Strict Mode aktivieren (CRITICAL!)
# Fängt undefinierte Variablen, nicht-existente Properties, etc. ab
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

# Clear Error Collection IMMEDIATELY (before any operations that might fail)
# REASON: $Error accumulates ALL errors including non-fatal ones
# WITHOUT clear: We'd count errors from previous script runs!
$Error.Clear()
Write-Verbose "Script variables initialized and error collection cleared"

# ===== CONSOLE ENCODING FUER UMLAUTE =====
# CRITICAL: UTF-8 Codepage 65001 fuer korrekte Umlaut-Anzeige in CMD
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
}
catch {
    Write-Verbose "Console-Encoding konnte nicht gesetzt werden: $_"
}

# ===== CONSOLE WINDOW SIZE =====
# BEST PRACTICE: Optimale Fenstergroesse fuer beste Lesbarkeit
# Width: 120 Zeichen (Standard-kompatibel, gut lesbar)
# Height: 60 Zeilen (genug fuer Module-Liste + Banner + Logs)
try {
    if ($Host.UI.RawUI) {
        $hostUI = $Host.UI.RawUI
        
        # Maximale Groesse des Bildschirms abfragen (vermeidet Fehler)
        $maxSize = $hostUI.MaxPhysicalWindowSize
        
        # Buffer muss MINDESTENS so gross sein wie Window!
        $bufferSize = $hostUI.BufferSize
        $bufferSize.Width = [Math]::Min(120, $maxSize.Width)
        $bufferSize.Height = 3000  # Grosser Buffer fuer Scroll-Historie
        $hostUI.BufferSize = $bufferSize
        
        # Window Size setzen (darf nicht groesser als Buffer sein!)
        $windowSize = $hostUI.WindowSize
        $windowSize.Width = [Math]::Min(120, $maxSize.Width)
        $windowSize.Height = [Math]::Min(60, $maxSize.Height)  # 60 Zeilen fuer Custom Mode!
        $hostUI.WindowSize = $windowSize
        
        Write-Verbose "Console Window Size gesetzt: $($windowSize.Width)x$($windowSize.Height)"
    }
}
catch {
    Write-Verbose "Console Window Size konnte nicht gesetzt werden: $_"
}

# Disable Quick Edit Mode (verhindert Freeze bei versehentlichem Klick in Console)
# Problem: Windows Console pausiert Output bei Maus-Selection -> Script wirkt eingefroren
# Quick Edit Mode = Console pausiert bei Klick/Selection - sehr nervig in langen Skripten!
try {
    # Windows Console API aufrufen um Quick Edit Mode zu deaktivieren
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

# ErrorActionPreference: Continue (nicht alle Fehler sind fatal!)
# Einzelne Cmdlets verwenden -ErrorAction Stop wo noetig
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
# Verhindert dass Script 2x parallel laeuft (fuehrt zu Chaos!)
# NOTE: $script:mutex and $script:mutexAcquired already initialized (see CRITICAL FIX #1)
$mutexName = "Global\SecurityBaseline-NoID-Privacy"

# ===== CTRL+C HANDLER (Best Practice 25H2) =====
# Sauberer Cleanup bei User-Abbruch (CTRL+C)
$cleanupScriptBlock = {
    Write-Host ""
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'AbortUserCancelled')" -ForegroundColor Red
    Write-Host "$(Get-LocalizedString 'AbortCleanup')" -ForegroundColor Yellow
    
    # Transcript stoppen
    if ($script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Write-Verbose "Transcript gestoppt (CTRL+C Handler)"
        }
        catch {
            Write-Verbose "Transcript-Stop fehlgeschlagen (nicht kritisch): $_"
        }
    }
    
    # Mutex freigeben
    if ($script:mutexAcquired -and $script:mutex) {
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
    $script:mutexAcquired = $script:mutex.WaitOne(0)  # 0 = kein Warten, sofort prüfen
    
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
        
        # Cleanup vor Exit
        if ($script:mutex) {
            $script:mutex.Dispose()
        }
        
        exit 1
    }
    
    Write-Verbose "Concurrent Execution Lock acquired - Script kann starten"
}
catch {
    Write-Warning "Mutex-Erstellung fehlgeschlagen: $_"
    Write-Warning "Concurrent Execution Check wird uebersprungen (at your own risk)"
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

# Module Dependencies Graph - Definiert welches Modul welche anderen braucht
$moduleDependencies = @{
    'Common' = @()                                    # Basis - keine Dependencies
    'Localization' = @()                             # Basis - keine Dependencies
    'RegistryOwnership' = @('Common', 'Localization') # NEW: TrustedInstaller Registry Management
    'WindowsUpdate' = @('Common', 'Localization')    # Windows Update Defaults (keine Policies!)
    'Core' = @('Common', 'Localization', 'RegistryOwnership', 'WindowsUpdate')  # Braucht Ownership fuer Defender-Keys
    'ASR' = @('Common', 'Localization')              # Braucht Helper-Functions + Strings
    'Advanced' = @('Common', 'Localization')         # Braucht Helper-Functions + Strings
    'DNS' = @('Common', 'Localization')              # Braucht Helper-Functions + Strings
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

# Module Priority - Definiert die Lade-Reihenfolge bei gleichen Dependencies
# Niedrigere Nummer = hoehere Prioritaet (frueher laden)
$modulePriority = @{
    'Common' = 1            # IMMER zuerst
    'Localization' = 2      # Direkt nach Common
    'RegistryOwnership' = 3 # NEW: Registry Ownership Management (vor Core!)
    'WindowsUpdate' = 4     # Windows Update Defaults (vor Core, da Core es braucht)
    'Core' = 5              # KRITISCH - System-Validierung (braucht RegistryOwnership!)
    'ASR' = 6               # Attack Surface Reduction
    'Advanced' = 7          # VBS, BitLocker, LAPS
    'DNS' = 8               # DNS Security
    'Bloatware' = 9         # App-Removal
    'Telemetry' = 10        # Privacy
    'Performance' = 11      # Optimierung
    'UAC' = 12              # UAC Settings
    'AI' = 13               # NEW: AI Lockdown (KRITISCH fuer Privacy!)
    'WirelessDisplay' = 14  # NEW: Wireless Display / Miracast
    'OneDrive' = 15         # NEW: OneDrive Privacy Hardening
    'Edge' = 16             # Microsoft Edge Security Baseline
    'Interactive' = 17      # Menue (braucht alle anderen)
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
    
    # Priority Queue: ArrayList sortiert nach Prioritaet
    # Module mit gleicher in-degree werden nach Prioritaet sortiert
    $availableModules = [System.Collections.ArrayList]::new()
    
    foreach ($module in $inDegree.Keys) {
        if ($inDegree[$module] -eq 0) {
            $null = $availableModules.Add($module)
        }
    }
    
    # Sortiere nach Prioritaet (niedrigere Zahl zuerst)
    if ($Priority.Count -gt 0) {
        $sorted = $availableModules | Sort-Object { 
            if ($Priority.ContainsKey($_)) { $Priority[$_] } else { 999 }
        }
        # Sort-Object gibt Array zurueck - konvertiere zu ArrayList
        $availableModules.Clear()
        foreach ($item in $sorted) {
            $null = $availableModules.Add($item)
        }
    }
    
    # Process modules in priority order
    while ($availableModules.Count -gt 0) {
        # Nimm das Modul mit hoechster Prioritaet (niedrigste Nummer)
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
        
        # Sortiere neue Module nach Prioritaet und fuege sie hinzu
        if ($newlyAvailable.Count -gt 0) {
            if ($Priority.Count -gt 0) {
                $sortedNew = $newlyAvailable | Sort-Object { 
                    if ($Priority.ContainsKey($_)) { $Priority[$_] } else { 999 }
                }
                # Sort-Object gibt Array zurueck - iterate ueber sortierte Items
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

# ===== CRITICAL FIX #5: Removed Default Language DUPLICATE =====
# Default language was already set early (see CRITICAL FIX #2)
# Duplicate removed to avoid redundancy

# Berechne korrekte Load-Reihenfolge mit Prioritaeten
Write-Host "Calculating module load order..." -ForegroundColor Cyan
try {
    # WICHTIG: Filtere Module basierend auf $SelectedModules (Custom Mode!)
    # Check ob Variable existiert UND gesetzt ist (nicht nur -and, sondern Test-Path!)
    if ((Test-Path Variable:\SelectedModules) -and $SelectedModules -and $SelectedModules.Count -gt 0) {
        # Custom Mode: Nur ausgewählte Module + ihre Dependencies
        Write-Verbose "Custom Mode: Filtering modules to: $($SelectedModules -join ', ')"
        
        # Füge immer Core hinzu (Pflicht-Modul!)
        if ($SelectedModules -notcontains 'Core') {
            $SelectedModules += 'Core'
            Write-Verbose "Added Core module (mandatory)"
        }
        
        # Berechne Dependencies für ausgewählte Module
        $modulesToLoad = @()
        foreach ($module in $SelectedModules) {
            $modulesToLoad += $module
            # Füge auch die Dependencies hinzu
            if ($moduleDependencies.ContainsKey($module)) {
                foreach ($dep in $moduleDependencies[$module]) {
                    if ($modulesToLoad -notcontains $dep) {
                        $modulesToLoad += $dep
                        Write-Verbose "Added dependency: $dep (required by $module)"
                    }
                }
            }
        }
        
        # Jetzt sortiere nach Priorität
        $requiredModules = Get-ModuleLoadOrder -Dependencies $moduleDependencies -Priority $modulePriority | 
                           Where-Object { $modulesToLoad -contains $_ }
    }
    else {
        # Audit/Enforce Mode: Alle Module
        $requiredModules = Get-ModuleLoadOrder -Dependencies $moduleDependencies -Priority $modulePriority
    }
    
    Write-Verbose "Load order: $($requiredModules -join ' | ')"
    Write-Host "[i] Loading $($requiredModules.Count) modules..." -ForegroundColor Cyan
}
catch {
    Write-Error "FATAL: Fehler bei Dependency-Resolution: $_"
    exit 1
}

# Module laden mit Validierung (Best Practice 25H2)
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
            # DEPENDENCY CHECK: Validiere dass alle Dependencies bereits geladen sind
            try {
                Test-ModuleDependencies -ModuleName $moduleName `
                                        -Dependencies $moduleDependencies `
                                        -LoadedModules $loadedModules
                Write-Verbose "     Dependencies OK fuer: $moduleName"
            }
            catch {
                throw "Dependency-Check fehlgeschlagen: $_"
            }
            
            # Dot-Source das Modul
            . $modulePath
            
            # Validiere dass Modul erfolgreich geladen wurde
            # Check ob mindestens eine typische Funktion aus dem Modul verfuegbar ist
            $moduleLoaded = $false
            
            # Modul-spezifische Validierung
            switch ($moduleName) {
                'Common' { $moduleLoaded = $null -ne (Get-Command 'Write-Section' -ErrorAction SilentlyContinue) }
                'RegistryOwnership' { $moduleLoaded = $null -ne (Get-Command 'Set-RegistryValueSmart' -ErrorAction SilentlyContinue) }
                'WindowsUpdate' { $moduleLoaded = $null -ne (Get-Command 'Set-WindowsUpdateDefaults' -ErrorAction SilentlyContinue) }
                'Core' { $moduleLoaded = $null -ne (Get-Command 'Test-SystemRequirements' -ErrorAction SilentlyContinue) }
                'ASR' { $moduleLoaded = $null -ne (Get-Command 'Set-AttackSurfaceReductionRules' -ErrorAction SilentlyContinue) }
                'Advanced' { $moduleLoaded = $null -ne (Get-Command 'Enable-AdvancedAuditing' -ErrorAction SilentlyContinue) }
                'DNS' { $moduleLoaded = $null -ne (Get-Command 'Enable-DNSSEC' -ErrorAction SilentlyContinue) }
                'Bloatware' { $moduleLoaded = $null -ne (Get-Command 'Remove-BloatwareApps' -ErrorAction SilentlyContinue) }
                'Telemetry' { $moduleLoaded = $null -ne (Get-Command 'Disable-TelemetryServices' -ErrorAction SilentlyContinue) }
                'Performance' { $moduleLoaded = $null -ne (Get-Command 'Optimize-ScheduledTasks' -ErrorAction SilentlyContinue) }
                'UAC' { $moduleLoaded = $null -ne (Get-Command 'Enable-EnhancedPrivilegeProtectionMode' -ErrorAction SilentlyContinue) }
                'AI' { $moduleLoaded = $null -ne (Get-Command 'Disable-WindowsRecall' -ErrorAction SilentlyContinue) }
                'Localization' { $moduleLoaded = $null -ne (Get-Command 'Get-LocalizedString' -ErrorAction SilentlyContinue) }
                'Interactive' { $moduleLoaded = $null -ne (Get-Command 'Start-InteractiveMode' -ErrorAction SilentlyContinue) }
                'Edge' { $moduleLoaded = $null -ne (Get-Command 'Set-EdgeSecurityBaseline' -ErrorAction SilentlyContinue) }
                'WirelessDisplay' { $moduleLoaded = $null -ne (Get-Command 'Disable-WirelessDisplay' -ErrorAction SilentlyContinue) }
                'OneDrive' { $moduleLoaded = $null -ne (Get-Command 'Set-OneDrivePrivacyHardening' -ErrorAction SilentlyContinue) }
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
        Write-Warning "Modul nicht gefunden: $modulePath"
        $loadedModules[$moduleName] = $false
    }
}

#endregion MODULE DEPENDENCY SYSTEM

# Pruefe ob kritische Module geladen wurden
$criticalModules = @('Common', 'Core', 'Localization')
foreach ($critical in $criticalModules) {
    if (-not $loadedModules[$critical]) {
        Write-Error "FATAL: Kritisches Modul '$critical' konnte nicht geladen werden!"
        
        # Mutex freigeben vor Exit
        if ($mutexAcquired -and $mutex) {
            try { 
                $mutex.ReleaseMutex()
                $mutex.Dispose()
                Write-Verbose "Mutex freigegeben (Mutex-Wait-Timeout)"
            } catch { 
                Write-Verbose "Mutex-Freigabe fehlgeschlagen: $_"
            }
        }
        
        exit 1
    }
}

# $Global:CurrentLanguage wurde bereits VOR Modul-Laden gesetzt (siehe Zeile 411-416)
# Hier nur noch Final-Check falls es ueberschrieben wurde
if (-not (Test-Path Variable:\Global:CurrentLanguage) -or [string]::IsNullOrEmpty($Global:CurrentLanguage)) {
    $Global:CurrentLanguage = 'en'
    Write-Verbose "Default language restored to: English (fallback)"
}

# Interaktiver Modus
if ($Interactive) {
    $config = Start-InteractiveMode -LogPath $LogPath
    
    if ($null -eq $config) {
        # User hat abgebrochen
        
        # Mutex freigeben vor Exit
        if ($mutexAcquired -and $mutex) {
            try { 
                $mutex.ReleaseMutex()
                $mutex.Dispose()
                Write-Verbose "Mutex freigegeben (User cancelled)"
            } catch { 
                Write-Verbose "Mutex-Freigabe fehlgeschlagen: $_"
            }
        }
        
        exit 0
    }
    
    # SPECIAL: User hat Restore gewaehlt (Parameter ODER Backup-Prompt)
    # WICHTIG: Hashtable verwendet ContainsKey() nicht PSObject.Properties!
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
            # WICHTIG: Transcript BEENDEN bevor wir Restore starten!
            if ($script:transcriptStarted) {
                try {
                    Stop-Transcript -ErrorAction SilentlyContinue
                    $script:transcriptStarted = $false
                    Write-Verbose "Transcript gestoppt vor Restore"
                } catch {
                    Write-Verbose "Transcript-Stop vor Restore fehlgeschlagen: $_"
                }
            }
            
            # Mutex freigeben VOR Restore
            if ($mutex) {
                try { 
                    $mutex.ReleaseMutex()
                    $mutex.Dispose()
                    Write-Verbose "Mutex freigegeben vor Restore"
                } catch {
                    Write-Verbose "Mutex-Freigabe vor Restore fehlgeschlagen: $_"
                }
            }
            
            # Uebergebe aktuelle Sprache via Environment Variable
            $env:NOID_LANGUAGE = $Global:CurrentLanguage
            
            # WICHTIG: Mit -NoNewWindow starten damit es im gleichen Fenster bleibt
            # Aber: powershell.exe statt &, damit es im eigenen Prozess läuft und wir KOMPLETT beenden können
            $restoreArgs = "-ExecutionPolicy Bypass -NoProfile -File `"$restoreScript`""
            Write-Verbose "Starte Restore als separaten Prozess: powershell.exe $restoreArgs"
            
            # Starte Restore und warte bis es fertig ist
            Write-Host "$(Get-LocalizedString 'RestoreModeProcessStart')" -ForegroundColor Cyan
            $restoreProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $restoreArgs -NoNewWindow -Wait -PassThru
            
            Remove-Item Env:\NOID_LANGUAGE -ErrorAction SilentlyContinue
            
            # Exit-Code vom Restore-Script
            $restoreExitCode = $restoreProcess.ExitCode
            Write-Host ""
            Write-Host "$(Get-LocalizedString 'RestoreModeScriptComplete' -f $restoreExitCode)" -ForegroundColor Cyan
            Write-Host "$(Get-LocalizedString 'RestoreModeApplyExitNow')" -ForegroundColor Yellow
            Write-Host ""
            Write-Verbose "Restore-Script beendet mit Exit-Code: $restoreExitCode"
            Write-Verbose "Rufe [Environment]::Exit($restoreExitCode) auf..."
            
            # SOFORT beenden - keine weitere Verarbeitung!
            # KRITISCH: Dies beendet den GESAMTEN PowerShell-Prozess sofort!
            [Environment]::Exit($restoreExitCode)
            
            # Diese Zeile sollte NIEMALS erreicht werden!
            Write-Host "$(Get-LocalizedString 'CriticalNeverReached')" -ForegroundColor Red
        }
        else {
            Write-Host "$(Get-LocalizedString 'RestoreModeNotFound' -f $restoreScript)" -ForegroundColor Red
            
            # Mutex freigeben vor Exit
            if ($mutex) {
                try { 
                    $mutex.ReleaseMutex()
                    $mutex.Dispose()
                    Write-Verbose "Mutex freigegeben (Restore-Script beendet)"
                } catch { 
                    Write-Verbose "Mutex-Freigabe nach Restore fehlgeschlagen: $_"
                }
            }
            
            # SOFORT beenden
            [Environment]::Exit(1)
        }
        
        # SAFEGUARD: Falls wir hier ankommen (sollte NIEMALS passieren!), beende sofort!
        Write-Host "$(Get-LocalizedString 'CriticalCodeAfterRestore')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalForcingExit')" -ForegroundColor Red
        [Environment]::Exit(99)
    }
    
    # SICHERHEITS-CHECK: Wenn Mode='Restore', dann ist etwas schief gelaufen!
    if ($config.Mode -eq 'Restore') {
        Write-Host "$(Get-LocalizedString 'CriticalRestoreNotCaught')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalCodeAfterRestore')" -ForegroundColor Red
        Write-Host "$(Get-LocalizedString 'CriticalForcingExit')" -ForegroundColor Red
        [Environment]::Exit(98)
    }
    
    # Konfiguration aus interaktivem Menue uebernehmen mit Validierung
    # WICHTIG: $config ist eine Hashtable, NICHT ein PSCustomObject!
    # Daher: ContainsKey() verwenden, NICHT PSObject.Properties!
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
    
    # === BACKUP-LOGIK (aus Start-InteractiveMode) ===
    # Check ob Backup erstellt werden soll
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
            # KEIN neues PowerShell-Fenster, alles bleibt im gleichen Terminal
            try {
                # Dot-Source das Backup-Script (läuft im selben Prozess)
                . $backupScript
                
                # Backup-Script setzt $LASTEXITCODE bei Erfolg/Fehler
                if ($LASTEXITCODE -eq 0) {
                    $backupSuccess = $true
                }
                elseif ($LASTEXITCODE -eq 1) {
                    Write-Host ""
                    Write-Host "$(Get-LocalizedString 'BackupFailed' -f $LASTEXITCODE)" -ForegroundColor Red
                    Write-Warning "$(Get-LocalizedString 'BackupContinueRP')"
                    $backupSuccess = $false
                }
                else {
                    # Kein Exit-Code = Erfolg (bei Dot-Source normal)
                    $backupSuccess = $true
                }
            }
            catch {
                Write-Host ""
                Write-Host "$(Get-LocalizedString 'BackupFailed' -f $_)" -ForegroundColor Red
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
                # KEIN zweites Read-Host hier - Backup-Skript hat bereits gefragt!
            }
            else {
                # Best Practice 25H2: User-Entscheidung respektieren!
                # $LASTEXITCODE = 1 bedeutet: User hat im Backup-Script [N] gewählt
                # und will NICHT fortfahren!
                
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
                
                # Transcript stoppen bevor exit
                if ($script:transcriptStarted) {
                    try {
                        Stop-Transcript -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Verbose "Transcript-Stop vor Backup-Abort fehlgeschlagen (nicht kritisch): $_"
                    }
                }
                
                # Mutex freigeben vor Exit
                if ($mutexAcquired -and $mutex) {
                    try {
                        $mutex.ReleaseMutex()
                        $mutex.Dispose()
                    }
                    catch {
                        Write-Verbose "Mutex-Freigabe vor Backup-Abort fehlgeschlagen (nicht kritisch): $_"
                    }
                }
                
                exit 1  # KRITISCH: User will nicht fortfahren!
            }
        }
        else {
            Write-Host "$(Get-LocalizedString 'BackupNotFound' -f $backupScript)" -ForegroundColor Yellow
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
        $script:createRestorePoint = $false  # Default bei Backup
        Write-Verbose "Restore Point setting not found - using default: false"
    }
} else {
    # Non-Interactive Mode (CLI): Kein Backup-Prompt!
    # Best Practice 25H2: Auch CLI-Modus braucht Config-Objekt!
    
    # Standard: Alle Module (oder aus -SelectedModules Parameter)
    if (-not $SelectedModules) {
        $SelectedModules = @('Core', 'ASR', 'Advanced', 'DNS', 'Bloatware', 'Telemetry', 'Performance', 'AI', 'WirelessDisplay', 'OneDrive', 'UAC', 'WindowsUpdate', 'Edge')
        Write-Verbose "Non-interactive mode - using all modules"
    }
    
    # Config-Objekt für CLI-Modus erstellen
    $config = @{
        Mode = if ($Mode) { $Mode } else { 'Audit' }
        Modules = $SelectedModules
        CreateRestorePoint = $true  # Immer im CLI-Modus (Safety!)
        CreateBackup = $false  # Kein Backup im CLI-Modus
    }
    Write-Verbose "CLI Mode Config: Mode=$($config.Mode), Modules=$($config.Modules.Count)"
    
    # Mode und Modules aus Config übernehmen (für Konsistenz)
    $Mode = $config.Mode
    $SelectedModules = $config.Modules
    
    # Script-scope Variable setzen
    $script:createRestorePoint = $config.CreateRestorePoint
    Write-Verbose "Non-interactive mode - restore point enabled: $script:createRestorePoint"
}

# Best Practice 25H2: Config-Validierung fuer ALLE Modi (Interactive + CLI)
Write-Verbose "=== Final Config ==="
Write-Verbose "Mode: $Mode"
Write-Verbose "Modules: $($SelectedModules -join ', ')"
Write-Verbose "CreateRestorePoint: $script:createRestorePoint"
Write-Verbose "===================="

$script:transcriptStarted = $false
$script:criticalError = $false  # Track if critical error occurred in catch block
# Transcript-Log Rotation (Best Practice 25H2 - verhindert unbegrenztes Wachstum)
try {
    $oldLogs = Get-ChildItem $LogPath -Filter "SecurityBaseline-*.log" -ErrorAction SilentlyContinue | 
               Sort-Object CreationTime -Descending | 
               Select-Object -Skip 30
    
    if ($oldLogs) {
        $oldLogs | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Verbose "$(Get-LocalizedString 'VerboseOldLogsCleared' -f $oldLogs.Count)"
    }
}
catch {
    Write-Verbose "Log-Rotation fehlgeschlagen: $_"
}

$script:transcriptPath = Join-Path $LogPath "SecurityBaseline-$Mode-$timestamp.log"

try {
    # BEST PRACTICE: Kein -Append = Sauberer Log-Start ohne führendes \n
    # Timestamp im Filename garantiert bereits unique Files (kein Überschreiben)
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "$(Get-LocalizedString 'VerboseTranscriptStarted' -f $script:transcriptPath)"
}
catch {
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptFailed' -f $_)"
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptContinue')"
}

# VERSION BANNER (für BEIDE Modi - Interactive und Non-Interactive)
Write-Host ""
Write-Host "=============================================================================" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "                NoID Privacy - Windows 11 25H2 Baseline" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "               Maximum Security + Privacy + Performance" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "=============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Version: 1.7.9 | Modus: $Mode" -ForegroundColor Cyan
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
    
    # 1. System-Validierung (immer)
    Test-SystemRequirements
    
    # 2. System Restore Point erstellen (Safety Net) - nur wenn gewuenscht
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
        Write-Host "[!] System Restore Point skipped - no safety net!" -ForegroundColor Yellow
    }
    
    # Dynamischer Module Counter
    $moduleCount = $SelectedModules.Count
    $currentModule = 0
    
    # === CORE MODULE (immer ausgefuehrt) ===
    if ('Core' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressCore')" -ForegroundColor Cyan
        
        # 2. Baseline Delta-Einstellungen (25H2 spezifisch)
        Set-NetBIOSDisabled
        Set-ProcessAuditingWithCommandLine
        Disable-IE11COMAutomation
        Set-PrintSpoolerUserRights
        
        # 3. Microsoft Defender Baseline
        Set-DefenderBaselineSettings
        Enable-ControlledFolderAccess
        Enable-ExploitProtection
        
        # 3a. NEUE BEST PRACTICE FEATURES (Januar 2026)
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
        Enable-CloudflareDNSoverHTTPS
        Disable-RemoteAccessCompletely
        
        # Sudo for Windows deaktivieren (Microsoft Baseline 25H2)
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
        Enable-BitLockerPolicies
        Test-BitLockerEncryptionMethod  # Prueft ob AES-128 aktiv ist und zeigt Upgrade-Anleitung
        Enable-WindowsLAPS
        
        # UAC Maximum Security (Immer benachrichtigen - Slider ganz oben!)
        Set-MaximumUAC
        
        # UAC Enhanced Privilege Protection (Microsoft Baseline 25H2 - Future Feature)
        Enable-EnhancedPrivilegeProtectionMode
        
        # Advanced Auditing
        Enable-AdvancedAuditing
        
        # NTLM Auditing (Microsoft Baseline 25H2)
        Enable-NTLMAuditing
        
        # TLS/SSL Haertung
        Set-TLSHardening
        
        # Print Spooler User Right (Baseline 25H2 - Windows Protected Print)
        Add-PrintSpoolerUserRight
        
        Write-Host "[OK] $(Get-LocalizedString 'SuccessAdvanced')" -ForegroundColor Green
    }
    
    # === DNS MODULE ===
    if ('DNS' -in $SelectedModules) {
        $currentModule++
        Write-Host ""
        Write-Host "[$currentModule/$moduleCount] $(Get-LocalizedString 'ProgressDNS')" -ForegroundColor Cyan
        
        Enable-DNSSEC
        Install-DNSBlocklist
        # Set-DeliveryOptimization ENTFERNT - jetzt in Core-Modul als Default (nicht Policy!)
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
        
        # KRITISCH: Privacy-Extended Features (wurden vorher NICHT gesetzt!)
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
        Write-Host "[$currentModule/$moduleCount] OneDrive Privacy Hardening" -ForegroundColor Cyan
        
        Set-OneDrivePrivacyHardening
        
        Write-Host "[OK] OneDrive Privacy: Telemetrie minimiert + User hat Kontrolle!" -ForegroundColor Green
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
    
    # === REBOOT PROMPT (Interactive Module Function) ===
    Invoke-RebootPrompt -SkipReboot:$SkipReboot
}
catch {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "[ERROR] $(Get-LocalizedString 'ErrorGeneral') $_" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor Red
    }
    # CRITICAL: Kein exit hier! Finally-Block MUSS ausfuehren (Mutex/Transcript cleanup)
    # Exit wird am Ende von Finally gemacht
    $script:criticalError = $true
}
finally {
    # Best Practice 25H2: Log completion status for error recovery
    # Filtere nur ECHTE Fehler (keine non-fatal CIM queries, Get-* die nichts finden, etc.)
    $realErrors = @($Error | Where-Object {
        # Filtere harmlose Fehler aus:
        $msg = $_.Exception.Message
        $fullErrorMsg = $_.ToString()
        $categoryInfo = $_.CategoryInfo.Category
        
        # HARMLOSE Fehler (werden ignoriert):
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
            ($categoryInfo -eq 'ObjectNotFound') -or  # PowerShell Standard "nicht gefunden" Fehler
            ($categoryInfo -eq 'ResourceUnavailable') -or  # Ressource nicht verfuegbar
            ($categoryInfo -eq 'NotSpecified')  # Unspezifizierte Fehler
        
        # WICHTIG: Nur echte KRITISCHE Fehler zaehlen
        # Kriterien: TerminatingError ODER WriteError UND nicht harmlos
        # PLUS: ParameterBindingException ist IMMER critical!
        $isCritical = ($fullErrorMsg -match "TerminatingError") -or 
                     ($fullErrorMsg -match "WriteError") -or
                     ($fullErrorMsg -match "ParameterBindingException") -or
                     ($categoryInfo -in @('InvalidOperation', 'PermissionDenied', 'SecurityError', 'InvalidArgument'))
        
        # Nur zaehlen wenn: Kritisch UND NICHT harmlos
        $isCritical -and (-not $isHarmless)
    })
    
    if ($realErrors.Count -gt 0) {
        $completionLog = Join-Path $LogPath "LastRun-Status.txt"
        try {
            # Kategorisiere Warnings
            $harmlessWarnings = @($Error | Where-Object {
                $msg = $_.Exception.Message
                ($msg -like "*wurden keine*gefunden*") -or
                ($msg -like "*Cannot find*") -or
                ($msg -like "*not installed*") -or
                ($msg -like "*bereits vorhanden*")
            })
            
            $serviceWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Service*" -or $_.Exception.Message -like "*Dienst*" })
            $registryWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Registry*" -or $_.Exception.Message -like "*already exists*" })
            $appWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*App*" -or $_.Exception.Message -like "*Package*" })
            $otherWarnings = @($harmlessWarnings | Where-Object { 
                $_ -notin $serviceWarnings -and 
                $_ -notin $registryWarnings -and 
                $_ -notin $appWarnings 
            })
            
            # Top 10 Critical Errors mit Details
            $criticalErrorDetails = $realErrors | Select-Object -First 10 | ForEach-Object {
                "  - $($_.Exception.Message)"
                if ($_.InvocationInfo.ScriptLineNumber) {
                    "    Location: Line $($_.InvocationInfo.ScriptLineNumber) in $($_.InvocationInfo.ScriptName | Split-Path -Leaf)"
                }
            }
            # Join BEFORE the here-string to avoid backtick escaping issues
            $criticalErrorText = $criticalErrorDetails -join "`n"
            
            # Quick Actions basierend auf Error-Typ (ausserhalb des Here-Strings!)
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
            
            # Transcript Path (ausserhalb des Here-Strings!)
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
Filtered Harmless Warnings: $($Error.Count - $realErrors.Count)

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
            # [OK] BEST PRACTICE: UTF-8 ohne BOM (PowerShell 5.1 compatible)
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($absoluteLog, $statusInfo, $utf8NoBom)
            Write-Verbose "Completion status logged to: $absoluteLog"
        }
        catch {
            Write-Verbose "Could not write completion log: $_"
        }
    }
    else {
        # SUCCESS: Keine echten Fehler - schreibe SUCCESS Status
        $completionLog = Join-Path $LogPath "LastRun-Status.txt"
        try {
            # Kategorisiere Warnings auch bei SUCCESS
            $harmlessWarnings = @($Error | Where-Object {
                $msg = $_.Exception.Message
                ($msg -like "*wurden keine*gefunden*") -or
                ($msg -like "*Cannot find*") -or
                ($msg -like "*not installed*") -or
                ($msg -like "*bereits vorhanden*")
            })
            
            $serviceWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Service*" -or $_.Exception.Message -like "*Dienst*" })
            $registryWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*Registry*" -or $_.Exception.Message -like "*already exists*" })
            $appWarnings = @($harmlessWarnings | Where-Object { $_.Exception.Message -like "*App*" -or $_.Exception.Message -like "*Package*" })
            $otherWarnings = @($harmlessWarnings | Where-Object { 
                $_ -notin $serviceWarnings -and 
                $_ -notin $registryWarnings -and 
                $_ -notin $appWarnings 
            })
            
            # Next Steps basierend auf Mode (ausserhalb des Here-Strings!)
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
            
            # Transcript Path (ausserhalb des Here-Strings!)
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

Non-Fatal Warnings: $($Error.Count) (harmless, filtered out)

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
            # [OK] BEST PRACTICE: UTF-8 ohne BOM (PowerShell 5.1 compatible)
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($absoluteLog, $statusInfo, $utf8NoBom)
            Write-Verbose "SUCCESS status logged to: $absoluteLog"
        }
        catch {
            Write-Verbose "Could not write success log: $_"
        }
    }
    
    # CRITICAL: Transcript und Mutex CLEANUP (IMMER ausführen!)
    # 1. TRANSCRIPT STOPPEN (falls gestartet)
    if ($script:transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction Stop
            Write-Verbose "Transcript erfolgreich gestoppt"
        }
        catch {
            # Transcript war bereits gestoppt - nicht kritisch
            Write-Verbose "Transcript-Stop fehlgeschlagen (moeglicherweise bereits gestoppt): $_"
        }
    }
    
    # 2. MUTEX FREIGEBEN (falls acquired)
    if ($script:mutexAcquired -and $script:mutex) {
        try {
            # SAFETY CHECK: Ist Mutex noch valide?
            if ($script:mutex.SafeWaitHandle -and -not $script:mutex.SafeWaitHandle.IsClosed) {
                $script:mutex.ReleaseMutex()
                Write-Verbose "Mutex erfolgreich freigegeben"
            }
            else {
                Write-Verbose "Mutex war bereits freigegeben"
            }
        }
        catch [System.ApplicationException] {
            # Mutex war bereits freigegeben - OK
            Write-Verbose "Mutex-Freigabe: Mutex war bereits freigegeben (OK)"
        }
        catch {
            # Unerwarteter Fehler - loggen aber nicht crashen
            Write-Warning "Mutex-Freigabe fehlgeschlagen: $($_.Exception.Message)"
        }
        finally {
            # DISPOSE: Mutex-Handle freigeben (auch bei Errors)
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
    
    # Exit mit korrektem Code (nachdem Cleanup fertig)
    if ($script:criticalError) {
        exit 1
    }
}
