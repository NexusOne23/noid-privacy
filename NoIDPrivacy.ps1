#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NoID Privacy - Professional Windows 11 Security & Privacy Hardening Framework
    
.DESCRIPTION
    Enterprise-grade security hardening for Windows 11 implementing:
    - Microsoft Security Baseline (425+ settings)
    - Attack Surface Reduction (19 rules)
    - Secure DNS configuration
    - AI features disable
    - Telemetry & privacy controls
    - And more...
    
.PARAMETER Module
    Specific module to run (SecurityBaseline, ASR, DNS, etc.)
    If not specified, shows interactive menu
    
.PARAMETER DryRun
    Preview changes without applying them
    
.PARAMETER VerboseLogging
    Enable verbose logging output
    
.PARAMETER Config
    Path to custom configuration file (default: config.json)
    
.EXAMPLE
    .\NoIDPrivacy.ps1
    Interactive menu mode
    
.EXAMPLE
    .\NoIDPrivacy.ps1 -Module SecurityBaseline
    Run only the Security Baseline module
    
.EXAMPLE
    .\NoIDPrivacy.ps1 -Module ASR -DryRun
    Preview ASR rule changes without applying
    
.EXAMPLE
    .\NoIDPrivacy.ps1 -Module All -VerboseLogging
    Run all enabled modules with verbose logging
    
.NOTES
    DISCLAIMER:
    This software is provided "as is" without warranty of any kind. 
    By using this software, you agree that the authors are not liable for any damages 
    resulting from its use. USE AT YOUR OWN RISK.

    Author: NexusOne23
    Version: 2.2.0
    Requires: PowerShell 5.1+, Administrator privileges, Windows 11
    License: GPL-3.0 (Core CLI). See LICENSE for full terms.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet(
        "SecurityBaseline",
        "ASR",
        "DNS",
        "Privacy",
        "AntiAI",
        "EdgeHardening",
        "AdvancedSecurity",
        "All"
    )]
    [string]$Module,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

# Enable strict mode for better error detection
Set-StrictMode -Version Latest

# Script root path
$script:RootPath = $PSScriptRoot

# Import Core modules
Write-Host "Loading NoID Privacy Framework..." -ForegroundColor Cyan
Write-Host ""

try {
    # Load Logger first
    . (Join-Path $script:RootPath "Core\Logger.ps1")
    
    # Initialize logger with absolute path
    $logLevel = if ($VerboseLogging) { [LogLevel]::DEBUG } else { [LogLevel]::INFO }
    $logDirectory = Join-Path $script:RootPath "Logs"
    Initialize-Logger -LogDirectory $logDirectory -MinimumLevel $logLevel
    
    Write-Log -Level INFO -Message "=== NoID Privacy Framework v2.2.0 ===" -Module "Main"
    Write-Log -Level INFO -Message "Starting framework initialization..." -Module "Main"
    
    # Load other Core modules
    . (Join-Path $script:RootPath "Core\Config.ps1")
    . (Join-Path $script:RootPath "Core\Validator.ps1")
    . (Join-Path $script:RootPath "Core\Rollback.ps1")
    . (Join-Path $script:RootPath "Core\NonInteractive.ps1")  # Must load BEFORE Framework for GUI mode
    . (Join-Path $script:RootPath "Core\Framework.ps1")
    
    # Load Utils
    . (Join-Path $script:RootPath "Utils\Registry.ps1")
    . (Join-Path $script:RootPath "Utils\Service.ps1")
    . (Join-Path $script:RootPath "Utils\Hardware.ps1")
    # NOTE: Utils\GPO.ps1 removed - v2.0 SecurityBaseline is self-contained
    . (Join-Path $script:RootPath "Utils\Localization.ps1")
    . (Join-Path $script:RootPath "Utils\Compatibility.ps1")
    . (Join-Path $script:RootPath "Utils\Dependencies.ps1")
    
    Write-Log -Level SUCCESS -Message "All core modules loaded successfully" -Module "Main"
}
catch {
    Write-Host "" -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "FATAL ERROR: Failed to load core framework modules" -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Location: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    Write-Host "" -ForegroundColor Red
    Write-Host "Please ensure all framework files are present and not corrupted." -ForegroundColor Yellow
    exit 1
}

# Load configuration
try {
    Write-Log -Level INFO -Message "Loading configuration..." -Module "Main"
    
    # Check for ConfigPath from environment variable (GUI mode)
    if ([string]::IsNullOrEmpty($ConfigPath) -and $env:NOIDPRIVACY_CONFIGPATH) {
        $ConfigPath = $env:NOIDPRIVACY_CONFIGPATH
    }
    
    if ($ConfigPath) {
        Initialize-Config -ConfigPath $ConfigPath
    }
    else {
        Initialize-Config
    }
    
    Write-Log -Level SUCCESS -Message "Configuration loaded" -Module "Main"
}
catch {
    Write-Log -Level ERROR -Message "Failed to load configuration file" -Module "Main" -Exception $_.Exception
    Write-Host "ERROR: Configuration file error - check config.json syntax" -ForegroundColor Red
    exit 1
}

# Validate prerequisites (full framework pre-flight: system, domain, backup)
try {
    Write-Log -Level INFO -Message "Validating framework prerequisites..." -Module "Main"
    
    $ok = Test-FrameworkPrerequisites
    
    if (-not $ok) {
        Write-Log -Level ERROR -Message "Framework prerequisites failed" -Module "Main"
        Write-Host "ERROR: Prerequisite checks failed. See log for details." -ForegroundColor Red
        exit 1
    }
    
    Write-Log -Level SUCCESS -Message "Framework prerequisites met" -Module "Main"
}
catch {
    Write-ErrorLog -Message "Framework prerequisite validation failed" -Module "Main" -ErrorRecord $_
    Write-Host "ERROR: System requirements not met - see log for details" -ForegroundColor Red
    exit 1
}

# Display banner
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NoID Privacy - v2.2.0" -ForegroundColor Cyan
Write-Host "  Windows 11 Security Hardening" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY RUN MODE - No changes will be applied]" -ForegroundColor Yellow
    Write-Host ""
}

# Interactive menu or direct module execution
if (-not $Module) {
    # Show interactive menu
    Write-Host "Available Actions:" -ForegroundColor White
    Write-Host ""
    Write-Host "  APPLY HARDENING:" -ForegroundColor Cyan
    Write-Host "  1. SecurityBaseline     - Microsoft Security Baseline (425+ settings)" -ForegroundColor Green
    Write-Host "  2. ASR                  - Attack Surface Reduction (19 rules)" -ForegroundColor Green
    Write-Host "  3. DNS                  - Secure DNS with DoH (Quad9/Cloudflare/AdGuard)" -ForegroundColor Green
    Write-Host "  4. Privacy              - Telemetry & Privacy hardening (3 modes)" -ForegroundColor Green
    Write-Host "  5. AntiAI               - Disable Windows AI features (15 features, 32 policies)" -ForegroundColor Green
    Write-Host "  6. EdgeHardening        - Secure Microsoft Edge browser" -ForegroundColor Green
    Write-Host "  7. AdvancedSecurity     - Legacy Protocol hardening, Windows Update, SRP (CVE-2025-9491)" -ForegroundColor Green
    Write-Host " 99. ALL MODULES (WIZARD) - Interactive setup for all modules" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  SYSTEM OPERATIONS:" -ForegroundColor Cyan
    Write-Host "  V. Verify Settings      - Check up to 630+ hardening settings" -ForegroundColor Magenta
    Write-Host "  R. Restore Backup       - Rollback to previous state" -ForegroundColor Yellow
    Write-Host "  B. List Backups         - Show all available backups" -ForegroundColor Gray
    Write-Host "  I. System Info          - Display system information" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  0. Exit" -ForegroundColor Red
    Write-Host ""
    
    do {
        $selection = Read-Host "Select option [1-7, 99, V, R, B, I, 0] (default: 99)"
        if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "99" }
        $selection = $selection.ToUpper()
        
        if ($selection -notin @('1','2','3','4','5','6','7','99','V','R','B','I','0')) {
            Write-Host ""
            Write-Host "Invalid selection. Please choose from the menu." -ForegroundColor Red
            Write-Host ""
        }
    } while ($selection -notin @('1','2','3','4','5','6','7','99','V','R','B','I','0'))
    
    switch ($selection) {
        "1"  { $Module = "SecurityBaseline" }
        "2"  { $Module = "ASR" }
        "3"  { $Module = "DNS" }
        "4"  { $Module = "Privacy" }
        "5"  { $Module = "AntiAI" }
        "6"  { $Module = "EdgeHardening" }
        "7"  { $Module = "AdvancedSecurity" }
        "99" { $Module = "All" }
        "V"  {
            # Verify all settings
            Write-Host ""
            Write-Host "Running complete verification..." -ForegroundColor Cyan
            Write-Host ""
            
            $verifyScript = Join-Path $script:RootPath "Tools\Verify-Complete-Hardening.ps1"
            if (Test-Path $verifyScript) {
                # Discard return value so that 'True' / 'False' is not printed to console
                $null = & $verifyScript
            }
            else {
                Write-Host "ERROR: Verification script not found" -ForegroundColor Red
            }
            
            Write-Host ""
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 0
        }
        "R"  {
            # Restore from backup - Interactive session selection from disk
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  RESTORE FROM BACKUP" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            
            # Get all backup sessions from disk
            $sessions = Get-BackupSessions
            
            if ($sessions.Count -eq 0) {
                Write-Host "No backup sessions found." -ForegroundColor Yellow
                Write-Host "Backups are created when you apply hardening modules." -ForegroundColor Gray
                Write-Host ""
                Write-Host "Press any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit 0
            }
            
            Write-Host "Available backup sessions:" -ForegroundColor White
            Write-Host ""
            
            $i = 1
            foreach ($session in $sessions) {
                $moduleNames = ($session.Modules | ForEach-Object { $_.name }) -join ", "
                $dateStr = $session.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                
                Write-Host "  [$i] $dateStr" -ForegroundColor Green
                Write-Host "      Modules: $moduleNames" -ForegroundColor Gray
                Write-Host "      Items: $($session.TotalItems)" -ForegroundColor Gray
                Write-Host ""
                $i++
            }
            
            Write-Host "  [0] Cancel and return" -ForegroundColor Red
            Write-Host ""
            
            $selection = Read-Host "Select session to restore [1-$($sessions.Count), 0=Cancel]"
            
            if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
                Write-Host "Restore cancelled." -ForegroundColor Yellow
                exit 0
            }
            
            $selIndex = [int]$selection - 1
            if ($selIndex -lt 0 -or $selIndex -ge $sessions.Count) {
                Write-Host "Invalid selection." -ForegroundColor Red
                exit 1
            }
            
            $selectedSession = $sessions[$selIndex]
            
            Write-Host ""
            Write-Host "Restoring session: $($selectedSession.SessionId)" -ForegroundColor Cyan
            Write-Host ""
            
            # Call Restore-Session with the session path
            $success = Restore-Session -SessionPath $selectedSession.FolderPath
            
            if ($success) {
                Write-Host ""
                Write-Host "Restore completed successfully!" -ForegroundColor Green
            }
            else {
                Write-Host ""
                Write-Host "Restore completed with some errors. Check logs for details." -ForegroundColor Yellow
            }
            
            Write-Host ""
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 0
        }
        "B"  {
            # List backups
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Available Backups" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            
            $backupPath = Join-Path $script:RootPath "Backups"
            if (Test-Path $backupPath) {
                $backups = Get-ChildItem -Path $backupPath -Directory | Sort-Object CreationTime -Descending
                
                if ($backups.Count -eq 0) {
                    Write-Host "  No backups found" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Found $($backups.Count) backup(s):" -ForegroundColor White
                    Write-Host ""
                    
                    foreach ($backup in $backups) {
                        $age = (Get-Date) - $backup.CreationTime
                        $ageStr = if ($age.TotalHours -lt 1) { "$([math]::Round($age.TotalMinutes)) minutes ago" }
                                  elseif ($age.TotalDays -lt 1) { "$([math]::Round($age.TotalHours)) hours ago" }
                                  else { "$([math]::Round($age.TotalDays)) days ago" }
                        
                        Write-Host "  - $($backup.Name)" -ForegroundColor Green -NoNewline
                        Write-Host " ($ageStr)" -ForegroundColor Gray
                    }
                }
            }
            else {
                Write-Host "  Backup directory not found" -ForegroundColor Yellow
            }
            
            Write-Host ""
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 0
        }
        "I"  {
            # System information
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  System Information" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            
            try {
                $os = Get-CimInstance Win32_OperatingSystem
                $cs = Get-CimInstance Win32_ComputerSystem
                
                Write-Host "  Computer Name:     $($cs.Name)" -ForegroundColor White
                Write-Host "  OS Version:        $($os.Caption) Build $($os.BuildNumber)" -ForegroundColor White
                Write-Host "  PowerShell:        $($PSVersionTable.PSVersion)" -ForegroundColor White
                Write-Host "  Domain Joined:     $(if ($cs.PartOfDomain) { 'Yes' } else { 'No (Standalone)' })" -ForegroundColor White
                
                Write-Host ""
                Write-Host "  Security Status:" -ForegroundColor Yellow
                
                # Check VBS
                try {
                    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
                    if ($vbs) {
                        Write-Host "    VBS Enabled:     $(if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { 'Green' } else { 'Red' })
                    }
                }
                catch { $null = $null }  # Intentionally ignore VBS query errors
                
                # Check Defender
                try {
                    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($defender) {
                        Write-Host "    Defender Active: $(if ($defender.AntivirusEnabled) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($defender.AntivirusEnabled) { 'Green' } else { 'Red' })
                    }
                }
                catch { $null = $null }  # Intentionally ignore Defender query errors
            }
            catch {
                Write-Host "  Failed to retrieve system information" -ForegroundColor Red
            }
            
            Write-Host ""
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 0
        }
        "0"  { 
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
    }
}

# Execute selected module(s)
try {
    Write-Log -Level INFO -Message "Starting module execution: $Module" -Module "Main"
    
    $result = Invoke-Hardening -Module $Module -DryRun:$DryRun
    
    # Handle array return (pipeline contamination protection)
    if ($result -is [array]) {
        Write-Log -Level DEBUG -Message "Invoke-Hardening returned array ($($result.Count) items), using last element" -Module "Main"
        $result = $result[-1]
    }
    
    # Display results
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Execution Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($result.Success) {
        Write-Host "Status: SUCCESS" -ForegroundColor Green
        Write-Host "Modules Executed: $($result.ModulesExecuted)" -ForegroundColor White
        Write-Host "Duration: $($result.Duration.TotalSeconds) seconds" -ForegroundColor White
    }
    else {
        Write-Host "Status: FAILED" -ForegroundColor Red
        Write-Host "Errors: $($result.Errors.Count)" -ForegroundColor Red
        
        if ($result.Errors.Count -gt 0) {
            Write-Host ""
            Write-Host "Error Details:" -ForegroundColor Red
            foreach ($errMsg in $result.Errors) {
                Write-Host "  - $errMsg" -ForegroundColor Red
            }
        }
    }
    
    if ($result.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings: $($result.Warnings.Count)" -ForegroundColor Yellow
        foreach ($warning in $result.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "Log file: $(Get-LogFilePath)" -ForegroundColor Cyan
    Write-Host ""
    
    if ($result.Success) {
        Write-Log -Level SUCCESS -Message "Framework execution completed successfully" -Module "Main"
        exit 0
    }
    else {
        Write-Log -Level ERROR -Message "Framework execution completed with errors" -Module "Main"
        exit 1
    }
}
catch {
    Write-ErrorLog -Message "Fatal error during framework execution" -Module "Main" -ErrorRecord $_
    Write-Host ""
    Write-Host "FATAL ERROR: Unexpected exception during execution" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}
