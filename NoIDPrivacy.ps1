#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NoID Privacy - Professional Windows 11 Security & Privacy Hardening Framework

.DESCRIPTION
    Security & privacy hardening for Windows 11 implementing:
    - Microsoft Security Baseline-derived profile (425 declared targets)
    - Attack Surface Reduction (19 rules)
    - Secure DNS configuration
    - AI features disable
    - Telemetry & privacy controls
    - And more...

.PARAMETER Module
    Specific module to run (SecurityBaseline, ASR, DNS, etc.)
    If not specified, shows interactive menu

.PARAMETER Modules
    Explicit set of modules to run together in one process and one sealed BAVR
    session. Cannot be combined with -Module.

.PARAMETER DryRun
    Preview changes without applying them

.PARAMETER VerboseLogging
    Enable verbose logging output

.PARAMETER ConfigPath
    Path to custom configuration file (default: config.json)

.PARAMETER RestoreSessionPath
    Restore one explicit sealed session noninteractively. Intended for the
    guarded Windows 11 BAVR validation workflow and other audited automation.

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
    .\NoIDPrivacy.ps1 -Modules ASR,DNS,Privacy
    Run the selected modules in one shared backup/apply/verify session

.EXAMPLE
    .\NoIDPrivacy.ps1 -RestoreSessionPath .\Backups\Session_20260710_120000_000_ab12cd34
    Restore and verify exactly one sealed session without menu selection

.EXAMPLE
    .\NoIDPrivacy.ps1 -Module All -VerboseLogging
    Run all enabled modules with verbose logging

.NOTES
    DISCLAIMER:
    This software is provided "as is" without warranty of any kind.
    By using this software, you agree that the authors are not liable for any damages
    resulting from its use. USE AT YOUR OWN RISK.

    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+, Administrator privileges, Windows 11
    License: GPL-3.0 (Core CLI). See LICENSE for full terms.

.OUTPUTS
    Exit Codes for CI/CD Integration:

    0  = SUCCESS              - All operations completed successfully
    1  = ERROR_GENERAL        - General/unspecified error
    2  = ERROR_PREREQUISITES  - System requirements not met (OS, PowerShell, Admin)
    3  = ERROR_CONFIG         - Configuration file error (missing, invalid JSON)
    4  = ERROR_MODULE         - One or more modules failed during execution
    5  = ERROR_FATAL          - Fatal/unexpected exception
    10 = SUCCESS_REBOOT       - Success, but reboot is required for changes to take effect

    Example CI/CD usage:
    $exitCode = (Start-Process powershell -ArgumentList "-File NoIDPrivacy.ps1 -Module All" -Wait -PassThru).ExitCode
    if ($exitCode -eq 0 -or $exitCode -eq 10) { "Success" } else { "Failed with code $exitCode" }
#>

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = 'Single')]
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

    [Parameter(Mandatory = $true, ParameterSetName = 'Multiple')]
    [ValidateCount(1, 7)]
    [ValidateScript({
        $validModules = @(
            'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
            'EdgeHardening', 'AdvancedSecurity'
        )
        foreach ($selectedModule in $_) {
            if ($selectedModule -notin $validModules) {
                throw "Invalid module name '$selectedModule'. Valid: $($validModules -join ', ')"
            }
        }
        $true
    })]
    [string[]]$Modules,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [ValidateNotNullOrEmpty()]
    [string]$RestoreSessionPath
)

# Windows PowerShell 5.1 invokes ValidateScript on a [string[]] once per
# element, so an attribute cannot compare the complete bound array. Reject
# duplicate logical module identities here, before initialization, backup or
# any Windows-state query/mutation. OrdinalIgnoreCase matches parameter-name
# validation and prevents aliases such as ASR/asr from executing twice.
if ($PSBoundParameters.ContainsKey('Modules')) {
    $boundModuleIdentities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($boundModule in @($Modules)) {
        if (-not $boundModuleIdentities.Add([string]$boundModule)) {
            throw "Duplicate module names are not allowed: $boundModule"
        }
    }
}

# Enable strict mode for better error detection
Set-StrictMode -Version Latest

# ============================================================================
# RESET BACKUP STATE - Each NoIDPrivacy.ps1 call gets a fresh session
# ============================================================================
# This ensures multiple runs from Interactive Menu create separate sessions
$global:BackupBasePath = ""
$global:BackupIndex = @()
$global:SessionManifest = @{}
$global:CurrentModule = ""

# ============================================================================
# EXIT CODES - For CI/CD and automation integration
# ============================================================================
$script:EXIT_SUCCESS = 0   # All operations completed successfully
$script:EXIT_ERROR_GENERAL = 1   # General/unspecified error
$script:EXIT_ERROR_PREREQUISITES = 2  # System requirements not met
$script:EXIT_ERROR_CONFIG = 3   # Configuration file error
$script:EXIT_ERROR_MODULE = 4   # One or more modules failed
$script:EXIT_ERROR_FATAL = 5   # Fatal/unexpected exception
$script:EXIT_SUCCESS_REBOOT = 10  # Success, reboot required

# Windows PowerShell 5.1 collapses a non-zero `exit` from a script invoked via
# the call operator to process exit 1. Pair every exit below with
# PSHost.SetShouldExit so direct -File, interactive, and embedded GUI/Shell
# callers observe the same documented numeric contract.

# Script root path
$script:RootPath = $PSScriptRoot

# Import Core modules
Write-Host "Loading NoID Privacy Framework..." -ForegroundColor Cyan
Write-Host ""

try {
    $versionPath = Join-Path $script:RootPath 'VERSION'
    if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
        throw "Canonical VERSION file is missing: $versionPath"
    }
    $script:FrameworkVersion = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
    if ($script:FrameworkVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Canonical VERSION value is invalid: '$script:FrameworkVersion'"
    }

    # Load Logger first
    . (Join-Path $script:RootPath "Core\Logger.ps1")

    # Initialize logger with absolute path
    $logLevel = if ($VerboseLogging) { [LogLevel]::DEBUG } else { [LogLevel]::INFO }
    $logDirectory = Join-Path $script:RootPath "Logs"
    Initialize-Logger -LogDirectory $logDirectory -MinimumLevel $logLevel

    Write-Log -Level INFO -Message "=== NoID Privacy Framework v$script:FrameworkVersion ===" -Module "Main"
    Write-Log -Level INFO -Message "Starting framework initialization..." -Module "Main"

    # Load other Core modules
    . (Join-Path $script:RootPath "Core\Config.ps1")
    . (Join-Path $script:RootPath "Core\Validator.ps1")
    . (Join-Path $script:RootPath "Core\Rollback.ps1")
    . (Join-Path $script:RootPath "Core\IntentState.ps1")
    . (Join-Path $script:RootPath "Core\NonInteractive.ps1")  # Must load BEFORE Framework for GUI mode
    . (Join-Path $script:RootPath "Core\Framework.ps1")

    # Load Utils
    . (Join-Path $script:RootPath "Utils\Hardware.ps1")
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
    $host.SetShouldExit($script:EXIT_ERROR_FATAL)
    exit $script:EXIT_ERROR_FATAL
}

# Load configuration
try {
    Write-Log -Level INFO -Message "Loading configuration..." -Module "Main"

    # A GUI Apply passes its closed config in the child process environment so
    # no user-writable temporary file can be swapped between validation and use.
    $configJsonBase64 = [string]$env:NOIDPRIVACY_CONFIG_JSON_BASE64

    # Check for legacy/file-backed ConfigPath from environment variable.
    if ([string]::IsNullOrEmpty($ConfigPath) -and $env:NOIDPRIVACY_CONFIGPATH) {
        $ConfigPath = $env:NOIDPRIVACY_CONFIGPATH
    }

    if (-not [string]::IsNullOrWhiteSpace($configJsonBase64)) {
        if ($ConfigPath) {
            throw 'In-memory GUI configuration and ConfigPath are mutually exclusive'
        }
        if ([string]$env:NOIDPRIVACY_NONINTERACTIVE -cne 'true') {
            throw 'In-memory GUI configuration requires the explicit non-interactive process contract'
        }
        try {
            $configJson = [System.Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($configJsonBase64)
            )
        }
        catch {
            throw "In-memory GUI configuration is not valid base64 UTF-8: $($_.Exception.Message)"
        }
        Initialize-Config -ConfigJson $configJson -CreateDefault $false
    }
    elseif ($ConfigPath) {
        # An explicitly supplied path is part of the caller's mutation plan.
        # Replacing a missing file with repository defaults would silently
        # replace that plan, so only the canonical implicit path may self-heal.
        Initialize-Config -ConfigPath $ConfigPath -CreateDefault $false
    }
    else {
        # Only the implicit canonical repository config may self-heal. Every
        # caller-selected path and every in-memory mutation plan is fail-closed.
        Initialize-Config -CreateDefault $true
    }

    Write-Log -Level SUCCESS -Message "Configuration loaded" -Module "Main"
}
catch {
    Write-Log -Level ERROR -Message "Failed to load configuration file" -Module "Main" -Exception $_.Exception
    Write-Host "ERROR: Configuration file error - check config.json syntax" -ForegroundColor Red
    $host.SetShouldExit($script:EXIT_ERROR_CONFIG)
    exit $script:EXIT_ERROR_CONFIG
}

# Validate prerequisites (full framework pre-flight: system, domain, backup)
try {
    Write-Log -Level INFO -Message "Validating framework prerequisites..." -Module "Main"

    $ok = Test-FrameworkPrerequisites

    if (-not $ok) {
        Write-Log -Level ERROR -Message "Framework prerequisites failed" -Module "Main"
        Write-Host "ERROR: Prerequisite checks failed. See log for details." -ForegroundColor Red
        $host.SetShouldExit($script:EXIT_ERROR_PREREQUISITES)
        exit $script:EXIT_ERROR_PREREQUISITES
    }

    Write-Log -Level SUCCESS -Message "Framework prerequisites met" -Module "Main"
}
catch {
    Write-ErrorLog -Message "Framework prerequisite validation failed" -Module "Main" -ErrorRecord $_
    Write-Host "ERROR: System requirements not met - see log for details" -ForegroundColor Red
    $host.SetShouldExit($script:EXIT_ERROR_PREREQUISITES)
    exit $script:EXIT_ERROR_PREREQUISITES
}

if ($PSCmdlet.ParameterSetName -eq 'Restore') {
    if ($DryRun) {
        Write-Log -Level ERROR -Message 'DryRun cannot be combined with RestoreSessionPath' -Module 'Main'
        $host.SetShouldExit($script:EXIT_ERROR_CONFIG)
        exit $script:EXIT_ERROR_CONFIG
    }
    try {
        $resolvedRestoreSession = (Resolve-Path -LiteralPath $RestoreSessionPath -ErrorAction Stop).Path
        Write-Log -Level INFO -Message "Automated sealed-session restore requested: $resolvedRestoreSession" -Module 'Main'
        $restoreSucceeded = [bool](Restore-Session -SessionPath $resolvedRestoreSession -NoReboot)
        if ($restoreSucceeded) {
            Write-Host 'Restore completed and every sealed target verified.' -ForegroundColor Green
            $host.SetShouldExit($script:EXIT_SUCCESS)
            exit $script:EXIT_SUCCESS
        }
        Write-Host 'Restore failed or did not verify completely. Check the restore log.' -ForegroundColor Red
        $host.SetShouldExit($script:EXIT_ERROR_MODULE)
        exit $script:EXIT_ERROR_MODULE
    }
    catch {
        Write-ErrorLog -Message 'Automated sealed-session restore failed' -Module 'Main' -ErrorRecord $_
        $host.SetShouldExit($script:EXIT_ERROR_MODULE)
        exit $script:EXIT_ERROR_MODULE
    }
}

# Display banner
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NoID Privacy v$script:FrameworkVersion" -ForegroundColor Cyan
Write-Host "  Windows 11 Security Hardening" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY RUN MODE - No changes will be applied]" -ForegroundColor Yellow
    Write-Host ""
}

# Interactive menu or direct module execution
if (-not $Module -and -not $PSBoundParameters.ContainsKey('Modules')) {
    # Show interactive menu
    Write-Host "Available Actions:" -ForegroundColor White
    Write-Host ""
    Write-Host "  APPLY HARDENING:" -ForegroundColor Cyan
    Write-Host "  1. SecurityBaseline     - 25H2 baseline-derived profile (425 declared targets)" -ForegroundColor Green
    Write-Host "  2. ASR                  - Attack Surface Reduction (19 rules)" -ForegroundColor Green
    Write-Host "  3. DNS                  - Secure DNS with DoH (Quad9/Cloudflare/AdGuard)" -ForegroundColor Green
    Write-Host "  4. Privacy              - Telemetry & Privacy hardening (3 modes)" -ForegroundColor Green
    Write-Host "  5. AntiAI               - Reversible AI hardening (43 registry + 4 URI checks)" -ForegroundColor Green
    Write-Host "  6. EdgeHardening        - Secure Microsoft Edge browser" -ForegroundColor Green
    Write-Host "  7. AdvancedSecurity     - Legacy Protocol hardening, Windows Update, SRP (CVE-2025-9491)" -ForegroundColor Green
    Write-Host " 99. ALL MODULES (WIZARD) - Interactive setup for all modules" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  SYSTEM OPERATIONS:" -ForegroundColor Cyan
    Write-Host "  V. Verify Settings      - Four-state declared-scope verification" -ForegroundColor Magenta
    Write-Host "  R. Restore Backup       - Rollback to previous state" -ForegroundColor Yellow
    Write-Host "  B. List Backups         - Show all available backups" -ForegroundColor Gray
    Write-Host "  I. System Info          - Display system information" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  0. Exit" -ForegroundColor Red
    Write-Host ""

    do {
        Write-Host "Select option [1-7, 99, V, R, B, I, 0] (default: 99): " -ForegroundColor Yellow -NoNewline
        $selection = Read-Host
        if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "99" }
        $selection = $selection.ToUpperInvariant()

        if ($selection -notin @('1', '2', '3', '4', '5', '6', '7', '99', 'V', 'R', 'B', 'I', '0')) {
            Write-Host ""
            Write-Host "Invalid selection. Please choose from the menu." -ForegroundColor Red
            Write-Host ""
        }
    } while ($selection -notin @('1', '2', '3', '4', '5', '6', '7', '99', 'V', 'R', 'B', 'I', '0'))

    switch ($selection) {
        "1" { $Module = "SecurityBaseline" }
        "2" { $Module = "ASR" }
        "3" { $Module = "DNS" }
        "4" { $Module = "Privacy" }
        "5" { $Module = "AntiAI" }
        "6" { $Module = "EdgeHardening" }
        "7" { $Module = "AdvancedSecurity" }
        "99" { $Module = "All" }
        "V" {
            # Verify all settings
            Write-Host ""
            Write-Host "Running complete verification..." -ForegroundColor Cyan
            Write-Host ""

            $verifyScript = Join-Path $script:RootPath "Tools\Verify-Complete-Hardening.ps1"
            # Capture the pipeline so the raw True/False verdict is not printed;
            # the NOID_VERIFY_JSON contract line then decides an honest exit code
            # instead of the former unconditional success: failures exit as a
            # module error, unresolved uncertainty as a general error, and only
            # a clean run (every NotChecked a proven deliberate choice) exits 0.
            $verifyExitCode = $script:EXIT_ERROR_GENERAL
            if (Test-Path $verifyScript) {
                $verifyOutput = @(& $verifyScript)
                $verifyJsonLine = $verifyOutput |
                    Where-Object { $_ -is [string] -and ([string]$_).StartsWith('NOID_VERIFY_JSON=') } |
                    Select-Object -Last 1
                if ($verifyJsonLine) {
                    try {
                        $verifySummary = ([string]$verifyJsonLine).Substring('NOID_VERIFY_JSON='.Length) | ConvertFrom-Json
                        if ([int]$verifySummary.failed -gt 0) {
                            $verifyExitCode = $script:EXIT_ERROR_MODULE
                        }
                        elseif ([int]$verifySummary.notChecked -eq [int]$verifySummary.notCheckedDeliberate) {
                            $verifyExitCode = $script:EXIT_SUCCESS
                        }
                        else {
                            $verifyExitCode = $script:EXIT_ERROR_GENERAL
                        }
                    }
                    catch {
                        $verifyExitCode = $script:EXIT_ERROR_GENERAL
                    }
                }
            }
            else {
                Write-Host "ERROR: Verification script not found" -ForegroundColor Red
                $verifyExitCode = $script:EXIT_ERROR_CONFIG
            }

            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  Press any key to exit..." -ForegroundColor White
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $host.SetShouldExit($verifyExitCode)
            exit $verifyExitCode
        }
        "R" {
            # -DryRun printed "[DRY RUN MODE - No changes will be applied]" and then
            # let this branch perform a real, destructive restore: registry policies,
            # security template, audit policies, services and scheduled tasks
            # rewritten, Apply intent invalidated, a receipt published - and exit 0.
            # The -RestoreSessionPath parameter set already refuses the combination
            # (line 309); the menu must refuse it identically rather than break the
            # promise the banner just made.
            if ($DryRun) {
                Write-Host ""
                Write-Host "Restore cannot run in dry-run mode: a restore is a real, destructive operation" -ForegroundColor Red
                Write-Host "and NoID Privacy will not simulate one. Re-run without -DryRun to restore." -ForegroundColor Red
                Write-Host "Nothing was changed." -ForegroundColor Red
                Write-Log -Level ERROR -Message 'DryRun cannot be combined with the interactive Restore action' -Module 'Main'
                $host.SetShouldExit($script:EXIT_ERROR_CONFIG)
                exit $script:EXIT_ERROR_CONFIG
            }

            # Restore from backup - Interactive session selection from disk
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  RESTORE FROM BACKUP" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""

            # Get all backup sessions from disk
            try {
                $sessions = @(Get-BackupSessions)
            }
            catch {
                Write-Host "Backup directory could not be read. No files were changed." -ForegroundColor Red
                Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Red
                $host.SetShouldExit($script:EXIT_ERROR_GENERAL)
                exit $script:EXIT_ERROR_GENERAL
            }

            if ($sessions.Count -eq 0) {
                Write-Host "No backup sessions found." -ForegroundColor Yellow
                Write-Host "Backups are created when you apply hardening modules." -ForegroundColor Gray
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  Press any key to continue..." -ForegroundColor White
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                $host.SetShouldExit(0)
                exit 0
            }

            Write-Host "Available backup sessions:" -ForegroundColor White
            Write-Host ""

            $i = 1
            foreach ($session in $sessions) {
                $moduleNames = @($session.Modules | ForEach-Object { $_.name }) -join ", "
                if ([string]::IsNullOrWhiteSpace($moduleNames)) { $moduleNames = 'Unknown' }
                $dateStr = if ([DateTime]$session.Timestamp -eq [DateTime]::MinValue) {
                    'Unknown'
                }
                else {
                    ([DateTime]$session.Timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                }

                $statusColor = if ($session.Restorable) { 'Green' } else { 'Yellow' }
                Write-Host "  [$i] $($session.SessionId)" -ForegroundColor $statusColor
                Write-Host "      Created: $dateStr" -ForegroundColor Gray
                if (-not [string]::IsNullOrWhiteSpace([string]$session.DisplayName)) {
                    Write-Host "      Name: $($session.DisplayName)" -ForegroundColor Gray
                }
                Write-Host "      Modules: $moduleNames" -ForegroundColor Gray
                Write-Host "      Items: $($session.TotalItems)" -ForegroundColor Gray
                Write-Host "      Folder: $($session.FolderPath)" -ForegroundColor Gray
                if ($session.Restorable) {
                    Write-Host "      Status: SEALED + VALIDATED" -ForegroundColor Green
                    $restoreHistory = Get-SessionRestoreHistoryText -Session $session
                    if (-not [string]::IsNullOrWhiteSpace($restoreHistory)) {
                        Write-Host "              Last restored: $restoreHistory" -ForegroundColor DarkGray
                    }
                }
                else {
                    Write-Host "      Status: NOT RESTORABLE" -ForegroundColor Yellow
                    Write-Host "              $($session.ValidationError)" -ForegroundColor DarkGray
                }
                Write-Host ""
                $i++
            }

            Write-Host "  [0] Cancel and return" -ForegroundColor Red
            Write-Host ""

            do {
                Write-Host "Select session to restore [1-$($sessions.Count)] (0 = cancel): " -ForegroundColor Yellow -NoNewline
                $selection = Read-Host

                if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
                    Write-Host "Restore cancelled." -ForegroundColor Yellow
                    $host.SetShouldExit(0)
                    exit 0
                }

                $validSelection = $false
                $parsedIndex = 0
                if ([int]::TryParse($selection, [ref]$parsedIndex) -and
                    $parsedIndex -ge 1 -and $parsedIndex -le $sessions.Count) {
                    $validSelection = $true
                }

                if (-not $validSelection) {
                    Write-Host ""
                    Write-Host "Invalid input. Please enter a number between 1 and $($sessions.Count), or 0 to cancel." -ForegroundColor Red
                    Write-Host ""
                }
            } while (-not $validSelection)

            $selIndex = $parsedIndex - 1
            $selectedSession = $sessions[$selIndex]

            if (-not [bool]$selectedSession.Restorable) {
                Write-Host "This session is retained for visibility but cannot be restored." -ForegroundColor Red
                Write-Host "Reason: $($selectedSession.ValidationError)" -ForegroundColor Red
                $host.SetShouldExit($script:EXIT_ERROR_MODULE)
                exit $script:EXIT_ERROR_MODULE
            }

            Write-Host ""
            Write-Host "Restoring session: $($selectedSession.SessionId)" -ForegroundColor Cyan
            Write-Host ""

            # Call Restore-Session with the session path. The reboot prompt is
            # deferred: it must come AFTER the Tier-2 reinstall offer below,
            # otherwise an accepted reboot (default Y) would skip the offer.
            $success = Restore-Session -SessionPath $selectedSession.FolderPath -SuppressRebootPrompt

            if ($success) {
                Write-Host ""
                Write-Host "Restore completed successfully!" -ForegroundColor Green

                # Conservative fallback: if the manifest read below fails, still
                # prompt for reboot as if all restart-sensitive modules restored.
                $restoredModuleNamesForReboot = @('SecurityBaseline', 'AntiAI', 'AdvancedSecurity')

                # Restore-Session owns the shared Tier 2 reinstall offer so direct
                # callers and both interactive menus cannot drift apart. This
                # manifest read is only needed to scope the deferred reboot prompt.
                try {
                    $restoredManifest = Get-SessionManifest -SessionPath $selectedSession.FolderPath
                    $restoredModuleNamesForReboot = @($restoredManifest.modules | ForEach-Object { [string]$_.name })
                }
                catch {
                    Write-Host "Restored module list could not be read for the reboot prompt: $($_.Exception.Message)" -ForegroundColor Yellow
                }

                # Deferred reboot prompt: runs after the Tier-2 offer so an
                # accepted reboot can no longer swallow it.
                Invoke-RestoreRebootPrompt -Reasons @(Get-RestoreRebootReasons -ModuleNames $restoredModuleNamesForReboot)
            }
            else {
                Write-Host ""
                Write-Host "Restore completed with some errors. Check logs for details." -ForegroundColor Yellow
            }

            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  Press any key to exit..." -ForegroundColor White
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($success) {
                $host.SetShouldExit($script:EXIT_SUCCESS)
                exit $script:EXIT_SUCCESS
            }
            $host.SetShouldExit($script:EXIT_ERROR_MODULE)
            exit $script:EXIT_ERROR_MODULE
        }
        "B" {
            # List backups
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Available Backups" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""

            $backupPath = Join-Path $script:RootPath "Backups"
            if (Test-Path -LiteralPath $backupPath -PathType Container) {
                try {
                    $backups = @(Get-BackupSessions -BackupDirectory $backupPath)
                }
                catch {
                    Write-Host "  Backup directory could not be read. No files were changed." -ForegroundColor Red
                    Write-Host "  Folder: $backupPath" -ForegroundColor Gray
                    Write-Host "  Reason: $($_.Exception.Message)" -ForegroundColor Red
                    $host.SetShouldExit($script:EXIT_ERROR_GENERAL)
                    exit $script:EXIT_ERROR_GENERAL
                }

                if ($backups.Count -eq 0) {
                    Write-Host "  No backups found" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Found $($backups.Count) backup(s):" -ForegroundColor White
                    Write-Host ""

                    foreach ($backup in $backups) {
                        $statusColor = if ([bool]$backup.Restorable) { 'Green' } else { 'Yellow' }
                        $moduleNames = @($backup.Modules | ForEach-Object { [string]$_.name })
                        $moduleText = if ($moduleNames.Count -gt 0) { $moduleNames -join ', ' } else { 'Unknown' }
                        $createdText = if ([DateTime]$backup.Timestamp -eq [DateTime]::MinValue) {
                            'Unknown'
                        }
                        else {
                            ([DateTime]$backup.Timestamp).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                        }

                        Write-Host "  $($backup.DisplayName)" -ForegroundColor $statusColor
                        Write-Host "    Session ID: $($backup.SessionId)" -ForegroundColor Gray
                        Write-Host "    Created:    $createdText" -ForegroundColor Gray
                        Write-Host "    Status:     $($backup.ValidationStatus)" -ForegroundColor $statusColor
                        Write-Host "    Modules:    $moduleText" -ForegroundColor Gray
                        Write-Host "    Items:      $($backup.TotalItems)" -ForegroundColor Gray
                        Write-Host "    Folder:     $($backup.FolderPath)" -ForegroundColor Gray
                        $restoreHistory = Get-SessionRestoreHistoryText -Session $backup
                        if (-not [string]::IsNullOrWhiteSpace($restoreHistory)) {
                            Write-Host "    Restored:   $restoreHistory" -ForegroundColor Gray
                        }
                        if (-not [bool]$backup.Restorable) {
                            Write-Host "    Reason:     $($backup.ValidationError)" -ForegroundColor Yellow
                        }
                        Write-Host ""
                    }
                }
            }
            else {
                Write-Host "  Backup directory not found" -ForegroundColor Yellow
            }

            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  Press any key to exit..." -ForegroundColor White
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $host.SetShouldExit(0)
            exit 0
        }
        "I" {
            # System information
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  System Information" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""

            try {
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

                Write-Host "  Computer Name:     $($cs.Name)" -ForegroundColor White
                Write-Host "  OS Version:        $($os.Caption) Build $($os.BuildNumber)" -ForegroundColor White
                Write-Host "  PowerShell:        $($PSVersionTable.PSVersion)" -ForegroundColor White
                Write-Host "  Domain Joined:     $(if ($cs.PartOfDomain) { 'Yes' } else { 'No (Standalone)' })" -ForegroundColor White

                Write-Host ""
                Write-Host "  Security Status:" -ForegroundColor Yellow

                # Check VBS
                try {
                    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
                    if (-not $vbs) { throw 'Win32_DeviceGuard returned no result' }
                    Write-Host "    VBS Enabled:     $(if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { 'Green' } else { 'Red' })
                }
                catch { Write-Host '    VBS Enabled:     Unknown' -ForegroundColor Yellow }

                # Check Defender
                try {
                    $defender = Get-MpComputerStatus -ErrorAction Stop
                    if (-not $defender) { throw 'Get-MpComputerStatus returned no result' }
                    Write-Host "    Defender Active: $(if ($defender.AntivirusEnabled) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($defender.AntivirusEnabled) { 'Green' } else { 'Red' })
                }
                catch { Write-Host '    Defender Active: Unknown' -ForegroundColor Yellow }
            }
            catch {
                Write-Host "  Failed to retrieve system information" -ForegroundColor Red
            }

            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "  Press any key to exit..." -ForegroundColor White
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host ""
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $host.SetShouldExit(0)
            exit 0
        }
        "0" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            $host.SetShouldExit(0)
            exit 0
        }
    }
}

# Execute selected module(s)
try {
    $multipleModulesRequested = $PSBoundParameters.ContainsKey('Modules')
    $selectionDescription = if ($multipleModulesRequested) { $Modules -join ', ' } else { $Module }
    Write-Log -Level INFO -Message "Starting module execution: $selectionDescription" -Module "Main"

    $result = if ($multipleModulesRequested) {
        Invoke-Hardening -Modules $Modules -DryRun:$DryRun
    }
    else {
        Invoke-Hardening -Module $Module -DryRun:$DryRun
    }

    # Reject pipeline contamination. Choosing the last object could turn an
    # earlier error/log object into a false successful framework result.
    if ($result -is [array]) {
        throw "Invoke-Hardening returned $($result.Count) pipeline objects instead of exactly one structured result"
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
        Write-Host "Duration: $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -ForegroundColor White
    }
    elseif ($result.ModulesSkipped -gt 0 -and $result.Errors.Count -eq 0 -and
            [int]$result.ModulesExecuted -eq 0 -and [int]$result.TotalSettingsApplied -eq 0) {
        # A skip is fail-closed by contract (Success=false, module exit code),
        # but announcing it as FAILED with zero errors reads like a defect.
        # Only claim "nothing was applied" when nothing actually was.
        Write-Host "Status: SKIPPED" -ForegroundColor Yellow
        Write-Host "Modules Skipped: $($result.ModulesSkipped) (disabled in configuration or not selected; nothing was applied)" -ForegroundColor Yellow
    }
    elseif ($result.ModulesSkipped -gt 0 -and $result.Errors.Count -eq 0) {
        # Some modules self-skip without erroring - ASR does this whenever
        # Defender is not the proven primary engine. The old SKIPPED branch then
        # printed "nothing was applied" for a run that had changed hundreds of
        # settings and sealed a rollback session, so the operator neither rebooted
        # nor knew a restore point existed. Name both halves.
        Write-Host "Status: PARTIAL" -ForegroundColor Yellow
        Write-Host "Modules Executed: $($result.ModulesExecuted)" -ForegroundColor White
        Write-Host "Settings Applied: $($result.TotalSettingsApplied)" -ForegroundColor White
        Write-Host "Modules Skipped: $($result.ModulesSkipped) (disabled in configuration, not selected, or self-skipped without error)" -ForegroundColor Yellow
        Write-Host "Duration: $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -ForegroundColor White
        if (-not [string]::IsNullOrWhiteSpace([string]$result.BackupPath)) {
            Write-Host "Rollback session: $($result.BackupPath)" -ForegroundColor White
        }
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

    if ($result.WarningsLogged -gt 0) {
        Write-Host ""
        Write-Host "Warnings: $($result.WarningsLogged)" -ForegroundColor Yellow
        Write-Host "  Full details appear in the warning lines above and in the run log." -ForegroundColor DarkGray
    }

    # Stable, single-line GUI contract. Human log wording is deliberately not an
    # API: the commercial wrapper parses only this closed summary object and
    # requires it to agree with the process exit code.
    if ([string]$script:ConfigPayloadSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Effective configuration fingerprint is unavailable; refusing to emit an unbound result contract'
    }
    $guiResult = [ordered]@{
        schemaVersion        = 2
        configSha256         = [string]$script:ConfigPayloadSha256
        success              = [bool]$result.Success
        status               = [string]$result.Status
        totalSettingsApplied = [int]$result.TotalSettingsApplied
        modulesExecuted      = [int]$result.ModulesExecuted
        modulesSkipped       = [int]$result.ModulesSkipped
        modulesFailed        = [int]$result.ModulesFailed
        backupPath           = [string]$result.BackupPath
        modules              = @($result.ModuleResults | ForEach-Object {
            $isObjectResult = $_ -is [PSCustomObject]
            [ordered]@{
                name         = if ($isObjectResult -and $_.PSObject.Properties['ModuleName']) { [string]$_.ModuleName } else { 'Unknown' }
                success      = if ($isObjectResult -and $_.PSObject.Properties['Success']) { [bool]$_.Success } else { $false }
                status       = if ($isObjectResult -and $_.PSObject.Properties['Status']) { [string]$_.Status } else { 'Failed' }
                appliedCount = if ($isObjectResult -and $_.PSObject.Properties['AppliedSettingsCount']) { [int]$_.AppliedSettingsCount } else { 0 }
            }
        })
    }
    Write-Output ("NOID_RESULT_JSON=" + ($guiResult | ConvertTo-Json -Compress -Depth 5))

    Write-Host ""
    Write-Host "Log file: $(Get-LogFilePath)" -ForegroundColor Cyan
    Write-Host ""

    if ($result.Success) {
        Write-Log -Level SUCCESS -Message "Framework execution completed successfully" -Module "Main"

        # Reboot status is an explicit module result, never inferred from the
        # requested module name (a skipped/no-op module must not force exit 10).
        $needsReboot = $false
        foreach ($moduleResult in @($result.ModuleResults)) {
            if ($moduleResult -isnot [PSCustomObject]) { continue }
            if (($moduleResult.PSObject.Properties['RequiresReboot'] -and [bool]$moduleResult.RequiresReboot) -or
                ($moduleResult.PSObject.Properties['RebootRequired'] -and [bool]$moduleResult.RebootRequired)) {
                $needsReboot = $true
                break
            }
        }

        if ($needsReboot -and -not $DryRun) {
            Write-Host ""
            Write-Host "NOTE: A system reboot is recommended for all changes to take effect." -ForegroundColor Yellow
            $host.SetShouldExit($script:EXIT_SUCCESS_REBOOT)
            exit $script:EXIT_SUCCESS_REBOOT
        }
        else {
            $host.SetShouldExit($script:EXIT_SUCCESS)
            exit $script:EXIT_SUCCESS
        }
    }
    else {
        Write-Log -Level ERROR -Message "Framework execution completed with errors" -Module "Main"
        $host.SetShouldExit($script:EXIT_ERROR_MODULE)
        exit $script:EXIT_ERROR_MODULE
    }
}
catch {
    Write-ErrorLog -Message "Fatal error during framework execution" -Module "Main" -ErrorRecord $_
    Write-Host ""
    Write-Host "FATAL ERROR: Unexpected exception during execution" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    $host.SetShouldExit($script:EXIT_ERROR_FATAL)
    exit $script:EXIT_ERROR_FATAL
}
