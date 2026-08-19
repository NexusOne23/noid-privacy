<#
.SYNOPSIS
    NoID Privacy - Interactive Menu Interface

.DESCRIPTION
    User-friendly interactive menu for Windows 11 security hardening with:
    - Visual menu navigation
    - Clear status feedback
    - Automatic backups before changes
    - Easy restore and verification
    - Guided workflow
.LINK
    https://github.com/NexusOne23/noid-privacy

.NOTES
    DISCLAIMER:
    This software is provided "as is" without warranty of any kind.
    By using this software, you agree that the authors are not liable for any damages
    resulting from its use. USE AT YOUR OWN RISK.

    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+, Administrator
    For CLI mode use: NoIDPrivacy.ps1 -Module <name>
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# No parameters - interactive mode only

$ErrorActionPreference = 'Stop'

# Set script root path (required by modules to load configs)
$script:RootPath = $PSScriptRoot
$versionFile = Join-Path $script:RootPath 'VERSION'
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    throw "Canonical VERSION file is missing: $versionFile"
}
$script:FrameworkVersion = (Get-Content -LiteralPath $versionFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
if ($script:FrameworkVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "Canonical VERSION value is invalid: '$script:FrameworkVersion'"
}
$Host.UI.RawUI.WindowTitle = "NoID Privacy v$script:FrameworkVersion"

# ============================================================================
# COLOR FUNCTIONS
# ============================================================================

function Write-ColorText {
    param(
        [string]$Text,
        [string]$Color = 'White',
        [switch]$NoNewline
    )

    # Honour the cross-platform NO_COLOR convention (https://no-color.org) so users in
    # logging shells / CI can disable ANSI colour without touching the script.
    if ($env:NO_COLOR) {
        if ($NoNewline) { Write-Host $Text -NoNewline }
        else { Write-Host $Text }
    }
    else {
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else { Write-Host $Text -ForegroundColor $Color }
    }
}

function Write-Header {
    param([string]$Text)

    Write-Host ""
    Write-ColorText "====================================================================" -Color Cyan
    # Pad the header text so it fully overwrites any residual characters on the console line
    Write-ColorText ("  $Text".PadRight(68)) -Color Cyan
    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""
}

function Write-Step {
    param(
        [string]$Text,
        [string]$Status = "INFO"
    )

    $symbol = switch ($Status) {
        "SUCCESS" { "[+]"; $color = "Green" }
        "ERROR" { "[-]"; $color = "Red" }
        "WARNING" { "[!]"; $color = "Yellow" }
        "INFO" { "[>]"; $color = "Cyan" }
        "WAIT" { "[.]"; $color = "Gray" }
        default { "[ ]"; $color = "White" }
    }

    Write-ColorText $symbol -Color $color -NoNewline
    Write-Host " $Text"
}

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "    ========================================" -ForegroundColor Cyan
    Write-Host "         NoID Privacy v$script:FrameworkVersion          " -ForegroundColor Cyan
    Write-Host "    ========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Professional Windows 11 Security & Privacy Hardening Framework" -ForegroundColor Gray
    # Dynamic environment line: canonical product version plus live environment.
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        $os = $null
    }

    $osBuild = if ($os) { $os.BuildNumber } else { $null }
    $psVersion = $PSVersionTable.PSVersion.ToString()

    $envLine = if ($osBuild) {
        "    Windows Build $osBuild"
    }
    else {
        "    Windows build Unknown"
    }
    $envLine += " | PowerShell $psVersion"

    Write-Host $envLine -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# PROGRESS FUNCTIONS
# ============================================================================

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )

    if (-not $env:NOIDPRIVACY_QUIET) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

function Show-ModuleProgress {
    param(
        [string]$Module,
        [int]$Current,
        [int]$Total,
        [string]$Status = "Processing"
    )

    $percent = [math]::Round(($Current / $Total) * 100)
    Show-Progress -Activity "Applying $Module" -Status "$Status ($Current/$Total)" -PercentComplete $percent
}

# ============================================================================
# SYSTEM INFO FUNCTION
# ============================================================================

function Show-SystemInfo {
    Write-Header "SYSTEM INFORMATION"

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

        Write-ColorText "  Computer Name:    " -Color Gray -NoNewline
        Write-ColorText $cs.Name -Color White

        Write-ColorText "  OS Version:       " -Color Gray -NoNewline
        Write-ColorText "$($os.Caption) Build $($os.BuildNumber)" -Color White

        Write-ColorText "  PowerShell:       " -Color Gray -NoNewline
        Write-ColorText "$($PSVersionTable.PSVersion)" -Color White

        Write-ColorText "  Administrator:    " -Color Gray -NoNewline
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $adminStatus = if ($isAdmin) { "Yes [+]" } else { "No [-]" }
        $adminColor = if ($isAdmin) { "Green" } else { "Red" }
        Write-ColorText $adminStatus -Color $adminColor

        Write-ColorText "  Domain Joined:    " -Color Gray -NoNewline
        $isDomain = $cs.PartOfDomain
        $domainStatus = if ($isDomain) { "Yes" } else { "No (Standalone)" }
        $domainColor = if ($isDomain) { "Yellow" } else { "Cyan" }
        Write-ColorText $domainStatus -Color $domainColor

        Write-Host ""

        # Security Status
        Write-ColorText "  Security Status:" -Color Yellow

        # Check VBS
        try {
            $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            if (-not $vbs) { throw 'Win32_DeviceGuard returned no result' }
            Write-ColorText "    VBS Enabled:     " -Color Gray -NoNewline
            $vbsStatus = if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { "Yes [+]" } else { "No [-]" }
            $vbsColor = if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { "Green" } else { "Red" }
            Write-ColorText $vbsStatus -Color $vbsColor
        }
        catch {
            # VBS status could not be determined - not critical for menu display
            Write-ColorText "    VBS Enabled:     " -Color Gray -NoNewline
            Write-ColorText "Unknown" -Color Yellow
        }

        # Check Defender
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            if (-not $defender) { throw 'Get-MpComputerStatus returned no result' }
            Write-ColorText "    Defender Active: " -Color Gray -NoNewline
            $defenderStatus = if ($defender.AntivirusEnabled) { "Yes [+]" } else { "No [-]" }
            $defenderColor = if ($defender.AntivirusEnabled) { "Green" } else { "Red" }
            Write-ColorText $defenderStatus -Color $defenderColor
        }
        catch {
            # Defender status could not be determined - not critical for menu display
            Write-ColorText "    Defender Active: " -Color Gray -NoNewline
            Write-ColorText "Unknown" -Color Yellow
        }

        Write-Host ""
    }
    catch {
        Write-Step "Failed to retrieve system information" -Status ERROR
    }

    Write-Host ""
    Write-ColorText "====================================================================" -Color Cyan
    Write-ColorText "  Press any key to return to the main menu..." -Color White
    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
}

# ============================================================================
# REBOOT PROMPT FUNCTION
# ============================================================================

function Invoke-RebootPrompt {
    <#
    .SYNOPSIS
        Prompts user for system reboot with countdown

    .NOTES
        Hardening-only. Restore flows use Invoke-RestoreRebootPrompt
        (Core/Rollback.ps1) with Get-RestoreRebootReasons instead.
    #>
    param()

    Write-Host ""
    Write-ColorText "====================================================================" -Color Cyan
    Write-ColorText "  SYSTEM REBOOT RECOMMENDED" -Color Yellow
    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""

    Write-ColorText "  The applied security changes require a system reboot to take full effect." -Color White
    Write-Host ""
    Write-ColorText "  Changes that may require reboot:" -Color Gray
    Write-Host ""
    Write-ColorText "    - Registry Policies" -Color Yellow -NoNewline
    Write-ColorText " (Security settings and configurations)" -Color Gray
    Write-ColorText "    - Windows Services" -Color Yellow -NoNewline
    Write-ColorText " (Startup type and state changes)" -Color Gray
    Write-ColorText "    - Windows Features" -Color Yellow -NoNewline
    Write-ColorText " (selected optional components)" -Color Gray
    Write-ColorText "    - Network Settings" -Color Yellow -NoNewline
    Write-ColorText " (Admin Shares, NetBIOS, Firewall rules)" -Color Gray
    Write-Host ""
    Write-ColorText "  Immediate state was verified; restart-dependent Windows components" -Color Gray
    Write-ColorText "  can take effect only after reboot and must be checked again afterward." -Color White
    Write-Host ""
    Write-Host ""
    Write-ColorText "  To verify full compliance after reboot, run:" -Color White
    Write-ColorText "    .\Tools\Verify-Complete-Hardening.ps1" -Color Cyan

    Write-Host ""
    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""

    Write-ColorText "  [Y] YES - Reboot now (Recommended)" -Color Green
    Write-ColorText "      - Restart-dependent changes take effect immediately" -Color Gray
    Write-Host ""
    Write-ColorText "  [N] NO - Reboot later" -Color Cyan
    Write-ColorText "      - Restart-dependent changes stay inactive until the next reboot" -Color Gray
    Write-Host ""

    # Prompt user with validation loop
    do {
        Write-ColorText "  Reboot now? [Y/N] (default: Y): " -Color Yellow -NoNewline
        $choice = Read-Host
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "Y" }
        $choice = $choice.Trim().ToUpperInvariant()

        if ($choice -notin @('Y', 'N')) {
            Write-Host ""
            Write-ColorText "  Invalid input. Please enter Y or N." -Color Red
            Write-Host ""
        }
    } while ($choice -notin @('Y', 'N'))

    if ($choice -eq 'Y') {
        Write-Host ""
        Write-Step "Initiating system reboot in 10 seconds..." -Status WARNING
        Write-ColorText "  Press Ctrl+C to cancel" -Color Gray
        Write-Host ""

        # Countdown from 10
        for ($i = 10; $i -gt 0; $i--) {
            Write-ColorText "    Rebooting in $i seconds..." -Color Yellow
            Start-Sleep -Seconds 1
        }

        Write-Host ""
        Write-Step "Rebooting system now..." -Status SUCCESS
        Write-Host ""

        # Reboot
        Restart-Computer -Force
    }
    else {
        Write-Host ""
        Write-Step "Reboot deferred" -Status WARNING
        Write-Host ""
        Write-ColorText "  IMPORTANT: Please reboot manually at your earliest convenience." -Color White
        Write-ColorText "  Restart-dependent changes are not yet proven effective." -Color Gray
        Write-Host ""

        Write-ColorText "  To verify after reboot, run:" -Color White
        Write-ColorText "    .\Tools\Verify-Complete-Hardening.ps1" -Color Cyan
        Write-Host ""
    }
}

# ============================================================================
# BACKUP LIST FUNCTION
# ============================================================================

function Show-BackupList {
    Write-Header "AVAILABLE BACKUP SESSIONS"

    $backupPath = Join-Path $PSScriptRoot "Backups"

    # Get sessions using new Rollback.ps1 function
    try {
        # Force result to array to handle single-session case correctly
        if (Test-Path $backupPath) {
            $sessions = @(Get-BackupSessions -BackupDirectory $backupPath)
        }
        else {
            $sessions = @()
        }
    }
    catch {
        Write-Step "Failed to load backup sessions: $_" -Status ERROR
        Write-Host ""
        return $null
    }

    # Single check for no sessions (whether folder doesn't exist or is empty)
    if ($sessions.Count -eq 0) {
        Write-Step "No backup sessions found" -Status WARNING
        Write-Host ""
        return $null
    }

    Write-ColorText "  Found $($sessions.Count) backup session(s):" -Color Cyan
    Write-Host ""

    for ($i = 0; $i -lt $sessions.Count; $i++) {
        $session = $sessions[$i]

        try {
            $age = (Get-Date) - $session.Timestamp
            $ageStr = if ($age.TotalHours -lt 1) { "$([math]::Round($age.TotalMinutes)) minutes ago" }
            elseif ($age.TotalDays -lt 1) { "$([math]::Round($age.TotalHours)) hours ago" }
            else { "$([math]::Round($age.TotalDays)) days ago" }
        }
        catch {
            $ageStr = "unknown age"
        }

        Write-ColorText "  [$($i+1)] " -Color Yellow -NoNewline
        Write-ColorText "$($session.SessionId)" -Color White -NoNewline
        Write-ColorText " ($ageStr)" -Color Gray

        if (-not [string]::IsNullOrWhiteSpace([string]$session.DisplayName)) {
            Write-ColorText "      " -Color Gray -NoNewline
            Write-ColorText "> Name: " -Color DarkGray -NoNewline
            Write-ColorText ([string]$session.DisplayName) -Color White
        }

        Write-ColorText "      " -Color Gray -NoNewline
        Write-ColorText "> Status: " -Color DarkGray -NoNewline
        if ([bool]$session.Restorable) {
            Write-ColorText "SEALED + VALIDATED" -Color Green
            $restoreHistory = Get-SessionRestoreHistoryText -Session $session
            if (-not [string]::IsNullOrWhiteSpace($restoreHistory)) {
                Write-ColorText "      " -Color Gray -NoNewline
                Write-ColorText "> Last restored: " -Color DarkGray -NoNewline
                Write-ColorText $restoreHistory -Color Gray
            }
        }
        else {
            Write-ColorText "NOT RESTORABLE" -Color Yellow
            Write-ColorText "        $($session.ValidationError)" -Color DarkGray
        }

        Write-ColorText "      " -Color Gray -NoNewline
        Write-ColorText "> Modules: " -Color DarkGray -NoNewline
        if ($session.Modules -and $session.Modules.Count -gt 0) {
            Write-ColorText ($session.Modules.name -join ", ") -Color Cyan
        }
        else {
            Write-ColorText "No modules" -Color DarkGray
        }

        Write-ColorText "      " -Color Gray -NoNewline
        Write-ColorText "> Total Items: " -Color DarkGray -NoNewline
        Write-ColorText "$($session.TotalItems)" -Color Green

        Write-Host ""
    }

    Write-Host ""

    # Ensure we return an array (even for single item)
    return @($sessions)
}

# ============================================================================
# MAIN MENU
# ============================================================================

function Show-MainMenu {
    Write-Banner
    Write-Header "MAIN MENU"

    Write-ColorText "  [A]" -Color Green -NoNewline
    Write-Host " Apply Security Hardening"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Automatic backup before changes" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Four-state declared-scope verification" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Detailed progress tracking" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [V]" -Color Cyan -NoNewline
    Write-Host " Verify Current Settings"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Verified / Failed / NotChecked / NotApplicable" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Detailed compliance report" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [R]" -Color Yellow -NoNewline
    Write-Host " Restore from Backup"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Rollback to previous state" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Restore sealed NoID Privacy-owned pre-state" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [I]" -Color Magenta -NoNewline
    Write-Host " System Information"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> OS, Build, Security Status" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [X]" -Color Red -NoNewline
    Write-Host " Exit"
    Write-Host ""

    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""
    Write-ColorText "  Select [A/V/R/I/X]: " -Color Yellow -NoNewline
}

# ============================================================================
# MODULE SELECTION MENU
# ============================================================================

function Show-ModuleMenu {
    Write-Banner
    Write-Header "SELECT MODULES TO APPLY"

    # Module definitions with descriptions
    $moduleDefinitions = @{
        "SecurityBaseline" = "Microsoft Security Baseline (425 settings)"
        "ASR"              = "Attack Surface Reduction (19 rules)"
        "DNS"              = "Secure DNS with DoH (Quad9/Cloudflare/AdGuard)"
        "Privacy"          = "Telemetry & Privacy hardening (3 modes)"
        "AntiAI"           = "Reversible Windows AI hardening (43 registry + 4 URI checks, 12 groups)"
        "EdgeHardening"    = "Secure Microsoft Edge (19 v139 baseline + 7 privacy values)"
        "AdvancedSecurity" = "Beyond MS Baseline (60 declared checks, 14 features)"
    }

    # Try to load config.json to check module status
    $configPath = Join-Path $PSScriptRoot "config.json"
    $config = $null
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
        }
        catch {
            # If config fails to load, all modules default to enabled
            Write-Verbose "config.json load failed (defaulting all modules to enabled): $($_.Exception.Message)"
        }
    }

    # Build module list with status from config
    $modules = @(
        [PSCustomObject]@{ Key = "1"; Name = "SecurityBaseline"; Description = $moduleDefinitions["SecurityBaseline"]; Enabled = $true }
        [PSCustomObject]@{ Key = "2"; Name = "ASR"; Description = $moduleDefinitions["ASR"]; Enabled = $true }
        [PSCustomObject]@{ Key = "3"; Name = "DNS"; Description = $moduleDefinitions["DNS"]; Enabled = $true }
        [PSCustomObject]@{ Key = "4"; Name = "Privacy"; Description = $moduleDefinitions["Privacy"]; Enabled = $true }
        [PSCustomObject]@{ Key = "5"; Name = "AntiAI"; Description = $moduleDefinitions["AntiAI"]; Enabled = $true }
        [PSCustomObject]@{ Key = "6"; Name = "EdgeHardening"; Description = $moduleDefinitions["EdgeHardening"]; Enabled = $true }
        [PSCustomObject]@{ Key = "7"; Name = "AdvancedSecurity"; Description = $moduleDefinitions["AdvancedSecurity"]; Enabled = $true }
    )

    # Override enabled status from config.json if available
    if ($config -and $config.modules) {
        foreach ($module in $modules) {
            $configModule = $config.modules.PSObject.Properties[$module.Name]
            if ($configModule -and $configModule.Value.PSObject.Properties['enabled']) {
                $module.Enabled = [bool]$configModule.Value.enabled
            }
        }
    }

    foreach ($module in $modules) {
        if ($module.Enabled) {
            Write-ColorText "  [$($module.Key)]" -Color Green -NoNewline
        }
        else {
            Write-ColorText "  [$($module.Key)]" -Color DarkGray -NoNewline
        }

        Write-Host " $($module.Name)"
        Write-ColorText "      " -Color Gray -NoNewline

        if ($module.Enabled) {
            Write-ColorText "> $($module.Description)" -Color White
        }
        else {
            Write-ColorText "> $($module.Description) " -Color DarkGray -NoNewline
            # Every module in this list ships and works. The only reason one is
            # greyed out here is that config.json switched it off, so name that
            # cause: "(Not yet implemented)" told users the flagship module did
            # not exist in this build and left them no way to find the setting.
            Write-ColorText "(disabled in config.json - set modules.$($module.Name).enabled = true to run it)" -Color DarkYellow
        }
    }

    Write-Host ""
    Write-ColorText "  [99]" -Color Yellow -NoNewline
    Write-Host " ALL MODULES (WIZARD) - Interactive setup for all modules"
    Write-Host ""
    Write-ColorText "  [0]" -Color Red -NoNewline
    Write-Host " Back to Main Menu"
    Write-Host ""

    Write-ColorText "====================================================================" -Color Cyan
    Write-Host ""
    Write-ColorText "  Select module [1-7, 99, 0]: " -Color Yellow -NoNewline

    return $modules
}

# ============================================================================
# APPLY HARDENING WORKFLOW
# ============================================================================

function Invoke-HardeningWorkflow {
    param([string[]]$SelectedModules)

    Write-Banner
    Write-Header "SECURITY HARDENING WORKFLOW"

    # Phase 1: Pre-flight checks
    Write-Step "Running pre-flight checks..." -Status INFO

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Step "Administrator privileges required" -Status ERROR
        return
    }
    Write-Step "Administrator privileges confirmed" -Status SUCCESS

    # Phase 2: Call real Framework
    Write-Host ""
    Write-Step "Initializing NoID Privacy Framework..." -Status INFO
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Automatic backup will be created before changes" -Color DarkGray
    Write-Host ""

    try {
        # Determine which modules to execute - ensure proper string array
        [string[]]$modulesToRun = @($SelectedModules)

        # Debug output to verify correct module names
        Write-Step "Modules to apply: $($modulesToRun -join ', ')" -Status INFO

        # Call the real framework via NoIDPrivacy.ps1
        $frameworkScript = Join-Path $PSScriptRoot "NoIDPrivacy.ps1"

        if (-not (Test-Path $frameworkScript)) {
            Write-Step "Framework script not found: $frameworkScript" -Status ERROR
            return
        }

        # Execute framework (always with verbose logging for full support trace)
        Write-Step "Executing hardening modules..." -Status INFO
        Write-Host ""

        $allSucceeded = $true

        # FIX: Call framework ONCE with all modules instead of separate calls
        # This ensures single backup session and single log file
        # Exit code handling: 0 = Success, 10 = Success with Reboot recommended
        # Any other code indicates failure
        $rebootRecommended = $false

        if ($modulesToRun.Count -eq 7) {
            # All modules selected - use "All" for single unified session
            Write-Step "Running ALL modules in unified session..." -Status INFO
            & $frameworkScript -Module All -VerboseLogging
            if ($LASTEXITCODE -eq 10) {
                $rebootRecommended = $true
            }
            elseif ($LASTEXITCODE -ne 0) {
                $allSucceeded = $false
            }
        }
        elseif ($modulesToRun.Count -eq 1) {
            # Single module
            Write-Step "Running module: $($modulesToRun[0])" -Status INFO
            & $frameworkScript -Module $modulesToRun[0] -VerboseLogging
            if ($LASTEXITCODE -eq 10) {
                $rebootRecommended = $true
            }
            elseif ($LASTEXITCODE -ne 0) {
                $allSucceeded = $false
            }
        }
        else {
            # One process means one sealed BAVR session, one manifest and one log
            # for the complete selected set. The aggregate exit code remains the
            # authority for success/reboot status.
            Write-Step "Running selected modules in one unified session..." -Status INFO
            & $frameworkScript -Modules $modulesToRun -VerboseLogging
            if ($LASTEXITCODE -eq 10) {
                $rebootRecommended = $true
            }
            elseif ($LASTEXITCODE -ne 0) {
                $allSucceeded = $false
            }
        }
        Write-Host ""

        # Display results
        Write-Host ""
        Write-Header "HARDENING COMPLETE"

        if ($allSucceeded) {
            Write-ColorText "  Status:           " -Color Gray -NoNewline
            Write-ColorText "SUCCESS [+]" -Color Green
        }
        else {
            Write-ColorText "  Status:           " -Color Gray -NoNewline
            Write-ColorText "FAILED [-]" -Color Red
        }

        Write-ColorText "  Modules Selected: " -Color Gray -NoNewline
        Write-ColorText "$($modulesToRun.Count)" -Color White
        Write-ColorText "  (Check output above for actual results per module)" -Color DarkGray

        Write-Host ""

        if ($allSucceeded) {
            Write-ColorText "  Selected hardening modules applied successfully." -Color Green
            Write-ColorText "  Run Tools\Verify-Complete-Hardening.ps1 to confirm the applied settings." -Color Gray
            if ($rebootRecommended) {
                Write-ColorText "  A system reboot is recommended for all changes to take effect." -Color Yellow
            }
        }
        else {
            Write-ColorText "  One or more modules failed, were incomplete, or were skipped. Check details above." -Color Yellow
            Write-ColorText "  Review the log file for complete details." -Color White
        }

        Write-Host ""

        # Success alone must not create a reboot prompt. Exit code 10 is emitted
        # only from explicit restart-sensitive module results.
        if ($rebootRecommended) {
            Invoke-RebootPrompt
        }

        Write-Host ""
    }
    catch {
        Write-Host ""
        Write-Step "Fatal error: $($_.Exception.Message)" -Status ERROR
        Write-Host ""
    }
}

# ============================================================================
# VERIFY WORKFLOW
# ============================================================================

function Invoke-VerifyWorkflow {
    Write-Banner
    Write-Header "SETTINGS VERIFICATION"

    Write-Step "Running comprehensive verification..." -Status INFO
    Write-Host ""

    try {
        # Call the real verification script
        $verifyScript = Join-Path $PSScriptRoot "Tools\Verify-Complete-Hardening.ps1"

        if (Test-Path $verifyScript) {
            # Discard return value so that 'True' / 'False' is not printed to console
            $null = & $verifyScript
        }
        else {
            Write-Step "Verification script not found: $verifyScript" -Status ERROR
        }
    }
    catch {
        Write-Step "Verification failed: $($_.Exception.Message)" -Status ERROR
    }

    Write-Host ""
}

# ============================================================================
# RESTORE WORKFLOW
# ============================================================================

function Invoke-RestoreWorkflow {
    $sessions = Show-BackupList

    # Show-BackupList already displays warning if no sessions found
    if (-not $sessions -or $sessions.Count -eq 0) {
        Start-Sleep -Seconds 2
        return
    }

    # Force as array to ensure Count property exists
    $sessions = @($sessions)

    do {
        Write-ColorText "  Enter session number to restore [1-$($sessions.Count)] (0 = cancel): " -Color Yellow -NoNewline
        $selection = Read-Host

        # Trim whitespace
        $selection = $selection.Trim()

        if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
            return
        }

        $validSelection = $false
        $parsedSelection = 0
        if ([int]::TryParse($selection, [ref]$parsedSelection) -and
            $parsedSelection -ge 1 -and $parsedSelection -le $sessions.Count) {
            $validSelection = $true
        }

        if (-not $validSelection) {
            Write-Host ""
            Write-ColorText "  Invalid input. Please enter a number between 1 and $($sessions.Count), or 0 to cancel." -Color Red
            Write-Host ""
        }
    } while (-not $validSelection)

    $index = $parsedSelection - 1
    $selectedSession = $sessions[$index]

    if (-not [bool]$selectedSession.Restorable) {
        Write-Step "This session is retained for visibility but cannot be restored: $($selectedSession.ValidationError)" -Status ERROR
        Start-Sleep -Seconds 2
        return
    }

    # Determine available modules in this session
    $availableModules = @()
    if ($selectedSession.Modules) {
        $availableModules = @($selectedSession.Modules)
    }

    $restoreMode = "A"       # A = All modules, M = Selected modules
    $selectedModuleNames = @()

    if ($availableModules.Count -gt 0) {
        Write-Host ""
        Write-Header "RESTORE MODE"

        Write-ColorText "  Session contains the following modules:" -Color Yellow
        Write-Host ""
        for ($m = 0; $m -lt $availableModules.Count; $m++) {
            $mod = $availableModules[$m]
            Write-ColorText "  [$($m+1)] " -Color Cyan -NoNewline
            Write-ColorText "$($mod.name)" -Color White
        }
        Write-Host ""

        # Restore mode selection - options shown once, before the loop
        Write-ColorText "  [A] Restore ALL modules in this session (Recommended)" -Color Green
        Write-ColorText "  [M] Restore only SELECTED modules from this session" -Color Cyan
        Write-Host ""

        do {
            Write-ColorText "  Select restore mode [A/M] (default: A): " -Color Yellow -NoNewline
            $modeInput = Read-Host
            if ([string]::IsNullOrWhiteSpace($modeInput)) { $modeInput = "A" }
            $modeInput = $modeInput.Trim().ToUpperInvariant()

            if ($modeInput -in @('A', 'M')) {
                $restoreMode = $modeInput
                break
            }
            Write-Host ""
            Write-ColorText "  Invalid input. Please enter A or M." -Color Red
            Write-Host ""
        } while ($true)

        # If user chose module selection, ask for specific modules
        if ($restoreMode -eq 'M') {
            Write-Host ""
            $indices = @()
            do {
                Write-ColorText "  Enter module numbers to restore [1-$($availableModules.Count), e.g. 1,3,5] (0 = cancel): " -Color Yellow -NoNewline
                $moduleInput = Read-Host
                $moduleInput = $moduleInput.Trim()

                if ([string]::IsNullOrWhiteSpace($moduleInput) -or $moduleInput -eq '0') {
                    Write-Step "Restore cancelled" -Status WARNING
                    Start-Sleep -Seconds 1
                    return
                }

                $indices = @()
                foreach ($token in ($moduleInput -split '[,; ]')) {
                    if (-not [string]::IsNullOrWhiteSpace($token)) {
                        $parsed = 0
                        if ([int]::TryParse($token.Trim(), [ref]$parsed)) {
                            if ($parsed -ge 1 -and $parsed -le $availableModules.Count) {
                                $indices += $parsed
                            }
                        }
                    }
                }

                $indices = @($indices | Sort-Object -Unique)
                if ($indices.Count -eq 0) {
                    Write-Host ""
                    Write-ColorText "  Invalid input. Please enter module numbers between 1 and $($availableModules.Count), or 0 to cancel." -Color Red
                    Write-Host ""
                }
            } while ($indices.Count -eq 0)

            foreach ($i in $indices) {
                $selectedModuleNames += $availableModules[$i - 1].name
            }
        }
    }

    Write-Host ""
    Write-Header "RESTORE CONFIRMATION"

    Write-ColorText "  You are about to restore from:" -Color Yellow
    Write-ColorText "    Session: $($selectedSession.SessionId)" -Color White
    Write-ColorText "    Created: $($selectedSession.Timestamp)" -Color Gray

    if ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0) {
        Write-ColorText "    Modules to restore: $($selectedModuleNames -join ', ')" -Color Cyan
    }
    else {
        Write-ColorText "    Modules: $($selectedSession.Modules.name -join ', ')" -Color Cyan
    }

    Write-ColorText "    Total Items: $($selectedSession.TotalItems)" -Color Green
    Write-Host ""

    if ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0) {
        Write-ColorText "  This will restore every sealed NoID Privacy-owned target for the selected modules." -Color Yellow
    }
    else {
        Write-ColorText "  This will restore every sealed NoID Privacy-owned target in this session." -Color Yellow
    }
    Write-ColorText "  Any target that cannot be restored and verified makes the restore fail." -Color Yellow
    Write-Host ""
    Write-ColorText "  Are you sure?" -Color Yellow
    Write-Host ""
    Write-ColorText "  [N] NO - Cancel the restore (default)" -Color Green
    Write-ColorText "      - No settings are changed" -Color Gray
    Write-Host ""
    Write-ColorText "  [Y] YES - Start the restore now" -Color Cyan
    Write-ColorText "      - Restores every sealed NoID Privacy-owned target selected above" -Color Gray
    Write-Host ""

    do {
        Write-ColorText "  Your choice [Y/N] (default: N): " -Color Yellow -NoNewline
        $confirm = Read-Host
        if ([string]::IsNullOrWhiteSpace($confirm)) { $confirm = "N" }
        $confirm = $confirm.Trim().ToUpperInvariant()

        if ($confirm -notin @('Y', 'N')) {
            Write-Host ""
            Write-ColorText "  Invalid input. Please enter Y or N." -Color Red
            Write-Host ""
        }
    } while ($confirm -notin @('Y', 'N'))

    if ($confirm -ne 'Y') {
        Write-Step "Restore cancelled" -Status WARNING
        Start-Sleep -Seconds 1
        return
    }

    Write-Host ""
    Write-Step "Starting session restore..." -Status INFO
    Write-Host ""

    try {
        # Restore-Session should already be loaded from Rollback.ps1
        if (Get-Command Restore-Session -ErrorAction SilentlyContinue) {
            # Call restore for the selected session (full or partial). The
            # engine reboot prompt is deferred: it must come AFTER the Tier-2
            # reinstall offer below, otherwise an accepted reboot (default Y)
            # would swallow the offer.
            $isPartialRestore = ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0)
            if ($isPartialRestore) {
                $success = Restore-Session -SessionPath $selectedSession.FolderPath -ModuleNames $selectedModuleNames -SuppressRebootPrompt
            }
            else {
                $success = Restore-Session -SessionPath $selectedSession.FolderPath -SuppressRebootPrompt
            }

            if ($success) {
                Write-Host ""
                Write-Step "Session restored successfully" -Status SUCCESS

                # Conservative fallback if the manifest read below fails: still
                # prompt as if all restart-sensitive modules were restored.
                $restoredModuleNamesForReboot = if ($isPartialRestore) { @($selectedModuleNames) }
                else { @('SecurityBaseline', 'AntiAI', 'AdvancedSecurity') }

                # Restore-Session owns the shared Tier 2 reinstall offer so direct
                # callers and both interactive menus cannot drift apart. This
                # manifest read is only needed to scope the deferred reboot prompt.
                try {
                    $restoredManifest = Get-SessionManifest -SessionPath $selectedSession.FolderPath
                    if (-not $isPartialRestore) {
                        $restoredModuleNamesForReboot = @($restoredManifest.modules | ForEach-Object { [string]$_.name })
                    }
                }
                catch {
                    Write-ColorText "  Restored module list could not be read for the reboot prompt: $($_.Exception.Message)" -Color Yellow
                }

                # Deferred reboot prompt (restart-sensitive restored state only)
                Invoke-RestoreRebootPrompt -Reasons @(Get-RestoreRebootReasons -ModuleNames $restoredModuleNamesForReboot)
            }
            else {
                Write-Host ""
                Write-Step "Session restore completed with some failures" -Status WARNING
                # The engine suppresses its reboot prompt after a failed restore.
            }
        }
        else {
            Write-Step "Restore function not available - Rollback.ps1 not loaded" -Status ERROR
        }
    }
    catch {
        Write-Step "Restore failed: $($_.Exception.Message)" -Status ERROR
    }

    Write-Host ""
}

# ============================================================================
# MAIN PROGRAM LOOP
# ============================================================================

try {
    # Load Logger (required by Rollback.ps1) but don't initialize a hardening log yet.
    $loggerPath = Join-Path $PSScriptRoot "Core\Logger.ps1"
    if (-not (Test-Path -LiteralPath $loggerPath -PathType Leaf)) {
        throw "Required logger is missing: $loggerPath"
    }
    . $loggerPath
    if (-not (Get-Command Write-Log -ErrorAction Stop)) {
        throw 'Logger loaded without the required Write-Log command'
    }

    # Load Rollback system (required for Get-BackupSessions)
    $rollbackPath = Join-Path $PSScriptRoot "Core\Rollback.ps1"
    if (Test-Path $rollbackPath) {
        . $rollbackPath
    }
    else {
        Write-Host "[ERROR] Rollback.ps1 not found!" -ForegroundColor Red
        exit 1
    }

    # Load Framework (required for core functions like Test-IsAdmin used by modules)
    $frameworkPath = Join-Path $PSScriptRoot "Core\Framework.ps1"
    if (Test-Path $frameworkPath) {
        . $frameworkPath
    }
    else {
        Write-Host "[ERROR] Framework.ps1 not found!" -ForegroundColor Red
        exit 1
    }

    while ($true) {
        # Clear before each main menu redraw
        Clear-Host
        Show-MainMenu
        $choice = Read-Host

        switch ($choice.ToUpperInvariant()) {
            "A" {
                # Initialize to ensure clean state
                [string[]]$selectedModules = @()

                $modules = Show-ModuleMenu
                $moduleChoice = Read-Host

                if ($moduleChoice -eq "0") {
                    continue
                }
                elseif ($moduleChoice -eq "99") {
                    # All modules - force as string array
                    [string[]]$selectedModules = @($modules | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
                }
                else {
                    $selectedModule = $modules | Where-Object { $_.Key -eq $moduleChoice }
                    if ($selectedModule -and $selectedModule.Enabled) {
                        # Single module - force as string array with explicit cast
                        [string[]]$selectedModules = @([string]$selectedModule.Name)
                    }
                    elseif ($selectedModule) {
                        # It exists and is implemented; it is switched off in
                        # config.json. Say so instead of "unavailable".
                        Write-Step "$($selectedModule.Name) is disabled in config.json - set modules.$($selectedModule.Name).enabled = true to run it" -Status ERROR
                        Start-Sleep -Seconds 2
                        continue
                    }
                    else {
                        Write-Step "Invalid module selection" -Status ERROR
                        Start-Sleep -Seconds 1
                        continue
                    }
                }

                # Pass as explicit array
                Invoke-HardeningWorkflow -SelectedModules ([string[]]$selectedModules)

                Write-Host ""
                Write-ColorText "====================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "====================================================================" -Color Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "V" {
                Invoke-VerifyWorkflow

                Write-Host ""
                Write-ColorText "====================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "====================================================================" -Color Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "R" {
                Invoke-RestoreWorkflow

                Write-Host ""
                Write-ColorText "====================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "====================================================================" -Color Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "I" {
                Show-SystemInfo
            }
            "X" {
                Write-Host ""
                Write-ColorText "  Thank you for using NoID Privacy!" -Color Cyan
                Write-Host ""
                exit 0
            }
            default {
                # Invalid choice, loop continues
            }
        }
    }
}
catch {
    Write-Host ""
    Write-Step "Fatal error: $($_.Exception.Message)" -Status ERROR
    Write-Host ""
    Write-ColorText "  Press any key to exit..." -Color Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
