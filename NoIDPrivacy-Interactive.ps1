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
    Version: 2.2.6
    Requires: 64-bit Windows PowerShell 5.1, Administrator
    For CLI mode use: NoIDPrivacy.ps1 -Module <name>
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# No parameters - interactive mode only

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Core\Runtime.ps1')
Assert-NoIDPowerShellRuntime

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

function Test-NoIDQuietOutput {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return $env:NOIDPRIVACY_QUIET -eq 'true'
}

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
    Write-ColorText "===================================================================" -Color Cyan
    # Pad the header text so it fully overwrites any residual characters on the console line
    Write-ColorText ("  $Text".PadRight(67)) -Color Cyan
    Write-ColorText "===================================================================" -Color Cyan
    Write-Host ""
}

function Write-Step {
    param(
        [string]$Text,
        [string]$Status = "INFO"
    )

    if ((Test-NoIDQuietOutput) -and $Status -in @('INFO', 'WAIT')) {
        return
    }

    $symbol = switch ($Status) {
        "SUCCESS" { "[+]"; $color = "Green" }
        "ERROR" { "[-]"; $color = "Red" }
        "WARNING" { "[!]"; $color = "Yellow" }
        "NOTE" { "[i]"; $color = "Cyan" }
        "INFO" { "[>]"; $color = "Cyan" }
        "WAIT" { "[.]"; $color = "Gray" }
        default { "[ ]"; $color = "White" }
    }

    # Status lines share the two-space indent of the framework's [+]/[!]/[i] lines.
    Write-ColorText "  $symbol" -Color $color -NoNewline
    Write-Host " $Text"
}

function Write-Banner {
    if (Test-NoIDQuietOutput) {
        return
    }

    Clear-Host
    Write-Host ""
    Write-ColorText "    ========================================" -Color Cyan
    Write-ColorText "         NoID Privacy v$script:FrameworkVersion          " -Color Cyan
    Write-ColorText "    ========================================" -Color Cyan
    Write-Host ""
    Write-ColorText "    Professional Windows 11 Security & Privacy Hardening Framework" -Color Gray
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

    Write-ColorText $envLine -Color DarkGray
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

    if (-not (Test-NoIDQuietOutput)) {
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
        $domainColor = if ($isDomain) { "White" } else { "Cyan" }
        Write-ColorText $domainStatus -Color $domainColor

        Write-Host ""

        # Security Status
        Write-ColorText "  Security Status:" -Color Cyan

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
    Write-ColorText "===================================================================" -Color Cyan
    Write-ColorText "  Press any key to return to the main menu..." -Color White
    Write-ColorText "===================================================================" -Color Cyan
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
    param([switch]$HadFailures)

    Write-Host ""
    Write-ColorText "===================================================================" -Color Cyan
    Write-ColorText "  SYSTEM REBOOT RECOMMENDED" -Color Cyan
    Write-ColorText "===================================================================" -Color Cyan
    Write-Host ""

    Write-ColorText "  The applied security changes require a system reboot to take full effect." -Color White
    Write-Host ""
    Write-ColorText "  Some Windows components pick up the applied changes only after a restart." -Color Gray
    if ($HadFailures) {
        Write-ColorText "  Some steps failed. A restart does not fix those errors; review the results above." -Color Yellow
    }
    Write-Host ""
    Write-ColorText "  After the restart, choose [V] Verify in the main menu to check everything." -Color White

    Write-Host ""
    Write-ColorText "===================================================================" -Color Cyan
    Write-Host ""

    Write-ColorText "  [Y] YES - Reboot now (Recommended)" -Color Green
    Write-ColorText "      - Restart-dependent changes take effect immediately" -Color Gray
    Write-Host ""
    Write-ColorText "  [N] NO - Reboot later" -Color Cyan
    Write-ColorText "      - Restart-dependent changes stay inactive until the next reboot" -Color Gray
    Write-Host ""

    # Prompt user with validation loop
    do {
        Write-ColorText "  Reboot now? [Y/N] (default: Y): " -Color White -NoNewline
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
        Write-Step "Initiating system reboot in 10 seconds..." -Status NOTE
        Write-ColorText "  Press Ctrl+C to cancel" -Color Gray
        Write-Host ""

        # Countdown from 10
        for ($i = 10; $i -gt 0; $i--) {
            Write-ColorText "    Rebooting in $i seconds..." -Color Cyan
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
        Write-Step "Reboot deferred" -Status NOTE
        Write-Host ""
        Write-ColorText "  Please restart Windows when it suits you." -Color White
        Write-ColorText "  Some changes take effect only after the restart." -Color Gray
    }
}

# ============================================================================
# BACKUP LIST FUNCTION
# ============================================================================

function Show-BackupList {
    Write-Header "AVAILABLE BACKUP SESSIONS"

    $backupPath = Join-Path $PSScriptRoot "Backups"

    # Get sessions through Rollback.ps1
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
        Write-Step "No backup sessions found" -Status NOTE
        Write-Host ""
        return $null
    }

    Write-ColorText "  Found $($sessions.Count) backup session(s):" -Color Cyan
    Write-Host ""

    for ($i = 0; $i -lt $sessions.Count; $i++) {
        $session = $sessions[$i]

        try {
            if ([DateTime]$session.Timestamp -eq [DateTime]::MinValue) {
                throw 'Session timestamp is unknown'
            }
            $age = (Get-Date) - [DateTime]$session.Timestamp
            $ageStr = if ($age.TotalHours -lt 1) { "$([math]::Round($age.TotalMinutes)) minutes ago" }
            elseif ($age.TotalDays -lt 1) { "$([math]::Round($age.TotalHours)) hours ago" }
            else { "$([math]::Round($age.TotalDays)) days ago" }
        }
        catch {
            $ageStr = "unknown age"
        }

        Write-ColorText "  [$($i+1)] " -Color Cyan -NoNewline
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
            Write-ColorText "Ready to restore" -Color Green
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
    Write-ColorText "> Checks every setting afterwards" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Detailed progress tracking" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [V]" -Color Cyan -NoNewline
    Write-Host " Verify Current Settings"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Passed / Failed / By choice / Not applicable" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Detailed compliance report" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [R]" -Color Cyan -NoNewline
    Write-Host " Restore from Backup"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Rollback to previous state" -Color DarkGray
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> Brings back the settings saved before the change" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [I]" -Color Magenta -NoNewline
    Write-Host " System Information"
    Write-ColorText "      " -Color Gray -NoNewline
    Write-ColorText "> OS, Build, Security Status" -Color DarkGray
    Write-Host ""

    Write-ColorText "  [X]" -Color Red -NoNewline
    Write-Host " Exit"
    Write-Host ""

    Write-ColorText "===================================================================" -Color Cyan
    Write-Host ""
    Write-ColorText "  Select [A/V/R/I/X]: " -Color White -NoNewline
}

# ============================================================================
# MODULE SELECTION MENU
# ============================================================================

function Show-ModuleMenu {
    Write-Banner
    Write-Header "SELECT MODULES TO APPLY"

    # Module definitions with descriptions
    $moduleDefinitions = @{
        "SecurityBaseline" = "Microsoft-derived baseline (425 settings; no new UEFI locks)"
        "ASR"              = "Attack Surface Reduction (19 declared; 18 Windows-client applicable)"
        "DNS"              = "Secure DNS with DoH (Quad9/Cloudflare/AdGuard)"
        "Privacy"          = "Telemetry & Privacy hardening (3 modes)"
        "AntiAI"           = "Windows AI policy hardening (50 registry + 4 URI checks, 12 groups)"
        "EdgeHardening"    = "Secure Microsoft Edge (24 v151 baseline + 7 privacy values)"
        "AdvancedSecurity" = "Beyond MS Baseline (48 declared checks, 13 features)"
    }

    # Try to load config.json to check module status
    $configPath = Join-Path $PSScriptRoot "config.json"
    $config = $null
    if (Test-Path $configPath) {
        try {
            $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
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
            # cause and the setting that re-enables it.
            Write-ColorText "(disabled in config.json - set modules.$($module.Name).enabled = true to run it)" -Color DarkGray
        }
    }

    Write-Host ""
    Write-ColorText "  [99]" -Color Cyan -NoNewline
    Write-Host " ALL MODULES (WIZARD) - Interactive setup for all modules"
    Write-Host ""
    Write-ColorText "  [0]" -Color Red -NoNewline
    Write-Host " Back to Main Menu"
    Write-Host ""

    Write-ColorText "===================================================================" -Color Cyan
    Write-Host ""
    Write-ColorText "  Select module [1-7, 99, 0]: " -Color White -NoNewline

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

        # The framework skips its own banner and reboot note under the menu,
        # which shows both itself.
        $global:NoIDCalledFromMenu = $true
        $allSucceeded = $true

        # Call the framework ONCE with all selected modules so the run has a
        # single backup session and a single log file.
        # Success and restart need are independent: a failed module must not
        # discard restart-sensitive changes already made by another module.
        $rebootRecommended = $false

        if ($modulesToRun.Count -eq 7) {
            # All modules selected - use "All" for single unified session
            Write-Step "Running ALL modules in unified session..." -Status INFO
            & $frameworkScript -Module All -VerboseLogging -RebootRequired ([ref]$rebootRecommended)
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
            & $frameworkScript -Module $modulesToRun[0] -VerboseLogging -RebootRequired ([ref]$rebootRecommended)
            if ($LASTEXITCODE -eq 10) {
                $rebootRecommended = $true
            }
            elseif ($LASTEXITCODE -ne 0) {
                $allSucceeded = $false
            }
        }
        else {
            # One process means one sealed BAVR session, one manifest and one log
            # for the complete selected set. The exit code reports success;
            # the separate result also retains restart need on partial failure.
            Write-Step "Running selected modules in one unified session..." -Status INFO
            & $frameworkScript -Modules $modulesToRun -VerboseLogging -RebootRequired ([ref]$rebootRecommended)
            if ($LASTEXITCODE -eq 10) {
                $rebootRecommended = $true
            }
            elseif ($LASTEXITCODE -ne 0) {
                $allSucceeded = $false
            }
        }
        # The framework's Execution Results above are the summary; only the
        # next step is added here.
        if (-not $allSucceeded) {
            Write-ColorText "  Not every module finished. The reasons are listed above under Execution Results." -Color Yellow
        }
        elseif (-not $rebootRecommended) {
            # With a restart pending, the reboot block below gives this hint.
            Write-Host ""
            Write-ColorText "  Next: choose [V] Verify in the main menu to check every setting." -Color Gray
        }

        # Only explicit restart-sensitive module results create this prompt.
        if ($rebootRecommended) {
            Invoke-RebootPrompt -HadFailures:(-not $allSucceeded)
        }
    }
    catch {
        Write-Host ""
        Write-Step "Fatal error: $($_.Exception.Message)" -Status ERROR
        Write-Host ""
    }
    finally {
        Remove-Variable -Name NoIDCalledFromMenu -Scope Global -ErrorAction SilentlyContinue
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
        Write-ColorText "  Enter session number to restore [1-$($sessions.Count)] (0 = cancel): " -Color White -NoNewline
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

    $isXboxSettingsRestore = $selectedSession.PSObject.Properties['RestoreMode'] -and
        [string]$selectedSession.RestoreMode -ceq 'SettingsOnly'
    $restoreArguments = @{SessionPath=$selectedSession.FolderPath;SuppressRebootPrompt=$true}
    if ($isXboxSettingsRestore) {
        if (-not $selectedSession.PSObject.Properties['ExpectedSettingsFingerprint'] -or
            [string]$selectedSession.ExpectedSettingsFingerprint -cnotmatch '^[0-9a-f]{64}$') {
            Write-Step 'Xbox settings could not be compared. Refresh the backup list before restoring.' -Status ERROR
            return
        }
        $restoreArguments.ExpectedSettingsFingerprint = [string]$selectedSession.ExpectedSettingsFingerprint
    }

    # Determine available modules in this session
    $availableModules = @()
    if ($selectedSession.Modules) {
        $availableModules = @($selectedSession.Modules)
    }

    $restoreMode = "A"       # A = All modules, M = Selected modules
    $selectedModuleNames = @()

    if ($availableModules.Count -gt 0 -and -not $isXboxSettingsRestore) {
        Write-Header "RESTORE MODE"

        Write-ColorText "  Session contains the following modules:" -Color Cyan
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
            Write-ColorText "  Select restore mode [A/M] (default: A): " -Color White -NoNewline
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
                Write-ColorText "  Enter module numbers to restore [1-$($availableModules.Count), e.g. 1,3,5] (0 = cancel): " -Color White -NoNewline
                $moduleInput = Read-Host
                $moduleInput = $moduleInput.Trim()

                if ([string]::IsNullOrWhiteSpace($moduleInput) -or $moduleInput -eq '0') {
                    Write-Step "Restore cancelled" -Status NOTE
                    Start-Sleep -Seconds 1
                    return
                }

                $indices = @()
                foreach ($token in ($moduleInput -split '[,; ]')) {
                    if (-not [string]::IsNullOrWhiteSpace($token)) {
                        $parsed = 0
                        if (-not [int]::TryParse($token.Trim(), [ref]$parsed) -or
                            $parsed -lt 1 -or $parsed -gt $availableModules.Count) {
                            # Reject the entire input instead of silently
                            # restoring only its valid fragments.
                            $indices = @()
                            break
                        }
                        $indices += $parsed
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

    Write-Header "RESTORE CONFIRMATION"

    Write-ColorText "  You are about to restore from:" -Color Cyan
    Write-ColorText "    Session: $($selectedSession.SessionId)" -Color White
    $createdText = try {
        ([DateTime]$selectedSession.Timestamp).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch { [string]$selectedSession.Timestamp }
    Write-ColorText "    Created: $createdText" -Color Gray

    if ($isXboxSettingsRestore) {
        Write-ColorText '    Scope: Xbox settings only' -Color Cyan
    }
    elseif ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0) {
        Write-ColorText "    Modules to restore: $($selectedModuleNames -join ', ')" -Color Cyan
    }
    else {
        Write-ColorText "    Modules: $($selectedSession.Modules.name -join ', ')" -Color Cyan
    }

    Write-ColorText "    Total Items: $($selectedSession.TotalItems)" -Color Green
    Write-Host ""

    if ($isXboxSettingsRestore) {
        Write-ColorText '  Xbox settings only. Installed apps and their data are left unchanged.' -Color Cyan
        Write-ColorText '  If these settings change after this list was opened, refresh the list and try again.' -Color Gray
    }
    elseif ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0) {
        Write-ColorText "  This brings back every setting NoID Privacy saved before its changes, for the selected modules." -Color Cyan
    }
    else {
        Write-ColorText "  This brings back every setting NoID Privacy saved before its changes in this session." -Color Cyan
    }
    Write-ColorText "  If a setting cannot be brought back exactly, the restore names it and reports it as failed." -Color Cyan
    Write-Host ""
    Write-ColorText "  Are you sure?" -Color White
    Write-Host ""
    Write-ColorText "  [N] NO - Cancel the restore (default)" -Color Green
    Write-ColorText "      - No settings are changed" -Color Gray
    Write-Host ""
    Write-ColorText "  [Y] YES - Start the restore now" -Color Cyan
    Write-ColorText "      - Brings back the saved settings selected above" -Color Gray
    Write-Host ""

    do {
        Write-ColorText "  Your choice [Y/N] (default: N): " -Color White -NoNewline
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
        Write-Step "Restore cancelled" -Status NOTE
        Start-Sleep -Seconds 1
        return
    }

    Write-Host ""
    Write-Step "Starting session restore..." -Status INFO
    Write-Host ""

    try {
        # Restore-Session should already be loaded from Rollback.ps1
        if (Get-Command Restore-Session -ErrorAction SilentlyContinue) {
            # Call restore for the selected session (full or partial).
            # Restore-Session runs the optional Tier 1/Tier 2 app-recovery offer
            # itself before it returns; the engine reboot prompt is deferred
            # until after this menu's own result output.
            $isPartialRestore = ($restoreMode -eq 'M' -and $selectedModuleNames.Count -gt 0)
            if ($isPartialRestore) {
                $restoreArguments.ModuleNames = $selectedModuleNames
            }
            $success = Restore-Session @restoreArguments

            if ($success) {
                # The engine's RESTORE COMPLETED frame above is the result line.
                if ($isXboxSettingsRestore) {
                    Write-Step 'Xbox settings restored. Installed apps were left unchanged.' -Status SUCCESS
                    return
                }

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
    # This menu is always read by a person: plain sentences on the console,
    # full records in the log files.
    $global:LoggerConfig.ConsoleStyle = 'Plain'

    # Load Rollback system (required for Get-BackupSessions)
    $rollbackPath = Join-Path $PSScriptRoot "Core\Rollback.ps1"
    if (Test-Path $rollbackPath) {
        . $rollbackPath
    }
    else {
        Write-ColorText "[ERROR] Rollback.ps1 not found!" -Color Red
        exit 1
    }

    # Load Framework (required for core functions like Test-IsAdmin used by modules)
    $frameworkPath = Join-Path $PSScriptRoot "Core\Framework.ps1"
    if (Test-Path $frameworkPath) {
        . $frameworkPath
    }
    else {
        Write-ColorText "[ERROR] Framework.ps1 not found!" -Color Red
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
                    if ($selectedModules.Count -eq 0) {
                        Write-Step "All modules are disabled in config.json - set modules.<Name>.enabled = true to run them" -Status ERROR
                        Start-Sleep -Seconds 2
                        continue
                    }
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
                Write-ColorText "===================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "===================================================================" -Color Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "V" {
                Invoke-VerifyWorkflow

                Write-Host ""
                Write-ColorText "===================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "===================================================================" -Color Cyan
                Write-Host ""
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "R" {
                Invoke-RestoreWorkflow

                Write-Host ""
                Write-ColorText "===================================================================" -Color Cyan
                Write-ColorText "  Press any key to return to the main menu..." -Color White
                Write-ColorText "===================================================================" -Color Cyan
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
