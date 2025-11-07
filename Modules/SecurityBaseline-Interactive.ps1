# =======================================================================================
# SecurityBaseline-Interactive.ps1 - Interaktives Menue-System
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Show-Banner {
    <#
    .SYNOPSIS
        Shows the NoID Privacy Banner
    .DESCRIPTION
        Clears the screen and displays the decorative banner with branding.
        Best Practice 25H2: Error-Handling for Clear-Host in non-interactive sessions.
    .EXAMPLE
        Show-Banner
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    try {
        Clear-Host
    }
    catch {
        # Fallback for non-interactive sessions
        $verboseMsg = Get-LocalizedString 'ErrorClearHostFailed'
        if (-not $verboseMsg) { $verboseMsg = "Clear-Host not available (non-interactive session)" }
        Write-Verbose $verboseMsg
    }
    
    Write-Host ""
    Write-Host "=============================================================================" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "                NoID Privacy - Windows 11 25H2 Baseline" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "               Maximum Security + Privacy + Performance" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "=============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    <#
    .SYNOPSIS
        Zeigt das Hauptmenue an
    .DESCRIPTION
        Zeigt das Hauptmenue mit allen verfuegbaren Optionen und aktuellen Modus.
        Best Practice 25H2: Get-LocalizedString mit Fallback-Validierung.
    .PARAMETER SelectedMode
        Aktuell ausgewaehlter Modus (optional)
    .EXAMPLE
        Show-MainMenu
    .EXAMPLE
        Show-MainMenu -SelectedMode "Audit"
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [string]$SelectedMode = ""
    )
    
    Show-Banner
    
    # Get-LocalizedString with fallback
    $title = Get-LocalizedString "MainMenuTitle"
    if (-not $title) { $title = "MAIN MENU" }
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                            $title" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    if ($SelectedMode) {
        $currentModeText = Get-LocalizedString 'CurrentMode'
        if (-not $currentModeText) { $currentModeText = "Current Mode" }
        Write-Host "  $currentModeText " -NoNewline -ForegroundColor White
        Write-Host $SelectedMode -ForegroundColor Green
        Write-Host ""
    }
    
    $menuAudit = Get-LocalizedString 'MainMenuAudit'
    if (-not $menuAudit) { $menuAudit = "Audit Mode" }
    Write-Host "  [1] $menuAudit" -ForegroundColor White
    
    $menuAuditDesc = Get-LocalizedString 'MainMenuAuditDesc'
    if (-not $menuAuditDesc) { $menuAuditDesc = "Apply full baseline, ASR in audit (no blocking)" }
    Write-Host "         $menuAuditDesc" -ForegroundColor Gray
    
    $menuAuditFollow = Get-LocalizedString 'MainMenuAuditFollow'
    if (-not $menuAuditFollow) { $menuAuditFollow = "-> DNS, OneDrive & Remote Access configuration follows" }
    Write-Host "         $menuAuditFollow" -ForegroundColor DarkCyan
    Write-Host ""
    
    $menuEnforce = Get-LocalizedString 'MainMenuEnforce'
    if (-not $menuEnforce) { $menuEnforce = "Enforce Mode" }
    Write-Host "  [2] $menuEnforce" -ForegroundColor White
    
    $menuEnforceDesc = Get-LocalizedString 'MainMenuEnforceDesc'
    if (-not $menuEnforceDesc) { $menuEnforceDesc = "Apply all settings" }
    Write-Host "         $menuEnforceDesc" -ForegroundColor Gray
    
    $menuEnforceFollow = Get-LocalizedString 'MainMenuEnforceFollow'
    if (-not $menuEnforceFollow) { $menuEnforceFollow = "-> DNS, OneDrive & Remote Access configuration follows" }
    Write-Host "         $menuEnforceFollow" -ForegroundColor DarkCyan
    Write-Host ""
    
    $menuCustom = Get-LocalizedString 'MainMenuCustom'
    if (-not $menuCustom) { $menuCustom = "Custom Mode" }
    Write-Host "  [3] $menuCustom" -ForegroundColor White
    
    $menuCustomDesc = Get-LocalizedString 'MainMenuCustomDesc'
    if (-not $menuCustomDesc) { $menuCustomDesc = "Select modules" }
    Write-Host "         $menuCustomDesc" -ForegroundColor Gray
    
    $menuCustomFollow = Get-LocalizedString 'MainMenuCustomFollow'
    if (-not $menuCustomFollow) { $menuCustomFollow = "-> DNS, OneDrive & Remote Access configuration follows" }
    Write-Host "         $menuCustomFollow" -ForegroundColor DarkCyan
    Write-Host ""
    
    $menuVerify = Get-LocalizedString 'MainMenuVerify'
    if (-not $menuVerify) { $menuVerify = "Verify" }
    Write-Host "  [4] $menuVerify" -ForegroundColor White
    
    $menuVerifyDesc = Get-LocalizedString 'MainMenuVerifyDesc'
    if (-not $menuVerifyDesc) { $menuVerifyDesc = "Check current settings" }
    Write-Host "         $menuVerifyDesc" -ForegroundColor Gray
    Write-Host ""
    
    $menuExit = Get-LocalizedString 'MainMenuExit'
    if (-not $menuExit) { $menuExit = "Exit" }
    Write-Host "  [5] $menuExit" -ForegroundColor White
    
    $menuExitDesc = Get-LocalizedString 'MainMenuExitDesc'
    if (-not $menuExitDesc) { $menuExitDesc = "Exit program" }
    Write-Host "         $menuExitDesc" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
}

function Get-UserChoice {
    <#
    .SYNOPSIS
        Fordert Benutzereingabe mit Validierung an
    .DESCRIPTION
        Zeigt Eingabeaufforderung mit gueltigen Optionen und validiert die Eingabe.
        Best Practice 25H2: Input-Validierung mit Trim() und Error-Handling.
    .PARAMETER Prompt
        Text der Eingabeaufforderung
    .PARAMETER ValidChoices
        Array von gueltigen Auswahlmoeglichkeiten
    .OUTPUTS
        [string] Die validierte Benutzerwahl
    .EXAMPLE
        Get-UserChoice -Prompt "Waehlen Sie" -ValidChoices @('1', '2', '3')
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Prompt,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidChoices = @('1', '2', '3', '4', '5', '6')
    )
    
    if (-not $Prompt) {
        $Prompt = Get-LocalizedString "MainMenuPrompt"
        if (-not $Prompt) { $Prompt = "Your choice" }
    }
    
    do {
        Write-Host "  $Prompt " -NoNewline -ForegroundColor Cyan
        Write-Host "[" -NoNewline -ForegroundColor Gray
        Write-Host ($ValidChoices -join '/') -NoNewline -ForegroundColor White
        Write-Host "]: " -NoNewline -ForegroundColor Gray
        
        try {
            $choice = Read-Host
            
            # INPUT VALIDIERUNG (Best Practice 25H2)
            if ([string]::IsNullOrWhiteSpace($choice)) {
                $emptyMsg = Get-LocalizedString 'ErrorEmptyInput'
                if (-not $emptyMsg) { $emptyMsg = "Empty input not allowed!" }
                Write-Host "  [ERROR] $emptyMsg" -ForegroundColor Red
                Write-Host ""
                continue
            }
            
            # Trim and case-insensitive
            $choice = $choice.Trim().ToUpper()
            
            # Validate against valid choices (case-insensitive)
            $validChoicesUpper = $ValidChoices | ForEach-Object { $_.ToUpper() }
            
            if ($choice -notin $validChoicesUpper) {
                $errorMsg = Get-LocalizedString 'ErrorInvalidInput'
                if (-not $errorMsg) { $errorMsg = "Invalid input! Valid options:" }
                
                Write-Host "  [ERROR] $errorMsg " -NoNewline -ForegroundColor Red
                Write-Host ($ValidChoices -join ', ') -NoNewline -ForegroundColor Yellow
                Write-Host "!" -ForegroundColor Red
                Write-Host ""
                continue
            }
            
            # Validation successful - return ORIGINAL case
            $matchIndex = [array]::IndexOf($validChoicesUpper, $choice)
            if ($matchIndex -ge 0) {
                $choice = $ValidChoices[$matchIndex]
            }
            
            break  # Input is valid - exit loop
        }
        catch {
            $errorMsg = Get-LocalizedString 'ErrorInputFailed' $_.Exception.Message
            if (-not $errorMsg) { $errorMsg = "Input error: $($_.Exception.Message)" }
            Write-Warning $errorMsg
            Write-Host ""
        }
    } while ($true)
    
    return $choice
}

function Show-ModuleSelection {
    <#
    .SYNOPSIS
        Zeigt interaktive Modul-Auswahl an
    .DESCRIPTION
        Zeigt eine interaktive Liste von Modulen mit Cursor-Navigation.
        Best Practice 25H2: Check fuer $Host.UI.RawUI availability (non-interactive sessions).
    .OUTPUTS
        [array] Array von ausgewaehlten Modulen oder $null bei Abbruch
    .EXAMPLE
        $selectedModules = Show-ModuleSelection
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param()
    
    # Check ob interactive session
    if (-not $Host.UI.RawUI) {
        $warnMsg = Get-LocalizedString 'ErrorInteractiveRequired'
        if (-not $warnMsg) { $warnMsg = "This function requires an interactive PowerShell session." }
        Write-Warning $warnMsg
        return $null
    }
    
    # IMPORTANT: Check if PowerShell ISE (arrow keys do NOT work there!)
    if ($Host.Name -match "ISE") {
        $title = Get-LocalizedString 'ISEWarningTitle'
        if (-not $title) { $title = "WARNING: PowerShell ISE NOT SUPPORTED!" }
        
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Red
        Write-Host "  $title" -ForegroundColor Red
        Write-Host "============================================================================" -ForegroundColor Red
        Write-Host ""
        
        $message = Get-LocalizedString 'ISEWarningMessage'
        if (-not $message) { $message = "Custom Mode requires arrow key navigation." }
        Write-Host "  $message" -ForegroundColor Yellow
        
        $notWork = Get-LocalizedString 'ISEWarningNotWork'
        if (-not $notWork) { $notWork = "This does NOT work in PowerShell ISE!" }
        Write-Host "  $notWork" -ForegroundColor Yellow
        Write-Host ""
        
        $solution = Get-LocalizedString 'ISEWarningSolution'
        if (-not $solution) { $solution = "SOLUTION:" }
        Write-Host "  $solution" -ForegroundColor Cyan
        
        $step1 = Get-LocalizedString 'ISEWarningStep1'
        if (-not $step1) { $step1 = "1. Open a NORMAL PowerShell Console" }
        Write-Host "  $step1" -ForegroundColor White
        
        $step2 = Get-LocalizedString 'ISEWarningStep2'
        if (-not $step2) { $step2 = "2. Run the script there" }
        Write-Host "  $step2" -ForegroundColor White
        Write-Host ""
        
        $alternative = Get-LocalizedString 'ISEWarningAlternative'
        if (-not $alternative) { $alternative = "Alternative: Use Audit/Enforce Mode (Option 1/2)" }
        Write-Host "  $alternative" -ForegroundColor Gray
        Write-Host ""
        
        $pressKeyMsg = Get-LocalizedString 'PressAnyKeyToReturn'
        if (-not $pressKeyMsg) { $pressKeyMsg = "Press any key to return..." }
        Write-Host "  $pressKeyMsg" -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return $null
    }
    
    $modules = @(
        @{
            Name = "Security Baseline Core"
            Key = "Core"
            Description = "Microsoft Security Baseline 25H2: Defender, Firewall, Services, Audit Policies"
            Enabled = $true
            Mandatory = $true
        },
        @{
            Name = "ASR Rules (Attack Surface Reduction)"
            Key = "ASR"
            Description = "19 Attack Surface Reduction Rules + Exploit Protection + SmartScreen"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Advanced Security"
            Key = "Advanced"
            Description = "Virtualization-Based Security (VBS), Credential Guard, BitLocker Policies, LAPS"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "DNS Security"
            Key = "DNS"
            Description = "DNS over HTTPS (DoH), DNSSEC, Malware/Ad Blocklist (107.000+ Domains)"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Bloatware Removal"
            Key = "Bloatware"
            Description = "Entfernt 50+ vorinstallierte Apps: Spiele, Werbung, Bloatware (Xbox, Candy Crush, etc.)"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Telemetry Deactivation"
            Key = "Telemetry"
            Description = "95% Telemetrie deaktiviert + alle 37 App-Berechtigungen auf Standard 'Deny'"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Performance Optimization"
            Key = "Performance"
            Description = "100+ Scheduled Tasks deaktiviert + Event Logs optimiert + Background Apps gestoppt"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "AI Features Lockdown"
            Key = "AI"
            Description = "Windows Recall blockiert + Copilot deaktiviert + AI-Features in Paint/Settings aus"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Wireless Display / Miracast"
            Key = "WirelessDisplay"
            Description = "[!] BREAKS CASTING! Disables Miracast/Cast (Services, Firewall, Registry).`n      Error appears only on Cast button click. Skip if needed."
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "OneDrive Privacy Hardening"
            Key = "OneDrive"
            Description = "OneDrive Telemetrie minimiert + Known Folder Management (Auto-Backup) blockiert"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Microsoft Edge Security"
            Key = "Edge"
            Description = "Microsoft Edge Security Baseline v139+: SmartScreen, DNS-over-HTTPS, Password Monitor"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "UAC Maximum Security"
            Key = "UAC"
            Description = "UAC auf hoechster Stufe + Enhanced Privilege Protection (Admin Token Hardening)"
            Enabled = $true
            Mandatory = $false
        },
        @{
            Name = "Windows Update Defaults"
            Key = "WindowsUpdate"
            Description = "Windows Update: Automatische Updates aktiviert + Delivery Optimization konfiguriert"
            Enabled = $true
            Mandatory = $false
        }
    )
    
    $currentSelection = 0
    $done = $false
    
    while (-not $done) {
        Show-Banner
        
        $title = Get-LocalizedString 'ModuleSelectionTitle'
        if (-not $title) { $title = "MODULE SELECTION (Custom Mode)" }
        
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host "                        $title" -ForegroundColor Yellow
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host ""
        
        $controls = Get-LocalizedString 'ModuleSelectionControls'
        if (-not $controls) { $controls = "CONTROLS:" }
        Write-Host "  $controls" -ForegroundColor Cyan
        
        $arrows = Get-LocalizedString 'ModuleSelectionArrows'
        if (-not $arrows) { $arrows = "[Arrow Keys Up/Down]  - Move cursor" }
        Write-Host "    $arrows" -ForegroundColor White
        
        $space = Get-LocalizedString 'ModuleSelectionSpace'
        if (-not $space) { $space = "[SPACE]                - Enable/disable module (not for mandatory modules)" }
        Write-Host "    $space" -ForegroundColor White
        
        $selectAll = Get-LocalizedString 'ModuleSelectionA'
        if (-not $selectAll) { $selectAll = "[A]                    - Select ALL modules" }
        Write-Host "    $selectAll" -ForegroundColor White
        
        $selectNone = Get-LocalizedString 'ModuleSelectionN'
        if (-not $selectNone) { $selectNone = "[N]                    - Select NONE (mandatory modules stay active)" }
        Write-Host "    $selectNone" -ForegroundColor White
        
        $enter = Get-LocalizedString 'ModuleSelectionEnter'
        if (-not $enter) { $enter = "[ENTER]                - Confirm selection and start" }
        Write-Host "    $enter" -ForegroundColor Green
        
        $esc = Get-LocalizedString 'ModuleSelectionEsc'
        if (-not $esc) { $esc = "[ESC]                  - Return to main menu (without changes)" }
        Write-Host "    $esc" -ForegroundColor Yellow
        Write-Host ""
        
        $hint = Get-LocalizedString 'ModuleSelectionHint'
        if (-not $hint) { $hint = "HINT:" }
        Write-Host "  $hint " -NoNewline -ForegroundColor Yellow
        
        $mandatory = Get-LocalizedString 'ModuleSelectionMandatory'
        if (-not $mandatory) { $mandatory = "YELLOW modules are mandatory and always active!" }
        Write-Host "$mandatory" -ForegroundColor Yellow
        Write-Host ""
        
        for ($i = 0; $i -lt $modules.Count; $i++) {
            $module = $modules[$i]
            $prefix = if ($i -eq $currentSelection) { "-> " } else { "  " }
            
            # Mandatory modules: Always [X] and not changeable
            if ($module.Mandatory) {
                $checkbox = "[X]"
                $checkColor = "Yellow"  # Yellow for mandatory!
                $nameColor = "Yellow"   # Ganzer Name in Gelb
                $mandatoryTag = Get-LocalizedString 'ModuleSelectionMandatoryTag'
                if (-not $mandatoryTag) { $mandatoryTag = "[MANDATORY - CANNOT BE DISABLED]" }
                $mandatory = " $mandatoryTag"
            }
            else {
                $checkbox = if ($module.Enabled) { "[X]" } else { "[ ]" }
                $checkColor = if ($module.Enabled) { "Green" } else { "DarkGray" }
                $nameColor = if ($i -eq $currentSelection) { "Cyan" } else { "White" }
                $mandatory = ""
            }
            
            $cursorColor = if ($i -eq $currentSelection) { "Cyan" } else { "White" }
            
            Write-Host $prefix -NoNewline -ForegroundColor $cursorColor
            Write-Host $checkbox -NoNewline -ForegroundColor $checkColor
            Write-Host " $($module.Name)" -NoNewline -ForegroundColor $nameColor
            if ($mandatory) {
                Write-Host $mandatory -ForegroundColor Yellow
            }
            else {
                Write-Host ""
            }
            Write-Host "      $($module.Description)" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host ""
        
        # Wait for keypress with error handling
        try {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        catch {
            $errorMsg = Get-LocalizedString 'ErrorKeyboardFailed' $_
            if (-not $errorMsg) { $errorMsg = "Keyboard input failed: $_" }
            Write-Warning $errorMsg
            return $null
        }
        
        switch ($key.VirtualKeyCode) {
            38 { # Arrow Up
                if ($currentSelection -gt 0) {
                    $currentSelection--
                }
            }
            40 { # Arrow Down
                if ($currentSelection -lt ($modules.Count - 1)) {
                    $currentSelection++
                }
            }
            32 { # Space
                if (-not $modules[$currentSelection].Mandatory) {
                    $modules[$currentSelection].Enabled = -not $modules[$currentSelection].Enabled
                }
            }
            65 { # A - Select All
                for ($i = 0; $i -lt $modules.Count; $i++) {
                    $modules[$i].Enabled = $true
                }
            }
            78 { # N - Select None (nur non-mandatory)
                for ($i = 0; $i -lt $modules.Count; $i++) {
                    if (-not $modules[$i].Mandatory) {
                        $modules[$i].Enabled = $false
                    }
                }
            }
            13 { # Enter
                $done = $true
            }
            27 { # Escape
                $done = $true
            }
        }
    }
    
    # If user pressed Escape, return null
    if ($key.VirtualKeyCode -eq 27) {
        return $null
    }
    
    return $modules
}

function Show-Progress {
    <#
    .SYNOPSIS
        Zeigt Fortschrittsbalken an
    .DESCRIPTION
        Wrapper fuer Write-Progress mit Error-Handling fuer non-interactive sessions.
        Best Practice 25H2: Graceful degradation bei fehlender Progress-Bar-Unterstuetzung.
    .PARAMETER Activity
        Beschreibung der Aktivitaet
    .PARAMETER Status
        Aktueller Status
    .PARAMETER PercentComplete
        Fortschritt in Prozent (0-100)
    .EXAMPLE
        Show-Progress -Activity "Installing" -Status "Module 1/5" -PercentComplete 20
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Status,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete
    )
    
    try {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
    catch {
        # Fallback for non-interactive sessions
        Write-Verbose "$Activity - $Status ($PercentComplete%)"
    }
}

function Invoke-AuditMode {
    <#
    .SYNOPSIS
        Startet den Audit-Modus
    .DESCRIPTION
        Zeigt Audit-Modus-Dialog und fragt Bestaetigung ab.
        Best Practice 25H2: Read-Host mit Validierung und multi-language support.
    .OUTPUTS
        [hashtable] Konfigurations-Hashtable oder $null bei Abbruch
    .EXAMPLE
        $config = Invoke-AuditMode
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()
    
    Show-Banner
    
    $title = Get-LocalizedString 'AuditModeTitle'
    if (-not $title) { $title = "Audit Mode" }
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                           $title" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    $bannerTitle = Get-LocalizedString 'AuditModeBannerTitle'
    if (-not $bannerTitle) { $bannerTitle = "AUDIT MODE - SAFE TEST MODE:" }
    Write-Host "  $bannerTitle" -ForegroundColor Green
    Write-Host ""
    
    $whatHappens = Get-LocalizedString 'AuditModeWhatHappens'
    if (-not $whatHappens) { $whatHappens = "What happens:" }
    Write-Host "  $whatHappens" -ForegroundColor Cyan
    
    $step1 = Get-LocalizedString 'AuditModeStep1'
    if (-not $step1) { $step1 = "1. Full security baseline will be applied (Core, Advanced, DNS, ...)" }
    Write-Host "    $step1" -ForegroundColor White
    
    $step2 = Get-LocalizedString 'AuditModeStep2'
    if (-not $step2) { $step2 = "2. ASR Rules run in AUDIT mode:" }
    Write-Host "    $step2" -ForegroundColor White
    
    $step2a = Get-LocalizedString 'AuditModeStep2a'
    if (-not $step2a) { $step2a = "- Events are logged" }
    Write-Host "       $step2a" -ForegroundColor Gray
    
    $step2b = Get-LocalizedString 'AuditModeStep2b'
    if (-not $step2b) { $step2b = "- But NOT blocked" }
    Write-Host "       $step2b" -ForegroundColor Gray
    
    $step2c = Get-LocalizedString 'AuditModeStep2c'
    if (-not $step2c) { $step2c = "- Microsoft Best Practice: First Audit, then Enforce!" }
    Write-Host "       $step2c" -ForegroundColor Gray
    Write-Host ""
    
    $important = Get-LocalizedString 'AuditModeImportant'
    if (-not $important) { $important = "IMPORTANT:" }
    Write-Host "  $important " -NoNewline -ForegroundColor Yellow
    
    $importantMsg = Get-LocalizedString 'AuditModeImportantMsg'
    if (-not $importantMsg) { $importantMsg = "Audit Mode affects ONLY ASR Rules." }
    Write-Host "$importantMsg" -ForegroundColor Yellow
    
    $unchanged = Get-LocalizedString 'AuditModeUnchanged'
    if (-not $unchanged) { $unchanged = "All other security settings are applied normally (ENFORCE)." }
    Write-Host "           $unchanged" -ForegroundColor Yellow
    Write-Host ""
    
    $continuePrompt = Get-LocalizedString 'AuditModeContinue'
    if (-not $continuePrompt) { $continuePrompt = "Would you like to continue? [Y/N]:" }
    Write-Host "  $continuePrompt " -NoNewline -ForegroundColor Cyan
    
    $confirm = Read-Host
    if ($confirm) {
        $confirm = $confirm.Trim().ToUpper()
    }
    
    # Support for German (J/j) and English (Y/y)
    if ($confirm -in @('J', 'Y')) {
        # Best Practice 25H2: Explicitly create hashtable with all properties
        $auditConfig = @{
            Mode = 'Audit'
            Modules = @('Core', 'ASR', 'Advanced', 'DNS', 'Bloatware', 'Telemetry', 'Performance', 'AI', 'WirelessDisplay', 'OneDrive', 'UAC', 'WindowsUpdate', 'Edge')
            CreateRestorePoint = $true
            CreateBackup = $false  # Wird spaeter von Start-InteractiveMode ueberschrieben
        }
        Write-Verbose "Audit Mode Config created with Mode=$($auditConfig.Mode)"
        return $auditConfig
    }
    return $null
}

function Invoke-EnforceMode {
    <#
    .SYNOPSIS
        Startet den Enforce-Modus
    .DESCRIPTION
        Zeigt Enforce-Modus-Dialog mit double-confirmation.
        Best Practice 25H2: Doppelte Bestaetigung fuer destruktive Operationen.
    .OUTPUTS
        [hashtable] Konfigurations-Hashtable oder $null bei Abbruch
    .EXAMPLE
        $config = Invoke-EnforceMode
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()
    
    Show-Banner
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                          Enforce Mode" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerTitle')" -ForegroundColor Red
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerWarning1')" -ForegroundColor Red
    Write-Host "  $(Get-LocalizedString 'EnforceBannerWarning2')" -ForegroundColor Red
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerModulesTitle')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerSecurityTitle')" -ForegroundColor Cyan
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurity1')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurity2')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurity3')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurity4')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurity5')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerSecurityMore')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerNetworkTitle')" -ForegroundColor Cyan
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetwork1')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetwork2')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetwork3')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetwork4')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetwork5')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerNetworkMore')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerPrivacyTitle')" -ForegroundColor Cyan
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacy1')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacy2')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacy3')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacy4')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacy5')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerPrivacyMore')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerBloatwareTitle')" -ForegroundColor Cyan
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatware1')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatware2')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatware3')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatware4')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatware5')" -ForegroundColor White
    Write-Host "    - $(Get-LocalizedString 'EnforceBannerBloatwareMore')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  $(Get-LocalizedString 'EnforceBannerConfirm') " -NoNewline -ForegroundColor Red
    
    $confirm = Read-Host
    if ($confirm) {
        $confirm = $confirm.Trim().ToUpper()
    }
    
    # Support for German (J) and English (Y)
    if ($confirm -in @('J', 'Y')) {
        Write-Host ""
        Write-Host "  $(Get-LocalizedString 'EnforceBannerStarting')" -ForegroundColor Green
        Write-Host ""
        
        # Best Practice 25H2: Explicitly create hashtable with all properties
        $enforceConfig = @{
            Mode = 'Enforce'
            Modules = @('Core', 'ASR', 'Advanced', 'DNS', 'Bloatware', 'Telemetry', 'Performance', 'AI', 'WirelessDisplay', 'OneDrive', 'UAC', 'WindowsUpdate', 'Edge')
            CreateRestorePoint = $true
            CreateBackup = $false  # Wird spaeter von Start-InteractiveMode ueberschrieben
        }
        Write-Verbose "Enforce Mode Config created with Mode=$($enforceConfig.Mode)"
        return $enforceConfig
    }
    return $null
}

function Invoke-CustomMode {
    <#
    .SYNOPSIS
        Startet den Custom-Modus mit Modul-Auswahl
    .DESCRIPTION
        Zeigt Modul-Auswahl und fragt ASR-Modus ab.
        Best Practice 25H2: ReadKey mit Error-Handling und Input-Validierung.
    .OUTPUTS
        [hashtable] Konfigurations-Hashtable oder $null bei Abbruch
    .EXAMPLE
        $config = Invoke-CustomMode
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()
    
    $modules = Show-ModuleSelection
    
    if ($null -eq $modules) {
        return $null
    }
    
    $enabledModules = @($modules | Where-Object { $_.Enabled } | ForEach-Object { $_.Key })
    
    if ($enabledModules.Count -eq 0) {
        Show-Banner
        
        $noModules = Get-LocalizedString 'CustomModeNoModules'
        if (-not $noModules) { $noModules = "No modules selected!" }
        Write-Host "  $noModules" -ForegroundColor Red
        Write-Host ""
        $pressKeyMsg = Get-LocalizedString 'PressAnyKey'
        if (-not $pressKeyMsg) { $pressKeyMsg = "Press any key..." }
        Write-Host "  $pressKeyMsg" -ForegroundColor Gray
        
        # ReadKey with error handling
        try {
            if ($Host.UI.RawUI) {
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            else {
                $pressEnterMsg = Get-LocalizedString 'PressEnter'
                if (-not $pressEnterMsg) { $pressEnterMsg = "Press Enter" }
                Read-Host -Prompt "  $pressEnterMsg"
            }
        }
        catch {
            $verboseMsg = Get-LocalizedString 'ErrorReadKeyFailed' $_
            if (-not $verboseMsg) { $verboseMsg = "ReadKey failed: $_" }
            Write-Verbose $verboseMsg
        }
        
        # NO FLUSH AFTER CUSTOM!
        # User already pressed key to continue - flushing would consume that key or KeyUp event
        # causing them to press twice before menu responds
        
        return $null
    }
    
    Show-Banner
    
    $title = Get-LocalizedString 'CustomModeSummaryTitle'
    if (-not $title) { $title = "Custom Mode" }
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                          $title" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    $selectedModules = Get-LocalizedString 'CustomModeSelectedModules'
    if (-not $selectedModules) { $selectedModules = "Selected Modules:" }
    Write-Host "  $selectedModules" -ForegroundColor Cyan
    foreach ($key in $enabledModules) {
        $module = $modules | Where-Object { $_.Key -eq $key }
        Write-Host "  * $($module.Name)" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    $step2 = Get-LocalizedString 'CustomModeStep2'
    if (-not $step2) { $step2 = "STEP 2: Choose mode for ASR rules:" }
    Write-Host "  $step2" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Audit Mode   (ONLY ASR on Audit, everything else Enforce)" -ForegroundColor White
    Write-Host "      - ASR Rules only log (recommended for testing)" -ForegroundColor Gray
    Write-Host "      - Registry, Services, Apps etc. are still applied" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Enforce Mode (EVERYTHING enforced incl. ASR)" -ForegroundColor White
    Write-Host "      - ASR Rules actively block (Production)" -ForegroundColor Gray
    Write-Host "      - Maximum Protection" -ForegroundColor Gray
    Write-Host ""
    
    $asrMode = Get-UserChoice -Prompt "ASR-Modus" -ValidChoices @('1', '2')
    $mode = if ($asrMode -eq '1') { 'Audit' } else { 'Enforce' }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    
    $ready = Get-LocalizedString 'CustomModeReady'
    if (-not $ready) { $ready = "READY TO START!" }
    Write-Host "  $ready" -ForegroundColor Green
    Write-Host ""
    
    $moduleCount = Get-LocalizedString 'CustomModeModuleCount' $enabledModules.Count
    if (-not $moduleCount) { $moduleCount = "Selected Modules: $($enabledModules.Count)" }
    Write-Host "  $moduleCount" -ForegroundColor White
    
    $asrMode = Get-LocalizedString 'CustomModeASRMode' $mode
    if (-not $asrMode) { $asrMode = "ASR Mode: $mode" }
    Write-Host "  $asrMode" -ForegroundColor White
    Write-Host ""
    
    $willStart = Get-LocalizedString 'CustomModeWillStart'
    if (-not $willStart) { $willStart = "The script will now start with your configuration." }
    Write-Host "  $willStart" -ForegroundColor Yellow
    Write-Host ""
    
    $startNow = Get-LocalizedString 'CustomModeStartNow'
    if (-not $startNow) { $startNow = "Would you like to start NOW? [Y/N]:" }
    Write-Host "  $startNow " -NoNewline -ForegroundColor Cyan
    
    $confirm = Read-Host
    if ($confirm) {
        $confirm = $confirm.Trim().ToUpper()
    }
    
    # Support for German (J) and English (Y)
    if ($confirm -in @('J', 'Y')) {
        # Best Practice 25H2: Explicitly create hashtable with all properties
        $customConfig = @{
            Mode = $mode
            Modules = $enabledModules
            CreateRestorePoint = $true
            CreateBackup = $false  # Wird spaeter von Start-InteractiveMode ueberschrieben
        }
        Write-Verbose "Custom Mode Config created with Mode=$($customConfig.Mode), Modules=$($customConfig.Modules -join ',')"
        return $customConfig
    }
    return $null
}

function Invoke-VerifyMode {
    <#
    .SYNOPSIS
        Startet den Verify-Modus
    .DESCRIPTION
        Ruft das Verify-Skript auf, um die Baseline-Konfiguration zu pruefen.
        Best Practice 25H2: $PSCommandPath Null-Check, Try-Catch fuer Script-Aufruf, ReadKey Error-Handling.
    .OUTPUTS
        [object] $null
    .EXAMPLE
        Invoke-VerifyMode
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Show-Banner
    
    $title = Get-LocalizedString 'VerifyModeTitle'
    if (-not $title) { $title = "Verify Mode" }
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                          $title" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    $message = Get-LocalizedString 'VerifyModeMessage'
    if (-not $message) { $message = "Verify checks if the baseline was applied correctly." }
    Write-Host "  $message" -ForegroundColor Yellow
    
    $call = Get-LocalizedString 'VerifyModeCall'
    if (-not $call) { $call = "This calls the Verify script." }
    Write-Host "  $call" -ForegroundColor Yellow
    Write-Host ""
    
    $continuePrompt = Get-LocalizedString 'VerifyModeContinue'
    if (-not $continuePrompt) { $continuePrompt = "Would you like to continue? [Y/N]:" }
    Write-Host "  $continuePrompt " -NoNewline -ForegroundColor Cyan
    
    $confirm = Read-Host
    if ($confirm) {
        $confirm = $confirm.Trim().ToUpper()
    }
    
    if ($confirm -in @('J', 'Y')) {
        # $PSCommandPath null check with robust error handling
        if (-not $PSCommandPath) {
            $errorPath = Get-LocalizedString 'VerifyModeErrorPath'
            if (-not $errorPath) { $errorPath = "[ERROR] Script path could not be determined (dot-sourced script?)" }
            Write-Host "  $errorPath" -ForegroundColor Red
            
            $runManual = Get-LocalizedString 'VerifyModeErrorRunManual'
            if (-not $runManual) { $runManual = "Please run the Verify script directly." }
            Write-Host "  $runManual" -ForegroundColor Yellow
        }
        else {
            try {
                $scriptDir = Split-Path -Parent $PSCommandPath -ErrorAction Stop
                if ([string]::IsNullOrEmpty($scriptDir)) {
                    throw "Split-Path ergab leeren Pfad"
                }
                
                $parentDir = Split-Path -Parent $scriptDir -ErrorAction Stop
                if ([string]::IsNullOrEmpty($parentDir)) {
                    throw "Parent-Verzeichnis konnte nicht ermittelt werden"
                }
                
                $verifyScript = Join-Path $parentDir "Verify-SecurityBaseline.ps1"
                
                if (Test-Path $verifyScript) {
                    Write-Host ""
                    
                    $starting = Get-LocalizedString 'VerifyModeStarting'
                    if (-not $starting) { $starting = "[INFO] Starting Verify script..." }
                    Write-Host "  $starting" -ForegroundColor Cyan
                    & $verifyScript
                    Write-Host ""
                    
                    $complete = Get-LocalizedString 'VerifyModeComplete'
                    if (-not $complete) { $complete = "[OK] Verify script completed" }
                    Write-Host "  $complete" -ForegroundColor Green
                }
                else {
                    $notFound = Get-LocalizedString 'VerifyModeErrorNotFound'
                    if (-not $notFound) { $notFound = "[ERROR] Verify script not found!" }
                    Write-Host "  $notFound" -ForegroundColor Red
                    
                    $expected = Get-LocalizedString 'VerifyModeErrorExpected' $verifyScript
                    if (-not $expected) { $expected = "Expected: $verifyScript" }
                    Write-Host "  $expected" -ForegroundColor Gray
                }
            }
            catch {
                $errorRun = Get-LocalizedString 'VerifyModeErrorRun'
                if (-not $errorRun) { $errorRun = "[ERROR] Error running Verify script!" }
                Write-Host "  $errorRun" -ForegroundColor Red
                
                $details = Get-LocalizedString 'VerifyModeErrorDetails' $_
                if (-not $details) { $details = "Details: $_" }
                Write-Host "  $details" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
        $pressKeyMsg = Get-LocalizedString 'PressAnyKey'
        if (-not $pressKeyMsg) { $pressKeyMsg = "Press any key..." }
        Write-Host "  $pressKeyMsg" -ForegroundColor Gray
        
        # ReadKey with error handling
        try {
            if ($Host.UI.RawUI) {
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            else {
                $pressEnterMsg = Get-LocalizedString 'PressEnter'
                if (-not $pressEnterMsg) { $pressEnterMsg = "Press Enter" }
                Read-Host -Prompt "  $pressEnterMsg"
            }
        }
        catch {
            $verboseMsg = Get-LocalizedString 'ErrorReadKeyFailed' $_
            if (-not $verboseMsg) { $verboseMsg = "ReadKey failed: $_" }
            Write-Verbose $verboseMsg
        }
        
        # NO FLUSH AFTER VERIFY!
        # User already pressed key to continue - flushing would consume that key or KeyUp event
        # causing them to press twice before menu responds
    }
    return $null
}

function Invoke-RebootPrompt {
    <#
    .SYNOPSIS
        Benutzerfreundliche Reboot-Abfrage mit Wahlmoeglichkeiten
    .DESCRIPTION
        Best Practice 25H2: User kann waehlen zwischen Jetzt/Spaeter/Abbrechen.
        Restart-Computer mit Error-Handling fuer Berechtigungsprobleme.
    .PARAMETER SkipReboot
        ueberspringt die Reboot-Abfrage und zeigt nur eine Warnung
    .EXAMPLE
        Invoke-RebootPrompt
    .EXAMPLE
        Invoke-RebootPrompt -SkipReboot
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [switch]$SkipReboot
    )
    
    if ($SkipReboot) {
        Write-Host ""
        Write-Host "[!] $(Get-LocalizedString 'RebootSkipped')" -ForegroundColor Yellow
        Write-Host "   $(Get-LocalizedString 'RebootSkippedWarning')" -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "                          $(Get-LocalizedString 'RebootTitle')" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'RebootChanges')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  * $(Get-LocalizedString 'RebootVBS')" -ForegroundColor White
    Write-Host "  * $(Get-LocalizedString 'RebootBitLocker')" -ForegroundColor White
    Write-Host "  * $(Get-LocalizedString 'RebootFirewall')" -ForegroundColor White
    Write-Host "  * $(Get-LocalizedString 'RebootServices')" -ForegroundColor White
    Write-Host "  * $(Get-LocalizedString 'RebootRegistry')" -ForegroundColor White
    Write-Host "  * $(Get-LocalizedString 'RebootPerformance')" -ForegroundColor White
    Write-Host ""
    Write-Host "  [!] $(Get-LocalizedString 'RebootWarning')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'RebootQuestion')" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [J] $(Get-LocalizedString 'RebootNow')" -ForegroundColor Green
    Write-Host "         $(Get-LocalizedString 'RebootNowDesc')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [N] $(Get-LocalizedString 'RebootLater')" -ForegroundColor Yellow
    Write-Host "         $(Get-LocalizedString 'RebootLaterDesc')" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $promptText = Get-LocalizedString "RebootPrompt"
    if (-not $promptText) { $promptText = "Ihre Wahl" }
    
    $choiceFormat = Get-LocalizedString "RebootChoiceFormat"
    if (-not $choiceFormat) { $choiceFormat = "[Y/N]:" }
    
    do {
        Write-Host "  $promptText " -NoNewline -ForegroundColor Cyan
        Write-Host "$choiceFormat " -NoNewline -ForegroundColor Gray
        $choice = Read-Host
        
        # Input validation: Trim and ToUpper with null check
        if ($choice) {
            $choice = $choice.Trim().ToUpper()
        }
        
        # Support for Y (English: Yes = Ja)
        if ($choice -eq 'Y') { $choice = 'J' }
        
        if ($choice -notin @('J', 'N')) {
            $errorMsg = Get-LocalizedString 'ErrorInvalidInput'
            if (-not $errorMsg) { $errorMsg = "Ungueltige Eingabe! Bitte eingeben:" }
            Write-Host "  [ERROR] $errorMsg J/N (oder Y/N)!" -ForegroundColor Red
            Write-Host ""
        }
    } while ($choice -notin @('J', 'N'))
    
    Write-Host ""
    
    switch ($choice) {
        'J' {
            Write-Host "  [OK] $(Get-LocalizedString 'RebootStarting')" -ForegroundColor Green
            Write-Host ""
            Write-Host "  $(Get-LocalizedString 'RebootCountdown')" -ForegroundColor Yellow
            
            for ($i = 10; $i -gt 0; $i--) {
                Write-Host "  $i $(Get-LocalizedString 'RebootSeconds') " -NoNewline -ForegroundColor Yellow
                if ($i -eq 10) {
                    Write-Host "$(Get-LocalizedString 'RebootAbortHint')" -ForegroundColor Gray
                } else {
                    Write-Host ""
                }
                Start-Sleep -Seconds 1
            }
            
            Write-Host ""
            Write-Host "  $(Get-LocalizedString 'RebootStarting')" -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            
            # Restart-Computer with error handling
            try {
                Restart-Computer -Force -ErrorAction Stop
            }
            catch {
                Write-Host ""
                Write-Host "  [ERROR] $(Get-LocalizedString 'RebootErrorTitle')" -ForegroundColor Red
                Write-Host "  $(Get-LocalizedString 'RebootErrorDetails' $_)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  $(Get-LocalizedString 'RebootManualRestartPrompt')" -ForegroundColor Yellow
                Write-Host "  $(Get-LocalizedString 'RebootManualRestartCommand')" -ForegroundColor Cyan
            }
        }
        'N' {
            Write-Host "  [!] $(Get-LocalizedString 'RebootPostponed')" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [!] $(Get-LocalizedString 'RebootImportant')" -ForegroundColor Red
            Write-Host "  $(Get-LocalizedString 'RebootFeaturesActive')" -ForegroundColor Yellow
            Write-Host "  - VBS/Credential Guard" -ForegroundColor Gray
            Write-Host "  - $(Get-LocalizedString 'RebootFirewall')" -ForegroundColor Gray
            Write-Host "  - $(Get-LocalizedString 'RebootServices')" -ForegroundColor Gray
            Write-Host "  - $(Get-LocalizedString 'RebootPerformance')" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  $(Get-LocalizedString 'RebootManualCommand')" -ForegroundColor Cyan
        }
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-SafetyWarning {
    <#
    .SYNOPSIS
        Shows critical safety warning before script execution
    .DESCRIPTION
        Displays mandatory safety warning requiring user acknowledgment.
        User MUST confirm README read and system backup created.
        ASCII-only for maximum compatibility (no emojis, escaped umlauts).
    .OUTPUTS
        Exits script if user declines
    .EXAMPLE
        Show-SafetyWarning
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                   !!! CRITICAL SAFETY WARNING !!!" -ForegroundColor Yellow  
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    if ($Global:CurrentLanguage -eq 'de') {
        Write-Host "  DIESES SCRIPT FUEHRT UMFANGREICHE SYSTEM-HAERTUNGEN DURCH!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Bevor Sie fortfahren:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Lesen Sie die README.md VOLLSTAENDIG" -ForegroundColor Cyan
        Write-Host "      -> Verstehen Sie was das Script tut" -ForegroundColor Gray
        Write-Host "      -> Pruefen Sie ob es zu Ihrem Anwendungsfall passt" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  2. Erstellen Sie ein VOLLSTAENDIGES SYSTEM-BACKUP" -ForegroundColor Cyan
        Write-Host "      -> Windows Systemabbild ODER VM-Snapshot" -ForegroundColor Gray
        Write-Host "      -> Fuer maximale Sicherheit empfohlen!" -ForegroundColor Gray
        Write-Host "      -> Garantiert 100% Wiederherstellung" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  WARUM SO WICHTIG?" -ForegroundColor Yellow
        Write-Host "  * Script haertet Windows sehr strikt (Sicherheit > Komfort)" -ForegroundColor White
        Write-Host "  * Manche Funktionen werden stark eingeschraenkt" -ForegroundColor White
        Write-Host "  * Je nach Anwendungsfall evtl. nicht passend" -ForegroundColor White
        Write-Host "  * Windows wird NICHT kaputt gehen - aber Vorsicht ist besser!" -ForegroundColor White
        Write-Host ""
        Write-Host "  Hinweis:" -ForegroundColor Cyan
        Write-Host "  - Script erstellt automatisch Backup aller Einstellungen" -ForegroundColor Gray
        Write-Host "  - Restore-Funktion ist integriert" -ForegroundColor Gray
        Write-Host "  - Trotzdem: Vollstaendiges System-Backup dringend empfohlen!" -ForegroundColor Gray
        Write-Host ""
    }
    else {
        Write-Host "  THIS SCRIPT PERFORMS EXTENSIVE SYSTEM HARDENING!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Before you proceed:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Read the README.md COMPLETELY" -ForegroundColor Cyan
        Write-Host "      -> Understand what this script does" -ForegroundColor Gray
        Write-Host "      -> Check if it fits your use case" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  2. Create a FULL SYSTEM BACKUP" -ForegroundColor Cyan
        Write-Host "      -> Windows System Image OR VM Snapshot" -ForegroundColor Gray
        Write-Host "      -> Recommended for maximum safety!" -ForegroundColor Gray
        Write-Host "      -> Guarantees 100% recovery" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  WHY SO IMPORTANT?" -ForegroundColor Yellow
        Write-Host "  * Script hardens Windows very strictly (Security > Comfort)" -ForegroundColor White
        Write-Host "  * Some functions will be heavily restricted" -ForegroundColor White
        Write-Host "  * Depending on use case, may not be suitable" -ForegroundColor White
        Write-Host "  * Windows will NOT break - but better safe than sorry!" -ForegroundColor White
        Write-Host ""
        Write-Host "  Note:" -ForegroundColor Cyan
        Write-Host "  - Script automatically creates backup of all settings" -ForegroundColor Gray
        Write-Host "  - Restore function is integrated" -ForegroundColor Gray
        Write-Host "  - Nevertheless: Full system backup is strongly recommended!" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "                           DISCLAIMER" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    if ($Global:CurrentLanguage -eq 'de') {
        Write-Host "  Die Autoren uebernehmen KEINE Haftung fuer:" -ForegroundColor Yellow
        Write-Host "  * Datenverlust" -ForegroundColor White
        Write-Host "  * Systemschaeden" -ForegroundColor White
        Write-Host "  * Funktionsbeeintraechtigungen" -ForegroundColor White
        Write-Host "  * Andere Probleme durch die Ausfuehrung dieses Scripts" -ForegroundColor White
        Write-Host ""
        Write-Host "  Sie verwenden dieses Script auf EIGENE GEFAHR!" -ForegroundColor Yellow
    }
    else {
        Write-Host "  The authors are NOT responsible for:" -ForegroundColor Yellow
        Write-Host "  * Data loss" -ForegroundColor White
        Write-Host "  * System damage" -ForegroundColor White
        Write-Host "  * Functional impairments" -ForegroundColor White
        Write-Host "  * Any other issues caused by running this script" -ForegroundColor White
        Write-Host ""
        Write-Host "  You use this script at YOUR OWN RISK!" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    # Get localized safety check messages
    $safetyQuestion = Get-LocalizedString 'SafetyCheckQuestion'
    $safetyYes = Get-LocalizedString 'SafetyCheckYes'
    $safetyNo = Get-LocalizedString 'SafetyCheckNo'
    
    # Fallback if localization fails
    if (-not $safetyQuestion) {
        if ($Global:CurrentLanguage -eq 'de') {
            $safetyQuestion = "Haben Sie die README gelesen UND ein System-Backup erstellt?"
            $safetyYes = "Ja, ich habe alles gelesen und ein Backup erstellt"
            $safetyNo = "Nein, ich breche ab"
        }
        else {
            $safetyQuestion = "Have you read the README AND created a system backup?"
            $safetyYes = "Yes, I have read everything and created a backup"
            $safetyNo = "No, I will cancel"
        }
    }
    
    $yesKey = if ($Global:CurrentLanguage -eq 'de') { "[J]" } else { "[Y]" }
    
    Write-Host "  $safetyQuestion" -ForegroundColor Cyan
    Write-Host "  $yesKey $safetyYes" -ForegroundColor Green
    Write-Host "  [N] $safetyNo" -ForegroundColor Yellow
    
    Write-Host ""
    
    # Get localized prompt
    $inputPrompt = Get-LocalizedString 'UserInputPrompt'
    if (-not $inputPrompt) { 
        $inputPrompt = if ($Global:CurrentLanguage -eq 'de') { "Ihre Eingabe" } else { "Your input" }
    }
    
    $choiceFormat = Get-LocalizedString 'RebootChoiceFormat'
    if (-not $choiceFormat) { 
        $choiceFormat = if ($Global:CurrentLanguage -eq 'de') { "[J/N]:" } else { "[Y/N]:" }
    }
    
    do {
        Write-Host "  $inputPrompt $choiceFormat " -NoNewline -ForegroundColor Cyan
        
        $userAck = Read-Host
        if ($userAck) {
            $userAck = $userAck.Trim().ToUpper()
        }
        
        # Support Y=J, J=Y
        if ($userAck -eq 'Y') { $userAck = 'J' }
        if ($userAck -eq 'S') { $userAck = 'N' }
        
        if ($userAck -notin @('J', 'N')) {
            if ($Global:CurrentLanguage -eq 'de') {
                Write-Host "  [ERROR] Ungueltige Eingabe! Bitte J oder N eingeben." -ForegroundColor Red
            }
            else {
                Write-Host "  [ERROR] Invalid input! Please enter Y or N." -ForegroundColor Red
            }
            Write-Host ""
        }
    } while ($userAck -notin @('J', 'N'))
    
    if ($userAck -eq 'N') {
        Write-Host ""
        if ($Global:CurrentLanguage -eq 'de') {
            Write-Host "  [i] Script abgebrochen - Gute Entscheidung!" -ForegroundColor Yellow
            Write-Host "      Bitte lesen Sie die README und erstellen Sie ein Backup." -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Dateien:" -ForegroundColor Cyan
            Write-Host "  * README.md - Vollstaendige Dokumentation" -ForegroundColor White
            Write-Host "  * CHANGELOG.md - Was macht das Script genau?" -ForegroundColor White
            Write-Host "  * FAQ.md - Haeufige Fragen" -ForegroundColor White
        }
        else {
            Write-Host "  [i] Script cancelled - Good decision!" -ForegroundColor Yellow
            Write-Host "      Please read the README and create a backup." -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Files:" -ForegroundColor Cyan
            Write-Host "  * README.md - Complete documentation" -ForegroundColor White
            Write-Host "  * CHANGELOG.md - What does the script do exactly?" -ForegroundColor White
            Write-Host "  * FAQ.md - Frequently asked questions" -ForegroundColor White
        }
        Write-Host ""
        exit 0
    }
    
    Write-Host ""
    if ($Global:CurrentLanguage -eq 'de') {
        Write-Host "  [OK] Bestaetigt - Script wird fortgesetzt..." -ForegroundColor Green
    }
    else {
        Write-Host "  [OK] Confirmed - Script will continue..." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
}

function Start-InteractiveMode {
    <#
    .SYNOPSIS
        Startet den interaktiven Modus
    .DESCRIPTION
        Hauptfunktion fuer das interaktive Menue-System.
        Best Practice 25H2: Select-Language Existenz-Check, Add-Member Validierung.
    .PARAMETER LogPath
        Pfad zur Log-Datei (optional, wird aktuell nicht verwendet)
    .OUTPUTS
        [hashtable] Konfigurations-Hashtable oder $null bei Exit
    .EXAMPLE
        $config = Start-InteractiveMode
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [string]$LogPath
    )
    
    # Language selection at first start - with existence check
    if (Get-Command -Name Select-Language -ErrorAction SilentlyContinue) {
        try {
            Select-Language
        }
        catch {
            Write-Warning "Sprachauswahl fehlgeschlagen: $_"
            Write-Verbose "Fallback auf Standard-Sprache"
        }
    }
    else {
        Write-Verbose "Select-Language Funktion nicht verfuegbar - verwende Fallback"
    }
    
    # VERSION BANNER was removed - now shown AFTER Start-Transcript in main script!
    # Reason: Interactive mode starts BEFORE transcript, so banner would not appear in log
    
    # === CRITICAL SAFETY WARNING (AFTER LANGUAGE SELECTION!) ===
    Show-SafetyWarning
    
    # === NEW: BACKUP/RESTORE PROMPT (AFTER LANGUAGE, BEFORE MODULES!) ===
    $backupChoice = Show-BackupPrompt
    
    # Handle Backup-Choice Actions
    if ($backupChoice.Action -eq 'Exit') {
        # User cancelled
        return $null
    }
    elseif ($backupChoice.Action -eq 'Restore') {
        # User wants restore - return special config
        return @{
            Action = 'Restore'
            Mode = 'Restore'
        }
    }
    
    # Remember if Backup or NoBackup
    $createRestorePoint = ($backupChoice.Action -eq 'NoBackup')
    $createBackup = ($backupChoice.Action -eq 'Backup')
    
    $continue = $true
    
    while ($continue) {
        Show-MainMenu
        
        # NO FLUSH NEEDED!
        # Previous flush system was symptom-fix for Exit bug (Array pollution)
        # Root cause fixed with Array cleanup (Lines 777-824 in Apply script)
        # Buffer is clean after normal ReadKey operations
        
        $promptText = Get-LocalizedString 'MainMenuPrompt'
        $choice = Get-UserChoice -Prompt $promptText -ValidChoices @('1', '2', '3', '4', '5')
        
        $config = $null
        
        switch ($choice) {
            '1' { 
                $config = Invoke-AuditMode 
            }
            '2' { $config = Invoke-EnforceMode }
            '3' { $config = Invoke-CustomMode }
            '4' { Invoke-VerifyMode; continue }
            '5' { 
                Show-Banner
                $goodbyeMsg = Get-LocalizedString 'Goodbye'
                if (-not $goodbyeMsg) { $goodbyeMsg = "Auf Wiedersehen!" }
                Write-Host "  $goodbyeMsg" -ForegroundColor Cyan
                Write-Host ""
                $continue = $false
                return $null
            }
        }
        
        if ($null -ne $config) {
            # Best Practice 25H2: Overwrite Backup/Restore Point settings
            # from Show-BackupPrompt, not just add!
            
            # IMPORTANT: $config is a Hashtable, NOT PSCustomObject!
            # Therefore: Use direct assignment, NO Add-Member!
            
            # Overwrite CreateRestorePoint (always works with hashtables)
            $config.CreateRestorePoint = $createRestorePoint
            Write-Verbose "CreateRestorePoint gesetzt: $createRestorePoint"
            
            # Overwrite CreateBackup (always works with hashtables)
            $config.CreateBackup = $createBackup
            Write-Verbose "CreateBackup gesetzt: $createBackup"
            
            return $config
        }
    }
    
    return $null
}

function Show-BackupPrompt {
    <#
    .SYNOPSIS
        Zeigt Backup & Restore Prompt an
    .DESCRIPTION
        Fragt den Benutzer ob ein vollstaendiges Backup erstellt werden soll.
        Bietet 3 Optionen: [J] Backup erstellen, [N] Kein Backup, [R] Restore von Backup
        Best Practice 25H2: Klare Kommunikation, Restore-Integration, Input-Validierung.
    .OUTPUTS
        [hashtable] @{Action='Backup'|'NoBackup'|'Restore'|'Exit'; Success=$true|$false}
    .EXAMPLE
        $result = Show-BackupPrompt
        if ($result.Action -eq 'Restore') { exit 0 }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    # Clear-Host with error handling
    try {
        Clear-Host
    }
    catch {
        Write-Verbose "Clear-Host nicht verfuegbar (non-interactive session)"
    }
    
    Write-Host ""
    Write-Host "=============================================================================" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "                NoID Privacy - Windows 11 25H2 Baseline" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "               Maximum Security + Privacy + Performance" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "=============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check ob $Global:CurrentLanguage existiert
    $isGerman = $false
    if (Test-Path Variable:\Global:CurrentLanguage) {
        $isGerman = ($Global:CurrentLanguage -eq 'de')
    }
    
    if ($isGerman) {
        Write-Host "  Dieses Script aendert viele System-Einstellungen!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  BACKUP erstellt vollstaendige Sicherung von 494 Einstellungen:" -ForegroundColor White
        Write-Host "    - DNS Settings + DoH (meist Router-DNS, kein DoH)" -ForegroundColor Gray
        Write-Host "    - Hosts-Datei (Windows-Default ~5 Zeilen, ohne 107.772 Domains Blocklist)" -ForegroundColor Gray
        Write-Host "    - Installierte Apps (Liste mit Namen, NICHT die Apps selbst)" -ForegroundColor Gray
        Write-Host "    - Services (25+ Services die Script aendert)" -ForegroundColor Gray
        Write-Host "    - Firewall (alle Regeln + 3 Profile Domain/Private/Public)" -ForegroundColor Gray
        Write-Host "    - Scheduled Tasks (30 Tasks die Script aendert)" -ForegroundColor Gray
        Write-Host "    - Registry (391 Keys die Script aendert)" -ForegroundColor Gray
        Write-Host "    - Built-in Admin (Name 'Administrator' + Enabled=$false)" -ForegroundColor Gray
        Write-Host "    - ASR (19 Regeln) + Exploit Protection (13 Mitigations)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  WIEDERHERSTELLUNG:" -ForegroundColor Cyan
        Write-Host "     Fuehre einfach aus: " -NoNewline -ForegroundColor Gray
        Write-Host "Restore-SecurityBaseline.ps1" -ForegroundColor Yellow
        Write-Host "     100% Wiederherstellung aller Einstellungen!" -ForegroundColor Green
        Write-Host ""
        Write-Host "=============================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Was moechten Sie tun?" -ForegroundColor White
        Write-Host ""
        Write-Host "  [J] Backup erstellen und fortfahren (EMPFOHLEN!)" -ForegroundColor Green
        Write-Host "         Dauert ca. 2-3 Minuten (max. 6 Min)" -ForegroundColor Gray
        Write-Host "         Bei Problemen: Vollstaendige Wiederherstellung!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [N] Kein Backup (nur Windows Restore Point)" -ForegroundColor Yellow
        Write-Host "         Schneller Start" -ForegroundColor Gray
        Write-Host "         WARNUNG: Nur ~70% wiederherstellbar!" -ForegroundColor Yellow
        Write-Host "         DNS, Hosts, Apps NICHT wiederherstellbar!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [R] Backup WIEDERHERSTELLEN" -ForegroundColor Cyan
        Write-Host "         Macht alle Aenderungen rueckgaengig!" -ForegroundColor Gray
        Write-Host "         System wird auf Backup-Zustand zurueckgesetzt" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [0] Abbrechen" -ForegroundColor Gray
        Write-Host ""
        Write-Host "=============================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        do {
            Write-Host "  Ihre Wahl " -NoNewline -ForegroundColor Cyan
            Write-Host "[J/N/R/0]" -NoNewline -ForegroundColor White
            Write-Host " (Empfohlen: J): " -NoNewline -ForegroundColor Gray
            $choice = Read-Host
            
            # Input-Validierung
            if ($choice) {
                $choice = $choice.Trim().ToUpper()
            }
            else {
                $choice = ''
            }
            
            # Support for Y (English)
            if ($choice -eq 'Y') { $choice = 'J' }
            
            if ($choice -notin @('J', 'N', 'R', '0', '')) {
                Write-Host "  [ERROR] Ungueltige Eingabe! Bitte J, N, R oder 0 eingeben." -ForegroundColor Red
                Write-Host ""
            }
        } while ($choice -notin @('J', 'N', 'R', '0', ''))
        
        # Leere Eingabe = Standard (Ja, Backup)
        if ($choice -eq '' -or $choice -eq 'J') {
            Write-Host ""
            Write-Host "  [OK] Vollstaendiges Backup wird erstellt" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return @{Action='Backup'; Success=$true}
        }
        elseif ($choice -eq 'N') {
            Write-Host ""
            Write-Host "  [!] KEIN Backup - nur Windows Restore Point" -ForegroundColor Yellow
            Write-Host "      Warnung: Nur ~70% wiederherstellbar!" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return @{Action='NoBackup'; Success=$true}
        }
        elseif ($choice -eq 'R') {
            Write-Host ""
            Write-Host "  [i] Starte Restore-Prozess..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            return @{Action='Restore'; Success=$true}
        }
        else {
            Write-Host ""
            Write-Host "  [!] Abgebrochen" -ForegroundColor Yellow
            return @{Action='Exit'; Success=$false}
        }
    }
    else {
        # English Version
        Write-Host "  This script will change many system settings!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  BACKUP creates complete copy of 494 settings:" -ForegroundColor White
        Write-Host "  - DNS Settings + DoH (usually Router-DNS, no DoH)" -ForegroundColor Gray
        Write-Host "  - Hosts file (Windows default ~5 lines, without 107,772 domains blocklist)" -ForegroundColor Gray
        Write-Host "  - Installed Apps (list with names, NOT the apps themselves)" -ForegroundColor Gray
        Write-Host "  - Services (25+ services that script modifies)" -ForegroundColor Gray
        Write-Host "  - Firewall (all rules + 3 profiles Domain/Private/Public)" -ForegroundColor Gray
        Write-Host "  - Scheduled Tasks (30 tasks that script modifies)" -ForegroundColor Gray
        Write-Host "  - Registry (391 keys that script modifies)" -ForegroundColor Gray
        Write-Host "  - Built-in Admin (name 'Administrator' + Enabled=$false)" -ForegroundColor Gray
        Write-Host "  - ASR (19 rules) + Exploit Protection (13 mitigations)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  RESTORE:" -ForegroundColor Cyan
        Write-Host "     Simply run: " -NoNewline -ForegroundColor Gray
        Write-Host "Restore-SecurityBaseline.ps1" -ForegroundColor Yellow
        Write-Host "     100% restoration of all settings!" -ForegroundColor Green
        Write-Host ""
        Write-Host "=============================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What would you like to do?" -ForegroundColor White
        Write-Host ""
        Write-Host "  [Y] Create backup and continue (RECOMMENDED!)" -ForegroundColor Green
        Write-Host "         Takes about 2-3 minutes (max. 6 min)" -ForegroundColor Gray
        Write-Host "         If problems occur: Full restoration!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [N] No backup (only Windows Restore Point)" -ForegroundColor Yellow
        Write-Host "         Faster start" -ForegroundColor Gray
        Write-Host "         WARNING: Only ~70% restorable!" -ForegroundColor Yellow
        Write-Host "         DNS, Hosts, Apps NOT restorable!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [R] RESTORE from backup" -ForegroundColor Cyan
        Write-Host "         Reverts all changes!" -ForegroundColor Gray
        Write-Host "         System will be reset to backup state" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [0] Cancel" -ForegroundColor Gray
        Write-Host ""
        Write-Host "=============================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        do {
            Write-Host "  Your choice " -NoNewline -ForegroundColor Cyan
            Write-Host "[Y/N/R/0]" -NoNewline -ForegroundColor White
            Write-Host " (Recommended: Y): " -NoNewline -ForegroundColor Gray
            $choice = Read-Host
            
            # Input validation
            if ($choice) {
                $choice = $choice.Trim().ToUpper()
            }
            else {
                $choice = ''
            }
            
            # Support for J (German)
            if ($choice -eq 'J') { $choice = 'Y' }
            
            if ($choice -notin @('Y', 'N', 'R', '0', '')) {
                Write-Host "  [ERROR] Invalid input! Please enter Y, N, R or 0." -ForegroundColor Red
                Write-Host ""
            }
        } while ($choice -notin @('Y', 'N', 'R', '0', ''))
        
        # Empty input = Default (Yes, Backup)
        if ($choice -eq '' -or $choice -eq 'Y') {
            Write-Host ""
            Write-Host "  [OK] Complete backup will be created" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return @{Action='Backup'; Success=$true}
        }
        elseif ($choice -eq 'N') {
            Write-Host ""
            Write-Host "  [!] NO Backup - only Windows Restore Point" -ForegroundColor Yellow
            Write-Host "      Warning: Only ~70% restorable!" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return @{Action='NoBackup'; Success=$true}
        }
        elseif ($choice -eq 'R') {
            Write-Host ""
            Write-Host "  [i] Starting restore process..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            return @{Action='Restore'; Success=$true}
        }
        else {
            Write-Host ""
            Write-Host "  [!] Cancelled" -ForegroundColor Yellow
            return @{Action='Exit'; Success=$false}
        }
    }
}

function Show-DNSProviderMenu {
    <#
    .SYNOPSIS
        Shows DNS provider selection menu
    .DESCRIPTION
        Allows user to choose between Cloudflare, AdGuard, NextDNS, Quad9, or keep existing DNS
        Fully localized (EN/DE) with Get-LocalizedString
    .OUTPUTS
        String: '1' (Cloudflare), '2' (AdGuard), '3' (NextDNS), '4' (Quad9), '5' (Keep existing)
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n===========================================================" -ForegroundColor Cyan
    Write-Host "  $(Get-LocalizedString 'DNSMenuTitle')" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host (Get-LocalizedString 'DNSMenuPrompt') -ForegroundColor White
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuOption1')" -ForegroundColor Yellow
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption1Speed')" -ForegroundColor Gray
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption1Desc')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuOption2')" -ForegroundColor Yellow
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption2Speed')" -ForegroundColor Gray
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption2Desc')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuOption3')" -ForegroundColor Yellow
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption3Speed')" -ForegroundColor Gray
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption3Desc')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuOption4')" -ForegroundColor Yellow
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption4Speed')" -ForegroundColor Gray
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption4Desc')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuOption5')" -ForegroundColor Yellow
    Write-Host "      $(Get-LocalizedString 'DNSMenuOption5Desc')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'DNSMenuRecommendation')" -ForegroundColor Cyan
    Write-Host ""
    
    do {
        $choice = Read-Host (Get-LocalizedString 'DNSMenuChoice')
    } while ($choice -notin @('1','2','3','4','5'))
    
    return $choice
}

function Show-OneDriveMenu {
    <#
    .SYNOPSIS
        Shows OneDrive handling menu
    .DESCRIPTION
        Allows user to choose between privacy hardening, complete removal, or skip
        Fully localized (EN/DE) with Get-LocalizedString
    .OUTPUTS
        String: '1' (Hardening), '2' (Remove), '3' (Skip)
    #>
    [CmdletBinding()]
    param()
    
    $title = Get-LocalizedString 'OneDriveMenuTitle'
    $question = Get-LocalizedString 'OneDriveMenuQuestion'
    
    Write-Host "`n===========================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$question" -ForegroundColor White
    Write-Host ""
    
    # Option 1
    Write-Host "  [1] $(Get-LocalizedString 'OneDriveMenuOption1')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption1Desc1')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption1Desc2')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption1Desc3')" -ForegroundColor Gray
    Write-Host ""
    
    # Option 2
    Write-Host "  [2] $(Get-LocalizedString 'OneDriveMenuOption2')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption2Desc1')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption2Warning')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption2Desc2')" -ForegroundColor Green
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption2Desc3')" -ForegroundColor Gray
    Write-Host ""
    
    # Option 3
    Write-Host "  [3] $(Get-LocalizedString 'OneDriveMenuOption3')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'OneDriveMenuOption3Desc')" -ForegroundColor Gray
    Write-Host ""
    
    $prompt = Get-LocalizedString 'OneDriveMenuPrompt'
    do {
        $choice = Read-Host "$prompt"
    } while ($choice -notin @('1','2','3'))
    
    return $choice
}

function Show-RemoteAccessMenu {
    <#
    .SYNOPSIS
        Shows Remote Access (RDP) configuration menu
    .DESCRIPTION
        Allows user to configure Remote Desktop (RDP) and Firewall strictness
        Important for: Remote servers, NUC with Tailscale, Development machines with local services
        Fully localized (EN/DE) with Get-LocalizedString
    .OUTPUTS
        String: '1' (Disable RDP + Strict Firewall), '2' (Keep RDP + Allow localhost)
    #>
    [CmdletBinding()]
    param()
    
    $title = Get-LocalizedString 'RemoteMenuTitle'
    $question = Get-LocalizedString 'RemoteMenuQuestion'
    
    Write-Host "`n===========================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$question" -ForegroundColor White
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'RemoteMenuExamples')" -ForegroundColor Cyan
    Write-Host "  - $(Get-LocalizedString 'RemoteMenuExample1')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RemoteMenuExample2')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RemoteMenuExample3')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RemoteMenuExample4')" -ForegroundColor Gray
    Write-Host "  - $(Get-LocalizedString 'RemoteMenuExample5')" -ForegroundColor Gray
    Write-Host ""
    
    # Option 1
    Write-Host "  [1] $(Get-LocalizedString 'RemoteMenuOption1')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Desc1')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Desc2')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Desc3')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Desc4')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Pro')" -ForegroundColor Green
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Con')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption1Warning1')" -ForegroundColor Yellow
    Write-Host "        $(Get-LocalizedString 'RemoteMenuOption1Warning2')" -ForegroundColor Yellow
    Write-Host ""
    
    # Option 2
    Write-Host "  [2] $(Get-LocalizedString 'RemoteMenuOption2')" -ForegroundColor Yellow
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Desc1')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Desc2')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Desc3')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Desc4')" -ForegroundColor Gray
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Pro1')" -ForegroundColor Green
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Pro2')" -ForegroundColor Green
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Pro3')" -ForegroundColor Green
    Write-Host "      - $(Get-LocalizedString 'RemoteMenuOption2Con')" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  $(Get-LocalizedString 'RemoteMenuRecommendation')" -ForegroundColor Cyan
    Write-Host ""
    
    $prompt = Get-LocalizedString 'RemoteMenuPrompt'
    do {
        $choice = Read-Host "$prompt"
    } while ($choice -notin @('1','2'))
    
    return $choice
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
