# =======================================================================================
# SecurityBaseline-Localization.ps1 - Multi-Language Support (EN/DE)
# =======================================================================================

# Strict Mode aktivieren
Set-StrictMode -Version Latest

# Default: English (nur wenn noch nicht gesetzt!)
# WICHTIG: Nicht überschreiben wenn bereits gesetzt (z.B. von Parent-Script)
# WICHTIG: Test-Path verwenden wegen Strict Mode!
if (-not (Test-Path Variable:\Global:CurrentLanguage)) {
    $Global:CurrentLanguage = "en"
}

$Global:Strings = @{
    en = @{
        # Banner
        BannerTitle = "NoID Privacy - Windows 11 25H2 Security Baseline"
        BannerSubtitle = "Maximum Security + Privacy + Performance"
        
        # Main Menu
        MainMenuTitle = "MAIN MENU"
        MainMenuAudit = "Audit Mode"
        MainMenuAuditDesc = "Check only, change NOTHING (recommended for testing)"
        MainMenuEnforce = "Enforce Mode"
        MainMenuEnforceDesc = "Apply EVERYTHING (full hardening)"
        MainMenuCustom = "Custom Mode"
        MainMenuCustomDesc = "Select modules individually"
        MainMenuVerify = "Verify"
        MainMenuVerifyDesc = "Check if baseline is applied"
        MainMenuExit = "Exit"
        MainMenuExitDesc = "Quit"
        MainMenuPrompt = "Your choice"
        
        # Language Selection
        LanguagePrompt = "Select language / Sprache waehlen"
        LanguageEnglish = "English"
        LanguageGerman = "German / Deutsch"
        
        # Module Selection
        ModuleSelectionTitle = "MODULE SELECTION (Custom Mode)"
        ModuleSelectionInstructions = "Use UP/DOWN to navigate, SPACE to enable/disable"
        ModuleSelectionConfirm = "ENTER to confirm and start"
        ModuleMandatory = "(Mandatory)"
        
        # Modules
        ModuleCore = "Security Baseline Core"
        ModuleCoreDesc = "Base hardening - NetBIOS + Auditing + Print Spooler + etc."
        ModuleASR = "ASR Rules (Attack Surface Reduction)"
        ModuleASRDesc = "19 ASR rules + USB Control + Smart App Control"
        ModuleAdvanced = "Advanced Security"
        ModuleAdvancedDesc = "VBS + Credential Guard + BitLocker + LAPS"
        ModuleDNS = "DNS Security"
        ModuleDNSDesc = "DNSSEC + DNS Blocklist (80K Domains) + Firewall"
        ModuleBloatware = "Bloatware Removal"
        ModuleBloatwareDesc = "Remove pre-installed apps - games and ads"
        ModuleTelemetry = "Telemetry Deactivation"
        ModuleTelemetryDesc = "95% telemetry disabled"
        ModulePerformance = "Performance Optimization"
        ModulePerformanceDesc = "Scheduled Tasks + Event Logs + Background Activities"
        
        # Reboot Prompt
        RebootTitle = "REBOOT REQUIRED"
        RebootChanges = "The following changes require a reboot:"
        RebootVBS = "VBS/Credential Guard (Hardware-Security)"
        RebootBitLocker = "BitLocker Policies"
        RebootFirewall = "Firewall Rules"
        RebootServices = "Service Changes"
        RebootRegistry = "Registry Settings"
        RebootPerformance = "Performance Optimizations"
        RebootWarning = "Without reboot, some features are NOT active!"
        RebootQuestion = "What would you like to do?"
        RebootNow = "Reboot now"
        RebootNowDesc = "Countdown 10 seconds, then reboot"
        RebootLater = "Reboot later"
        RebootLaterDesc = "You must reboot manually!"
        RebootPrompt = "Your choice"
        RebootCountdown = "Reboot in:"
        RebootSeconds = "seconds..."
        RebootAbortHint = "(CTRL+C to abort)"
        RebootStarting = "System is rebooting..."
        RebootPostponed = "Reboot was postponed."
        RebootImportant = "IMPORTANT: Please reboot your computer manually!"
        RebootFeaturesActive = "The following features are only active after reboot:"
        RebootManualCommand = "You can reboot now with 'shutdown /r /t 0'."
        RebootSkipped = "Reboot was skipped (-SkipReboot parameter)"
        RebootSkippedWarning = "Some changes will only be active after reboot!"
        
        # CTRL+C Handler
        AbortUserCancelled = "[ABORT] User cancelled script with CTRL+C!"
        AbortCleanup = "[i] Performing cleanup..."
        AbortComplete = "[OK] Cleanup complete"
        AbortExited = "[i] Script safely terminated"
        
        # Instance/Mutex Errors
        ErrorInstanceRunning = "[ERROR] Script is already running!"
        ErrorInstanceParallel = "The Security Baseline Script cannot be executed in parallel."
        ErrorInstanceReason = "Reason: Registry/Service changes would interfere with each other."
        ErrorInstanceWait = "Please wait until the other instance finishes."
        
        # Module Loading
        InfoCalculatingOrder = "[i] Calculating module load order..."
        InfoLoadingModules = "[i] Loading modules..."
        InfoLoadedModule = "[i] Module loaded:"
        ErrorLoadModule = "[ERROR] Could not load module:"
        
        # Restore Mode Messages
        RestoreModeActivated = "RESTORE MODE ACTIVATED"
        RestoreModeApplyExiting = "[i] Apply-Script is EXITING"
        RestoreModeStarting = "[i] Restore-Script starting..."
        RestoreModeProcessStart = "[i] Starting restore process (please wait)..."
        RestoreModeScriptComplete = "[i] Restore-Script completed (Exit-Code: {0})"
        RestoreModeApplyExitNow = "[i] Apply-Script exiting NOW (Environment.Exit)..."
        RestoreModeNotFound = "[ERROR] Restore-Script not found: {0}"
        
        # Backup Creation Messages
        BackupFullCreating = "COMPLETE BACKUP BEING CREATED"
        BackupIncludes = "[i] Backup includes:"
        BackupIncludesDNS = "    - DNS Settings (all adapters)"
        BackupIncludesHosts = "    - Hosts file (current version)"
        BackupIncludesServices = "    - All Services (StartType)"
        BackupIncludesFirewall = "    - Firewall Rules (status)"
        BackupIncludesRegistry = "    - Registry Keys (important ones)"
        BackupIncludesUsers = "    - User Accounts (names)"
        BackupIncludesApps = "    - Installed Apps (list)"
        BackupDuration = "[i] Expected duration: 2-3 minutes (max 6 min)"
        BackupRunning = "[i] Backup running now - please wait..."
        BackupFailed = "[ERROR] Backup failed (Exit-Code: {0})"
        BackupContinueRP = "Continuing with Restore Point only..."
        BackupNotFound = "[WARNING] Backup-Script not found: {0}"
        BackupFallbackRP = "[WARNING] Continuing with Restore Point only..."
        
        # Critical Errors
        CriticalCodeAfterRestore = "[CRITICAL ERROR] Code should not continue after Restore!"
        CriticalRestoreNotCaught = "[CRITICAL ERROR] Restore mode was not caught!"
        CriticalForcingExit = "[CRITICAL ERROR] Forcing exit..."
        CriticalNeverReached = "[ERROR] This line should NEVER be displayed!"
        
        # Logging
        VerboseOldLogsCleared = "Old transcript logs cleared: {0} files"
        VerboseLoadOrder = "Load order: {0}"
        VerboseTranscriptStarted = "Transcript started: {0}"
        WarningTranscriptFailed = "Could not start transcript: {0}"
        WarningTranscriptContinue = "Continuing without transcript logging..."
        
        # Backup Success & Abort Messages
        BackupSuccessComplete = "BACKUP SUCCESSFULLY COMPLETED"
        BackupCanRestore = "[OK] Backup can be restored anytime:"
        BackupRunRestore = "     Run Restore-SecurityBaseline.ps1"
        BackupAbortTitle = "[ABORT] Backup failed and user cancelled!"
        BackupAbortNoScript = "Main script will NOT continue."
        BackupAbortReason = "Reason: No safety net (no backup, no restore point)."
        BackupAbortRecommend = "Recommendation:"
        BackupAbortStep1 = "1. Fix the problem (see error above)"
        BackupAbortStep2 = "2. Run script again"
        BackupAbortStep3 = "3. Or: Create manual Restore Point and continue"
        BackupValidationSuccess = "[SUCCESS] BACKUP SUCCESSFULLY VALIDATED!"
        
        # Privacy Settings User Messages (App Permissions, NOT Hardware!)
        CameraMicDefaultOff = "App permissions for Camera and Microphone: REMOVED"
        CameraMicUserCan = "To allow apps again: Settings | Privacy | Camera/Microphone:"
        CameraMicStep1 = "  1. Enable master-switch"
        CameraMicStep2 = "  2. Then allow individual apps"
        CameraMicBestPractice = "NOTE: Hardware devices are still ACTIVE! Disable in Device Manager if needed."
        
        # Progress
        ProgressCore = "Core Security Baseline..."
        ProgressASR = "Attack Surface Reduction..."
        ProgressAdvanced = "Advanced Security (VBS + BitLocker + LAPS)..."
        ProgressDNS = "DNS Security and Firewall..."
        ProgressBloatware = "Bloatware Removal..."
        ProgressTelemetry = "Telemetry Deactivation..."
        ProgressPerformance = "Performance Optimization..."
        
        # Success Messages
        SuccessCore = "Core Security Baseline completed!"
        SuccessASR = "ASR Rules activated"
        SuccessAdvanced = "Advanced Security activated!"
        SuccessDNS = "DNS Security and Firewall configured!"
        SuccessBloatware = "Bloatware removed!"
        SuccessTelemetry = "Telemetry disabled!"
        SuccessPerformance = "Performance optimized!"
        SuccessFinal = "Security Baseline successfully applied!"
        SuccessReport = "Compliance Report:"
        
        # Errors
        ErrorGeneral = "ERROR:"
        ErrorInvalidInput = "Invalid input! Please enter"
        ErrorNotFound = "not found!"
        ErrorExpected = "Expected:"
        
        # Confirmations
        ConfirmContinue = "Would you like to continue? [Y/N]:"
        ConfirmWarning = "Last warning! Are you SURE? [Y/N]:"
        ConfirmYes = "Y"
        ConfirmNo = "N"
        
        # Goodbye
        Goodbye = "Goodbye!"
        
        # Backup Script
        BackupBanner = "BACKUP - Windows 11 Security Baseline Settings"
        BackupCreating = "Creating complete backup..."
        BackupDirCreated = "Backup directory created:"
        BackupCheckOld = "Checking old backups..."
        BackupDeleteOld = "Deleting {0} old backups (older than last 30)..."
        BackupDeleted = "old backups deleted"
        BackupNoOld = "No old backups to delete (max. 30 kept)"
        BackupDNS = "DNS Settings being backed up..."
        BackupDNSAdapter = "DNS from adapter '{0}':"
        BackupDNSSaved = "DNS Settings backed up ({0} adapters)"
        BackupHosts = "Hosts file being backed up..."
        BackupHostsSaved = "Hosts file backed up ({0} lines)"
        BackupApps = "Installed apps being backed up..."
        BackupAppsUser = "User apps backed up"
        BackupAppsProvisioned = "Backing up Provisioned Packages (for restore)..."
        BackupAppsProvisionedSaved = "Provisioned Packages backed up"
        BackupServices = "Service start types being backed up..."
        BackupServicesSaved = "Services backed up (ALL!)"
        BackupServicesNote = "This allows 100% restore"
        BackupFirewall = "Firewall rules being backed up..."
        BackupFirewallSaved = "Firewall rules backed up (ALL!)"
        BackupFirewallNote = "Incl. status of all standard rules (enabled/disabled)"
        BackupUsers = "User accounts being backed up..."
        BackupUsersSaved = "User accounts backed up"
        BackupUsersWarning = "NOTE: Passwords cannot be backed up!"
        BackupUsersPasswordNote = "During restore a NEW password will be set (displayed)"
        BackupRegistry = "Important registry keys being backed up..."
        BackupRegistrySaved = "Registry keys backed up"
        BackupSystem = "System information being backed up..."
        BackupSystemSaved = "System information backed up"
        BackupSaving = "Saving backup..."
        BackupSuccess = "Backup successfully created!"
        BackupCompleted = "BACKUP SUCCESSFULLY COMPLETED"
        BackupFile = "Backup file:"
        BackupSize = "Size:"
        BackupSavedItems = "Backed up:"
        BackupNote = "This backup can be restored by running this script again and selecting 'Restore' from the main menu."
        
        # Restore Script
        RestoreBanner = "RESTORE - Windows 11 Security Baseline Settings"
        RestoreSearching = "Searching for available backups..."
        RestoreNoneFound = "No backups found in:"
        RestoreCreateFirst = "Create a backup first with: .\\Backup-SecurityBaseline.ps1"
        RestoreAvailable = "Available backups: {0} found"
        RestoreShowingLatest = "Showing the {0} newest backups"
        RestoreShowAll = "For all backups: Press [A]"
        RestoreSelectPrompt = "Select a backup"
        RestoreOrCancel = "or [0] to cancel:"
        RestoreShowingAll = "Showing ALL {0} backups..."
        RestoreCancelled = "Cancelled."
        RestoreInvalidSelection = "Invalid selection!"
        RestoreNotFound = "Backup file not found:"
        RestoreLoading = "Loading backup..."
        RestoreLoaded = "Backup loaded"
        RestoreBackupDate = "Backup date:"
        RestoreHostname = "Hostname:"
        RestoreOS = "OS:"
        RestoreLoadError = "Backup could not be loaded:"
        RestoreLoadReasons = "Possible reasons:"
        RestoreLoadCorrupt = "File is corrupt"
        RestoreLoadInvalid = "Invalid JSON format"
        RestoreLoadModified = "File was manually modified"
        RestoreWarningTitle = "!!! WARNING !!!"
        RestoreWarningText = "This script restores ALL settings from backup!"
        RestoreWarningMeans = "This means:"
        RestoreWarningDNS = "DNS will be reset"
        RestoreWarningHosts = "Hosts file will be overwritten"
        RestoreWarningServices = "Services will be reset"
        RestoreWarningFirewall = "Firewall rules will be deleted"
        RestoreWarningRegistry = "Registry keys will be reset"
        RestoreWarningRisk = "SECURITY RISK: System will be LESS secure!"
        RestoreConfirm = "Do you REALLY want to continue? [Y/N]:"
        RestoreStarting = "Starting restore process..."
        RestoreDNS = "DNS Settings being restored..."
        RestoreDNSOK = "DNS on '{0}' restored:"
        RestoreDNSAuto = "DNS on '{0}' set to AUTOMATIC"
        RestoreHosts = "Hosts file being restored..."
        RestoreHostsOK = "Hosts file restored"
        RestoreHostsBackup = "Old hosts file backed up:"
        RestoreServices = "Services being restored..."
        RestoreServicesOK = "StartType set to '{0}'"
        RestoreServicesNotFound = "Service '{0}' no longer exists"
        RestoreFirewall = "Firewall rules being restored..."
        RestoreFirewallDeleting = "Deleting custom firewall rules..."
        RestoreFirewallOK = "Rule '{0}' deleted"
        RestoreFirewallRestoring = "Restoring status of all firewall rules..."
        RestoreFirewallStatus = "Firewall rules status checked"
        RestoreFirewallChanged = "Rules status changed"
        RestoreFirewallNoData = "No firewall backup data found"
        RestoreRegistry = "Registry keys being restored..."
        RestoreRegistryOK = "Value set to '{0}'"
        RestoreRegistryDeleted = "deleted (originally didn't exist)"
        RestoreUsers = "User accounts being restored..."
        RestoreUsersRenamed = "Administrator account renamed: '{0}' -> '{1}'"
        RestoreUsersEnabled = "Administrator account enabled"
        RestoreUsersDisabled = "Administrator account disabled"
        RestoreUsersPasswordTitle = "IMPORTANT: Password must be reset!"
        RestoreUsersPasswordWarning = "Original password CANNOT be restored!"
        RestoreUsersPasswordPrompt = "Set a NEW password for '{0}'? [Y/N]:"
        RestoreUsersPasswordOptions = "Options:"
        RestoreUsersPasswordRandom = "[1] Generate RANDOM 20-character password (displayed!)"
        RestoreUsersPasswordCustom = "[2] Enter own password"
        RestoreUsersPasswordSkip = "[3] Skip"
        RestoreUsersPasswordChoose = "Choose [1-3]:"
        RestoreUsersPasswordNew = "NEW PASSWORD FOR '{0}':"
        RestoreUsersPasswordNote = "PLEASE WRITE DOWN THIS PASSWORD!"
        RestoreUsersPasswordSet = "Password set!"
        RestoreUsersPasswordSkipped = "Password setting skipped"
        RestoreUsersPasswordOldRandom = "Administrator still has old random password!"
        RestoreUsersAlready = "Administrator account already has original name"
        RestoreUsersNotFound = "Administrator account not found"
        RestoreApps = "Apps being restored..."
        RestoreAppsMissing = "apps were installed, now missing"
        RestoreAppsPackages = "Provisioned Packages found in backup!"
        RestoreAppsCanRestore = "These can be restored"
        RestoreAppsPrompt = "Restore missing apps? [Y/N]:"
        RestoreAppsRestoring = "Restoring Provisioned Packages..."
        RestoreAppsMayTakeTime = "(This may take several minutes!)"
        RestoreAppsInstalling = "Installing:"
        RestoreAppsMustReinstall = "Package must be installed via Microsoft Store"
        RestoreAppsManual = "Packages must be manually installed"
        RestoreAppsOpenStore = "Open Microsoft Store and search for the apps"
        RestoreAppsSkipped = "App restore skipped"
        RestoreAppsNone = "No Provisioned Packages in backup"
        RestoreAppsStoreNote = "Apps can be reinstalled via Microsoft Store"
        RestoreAppsList = "Missing apps (selection):"
        RestoreAppsMore = "... and {0} more"
        RestoreAppsAllPresent = "All apps still present"
        RestoreDNSClear = "Clearing DNS cache..."
        RestoreDNSCleared = "DNS cache cleared"
        RestoreDNSTimeout = "DNS Cache Flush timeout - will be cleared at reboot"
        RestoreCompleted = "RESTORE COMPLETED"
        RestoreStats = "Statistics:"
        RestoreStatsSuccess = "Successful:"
        RestoreStatsFailed = "Failed:"
        RestoreStatsSkipped = "Skipped:"
        RestoreSomeErrors = "Some restore operations failed!"
        RestoreCheckLog = "Check the log for details:"
        RestoreRebootTitle = "REBOOT RECOMMENDED"
        RestoreRebootNeeded = "Some changes require a reboot to be fully active:"
        RestoreRebootServices = "Service changes"
        RestoreRebootRegistry = "Registry changes"
        RestoreRebootDNS = "DNS settings"
        RestoreRebootNow = "Reboot NOW? [Y/N]:"
        RestoreRebooting = "Reboot in 10 seconds..."
        RestoreRebootAbort = "Press CTRL+C to abort"
        RestoreRebootPostponed = "Reboot postponed."
        RestoreRebootManual = "Please reboot manually: shutdown /r /t 0"
    }
    
    de = @{
        # Banner
        BannerTitle = "NoID Privacy - Windows 11 25H2 Security Baseline"
        BannerSubtitle = "Maximum Security + Privacy + Performance"
        
        # Main Menu
        MainMenuTitle = "HAUPT-MENUE"
        MainMenuAudit = "Audit Mode"
        MainMenuAuditDesc = "Nur pruefen, NICHTS aendern (empfohlen fuer Tests)"
        MainMenuEnforce = "Enforce Mode"
        MainMenuEnforceDesc = "ALLES anwenden (volle Haertung)"
        MainMenuCustom = "Custom Mode"
        MainMenuCustomDesc = "Module einzeln auswaehlen"
        MainMenuVerify = "Verify"
        MainMenuVerifyDesc = "Pruefen ob Baseline angewendet"
        MainMenuExit = "Exit"
        MainMenuExitDesc = "Beenden"
        MainMenuPrompt = "Ihre Wahl"
        
        # Language Selection
        LanguagePrompt = "Select language / Sprache waehlen"
        LanguageEnglish = "English"
        LanguageGerman = "German / Deutsch"
        
        # Module Selection
        ModuleSelectionTitle = "MODULE AUSWAHL (Custom Mode)"
        ModuleSelectionInstructions = "Verwenden Sie Pfeiltasten zum Navigieren, SPACE zum Aktivieren/Deaktivieren"
        ModuleSelectionConfirm = "ENTER zum Bestaetigen und Starten"
        ModuleMandatory = "(Pflicht)"
        
        # Modules
        ModuleCore = "Security Baseline Core"
        ModuleCoreDesc = "Basis-Haertung - NetBIOS + Auditing + Print Spooler + etc."
        ModuleASR = "ASR Rules (Attack Surface Reduction)"
        ModuleASRDesc = "19 ASR-Regeln + USB Control + Smart App Control"
        ModuleAdvanced = "Advanced Security"
        ModuleAdvancedDesc = "VBS + Credential Guard + BitLocker + LAPS"
        ModuleDNS = "DNS Security"
        ModuleDNSDesc = "DNSSEC + DNS Blocklist (80K Domains) + Firewall"
        ModuleBloatware = "Bloatware Removal"
        ModuleBloatwareDesc = "Entfernt vorinstallierte Apps - Games und Werbung"
        ModuleTelemetry = "Telemetry Deactivation"
        ModuleTelemetryDesc = "95% Telemetrie deaktiviert"
        ModulePerformance = "Performance Optimization"
        ModulePerformanceDesc = "Scheduled Tasks + Event Logs + Background Activities"
        
        # Reboot Prompt
        RebootTitle = "NEUSTART ERFORDERLICH"
        RebootChanges = "Folgende Aenderungen benoetigen einen Neustart:"
        RebootVBS = "VBS und Credential Guard (Hardware-Security)"
        RebootBitLocker = "BitLocker Policies"
        RebootFirewall = "Firewall-Regeln"
        RebootServices = "Service-Aenderungen"
        RebootRegistry = "Registry-Einstellungen"
        RebootPerformance = "Performance-Optimierungen"
        RebootWarning = "Ohne Neustart sind einige Features NICHT aktiv!"
        RebootQuestion = "Was moechten Sie tun?"
        RebootNow = "Jetzt neu starten"
        RebootNowDesc = "Countdown 10 Sekunden, dann Reboot"
        RebootLater = "Spaeter neu starten"
        RebootLaterDesc = "Sie muessen manuell neu starten!"
        RebootPrompt = "Ihre Wahl"
        RebootCountdown = "Neustart in:"
        RebootSeconds = "Sekunden..."
        RebootAbortHint = "(STRG+C zum Abbrechen)"
        RebootStarting = "System wird neu gestartet..."
        RebootPostponed = "Neustart wurde verschoben."
        RebootImportant = "WICHTIG: Bitte starten Sie Ihren Computer manuell neu!"
        RebootFeaturesActive = "Folgende Features sind erst nach Neustart aktiv:"
        RebootManualCommand = "Sie koennen jetzt mit 'shutdown /r /t 0' neu starten."
        RebootSkipped = "Neustart wurde uebersprungen (-SkipReboot Parameter)"
        RebootSkippedWarning = "Einige Aenderungen werden erst nach Neustart aktiv!"
        
        # CTRL+C Handler
        AbortUserCancelled = "[ABBRUCH] User hat Script mit STRG+C abgebrochen!"
        AbortCleanup = "[i] Cleanup wird durchgefuehrt..."
        AbortComplete = "[OK] Cleanup abgeschlossen"
        AbortExited = "[i] Script wurde sicher beendet"
        
        # Instance/Mutex Errors
        ErrorInstanceRunning = "[FEHLER] Script laeuft bereits!"
        ErrorInstanceParallel = "Das Security Baseline Script kann nicht parallel ausgefuehrt werden."
        ErrorInstanceReason = "Grund: Registry/Service-Aenderungen wuerden sich gegenseitig stoeren."
        ErrorInstanceWait = "Bitte warten Sie bis die andere Instanz fertig ist."
        
        # Module Loading
        InfoCalculatingOrder = "[i] Berechne Modul-Ladereihenfolge..."
        InfoLoadingModules = "[i] Lade Module..."
        InfoLoadedModule = "[i] Modul geladen:"
        ErrorLoadModule = "[FEHLER] Konnte Modul nicht laden:"
        
        # Restore Mode Messages
        RestoreModeActivated = "RESTORE MODUS AKTIVIERT"
        RestoreModeApplyExiting = "[i] Apply-Script wird BEENDET"
        RestoreModeStarting = "[i] Restore-Script wird gestartet..."
        RestoreModeProcessStart = "[i] Starte Restore-Prozess (bitte warten)..."
        RestoreModeScriptComplete = "[i] Restore-Script abgeschlossen (Exit-Code: {0})"
        RestoreModeApplyExitNow = "[i] Apply-Script wird JETZT beendet (Environment.Exit)..."
        RestoreModeNotFound = "[FEHLER] Restore-Script nicht gefunden: {0}"
        
        # Backup Creation Messages
        BackupFullCreating = "VOLLSTAENDIGES BACKUP WIRD ERSTELLT"
        BackupIncludes = "[i] Das Backup umfasst:"
        BackupIncludesDNS = "    - DNS Settings (alle Adapter)"
        BackupIncludesHosts = "    - Hosts-Datei (aktuelle Version)"
        BackupIncludesServices = "    - Alle Services (StartType)"
        BackupIncludesFirewall = "    - Firewall-Regeln (Status)"
        BackupIncludesRegistry = "    - Registry-Keys (wichtige)"
        BackupIncludesUsers = "    - User Accounts (Namen)"
        BackupIncludesApps = "    - Installierte Apps (Liste)"
        BackupDuration = "[i] Erwartete Dauer: 2-3 Minuten (max 6 Min)"
        BackupRunning = "[i] Backup laeuft jetzt - bitte warten..."
        BackupFailed = "[FEHLER] Backup fehlgeschlagen (Exit-Code: {0})"
        BackupContinueRP = "Fortfahren mit nur Restore Point..."
        BackupNotFound = "[WARNUNG] Backup-Script nicht gefunden: {0}"
        BackupFallbackRP = "[WARNUNG] Fortfahren mit nur Restore Point..."
        
        # Critical Errors
        CriticalCodeAfterRestore = "[CRITICAL ERROR] Code sollte nach Restore nicht weiterlaufen!"
        CriticalRestoreNotCaught = "[CRITICAL ERROR] Restore-Modus wurde nicht abgefangen!"
        CriticalForcingExit = "[CRITICAL ERROR] Erzwinge Exit..."
        CriticalNeverReached = "[FEHLER] Diese Zeile sollte NIEMALS angezeigt werden!"
        
        # Logging
        VerboseOldLogsCleared = "Alte Transcript-Logs bereinigt: {0} Dateien"
        VerboseLoadOrder = "Ladereihenfolge: {0}"
        VerboseTranscriptStarted = "Transcript gestartet: {0}"
        WarningTranscriptFailed = "Konnte Transcript nicht starten: {0}"
        WarningTranscriptContinue = "Fahre ohne Transcript-Logging fort..."
        
        # Backup Success & Abort Messages
        BackupSuccessComplete = "BACKUP ERFOLGREICH ABGESCHLOSSEN"
        BackupCanRestore = "[OK] Backup kann jederzeit wiederhergestellt werden:"
        BackupRunRestore = "     Restore-SecurityBaseline.ps1 ausfuehren"
        BackupAbortTitle = "[ABBRUCH] Backup fehlgeschlagen und User hat abgebrochen!"
        BackupAbortNoScript = "Das Hauptskript wird NICHT fortfahren."
        BackupAbortReason = "Grund: Kein Safety Net (kein Backup, kein Restore Point)."
        BackupAbortRecommend = "Empfehlung:"
        BackupAbortStep1 = "1. Problem beheben (siehe Fehler oben)"
        BackupAbortStep2 = "2. Script erneut starten"
        BackupAbortStep3 = "3. Oder: Manuelle Restore Point erstellen und fortfahren"
        BackupValidationSuccess = "[SUCCESS] BACKUP ERFOLGREICH VALIDIERT!"
        
        # Privacy Settings User Messages (App-Berechtigungen, NICHT Hardware!)
        CameraMicDefaultOff = "App-Berechtigungen fuer Kamera und Mikrofon: ENTFERNT"
        CameraMicUserCan = "Um Apps wieder zu erlauben: Settings | Datenschutz | Kamera/Mikrofon:"
        CameraMicStep1 = "  1. Master-Switch EINschalten"
        CameraMicStep2 = "  2. Dann einzelne Apps erlauben"
        CameraMicBestPractice = "HINWEIS: Hardware-Geraete sind noch AKTIV! Bei Bedarf im Geraete-Manager deaktivieren."
        
        # Progress
        ProgressCore = "Core Security Baseline..."
        ProgressASR = "Attack Surface Reduction..."
        ProgressAdvanced = "Advanced Security (VBS + BitLocker + LAPS)..."
        ProgressDNS = "DNS Security und Firewall..."
        ProgressBloatware = "Bloatware Removal..."
        ProgressTelemetry = "Telemetry Deactivation..."
        ProgressPerformance = "Performance Optimization..."
        
        # Success Messages
        SuccessCore = "Core Security Baseline abgeschlossen!"
        SuccessASR = "ASR Rules aktiviert"
        SuccessAdvanced = "Advanced Security aktiviert!"
        SuccessDNS = "DNS Security und Firewall konfiguriert!"
        SuccessBloatware = "Bloatware entfernt!"
        SuccessTelemetry = "Telemetrie deaktiviert!"
        SuccessPerformance = "Performance optimiert!"
        SuccessFinal = "Security Baseline erfolgreich angewendet!"
        SuccessReport = "Compliance Report:"
        
        # Errors
        ErrorGeneral = "FEHLER:"
        ErrorInvalidInput = "Ungueltige Eingabe! Bitte"
        ErrorNotFound = "nicht gefunden!"
        ErrorExpected = "Erwartet:"
        
        # Confirmations
        ConfirmContinue = "Moechten Sie fortfahren? [J/N]:"
        ConfirmYes = "J"
        ConfirmNo = "N"
        
        # Goodbye
        Goodbye = "Auf Wiedersehen!"
        
        # Backup Script
        BackupBanner = "BACKUP - Windows 11 Security Baseline Einstellungen"
        BackupCreating = "Erstelle vollstaendiges Backup..."
        BackupDirCreated = "Backup-Verzeichnis erstellt:"
        BackupCheckOld = "Pruefe alte Backups..."
        BackupDeleteOld = "Loesche {0} alte Backups (aelter als die letzten 30)..."
        BackupDeleted = "alte Backups geloescht"
        BackupNoOld = "Keine alten Backups zum Loeschen (max. 30 werden behalten)"
        BackupDNS = "DNS Settings werden gesichert..."
        BackupDNSAdapter = "DNS von Adapter '{0}':"
        BackupDNSSaved = "DNS Settings gesichert ({0} Adapter)"
        BackupHosts = "Hosts-Datei wird gesichert..."
        BackupHostsSaved = "Hosts-Datei gesichert ({0} Zeilen)"
        BackupApps = "Installierte Apps werden gesichert..."
        BackupAppsUser = "User Apps gesichert"
        BackupAppsProvisioned = "Sichere Provisioned Packages (fuer Wiederherstellung)..."
        BackupAppsProvisionedSaved = "Provisioned Packages gesichert"
        BackupServices = "Service Start-Types werden gesichert..."
        BackupServicesSaved = "Services gesichert (ALLE!)"
        BackupServicesNote = "Dadurch koennen wir 100% wiederherstellen"
        BackupFirewall = "Firewall-Regeln werden gesichert..."
        BackupFirewallSaved = "Firewall-Regeln gesichert (ALLE!)"
        BackupFirewallNote = "Inkl. Status aller Standard-Regeln (aktiviert/deaktiviert)"
        BackupUsers = "User Accounts werden gesichert..."
        BackupUsersSaved = "User Accounts gesichert"
        BackupUsersWarning = "HINWEIS: Passwoerter koennen NICHT gesichert werden!"
        BackupUsersPasswordNote = "Beim Restore wird ein NEUES Passwort gesetzt (wird angezeigt)"
        BackupRegistry = "Wichtige Registry-Keys werden gesichert..."
        BackupRegistrySaved = "Registry-Keys gesichert"
        BackupSystem = "System-Informationen werden gesichert..."
        BackupSystemSaved = "System-Informationen gesichert"
        BackupSaving = "Speichere Backup..."
        BackupSuccess = "Backup erfolgreich erstellt!"
        BackupCompleted = "BACKUP ERFOLGREICH ABGESCHLOSSEN"
        BackupFile = "Backup-Datei:"
        BackupSize = "Groesse:"
        BackupSavedItems = "Gesichert:"
        BackupNote = "Dieses Backup kann wiederhergestellt werden, indem Sie das Skript erneut ausfuehren und 'Restore' im Hauptmenue waehlen."
        
        # Restore Script
        RestoreBanner = "RESTORE - Windows 11 Security Baseline Einstellungen"
        RestoreSearching = "Suche nach verfuegbaren Backups..."
        RestoreNoneFound = "Keine Backups gefunden in:"
        RestoreCreateFirst = "Erstellen Sie zuerst ein Backup mit: .\\Backup-SecurityBaseline.ps1"
        RestoreAvailable = "Verfuegbare Backups: {0} gefunden"
        RestoreShowingLatest = "Zeige die {0} neuesten Backups"
        RestoreShowAll = "Fuer alle Backups: Druecken Sie [A]"
        RestoreSelectPrompt = "Waehlen Sie ein Backup"
        RestoreOrCancel = "oder [0] zum Abbrechen:"
        RestoreShowingAll = "Zeige ALLE {0} Backups..."
        RestoreCancelled = "Abgebrochen."
        RestoreInvalidSelection = "Ungueltige Auswahl!"
        RestoreNotFound = "Backup-Datei nicht gefunden:"
        RestoreLoading = "Lade Backup..."
        RestoreLoaded = "Backup geladen"
        RestoreBackupDate = "Backup-Datum:"
        RestoreHostname = "Hostname:"
        RestoreOS = "OS:"
        RestoreLoadError = "Backup konnte nicht geladen werden:"
        RestoreLoadReasons = "Moegliche Ursachen:"
        RestoreLoadCorrupt = "Datei ist korrupt"
        RestoreLoadInvalid = "Ungueltiges JSON-Format"
        RestoreLoadModified = "Datei wurde manuell veraendert"
        RestoreWarningTitle = "!!! WARNUNG !!!"
        RestoreWarningText = "Dieses Script stellt ALLE Settings aus dem Backup wieder her!"
        RestoreWarningMeans = "Das bedeutet:"
        RestoreWarningDNS = "DNS wird zurueckgesetzt"
        RestoreWarningHosts = "Hosts-Datei wird ueberschrieben"
        RestoreWarningServices = "Services werden zurueckgesetzt"
        RestoreWarningFirewall = "Firewall-Regeln werden geloescht"
        RestoreWarningRegistry = "Registry-Keys werden zurueckgesetzt"
        RestoreWarningRisk = "SICHERHEITSRISIKO: System wird WENIGER sicher!"
        RestoreConfirm = "Moechten Sie WIRKLICH fortfahren? [J/N]:"
        RestoreStarting = "Starte Restore-Prozess..."
        RestoreDNS = "DNS Settings werden wiederhergestellt..."
        RestoreDNSOK = "DNS auf '{0}' wiederhergestellt:"
        RestoreDNSAuto = "DNS auf '{0}' auf AUTOMATISCH gesetzt"
        RestoreHosts = "Hosts-Datei wird wiederhergestellt..."
        RestoreHostsOK = "Hosts-Datei wiederhergestellt"
        RestoreHostsBackup = "Alte Hosts-Datei gesichert:"
        RestoreServices = "Services werden wiederhergestellt..."
        RestoreServicesOK = "StartType auf '{0}' gesetzt"
        RestoreServicesNotFound = "Service '{0}' existiert nicht mehr"
        RestoreFirewall = "Firewall-Regeln werden wiederhergestellt..."
        RestoreFirewallDeleting = "Loesche Custom Firewall-Regeln..."
        RestoreFirewallOK = "Regel '{0}' geloescht"
        RestoreFirewallRestoring = "Stelle Status aller Firewall-Regeln wieder her..."
        RestoreFirewallStatus = "Firewall-Regeln Status geprueft"
        RestoreFirewallChanged = "Regeln Status geaendert"
        RestoreFirewallNoData = "Keine Firewall-Backup-Daten gefunden"
        RestoreRegistry = "Registry-Keys werden wiederhergestellt..."
        RestoreRegistryOK = "Wert auf '{0}' gesetzt"
        RestoreRegistryDeleted = "geloescht (existierte urspruenglich nicht)"
        RestoreUsers = "User Accounts werden wiederhergestellt..."
        RestoreUsersRenamed = "Administrator-Account zurueckbenannt: '{0}' -> '{1}'"
        RestoreUsersEnabled = "Administrator-Account aktiviert"
        RestoreUsersDisabled = "Administrator-Account deaktiviert"
        RestoreUsersPasswordTitle = "WICHTIG: Passwort muss neu gesetzt werden!"
        RestoreUsersPasswordWarning = "Original-Passwort kann NICHT wiederhergestellt werden!"
        RestoreUsersPasswordPrompt = "Moechten Sie ein NEUES Passwort fuer '{0}' setzen? [J/N]:"
        RestoreUsersPasswordOptions = "Optionen:"
        RestoreUsersPasswordRandom = "[1] Generiere ZUFAELLIGES 20-Zeichen-Passwort (wird angezeigt!)"
        RestoreUsersPasswordCustom = "[2] Eigenes Passwort eingeben"
        RestoreUsersPasswordSkip = "[3] Ueberspringen"
        RestoreUsersPasswordChoose = "Waehlen Sie [1-3]:"
        RestoreUsersPasswordNew = "NEUES PASSWORT FUER '{0}':"
        RestoreUsersPasswordNote = "BITTE NOTIEREN SIE DIESES PASSWORT!"
        RestoreUsersPasswordSet = "Passwort gesetzt!"
        RestoreUsersPasswordSkipped = "Passwort-Setzung uebersprungen"
        RestoreUsersPasswordOldRandom = "Administrator hat noch das alte zufaellige Passwort!"
        RestoreUsersAlready = "Administrator-Account hat bereits Original-Namen"
        RestoreUsersNotFound = "Administrator-Account nicht gefunden"
        RestoreApps = "Apps werden wiederhergestellt..."
        RestoreAppsMissing = "Apps waren installiert, fehlen jetzt"
        RestoreAppsPackages = "Provisioned Packages im Backup gefunden!"
        RestoreAppsCanRestore = "Diese koennen wiederhergestellt werden"
        RestoreAppsPrompt = "Moechten Sie fehlende Apps wiederherstellen? [J/N]:"
        RestoreAppsRestoring = "Stelle Provisioned Packages wieder her..."
        RestoreAppsMayTakeTime = "(Dies kann einige Minuten dauern!)"
        RestoreAppsInstalling = "Installiere:"
        RestoreAppsMustReinstall = "Package muss ueber Microsoft Store installiert werden"
        RestoreAppsManual = "Packages muessen manuell installiert werden"
        RestoreAppsOpenStore = "Oeffnen Sie Microsoft Store und suchen Sie nach den Apps"
        RestoreAppsSkipped = "App-Wiederherstellung uebersprungen"
        RestoreAppsNone = "Keine Provisioned Packages im Backup"
        RestoreAppsStoreNote = "Apps koennen ueber Microsoft Store neu installiert werden"
        RestoreAppsList = "Fehlende Apps (Auswahl):"
        RestoreAppsMore = "... und {0} weitere"
        RestoreAppsAllPresent = "Alle Apps noch vorhanden"
        RestoreDNSClear = "Leere DNS Cache..."
        RestoreDNSCleared = "DNS Cache geleert"
        RestoreDNSTimeout = "DNS Cache Flush Timeout - wird beim Neustart geleert"
        RestoreCompleted = "RESTORE ABGESCHLOSSEN"
        RestoreStats = "Statistik:"
        RestoreStatsSuccess = "Erfolgreich:"
        RestoreStatsFailed = "Fehlgeschlagen:"
        RestoreStatsSkipped = "Uebersprungen:"
        RestoreSomeErrors = "Einige Restore-Operationen sind fehlgeschlagen!"
        RestoreCheckLog = "Pruefen Sie das Log fuer Details:"
        RestoreRebootTitle = "NEUSTART EMPFOHLEN"
        RestoreRebootNeeded = "Einige Aenderungen benoetigen einen Neustart, um vollstaendig aktiv zu werden:"
        RestoreRebootServices = "Service-Aenderungen"
        RestoreRebootRegistry = "Registry-Aenderungen"
        RestoreRebootDNS = "DNS-Settings"
        RestoreRebootNow = "Moechten Sie JETZT neu starten? [J/N]:"
        RestoreRebooting = "Neustart in 10 Sekunden..."
        RestoreRebootAbort = "Druecken Sie STRG+C zum Abbrechen"
        RestoreRebootPostponed = "Neustart verschoben."
        RestoreRebootManual = "Bitte starten Sie manuell neu: shutdown /r /t 0"
    }
}

<#
.SYNOPSIS
    Gets a localized string for the current language.

.DESCRIPTION
    Retrieves a localized string from the global strings dictionary.
    Falls back to English if string not found in current language.
    Falls back to the key itself if not found in any language.

.PARAMETER Key
    The key of the localized string to retrieve.

.PARAMETER FallbackLanguage
    The fallback language to use if key not found. Default: 'en'

.EXAMPLE
    Get-LocalizedString 'MainMenuTitle'
    Returns the main menu title in the current language.

.EXAMPLE
    Get-LocalizedString 'CustomKey' -FallbackLanguage 'de'
    Returns the custom key with German as fallback.

.NOTES
    Requires $Global:Strings and $Global:CurrentLanguage to be initialized.
    Automatically handles missing keys and languages gracefully.
#>
function Get-LocalizedString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        
        [Parameter(Mandatory=$false)]
        [string]$FallbackLanguage = 'en'
    )
    
    # Validate global state
    if (-not $Global:Strings) {
        Write-Warning "Strings dictionary not initialized - returning key"
        return $Key
    }
    
    # Ensure current language is set
    if (-not (Test-Path Variable:\Global:CurrentLanguage) -or [string]::IsNullOrEmpty($Global:CurrentLanguage)) {
        Write-Verbose "CurrentLanguage not set - using fallback: $FallbackLanguage"
        $Global:CurrentLanguage = $FallbackLanguage
    }
    
    # Try current language first
    if ($Global:Strings.ContainsKey($Global:CurrentLanguage) -and 
        $Global:Strings[$Global:CurrentLanguage].ContainsKey($Key)) {
        return $Global:Strings[$Global:CurrentLanguage][$Key]
    }
    
    # Try fallback language
    if ($Global:Strings.ContainsKey($FallbackLanguage) -and 
        $Global:Strings[$FallbackLanguage].ContainsKey($Key)) {
        Write-Verbose "Key '$Key' not found in '$Global:CurrentLanguage' - using fallback: $FallbackLanguage"
        return $Global:Strings[$FallbackLanguage][$Key]
    }
    
    # Last resort: return the key itself
    Write-Warning "Localization key '$Key' not found in any language - returning key as string"
    return $Key
}

<#
.SYNOPSIS
    Displays a language selection menu and sets the global language.

.DESCRIPTION
    Shows an interactive menu allowing the user to select between
    English and German. Sets $Global:CurrentLanguage based on selection.
    
    The menu is displayed in both languages for accessibility.

.EXAMPLE
    Select-Language
    Displays the language selection menu and waits for user input.

.NOTES
    This function clears the host and displays a full-screen menu.
    The selected language is stored in $Global:CurrentLanguage.
    Valid values: 'en' (English) or 'de' (German)
#>
function Select-Language {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    # Best Practice 25H2: Strict Mode aktivieren for Clear-Host in non-interactive sessions
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
    
    Write-Host "=============================================================================" -ForegroundColor Yellow
    Write-Host "                   SELECT LANGUAGE / SPRACHE WAEHLEN" -ForegroundColor Yellow
    Write-Host "=============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  [1] English" -ForegroundColor White
    Write-Host ""
    Write-Host "  [2] German / Deutsch" -ForegroundColor White
    Write-Host ""
    Write-Host "=============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        Write-Host "  Your choice / Ihre Wahl " -NoNewline -ForegroundColor Cyan
        Write-Host "[1/2]: " -NoNewline -ForegroundColor Gray
        $choice = Read-Host
        
        if ($choice -notin @('1', '2')) {
            Write-Host "  [ERROR] Invalid input! / Ungueltige Eingabe!" -ForegroundColor Red
            Write-Host ""
        }
    } while ($choice -notin @('1', '2'))
    
    if ($choice -eq '1') {
        $Global:CurrentLanguage = "en"
        Write-Host "`n  [OK] Language set to English" -ForegroundColor Green
    } else {
        $Global:CurrentLanguage = "de"
        Write-Host "`n  [OK] Sprache auf Deutsch gesetzt" -ForegroundColor Green
    }
    
    Start-Sleep -Seconds 1
}

# Note: Export-ModuleMember is not needed for dot-sourced scripts
# Functions are automatically available in the calling scope
# This file is loaded with: . "$scriptDir\Modules\SecurityBaseline-Localization.ps1"
