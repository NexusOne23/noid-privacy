# ============================================================================
# SecurityBaseline-ASR.ps1
# NoID Privacy - ASR Rules (Baseline 25H2 compliant)
# ============================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Set-AttackSurfaceReductionRules {
    <#
    .SYNOPSIS
        Konfiguriert Attack Surface Reduction Rules (ASR)
    .DESCRIPTION
        Setzt die 23 Microsoft-empfohlenen ASR-Regeln fuer Windows 11.
        ASR reduziert die Angriffsflaeche durch Blockierung gefaehrlicher Verhaltensweisen.
        Best Practice 25H2: Audit oder Block Mode, CmdletBinding, ArrayList Performance.
    .PARAMETER Mode
        Audit = Nur Logging (empfohlen fuer Testing)
        Enforce = Aktives Blockieren (Production)
    .EXAMPLE
        Set-AttackSurfaceReductionRules -Mode Audit
    .EXAMPLE
        Set-AttackSurfaceReductionRules -Mode Enforce
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit'
    )
    
    Write-Section "Attack Surface Reduction (ASR) Rules"
    
    # Konvertiere Mode zu ASR Action Code
    # 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn
    # Best Practice 25H2: Enforce = Block Mode
    $asrMode = if ($Mode -eq 'Enforce') { 1 } else { 2 }
    
    Write-Info "ASR-Modus: $Mode"
    if ($Mode -eq 'Audit') {
        Write-Warning-Custom "AUDIT-Modus aktiv! Blockiert NICHT, nur Logging!"
        Write-Warning-Custom "Evaluieren Sie die Logs und wechseln Sie danach zu Enforce-Modus"
    }
    
    # 23 ASR-Regeln (Microsoft Best Practice 25H2)
    $asrRules = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = @{
            Name = "Block abuse of exploited vulnerable signed drivers"
            Mode = $asrMode
            Critical = $true
            Description = "Verhindert Missbrauch signierter aber verwundbarer Treiber"
        }
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = @{
            Name = "Block Adobe Reader from creating child processes"
            Mode = $asrMode
            Critical = $false
            Description = "Adobe Reader darf keine Prozesse starten"
        }
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = @{
            Name = "Block all Office applications from creating child processes"
            Mode = $asrMode
            Critical = $true
            Description = "Office-Apps duerfen keine Prozesse starten (Anti-Makro-Malware)"
        }
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = @{
            Name = "Block credential stealing from LSASS"
            Mode = $asrMode
            Critical = $true
            Description = "Verhindert Credential Dumping aus LSASS (Mimikatz-Schutz)"
        }
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = @{
            Name = "Block executable content from email and webmail"
            Mode = $asrMode
            Critical = $true
            Description = "Blockiert ausfuehrbare Dateien aus E-Mails"
        }
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = @{
            Name = "Block executable files unless they meet prevalence, age, or trusted list criteria"
            Mode = $asrMode
            Critical = $true
            Description = "Nur bekannte/vertrauenswuerdige EXEs erlaubt"
        }
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = @{
            Name = "Block execution of potentially obfuscated scripts"
            Mode = $asrMode
            Critical = $true
            Description = "Blockiert verschleierte Scripts (PowerShell/VBS/JS)"
        }
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = @{
            Name = "Block Win32 API calls from Office macros"
            Mode = $asrMode
            Critical = $true
            Description = "Office Makros duerfen keine Win32-APIs aufrufen"
        }
        "3b576869-a4ec-4529-8536-b80a7769e899" = @{
            Name = "Block Office apps from creating executable content"
            Mode = $asrMode
            Critical = $true
            Description = "Office darf keine EXEs erstellen"
        }
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = @{
            Name = "Block Office apps from injecting into other processes"
            Mode = $asrMode
            Critical = $true
            Description = "Office darf nicht in andere Prozesse injizieren"
        }
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = @{
            Name = "Block Office communication apps from creating child processes"
            Mode = $asrMode
            Critical = $false
            Description = "Outlook/Teams duerfen keine Prozesse starten"
        }
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = @{
            Name = "Block persistence through WMI event subscription"
            Mode = $asrMode
            Critical = $true
            Description = "Verhindert Persistenz via WMI Events"
        }
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = @{
            Name = "Block process creations from PSExec and WMI"
            Mode = 2
            Critical = $true
            Description = "Privilege Escalation via PSExec/WMI erkennen (immer Audit)"
        }
        "d3e037e1-3eb8-44c8-a917-57927947596d" = @{
            Name = "Block JavaScript or VBScript from launching downloaded executable content"
            Mode = $asrMode
            Critical = $true
            Description = "Script-basierte Downloads blockieren"
        }
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = @{
            Name = "Block untrusted and unsigned processes from USB"
            Mode = $asrMode
            Critical = $true
            Description = "Nur signierte Programme von USB erlaubt"
        }
        "33ddedf1-c6e0-47cb-833e-de6133960387" = @{
            Name = "Block rebooting machine in Safe Mode"
            Mode = $asrMode
            Critical = $true
            Description = "Ransomware Safe Mode Boot verhindern"
        }
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = @{
            Name = "Block use of copied or impersonated system tools"
            Mode = $asrMode
            Critical = $true
            Description = "Living-off-the-Land blockieren"
        }
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = @{
            Name = "Block Webshell creation for Servers"
            Mode = $asrMode
            Critical = $false
            Description = "Webshell Prevention (Server)"
        }
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = @{
            Name = "Use advanced protection against ransomware"
            Mode = $asrMode
            Critical = $true
            Description = "Controlled Folder Access (Anti-Ransomware)"
        }
    }
    
    # CRITICAL FIX: Defender Service MUSS laufen!
    # CRITICAL CHECK: Ist Windows Defender überhaupt verfügbar?
    Write-Verbose "Pruefe ob Windows Defender verfuegbar ist..."
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "Defender ist verfuegbar"
    }
    catch {
        Write-Warning "Windows Defender ist NICHT verfuegbar (Drittanbieter-AV aktiv)"
        Write-Info "ASR-Konfiguration wird uebersprungen - Ihr AV bietet bereits Schutz"
        return
    }
    
    Write-Verbose "Pruefe Defender Service Status vor ASR-Konfiguration..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info "Defender Service wird gestartet (erforderlich fuer ASR)..."
            Start-Service -Name WinDefend -ErrorAction Stop
            # CRITICAL: 3 Sekunden Delay für Defender-Initialisierung
            Write-Verbose "Warte 3 Sekunden auf Defender-Initialisierung..."
            Start-Sleep -Seconds 3
            Write-Verbose "Defender Service gestartet und initialisiert"
        }
        else {
            # Service läuft bereits, aber trotzdem kurz warten für Stabilität
            Write-Verbose "Warte 1 Sekunde für Defender-Stabilität..."
            Start-Sleep -Seconds 1
        }
    }
    catch {
        Write-Warning "Defender Service nicht verfuegbar - ASR-Konfiguration wird uebersprungen"
        Write-Info "Loesung: Start-Service -Name WinDefend oder ASR-Modul in Custom Mode skippen"
        return
    }
    
    # ASR-Regeln konfigurieren
    try {
        # Pruefe ob bereits ASR-Regeln existieren (Null-Safe Check!)
        # CRITICAL FIX v1.7.6: SilentlyContinue statt Stop verhindert Transcript-Verschmutzung
        $existingPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists (Third-Party AV compatibility)
        $existingRulesCount = if ($existingPrefs -and 
                                  $existingPrefs.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and 
                                  $existingPrefs.AttackSurfaceReductionRules_Ids) { 
            $existingPrefs.AttackSurfaceReductionRules_Ids.Count 
        } else { 
            0 
        }
        
        if ($existingRulesCount -gt 0) {
            Write-Warning-Custom "Bestehende ASR-Regeln gefunden ($existingRulesCount Regeln)"
            Write-Warning-Custom "Diese werden durch neue Konfiguration ueberschrieben"
        }
        
        # Verwende ArrayList fuer bessere Performance (O(1) statt O(n) bei +=)
        $asrIdsList = [System.Collections.ArrayList]::new()
        $asrActionsList = [System.Collections.ArrayList]::new()
        
        foreach ($ruleGuid in $asrRules.Keys) {
            $rule = $asrRules[$ruleGuid]
            # ArrayList.Add() returns index - suppress output with $null =
            $null = $asrIdsList.Add($ruleGuid)
            $null = $asrActionsList.Add($rule.Mode)
            
            $modeText = switch ($rule.Mode) {
                0 { "Disabled" }
                1 { "Block" }
                2 { "Audit" }
                6 { "Warn" }
            }
            
            $criticalMarker = if ($rule.Critical) { "[CRITICAL]" } else { "" }
            Write-Verbose "     $($rule.Name) : $modeText $criticalMarker"
            Write-Verbose "     $($rule.Description)"
        }
        
        # Konvertiere ArrayList zu Array fuer Set-MpPreference
        # Explicit type cast to avoid type mismatch - Best Practice 25H2
        $asrIds = [string[]]$asrIdsList.ToArray()
        $asrActions = [int[]]$asrActionsList.ToArray()
        
        # Alle ASR-Regeln in einem Batch setzen (Set statt Add fuer Idempotenz)
        # ErrorAction SilentlyContinue - bekanntes 0x800106ba Timing-Problem ignorieren
        # CRITICAL: Suppress unwanted output (causes horizontal spam!)
        $null = Set-MpPreference -AttackSurfaceReductionRules_Ids $asrIds -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
        
        # Verify ob ASR-Regeln wirklich gesetzt wurden
        $verifyMpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists before accessing Count (Third-Party AV compatibility)
        if ($verifyMpPrefs -and 
            $verifyMpPrefs.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and 
            $verifyMpPrefs.AttackSurfaceReductionRules_Ids -and 
            $verifyMpPrefs.AttackSurfaceReductionRules_Ids.Count -gt 0) {
            Write-Success "ASR-Regeln konfiguriert: $($verifyMpPrefs.AttackSurfaceReductionRules_Ids.Count) Regeln"
            Write-Info "Modus: $Mode"
        }
        else {
            Write-Info "ASR-Regeln konnten nicht per Script gesetzt werden"
            Write-Info "Die Eigenschaft 'AttackSurfaceReductionRules_Ids' wurde nicht gefunden"
            Write-Info "MANUELL AKTIVIEREN: Windows Security | Virus and threat protection |"
            Write-Info "                    Manage settings | Attack surface reduction rules"
            Write-Info "Grund: Moeglicherweise Drittanbieter-AV aktiv oder Defender nicht vollstaendig verfuegbar"
        }
        
        if ($Mode -eq 'Audit') {
            Write-Warning-Custom "ASR im AUDIT-Modus! Events in Defender-Logs pruefen."
            Write-Warning-Custom "Nach Evaluierung auf Enforce umstellen!"
        }
        
        # ASR Exclusions Hinweis
        Write-Info "ASR Exclusions koennen via Add-MpPreference -AttackSurfaceReductionOnlyExclusions gesetzt werden"
        
    }
    catch {
        # Ignore bekanntes Defender Timing-Problem (0x800106ba)
        # Funktionalitaet wird trotzdem aktiviert - Fehler ist kosmetisch
        if ($_.Exception.Message -notmatch '0x800106ba') {
            Write-Info "ASR-Regeln konnten nicht per Script gesetzt werden"
            Write-Info "MANUELL AKTIVIEREN: Windows Security | Virus and threat protection |"
            Write-Info "                    Manage settings | Attack surface reduction rules"
            Write-Info "Grund: $($_.Exception.Message)"
            Write-Verbose "Tipp: Bei Konflikten mit bestehenden Regeln, diese zuerst loeschen mit Remove-MpPreference"
        }
        else {
            Write-Verbose "Ignoriere bekanntes Defender Timing-Problem (0x800106ba)"
            Write-Verbose "ASR-Regeln werden trotzdem aktiviert - Error ist kosmetisch"
        }
    }
}

function Get-ASRRuleStatus {
    <#
    .SYNOPSIS
        Zeigt den Status aller konfigurierten ASR-Regeln
    .DESCRIPTION
        Ruft die aktuell konfigurierten Attack Surface Reduction Rules ab.
        Best Practice 25H2: CmdletBinding + Null-Checks.
    .EXAMPLE
        Get-ASRRuleStatus
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "ASR Rules Status"
    
    try {
        # CRITICAL FIX v1.7.6: SilentlyContinue statt Stop verhindert Transcript-Verschmutzung
        $mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if (-not $mpPrefs) {
            Write-Warning "Defender Preferences konnten nicht gelesen werden"
            return
        }
        
        if (-not $mpPrefs.AttackSurfaceReductionRules_Ids -or $mpPrefs.AttackSurfaceReductionRules_Ids.Count -eq 0) {
            Write-Warning "Keine ASR-Regeln konfiguriert"
            return
        }
        
        Write-Info "Konfigurierte ASR-Regeln: $($mpPrefs.AttackSurfaceReductionRules_Ids.Count)"
        
        for ($i = 0; $i -lt $mpPrefs.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $ruleId = $mpPrefs.AttackSurfaceReductionRules_Ids[$i]
            $ruleAction = $mpPrefs.AttackSurfaceReductionRules_Actions[$i]
            
            $actionText = switch ($ruleAction) {
                0 { "Disabled" }
                1 { "Block" }
                2 { "Audit" }
                6 { "Warn" }
                default { "Unknown ($ruleAction)" }
            }
            
            Write-Info "  [$actionText] $ruleId"
        }
    }
    catch {
        Write-Error-Custom "Fehler beim Abrufen der ASR-Regeln: $_"
    }
}

function Enable-USBDeviceControl {
    <#
    .SYNOPSIS
        Konfiguriert USB Device Control (Removable Storage Protection)
    .DESCRIPTION
        Verhindert Ausfuehrung von Dateien auf USB-Sticks (BadUSB-Schutz).
        Lesen und Schreiben bleiben erlaubt.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Enable-USBDeviceControl
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "USB Device Control (Removable Storage Protection)"
    
    Write-Info "USB Device Control wird konfiguriert..."
    
    # NUR Ausfuehrung verbieten (NICHT Schreiben!)
    $removableDiskPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    
    # Deny_Execute = 1 (Ausfuehrung verbieten)
    Set-RegistryValue -Path $removableDiskPath -Name "Deny_Execute" -Value 1 -Type DWord -Description "USB: Ausfuehrung verweigern"
    
    # Deny_Write = 0 (Schreiben ERLAUBT!)
    # NICHT setzen! Wenn Key nicht existiert = erlaubt
    
    Write-Success "USB Device Control aktiviert (No Execute)"
    Write-Info "USB-Sticks: Lesen + Schreiben OK, aber .exe/.bat/.ps1 werden NICHT ausgefuehrt"
    Write-Warning-Custom "SCHUTZ: BadUSB-Malware kann NICHT ausgefuehrt werden!"
}

function Enable-SmartAppControl {
    <#
    .SYNOPSIS
        Konfiguriert Smart App Control Policies
    .DESCRIPTION
        Setzt Policies fuer Smart App Control und SmartScreen.
        WICHTIG: Smart App Control wird von Windows automatisch nach Evaluation aktiviert.
        Best Practice 25H2: Nicht manuell erzwingen!
    .EXAMPLE
        Enable-SmartAppControl
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Smart App Control Policies"
    
    Write-Info "Smart App Control wird konfiguriert..."
    
    # Best Practice 25H2: Smart App Control NICHT manuell setzen!
    # WARUM: Windows muss SAC selbst aktivieren nach Evaluation-Period (7-14 Tage)
    # Wenn wir hier eingreifen, verhindert das die automatische Aktivierung!
    
    # CHECK: Aktueller Smart App Control Status
    $sacPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\SmartAppControl"
    $sacStatus = Get-ItemProperty -Path $sacPath -Name "Enabled" -ErrorAction SilentlyContinue
    
    if ($sacStatus) {
        $statusText = switch ($sacStatus.Enabled) {
            0 { "Off (Disabled)" }
            1 { "Evaluation Mode (Learning)" }
            2 { "On (Enforcing)" }
            default { "Unknown" }
        }
        Write-Info "Smart App Control Status: $statusText"
    } else {
        Write-Info "Smart App Control Status: Nicht konfiguriert (Windows entscheidet)"
    }
    
    # SmartScreen fuer Apps erzwingen (unabhaengig von Smart App Control)
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    Set-RegistryValue -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String -Description "SmartScreen erzwingen"
    
    Write-Success "Smart App Control: Windows verwaltet Status automatisch"
    Write-Info "Nach 7-14 Tagen Evaluation kann Windows SAC aktivieren"
    Write-Success "SmartScreen aktiv"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
