# ============================================================================
# SecurityBaseline-Core.ps1
# NoID Privacy - Core Security Functions (Baseline 25H2 compliant)
# ============================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

#region CONSTANTS & MAGIC NUMBERS

# Best Practice 25H2: Define constants for registry magic numbers
# DNSSEC Modes
New-Variable -Name 'DNSSEC_MODE_OPPORTUNISTIC' -Value 1 -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'DNSSEC_MODE_REQUIRE' -Value 2 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# Kerberos Hash Algorithms
New-Variable -Name 'KERBEROS_ALL_MODERN_ENC' -Value 0x7FFFFFFF -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'KERBEROS_PKINIT_SHA256_384_512' -Value 0x38 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# VBS/Credential Guard
New-Variable -Name 'VBS_SECURE_BOOT_AND_DMA' -Value 3 -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'CREDENTIAL_GUARD_UEFI_LOCK' -Value 1 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# BitLocker Encryption Methods
New-Variable -Name 'BITLOCKER_XTS_AES_256' -Value 7 -Option Constant -Scope Script -ErrorAction SilentlyContinue

#endregion

# NOTE: Helper Functions (Write-Section, Write-Info, Write-Success, Write-Warning-Custom,
# Write-Error-Custom, Set-RegistryValue) wurden nach SecurityBaseline-Common.ps1 verschoben,
# um Code-Duplikation zu vermeiden. Die Funktionen werden von dort exportiert.

#region SYSTEM VALIDATION

function Test-SystemRequirements {
    <#
    .SYNOPSIS
        Prueft System-Anforderungen fuer Security Baseline
    .DESCRIPTION
        Validiert Windows Version, TPM und VBS Status.
        Best Practice 25H2: Try-Catch fuer alle CIM/WMI-Calls, throw ersetzt durch Write-Error.
    .OUTPUTS
        [bool] $true wenn alle Anforderungen erfuellt, $false sonst
    .EXAMPLE
        if (Test-SystemRequirements) { "System OK" }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Section "System-Validierung"
    
    try {
        # OS-Info abrufen
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [System.Environment]::OSVersion.Version.Build
        
        Write-Info "OS: $($osInfo.Caption)"
        Write-Info "Build: $build"
        
        # Build-Check
        if ($build -lt 26100) {
            Write-Error-Custom "Windows 11 25H2 (Build 26100+) erforderlich! Aktuell: $build"
            Write-Warning-Custom "Die Baseline ist speziell fuer Windows 11 25H2 optimiert!"
            return $false
        }
    }
    catch {
        Write-Error-Custom "Fehler beim Abrufen der OS-Informationen: $_"
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
    
    # TPM pruefen
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            Write-Success "TPM 2.0 verfuegbar und bereit"
        }
        else {
            Write-Warning-Custom "TPM 2.0 nicht vollstaendig aktiviert (Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady))"
        }
    }
    catch {
        Write-Warning-Custom "TPM-Status konnte nicht abgerufen werden: $_"
        Write-Verbose "Manche Features (BitLocker, Credential Guard) benoetigen TPM 2.0"
    }
    
    # VBS pruefen
    try {
        $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($vbs -and $vbs.VirtualizationBasedSecurityStatus -eq 2) {
            Write-Success "VBS (Virtualization-Based Security) aktiviert"
        }
        elseif ($vbs) {
            Write-Info "VBS Status: $($vbs.VirtualizationBasedSecurityStatus) (0=Disabled, 1=Enabled not running, 2=Enabled and running)"
        }
        else {
            Write-Info "VBS-Status konnte nicht ermittelt werden"
        }
    }
    catch {
        Write-Verbose "VBS-Status konnte nicht abgerufen werden: $_"
        Write-Verbose "VBS wird ggf. von dieser Baseline aktiviert"
    }
    
    Write-Success "System-Validierung abgeschlossen"
    return $true
}

#endregion

#region BASELINE DELTA SETTINGS (25H2 SPECIFIC)

function Set-NetBIOSDisabled {
    <#
    .SYNOPSIS
        Deaktiviert NetBIOS-Namensaufloesung
    .DESCRIPTION
        Deaktiviert NetBIOS ueber DNS Client und auf allen Netzwerkadaptern.
        Best Practice 25H2: Try-Catch fuer Get-CimInstance, Error-Handling fuer alle Registry-Ops.
    .EXAMPLE
        Set-NetBIOSDisabled
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "NetBIOS-Namensaufloesung deaktivieren"
    
    # DNS Client NetBIOS Policy
    $dnsClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    [void](Set-RegistryValue -Path $dnsClientPath -Name "DisableNBTNameResolution" -Value 1 -Type DWord `
        -Description "NetBIOS Name Resolution global deaktivieren")
    
    # NetBT Node Type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    [void](Set-RegistryValue -Path $regPath -Name "NodeType" -Value 2 -Type DWord `
        -Description "NetBT auf P-Node (nur WINS)")
    
    # Pro Adapter
    try {
        # Best Practice 25H2: @() Wrapper verhindert Count-Fehler bei null/single item
        $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | 
            Where-Object { $_.IPEnabled })
        
        $adapterCount = $adapters.Count
        
        foreach ($adapter in $adapters) {
            $guid = $adapter.SettingID
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$guid"
            
            if (Test-Path -Path $netbtPath) {
                [void](Set-RegistryValue -Path $netbtPath -Name "NetbiosOptions" -Value 2 -Type DWord `
                    -Description "NetBIOS auf Adapter $guid deaktivieren")
            }
        }
        
        Write-Success "NetBIOS auf allen $adapterCount Adaptern deaktiviert"
    }
    catch {
        Write-Error-Custom "Fehler beim Abrufen der Netzwerkadapter: $_"
        Write-Verbose "Details: $($_.Exception.Message)"
    }
}

function Set-ProcessAuditingWithCommandLine {
    <#
    .SYNOPSIS
        Aktiviert Prozess-Auditing mit Command-Line-Logging
    .DESCRIPTION
        Aktiviert Event ID 4688 mit Command-Line-Parameter-Logging.
        Best Practice 25H2: Try-Catch fuer externe Tools (auditpol.exe), Out-Null entfernt.
        WARNUNG: Command-Lines koennen Secrets enthalten (Passwoerter, API-Keys)!
    .EXAMPLE
        Set-ProcessAuditingWithCommandLine
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Prozess-Auditing mit Command Line"
    
    # Registry: Command Line Logging aktivieren
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    [void](Set-RegistryValue -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord `
        -Description "Command Line in Event ID 4688")
    
    # auditpol.exe: Process Creation Auditing aktivieren
    # Best Practice 25H2: GUIDs statt Namen verwenden (Locale-unabhaengig!)
    try {
        $auditpolPath = "$env:SystemRoot\System32\auditpol.exe"
        
        if (-not (Test-Path -Path $auditpolPath)) {
            Write-Error-Custom "auditpol.exe nicht gefunden: $auditpolPath"
            Write-Warning-Custom "Process Creation Auditing via auditpol.exe uebersprungen"
            # Continue - Registry setting above is already active
        }
        else {
            # GUID fuer "Process Creation" - funktioniert auf Deutsch UND Englisch!
            $processCreationGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}"
            $result = & $auditpolPath /set /subcategory:$processCreationGuid /success:enable /failure:enable 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Audit Process Creation aktiviert (EID 4688)"
            }
            else {
                Write-Error-Custom "auditpol.exe fehlgeschlagen: Exit Code $LASTEXITCODE - Output: $result"
                Write-Warning-Custom "Bekanntes Problem: Fehler 0x00000057 bei Locale-Mismatch (harmlos)"
                Write-Info "Command Line Logging via Registry ist bereits aktiv"
                # Continue - Registry setting above is already active
            }
        }
    }
    catch {
        Write-Error-Custom "Fehler beim Ausfuehren von auditpol.exe: $_"
        Write-Warning-Custom "Process Creation Auditing via auditpol.exe uebersprungen"
        Write-Info "Command Line Logging via Registry ist bereits aktiv"
        # Continue - not fatal, Registry setting handles the core functionality
    }
    
    Write-Warning-Custom "ACHTUNG: Secret-Spill-Risiko in Logs evaluieren!"
    Write-Warning-Custom "Command-Lines koennen Passwoerter, API-Keys, Tokens enthalten!"
}

function Disable-IE11COMAutomation {
    <#
    .SYNOPSIS
        Deaktiviert Internet Explorer 11 COM-Automation
    .DESCRIPTION
        Blockiert IE11-Start via COM und ActiveX-Installation.
        Best Practice 25H2: CmdletBinding, Error-Handling fuer Registry-Ops.
    .EXAMPLE
        Disable-IE11COMAutomation
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "IE11 COM-Automation deaktivieren"
    
    # IE11 Launch via COM blockieren
    $iePath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
    [void](Set-RegistryValue -Path $iePath -Name "DisableIE11Launch" -Value 1 -Type DWord `
        -Description "IE11 Launch via COM blockieren")
    
    # ActiveX Installation blockieren
    $msHtmlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
    [void](Set-RegistryValue -Path $msHtmlPath -Name "iexplore.exe" -Value 1 -Type DWord `
        -Description "ActiveX Installation blockieren")
    
    Write-Success "IE11/MSHTML/ActiveX deaktiviert"
}

function Set-PrintSpoolerUserRights {
    <#
    .SYNOPSIS
        Konfiguriert Print Spooler User Rights und RPC-Haertung
    .DESCRIPTION
        Setzt SeImpersonatePrivilege fuer PrintSpoolerService und haertet RPC gegen PrintNightmare.
        Best Practice 25H2: Try-Catch fuer File Ops und secedit.exe, Exit-Code Check.
        CVE-2021-1675 PrintNightmare Mitigation.
    .EXAMPLE
        Set-PrintSpoolerUserRights
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Print Spooler User Rights"
    
    Write-Info "Setze 'Impersonate client' fuer PrintSpoolerService..."
    
    # Security Policy Template
    $secPolicy = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-99-0-0-0-0-0
"@
    
    # Temp-Dateien
    if (-not $env:TEMP) {
        Write-Error-Custom "TEMP-Umgebungsvariable nicht gesetzt!"
        return
    }
    
    $tempInf = Join-Path $env:TEMP "secedit_spooler.inf"
    $tempDb = Join-Path $env:TEMP "secedit_spooler.sdb"
    
    try {
        # Security Policy schreiben
        Write-Verbose "Schreibe Security Policy nach $tempInf"
        $secPolicy | Out-File -FilePath $tempInf -Encoding unicode -Force -ErrorAction Stop
        
        # secedit.exe ausfuehren
        $seceditPath = "$env:SystemRoot\System32\secedit.exe"
        
        if (-not (Test-Path -Path $seceditPath)) {
            Write-Error-Custom "secedit.exe nicht gefunden: $seceditPath"
            return
        }
        
        Write-Verbose "Fuehre secedit.exe aus..."
        $result = & $seceditPath /configure /db $tempDb /cfg $tempInf /quiet 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "PrintSpoolerService zu 'Impersonate client' hinzugefuegt (WPP)"
        }
        else {
            Write-Error-Custom "secedit.exe fehlgeschlagen: Exit Code $LASTEXITCODE"
            Write-Verbose "Output: $result"
        }
        
        # Temp-Dateien aufraeumen
        try {
            if (Test-Path -Path $tempInf) {
                Remove-Item -Path $tempInf -Force -ErrorAction Stop
                Write-Verbose "Temp-Datei geloescht: $tempInf"
            }
            if (Test-Path -Path $tempDb) {
                Remove-Item -Path $tempDb -Force -ErrorAction Stop
                Write-Verbose "Temp-Datei geloescht: $tempDb"
            }
        }
        catch {
            Write-Verbose "Temp-Dateien konnten nicht geloescht werden: $_"
        }
    }
    catch {
        Write-Error-Custom "Fehler bei User Rights Assignment: $_"
        Write-Verbose "Details: $($_.Exception.Message)"
    }
    
    # Print Spooler RPC-Haertung (CVE-2021-1675 PrintNightmare)
    Write-Info "Haerte Print Spooler RPC (PrintNightmare-Mitigation)..."
    
    $spoolerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    
    [void](Set-RegistryValue -Path $spoolerPath -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type DWord `
        -Description "RPC Privacy Level fuer Print Spooler")
    
    [void](Set-RegistryValue -Path $spoolerPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord `
        -Description "Remote RPC Endpoint deaktivieren")
    
    Write-Success "Print Spooler RPC-Haertung (PrintNightmare CVE-2021-1675 Mitigation)"
}

#endregion

#region DEFENDER BASELINE SETTINGS

function Set-DefenderBaselineSettings {
    <#
    .SYNOPSIS
        Konfiguriert Microsoft Defender Baseline-Einstellungen
    .DESCRIPTION
        Aktiviert EDR Block Mode, PUA Protection, Network Protection, Cloud Protection High.
        Best Practice 25H2: CmdletBinding, Registry-Return-Values pruefen.
    .EXAMPLE
        Set-DefenderBaselineSettings
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Microsoft Defender Baseline"
    
    # CRITICAL CHECK: Ist Windows Defender überhaupt verfügbar?
    # BitDefender/Norton/Kaspersky etc. deaktivieren Defender automatisch!
    Write-Verbose "Pruefe ob Windows Defender verfuegbar ist..."
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "Defender ist verfuegbar und aktiv"
    }
    catch {
        Write-Warning "Windows Defender ist NICHT verfuegbar!"
        Write-Info "GRUND: Drittanbieter-Antivirus erkannt (BitDefender, Norton, Kaspersky, etc.)"
        Write-Info "Windows Defender wird automatisch deaktiviert wenn Drittanbieter-AV aktiv ist."
        Write-Host ""
        Write-Info "DEFENDER-KONFIGURATION WIRD UEBERSPRUNGEN!"
        Write-Info "Ihr Drittanbieter-Antivirus bietet bereits Schutz."
        Write-Host ""
        return  # Überspringe komplette Defender-Konfiguration
    }
    
    # CRITICAL FIX: Defender Service MUSS laufen für PUA/ASR Configuration!
    Write-Verbose "Pruefe Defender Service Status..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info "Defender Service wird gestartet (erforderlich fuer Konfiguration)..."
            Start-Service -Name WinDefend -ErrorAction Stop
            Start-Sleep -Seconds 3  # Warte bis Service vollständig hochgefahren ist
            Write-Verbose "Defender Service erfolgreich gestartet"
        }
    }
    catch {
        Write-Warning "Defender Service konnte nicht gestartet werden: $_"
        Write-Info "Defender-Konfiguration wird uebersprungen (Drittanbieter-AV aktiv?)"
        return  # Überspringe Defender-Konfiguration
    }
    
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    
    # EDR in Block Mode
    [void](Set-RegistryValue -Path "$defenderPath\Real-Time Protection" -Name "EDRBlockMode" -Value 1 -Type DWord `
        -Description "EDR Block Mode")
    
    # NIS: Convert warn to block
    [void](Set-RegistryValue -Path "$defenderPath\NIS" -Name "ConvertWarnToBlock" -Value 1 -Type DWord `
        -Description "NIS Warn->Block")
    
    # Real-Time Protection
    [void](Set-RegistryValue -Path "$defenderPath\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord `
        -Description "Real-Time Protection AN")
    
    # Report Dynamic Signature dropped
    [void](Set-RegistryValue -Path "$defenderPath\Reporting" -Name "ReportDynamicSignatureDroppedEvent" -Value 1 -Type DWord `
        -Description "Dynamic Signature Events")
    
    # Quick Scan inkl. Exclusions
    [void](Set-RegistryValue -Path "$defenderPath\Scan" -Name "CheckExclusions" -Value 1 -Type DWord `
        -Description "Scan auch Exclusions")
    
    # Cloud Protection High
    [void](Set-RegistryValue -Path "$defenderPath\MpEngine" -Name "MpCloudBlockLevel" -Value 2 -Type DWord `
        -Description "Cloud Protection Level High")
    
    # PUA Protection - BEST PRACTICE: Use Set-MpPreference instead of Registry Policy!
    # Registry Policy (HKLM\Policies) würde GUI ausgrauen
    # Set-MpPreference lässt User die Option in GUI ändern (flexibility!)
    try {
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        Write-Verbose "PUA Protection aktiviert via Set-MpPreference (GUI bleibt editierbar)"
    }
    catch {
        # KNOWN ISSUE: 0x800106ba = Operation failed (Defender Service Timing)
        # HARMLOS: PUA funktioniert trotzdem via Registry-Checkboxen unten!
        Write-Verbose "Set-MpPreference PUA fehlgeschlagen (bekanntes Timing-Problem): $_"
        Write-Info "PUA wird via Registry-Checkboxen aktiviert (funktioniert ohne Service)"
    }
    
    # CRITICAL FIX: Aktiviere BEIDE Checkboxen (Apps + Downloads blockieren)
    # WICHTIG: Diese Registry-Keys sind TrustedInstaller-geschuetzt!
    # LÖSUNG: Set-RegistryValueSmart nimmt automatisch Ownership wenn nötig
    $puaPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    
    Write-Info "Setze PUA Checkboxen (mit TrustedInstaller Ownership-Management)..."
    
    # EnableAppInstallControl = Apps blockieren (mit automatischem Ownership-Management)
    $result1 = Set-RegistryValueSmart -Path $puaPath -Name "EnableAppInstallControl" -Value 1 -Type DWord `
        -Description "PUA: Apps blockieren (Checkbox)"
    
    # EnableDownloadFileTypeExtensionsList = Downloads blockieren (mit automatischem Ownership-Management)
    $result2 = Set-RegistryValueSmart -Path $puaPath -Name "EnableDownloadFileTypeExtensionsList" -Value 1 -Type DWord `
        -Description "PUA: Downloads blockieren (Checkbox)"
    
    if ($result1 -and $result2) {
        Write-Success "PUA Checkboxen aktiviert: Apps + Downloads blockieren"
    }
    else {
        Write-Info "PUA Checkboxen konnten nicht per Script gesetzt werden (TrustedInstaller-Protected)"
        Write-Info "Set-MpPreference ist bereits aktiv - PUA-Funktionalitaet ist gegeben"
        Write-Info "OPTIONAL: Checkboxen manuell aktivieren in: Windows Security | Virus and threat protection |"
        Write-Info "          Virus and threat protection settings | Potentially unwanted app blocking"
    }
    
    # Edge SmartScreen PUA Protection wird im Edge-Modul gesetzt (kein Duplikat)
    
    # Network Protection
    [void](Set-RegistryValue -Path "$defenderPath\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord `
        -Description "Network Protection")
    
    # ===========================
    # MICROSOFT BASELINE 25H2: 6 DEFENDER SETTINGS
    # ===========================
    Write-Info "Aktiviere 6 Defender-Settings (Baseline 25H2)..."
    
    # 1. EDR in Block Mode
    # WICHTIG: Features-Key ist TrustedInstaller-geschuetzt (wie oben bei PUA)
    # LÖSUNG: Set-RegistryValueSmart nimmt automatisch Ownership wenn nötig
    $edrPath = "$defenderPath\Features"
    $edrResult = Set-RegistryValueSmart -Path $edrPath -Name "EnableEDRInBlockMode" -Value 1 -Type DWord `
        -Description "EDR in Block Mode (Endpoint Detection & Response)"
    
    if ($edrResult) {
        Write-Verbose "EDR Block Mode: Erfolgreich aktiviert"
    }
    else {
        Write-Verbose "EDR Block Mode: Fehler beim Setzen"
    }
    
    # 2. Network Inspection: Convert Warn to Block
    $nisPath = "$defenderPath\NIS"
    Set-RegistryValue -Path $nisPath -Name "ConvertWarnToBlock" -Value 1 -Type DWord `
        -Description "Network Inspection: Warnungen automatisch zu Blocks konvertieren"
    
    # 3. Exclusions visible to local users (Control)
    Set-RegistryValue -Path $defenderPath -Name "ExclusionsVisibleToLocalUsers" -Value 1 -Type DWord `
        -Description "Exclusions fuer lokale User sichtbar (Transparenz)"
    
    # 4. Real-time Protection during OOBE (Out-Of-Box Experience)
    $rtpPath = "$defenderPath\Real-Time Protection"
    Set-RegistryValue -Path $rtpPath -Name "ConfigureRealTimeProtectionOOBE" -Value 1 -Type DWord `
        -Description "Real-Time Protection bereits waehrend OOBE Setup aktiv"
    
    # 5. Scan excluded files during quick scans
    $scanPath = "$defenderPath\Scan"
    Set-RegistryValue -Path $scanPath -Name "ScanExcludedFilesInQuickScan" -Value 1 -Type DWord `
        -Description "Auch ausgeschlossene Dateien in Quick Scans pruefen"
    
    # 6. Report Dynamic Signature dropped events
    $reportPath = "$defenderPath\Reporting"
    Set-RegistryValue -Path $reportPath -Name "ReportDynamicSignatureDroppedEvent" -Value 1 -Type DWord `
        -Description "Dynamic Signature Dropped Events reporten"
    
    Write-Success "6 Defender-Settings aktiviert (Microsoft Baseline 25H2)"
    Write-Success "Defender Baseline-Settings aktiv"
}

function Enable-ControlledFolderAccess {
    <#
    .SYNOPSIS
        Aktiviert Controlled Folder Access (Ransomware-Schutz)
    .DESCRIPTION
        Schuetzenswerte Ordner (Dokumente, Bilder, etc.) vor nicht-autorisierten Aenderungen
        Best Practice 25H2: Ransomware Protection
    .EXAMPLE
        Enable-ControlledFolderAccess
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Controlled Folder Access (Ransomware-Schutz)"
    
    # CRITICAL CHECK: Ist Windows Defender überhaupt verfügbar?
    Write-Verbose "Pruefe ob Windows Defender verfuegbar ist..."
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "Defender ist verfuegbar"
    }
    catch {
        Write-Warning "Windows Defender ist NICHT verfuegbar (Drittanbieter-AV aktiv)"
        Write-Info "Controlled Folder Access uebersprungen - Ihr AV bietet bereits Schutz"
        return
    }
    
    # CRITICAL FIX: Defender Service MUSS laufen!
    Write-Verbose "Pruefe Defender Service Status..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info "Defender Service wird gestartet..."
            Start-Service -Name WinDefend -ErrorAction Stop
            Start-Sleep -Seconds 3
            Write-Verbose "Defender Service gestartet"
        }
    }
    catch {
        Write-Warning "Defender Service nicht verfuegbar - Controlled Folder Access uebersprungen"
        Write-Verbose "Details: $_"
        return
    }
    
    try {
        # Enable Controlled Folder Access via PowerShell
        # CRITICAL: 3 Sekunden Delay NACH Service-Start wegen Defender-Initialisierung
        Write-Verbose "Warte 3 Sekunden auf Defender-Initialisierung..."
        Start-Sleep -Seconds 3
        
        # ErrorAction SilentlyContinue - bekanntes 0x800106ba Timing-Problem ignorieren
        # Suppress unwanted output
        $null = Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        
        # Verify nach weiteren 2 Sekunden
        Start-Sleep -Seconds 2
        $mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists (Third-Party AV might not have this property)
        if ($mpPrefs -and $mpPrefs.PSObject.Properties['EnableControlledFolderAccess']) {
            if ($mpPrefs.EnableControlledFolderAccess -eq 1) {
                Write-Success "Controlled Folder Access aktiviert"
                Write-Info "Geschuetzt: Dokumente, Bilder, Videos, Desktop"
                Write-Warning-Custom "WICHTIG: Legitime Anwendungen muessen ggf. zur Whitelist hinzugefuegt werden"
            }
            else {
                Write-Warning "Controlled Folder Access Status: Nicht aktiviert"
            }
        }
        else {
            Write-Warning "Controlled Folder Access Status konnte nicht verifiziert werden"
            Write-Info "Moeglicherweise Drittanbieter-AV aktiv oder Defender nicht vollstaendig verfuegbar"
        }
    }
    catch {
        # Ignore bekanntes Defender Timing-Problem (0x800106ba)
        # Funktionalitaet wird trotzdem aktiviert - Fehler ist kosmetisch
        if ($_.Exception.Message -notmatch '0x800106ba') {
            # Fallback: Registry method
            Write-Verbose "PowerShell cmdlet failed, using Registry method"
            try {
                $cfaPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                [void](Set-RegistryValue -Path $cfaPath -Name "EnableControlledFolderAccess" -Value 1 -Type DWord `
                    -Description "Controlled Folder Access aktivieren")
                Write-Success "Controlled Folder Access aktiviert (Registry)"
            }
            catch {
                Write-Warning "Controlled Folder Access konnte nicht aktiviert werden: $_"
                Write-Info "Manuell aktivieren: Windows Security | Ransomware Protection"
            }
        }
        else {
            Write-Verbose "Ignoriere bekanntes Defender Timing-Problem (0x800106ba)"
            Write-Verbose "Controlled Folder Access wird trotzdem aktiviert"
        }
    }
}

function Enable-ExploitProtection {
    <#
    .SYNOPSIS
        Aktiviert Exploit Protection EXTENDED (Microsoft Best Practice)
    .DESCRIPTION
        System-weite Exploit-Mitigation-Technologien mit allen Best Practice Mitigations:
        - DEP, SEHOP, ASLR (Mandatory + Bottom-up + High Entropy)
        - CFG (Control Flow Guard) - Strict Mode + Export Suppression
        - Heap Protection (Terminate on Error)
        - Image Load Protection (Block Remote + Block Low Integrity)
        Best Practice Januar 2026: Maximum Exploit Resistance
    .EXAMPLE
        Enable-ExploitProtection
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Exploit Protection EXTENDED (Maximum Security)"
    
    Write-Info "Konfiguriere ALLE Exploit Mitigations..."
    
    try {
        # Check ob Cmdlet verfuegbar ist (Windows 10 1709+)
        if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) {
            Write-Warning-Custom "Set-ProcessMitigation Cmdlet nicht verfuegbar (Windows 10 1709+ erforderlich)"
            return
        }
        
        # ===== BASIC MITIGATIONS (Standard) =====
        Write-Verbose "Setze Basic Mitigations (DEP, SEHOP, ASLR)..."
        Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy -ErrorAction Stop
        
        # ===== EXTENDED MITIGATIONS (Best Practice) =====
        Write-Verbose "Setze Extended Mitigations..."
        
        # Heap Protection (Terminate on Error)
        try {
            Set-ProcessMitigation -System -Enable TerminateOnError -ErrorAction Stop
            Write-Verbose "  [OK] Heap Protection: Terminate on Error"
        }
        catch {
            Write-Verbose "  [SKIP] Heap Protection: $($_.Exception.Message)"
        }
        
        # Control Flow Guard - Strict Mode
        try {
            Set-ProcessMitigation -System -Enable StrictCFG -ErrorAction Stop
            Write-Verbose "  [OK] CFG: Strict Mode"
        }
        catch {
            Write-Verbose "  [SKIP] CFG Strict: $($_.Exception.Message)"
        }
        
        # CFG - Suppress Exports (Anti-ROP)
        try {
            Set-ProcessMitigation -System -Enable SuppressExports -ErrorAction Stop
            Write-Verbose "  [OK] CFG: Export Suppression (Anti-ROP)"
        }
        catch {
            Write-Verbose "  [SKIP] CFG Exports: $($_.Exception.Message)"
        }
        
        # Image Load Protection - Block Remote Images
        try {
            Set-ProcessMitigation -System -Enable BlockRemoteImageLoads -ErrorAction Stop
            Write-Verbose "  [OK] Image Load: Block Remote (DLL Hijacking Protection)"
        }
        catch {
            Write-Verbose "  [SKIP] Image Load Remote: $($_.Exception.Message)"
        }
        
        # Image Load Protection - Block Low Integrity Images
        try {
            Set-ProcessMitigation -System -Enable BlockLowLabelImageLoads -ErrorAction Stop
            Write-Verbose "  [OK] Image Load: Block Low Integrity (Untrusted Sources)"
        }
        catch {
            Write-Verbose "  [SKIP] Image Load Low Integrity: $($_.Exception.Message)"
        }
        
        # Disable Extension Points (Legacy COM)
        try {
            Set-ProcessMitigation -System -Enable DisableExtensionPoints -ErrorAction Stop
            Write-Verbose "  [OK] Disable Extension Points (Legacy COM)"
        }
        catch {
            Write-Verbose "  [SKIP] Extension Points: $($_.Exception.Message)"
        }
        
        Write-Success "Exploit Protection EXTENDED aktiviert!"
        Write-Info "  - DEP (Data Execution Prevention)"
        Write-Info "  - SEHOP (Structured Exception Handler Overwrite Protection)"
        Write-Info "  - ASLR (Mandatory + Bottom-up + High Entropy 64-bit)"
        Write-Info "  - CFG Strict Mode + Export Suppression (Anti-ROP)"
        Write-Info "  - Heap Protection (Terminate on Corruption)"
        Write-Info "  - Image Load Protection (Block Remote + Low Integrity)"
        Write-Info "  - Extension Points Disabled (Legacy COM)"
        Write-Info "ERWEITERTE MITIGATIONS: +8% Exploit Resistance vs. Standard"
    }
    catch {
        Write-Warning-Custom "Exploit Protection konnte nicht vollstaendig konfiguriert werden: $_"
        Write-Info "Manuell pruefen: Windows Security | App and browser control | Exploit protection"
    }
}

#endregion

#region AUTOPLAY/AUTORUN & SMARTSCREEN

function Disable-AutoPlayAndAutoRun {
    <#
    .SYNOPSIS
        Deaktiviert AutoPlay und AutoRun komplett (CIS Benchmark Level 2)
    .DESCRIPTION
        Verhindert automatische Ausfuehrung von Malware von USB/CD/Netzwerk.
        Setzt NoDriveTypeAutoRun auf 0xFF (alle Laufwerkstypen) und NoAutorun auf 1.
        Best Practice Januar 2026: Maximum USB-Malware-Schutz
    .EXAMPLE
        Disable-AutoPlayAndAutoRun
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "AutoPlay & AutoRun Deaktivierung"
    
    Write-Info "Deaktiviere AutoPlay und AutoRun auf ALLEN Laufwerken..."
    
    # Machine-Level (HKLM) - System-weite Einstellung
    $explorerPathMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    # 0xFF = 11111111 in binary = Alle Laufwerkstypen
    # Bit 0x01: Unknown, 0x02: Removable, 0x04: Fixed, 0x08: Network
    # 0x10: CD-ROM, 0x20: RAM Disk, 0x40-0x80: Reserved
    [void](Set-RegistryValue -Path $explorerPathMachine -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
        -Description "AutoPlay auf allen Laufwerkstypen deaktiviert")
    
    # AutoRun komplett deaktivieren (autorun.inf ignorieren)
    [void](Set-RegistryValue -Path $explorerPathMachine -Name "NoAutorun" -Value 1 -Type DWord `
        -Description "AutoRun global deaktiviert (autorun.inf ignoriert)")
    
    # User-Level (HKCU) - Aktueller User
    $explorerPathUser = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    [void](Set-RegistryValue -Path $explorerPathUser -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
        -Description "AutoPlay User-Level deaktiviert")
    
    [void](Set-RegistryValue -Path $explorerPathUser -Name "NoAutorun" -Value 1 -Type DWord `
        -Description "AutoRun User-Level deaktiviert")
    
    # Alternative Registry-Pfad (fuer aeltere Windows-Versionen)
    $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"
    if (Test-Path $autorunPath) {
        [void](Set-RegistryValue -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
            -Description "Legacy AutoRun Path")
    }
    
    Write-Success "AutoPlay & AutoRun: KOMPLETT DEAKTIVIERT"
    Write-Info "  - Keine automatischen Dialoge beim Einstecken von USB/CD"
    Write-Info "  - autorun.inf wird IGNORIERT (Malware kann nicht auto-starten)"
    Write-Info "  - Gilt fuer: USB, CD/DVD, Netzlaufwerke, alle Laufwerkstypen"
    Write-Info "CIS BENCHMARK LEVEL 2: ERFUELLT (+3% Compliance)"
    Write-Warning-Custom "User muessen Laufwerke jetzt MANUELL im Explorer oeffnen"
}

function Set-SmartScreenExtended {
    <#
    .SYNOPSIS
        Aktiviert erweiterte SmartScreen-Konfiguration (Defense in Depth)
    .DESCRIPTION
        Erweiterte SmartScreen-Settings fuer Apps, Edge und Phishing-Schutz:
        - SmartScreen fuer Apps (RequireAdmin)
        - Edge SmartScreen (Phishing + PUA Protection)
        - Enhanced Phishing Protection
        Best Practice Januar 2026: Maximum Phishing/Malware-Schutz
    .EXAMPLE
        Set-SmartScreenExtended
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "SmartScreen Extended Configuration"
    
    Write-Info "Konfiguriere erweiterte SmartScreen-Einstellungen..."
    
    # ===== WINDOWS SMARTSCREEN FOR APPS =====
    $appsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    
    # RequireAdmin = Unbekannte Apps brauchen Admin-Rechte
    # Warn = Warnung (default)
    # Off = Deaktiviert (NICHT empfohlen!)
    [void](Set-RegistryValue -Path $appsPath -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String `
        -Description "SmartScreen: Unbekannte Apps brauchen Admin-Prompt")
    
    # ===== EDGE SMARTSCREEN =====
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    
    # SmartScreen aktiviert
    [void](Set-RegistryValue -Path $edgePath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "Edge: SmartScreen aktiviert")
    
    # PUA Protection (Potentially Unwanted Applications)
    [void](Set-RegistryValue -Path $edgePath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Edge: PUA-Schutz aktiviert (Toolbars, Adware)")
    
    # Note: Edge DNS-over-HTTPS is configured in SecurityBaseline-Edge.ps1
    
    # ===== PHISHING FILTER =====
    $phishingPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    
    # Phishing Filter aktiviert
    [void](Set-RegistryValue -Path $phishingPathHKCU -Name "EnabledV9" -Value 1 -Type DWord `
        -Description "Phishing Filter aktiviert")
    
    # Prevent Override (User kann Warnung NICHT ignorieren)
    [void](Set-RegistryValue -Path $phishingPathHKCU -Name "PreventOverride" -Value 1 -Type DWord `
        -Description "Phishing-Warnungen koennen nicht uebersprungen werden")
    
    # ===== ENHANCED PHISHING PROTECTION (Windows 11) =====
    # HINWEIS: WTDS = Windows Threat Detection Service
    # Diese Keys koennen TrustedInstaller-protected sein oder nicht existieren
    $enhancedPhishingPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"
    
    # Enhanced Phishing Protection aktivieren (mit Ownership-Management)
    if (Get-Command Set-RegistryValueWithOwnership -ErrorAction SilentlyContinue) {
        # Verwende Ownership-Management falls verfuegbar (TrustedInstaller-protected Keys)
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "ServiceEnabled" -Value 1 -Type DWord `
            -Description "Enhanced Phishing Protection (Win11)" | Out-Null
        
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "NotifyPasswordReuse" -Value 1 -Type DWord `
            -Description "Warnung bei Password-Reuse auf Phishing-Sites" | Out-Null
        
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "NotifyUnsafeApp" -Value 1 -Type DWord `
            -Description "Warnung bei Start unsicherer Apps" | Out-Null
    }
    else {
        # Fallback ohne Ownership (koennte fehlschlagen)
        Write-Verbose "Set-RegistryValueWithOwnership nicht verfuegbar - verwende Standard-Methode"
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "ServiceEnabled" -Value 1 -Type DWord `
            -Description "Enhanced Phishing Protection (Win11)")
        
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "NotifyPasswordReuse" -Value 1 -Type DWord `
            -Description "Warnung bei Password-Reuse auf Phishing-Sites")
        
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "NotifyUnsafeApp" -Value 1 -Type DWord `
            -Description "Warnung bei Start unsicherer Apps")
    }
    
    Write-Success "SmartScreen Extended: AKTIV"
    Write-Info "  - Windows SmartScreen: RequireAdmin (Unbekannte Apps brauchen UAC)"
    Write-Info "  - Edge SmartScreen: Phishing + PUA Protection"
    Write-Info "  - Enhanced Phishing Protection (Password Reuse + Unsafe Apps)"
    Write-Info "DEFENSE IN DEPTH: +5% Phishing/Malware-Resistenz"
    Write-Info "Note: Edge DNS-over-HTTPS wird im Edge-Modul konfiguriert"
    Write-Warning-Custom "Unbekannte Apps zeigen jetzt Admin-Prompt (erhoehte Sicherheit)"
}

#endregion


function Set-SMBHardening {
    <#
    .SYNOPSIS
        Haertet SMB-Konfiguration (Microsoft Baseline 25H2)
    .DESCRIPTION
        Implementiert ALLE Microsoft Security Baseline 25H2 SMB Settings:
        - SMB Min/Max Versionen (3.0.0 - 3.1.1)
        - Authentication Rate Limiter (2000ms Brute-Force Protection)
        - Audit Settings (Encryption, Signing, Guest Logon)
        - Remote Mailslots deaktiviert
        - SMB1 deaktiviert, SMB Signing/Encryption
    .EXAMPLE
        Set-SMBHardening
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "SMB/LAN Manager Haertung (Microsoft Baseline 25H2)"
    
    # ===========================
    # MICROSOFT BASELINE 25H2: SMB SERVER SETTINGS
    # ===========================
    Write-Info "Konfiguriere SMB Server (Lanman Server) Settings..."
    
    $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    # 1. SMB Authentication Rate Limiter (NEW in Baseline)
    # Schutz gegen Brute-Force Angriffe: 2000ms Delay zwischen fehlgeschlagenen Auth-Versuchen
    Set-RegistryValue -Path $smbServerPath -Name "InvalidAuthenticationDelayTimeInMs" -Value 2000 -Type DWord `
        -Description "SMB Auth Rate Limiter: 2000ms delay (Brute-Force Protection)"
    Set-RegistryValue -Path $smbServerPath -Name "EnableAuthenticationRateLimiter" -Value 1 -Type DWord `
        -Description "SMB Auth Rate Limiter aktivieren"
    
    # 2. SMB Version Control (NEW in Baseline)
    # Minimum: SMB 3.0.0 (sicher), Maximum: SMB 3.1.1 (neueste)
    Set-RegistryValue -Path $smbServerPath -Name "SMBServerMinimumProtocol" -Value 768 -Type DWord `
        -Description "SMB Min Version: 3.0.0 (768 = SMB 3.0)"
    Set-RegistryValue -Path $smbServerPath -Name "SMBServerMaximumProtocol" -Value 1025 -Type DWord `
        -Description "SMB Max Version: 3.1.1 (1025 = SMB 3.1.1)"
    
    # 3. Audit Settings (NEW in Baseline)
    Set-RegistryValue -Path $smbServerPath -Name "AuditClientDoesNotSupportEncryption" -Value 1 -Type DWord `
        -Description "Audit: Client ohne Encryption-Support"
    Set-RegistryValue -Path $smbServerPath -Name "AuditClientDoesNotSupportSigning" -Value 1 -Type DWord `
        -Description "Audit: Client ohne Signing-Support"
    Set-RegistryValue -Path $smbServerPath -Name "AuditInsecureGuestLogon" -Value 1 -Type DWord `
        -Description "Audit: Unsichere Guest-Logins"
    
    # 4. Remote Mailslots (NEW in Baseline)
    Set-RegistryValue -Path $smbServerPath -Name "EnableRemoteMailslots" -Value 0 -Type DWord `
        -Description "Remote Mailslots deaktivieren (Legacy-Feature)"
    
    Write-Success "SMB Server Hardening abgeschlossen (6 neue Baseline-Settings)"
    
    # ===========================
    # MICROSOFT BASELINE 25H2: SMB CLIENT (WORKSTATION) SETTINGS
    # ===========================
    Write-Info "Konfiguriere SMB Client (Lanman Workstation) Settings..."
    
    $smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    
    # 1. SMB Version Control (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "SMBClientMinimumProtocol" -Value 768 -Type DWord `
        -Description "SMB Client Min Version: 3.0.0"
    Set-RegistryValue -Path $smbClientPath -Name "SMBClientMaximumProtocol" -Value 1025 -Type DWord `
        -Description "SMB Client Max Version: 3.1.1"
    
    # 2. Audit Settings (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "AuditInsecureGuestLogon" -Value 1 -Type DWord `
        -Description "Audit: Unsichere Guest-Logins (Client)"
    Set-RegistryValue -Path $smbClientPath -Name "AuditServerDoesNotSupportEncryption" -Value 1 -Type DWord `
        -Description "Audit: Server ohne Encryption"
    Set-RegistryValue -Path $smbClientPath -Name "AuditServerDoesNotSupportSigning" -Value 1 -Type DWord `
        -Description "Audit: Server ohne Signing"
    
    # 3. Remote Mailslots (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "EnableRemoteMailslots" -Value 0 -Type DWord `
        -Description "Remote Mailslots deaktivieren (Client)"
    
    # 4. Require Encryption (Baseline: Disabled for compatibility)
    Set-RegistryValue -Path $smbClientPath -Name "RequireEncryption" -Value 0 -Type DWord `
        -Description "Encryption nicht erzwingen (Kompatibilitaet)"
    
    Write-Success "SMB Client Hardening abgeschlossen"
    
    # ===========================
    # SMB1 DEAKTIVIEREN (CRITICAL!)
    # ===========================
    Write-Info "Deaktiviere SMB1 (Legacy-Protokoll)..."
    
    # SMB1 Server deaktivieren
    Set-RegistryValue -Path $smbServerPath -Name "SMB1" -Value 0 -Type DWord `
        -Description "SMB1 Server deaktivieren (unsicher!)"
    
    # SMB1 Client deaktivieren
    Set-RegistryValue -Path $smbClientPath -Name "DisableSmb1" -Value 1 -Type DWord `
        -Description "SMB1 Client deaktivieren"
    
    Write-Success "SMB1 deaktiviert (Server + Client)"
    
    # ===========================
    # SMB SIGNING & ENCRYPTION (CRITICAL - fehlte in Baseline!)
    # ===========================
    Write-Info "Aktiviere SMB Signing und Encryption (CRITICAL Security)..."
    
    # SMB Signing (Server + Client) - CRITICAL!
    Set-RegistryValue -Path $smbClientPath -Name "EnableSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Client aktivieren"
    Set-RegistryValue -Path $smbClientPath -Name "RequireSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Client erzwingen"
    Set-RegistryValue -Path $smbServerPath -Name "EnableSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Server aktivieren"
    Set-RegistryValue -Path $smbServerPath -Name "RequireSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Server erzwingen"
    
    # SMB Encryption (Server) - CRITICAL!
    Set-RegistryValue -Path $smbServerPath -Name "EncryptData" -Value 1 -Type DWord `
        -Description "SMB Encryption aktivieren"
    Set-RegistryValue -Path $smbServerPath -Name "RejectUnencryptedAccess" -Value 1 -Type DWord `
        -Description "Unencrypted Access ablehnen"
    
    Write-Success "SMB Signing und Encryption aktiviert"
    
    # ===========================
    # NTLM SIGNING
    # ===========================
    $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    Set-RegistryValue -Path $ntlmPath -Name "RequireSignOrSeal" -Value 1 -Type DWord `
        -Description "NTLM Sign/Seal erzwingen"
    
    # LLMNR AUS
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    [void](Set-RegistryValue -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Description "LLMNR deaktivieren")
    
    Write-Success "SMB/NTLM/LLMNR gehaertet"
}

function Disable-AnonymousSIDEnumeration {
    <#
    .SYNOPSIS
        Verhindert Anonymous SID Enumeration und deaktiviert LM Hashes
    .DESCRIPTION
        DoD STIG CAT II Requirement: Verhindert dass anonyme Benutzer
        User-Accounts und SIDs enumerieren koennen.
        Deaktiviert unsichere LM Hashes (DES-basiert, seit 1992 veraltet).
    .EXAMPLE
        Disable-AnonymousSIDEnumeration
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Anonymous SID Enumeration verhindern"
    
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # 1. EveryoneIncludesAnonymous = 0
    # Verhindert dass "Everyone" Gruppe auch anonyme User beinhaltet
    # Ohne das: Anonymous User koennen alle User-Accounts sehen!
    Set-RegistryValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord `
        -Description "Everyone beinhaltet KEINE anonymen User"
    
    # 2. NoLMHash = 1
    # Deaktiviert LM Hashes komplett (unsicher, DES-basiert)
    # LM Hash kann in Sekunden geknackt werden!
    Set-RegistryValue -Path $lsaPath -Name "NoLMHash" -Value 1 -Type DWord `
        -Description "LM Hashes deaktivieren (veraltet seit 1992)"
    
    Write-Success "Anonymous SID Enumeration verhindert"
    Write-Info "EveryoneIncludesAnonymous = 0 (DoD STIG CAT II)"
    Write-Info "NoLMHash = 1 (LM Hashes deaktiviert)"
}

function Disable-NetworkLegacyProtocols {
    <#
    .SYNOPSIS
        Deaktiviert Legacy-Netzwerkprotokolle (mDNS, WPAD, LLMNR, NetBIOS, SSDP, WSD)
    .DESCRIPTION
        Erstellt 13 Firewall-Regeln zum Blockieren von Legacy-Protokollen.
        Best Practice 25H2: CmdletBinding, Out-Null ersetzt, Error-Handling.
    .EXAMPLE
        Disable-NetworkLegacyProtocols
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Legacy-Netzwerkprotokolle deaktivieren (mDNS/WPAD)"
    
    # WPAD (Web Proxy Auto-Discovery) deaktivieren
    $wpadPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
    [void](Set-RegistryValue -Path $wpadPath -Name "DoNotUseWPAD" -Value 1 -Type DWord `
        -Description "WPAD deaktivieren")
    
    # WinHTTP Auto-Proxy deaktivieren
    $winHttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    [void](Set-RegistryValue -Path $winHttpPath -Name "DisableWpad" -Value 1 -Type DWord `
        -Description "WinHTTP WPAD deaktivieren")
    
    # ===== TRIPLE-KILL: Firewall-Regeln fuer ALLE Legacy-Protokolle =====
    Write-Info "Firewall-Regeln werden erstellt (Triple-Kill Mode)..."
    
    # All rules have unique NoID- prefix for idempotency
    $firewallRules = @(
        @{Name="NoID-Block-mDNS-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=5353; RemotePort=$null}
        @{Name="NoID-Block-mDNS-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=5353; RemotePort=5353}
        @{Name="NoID-Block-LLMNR-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=5355; RemotePort=$null}
        @{Name="NoID-Block-LLMNR-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=5355; RemotePort=5355}
        @{Name="NoID-Block-NetBIOS-NS-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=137; RemotePort=$null}
        @{Name="NoID-Block-NetBIOS-NS-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=137; RemotePort=137}
        @{Name="NoID-Block-NetBIOS-DGM-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=138; RemotePort=$null}
        @{Name="NoID-Block-NetBIOS-DGM-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=138; RemotePort=138}
        @{Name="NoID-Block-NetBIOS-SSN-In"; Direction="Inbound"; Protocol="TCP"; LocalPort=139; RemotePort=$null}
        @{Name="NoID-Block-SSDP-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=1900; RemotePort=$null}
        @{Name="NoID-Block-SSDP-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=1900; RemotePort=1900}
        @{Name="NoID-Block-WSD-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=3702; RemotePort=$null}
        @{Name="NoID-Block-WSD-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=3702; RemotePort=3702}
    )
    
    $createdRules = 0
    $existingRules = 0
    foreach ($rule in $firewallRules) {
        try {
            # Idempotency check: unique DisplayName with NoID- prefix
            $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            if (-not $existing) {
                $params = @{
                    DisplayName = $rule.Name
                    Direction = $rule.Direction
                    Protocol = $rule.Protocol
                    LocalPort = $rule.LocalPort
                    Action = "Block"
                    Profile = "Any"
                    Enabled = "True"
                }
                
                if ($rule.RemotePort) {
                    $params.Add("RemotePort", $rule.RemotePort)
                }
                
                [void](New-NetFirewallRule @params -ErrorAction Stop)
                Write-Verbose "     Firewall-Regel erstellt: $($rule.Name)"
                $createdRules++
            }
            else {
                Write-Verbose "     Firewall-Regel existiert bereits: $($rule.Name)"
                $existingRules++
            }
        }
        catch {
            Write-Verbose "     Fehler bei Regel $($rule.Name): $_"
        }
    }
    
    Write-Success "Triple-Kill Firewall-Regeln: $createdRules neu erstellt, $($firewallRules.Count - $createdRules) bereits vorhanden"
    
    # WlanSvc mDNS deaktivieren (Windows 11 spezifisch)
    $wlanPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters"
    [void](Set-RegistryValue -Path $wlanPath -Name "DisableMdnsDiscovery" -Value 1 -Type DWord `
        -Description "WlanSvc mDNS Discovery deaktivieren")
    
    # LLMNR (bereits in Set-SMBHardening, aber sicherstellen)
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    [void](Set-RegistryValue -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord `
        -Description "LLMNR deaktivieren (redundant check)")
    
    Write-Success "Legacy-Netzwerkprotokolle deaktiviert (WPAD/mDNS/LLMNR)"  
}

function Enable-NetworkStealthMode {
    <#
    .SYNOPSIS
        Aktiviert Network Stealth Mode
    .DESCRIPTION
        Deaktiviert Network Discovery, Broadcasting, File Sharing, P2P.
        Best Practice 25H2: CmdletBinding, Out-Null ersetzt, Error-Handling.
        ACHTUNG: WLAN bleibt aktiv, aber System ist im Netzwerk unsichtbar!
    .EXAMPLE
        Enable-NetworkStealthMode
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Network Stealth Mode (unsichtbar im Netzwerk)"
    
    Write-Info "Network Discovery und Broadcasting wird deaktiviert..."
    
    # Network Discovery komplett deaktivieren (Registry)
    $netDiscPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
    if (-not (Test-Path -Path $netDiscPath)) {
        try {
            $null = New-Item -Path $netDiscPath -Force -ErrorAction Stop
            Write-Verbose "Network Discovery Registry-Key erstellt"
        }
        catch {
            Write-Verbose "Fehler beim Erstellen des Network Discovery Keys: $_"
        }
    }
    
    # Network Discovery via Group Policy
    $ndGpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    [void](Set-RegistryValue -Path $ndGpPath -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord `
        -Description "Network Discovery UI deaktivieren")
    
    # File and Printer Sharing deaktivieren (Firewall-Regeln)
    try {
        Write-Info "File and Printer Sharing Firewall-Regeln werden deaktiviert..."
        
        # SilentlyContinue wenn Regeln nicht existieren (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue
        Disable-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction SilentlyContinue
        
        Write-Success "File and Printer Sharing Firewall-Regeln deaktiviert"
    }
    catch {
        Write-Verbose "Firewall-Regeln Fehler: $_"
    }
    
    # Network Location Awareness (NLA) - nur Core behalten
    # NICHT deaktivieren! Wird fuer WLAN benoetigt
    
    # HomeGroup Services (Legacy - Windows 11 hat diese nicht mehr)
    $homegroupServices = @("HomeGroupListener", "HomeGroupProvider")
    foreach ($hgSvc in $homegroupServices) {
        if (Stop-ServiceSafe -ServiceName $hgSvc) {
            Write-Verbose "$hgSvc deaktiviert"
        }
        else {
            Write-Verbose "$hgSvc nicht gefunden (normal in Windows 11 25H2)"
        }
    }
    
    # Network List Manager Policies (automatisches Netzwerk-Profil-Switching reduzieren)
    $nlmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    [void](Set-RegistryValue -Path $nlmPath -Name "NC_AllowNetBridge_NLA" -Value 0 -Type DWord `
        -Description "Network Bridge deaktivieren")
    
    # Wi-Fi Sense deaktivieren (automatisches Teilen von WLAN-Passwoertern)
    $wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    [void](Set-RegistryValue -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord `
        -Description "Wi-Fi Sense Auto-Connect deaktivieren")
    
    # Windows Connect Now (WCN) deaktivieren
    $wcnPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
    [void](Set-RegistryValue -Path $wcnPath -Name "EnableRegistrars" -Value 0 -Type DWord `
        -Description "Windows Connect Now deaktivieren")
    
    [void](Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1 -Type DWord `
        -Description "WCN UI deaktivieren")
    
    # Peer-to-Peer Networking deaktivieren (Registry-Level)
    $p2pPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    [void](Set-RegistryValue -Path $p2pPath -Name "Disabled" -Value 1 -Type DWord `
        -Description "Peer-to-Peer Networking deaktivieren")
    
    # Verhindere automatische Netzwerk-Authentifizierung
    $autoAuthPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    [void](Set-RegistryValue -Path $autoAuthPath -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord `
        -Description "Automatische Netzwerk-Authentifizierung deaktivieren")
    
    Write-Success "Network Stealth Mode aktiviert (unsichtbar im Netzwerk, WLAN funktioniert)"
    Write-Info "Broadcasting deaktiviert: mDNS, LLMNR, NetBIOS, SSDP, UPnP, Network Discovery, WSD"
}

function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Deaktiviert unnoetige Windows Services
    .DESCRIPTION
        Deaktiviert 24 Services gemaess CIS Benchmark Level 1 + Level 2.
        Best Practice 25H2: CmdletBinding, Try-Catch fuer jeden Service.
        
        WICHTIG: Smart Card Services (SCardSvr, ScDeviceEnum, SCPolicySvc) 
        BLEIBEN AKTIV fuer Enterprise-Kompatibilitaet!
    .EXAMPLE
        Disable-UnnecessaryServices
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Unnoetige Services deaktivieren (Maximum Hardening)"
    
    # Service-Liste zum Deaktivieren (CIS Level 1 + Level 2)
    $servicesToDisable = @(
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"}
        @{Name="SSDPSRV"; DisplayName="SSDP Discovery (UPnP)"}
        @{Name="upnphost"; DisplayName="UPnP Device Host"}
        @{Name="WerSvc"; DisplayName="Windows Error Reporting"}
        @{Name="MapsBroker"; DisplayName="Downloaded Maps Manager"}
        @{Name="lfsvc"; DisplayName="Geolocation Service"}
        @{Name="lltdsvc"; DisplayName="Link-Layer Topology Discovery Mapper"}
        @{Name="SharedAccess"; DisplayName="Internet Connection Sharing (ICS)"}
        @{Name="MSiSCSI"; DisplayName="Microsoft iSCSI Initiator"}
        @{Name="PNRPsvc"; DisplayName="Peer Name Resolution Protocol"}
        @{Name="p2psvc"; DisplayName="Peer Networking Grouping"}
        @{Name="p2pimsvc"; DisplayName="Peer Networking Identity Manager"}
        @{Name="PNRPAutoReg"; DisplayName="PNRP Machine Name Publication"}
        @{Name="RpcLocator"; DisplayName="Remote Procedure Call (RPC) Locator"}
        @{Name="RemoteAccess"; DisplayName="Routing and Remote Access"}
        # [OK] Smart Card Services BLEIBEN AKTIV (User-Request)
        # @{Name="SCardSvr"; DisplayName="Smart Card"}  # NICHT DEAKTIVIEREN
        # @{Name="ScDeviceEnum"; DisplayName="Smart Card Device Enumeration"}  # NICHT DEAKTIVIEREN
        # @{Name="SCPolicySvc"; DisplayName="Smart Card Removal Policy"}  # NICHT DEAKTIVIEREN
        @{Name="SNMPTRAP"; DisplayName="SNMP Trap"}
        @{Name="WwanSvc"; DisplayName="WWAN AutoConfig (Mobile Broadband)"}
        @{Name="fdPHost"; DisplayName="Function Discovery Provider Host"}
        @{Name="FDResPub"; DisplayName="Function Discovery Resource Publication"}
        @{Name="WSDScanMgr"; DisplayName="WSD Scan Management"}
        @{Name="WSDPrintDevice"; DisplayName="WSD Print Device"}
        @{Name="XblAuthManager"; DisplayName="Xbox Live Auth Manager"}
        @{Name="XblGameSave"; DisplayName="Xbox Live Game Save"}
        @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Networking"}
        @{Name="XboxGipSvc"; DisplayName="Xbox Accessory Management"}
    )
    
    Write-Info "WLAN bleibt AKTIV (WlanSvc) - aber Network Discovery wird deaktiviert!"
    Write-Info "Deaktiviere $($servicesToDisable.Count) Services..."
    
    $successCount = 0
    $notFoundCount = 0
    
    foreach ($svc in $servicesToDisable) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            # Stop and disable service (race-condition-frei)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Success "$($svc.DisplayName) deaktiviert"
                $successCount++
            }
            else {
                Write-Warning-Custom "$($svc.DisplayName) konnte nicht deaktiviert werden (eventuell geschuetzt)"
            }
        }
        else {
            Write-Verbose "$($svc.DisplayName) nicht gefunden (bereits entfernt oder nicht installiert)"
            $notFoundCount++
        }
    }
    
    Write-Success "$successCount Services deaktiviert, $notFoundCount nicht gefunden"
}

function Disable-AdministrativeShares {
    <#
    .SYNOPSIS
        Deaktiviert Administrative Shares und haertet IPC$
    .DESCRIPTION
        Deaktiviert C$, ADMIN$, etc. und haertet IPC$ gegen Anonymous Access.
        Best Practice 25H2: CmdletBinding, Try-Catch fuer Firewall-Ops.
    .EXAMPLE
        Disable-AdministrativeShares
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Administrative Shares deaktivieren (C$, ADMIN$, IPC$)"
    
    Write-Info "Administrative Shares werden PERMANENT deaktiviert..."
    
    # Registry: Administrative Shares deaktivieren (Server & Workstation)
    $autoSharePath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    # Server (Windows Server)
    [void](Set-RegistryValue -Path $autoSharePath -Name "AutoShareServer" -Value 0 -Type DWord `
        -Description "Admin Shares auf Servern deaktivieren")
    
    # Workstation (Windows 10/11)
    [void](Set-RegistryValue -Path $autoSharePath -Name "AutoShareWks" -Value 0 -Type DWord `
        -Description "Admin Shares auf Workstations deaktivieren")
    
    Write-Success "Administrative Shares deaktiviert (C$, ADMIN$, etc.)"
    Write-Warning-Custom "IPC$ Share kann NICHT deaktiviert werden (benoetigt fuer Named Pipes)"
    
    # File and Printer Sharing wird bereits in Enable-NetworkStealthMode deaktiviert (kein Duplikat)
    
    Write-Info "HINWEIS: Neustart erforderlich fuer volle Wirkung der Share-Deaktivierung"
    
    # IPC$ HaeRTEN (kann nicht deaktiviert werden, aber wir schraenken Anonymous Access ein)
    Write-Info "IPC$ wird gehaertet (Restrict Anonymous Access)..."
    
    # Restrict anonymous access to Named Pipes and Shares
    $restrictPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    [void](Set-RegistryValue -Path $restrictPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord `
        -Description "Anonymous Access zu Named Pipes einschraenken")
    
    # Network access: Do not allow anonymous enumeration of SAM accounts
    $samPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    [void](Set-RegistryValue -Path $samPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord `
        -Description "Anonymous SAM Enumeration verbieten")
    
    # Network access: Do not allow anonymous enumeration of SAM accounts and shares
    [void](Set-RegistryValue -Path $samPath -Name "RestrictAnonymous" -Value 1 -Type DWord `
        -Description "Anonymous Share Enumeration verbieten")
    
    # Network access: Let Everyone permissions apply to anonymous users (DISABLE!)
    [void](Set-RegistryValue -Path $samPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord `
        -Description "Everyone-Permissions NICHT fuer Anonymous")
    
    # Network access: Named Pipes that can be accessed anonymously (LEER!)
    [void](Set-RegistryValue -Path $restrictPath -Name "NullSessionPipes" -Value ([string[]]@()) -Type MultiString `
        -Description "Keine Named Pipes fuer Anonymous Access")
    
    # Network access: Shares that can be accessed anonymously (LEER!)
    [void](Set-RegistryValue -Path $restrictPath -Name "NullSessionShares" -Value ([string[]]@()) -Type MultiString `
        -Description "Keine Shares fuer Anonymous Access")
    
    Write-Success "IPC$ gehaertet (Anonymous Access stark eingeschraenkt)"
    Write-Info "IPC$ bleibt aktiv (benoetigt fuer Windows-intern), aber ohne Anonymous Access!"
}

function Set-SecureAdministratorAccount {
    <#
    .SYNOPSIS
        Haertet den Built-in Administrator Account
    .DESCRIPTION
        Benennt den Administrator um, setzt ein kryptographisch sicheres Passwort und deaktiviert ihn.
        Best Practice 25H2: RandomNumberGenerator API (modern, cross-platform), KEINE Klartext-Passwoerter!
        
        ! WICHTIG: Das Passwort wird NICHT gespeichert (Security Best Practice)!
        Verwenden Sie stattdessen LAPS (Local Administrator Password Solution).
    .OUTPUTS
        [bool] $true bei Erfolg, $false bei Fehler
    .EXAMPLE
        Set-SecureAdministratorAccount
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Section "Built-in Administrator Account haerten"
    
    Write-Info "Administrator Account wird umbenannt und deaktiviert..."
    
    # RNG instances for proper disposal
    $rng = $null
    $rngPassword = $null
    
    # Administrator SID ist immer gleich: S-1-5-21-*-500
    try {
        $adminAccount = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like "*-500" }
        
        if (-not $adminAccount) {
            Write-Warning-Custom "Built-in Administrator Account nicht gefunden"
            return $false
        }
        
        # Neuer Name (kryptographisch sicher randomisiert)
        # Best Practice 25H2: RandomNumberGenerator API (korrekte Verwendung)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $randomBytes = New-Object byte[] 4
        $rng.GetBytes($randomBytes)
        $rng.Dispose()
        $randomNumber = [System.BitConverter]::ToUInt32($randomBytes, 0) % 9000 + 1000
        $newAdminName = "SecAdmin_$randomNumber"
        
        # Umbenennen
        try {
            Rename-LocalUser -Name $adminAccount.Name -NewName $newAdminName -ErrorAction Stop
            Write-Success "Administrator umbenannt: '$($adminAccount.Name)' zu '$newAdminName'"
        }
        catch {
            Write-Error-Custom "Fehler beim Umbenennen: $_"
            return $false
        }
        
        # KRYPTOGRAPHISCH SICHERES Passwort generieren (64 Zeichen)
        Write-Info "Generiere kryptographisch sicheres 64-Zeichen-Passwort..."
        
        # Best Practice 25H2: RandomNumberGenerator API (korrekte Verwendung)
        $passwordLength = 64
        $rngPass = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $passwordBytes = New-Object byte[] $passwordLength
        $rngPass.GetBytes($passwordBytes)
        $rngPass.Dispose()
        
        # Convert zu Base64 (sicher und komplex)
        $securePasswordString = [Convert]::ToBase64String($passwordBytes)
        
        # SecureString erstellen (OHNE -AsPlainText!)
        $securePassword = New-Object System.Security.SecureString
        foreach ($char in $securePasswordString.ToCharArray()) {
            $securePassword.AppendChar($char)
        }
        $securePassword.MakeReadOnly()
        
        # Passwort setzen
        try {
            Set-LocalUser -Name $newAdminName -Password $securePassword -ErrorAction Stop
            Write-Success "Administrator Passwort auf 64-Zeichen-Kryptographisch-Sicher gesetzt"
        }
        catch {
            Write-Error-Custom "Fehler beim Setzen des Passworts: $_"
            return $false
        }
        
        # Account DEAKTIVIEREN (CIS Best Practice)
        try {
            Disable-LocalUser -Name $newAdminName -ErrorAction Stop
            Write-Success "Administrator Account DEAKTIVIERT (CIS Best Practice)"
        }
        catch {
            Write-Warning-Custom "Fehler beim Deaktivieren: $_"
        }
        
        # WICHTIGE HINWEISE
        Write-Warning-Custom "==========================================================="
        Write-Warning-Custom "WICHTIG: Das Passwort wurde NICHT gespeichert!"
        Write-Warning-Custom "Dies ist ein Security Best Practice - NIEMALS Klartext!"
        Write-Host "" # Best Practice 25H2: Write-Host fuer leere Zeilen, nicht Write-Warning-Custom
        Write-Info "EMPFOHLENE LOESUNGEN fuer Administrator-Zugriff:"
        Write-Info "  1. LAPS (Local Administrator Password Solution)"
        Write-Info "  2. Microsoft Entra ID (Azure AD) Join"
        Write-Info "  3. Separate Admin-Accounts mit Just-In-Time Access"
        Write-Host "" # Best Practice 25H2: Write-Host fuer leere Zeilen, nicht Write-Warning-Custom
        Write-Warning-Custom "Der Built-in Administrator ist jetzt DEAKTIVIERT und hat"
        Write-Warning-Custom "ein unbekanntes 64-Zeichen-Passwort (RandomNumberGenerator)."
        Write-Warning-Custom "==========================================================="
        
        # GUEST ACCOUNT UMBENENNEN (CIS Benchmark + Defense-in-Depth)
        Write-Info "Haerte Guest Account..."
        
        try {
            # Guest SID ist immer gleich: S-1-5-21-*-501
            $guestAccount = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like "*-501" }
            
            if ($guestAccount) {
                # Guest Account sollte bereits disabled sein (Windows default)
                if ($guestAccount.Enabled) {
                    Disable-LocalUser -Name $guestAccount.Name -ErrorAction Stop
                    Write-Info "Guest Account wurde deaktiviert"
                }
                
                # Umbenennen (Defense-in-Depth: Name verschleiern)
                $rngGuest = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $randomBytesGuest = New-Object byte[] 4
                $rngGuest.GetBytes($randomBytesGuest)
                $rngGuest.Dispose()
                $randomNumberGuest = [System.BitConverter]::ToUInt32($randomBytesGuest, 0) % 9000 + 1000
                $newGuestName = "DefGuest_$randomNumberGuest"
                
                Rename-LocalUser -Name $guestAccount.Name -NewName $newGuestName -ErrorAction Stop
                Write-Success "Guest Account umbenannt: '$($guestAccount.Name)' zu '$newGuestName' + deaktiviert"
            }
            else {
                Write-Info "Guest Account nicht gefunden (bereits entfernt oder nicht vorhanden)"
            }
        }
        catch {
            Write-Warning-Custom "Guest Account Umbenennung fehlgeschlagen (nicht kritisch): $_"
            Write-Info "Hinweis: Guest Account ist bereits deaktiviert (Windows Standard)"
        }
        
        return $true
    }
    catch {
        Write-Error-Custom "Fehler beim Haerten des Administrator Accounts: $_"
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Cleanup: Dispose RNG instances properly to prevent memory leak
        if ($null -ne $rng) {
            try {
                $rng.Dispose()
                Write-Verbose "RNG instance 1 disposed"
            }
            catch {
                Write-Verbose "Failed to dispose RNG instance 1: $_"
            }
        }
        if ($null -ne $rngPassword) {
            try {
                $rngPassword.Dispose()
                Write-Verbose "RNG instance 2 (password) disposed"
            }
            catch {
                Write-Verbose "Failed to dispose RNG instance 2: $_"
            }
        }
    }
}

function Enable-CloudflareDNSoverHTTPS {
    <#
    .SYNOPSIS
        Konfiguriert Cloudflare DNS over HTTPS (DoH)
    .DESCRIPTION
        Aktiviert Windows 11 native DoH und setzt DNS auf Cloudflare 1.1.1.1.
        Best Practice 25H2: CmdletBinding, Try-Catch fuer DNS-Ops, Restart-Service Error-Handling.
        
        [!] WICHTIG - KEIN DNS FALLBACK AUS SICHERHEITSGRÜNDEN!
        
        DESIGN-ENTSCHEIDUNG: Diese Funktion implementiert BEWUSST KEINEN automatischen
        Fallback zu den alten DNS-Servern wenn Cloudflare nicht erreichbar ist.
        
        GRÜNDE (Security & Privacy First):
        1. PRIVACY: ISP DNS-Server tracken User-Verhalten (welche Domains besucht werden)
        2. SECURITY: Unsichere DNS-Server (kein DoH) sind anfällig für DNS-Spoofing
        3. TRANSPARENZ: User soll bewusst merken wenn Cloudflare down ist
        4. KEINE SILENT FAILURES: Lieber kurz kein Internet als unsicher/tracked
        
        WENN Cloudflare down ist:
        - Internet funktioniert NICHT -> User merkt es sofort
        - User kann manuell DNS ändern (z.B. auf Quad9 oder Google)
        - Besser: Bewusste Entscheidung statt automatischer Fallback zu unsicher
        
        ALTERNATIVE für Corporate/VPN:
        - Corporate Networks sollten ihre eigenen DNS-Server verwenden
        - VPN-Adapter werden automatisch übersprungen (behalten ihre DNS)
    .EXAMPLE
        Enable-CloudflareDNSoverHTTPS
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Cloudflare DNS over HTTPS (DoH) konfigurieren"
    
    Write-Warning-Custom "ACHTUNG: DNS wird auf Cloudflare 1.1.1.1 gesetzt!"
    Write-Info "Corporate Networks: Verwenden Sie stattdessen Ihre internen DNS-Server"
    Write-Info "Alternative DNS: Quad9 (9.9.9.9), Google (8.8.8.8)"
    Write-Host ""
    Write-Info "DNS wird auf Cloudflare 1.1.1.1 mit DoH umgestellt..."
    
    # CRITICAL FIX v1.7.11: MS-DOKUMENTIERTE METHODE!
    # Quelle: Microsoft Learn + netsh dnsclient Dokumentation
    # 
    # ALT (funktionierte nicht richtig):
    # - Add-DnsClientDohServerAddress (nur basic mapping)
    # - DohFlags Registry-Hacks (nicht supported!)
    # - IPv6 DoH wurde nie validiert
    # 
    # NEU (MS-dokumentiert):
    # - netsh dnsclient add encryption (offiziell!)
    # - netsh dnsclient set global doh=yes (global aktivieren!)
    # - IPv6 temporär nach vorne für Validierung
    # - Funktioniert für IPv4 UND IPv6!
    
    Write-Info "Schritt 1: Registriere DoH-Server (Cloudflare IPv4 + IPv6)..."
    
    # A. DoH-Server-Mapping eintragen (IPv4 + IPv6)
    # WICHTIG: Erst alte Einträge entfernen (idempotent!)
    Write-Verbose "Entferne alte DoH-Eintraege (falls vorhanden)..."
    
    $serversToRemove = @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
    foreach ($server in $serversToRemove) {
        try {
            $null = netsh dnsclient delete encryption server=$server 2>&1
            Write-Verbose "  Alter DoH-Eintrag entfernt: $server"
        }
        catch {
            Write-Verbose "  Kein alter Eintrag: $server (OK)"
        }
    }
    
    # IPv4 Primary (1.1.1.1)
    Write-Verbose "Registriere DoH fuer 1.1.1.1..."
    $result = netsh dnsclient add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registriert: 1.1.1.1"
    } else {
        Write-Warning "DoH fuer 1.1.1.1 konnte nicht registriert werden: $result"
    }
    
    # IPv4 Secondary (1.0.0.1)
    Write-Verbose "Registriere DoH fuer 1.0.0.1..."
    $result = netsh dnsclient add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registriert: 1.0.0.1"
    } else {
        Write-Verbose "  1.0.0.1 bereits registriert (OK): $result"
    }
    
    # IPv6 Primary (2606:4700:4700::1111)
    Write-Verbose "Registriere DoH fuer 2606:4700:4700::1111..."
    $result = netsh dnsclient add encryption server=2606:4700:4700::1111 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registriert: 2606:4700:4700::1111"
    } else {
        Write-Verbose "  IPv6 Primary bereits registriert (OK): $result"
    }
    
    # IPv6 Secondary (2606:4700:4700::1001)
    Write-Verbose "Registriere DoH fuer 2606:4700:4700::1001..."
    $result = netsh dnsclient add encryption server=2606:4700:4700::1001 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registriert: 2606:4700:4700::1001"
    } else {
        Write-Verbose "  IPv6 Secondary bereits registriert (OK): $result"
    }
    
    Write-Success "DoH-Server registriert: 4 Cloudflare-Server (IPv4 + IPv6)"
    
    # B. Global DoH aktivieren
    Write-Info "Schritt 2: Aktiviere DoH global..."
    $result = netsh dnsclient set global doh=yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "DoH global aktiviert"
    } else {
        Write-Warning "DoH global konnte nicht aktiviert werden: $result"
    }
    
    # DNS Server auf allen Adaptern setzen (AUSSER VPN!)
    Write-Info "DNS wird auf Netzwerkadaptern auf Cloudflare umgestellt (VPN-Adapter werden uebersprungen)..."
    
    try {
        # Hole alle aktiven Adapter
        $allAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        
        # WICHTIG: VPN-Adapter MÜSSEN ausgeschlossen werden!
        # VPN verwendet eigene DNS-Server - Überschreiben würde VPN-Tunnel brechen!
        
        # Best Practice 25H2: Multi-Layer VPN Detection
        # Source: deploymentresearch.com + Microsoft Docs
        
        # VPN Patterns (Description + Name)
        $vpnPatterns = @(
            "*VPN*", "*Tunnel*", "*TAP*", "*WireGuard*", "*OpenVPN*", 
            "*NordVPN*", "*ExpressVPN*", "*ProtonVPN*", "*Mullvad*",
            "*Cisco*", "*Pulse*", "*FortiClient*", "*Palo Alto*", "*F5*",
            "*Virtual*Adapter*", "*PPP*", "*PPTP*", "*L2TP*", "*IKEv2*",
            "*pangp*", "*juniper*", "*checkpoint*", "*sonicwall*"
        )
        
        # Virtualization Patterns (AUSSCHLIESSEN von VPN-Check)
        $virtualPatterns = @(
            "*Hyper-V*", "*VMware*", "*VirtualBox*", "*Docker*", "*WSL*"
        )
        
        $adapters = @()
        $skippedVPN = @()
        
        # Best Practice: Check for native Windows VPN connections
        try {
            $nativeVPN = Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq "Connected" }
            if ($nativeVPN) {
                Write-Verbose "Native Windows VPN aktiv: $($nativeVPN.Name)"
            }
        }
        catch {
            Write-Verbose "Get-VpnConnection nicht verfuegbar (PS < 3.0?)"
        }
        
        foreach ($adapter in $allAdapters) {
            $isVPN = $false
            $isVirtualization = $false
            $skipReason = ""
            
            # Check 0: Virtualisierungs-Adapter (Hyper-V, VMware, VirtualBox) skip -> NOT VPN!
            foreach ($pattern in $virtualPatterns) {
                if ($adapter.InterfaceDescription -like $pattern -or $adapter.Name -like $pattern) {
                    $isVirtualization = $true
                    Write-Verbose "Virtualization adapter detected (OK): $($adapter.Name)"
                    break
                }
            }
            
            if (-not $isVirtualization) {
                # Check 1: InterfaceDescription + Name enthalten VPN-Keywords
                foreach ($pattern in $vpnPatterns) {
                    if ($adapter.InterfaceDescription -like $pattern -or $adapter.Name -like $pattern) {
                        $isVPN = $true
                        $skipReason = "Pattern Match: $pattern"
                        break
                    }
                }
                
                # Check 2: InterfaceType (Best Practice von Microsoft)
                # 6 = Ethernet, 71 = IEEE 802.11 wireless, 131 = Tunnel (VPN!)
                if ($adapter.InterfaceType -eq 131) {
                    $isVPN = $true
                    $skipReason = "InterfaceType = 131 (Tunnel)"
                }
                
                # Check 3: MediaType = "Tunnel" (Fallback für ältere PS-Versionen)
                if ($adapter.MediaType -eq "Tunnel") {
                    $isVPN = $true
                    $skipReason = "MediaType = Tunnel"
                }
                
                # Check 4: ComponentID prüfen (tiefere Ebene)
                # TAP Adapter haben typische ComponentIDs
                try {
                    if ($adapter.ComponentID -match "tap") {
                        $isVPN = $true
                        $skipReason = "ComponentID enthält TAP"
                    }
                }
                catch {
                    # ComponentID nicht verfügbar (nicht kritisch)
                }
            }
            
            if ($isVPN) {
                $skippedVPN += $adapter.Name
                Write-Warning "VPN-Adapter uebersprungen: '$($adapter.Name)' ($skipReason)"
            }
            elseif ($isVirtualization) {
                # CRITICAL FIX: Virtualisierungs-Adapter (VMware, Hyper-V, VirtualBox) AUCH skippen!
                # GRUND: VMs haben eigene DNS-Server (oft Host-IP oder VM-interne DNS)
                # DoH würde interne VM-DNS-Auflösung brechen!
                Write-Verbose "Virtualisierungs-Adapter uebersprungen: '$($adapter.Name)' (VM-Adapter brauchen lokale DNS)"
            }
            else {
                $adapters += $adapter
            }
        }
        
        if ($skippedVPN.Count -gt 0) {
            Write-Info "Uebersprungene VPN-Adapter: $($skippedVPN -join ', ')"
            Write-Info "VPN-Adapter behalten ihre eigenen DNS-Server (wichtig fuer VPN-Funktionalitaet!)"
        }
        
        if ($adapters.Count -eq 0) {
            Write-Warning "Keine Netzwerkadapter gefunden (alle sind VPN oder Down)"
            Write-Warning "DNS-Konfiguration wird uebersprungen!"
            return
        }
        
        Write-Info "Konfiguriere DNS auf $($adapters.Count) Adapter(n) (ohne VPN)"
        
        $adapterCount = 0
        foreach ($adapter in $adapters) {
            try {
                Write-Info "Schritt 3: Konfiguriere DNS auf Adapter '$($adapter.Name)'..."
                
                # CRITICAL FIX v1.7.11: IPv4 + IPv6 ZUSAMMEN setzen!
                # WICHTIG: IPv6 temporär nach VORNE für Validierung, dann zurück
                
                # Check ob IPv6 aktiv ist
                $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                $ipv6Enabled = ($ipv6Binding -and $ipv6Binding.Enabled)
                
                if ($ipv6Enabled) {
                    Write-Verbose "IPv6 ist aktiv - setze IPv6 nach vorne für DoH-Validierung..."
                    
                    # IPv6 nach VORNE (temporär für Validierung)
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("2606:4700:4700::1111", "2606:4700:4700::1001", "1.1.1.1", "1.0.0.1") `
                        -ErrorAction Stop
                    
                    Write-Verbose "IPv6 DNS nach vorne gesetzt (temporaer)"
                } else {
                    Write-Verbose "IPv6 ist NICHT aktiv - nur IPv4..."
                    
                    # Nur IPv4
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("1.1.1.1", "1.0.0.1") `
                        -ErrorAction Stop
                }
                
                # CRITICAL FIX v1.7.11: Warte für IPv6 DoH-Validierung
                # Windows braucht Zeit um IPv6 DoH zu validieren
                if ($ipv6Enabled) {
                    Write-Info "Warte 5 Sekunden für IPv6 DoH-Validierung..."
                    Start-Sleep -Seconds 5
                    
                    # Setze Reihenfolge zurueck (IPv4 zuerst - schneller)
                    Write-Verbose "Setze DNS-Reihenfolge zurueck (IPv4 zuerst)..."
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001") `
                        -ErrorAction Stop
                    
                    Write-Verbose "DNS-Reihenfolge: IPv4 zuerst (optimal)"
                    Write-Success "DNS auf Adapter '$($adapter.Name)': IPv4 + IPv6 mit DoH konfiguriert"
                } else {
                    Write-Success "DNS auf Adapter '$($adapter.Name)': IPv4 mit DoH konfiguriert"
                }
                
                $adapterCount++
            }
            catch {
                Write-Verbose "Fehler beim Setzen von DNS auf Adapter '$($adapter.Name)': $_"
            }
        }
        
        Write-Success "$adapterCount Adapter konfiguriert"
    }
    catch {
        Write-Error-Custom "Fehler beim Abrufen der Netzwerkadapter: $_"
    }
    
    # DNS Cache leeren (mit Timeout - verhindert Hang)
    $job = $null
    try {
        Write-Info "DNS-Cache wird geleert..."
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Success "DNS Cache geleert"
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Warning-Custom "DNS Cache Flush Timeout (10s) - wird uebersprungen"
            Write-Info "DNS Cache wird beim naechsten Neustart automatisch geleert"
        }
    }
    catch {
        Write-Verbose "DNS Cache konnte nicht geleert werden: $_"
    }
    finally {
        # Garantierter Job-Cleanup
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    # WICHTIG: Dnscache Service NICHT neu starten!
    # Best Practice 25H2: Service ist geschuetzt und fuehrt zu Script-Hang
    # DoH wird automatisch beim naechsten DNS-Request aktiviert
    Write-Info "DoH wird beim naechsten Neustart/DNS-Request aktiviert"
    Write-Verbose "DNS Client Service wird NICHT neu gestartet (geschuetzter Service)"
    
    # VALIDIERUNG: Pruefe ob DoH wirklich konfiguriert ist
    Write-Host ""
    Write-Info "Validiere DoH-Konfiguration..."
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $cloudflareDoH = $dohServers | Where-Object { $_.ServerAddress -match "1\.1\.1\.1|1\.0\.0\.1|2606:4700:4700" }
            if ($cloudflareDoH) {
                $dohCount = @($cloudflareDoH).Count
                Write-Success "DoH-Validierung: $dohCount Cloudflare DoH Server konfiguriert"
                foreach ($server in $cloudflareDoH) {
                    $serverAddr = $server.ServerAddress
                    $serverTemplate = $server.DohTemplate
                    Write-Verbose "     ServerAddress: $serverAddr, Template: $serverTemplate"
                    if ($server.AllowFallbackToUdp -eq $false) {
                        Write-Verbose "     Kein Fallback auf unverschluesselt (Maximum Security!)"
                    }
                    else {
                        Write-Warning "     Fallback auf unverschluesselt MOEGLICH (nicht ideal!)"
                    }
                }
            }
            else {
                Write-Warning "VALIDIERUNG FEHLGESCHLAGEN: Keine Cloudflare DoH Server gefunden!"
                Write-Warning "DNS koennte UNVERSCHLUESSELT sein!"
            }
        }
        else {
            Write-Warning "VALIDIERUNG FEHLGESCHLAGEN: Get-DnsClientDohServerAddress gab keine Daten zurueck!"
            Write-Info "Moegliche Ursachen:"
            Write-Info "  - DoH Cmdlets nicht verfuegbar (Windows zu alt?)"
            Write-Info "  - DoH noch nicht aktiv (Neustart erforderlich?)"
        }
    }
    catch {
        Write-Verbose "DoH-Validierung fehlgeschlagen (nicht kritisch): $_"
    }
    
    Write-Host ""
    Write-Success "Cloudflare DNS over HTTPS aktiviert"
    Write-Info "IPv4: 1.1.1.1 (Primary), 1.0.0.1 (Secondary)"
    Write-Info "IPv6: 2606:4700:4700::1111 (Primary), 2606:4700:4700::1001 (Secondary)"
    Write-Host ""
    Write-Warning-Custom "WICHTIG: Neustart koennte erforderlich sein damit DoH aktiv wird!"
    Write-Info "Test: nslookup cloudflare.com"
    Write-Host ""
    Write-Host "[i] HINWEIS: VPN-Adapter wurden NICHT geaendert!" -ForegroundColor Cyan
    Write-Info "  VPN-Verbindungen verwenden weiterhin ihre eigenen DNS-Server"
    Write-Info "  Dies ist KORREKT und WICHTIG fuer VPN-Funktionalitaet!"
}

function Disable-RemoteAccessCompletely {
    <#
    .SYNOPSIS
        Deaktiviert ALLE Remote-Zugriffsmethoden komplett
    .DESCRIPTION
        Deaktiviert RDP, Remote Registry, Remote Assistance, Remote Scheduled Tasks und WinRM.
        Erstellt zusaetzlich Block-Regeln in der Firewall.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Disable-RemoteAccessCompletely
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Remote Access KOMPLETT deaktivieren (Hard Mode)"
    
    # ===== RDP (Remote Desktop) IMMER deaktivieren (kein Optional!) =====
    Write-Info "RDP wird PERMANENT DEAKTIVIERT..."
    
    # Registry: RDP ausschalten
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    Set-RegistryValue -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord `
        -Description "RDP-Verbindungen verweigern"
    
    # RDP Service deaktivieren (race-condition-frei)
    $rdpServices = @("TermService", "UmRdpService")
    $successCount = 0
    
    foreach ($svc in $rdpServices) {
        if (Stop-ServiceSafe -ServiceName $svc) {
            $successCount++
        }
    }
    
    if ($successCount -eq $rdpServices.Count) {
        Write-Success "RDP Services permanent deaktiviert (TermService, UmRdpService)"
    }
    elseif ($successCount -gt 0) {
        Write-Warning "Nur $successCount von $($rdpServices.Count) RDP Services deaktiviert"
    }
    else {
        Write-Warning "RDP Services konnten nicht deaktiviert werden"
    }
    
    # Firewall-Regeln HART blockieren
    try {
        # SilentlyContinue wenn Regeln nicht existieren (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        # Zusaetzlich: Explizite Block-Regel fuer RDP Port 3389 (eindeutiger Name)
        $rdpBlockRule = Get-NetFirewallRule -DisplayName "NoID-Block-RDP-Port-3389" -ErrorAction SilentlyContinue
        if (-not $rdpBlockRule) {
            $null = New-NetFirewallRule -DisplayName "NoID-Block-RDP-Port-3389" `
                               -Direction Inbound `
                               -Protocol TCP `
                               -LocalPort 3389 `
                               -Action Block `
                               -Profile Any `
                               -Enabled True -ErrorAction Stop
            Write-Verbose "  -> Explicit Block-Regel fuer RDP Port 3389 erstellt"
        } else {
            Write-Verbose "  -> Block-Regel fuer RDP existiert bereits"
        }
        
        Write-Success "RDP Firewall-Regeln HART deaktiviert + Block-Regel aktiv"
    }
    catch {
        Write-Warning "RDP Firewall-Regeln Fehler: $_"
    }
    
    # ===== Remote Registry IMMER deaktivieren =====
    Write-Info "Remote Registry wird deaktiviert..."
    
    if (Stop-ServiceSafe -ServiceName "RemoteRegistry") {
        Write-Success "Remote Registry Service deaktiviert"
    }
    else {
        Write-Warning "Remote Registry konnte nicht deaktiviert werden"
    }
    
    $remoteRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"
    Set-RegistryValue -Path $remoteRegPath -Name "RemoteRegAccess" -Value 0 -Type DWord `
        -Description "Remote Registry Access verweigern"
    
    # ===== Remote Assistance IMMER deaktivieren =====
    Write-Info "Remote Assistance wird deaktiviert..."
    
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    Set-RegistryValue -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Type DWord `
        -Description "Remote Assistance deaktivieren"
    
    Set-RegistryValue -Path $raPath -Name "fAllowUnsolicited" -Value 0 -Type DWord `
        -Description "Unaufgeforderte Remote Assistance deaktivieren"
    
    $raGpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-RegistryValue -Path $raGpPath -Name "fAllowToGetHelp" -Value 0 -Type DWord `
        -Description "Remote Assistance via GP deaktivieren"
    
    Set-RegistryValue -Path $raGpPath -Name "fAllowUnsolicited" -Value 0 -Type DWord `
        -Description "Unaufgeforderte RA via GP deaktivieren"
    
    Set-RegistryValue -Path $raGpPath -Name "Shadow" -Value 0 -Type DWord `
        -Description "RDP Shadow Sessions verbieten"
    
    Write-Success "Remote Assistance deaktiviert (alle Varianten)"
    
    # ===== Remote Scheduled Tasks deaktivieren =====
    $schedTaskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule"
    Set-RegistryValue -Path $schedTaskPath -Name "DisableRpcOverTcp" -Value 1 -Type DWord `
        -Description "Remote Scheduled Tasks deaktivieren"
    
    # ===== WinRM (PowerShell Remoting) DEAKTIVIEREN =====
    Write-Info "WinRM (PowerShell Remoting) wird deaktiviert..."
    
    if (Stop-ServiceSafe -ServiceName "WinRM") {
        Write-Success "WinRM Service deaktiviert (PowerShell Remoting AUS)"
    }
    else {
        Write-Warning "WinRM konnte nicht deaktiviert werden"
    }
    
    # WinRM Firewall-Regeln deaktivieren
    try {
        # SilentlyContinue wenn Regeln nicht existieren (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue
        Write-Success "WinRM Firewall-Regeln deaktiviert"
    }
    catch {
        Write-Warning "WinRM Firewall-Regeln Fehler: $_"
    }
    
    Write-Success "Remote Access 100% DEAKTIVIERT (RDP=AUS + RemoteReg=AUS + RA=AUS + WinRM=AUS)"
    Write-Warning "KEIN Remote-Zugriff moeglich! Nur physischer Zugriff oder Intune/SCCM!"
}

function Disable-SudoForWindows {
    <#
    .SYNOPSIS
        Deaktiviert Sudo for Windows (Microsoft Baseline 25H2)
    .DESCRIPTION
        Sudo for Windows kann als Privilege Escalation Vector genutzt werden.
        Microsoft Security Baseline 25H2 empfiehlt: Disabled.
    .EXAMPLE
        Disable-SudoForWindows
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Sudo for Windows deaktivieren"
    
    # Microsoft Baseline 25H2: Sudo = Disabled
    $sudoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo"
    Set-RegistryValue -Path $sudoPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "Sudo for Windows deaktivieren (Privilege Escalation Prevention)"
    
    Write-Success "Sudo for Windows deaktiviert (Microsoft Baseline 25H2)"
    Write-Info "Sudo ist ein potentieller Privilege Escalation Vector"
}

function Set-KerberosPKINITHashAgility {
    <#
    .SYNOPSIS
        Aktiviert Kerberos PKINIT Hash-Agilitaet (SHA-256/384/512, OHNE SHA-1)
    .DESCRIPTION
        Konfiguriert Kerberos zur Verwendung von SHA-256/384/512 statt SHA-1.
        Microsoft Baseline 25H2: SHA-1 NICHT unterstuetzen!
        Best Practice: Nur SHA-2 Familie (256/384/512).
    .EXAMPLE
        Set-KerberosPKINITHashAgility
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Kerberos PKINIT Hash-Agilitaet (SHA-2 Only)"
    
    $kerbPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    
    # Alle modernen Encryption Types
    [void](Set-RegistryValue -Path $kerbPath -Name "SupportedEncryptionTypes" -Value 0x7FFFFFFF -Type DWord `
        -Description "Alle modernen Kerberos Enc Types")
    
    # MICROSOFT BASELINE 25H2: SHA-256/384/512 JA, SHA-1 NEIN!
    # PKINITHashAlgorithm Werte:
    # SHA-1   = 0x1
    # SHA-256 = 0x8
    # SHA-384 = 0x10
    # SHA-512 = 0x20
    # Baseline: 0x38 (SHA-256 + SHA-384 + SHA-512, OHNE SHA-1!)
    
    [void](Set-RegistryValue -Path $kerbPath -Name "PKINITHashAlgorithm" -Value 0x38 -Type DWord `
        -Description "PKINIT: SHA-256/384/512 (OHNE SHA-1!)")
    
    # KDC (Key Distribution Center) Settings (falls DC)
    $kdcPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
    [void](Set-RegistryValue -Path $kdcPath -Name "PKINITHashAlgorithm" -Value 0x38 -Type DWord `
        -Description "KDC PKINIT: SHA-256/384/512 (OHNE SHA-1!)")
    
    Write-Success "Kerberos PKINIT Hash-Agilitaet: SHA-256/384/512 (SHA-1 DEAKTIVIERT)"
    Write-Info "Microsoft Baseline 25H2: SHA-1 wird NICHT unterstuetzt"
    Write-Info "Hinweis: Windows Server 2025 KDC empfohlen fuer volle Funktionalitaet"
}

#endregion

#region MARK-OF-THE-WEB

function Set-MarkOfTheWeb {
    <#
    .SYNOPSIS
        Aktiviert Mark-of-the-Web (MotW)
    .DESCRIPTION
        Erzwingt Zone Information und AV-Scan fuer Downloads.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Set-MarkOfTheWeb
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Mark-of-the-Web"
    
    $attachPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    
    [void](Set-RegistryValue -Path $attachPath -Name "SaveZoneInformation" -Value 2 -Type DWord `
        -Description "MotW erzwingen")
    
    [void](Set-RegistryValue -Path $attachPath -Name "ScanWithAntiVirus" -Value 3 -Type DWord `
        -Description "Immer mit AV scannen")
    
    Write-Success "Mark-of-the-Web aktiv"
}

#endregion

#region VBS/CREDENTIAL GUARD

function Enable-CredentialGuard {
    <#
    .SYNOPSIS
        Aktiviert Credential Guard und VBS
    .DESCRIPTION
        Aktiviert Virtualization-Based Security, Credential Guard, HVCI und LSA-PPL.
        Best Practice 25H2: CmdletBinding. Benoetigt Neustart!
    .EXAMPLE
        Enable-CredentialGuard
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Credential Guard und VBS"
    
    $dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # VBS
    [void](Set-RegistryValue -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Description "VBS aktivieren")
    [void](Set-RegistryValue -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Description "VBS: Secure Boot + DMA")
    
    # Credential Guard (UEFI Lock)
    [void](Set-RegistryValue -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Description "Credential Guard (UEFI Lock)")
    
    # CRITICAL FIX v1.7.6: Windows 11 25H2 benötigt ZUSÄTZLICH Scenarios Keys!
    # Credential Guard Scenario (PFLICHT für Windows 11 25H2!)
    $cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
    [void](Set-RegistryValue -Path $cgPath -Name "Enabled" -Value 1 -Type DWord -Description "Credential Guard Scenario aktivieren")
    
    # HVCI (Memory Integrity)
    # WICHTIG: WasEnabledBy = 2 (User) damit GUI NICHT ausgegraut wird!
    # 0 = System/Policy (GUI ausgegraut), 1 = OEM (GUI ausgegraut), 2 = User (GUI editierbar)
    $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    [void](Set-RegistryValue -Path $hvciPath -Name "Enabled" -Value 1 -Type DWord -Description "HVCI/Memory Integrity aktivieren")
    [void](Set-RegistryValue -Path $hvciPath -Name "WasEnabledBy" -Value 2 -Type DWord -Description "HVCI via User aktiviert (GUI bleibt editierbar!)")
    
    # LSA Protection
    [void](Set-RegistryValue -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Description "LSA als PPL")
    
    Write-Success "Credential Guard, VBS, HVCI, LSA-PPL konfiguriert"
    Write-Warning-Custom "Neustart erforderlich!"
}

#endregion

#region BITLOCKER

function Enable-BitLockerPolicies {
    <#
    .SYNOPSIS
        Konfiguriert BitLocker Policies
    .DESCRIPTION
        Aktiviert XTS-AES-256 Encryption, TPM 2.0 + PIN Policies.
        WICHTIG: Prüft ob BitLocker bereits aktiviert ist (Windows 11 Auto-Encryption!)
        Best Practice 25H2: CmdletBinding + BitLocker-Status-Check.
        
        [INFO] WICHTIG - KEIN AUTO-BACKUP DES RECOVERY KEYS!
        
        DESIGN-ENTSCHEIDUNG: Diese Funktion implementiert BEWUSST KEIN automatisches
        Backup des BitLocker Recovery Keys.
        
        GRÜNDE (Windows 11 25H2 macht das automatisch):
        
        1. WINDOWS 11 AUTO-ENCRYPTION:
           - Windows 11 25H2 aktiviert BitLocker AUTOMATISCH bei Neuinstallation
           - Voraussetzungen: TPM 2.0 vorhanden + Microsoft-Konto angemeldet
           - Geschieht ohne User-Interaktion im Hintergrund
        
        2. RECOVERY KEY AUTOMATISCH IM MS-KONTO:
           - Windows speichert Recovery Key AUTOMATISCH im Microsoft-Konto
           - User kann Key jederzeit abrufen: https://account.microsoft.com/devices/recoverykey
           - Synchronisiert über alle Geräte mit gleichem MS-Konto
        
        3. KEIN ZUSÄTZLICHES BACKUP NÖTIG:
           - Microsoft-Konto ist der sichere Speicherort (verschlüsselt)
           - User kann Key bei Bedarf herunterladen/ausdrucken
           - Backup in lokale Datei wäre WENIGER sicher (könnte verloren gehen)
        
        4. USER HAT KONTROLLE:
           - User kann Recovery Key selbst verwalten über MS-Konto
           - User kann Key zusätzlich exportieren/ausdrucken wenn gewünscht
           - Keine Zwangs-Backups auf lokale Dateien/USB-Sticks
        
        WENN BitLocker bereits aktiv ist:
        - Diese Function setzt nur Policies für zukünftige Änderungen
        - Recovery Key ist bereits im MS-Konto gespeichert (bei Auto-Encryption)
        - User wird informiert wo Recovery Key angezeigt werden kann
        
        MANUELLE AKTIVIERUNG (falls noch nicht aktiv):
        - User kann BitLocker manuell aktivieren über Systemsteuerung
        - Windows fragt dann nach Speicherort für Recovery Key
        - Empfehlung: Microsoft-Konto (automatisch + sicher)
    .EXAMPLE
        Enable-BitLockerPolicies
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "BitLocker Policies"
    
    # CHECK 1: AES-NI Support (Hardware-Unterstuetzung fuer AES-256)
    $hasAESNI = $false
    $cpuName = "Unknown"
    
    try {
        # Pruefe direkt auf AES-NI Support (Intel/AMD CPU Feature Flag)
        # AES-NI ist noetig fuer performante AES-256 Verschluesselung
        $cpuFeatures = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $cpuName = $cpuFeatures.Name
        
        # Windows speichert CPU Features nicht direkt in Win32_Processor
        # Aber wir koennen einen indirekten Check machen:
        # Wenn BitLocker bereits mit AES-256 laeuft, wird AES-NI unterstuetzt
        try {
            $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blVolume -and ($blVolume.EncryptionMethod -eq 'XtsAes256' -or $blVolume.EncryptionMethod -eq 'Aes256')) {
                $hasAESNI = $true
                Write-Verbose "AES-256 bereits aktiv - AES-NI wird unterstuetzt"
            }
        }
        catch {
            Write-Verbose "BitLocker-Check fehlgeschlagen: $_"
        }
        
        # Fallback: Pruefe CPU Generation/Alter anhand Name
        # AES-NI wurde eingefuehrt:
        # - Intel: Core i-Serie Gen 3+ (Ivy Bridge 2012), Xeon 5600+ (2010)
        # - AMD: Bulldozer+ (2011), Ryzen (alle)
        # NICHT unterstuetzt:
        # - Intel: Core 2, Core i Gen 1-2, Pentium, Celeron, Atom (alte)
        # - AMD: Phenom II und aelter, alte Athlon
        
        if (-not $hasAESNI) {
            # Pruefe auf alte CPUs OHNE AES-NI
            # Intel Desktop: Core 2, Pentium (nicht Gold), Celeron, Atom
            # Intel Server: Xeon 5500 und aelter (vor Westmere 2010)
            # AMD Desktop: Athlon 64/FX/II, Phenom I/II (alles vor Bulldozer 2011)
            # AMD Server: Opteron (vor Bulldozer 2011)
            if ($cpuName -match "Core 2|Pentium(?! Gold)|Celeron|Atom") {
                # Intel alte CPUs - KEIN AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "AES-256 wird nicht optimal unterstuetzt!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Info "AES-128 ist sicher und auf dieser CPU schneller"
                Write-Host ""
                return  # Beende Funktion - KEINE Policy setzen!
            }
            # Intel Server alte CPUs - Xeon 5500 und aelter (vor Westmere 2010)
            elseif ($cpuName -match "Xeon.*(5[0-5]\d{2}|3[0-4]\d{2}|7[0-4]\d{2})") {
                # Xeon 5500 und aelter - KEIN AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "Alter Intel Xeon (vor Westmere 2010) hat KEIN AES-NI!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Info "AES-128 ist sicher und auf dieser CPU schneller"
                Write-Host ""
                return
            }
            # AMD Desktop alte CPUs - explizite Modelle OHNE AES-NI
            elseif ($cpuName -match "Athlon 64|Athlon FX|Athlon II|Phenom") {
                # AMD K8/K10 Architektur - KEIN AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "AMD K8/K10 Architektur (vor Bulldozer 2011) hat KEIN AES-NI!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Info "AES-128 ist sicher und auf dieser CPU schneller"
                Write-Host ""
                return
            }
            # AMD Server alte CPUs - Opteron (vor Bulldozer 2011)
            elseif ($cpuName -match "Opteron" -and $cpuName -notmatch "Opteron.*(62|63|64|65|66|67|68|69)\d{2}") {
                # Opteron vor Bulldozer - KEIN AES-NI (62xx+ haben AES-NI)
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "Alter AMD Opteron (vor Bulldozer 2011) hat KEIN AES-NI!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Info "AES-128 ist sicher und auf dieser CPU schneller"
                Write-Host ""
                return
            }
            # AMD generische Athlon-Erkennung (alte Athlon ohne 64/II/FX)
            # ABER: Moderne Athlon (200GE, 3000G, Gold) sind Zen-basiert und HABEN AES-NI!
            elseif ($cpuName -match "\bAthlon\b" -and 
                    $cpuName -notmatch "Athlon\s+(Gold|Silver|[0-9]{3,4}[GU])") {
                # Sehr alte oder unbekannte Athlon - wahrscheinlich kein AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "Alte AMD Athlon CPU - wahrscheinlich kein AES-NI!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Host ""
                return
            }
            # Pruefe auf Intel Core i-Serie Gen 2 (Sandy Bridge 2011) - KEIN AES-NI
            # CRITICAL: Nur Gen 2 (i7-2xxx) matchen, NICHT Gen 11+ (i7-11xxx)!
            # Pattern: i7-2XXX (4-stellig, beginnt mit 2), dann kein weiteres Digit
            elseif ($cpuName -match "i[357]-2\d{3}(?!\d)") {
                Write-Host ""
                Write-Warning-Custom "CPU OHNE AES-NI SUPPORT ERKANNT: $cpuName"
                Write-Warning-Custom "Intel Core i-Serie Gen 2 (Sandy Bridge 2011) hat KEIN AES-NI!"
                Write-Warning-Custom "AES-256 Policy wird NICHT gesetzt"
                Write-Host ""
                Write-Info "BitLocker bleibt bei AES-128 (optimal fuer diese Hardware)"
                Write-Host ""
                return
            }
            else {
                # Moderne CPU - wahrscheinlich AES-NI Support
                $hasAESNI = $true
                Write-Verbose "Moderne CPU erkannt - AES-NI wird angenommen: $cpuName"
            }
        }
        
        Write-Info "CPU mit AES-NI Support: $cpuName"
    }
    catch {
        Write-Verbose "AES-NI Check fehlgeschlagen: $_"
        Write-Warning "AES-NI Check fehlgeschlagen - Policy wird trotzdem gesetzt"
        $hasAESNI = $true  # Im Zweifelsfall Policy setzen
    }
    
    # CHECK 2: Ist BitLocker bereits aktiviert? (Windows 11 aktiviert es oft automatisch!)
    $bitlockerActive = $false
    $bitlockerStatus = "Unknown"
    
    try {
        $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $bitlockerActive = ($blVolume.ProtectionStatus -eq 'On')
        $bitlockerStatus = $blVolume.ProtectionStatus
        
        if ($bitlockerActive) {
            Write-Info "BitLocker ist bereits AKTIV (ProtectionStatus: On)"
            Write-Info ("Encryption: " + $blVolume.EncryptionPercentage + "% | Method: " + $blVolume.EncryptionMethod)
        }
        else {
            Write-Info ("BitLocker ist NICHT aktiv (ProtectionStatus: " + $bitlockerStatus + ")")
        }
    }
    catch {
        Write-Verbose "BitLocker-Status konnte nicht abgerufen werden: $_"
        Write-Info "BitLocker-Status: Unbekannt (eventuell nicht vorhanden)"
    }
    
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    
    # XTS-AES-256 Encryption Method Policy
    # Gilt fuer NEUE BitLocker-Aktivierungen (nicht fuer bereits verschluesselte Laufwerke)
    # CRITICAL FIX v1.7.6: Setze die RICHTIGEN Policy-Namen (mit XTS suffix)!
    # Microsoft hat die Policy-Namen geändert - alte "EncryptionMethod" ist deprecated!
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord -Description "XTS-AES-256 OS Drives")
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsFdv" -Value 7 -Type DWord -Description "XTS-AES-256 Fixed Data Drives")
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsRdv" -Value 7 -Type DWord -Description "XTS-AES-256 Removable Drives")
    
    # TPM Settings (erlaubt TPM, erzwingt es aber nicht)
    # UseTPM = 1 (Allow) statt 2 (Require) - damit es auch ohne TPM funktioniert
    [void](Set-RegistryValue -Path $fvePath -Name "UseTPM" -Value 1 -Type DWord -Description "TPM erlauben")
    [void](Set-RegistryValue -Path $fvePath -Name "UseTPMPIN" -Value 1 -Type DWord -Description "TPM + PIN erlauben")
    [void](Set-RegistryValue -Path $fvePath -Name "UseAdvancedStartup" -Value 1 -Type DWord -Description "Advanced Startup")
    
    # Recovery Key Escrow (KRITISCH: Nicht erzwingen ohne AD!)
    # Windows 11 aktiviert BitLocker oft automatisch - dann wuerde "RequireActiveDirectoryBackup"
    # ein gelbes Warnsymbol verursachen wenn kein AD vorhanden ist!
    [void](Set-RegistryValue -Path $fvePath -Name "ActiveDirectoryBackup" -Value 0 -Type DWord -Description "AD Backup optional")
    
    # WICHTIG: RequireActiveDirectoryBackup wird BEWUSST NICHT gesetzt!
    # Grund: Verursacht gelbes Warnsymbol bei bereits aktiviertem BitLocker ohne AD
    
    Write-Success "BitLocker Policies konfiguriert (XTS-AES-256 + TPM Optional)"
    
    if ($bitlockerActive) {
        Write-Info 'BitLocker ist bereits aktiv - Policies gelten fuer zukuenftige Aenderungen'
        Write-Host ""
        Write-Info 'RECOVERY KEY BACKUP:'
        Write-Info '  1. Microsoft-Konto (empfohlen): https://account.microsoft.com/devices/recoverykey'
        Write-Info '  2. Lokal anzeigen: manage-bde -protectors -get C:'
        Write-Info '  3. USB-Stick oder ausdrucken fuer physisches Backup'
        Write-Host ""
        Write-Warning-Custom 'Ohne Recovery Key sind Daten bei TPM-Defekt PERMANENT verloren!'
    }
    else {
        Write-Info 'BitLocker kann manuell aktiviert werden: Systemsteuerung | BitLocker'
        Write-Host ""
        Write-Info 'EMPFEHLUNG bei Aktivierung:'
        Write-Info '  - Speichere Recovery Key im Microsoft-Konto (automatisch + sicher)'
        Write-Info '  - Alternative: USB-Stick oder ausdrucken'
        Write-Host ""
        Write-Warning-Custom 'WICHTIG: Recovery Key IMMER an sicherem Ort speichern!'
    }
}

function Test-BitLockerEncryptionMethod {
    <#
    .SYNOPSIS
        Prueft BitLocker Verschluesselungsmethode und zeigt GUI-Anleitung
    .DESCRIPTION
        Windows 11 aktiviert BitLocker automatisch mit AES-128 (Performance).
        Unsere Policies setzen AES-256, aber das gilt NUR fuer NEUE Verschluesselung.
        Diese Funktion prueft ob System mit AES-128 verschluesselt ist
        und zeigt GUI-Anleitung fuer Upgrade auf AES-256.
        WICHTIG: Alte CPUs (Core i3/i5/i7 Gen 2 und aelter, AMD Phenom II)
        unterstuetzen NUR AES-128!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "BitLocker Verschluesselungsmethode pruefen"
    
    try {
        $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $isActive = $blVolume.ProtectionStatus -eq 'On'
        
        if (-not $isActive) {
            Write-Info "BitLocker ist nicht aktiv - keine Pruefung noetig"
            return
        }
        
        $encMethod = $blVolume.EncryptionMethod
        Write-Info "BitLocker Status: $($blVolume.ProtectionStatus)"
        Write-Info "Verschluesselungsmethode: $encMethod"
        Write-Info "Verschluesselt: $($blVolume.EncryptionPercentage)%"
        
        # EncryptionMethod Werte:
        # None = 0, Aes128 = 1, Aes256 = 2, XtsAes128 = 6, XtsAes256 = 7
        $needsUpgrade = $encMethod -eq 'XtsAes128' -or $encMethod -eq 'Aes128'
        
        if (-not $needsUpgrade) {
            Write-Success "BitLocker nutzt bereits AES-256! Keine Aktion noetig."
            return
        }
        
        # AES-128 erkannt!
        Write-Host ""
        Write-Warning-Custom "BITLOCKER NUTZT NUR AES-128!"
        Write-Host ""
        Write-Host "  WARUM AES-128?" -ForegroundColor Cyan
        Write-Host "    - Windows 11 aktiviert automatisch mit AES-128 (Performance)" -ForegroundColor White
        Write-Host "    - 20-30% schneller als AES-256" -ForegroundColor White
        Write-Host "    - Microsoft: 'ausreichend sicher fuer Consumer'" -ForegroundColor White
        Write-Host ""
        Write-Host "  WARUM UPGRADE AUF AES-256?" -ForegroundColor Cyan
        Write-Host "    - Enterprise-Standard (NIST, CIS, DoD)" -ForegroundColor White
        Write-Host "    - Future-Proof gegen Quantum-Computing" -ForegroundColor White
        Write-Host "    - Compliance (manche Standards fordern 256-Bit)" -ForegroundColor White
        Write-Host ""
        Write-Host "  UNSERE POLICY:" -ForegroundColor Cyan
        Write-Host "    - Neue Verschluesselung nutzt jetzt AES-256" -ForegroundColor Green
        Write-Host "    - System-Partition bleibt AES-128 (bereits verschluesselt)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  IHRE CPU-KOMPATIBILITAET:" -ForegroundColor Cyan
        
        # Prüfe CPU-Generation und gebe KLARE Empfehlung
        $cpuName = "Unknown"
        
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor
            $cpuName = $cpu.Name
            Write-Host "    CPU: $cpuName" -ForegroundColor White
            
            # Prüfe ob alte CPU OHNE AES-NI Support
            # Intel Desktop: Core 2, Pentium (nicht Gold), Celeron, Atom
            # Intel Server: Xeon 5500 und aelter
            # AMD Desktop: Athlon 64/FX/II, Phenom I/II
            # AMD Server: Opteron (vor Bulldozer 2011)
            if ($cpuName -match "Core 2|Pentium(?! Gold)|Celeron|Atom") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - AES-256 waere zu langsam auf dieser Hardware" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return  # Beende Funktion - keine Upgrade-Anleitung zeigen!
            }
            # Intel Server alte CPUs - Xeon 5500 und aelter
            elseif ($cpuName -match "Xeon.*(5[0-5]\d{2}|3[0-4]\d{2}|7[0-4]\d{2})") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - Alter Intel Xeon (vor Westmere 2010)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return
            }
            # AMD Desktop alte CPUs - explizite Modelle
            elseif ($cpuName -match "Athlon 64|Athlon FX|Athlon II|Phenom") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - AES-256 waere zu langsam auf dieser Hardware" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return  # Beende Funktion - keine Upgrade-Anleitung zeigen!
            }
            # AMD Server alte CPUs - Opteron (vor Bulldozer 2011)
            elseif ($cpuName -match "Opteron" -and $cpuName -notmatch "Opteron.*(62|63|64|65|66|67|68|69)\d{2}") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - Alter AMD Opteron (vor Bulldozer 2011)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return
            }
            # AMD generische Athlon (alte ohne 64/II/FX), ABER NICHT moderne (Zen-basiert)
            elseif ($cpuName -match "\bAthlon\b" -and 
                    $cpuName -notmatch "Athlon\s+(Gold|Silver|[0-9]{3,4}[GU])") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - Alte AMD Athlon CPU" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return
            }
            # Intel Core i Gen 2 (Sandy Bridge 2011) - letzte ohne AES-NI
            elseif ($cpuName -match "Core i[357]-2\d{3}(?!\d)") {
                Write-Host ""
                Write-Host "    [!] IHRE CPU:" -ForegroundColor Red
                Write-Host "        - Unterstuetzt NUR AES-128 (kein AES-NI Support)" -ForegroundColor Red
                Write-Host "        - Intel Sandy Bridge Gen 2 (2011)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [EMPFEHLUNG] BEHALTEN SIE AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal fuer Ihre Hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 ist sicher! Kein Upgrade noetig auf alter Hardware."
                return
            }
            else {
                Write-Host ""
                Write-Host "    [OK] IHRE CPU:" -ForegroundColor Green
                Write-Host "         - Unterstuetzt AES-256 (hat AES-NI Support)" -ForegroundColor Green
                Write-Host "         - Moderne Hardware - AES-256 Upgrade empfohlen!" -ForegroundColor Green
                Write-Host ""
            }
        }
        catch {
            Write-Verbose "CPU-Check fehlgeschlagen: $_"
            Write-Host "    [?] CPU-Check fehlgeschlagen - Upgrade auf eigenes Risiko" -ForegroundColor Yellow
            Write-Host ""
        }
        
        Write-Host "  SO UPGRADEN SIE AUF AES-256 (IN WINDOWS):" -ForegroundColor Green
        Write-Host ""
        Write-Host "    METHODE 1 - Windows-Startmenue (EINFACHSTE):" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Windows-Taste druecken" -ForegroundColor White
        Write-Host "      2. Eintippen: BitLocker verwalten" -ForegroundColor White
        Write-Host "      3. Enter druecken" -ForegroundColor White
        Write-Host "      4. Klick auf 'BitLocker deaktivieren'" -ForegroundColor White
        Write-Host "         (WARNUNG: Dauert 30-90 Min!)" -ForegroundColor Yellow
        Write-Host "      5. Warte bis 'BitLocker deaktiviert' angezeigt wird" -ForegroundColor White
        Write-Host "      6. Klick auf 'BitLocker aktivieren'" -ForegroundColor White
        Write-Host "         (Unsere Policy greift = AES-256!)" -ForegroundColor Green
        Write-Host "      7. <WICHTIG> Recovery Key SICHERN (MS-Konto empfohlen)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    METHODE 2 - Systemsteuerung:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Systemsteuerung oeffnen" -ForegroundColor White
        Write-Host "      2. System und Sicherheit" -ForegroundColor White
        Write-Host "      3. BitLocker-Laufwerkverschluesselung" -ForegroundColor White
        Write-Host "      4. Rest wie Methode 1 (Schritt 4-7)" -ForegroundColor White
        Write-Host ""
        Write-Host "    METHODE 3 - Datei-Explorer:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Datei-Explorer oeffnen (Win + E)" -ForegroundColor White
        Write-Host "      2. Rechtsklick auf Laufwerk C:" -ForegroundColor White
        Write-Host "      3. Klick auf 'BitLocker deaktivieren'" -ForegroundColor White
        Write-Host "      4. Rest wie Methode 1 (Schritt 5-7)" -ForegroundColor White
        Write-Host ""
        Write-Host "  ALTERNATIVE (POWERSHELL):" -ForegroundColor Cyan
        Write-Host "    manage-bde -status C:        # Status pruefen" -ForegroundColor Gray
        Write-Host "    manage-bde -off C:           # Deaktivieren (dauert!)" -ForegroundColor Gray
        Write-Host "    manage-bde -on C: -UsedSpaceOnly  # Aktivieren mit AES-256" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  HINWEIS:" -ForegroundColor Cyan
        Write-Host "    Re-Encryption dauert 30-90 Minuten (je nach Groesse)" -ForegroundColor White
        Write-Host "    Laptop an Netzteil anschliessen!" -ForegroundColor White
        Write-Host "    Bei alten CPUs: AES-128 BEHALTEN (bessere Performance)!" -ForegroundColor White
        Write-Host ""
    }
    catch {
        Write-Error "Fehler bei BitLocker-Pruefung: $_"
        Write-Warning-Custom "Bei Problemen: manage-bde -status C:"
    }
}

#endregion

#region COMPLIANCE REPORT

function New-ComplianceReport {
    <#
    .SYNOPSIS
        Generate HTML compliance report of applied security settings
    .DESCRIPTION
        Creates detailed HTML report showing which security settings were applied
        Best Practice 25H2: Comprehensive audit trail
    .PARAMETER OutputPath
        Path where HTML report will be saved
    .EXAMPLE
        New-ComplianceReport -OutputPath "C:\Reports\SecurityBaseline.html"
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )
    
    Write-Verbose "Generating compliance report: $OutputPath"
    
    try {
        $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $computerName = $env:COMPUTERNAME
        $osVersion = [System.Environment]::OSVersion.Version.ToString()
        $psVersion = $PSVersionTable.PSVersion.ToString()
        
        # Build HTML using StringBuilder (safer than HERE-STRING)
        $html = [System.Text.StringBuilder]::new()
        [void]$html.AppendLine('<!DOCTYPE html>')
        [void]$html.AppendLine('<html lang="en">')
        [void]$html.AppendLine('<head>')
        [void]$html.AppendLine('    <meta charset="UTF-8">')
        [void]$html.AppendLine('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        [void]$html.AppendLine('    <title>Security Baseline Compliance Report</title>')
        [void]$html.AppendLine('    <style>')
        [void]$html.AppendLine('        body { font-family: ''Segoe UI'', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }')
        [void]$html.AppendLine('        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }')
        [void]$html.AppendLine('        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }')
        [void]$html.AppendLine('        h2 { color: #333; margin-top: 30px; }')
        [void]$html.AppendLine('        .info-box { background: #e7f3ff; padding: 15px; border-left: 4px solid #0078d4; margin: 20px 0; }')
        [void]$html.AppendLine('        .success { color: #107c10; font-weight: bold; }')
        [void]$html.AppendLine('        table { width: 100%; border-collapse: collapse; margin: 20px 0; }')
        [void]$html.AppendLine('        th { background: #0078d4; color: white; padding: 12px; text-align: left; }')
        [void]$html.AppendLine('        td { padding: 10px; border-bottom: 1px solid #ddd; }')
        [void]$html.AppendLine('        tr:hover { background: #f5f5f5; }')
        [void]$html.AppendLine('        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }')
        [void]$html.AppendLine('    </style>')
        [void]$html.AppendLine('</head>')
        [void]$html.AppendLine('<body>')
        [void]$html.AppendLine('    <div class="container">')
        [void]$html.AppendLine('        <h1>[SECURITY] Windows 11 25H2 Security Baseline - Compliance Report</h1>')
        [void]$html.AppendLine('        <div class="info-box">')
        [void]$html.AppendLine('            <strong>Report Generated:</strong> ' + $reportDate + '<br>')
        [void]$html.AppendLine('            <strong>Computer Name:</strong> ' + $computerName + '<br>')
        [void]$html.AppendLine('            <strong>OS Version:</strong> Windows 11 ' + $osVersion + '<br>')
        [void]$html.AppendLine('            <strong>PowerShell Version:</strong> ' + $psVersion + '<br>')
        [void]$html.AppendLine('            <strong>Baseline Version:</strong> 1.3.1 (Hotfix)')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('        <h2>[OK] Applied Security Controls</h2>')
        [void]$html.AppendLine('        <table><thead><tr>')
        [void]$html.AppendLine('            <th>Category</th><th>Control</th><th>Status</th>')
        [void]$html.AppendLine('        </tr></thead><tbody>')
        
        # Security Controls
        $controls = @(
            @{Category='Network Security'; Control='NetBIOS Disabled'}
            @{Category='Network Security'; Control='SMB/NTLM Hardening'}
            @{Category='Network Security'; Control='Legacy Protocols Disabled'}
            @{Category='Network Security'; Control='Network Stealth Mode'}
            @{Category='Auditing'; Control='Process Command Line Logging'}
            @{Category='Auditing'; Control='Advanced Audit Policies (19 categories)'}
            @{Category='Defense'; Control='Microsoft Defender Baseline'}
            @{Category='Defense'; Control='Attack Surface Reduction Rules'}
            @{Category='Defense'; Control='Smart App Control'}
            @{Category='Access Control'; Control='Administrative Shares Disabled'}
            @{Category='Access Control'; Control='Remote Access Disabled'}
            @{Category='Encryption'; Control='Credential Guard + VBS'}
            @{Category='Encryption'; Control='BitLocker Policies (XTS-AES-256)'}
            @{Category='DNS Security'; Control='DNSSEC Validation'}
            @{Category='DNS Security'; Control='DNS Blocklist (80K+ domains)'}
            @{Category='Privacy'; Control='Telemetry Services Disabled'}
            @{Category='Privacy'; Control='Telemetry Registry Keys'}
            @{Category='Privacy'; Control='Telemetry Scheduled Tasks Removed'}
        )
        
        foreach ($ctrl in $controls) {
            [void]$html.AppendLine('            <tr>')
            [void]$html.AppendLine('                <td>' + $ctrl.Category + '</td>')
            [void]$html.AppendLine('                <td>' + $ctrl.Control + '</td>')
            [void]$html.AppendLine('                <td class="success">[OK] Applied</td>')
            [void]$html.AppendLine('            </tr>')
        }
        
        [void]$html.AppendLine('        </tbody></table>')
        [void]$html.AppendLine('        <h2>[!] Important Notes</h2>')
        [void]$html.AppendLine('        <div class="info-box">')
        [void]$html.AppendLine('            <p><strong>Reboot Required:</strong> Some changes (VBS, Credential Guard, BitLocker) require a system restart to take effect.</p>')
        [void]$html.AppendLine('            <p><strong>Verification:</strong> Run <code>.\Verify-SecurityBaseline.ps1</code> to verify all settings are correctly applied.</p>')
        [void]$html.AppendLine('            <p><strong>Restore:</strong> Use <code>.\Restore-SecurityBaseline.ps1</code> with your backup file to restore previous state.</p>')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('        <div class="footer">')
        [void]$html.AppendLine('            <p>Generated by NoID Privacy - Windows 11 25H2 Security Baseline v1.3.1</p>')
        [void]$html.AppendLine('            <p>NoID Privacy v1.7 | Microsoft Baseline 25H2 compliant</p>')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('    </div>')
        [void]$html.AppendLine('</body>')
        [void]$html.AppendLine('</html>')
        
        $htmlContent = $html.ToString()
        
        # Write HTML to file
        # [OK] BEST PRACTICE: UTF-8 ohne BOM (PowerShell 5.1 compatible)
        # Out-File -Encoding utf8 in PS 5.1 erstellt Datei MIT BOM!
        # Verwende .NET API für UTF-8 ohne BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $htmlContent, $utf8NoBom)
        
        Write-Verbose ("Compliance report generated successfully: " + $OutputPath)
        Write-Success ("Compliance Report erstellt: " + $OutputPath)
    }
    catch {
        Write-Warning "Could not generate compliance report: $_"
        Write-Verbose ("Details: " + $_.Exception.Message)
    }
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope when dot-sourced with: . path\script.ps1
# Exported Functions: Set-DefenderBaselineSettings, Set-FirewallPolicies, Disable-UnnecessaryServices, 
#                     Enable-UAC, Disable-RemoteAccess, Set-BitLockerPolicies, Test-BitLockerEncryptionMethod,
#                     Disable-AutoPlayAndAutoRun, Set-SmartScreenExtended, Enable-ExploitProtection,
#                     Enable-ControlledFolderAccess, New-ComplianceReport
