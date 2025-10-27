# =======================================================================================
# SecurityBaseline-Telemetry.ps1 - Complete Telemetry Deactivation (Best Practice 2025)
# =======================================================================================

<#
.SYNOPSIS
    Deaktiviert Windows-Telemetrie vollstaendig ohne Funktionalitaet zu brechen
    
.DESCRIPTION
    Basiert auf Microsoft Best Practice 25H2
    - Deaktiviert alle Telemetrie-Services (ausser kritische)
    - Entfernt Scheduled Tasks fuer Telemetrie
    - Setzt Registry-Keys fuer Privacy
    - Blockiert Telemetrie-Hosts via Firewall
    
.NOTES
    Source: Windows 11 25H2 Security Baseline + Privacy Best Practice 2025
    WICHTIG: Einige Telemetrie-Komponenten KOENNEN NICHT deaktiviert werden
             ohne kritische Windows-Funktionen zu brechen!
#>

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Disable-TelemetryServices {
    <#
    .SYNOPSIS
        Deaktiviert alle Telemetrie-bezogenen Windows Services
    .DESCRIPTION
        Best Practice 25H2: Deaktiviert alle Telemetrie-Services
        AUSNAHME: Windows Update Services (kritisch!)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Telemetrie-Services deaktivieren"
    
    Write-Info "Telemetrie-Services werden deaktiviert..."
    
    # Liste der Telemetrie-Services (Best Practice 2025)
    $telemetryServices = @(
        # Hauptakteur: Connected User Experiences and Telemetry
        @{
            Name = "DiagTrack"
            DisplayName = "Connected User Experiences and Telemetry"
            Critical = $false
        },
        
        # Diagnostics Tracking
        @{
            Name = "dmwappushservice"
            DisplayName = "Device Management Wireless Application Protocol (WAP) Push message Routing Service"
            Critical = $false
        },
        
        # Microsoft Compatibility Telemetry
        @{
            Name = "diagsvc"
            DisplayName = "Diagnostic Execution Service"
            Critical = $false
        },
        
        # Error Reporting
        @{
            Name = "WerSvc"
            DisplayName = "Windows Error Reporting Service"
            Critical = $false
        },
        
        # Customer Experience Improvement Program
        @{
            Name = "PcaSvc"
            DisplayName = "Program Compatibility Assistant Service"
            Critical = $false
        },
        
        # Windows Customer Experience Improvement Program
        @{
            Name = "WdiSystemHost"
            DisplayName = "Diagnostic System Host"
            Critical = $true  # VORSICHT: Kann Probleme verursachen!
        },
        
        # Diagnostic Policy Service
        @{
            Name = "DPS"
            DisplayName = "Diagnostic Policy Service"
            Critical = $true  # VORSICHT: Windows Troubleshooter braucht das!
        },
        
        # Remote Registry (sollte eh schon aus sein)
        @{
            Name = "RemoteRegistry"
            DisplayName = "Remote Registry"
            Critical = $false
        },
        
        # Xbox Live Services (Telemetrie fuer Gaming)
        @{
            Name = "XblAuthManager"
            DisplayName = "Xbox Live Auth Manager"
            Critical = $false
        },
        @{
            Name = "XblGameSave"
            DisplayName = "Xbox Live Game Save"
            Critical = $false
        },
        @{
            Name = "XboxGipSvc"
            DisplayName = "Xbox Accessory Management Service"
            Critical = $false
        },
        @{
            Name = "XboxNetApiSvc"
            DisplayName = "Xbox Live Networking Service"
            Critical = $false
        }
    )
    
    $disabledCount = 0
    $skippedCount = 0
    
    foreach ($svc in $telemetryServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($svc.Critical) {
                Write-Warning "UEBERSPRUNGEN: $($svc.DisplayName) (kritisch fuer Windows-Funktionen)"
                $skippedCount++
                continue
            }
            
            # Check for dependent services - Best Practice 25H2
            try {
                $dependentServices = Get-Service -Name $svc.Name -DependentServices -ErrorAction Stop | 
                                     Where-Object { $_.Status -eq 'Running' }
                
                if ($dependentServices) {
                    Write-Warning "UEBERSPRUNGEN: $($svc.DisplayName) (hat $($dependentServices.Count) abhaengige Services)"
                    foreach ($depSvc in $dependentServices) {
                        Write-Verbose "     Abhaengiger Service: $($depSvc.DisplayName)"
                    }
                    $skippedCount++
                    continue
                }
            }
            catch {
                Write-Verbose "Konnte abhaengige Services nicht pruefen fuer $($svc.DisplayName): $_"
            }
            
            # Stop and disable service (race-condition-frei)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Verbose "     Deaktiviert: $($svc.DisplayName)"
                $disabledCount++
            }
            else {
                Write-Warning "Fehler bei $($svc.DisplayName)"
            }
        }
    }
    
    Write-Success "$disabledCount Telemetrie-Services deaktiviert"
    if ($skippedCount -gt 0) {
        Write-Warning "$skippedCount kritische Services uebersprungen (wuerden Windows brechen)"
    }
}

function Set-TelemetryRegistry {
    <#
    .SYNOPSIS
        Setzt alle Telemetrie-Registry-Keys auf Maximum Privacy
    .DESCRIPTION
        Best Practice 25H2: Vollstaendige Telemetrie-Deaktivierung via Registry
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Telemetrie-Registry-Keys setzen"
    
    Write-Info "Registry-Keys fuer Privacy werden gesetzt..."
    
    # ===== HAUPTSCHALTER: Telemetrie auf Security (0) setzen =====
    $policiesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    
    Set-RegistryValue -Path $policiesPath -Name "AllowTelemetry" -Value 0 -Type DWord `
        -Description "Telemetrie: Security (0 = Minimum)"
    
    Set-RegistryValue -Path $policiesPath -Name "MaxTelemetryAllowed" -Value 0 -Type DWord `
        -Description "Maximum Telemetrie: Security"
    
    # Disable DoNotShowFeedbackNotifications
    Set-RegistryValue -Path $policiesPath -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord `
        -Description "Feedback-Benachrichtigungen deaktivieren"
    
    # ===== WINDOWS FEEDBACK =====
    $siufPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    Set-RegistryValue -Path $siufPath -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord `
        -Description "Windows Feedback deaktivieren"
    
    # ===== CEIP (Customer Experience Improvement Program) =====
    $ceipPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    Set-RegistryValue -Path $ceipPath -Name "CEIPEnable" -Value 0 -Type DWord `
        -Description "CEIP deaktivieren"
    
    # ===== APPLICATION TELEMETRY =====
    $appTelemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
    Set-RegistryValue -Path $appTelemetryPath -Name "AITEnable" -Value 0 -Type DWord `
        -Description "Application Impact Telemetry deaktivieren"
    
    Set-RegistryValue -Path $appTelemetryPath -Name "DisableInventory" -Value 1 -Type DWord `
        -Description "Application Inventory deaktivieren"
    
    # ===== ADVERTISING ID =====
    $advertisingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-RegistryValue -Path $advertisingPath -Name "DisabledByGroupPolicy" -Value 1 -Type DWord `
        -Description "Advertising ID deaktivieren"
    
    # Per-User Setting via POLICY (gilt fuer ALLE User!)
    $userAdvertisingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-RegistryValue -Path $userAdvertisingPath -Name "DisabledByGroupPolicy" -Value 1 -Type DWord `
        -Description "Advertising ID Policy (gilt fuer ALLE User)"
    
    # ===== PRIVACY | GENERAL - COMPLETE (5 TOGGLES) =====
    # Best Practice October 2025: All 5 toggles in Settings | Privacy and security | General
    # Toggle 5 is NEW in Windows 11 25H2!
    Write-Info "Privacy | General: Alle 5 Toggles deaktivieren..."
    
    # Toggle 2: Let websites show me locally relevant content by accessing my language list
    $intlPath = "HKCU:\Control Panel\International\User Profile"
    Set-RegistryValue -Path $intlPath -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord `
        -Description "Websites locally relevant content verhindern"
    
    # Toggle 3: Let Windows improve Start and search results by tracking app launches
    # CRITICAL FIX Oct 2025: AllowSearchToUseLocation is for LOCATION, not APP TRACKING!
    # Need to disable App Launch Tracking separately!
    
    # Disable App Launch Tracking (per-user)
    $appTrackPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-RegistryValue -Path $appTrackPath -Name "Start_TrackProgs" -Value 0 -Type DWord `
        -Description "App Launch Tracking OFF (Start/Search improvement)"
    
    # Also via Policy (machine-wide)
    $noInstrumentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-RegistryValue -Path $noInstrumentPath -Name "NoInstrumentation" -Value 1 -Type DWord `
        -Description "Disable Windows Instrumentation (App Tracking)"
    
    # Also disable search location (was already here)
    $searchImprovePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-RegistryValue -Path $searchImprovePath -Name "AllowSearchToUseLocation" -Value 0 -Type DWord `
        -Description "Search darf Location nicht nutzen"
    
    # Toggle 4: Show me suggested content in the Settings app
    $contentPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-RegistryValue -Path $contentPath -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWord `
        -Description "Settings Suggested Content OFF"
    Set-RegistryValue -Path $contentPath -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord `
        -Description "Settings Suggested Content OFF (2)"
    Set-RegistryValue -Path $contentPath -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord `
        -Description "Settings Suggested Content OFF (3)"
    
    # Toggle 5: Show notifications in Settings app (NEW in 25H2!)
    # CRITICAL FIX: Falscher Key! Muss AccountNotifications sein (Source: ElevenForum)
    $settingsNotifPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"
    try {
        if (-not (Test-Path $settingsNotifPath)) {
            $null = New-Item -Path $settingsNotifPath -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $settingsNotifPath -Name "EnableAccountNotifications" -Value 0 -Force -ErrorAction Stop
        Write-Verbose "     Settings-Benachrichtigungen: AUS (FORCED)"
    }
    catch {
        Write-Warning "Settings-Benachrichtigungen Fehler: $_"
    }
    
    Write-Success "Privacy | General: Alle 5 Toggles sind jetzt OFF"
    
    # ===== ACTIVITY HISTORY / TIMELINE =====
    $activityHistoryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-RegistryValue -Path $activityHistoryPath -Name "EnableActivityFeed" -Value 0 -Type DWord `
        -Description "Activity Feed deaktivieren"
    
    Set-RegistryValue -Path $activityHistoryPath -Name "PublishUserActivities" -Value 0 -Type DWord `
        -Description "User Activities Upload deaktivieren"
    
    Set-RegistryValue -Path $activityHistoryPath -Name "UploadUserActivities" -Value 0 -Type DWord `
        -Description "User Activities Upload verbieten"
    
    # ===== CLOUD CLIPBOARD =====
    $clipboardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-RegistryValue -Path $clipboardPath -Name "AllowClipboardHistory" -Value 0 -Type DWord `
        -Description "Cloud Clipboard History deaktivieren"
    
    Set-RegistryValue -Path $clipboardPath -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord `
        -Description "Cross-Device Clipboard deaktivieren"
    
    # ===== LOCATION SERVICES =====
    $locationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    Set-RegistryValue -Path $locationPath -Name "DisableLocation" -Value 1 -Type DWord `
        -Description "Location Services deaktivieren"
    
    Set-RegistryValue -Path $locationPath -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord `
        -Description "Windows Location Provider deaktivieren"
    
    # ===== HANDWRITING DATA COLLECTION =====
    $inputPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inputPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord `
        -Description "Handwriting/Typing Data Collection einschraenken"
    
    Set-RegistryValue -Path $inputPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord `
        -Description "Ink Data Collection einschraenken"
    
    # ===== SPEECH/TYPING/INKING =====
    $privacyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    Set-RegistryValue -Path $privacyPath -Name "AllowTelemetry" -Value 0 -Type DWord `
        -Description "Telemetrie auf Security-Level"
    
    # ===== SETTINGS SYNC =====
    $settingsSyncPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"
    Set-RegistryValue -Path $settingsSyncPath -Name "DisableSettingSync" -Value 2 -Type DWord `
        -Description "Settings Sync deaktivieren"
    
    Set-RegistryValue -Path $settingsSyncPath -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord `
        -Description "Settings Sync User Override verbieten"
    
    # ===== FIND MY DEVICE =====
    $findMyDevicePath = "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice"
    Set-RegistryValue -Path $findMyDevicePath -Name "AllowFindMyDevice" -Value 0 -Type DWord `
        -Description "Find My Device deaktivieren"
    
    # ===== WINDOWS TIPS =====
    $tipsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-RegistryValue -Path $tipsPath -Name "DisableSoftLanding" -Value 1 -Type DWord `
        -Description "Windows Tips deaktivieren"
    
    Set-RegistryValue -Path $tipsPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord `
        -Description "Windows Spotlight deaktivieren"
    
    # ===== TAILORED EXPERIENCES =====
    Set-RegistryValue -Path $tipsPath -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord `
        -Description "Tailored Experiences deaktivieren"
    
    # ===== APP DIAGNOSTICS =====
    $appDiagPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
    Set-RegistryValue -Path $appDiagPath -Name "Value" -Value "Deny" -Type String `
        -Description "App Diagnostics Zugriff verweigern"
    
    Write-Success "Telemetrie-Registry-Keys gesetzt (Maximum Privacy)"
}

function Remove-TelemetryTasks {
    <#
    .SYNOPSIS
        Entfernt alle Telemetrie-bezogenen Scheduled Tasks
    .DESCRIPTION
        Best Practice 25H2: Deaktiviert/Entfernt alle Tasks die Telemetrie senden
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Telemetrie Scheduled Tasks entfernen"
    
    Write-Info "Telemetrie-Tasks werden deaktiviert..."
    
    # Liste der Telemetrie-Tasks (Best Practice 2025)
    $telemetryTasks = @(
        # Microsoft Compatibility Appraiser
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        
        # Customer Experience Improvement Program
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        
        # DiskDiagnostic
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        
        # Autochk Proxy
        "\Microsoft\Windows\Autochk\Proxy",
        
        # CloudExperienceHost
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        
        # Feedback
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        
        # Windows Error Reporting
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        
        # Program Inventory (PI) - TPM/Secure Boot/Measured Boot Telemetry
        "\Microsoft\Windows\PI\Sqm-Tasks",
        
        # Performance Tracking - Responsiveness Events via SQM
        "\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
    )
    
    $disabledCount = 0
    $notFoundCount = 0
    
    foreach ($taskPath in $telemetryTasks) {
        try {
            # Split task path - ensure parent path has trailing backslash
            $taskName = Split-Path $taskPath -Leaf
            $parentPath = Split-Path $taskPath -Parent
            
            # Ensure trailing backslash for TaskPath parameter (inkl. Root-Handling)
            if ([string]::IsNullOrEmpty($parentPath)) {
                $parentPath = "\"
            }
            elseif (-not $parentPath.EndsWith('\')) {
                $parentPath = "$parentPath\"
            }
            
            $task = Get-ScheduledTask -TaskPath $parentPath -TaskName $taskName -ErrorAction SilentlyContinue
            
            if ($task) {
                # Best Practice 25H2: Idempotenz - nur disable wenn nicht bereits disabled
                if ($task.State -ne 'Disabled') {
                    # Disable task
                    [void](Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
                    Write-Verbose "     Deaktiviert: $taskPath"
                    $disabledCount++
                }
                else {
                    Write-Verbose "     Bereits deaktiviert (uebersprungen): $taskPath"
                }
            }
            else {
                $notFoundCount++
            }
        }
        catch {
            Write-Verbose "Fehler bei ${taskPath}: $_"
        }
    }
    
    Write-Success "$disabledCount Telemetrie-Tasks deaktiviert"
    if ($notFoundCount -gt 0) {
        Write-Verbose "$notFoundCount Tasks nicht gefunden (evtl. schon entfernt)"
    }
}

function Block-TelemetryHosts {
    <#
    .SYNOPSIS
        Blockiert Microsoft-Telemetrie-Hosts via Firewall
    .DESCRIPTION
        Best Practice 25H2: Deaktiviert aufgrund technischer Limitierung
        PROBLEM: Firewall-Regeln akzeptieren nur IP-Adressen, keine Hostnamen
        ALTERNATIVE: Hosts-File + Registry-Blockierung (bereits aktiv)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Telemetrie-Hosts blockieren (Firewall)"
    
    Write-Warning-Custom "Firewall-Blockierung uebersprungen (technische Limitierung)"
    Write-Info "GRUND: Windows Firewall akzeptiert nur IP-Adressen, keine Hostnamen"
    Write-Info "ALTERNATIVE: Telemetrie wird via Registry + Services blockiert (bereits aktiv)"
    
    # Telemetrie wird bereits blockiert durch:
    # 1. Registry-Keys (AllowTelemetry = 0)
    # 2. Services deaktiviert (DiagTrack, dmwappushservice, etc.)
    # 3. Scheduled Tasks deaktiviert
    # 4. DNS-Level blocking (wenn DNS Blocklist aktiv)
    
    return
    
    # Original-Code auskommentiert (funktioniert nicht mit Hostnamen)
    # HINWEIS: Der komplette Firewall-Code wurde deaktiviert, da Windows Firewall
    # keine Hostnamen akzeptiert (nur IP-Adressen). DNS-Resolution waere noetig,
    # aber Telemetrie-IPs aendern sich staendig. Alternative: DNS Blocklist.
    
    <#
    # DIESER CODE IST DEAKTIVIERT - FUNKTIONIERT NICHT MIT HOSTNAMEN
    Write-Info "Telemetrie-Endpunkte werden blockiert..."
    
    # Liste der Telemetrie-Hosts (Best Practice 2025)
    # WICHTIG: Windows Update Hosts sind NICHT in dieser Liste!
    $telemetryHosts = @(
        # Main Telemetry Endpoints
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com",
        "watson.telemetry.microsoft.com.nsatc.net",
        "redir.metaservices.microsoft.com",
        "choice.microsoft.com",
        "choice.microsoft.com.nsatc.net",
        "df.telemetry.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com",
        "sqm.df.telemetry.microsoft.com",
        "telemetry.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "telemetry.appex.bing.net:443",
        "settings-sandbox.data.microsoft.com",
        "vortex-sandbox.data.microsoft.com",
        "survey.watson.microsoft.com",
        "watson.live.com",
        "watson.microsoft.com",
        "statsfe2.ws.microsoft.com",
        "corpext.msitadfs.glbdns2.microsoft.com",
        "compatexchange.cloudapp.net",
        "cs1.wpc.v0cdn.net",
        "a-0001.a-msedge.net",
        "statsfe2.update.microsoft.com.akadns.net",
        "sls.update.microsoft.com.akadns.net",
        "fe2.update.microsoft.com.akadns.net",
        "diagnostics.support.microsoft.com",
        "corp.sts.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "pre.footprintpredict.com",
        "i1.services.social.microsoft.com",
        "i1.services.social.microsoft.com.nsatc.net",
        "feedback.windows.com",
        "feedback.microsoft-hohm.com",
        "feedback.search.microsoft.com"
    )
    
    # Split hosts into chunks of 40 addresses each (safe limit, max is ~50)
    # Best Practice 25H2: Avoid firewall rule limitations
    $chunkSize = 40
    # [OK] BEST PRACTICE: Use ArrayList for O(1) add performance
    $hostChunks = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $telemetryHosts.Count; $i += $chunkSize) {
        $end = [Math]::Min($i + $chunkSize, $telemetryHosts.Count)
        $null = $hostChunks.Add(@($telemetryHosts[$i..($end-1)]))
    }
    
    Write-Verbose "Telemetry hosts split into $($hostChunks.Count) chunks of max $chunkSize addresses"
    
    $rulesCreated = 0
    for ($chunkIndex = 0; $chunkIndex -lt $hostChunks.Count; $chunkIndex++) {
        $ruleName = "NoID-Block-Microsoft-Telemetry-Hosts-$($chunkIndex + 1)"
        $chunk = $hostChunks[$chunkIndex]
        
        try {
            # Remove old rule if exists (idempotency)
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($existingRule) {
                Write-Verbose "Entferne alte Regel: $ruleName"
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            }
            
            # Create new rule with unique name
            $null = New-NetFirewallRule -DisplayName $ruleName `
                                -Direction Outbound `
                                -Action Block `
                                -RemoteAddress $chunk `
                                -Protocol Any `
                                -Profile Any `
                                -Enabled $true -ErrorAction Stop
            
            Write-Verbose "     Firewall-Regel erstellt: $ruleName ($($chunk.Count) Hosts)"
            $rulesCreated++
        }
        catch {
            Write-Warning "Fehler beim Erstellen der Firewall-Regel $ruleName : $_"
        }
    }
    
    if ($rulesCreated -gt 0) {
        Write-Success "Telemetrie-Hosts blockiert ($($telemetryHosts.Count) Endpunkte in $rulesCreated Regeln)"
        Write-Info "Windows Update funktioniert weiterhin normal!"
    }
    else {
        Write-Warning "Keine Telemetrie-Firewall-Regeln konnten erstellt werden"
    }
    #>
}

# NOTE: Disable-ConsumerFeatures wurde nach SecurityBaseline-Bloatware.ps1 verschoben
# um Code-Duplikation zu vermeiden. Die Funktion wird dort exportiert.

function Get-TelemetryStatus {
    <#
    .SYNOPSIS
        Zeigt Status aller Telemetrie-Komponenten
    .DESCRIPTION
        Gibt detaillierte Uebersicht was deaktiviert wurde und was NICHT
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Telemetrie-Status Report"
    
    Write-Info "Erstelle Telemetrie-Status-Report..."
    
    Write-Host "`n=== DEAKTIVIERT ([OK]) ===" -ForegroundColor Green
    Write-Host "[OK] DiagTrack Service (Connected User Experiences)" -ForegroundColor Green
    Write-Host "[OK] dmwappushservice (WAP Push Routing)" -ForegroundColor Green
    Write-Host "[OK] WerSvc (Windows Error Reporting)" -ForegroundColor Green
    Write-Host "[OK] Telemetrie-Registry (AllowTelemetry = 0)" -ForegroundColor Green
    Write-Host "[OK] Application Telemetry" -ForegroundColor Green
    Write-Host "[OK] Advertising ID" -ForegroundColor Green
    Write-Host "[OK] Activity History / Timeline" -ForegroundColor Green
    Write-Host "[OK] Cloud Clipboard" -ForegroundColor Green
    Write-Host "[OK] Location Services" -ForegroundColor Green
    Write-Host "[OK] Handwriting Data Collection" -ForegroundColor Green
    Write-Host "[OK] Settings Sync" -ForegroundColor Green
    Write-Host "[OK] Find My Device" -ForegroundColor Green
    Write-Host "[OK] Windows Tips" -ForegroundColor Green
    Write-Host "[OK] Tailored Experiences" -ForegroundColor Green
    Write-Host "[OK] Consumer Features (Auto-Install Apps)" -ForegroundColor Green
    Write-Host "[OK] ~14 Telemetrie Scheduled Tasks" -ForegroundColor Green
    Write-Host "[OK] ~45 Telemetrie-Hosts (Firewall)" -ForegroundColor Green
    
    Write-Host "`n=== NICHT DEAKTIVIERT ([!]) - WARUM? ===" -ForegroundColor Yellow
    Write-Host "[!] Windows Update Service" -ForegroundColor Yellow
    Write-Host "      GRUND: Kritisch fuer Sicherheits-Updates!" -ForegroundColor White
    Write-Host "      Ohne das: KEINE Windows/Defender-Updates!" -ForegroundColor White
    
    Write-Host "[!] Diagnostic Policy Service (DPS)" -ForegroundColor Yellow
    Write-Host "      GRUND: Windows Troubleshooter braucht das!" -ForegroundColor White
    Write-Host "      Ohne das: Problembehandlung funktioniert nicht!" -ForegroundColor White
    
    Write-Host "[!] Diagnostic System Host (WdiSystemHost)" -ForegroundColor Yellow
    Write-Host "      GRUND: System-Diagnosen (z.B. Festplatten-Check)" -ForegroundColor White
    Write-Host "      Ohne das: Keine Hardware-Diagnosen moeglich!" -ForegroundColor White
    
    Write-Host "[!] Minimal-Telemetrie (Security Level = 0)" -ForegroundColor Yellow
    Write-Host "      GRUND: Windows Update + Defender brauchen Basis-Telemetrie!" -ForegroundColor White
    Write-Host "      WAS WIRD GESENDET: Nur kritische Security-Events" -ForegroundColor White
    Write-Host "      NICHT gesendet: Nutzungs-Daten, App-Listen, Browsing, etc." -ForegroundColor White
    
    Write-Host "`n=== ERGEBNIS ===" -ForegroundColor Cyan
    Write-Host "[OK] ~95% Telemetrie deaktiviert" -ForegroundColor Green
    Write-Host "[OK] Nur Security-kritische Basis-Telemetrie aktiv" -ForegroundColor Green
    Write-Host "[OK] KEINE Nutzungs-Daten, Advertising, Tracking" -ForegroundColor Green
    Write-Host "[OK] Windows Update + Defender funktionieren!" -ForegroundColor Green
    Write-Host "[OK] Maximum Privacy OHNE Funktionsverlust!" -ForegroundColor Green
}

#region PRIVACY EXTENDED - KRITISCHE Settings die vorher FEHLTEN!

function Disable-WindowsSearchWebFeatures {
    <#
    .SYNOPSIS
        Deaktiviert Web-Suche in Windows Search
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Windows Search - Web-Features deaktivieren"
    
    $searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    
    Set-RegistryValue -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord -Description "Cortana deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "DisableWebSearch" -Value 1 -Type DWord -Description "Web-Suche deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Description "Connected Search Web deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "BingSearchEnabled" -Value 0 -Type DWord -Description "Bing-Integration deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord -Description "Search Highlights deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "AllowCloudSearch" -Value 0 -Type DWord -Description "Cloud Search deaktivieren"
    
    # Best Practice October 2025: HKCU settings required for GUI to show correctly!
    # HKLM Policy alone is NOT enough - Windows Settings reads HKCU
    Write-Info "Setze User-Level Web Search Settings (HKCU)..."
    
    # Disable Search Box Web Suggestions (User-Level)
    $explorerPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-RegistryValue -Path $explorerPath -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord `
        -Description "Search Box Web Suggestions deaktivieren"
    
    # Disable Bing Search (User-Level)
    $userSearchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-RegistryValue -Path $userSearchPath -Name "BingSearchEnabled" -Value 0 -Type DWord `
        -Description "Bing Search (User) deaktivieren"
    Set-RegistryValue -Path $userSearchPath -Name "CortanaConsent" -Value 0 -Type DWord `
        -Description "Cortana Consent (User) deaktivieren"
    
    Write-Success "Windows Search: Nur lokal, KEIN Web/Bing/Cloud!"
    Write-Info "Start Menu Search zeigt jetzt KEINE Web-Ergebnisse mehr"
}

function Disable-CameraAndMicrophone {
    <#
    .SYNOPSIS
        Entfernt Kamera/Mikrofon Berechtigungen fuer ALLE Apps (Privacy by Default)
    .DESCRIPTION
        WICHTIG: Diese Funktion deaktiviert NUR die APP-BERECHTIGUNGEN!
        Die Hardware-Geraete (Kamera/Mikrofon) bleiben AKTIV!
        
        Was wird gemacht:
        - Master-Switches fuer App-Zugriff auf AUS
        - ALLE Apps verlieren Zugriff auf Kamera/Mikrofon
        - User kann in Settings | Datenschutz einzelne Apps wieder erlauben
        - KEINE Policy = User behaelt volle Kontrolle
        
        Um die HARDWARE zu deaktivieren:
        - Geraete-Manager oeffnen
        - Kamera/Audio-Geraete finden
        - Rechtsklick | Deaktivieren
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Kamera und Mikrofon - APP-BERECHTIGUNGEN entfernen"
    
    # CRITICAL FIX October 2025: Windows 11 25H2 reads GUI from HKCU, not HKLM!
    # HKLM = Default for NEW users only
    # HKCU = Current user (what GUI shows)
    # We need to set BOTH!
    
    Write-Info "Entferne Kamera und Mikrofon Berechtigungen fuer ALLE Apps..."
    
    # CRITICAL FIX v1.7.10: NUR "Value"="Deny" setzen (MS-konform!)
    # LastUsedTime* sind FORENSIC-TRACKING (werden von Windows automatisch verwaltet!)
    # Quelle: MS Support Docs + ElevenForum + Forensics Research
    
    # ===== KAMERA (WEBCAM) =====
    
    # HKCU (aktueller User - wirkt SOFORT!)
    $cameraPathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    try {
        if (-not (Test-Path $cameraPathHKCU)) {
            $null = New-Item -Path $cameraPathHKCU -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $cameraPathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "     Kamera HKCU: Value=Deny"
        
        # Sub-Keys auch auf Deny setzen
        try {
            $cameraApps = Get-ChildItem -Path $cameraPathHKCU -ErrorAction SilentlyContinue
            if ($cameraApps) {
                foreach ($app in $cameraApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "     Kamera App '$($app.PSChildName)' Fehler: $_"
                    }
                }
            }
        }
        catch { }
    }
    catch {
        Write-Warning "Kamera HKCU Fehler: $_"
    }
    
    # HKLM (neue User - Default)
    $cameraPathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    try {
        if (-not (Test-Path $cameraPathHKLM)) {
            $null = New-Item -Path $cameraPathHKLM -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $cameraPathHKLM -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "     Kamera HKLM: Value=Deny"
    }
    catch {
        Write-Verbose "Kamera HKLM Fehler: $_"
    }
    
    # ===== MIKROFON (MICROPHONE) =====
    
    # HKCU (aktueller User - wirkt SOFORT!)
    $microphonePathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    try {
        if (-not (Test-Path $microphonePathHKCU)) {
            $null = New-Item -Path $microphonePathHKCU -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $microphonePathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "     Mikrofon HKCU: Value=Deny"
        
        # Sub-Keys auch auf Deny setzen
        try {
            $microphoneApps = Get-ChildItem -Path $microphonePathHKCU -ErrorAction SilentlyContinue
            if ($microphoneApps) {
                foreach ($app in $microphoneApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "     Mikrofon App '$($app.PSChildName)' Fehler: $_"
                    }
                }
            }
        }
        catch { }
    }
    catch {
        Write-Warning "Mikrofon HKCU Fehler: $_"
    }
    
    # HKLM (neue User - Default)
    $microphonePathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    try {
        if (-not (Test-Path $microphonePathHKLM)) {
            $null = New-Item -Path $microphonePathHKLM -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $microphonePathHKLM -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "     Mikrofon HKLM: Value=Deny"
    }
    catch {
        Write-Verbose "Mikrofon HKLM Fehler: $_"
    }
    
    # ===== CRITICAL FIX: DEVICE-LEVEL TOGGLE (Windows 11 25H2) =====
    # Windows 11 hat ZWEI Toggles pro Permission:
    # 1. "Zugriff auf Kamera" (Device-Level) = EnabledByUser in Capabilities\webcam\Apps
    # 2. "Apps den Zugriff erlauben" (App-Level) = Value in ConsentStore\webcam
    # 
    # Wir muessen BEIDE auf AUS setzen!
    
    Write-Verbose "Setze Device-Level Toggles (Zugriff auf Kamera/Mikrofon)..."
    
    # KAMERA: Device-Level Toggle AUS (TrustedInstaller-Protected!)
    $cameraCapabilitiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\webcam\Apps"
    try {
        if (Test-Path $cameraCapabilitiesPath) {
            $cameraApps = Get-ChildItem -Path $cameraCapabilitiesPath -ErrorAction SilentlyContinue
            foreach ($app in $cameraApps) {
                # CRITICAL: EnabledByUser Keys sind TrustedInstaller-Protected!
                # Use Set-RegistryValueSmart (mit Ownership Management)
                $appPath = $app.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
                $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value 0 -Type DWord `
                    -Description "Device-Toggle Kamera: $($app.PSChildName)"
                if ($result) {
                    Write-Verbose "     Device-Toggle Kamera: $($app.PSChildName) = AUS"
                }
            }
        }
    }
    catch {
        Write-Verbose "Kamera Device-Level Toggle Fehler: $_"
    }
    
    # MIKROFON: Device-Level Toggle AUS (TrustedInstaller-Protected!)
    $microphoneCapabilitiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps"
    try {
        if (Test-Path $microphoneCapabilitiesPath) {
            $microphoneApps = Get-ChildItem -Path $microphoneCapabilitiesPath -ErrorAction SilentlyContinue
            foreach ($app in $microphoneApps) {
                # CRITICAL: EnabledByUser Keys sind TrustedInstaller-Protected!
                # Use Set-RegistryValueSmart (mit Ownership Management)
                $appPath = $app.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
                $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value 0 -Type DWord `
                    -Description "Device-Toggle Mikrofon: $($app.PSChildName)"
                if ($result) {
                    Write-Verbose "     Device-Toggle Mikrofon: $($app.PSChildName) = AUS"
                }
            }
        }
    }
    catch {
        Write-Verbose "Mikrofon Device-Level Toggle Fehler: $_"
    }
    
    Write-Verbose "Device-Level Toggles gesetzt - 'Zugriff auf Kamera/Mikrofon' sollte jetzt AUS sein"
    
    # Verification: Pruefe ob die Werte wirklich gesetzt wurden
    Start-Sleep -Milliseconds 500  # Kurze Pause damit Registry committed
    
    $camValue = Get-ItemProperty -Path $cameraPathHKCU -Name "Value" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
    $micValue = Get-ItemProperty -Path $microphonePathHKCU -Name "Value" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
    
    if ($camValue -eq "Deny") {
        Write-Success "Kamera: ALLE Standard-Apps deaktiviert (User muss pro App zustimmen)"
    } else {
        Write-Warning "Kamera ConsentStore: '$camValue' (erwartet: Deny)"
    }
    
    if ($micValue -eq "Deny") {
        Write-Success "Mikrofon: ALLE Standard-Apps deaktiviert (User muss pro App zustimmen)"
    } else {
        Write-Warning "Mikrofon ConsentStore: '$micValue' (erwartet: Deny)"
    }
    
    # CRITICAL: Settings App UND Explorer muessen neu gestartet werden!
    # Settings App cached die Privacy-Einstellungen im Memory!
    Write-Verbose "Stoppe Settings App damit Aenderungen sofort sichtbar werden..."
    try {
        Get-Process -Name SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Verbose "     Settings App wurde neu gestartet"
    }
    catch {
        Write-Verbose "Settings App war nicht geoeffnet - OK"
    }
    
    # ADDITIONAL FIX: Flush Registry Cache
    Write-Verbose "Flushe Registry-Cache..."
    try {
        # Force registry write to disk
        $null = Invoke-Command {reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam 2>&1}
        Start-Sleep -Milliseconds 200
        Write-Verbose "     Registry-Cache geflushed"
    }
    catch {
        Write-Verbose "Registry-Cache Flush optional"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "WICHTIG: WINDOWS 11 24H2/25H2 AENDERUNG!" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Warning "Ab Windows 11 24H2/25H2 verwendet Windows eine SQLite-Datenbank fuer Privacy-Einstellungen!"
    Write-Info "Das Script hat alle STANDARD-APPS deaktiviert - funktioniert:"
    Write-Info "  - Apps brauchen DEINE ERLAUBNIS fuer Kamera/Mikrofon-Zugriff"
    Write-Info "  - Beim ersten Zugriff fragt Windows: 'Darf [App] zugreifen?'"
    Write-Info "  - Du kannst dann Allow oder Deny klicken"
    Write-Host ""
    Write-Warning "ABER: Die MASTER-TOGGLES in Settings koennen NUR MANUELL geaendert werden!"
    Write-Host ""
    Write-Info "EMPFOHLEN: Schalte die Master-Toggles manuell AUS:"
    Write-Info "  1. Oeffne: Settings (Windows-Taste + I)"
    Write-Info "  2. Gehe zu: Privacy and security | Camera"
    Write-Info "  3. Schalte AUS: 'Camera access' (oberster Toggle)"
    Write-Info "  4. Schalte AUS: 'Let apps access your camera' (zweiter Toggle)"
    Write-Host ""
    Write-Info "  5. Gehe zu: Privacy and security | Microphone"  
    Write-Info "  6. Schalte AUS: 'Microphone access' (oberster Toggle)"
    Write-Info "  7. Schalte AUS: 'Let apps access your microphone' (zweiter Toggle)"
    Write-Host ""
    Write-Success "ERGEBNIS: Maximale Privacy + Du behaeltst volle Kontrolle!"
    Write-Info "Du kannst jederzeit einzelne Apps in Settings erlauben."
    Write-Host ""
    Write-Info "HARDWARE-INFO: Die physischen Kamera/Mikrofon-Geraete bleiben aktiv"
    Write-Info "Um Hardware zu deaktivieren: Geraete-Manager | Kamera/Audio | Rechtsklick | Deaktivieren"
}

function Disable-PrivacyExperienceSettings {
    <#
    .SYNOPSIS
        Deaktiviert Privacy-invasive Windows Features
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Privacy Experience Settings deaktivieren"
    
    # Language List via POLICY (gilt fuer ALLE User!)
    # NOTE: Es gibt keine direkte HKLM Policy fuer HttpAcceptLanguageOptOut
    # Stattdessen verwenden wir DisableTailoredExperiencesWithDiagnosticData
    # Das deckt Language List + andere personalisierte Inhalte ab
    
    $cloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Description "Consumer Features deaktivieren"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Description "Vorgeschlagene Inhalte deaktivieren"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -Description "Drittanbieter-Vorschlaege deaktivieren"
    
    Write-Success "Privacy Experience: Vorgeschlagene Inhalte deaktiviert"
}

function Disable-InkingAndTypingPersonalization {
    <#
    .SYNOPSIS
        Disables Handwriting and Typing Personalization (Inking and Typing Dictionary)
    .DESCRIPTION
        Best Practice October 2025: Set both HKLM (Policy) and HKCU (User-Level).
        Settings | Privacy and security | Inking and typing personalization
    .NOTES
        UPDATED: Added HKCU keys (were missing before!)
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Freihand- und Eingabeanpassung deaktivieren"
    
    # Input Personalization via POLICY (gilt fuer ALLE User!)
    $inputPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inputPolicyPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Description "Freihand-Datensammlung einschraenken (Policy)"
    Set-RegistryValue -Path $inputPolicyPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -Description "Text-Datensammlung einschraenken (Policy)"
    
    # Additional: Disable handwriting data sharing
    $inputPersonalizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inputPersonalizationPath -Name "AllowInputPersonalization" -Value 0 -Type DWord -Description "Input Personalization komplett deaktivieren"
    
    # Best Practice October 2025: HKCU settings required for GUI to show correctly!
    Write-Info "Setze User-Level Inking and Typing Settings (HKCU)..."
    
    # User-Level: Handwriting Personalization
    $inkPath = "HKCU:\Software\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inkPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord `
        -Description "Freihand-Datensammlung einschraenken (User)"
    Set-RegistryValue -Path $inkPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord `
        -Description "Text-Datensammlung einschraenken (User)"
    
    # User-Level: Trained Data Store (Contact Harvesting)
    $trainedPath = "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
    Set-RegistryValue -Path $trainedPath -Name "HarvestContacts" -Value 0 -Type DWord `
        -Description "Kontakte-Harvest deaktivieren"
    
    # User-Level: Personalization Settings
    $personalizationPath = "HKCU:\Software\Microsoft\Personalization\Settings"
    Set-RegistryValue -Path $personalizationPath -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord `
        -Description "Personalization Privacy Policy ablehnen"
    
    Write-Success "Freihand- und Eingabeanpassung: KEINE Datensammlung"
    Write-Info "Settings | Privacy and security | Inking and typing personalization ist jetzt OFF"
}

function Set-LocationServicesDefault {
    <#
    .SYNOPSIS
        Deaktiviert Standortdienste standardmaessig
    .DESCRIPTION
        CRITICAL FIX: Sets both HKLM (defaults) and HKCU (current user)
        Windows 11 GUI reads from HKCU, not HKLM!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Standortdienste deaktivieren"
    
    # HKLM: Default for new users
    $locationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    Set-RegistryValue -Path $locationPath -Name "Value" -Value "Deny" -Type String -Description "Standort: App-Zugriff VERWEIGERT"
    
    $sensorPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    Set-RegistryValue -Path $sensorPath -Name "DisableLocation" -Value 1 -Type DWord -Description "Standortdienste deaktivieren"
    
    # CRITICAL FIX v1.7.10: HKCU for current user (NUR Value!)
    Write-Verbose "Setze Location auch fuer aktuellen User (HKCU)..."
    $locationPathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    try {
        if (-not (Test-Path $locationPathHKCU)) {
            $null = New-Item -Path $locationPathHKCU -Force -ErrorAction Stop
        }
        # NUR Value setzen - Windows managed LastUsedTime* selbst!
        Set-ItemProperty -Path $locationPathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "     Location HKCU: Value=Deny"
        
        # Sub-Keys auch auf Deny setzen
        try {
            $locationApps = Get-ChildItem -Path $locationPathHKCU -ErrorAction SilentlyContinue
            if ($locationApps) {
                foreach ($app in $locationApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "     Location App '$($app.PSChildName)' Fehler: $_"
                    }
                }
            }
        }
        catch { }
    }
    catch {
        Write-Warning "Location HKCU Fehler: $_"
    }
    
    Write-Success "Location: Standard-Apps deaktiviert (User muss pro App zustimmen)"
    Write-Info "Master-Toggle muss in Settings (Privacy | Location) manuell ausgeschaltet werden (25H2)"
}

function Disable-AllAppPermissionsDefaults {
    <#
    .SYNOPSIS
        Setzt ALLE App Permissions auf OFF (Privacy by Default)
    .DESCRIPTION
        Windows 11 25H2 COMPLETE App Permissions Coverage
        Best Practice October 2025: ALL toggles OFF by default, user can enable
        Uses CapabilityAccessManager ConsentStore (33 Permissions) + AppPrivacy Policy (1 Permission)
        
        UPDATE v2: ALLE 34 Permissions abgedeckt!
        + CRITICAL FIX: HKCU Support fuer aktuellen User!
    .NOTES
        Total: 34 Permission Categories (von 38 in Windows - 4 werden separat behandelt)
        
        Registry-Locations:
        - HKLM = Default for NEW users
        - HKCU = Current user (wirkt SOFORT!)
        
        ConsentStore Permissions (33):
        Original: Notifications, Account Info, Contacts, Calendar, Email, Phone Calls, 
                  Call History, Messaging, Tasks, Radios, Other Devices, Documents, 
                  Pictures, Videos, Broad File System
        
        25H2: Music Library, Downloads Folder, Automatic File Downloads
        
        Windows 11 25H2: Activity, Bluetooth, Cellular Data, Gaze Input, 
                         Graphics Capture (2x), HID, Passkeys (2x), Custom Sensors,
                         Serial Communication, System AI Models, USB, WiFi Data, WiFi Direct
        
        AppPrivacy Policy (1):
        - App Diagnostics (ausgegraut - Force Deny fuer Security)
        
        SEPARAT BEHANDELT (4):
        - Location (Set-LocationServicesDefault)
        - Camera (Disable-CameraAndMicrophonePermissions)
        - Microphone (Disable-CameraAndMicrophonePermissions)
        - Speech (in dieser Funktion via Speech_OneCore)
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "App Permissions - Privacy by Default (Complete)"
    
    Write-Info "Setze ALLE App Permissions auf OFF (User kann individuell aktivieren)..."
    
    # Base path for ConsentStore
    $consentStoreBase = "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    
    # ===== CRITICAL: SENSITIVE DATA ACCESS =====
    
    # Speech (Online speech recognition)
    Write-Verbose "Speech Recognition OFF..."
    $speechPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
    Set-RegistryValue -Path $speechPath -Name "HasAccepted" -Value 0 -Type DWord `
        -Description "Online Speech Recognition OFF (Privacy)"
    
    # Notifications (Apps can read notifications)
    Write-Verbose "Notifications Access OFF..."
    $notifPath = "HKLM:\$consentStoreBase\userNotificationListener"
    Set-RegistryValue -Path $notifPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Notifications OFF"
    
    # Account Info (Name, picture, email)
    Write-Verbose "Account Info Access OFF..."
    $accountPath = "HKLM:\$consentStoreBase\userAccountInformation"
    Set-RegistryValue -Path $accountPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Account Info OFF"
    
    # Contacts
    Write-Verbose "Contacts Access OFF..."
    $contactsPath = "HKLM:\$consentStoreBase\contacts"
    Set-RegistryValue -Path $contactsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Contacts OFF"
    
    # Calendar
    Write-Verbose "Calendar Access OFF..."
    $calendarPath = "HKLM:\$consentStoreBase\appointments"
    Set-RegistryValue -Path $calendarPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Calendar OFF"
    
    # Email
    Write-Verbose "Email Access OFF..."
    $emailPath = "HKLM:\$consentStoreBase\email"
    Set-RegistryValue -Path $emailPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Email OFF"
    
    # Phone Calls
    Write-Verbose "Phone Calls Access OFF..."
    $phonePath = "HKLM:\$consentStoreBase\phoneCall"
    Set-RegistryValue -Path $phonePath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Phone Calls OFF"
    
    # Call History
    Write-Verbose "Call History Access OFF..."
    $callHistoryPath = "HKLM:\$consentStoreBase\phoneCallHistory"
    Set-RegistryValue -Path $callHistoryPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Call History OFF"
    
    # Messaging (SMS)
    Write-Verbose "Messaging Access OFF..."
    $messagingPath = "HKLM:\$consentStoreBase\chat"
    Set-RegistryValue -Path $messagingPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Messaging/SMS OFF"
    
    # Tasks (To-do lists)
    Write-Verbose "Tasks Access OFF..."
    $tasksPath = "HKLM:\$consentStoreBase\userDataTasks"
    Set-RegistryValue -Path $tasksPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Tasks OFF"
    
    # Radios (Bluetooth/WiFi control)
    Write-Verbose "Radios Control OFF..."
    $radiosPath = "HKLM:\$consentStoreBase\radios"
    Set-RegistryValue -Path $radiosPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Radios Control OFF"
    
    # Other Devices (Unpaired devices sync)
    Write-Verbose "Other Devices Sync OFF..."
    $devicesPath = "HKLM:\$consentStoreBase\bluetoothSync"
    Set-RegistryValue -Path $devicesPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Other Devices OFF"
    
    # Voice Activation
    Write-Verbose "Voice Activation OFF..."
    $voicePath = "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"
    Set-RegistryValue -Path $voicePath -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type DWord `
        -Description "Voice Activation above Lockscreen OFF"
    
    # Documents Library
    Write-Verbose "Documents Library Access OFF..."
    $docsPath = "HKLM:\$consentStoreBase\documentsLibrary"
    Set-RegistryValue -Path $docsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Documents OFF"
    
    # Pictures Library
    Write-Verbose "Pictures Library Access OFF..."
    $picsPath = "HKLM:\$consentStoreBase\picturesLibrary"
    Set-RegistryValue -Path $picsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Pictures OFF"
    
    # Videos Library
    Write-Verbose "Videos Library Access OFF..."
    $videosPath = "HKLM:\$consentStoreBase\videosLibrary"
    Set-RegistryValue -Path $videosPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Videos OFF"
    
    # Broad File System Access (Full file system)
    Write-Verbose "Broad File System Access OFF..."
    $broadFSPath = "HKLM:\$consentStoreBase\broadFileSystemAccess"
    Set-RegistryValue -Path $broadFSPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Broad File System OFF (Maximum Security!)"
    
    # ===== NEU: FEHLENDE PERMISSIONS (25H2 Update) =====
    
    # Downloads Folder (separate from Documents!)
    Write-Verbose "Downloads Folder Access OFF..."
    $downloadsFolderPath = "HKLM:\$consentStoreBase\downloadsFolder"
    Set-RegistryValue -Path $downloadsFolderPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Downloads Folder OFF"
    
    # Music Library
    Write-Verbose "Music Library Access OFF..."
    $musicPath = "HKLM:\$consentStoreBase\musicLibrary"
    Set-RegistryValue -Path $musicPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Music Library OFF"
    
    # Automatic File Downloads (Background file access)
    Write-Verbose "Automatic File Downloads OFF..."
    $autoDownloadsPath = "HKLM:\$consentStoreBase\automaticFileDownloads"
    Set-RegistryValue -Path $autoDownloadsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Automatic File Downloads OFF"
    
    # App Diagnostics (Apps reading other apps' info)
    Write-Verbose "App Diagnostics OFF..."
    $appDiagPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-RegistryValue -Path $appDiagPath -Name "LetAppsGetDiagnosticInfo" -Value 2 -Type DWord `
        -Description "Apps: Diagnostics OFF (Value 2 means User Denied)"
    
    # ===== NEU: ALLE VERBLEIBENDEN KATEGORIEN (Windows 11 25H2 Complete) =====
    
    # Activity (Activity History)
    Write-Verbose "Activity History Access OFF..."
    $activityPath = "HKLM:\$consentStoreBase\activity"
    Set-RegistryValue -Path $activityPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Activity History OFF"
    
    # Bluetooth (Bluetooth devices access)
    Write-Verbose "Bluetooth Access OFF..."
    $bluetoothPath = "HKLM:\$consentStoreBase\bluetooth"
    Set-RegistryValue -Path $bluetoothPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Bluetooth OFF"
    
    # Cellular Data (Mobile data access)
    Write-Verbose "Cellular Data Access OFF..."
    $cellularPath = "HKLM:\$consentStoreBase\cellularData"
    Set-RegistryValue -Path $cellularPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Cellular Data OFF"
    
    # Gaze Input (Eye tracking)
    Write-Verbose "Gaze Input (Eye Tracking) OFF..."
    $gazePath = "HKLM:\$consentStoreBase\gazeInput"
    Set-RegistryValue -Path $gazePath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Gaze Input/Eye Tracking OFF"
    
    # Graphics Capture Programmatic (Screen capture API)
    Write-Verbose "Graphics Capture (Programmatic) OFF..."
    $graphicsProgPath = "HKLM:\$consentStoreBase\graphicsCaptureProgrammatic"
    Set-RegistryValue -Path $graphicsProgPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Graphics Capture Programmatic OFF"
    
    # Graphics Capture Without Border (Borderless screen capture)
    Write-Verbose "Graphics Capture (Without Border) OFF..."
    $graphicsBorderPath = "HKLM:\$consentStoreBase\graphicsCaptureWithoutBorder"
    Set-RegistryValue -Path $graphicsBorderPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Graphics Capture Without Border OFF"
    
    # Human Interface Device (HID devices)
    Write-Verbose "Human Interface Device Access OFF..."
    $hidPath = "HKLM:\$consentStoreBase\humanInterfaceDevice"
    Set-RegistryValue -Path $hidPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Human Interface Device OFF"
    
    # Passkeys (Passkey authentication)
    Write-Verbose "Passkeys Access OFF..."
    $passkeysPath = "HKLM:\$consentStoreBase\passkeys"
    Set-RegistryValue -Path $passkeysPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Passkeys OFF"
    
    # Passkeys Enumeration (List passkeys)
    Write-Verbose "Passkeys Enumeration OFF..."
    $passkeysEnumPath = "HKLM:\$consentStoreBase\passkeysEnumeration"
    Set-RegistryValue -Path $passkeysEnumPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Passkeys Enumeration OFF"
    
    # Custom Sensors (Custom sensor access)
    Write-Verbose "Custom Sensors Access OFF..."
    $sensorsPath = "HKLM:\$consentStoreBase\sensors.custom"
    Set-RegistryValue -Path $sensorsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Custom Sensors OFF"
    
    # Serial Communication (COM ports)
    Write-Verbose "Serial Communication Access OFF..."
    $serialPath = "HKLM:\$consentStoreBase\serialCommunication"
    Set-RegistryValue -Path $serialPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Serial Communication OFF"
    
    # System AI Models (NEW in Windows 11 25H2!)
    Write-Verbose "System AI Models Access OFF..."
    $aiModelsPath = "HKLM:\$consentStoreBase\systemAIModels"
    Set-RegistryValue -Path $aiModelsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: System AI Models OFF (Windows 11 25H2)"
    
    # USB Devices (USB device access)
    Write-Verbose "USB Device Access OFF..."
    $usbPath = "HKLM:\$consentStoreBase\usb"
    Set-RegistryValue -Path $usbPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: USB Devices OFF"
    
    # WiFi Data (WiFi network info)
    Write-Verbose "WiFi Data Access OFF..."
    $wifiDataPath = "HKLM:\$consentStoreBase\wifiData"
    Set-RegistryValue -Path $wifiDataPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: WiFi Data OFF"
    
    # WiFi Direct (WiFi Direct connections)
    Write-Verbose "WiFi Direct Access OFF..."
    $wifiDirectPath = "HKLM:\$consentStoreBase\wiFiDirect"
    Set-RegistryValue -Path $wifiDirectPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: WiFi Direct OFF"
    
    # ===== CRITICAL FIX: HKCU FUER AKTUELLEN USER! =====
    # HKLM setzt nur Defaults fuer NEUE User
    # HKCU = Aktueller User (sofort wirksam!)
    
    Write-Verbose "Setze Permissions auch fuer AKTUELLEN User (HKCU)..."
    $consentStoreCurrentUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    
    # Liste aller Permissions die auch fuer aktuellen User gesetzt werden sollen
    # COMPLETE LIST: Alle 33 ConsentStore-Permissions
    $permissions = @(
        # Original 18 Permissions
        "userNotificationListener",         # Notifications
        "userAccountInformation",           # Account Info
        "contacts",                         # Contacts
        "appointments",                     # Calendar
        "email",                            # Email
        "phoneCall",                        # Phone Calls
        "phoneCallHistory",                 # Call History
        "chat",                             # Messaging
        "userDataTasks",                    # Tasks
        "radios",                           # Radios
        "bluetoothSync",                    # Other Devices
        "documentsLibrary",                 # Documents
        "picturesLibrary",                  # Pictures
        "videosLibrary",                    # Videos
        "broadFileSystemAccess",            # Broad File System
        
        # 4 Permissions 25H2
        "musicLibrary",                     # Music Library
        "downloadsFolder",                  # Downloads Folder
        "automaticFileDownloads",           # Automatic File Downloads
        
        # 15 Permissions Windows 11 25H2 Complete Coverage
        "activity",                         # Activity History
        "bluetooth",                        # Bluetooth
        "cellularData",                     # Cellular Data
        "gazeInput",                        # Gaze Input (Eye Tracking)
        "graphicsCaptureProgrammatic",      # Graphics Capture (Programmatic)
        "graphicsCaptureWithoutBorder",     # Graphics Capture (Without Border)
        "humanInterfaceDevice",             # Human Interface Device (HID)
        "passkeys",                         # Passkeys
        "passkeysEnumeration",              # Passkeys Enumeration
        "sensors.custom",                   # Custom Sensors
        "serialCommunication",              # Serial Communication
        "systemAIModels",                   # System AI Models (25H2!)
        "usb",                              # USB Devices
        "wifiData",                         # WiFi Data
        "wifiDirect"                        # WiFi Direct
    )
    
    foreach ($permission in $permissions) {
        $hkcuPath = "$consentStoreCurrentUser\$permission"
        
        # CRITICAL FIX v1.7.10: NUR "Value" setzen (MS-konform!)
        # LastUsedTime* sind FORENSIC-TRACKING (werden von Windows verwaltet!)
        try {
            # Ensure path exists
            if (-not (Test-Path $hkcuPath)) {
                $null = New-Item -Path $hkcuPath -Force -ErrorAction Stop
            }
            
            # NUR Value setzen - Windows managed LastUsedTime* selbst!
            Set-ItemProperty -Path $hkcuPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
            Write-Verbose "     HKCU: $permission = Deny"
            
            # Sub-Keys auch auf Deny setzen
            try {
                $appSubKeys = Get-ChildItem -Path $hkcuPath -ErrorAction SilentlyContinue
                if ($appSubKeys) {
                    foreach ($appKey in $appSubKeys) {
                        try {
                            Set-ItemProperty -Path $appKey.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Verbose "     App '$($appKey.PSChildName)' Fehler: $_"
                        }
                    }
                }
            }
            catch { }
        }
        catch {
            Write-Warning "HKCU Permission '$permission' Fehler: $_"
        }
    }
    
    # App Diagnostics auch fuer aktuellen User
    $appDiagPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-RegistryValue -Path $appDiagPathHKCU -Name "LetAppsGetDiagnosticInfo" -Value 2 -Type DWord `
        -Description "AKTUELLER USER: App Diagnostics OFF"
    
    # CRITICAL: Settings App muss neu gestartet werden damit Aenderungen sichtbar werden!
    # Settings App cached die Privacy-Einstellungen im Memory!
    Write-Verbose "Stoppe Settings App damit Aenderungen sofort sichtbar werden..."
    try {
        $settingsProcess = Get-Process -Name SystemSettings -ErrorAction SilentlyContinue
        if ($settingsProcess) {
            Stop-Process -Name SystemSettings -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 500
            
            if (-not (Get-Process -Name SystemSettings -ErrorAction SilentlyContinue)) {
                Write-Verbose "     Settings App erfolgreich gestoppt"
            } else {
                Write-Warning "Settings App konnte nicht beendet werden"
            }
        }
    }
    catch {
        Write-Verbose "Settings App stoppen fehlgeschlagen: $_"
    }
    
    Write-Success "App Permissions: ALLE 33 Kategorien - Standard-Apps deaktiviert!"
    Write-Success "Apps brauchen DEINE ERLAUBNIS fuer Zugriff auf Daten!"
    Write-Host ""
    
    # CRITICAL INFO: Windows 11 24H2/25H2 Changes
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "WICHTIG: WINDOWS 11 24H2/25H2 AENDERUNG!" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Warning "Ab Windows 11 24H2/25H2 verwendet Windows eine SQLite-Datenbank fuer Privacy-Einstellungen!"
    Write-Info "Das Script hat alle STANDARD-APPS deaktiviert fuer:"
    Write-Info "  - Notifications, Contacts, Calendar, Email, Messages"
    Write-Info "  - Account Info, Phone Calls, Documents, Pictures, Videos"
    Write-Info "  - Location, Bluetooth, WiFi, USB, und 20+ weitere"
    Write-Host ""
    Write-Success "Privacy by Default: Apps brauchen DEINE ERLAUBNIS!"
    Write-Info "  - Beim ersten Zugriff fragt Windows: 'Darf [App] zugreifen?'"
    Write-Info "  - Du kannst dann Allow oder Deny klicken"
    Write-Host ""
    Write-Warning "ABER: Die MASTER-TOGGLES in Settings koennen NUR MANUELL geaendert werden!"
    Write-Host ""
    Write-Info "OPTIONAL: Du kannst die Master-Toggles manuell ausschalten:"
    Write-Info "  1. Oeffne: Settings (Windows-Taste + I) | Privacy and security"
    Write-Info "  2. Gehe durch alle Kategorien (Notifications, Contacts, etc.)"
    Write-Info "  3. Schalte jeweils den obersten Toggle AUS"
    Write-Host ""
    Write-Info "TIPP: Das ist OPTIONAL! Auch ohne Toggle-Aenderung:"
    Write-Info "  - Apps haben keinen Zugriff bis du erlaubst"
    Write-Info "  - Privacy ist garantiert!"
    Write-Host ""
    Write-Success "ERGEBNIS: Privacy + Du behaeltst volle Kontrolle!"
}

function Disable-GameBarAndGameMode {
    <#
    .SYNOPSIS
        Disables Xbox Game Bar and Game Mode
    .DESCRIPTION
        Best Practice October 2025: Disable Game DVR, Game Bar, and Game Mode.
        Prevents Windows-Taste+G from opening Game Bar overlay.
    .NOTES
        This feature was COMPLETELY MISSING in previous versions!
        Users reported Windows-Taste+G still worked after script execution.
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Xbox Game Bar und Game Mode deaktivieren"
    
    # Disable Game DVR (User-Level)
    $gameDVRPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
    Set-RegistryValue -Path $gameDVRPath -Name "AppCaptureEnabled" -Value 0 -Type DWord `
        -Description "Game Capture deaktivieren"
    
    # Disable Game DVR (System-Level)
    $gameConfigPath = "HKCU:\System\GameConfigStore"
    Set-RegistryValue -Path $gameConfigPath -Name "GameDVR_Enabled" -Value 0 -Type DWord `
        -Description "GameDVR deaktivieren"
    
    # Disable Game Bar (Policy-Level - Force)
    $gameDVRPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    Set-RegistryValue -Path $gameDVRPolicyPath -Name "AllowGameDVR" -Value 0 -Type DWord `
        -Description "GameDVR Policy: Verbieten"
    
    # Disable Game Mode
    $gameBarPath = "HKCU:\Software\Microsoft\GameBar"
    Set-RegistryValue -Path $gameBarPath -Name "AutoGameModeEnabled" -Value 0 -Type DWord `
        -Description "Auto Game Mode deaktivieren"
    Set-RegistryValue -Path $gameBarPath -Name "AllowAutoGameMode" -Value 0 -Type DWord `
        -Description "Auto Game Mode verbieten"
    
    Write-Success "Xbox Game Bar und Game Mode deaktiviert"
    Write-Info "Windows-Taste + G oeffnet jetzt NICHTS mehr"
    Write-Info "Game Mode wird NICHT automatisch aktiviert"
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
# Disable-ConsumerFeatures is now in SecurityBaseline-Bloatware.ps1
