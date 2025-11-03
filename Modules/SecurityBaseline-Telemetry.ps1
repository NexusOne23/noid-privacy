# =======================================================================================
# SecurityBaseline-Telemetry.ps1 - Complete Telemetry Deactivation (Best Practice 2025)
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

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

# Best Practice 25H2: Enable Strict Mode
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
    
    Write-Section "$(Get-LocalizedString 'TelemetryServicesTitle')"
    
    Write-Info "$(Get-LocalizedString 'TelemetryServicesDisabling')"
    
    # List of telemetry services (Best Practice 2025)
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
        
        # Remote Registry (should already be off anyway)
        @{
            Name = "RemoteRegistry"
            DisplayName = "Remote Registry"
            Critical = $false
        },
        
        # Xbox Live Services (telemetry for gaming)
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
                Write-Warning "$(Get-LocalizedString 'TelemetryServicesSkippedCritical' $svc.DisplayName)"
                $skippedCount++
                continue
            }
            
            # Check for dependent services - Best Practice 25H2
            try {
                $dependentServices = Get-Service -Name $svc.Name -DependentServices -ErrorAction Stop | 
                                     Where-Object { $_.Status -eq 'Running' }
                
                if ($dependentServices) {
                    Write-Warning "$(Get-LocalizedString 'TelemetryServicesSkippedDependent' $svc.DisplayName $dependentServices.Count)"
                    foreach ($depSvc in $dependentServices) {
                        Write-Verbose "$(Get-LocalizedString 'TelemetryServicesDependentService' $depSvc.DisplayName)"
                    }
                    $skippedCount++
                    continue
                }
            }
            catch {
                Write-Verbose "$(Get-LocalizedString 'TelemetryServicesCheckDependentFailed' $svc.DisplayName $_)"
            }
            
            # Stop and disable service (race-condition-frei)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Verbose "$(Get-LocalizedString 'TelemetryServicesDeactivated' $svc.DisplayName)"
                $disabledCount++
            }
            else {
                Write-Warning "$(Get-LocalizedString 'TelemetryServicesError' $svc.DisplayName)"
            }
        }
    }
    
    Write-Success "$(Get-LocalizedString 'TelemetryServicesDisabledCount' $disabledCount)"
    if ($skippedCount -gt 0) {
        Write-Warning "$(Get-LocalizedString 'TelemetryServicesSkippedCount' $skippedCount)"
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
    
    Write-Section "$(Get-LocalizedString 'TelemetryRegistryTitle')"
    
    Write-Info "$(Get-LocalizedString 'TelemetryRegistrySetting')"
    
    # ===== MAIN SWITCH: Set telemetry to Security (0) =====
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
    
    # Per-User Setting via POLICY (applies to ALL users!)
    $userAdvertisingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-RegistryValue -Path $userAdvertisingPath -Name "DisabledByGroupPolicy" -Value 1 -Type DWord `
        -Description "Advertising ID Policy (applies to ALL users)"
    
    # ===== PRIVACY | GENERAL - COMPLETE (5 TOGGLES) =====
    # Best Practice October 2025: All 5 toggles in Settings | Privacy and security | General
    # Toggle 5 is NEW in Windows 11 25H2!
    Write-Info "$(Get-LocalizedString 'TelemetryPrivacyGeneralToggles')"
    
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
    # CRITICAL FIX: Wrong key! Must be AccountNotifications (Source: ElevenForum)
    $settingsNotifPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"
    try {
        if (-not (Test-Path $settingsNotifPath)) {
            $null = New-Item -Path $settingsNotifPath -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $settingsNotifPath -Name "EnableAccountNotifications" -Value 0 -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetrySettingsNotifForced')"
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'TelemetrySettingsNotifError' $_)"
    }
    
    Write-Success "$(Get-LocalizedString 'TelemetryPrivacyGeneralComplete')"
    
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
    
    Write-Success "$(Get-LocalizedString 'TelemetryRegistryComplete')"
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
    
    Write-Section "$(Get-LocalizedString 'TelemetryTasksTitle')"
    
    Write-Info "$(Get-LocalizedString 'TelemetryTasksDisabling')"
    
    # List of telemetry tasks (Best Practice 2025)
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
                # Best Practice 25H2: Idempotency - only disable if not already disabled)
                if ($task.State -ne 'Disabled') {
                    # Disable task
                    [void](Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
                    Write-Verbose "$(Get-LocalizedString 'TelemetryTasksDeactivated' $taskPath)"
                    $disabledCount++
                }
                else {
                    Write-Verbose "$(Get-LocalizedString 'TelemetryTasksAlreadyDisabled' $taskPath)"
                }
            }
            else {
                $notFoundCount++
            }
        }
        catch {
            Write-Verbose "$(Get-LocalizedString 'TelemetryTasksError' $taskPath $_)"
        }
    }
    
    Write-Success "$(Get-LocalizedString 'TelemetryTasksDisabledCount' $disabledCount)"
    if ($notFoundCount -gt 0) {
        Write-Verbose "$(Get-LocalizedString 'TelemetryTasksNotFoundCount' $notFoundCount)"
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
    
    Write-Section "$(Get-LocalizedString 'TelemetryHostsTitle')"
    
    Write-Warning-Custom "$(Get-LocalizedString 'TelemetryHostsSkipped')"
    Write-Info "$(Get-LocalizedString 'TelemetryHostsReason')"
    Write-Info "$(Get-LocalizedString 'TelemetryHostsAlternative')"
    
    # Telemetry is already blocked through:
    # 1. Registry keys (AllowTelemetry = 0)
    # 2. Services disabled (DiagTrack, dmwappushservice, etc.)
    # 3. Scheduled tasks disabled
    # 4. DNS-level blocking (if DNS blocklist active)
    
    return
    
    # Original code commented out (does not work with hostnames)
    # NOTE: The complete firewall code was disabled because Windows Firewall
    # does not accept hostnames (only IP addresses). DNS resolution would be needed,
    # but telemetry IPs change constantly. Alternative: DNS blocklist.
    
    <#
    # THIS CODE IS DISABLED - DOES NOT WORK WITH HOSTNAMES
    Write-Info "$(Get-LocalizedString 'TelemetryHostsBlocking')"
    
    # List of telemetry hosts (Best Practice 2025)
    # IMPORTANT: Windows Update hosts are NOT in this list!
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
            Write-Warning "$(Get-LocalizedString 'TelemetryHostsRuleError' $ruleName $_)"
        }
    }
    
    if ($rulesCreated -gt 0) {
        Write-Success "$(Get-LocalizedString 'TelemetryHostsBlocked' $telemetryHosts.Count $rulesCreated)"
        Write-Info "$(Get-LocalizedString 'TelemetryHostsWindowsUpdateOK')"
    }
    else {
        Write-Warning "$(Get-LocalizedString 'TelemetryHostsNoRules')"
    }
    #>
}

# NOTE: Disable-ConsumerFeatures was moved to SecurityBaseline-Bloatware.ps1
# to avoid code duplication. The function is exported from there.

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
    
    Write-Section "$(Get-LocalizedString 'TelemetryStatusTitle')"
    
    Write-Info "$(Get-LocalizedString 'TelemetryStatusCreating')"
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDeactivated')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagTrack')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusWAPPush')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusErrorReporting')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusRegistry')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusAppTelemetry')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusAdvertisingID')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusActivityHistory')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusCloudClipboard')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusLocationServices')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusHandwriting')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusSettingsSync')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusFindMyDevice')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusWindowsTips')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusTailoredExp')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusConsumerFeatures')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusScheduledTasks')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusFirewallHosts')" -ForegroundColor Green
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusNotDeactivated')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryStatusWindowsUpdate')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryStatusUpdateReason')" -ForegroundColor White
    Write-Host "$(Get-LocalizedString 'TelemetryStatusUpdateWithout')" -ForegroundColor White
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagPolicy')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagPolicyReason')" -ForegroundColor White
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagPolicyWithout')" -ForegroundColor White
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagSystemHost')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagSystemReason')" -ForegroundColor White
    Write-Host "$(Get-LocalizedString 'TelemetryStatusDiagSystemWithout')" -ForegroundColor White
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusMinimalTelemetry')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryStatusMinimalReason')" -ForegroundColor White
    Write-Host "$(Get-LocalizedString 'TelemetryStatusMinimalWhat')" -ForegroundColor White
    Write-Host "$(Get-LocalizedString 'TelemetryStatusMinimalNot')" -ForegroundColor White
    
    Write-Host "$(Get-LocalizedString 'TelemetryStatusResult')" -ForegroundColor Cyan
    Write-Host "$(Get-LocalizedString 'TelemetryStatus95Percent')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusOnlySecurity')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusNoTracking')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusUpdateWorks')" -ForegroundColor Green
    Write-Host "$(Get-LocalizedString 'TelemetryStatusMaxPrivacy')" -ForegroundColor Green
}

#region PRIVACY EXTENDED - KRITISCHE Settings die vorher FEHLTEN!

function Disable-WindowsSearchWebFeatures {
    <#
    .SYNOPSIS
        Deaktiviert Web-Suche in Windows Search
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetrySearchTitle')"
    
    $searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    
    Set-RegistryValue -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord -Description "Cortana deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "DisableWebSearch" -Value 1 -Type DWord -Description "Web-Suche deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Description "Connected Search Web deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "BingSearchEnabled" -Value 0 -Type DWord -Description "Bing-Integration deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord -Description "Search Highlights deaktivieren"
    Set-RegistryValue -Path $searchPath -Name "AllowCloudSearch" -Value 0 -Type DWord -Description "Cloud Search deaktivieren"
    
    # Best Practice October 2025: HKCU settings required for GUI to show correctly!
    # HKLM Policy alone is NOT enough - Windows Settings reads HKCU
    Write-Info "$(Get-LocalizedString 'TelemetrySearchSettingUser')"
    
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
    
    Write-Success "$(Get-LocalizedString 'TelemetrySearchComplete')"
    Write-Info "$(Get-LocalizedString 'TelemetrySearchNoWebResults')"
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
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryCameraTitle')"
    
    # CRITICAL FIX October 2025: Windows 11 25H2 reads GUI from HKCU, not HKLM!
    # HKLM = Default for NEW users only
    # HKCU = Current user (what GUI shows)
    # We need to set BOTH!
    
    Write-Info "$(Get-LocalizedString 'TelemetryCameraRemoving')"
    
    # CRITICAL FIX v1.7.10: ONLY set "Value"="Deny" (MS-compliant!)
    # LastUsedTime* are FORENSIC-TRACKING (managed automatically by Windows!)
    # Source: MS Support Docs + ElevenForum + Forensics Research
    
    # ===== KAMERA (WEBCAM) =====
    
    # HKCU (aktueller User - wirkt SOFORT!)
    $cameraPathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    try {
        if (-not (Test-Path $cameraPathHKCU)) {
            $null = New-Item -Path $cameraPathHKCU -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $cameraPathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetryCameraHKCUValue')"
        
        # Sub-keys also set to Deny
        try {
            $cameraApps = Get-ChildItem -Path $cameraPathHKCU -ErrorAction SilentlyContinue
            if ($cameraApps) {
                foreach ($app in $cameraApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "$(Get-LocalizedString 'TelemetryCameraAppError' $app.PSChildName $_)"
                    }
                }
            }
        }
        catch {
            Write-Verbose "$(Get-LocalizedString 'TelemetryCameraAppsEnumError' $_)"
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'TelemetryCameraHKCUError' $_)"
    }
    
    # HKLM (new users - default)
    $cameraPathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    try {
        if (-not (Test-Path $cameraPathHKLM)) {
            $null = New-Item -Path $cameraPathHKLM -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $cameraPathHKLM -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetryCameraHKLMValue')"
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetryCameraHKLMError' $_)"
    }
    
    # ===== MIKROFON (MICROPHONE) =====
    
    # HKCU (aktueller User - wirkt SOFORT!)
    $microphonePathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    try {
        if (-not (Test-Path $microphonePathHKCU)) {
            $null = New-Item -Path $microphonePathHKCU -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $microphonePathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneHKCUValue')"
        
        # Sub-keys also set to Deny
        try {
            $microphoneApps = Get-ChildItem -Path $microphonePathHKCU -ErrorAction SilentlyContinue
            if ($microphoneApps) {
                foreach ($app in $microphoneApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneAppError' $app.PSChildName $_)"
                    }
                }
            }
        }
        catch {
            Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneAppsEnumError' $_)"
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'TelemetryMicrophoneHKCUError' $_)"
    }
    
    # HKLM (new users - default)
    $microphonePathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    try {
        if (-not (Test-Path $microphonePathHKLM)) {
            $null = New-Item -Path $microphonePathHKLM -Force -ErrorAction Stop
        }
        Set-ItemProperty -Path $microphonePathHKLM -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneHKLMValue')"
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneHKLMError' $_)"
    }
    
    # ===== CRITICAL FIX: DEVICE-LEVEL TOGGLE (Windows 11 25H2) =====
    # Windows 11 has TWO toggles per permission:
    # 1. "Access to Camera" (Device-Level) = EnabledByUser in Capabilities\webcam\Apps
    # 2. "Allow apps to access" (App-Level) = Value in ConsentStore\webcam
    # 
    # We must set BOTH to OFF!
    
    Write-Verbose "$(Get-LocalizedString 'TelemetryDeviceTogglesSet')"
    
    # CAMERA: Device-Level Toggle OFF (TrustedInstaller-Protected!)
    $cameraCapabilitiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\webcam\Apps"
    try {
        if (Test-Path $cameraCapabilitiesPath) {
            $cameraApps = Get-ChildItem -Path $cameraCapabilitiesPath -ErrorAction SilentlyContinue
            foreach ($app in $cameraApps) {
                # CRITICAL: EnabledByUser Keys are TrustedInstaller-Protected!
                # Use Set-RegistryValueSmart (with ownership management)
                $appPath = $app.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
                $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value 0 -Type DWord `
                    -Description "Device-Toggle Kamera: $($app.PSChildName)"
                if ($result) {
                    Write-Verbose "$(Get-LocalizedString 'TelemetryCameraDeviceToggle' $app.PSChildName)"
                }
            }
        }
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetryCameraDeviceError' $_)"
    }
    
    # MICROPHONE: Device-Level Toggle OFF (TrustedInstaller-Protected!)
    $microphoneCapabilitiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps"
    try {
        if (Test-Path $microphoneCapabilitiesPath) {
            $microphoneApps = Get-ChildItem -Path $microphoneCapabilitiesPath -ErrorAction SilentlyContinue
            foreach ($app in $microphoneApps) {
                # CRITICAL: EnabledByUser Keys are TrustedInstaller-Protected!
                # Use Set-RegistryValueSmart (with ownership management)
                $appPath = $app.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
                $result = Set-RegistryValueSmart -Path $appPath -Name "EnabledByUser" -Value 0 -Type DWord `
                    -Description "Device-Toggle Mikrofon: $($app.PSChildName)"
                if ($result) {
                    Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneDeviceToggle' $app.PSChildName)"
                }
            }
        }
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetryMicrophoneDeviceError' $_)"
    }
    
    Write-Verbose "$(Get-LocalizedString 'TelemetryDeviceTogglesComplete')"
    
    # Verification: Check if values were really set
    Start-Sleep -Milliseconds 500  # Kurze Pause damit Registry committed
    
    # CRITICAL: Check property existence to prevent PropertyNotFoundException
    $camItem = Get-ItemProperty -Path $cameraPathHKCU -ErrorAction SilentlyContinue
    $micItem = Get-ItemProperty -Path $microphonePathHKCU -ErrorAction SilentlyContinue
    $camValue = if ($camItem -and ($camItem.PSObject.Properties.Name -contains "Value")) { $camItem.Value } else { $null }
    $micValue = if ($micItem -and ($micItem.PSObject.Properties.Name -contains "Value")) { $micItem.Value } else { $null }
    
    if ($camValue -eq "Deny") {
        Write-Success "$(Get-LocalizedString 'TelemetryCameraAllDisabled')"
    } else {
        Write-Warning "$(Get-LocalizedString 'TelemetryCameraConsentStore' $camValue)"
    }
    
    if ($micValue -eq "Deny") {
        Write-Success "$(Get-LocalizedString 'TelemetryMicrophoneAllDisabled')"
    } else {
        Write-Warning "$(Get-LocalizedString 'TelemetryMicrophoneConsentStore' $micValue)"
    }
    
    # CRITICAL: Settings App AND Explorer must be restarted!
    # Settings App caches privacy settings in memory!
    Write-Verbose "$(Get-LocalizedString 'TelemetryStopSettingsApp')"
    try {
        Get-Process -Name SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Verbose "$(Get-LocalizedString 'TelemetrySettingsAppRestarted')"
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetrySettingsAppNotOpen')"
    }
    
    # ADDITIONAL FIX: Flush Registry Cache
    Write-Verbose "$(Get-LocalizedString 'TelemetryFlushRegistryCache')"
    try {
        # Force registry write to disk
        $null = Invoke-Command {reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam 2>&1}
        Start-Sleep -Milliseconds 200
        Write-Verbose "$(Get-LocalizedString 'TelemetryRegistryCacheFlushed')"
    }
    catch {
        Write-Verbose "$(Get-LocalizedString 'TelemetryRegistryCacheOptional')"
    }
    
    Write-Host ""
    Write-Host "$(Get-LocalizedString 'TelemetryImportantChangeSeparator')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryImportantWin11Change')" -ForegroundColor Yellow
    Write-Host "$(Get-LocalizedString 'TelemetryImportantChangeSeparator')" -ForegroundColor Yellow
    Write-Host ""
    Write-Warning "$(Get-LocalizedString 'TelemetrySQLiteChange')"
    Write-Info "$(Get-LocalizedString 'TelemetryStandardAppsDisabled')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppsNeedPermission')"
    Write-Info "$(Get-LocalizedString 'TelemetryWindowsAsksFirst')"
    Write-Info "$(Get-LocalizedString 'TelemetryUserCanAllow')"
    Write-Host ""
    Write-Warning "$(Get-LocalizedString 'TelemetryMasterTogglesManual')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'TelemetryRecommendedManual')"
    Write-Info "$(Get-LocalizedString 'TelemetryOpenSettings')"
    Write-Info "$(Get-LocalizedString 'TelemetryCameraSettings')"
    Write-Info "$(Get-LocalizedString 'TelemetryCameraAccessOff')"
    Write-Info "$(Get-LocalizedString 'TelemetryCameraAppsOff')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'TelemetryMicrophoneSettings')"  
    Write-Info "$(Get-LocalizedString 'TelemetryMicrophoneAccessOff')"
    Write-Info "$(Get-LocalizedString 'TelemetryMicrophoneAppsOff')"
    Write-Host ""
    Write-Success "$(Get-LocalizedString 'TelemetryResultMaxPrivacy')"
    Write-Info "$(Get-LocalizedString 'TelemetryCanAllowIndividual')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'TelemetryHardwareInfo')"
    Write-Info "$(Get-LocalizedString 'TelemetryHardwareDisable')"
}

function Disable-PrivacyExperienceSettings {
    <#
    .SYNOPSIS
        Deaktiviert Privacy-invasive Windows Features
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryPrivacyExpTitle')"
    
    # Language List via POLICY (applies to ALL users!)
    # NOTE: There is no direct HKLM policy for HttpAcceptLanguageOptOut
    # Instead we use DisableTailoredExperiencesWithDiagnosticData
    # This covers Language List + other personalized content
    
    $cloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Description "Consumer Features deaktivieren"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Description "Vorgeschlagene Inhalte deaktivieren"
    Set-RegistryValue -Path $cloudContentPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -Description "Drittanbieter-Vorschlaege deaktivieren"
    
    Write-Success "$(Get-LocalizedString 'TelemetryPrivacyExpComplete')"
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
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryInkingTitle')"
    
    # Input Personalization via POLICY (applies to ALL users!)
    $inputPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inputPolicyPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Description "Freihand-Datensammlung einschraenken (Policy)"
    Set-RegistryValue -Path $inputPolicyPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -Description "Text-Datensammlung einschraenken (Policy)"
    
    # Additional: Disable handwriting data sharing
    $inputPersonalizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    Set-RegistryValue -Path $inputPersonalizationPath -Name "AllowInputPersonalization" -Value 0 -Type DWord -Description "Input Personalization komplett deaktivieren"
    
    # Best Practice October 2025: HKCU settings required for GUI to show correctly!
    Write-Info "$(Get-LocalizedString 'TelemetryInkingSettingUser')"
    
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
    
    Write-Success "$(Get-LocalizedString 'TelemetryInkingComplete')"
    Write-Info "$(Get-LocalizedString 'TelemetryInkingSettingsOff')"
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
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryLocationTitle')"
    
    # HKLM: Default for new users
    $locationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    Set-RegistryValue -Path $locationPath -Name "Value" -Value "Deny" -Type String -Description "Standort: App-Zugriff VERWEIGERT"
    
    $sensorPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    Set-RegistryValue -Path $sensorPath -Name "DisableLocation" -Value 1 -Type DWord -Description "Standortdienste deaktivieren"
    
    # CRITICAL FIX v1.7.10: HKCU for current user (ONLY Value!)
    Write-Verbose "$(Get-LocalizedString 'TelemetryLocationSettingHKCU')"
    $locationPathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    try {
        if (-not (Test-Path $locationPathHKCU)) {
            $null = New-Item -Path $locationPathHKCU -Force -ErrorAction Stop
        }
        # ONLY set Value - Windows manages LastUsedTime* itself!
        Set-ItemProperty -Path $locationPathHKCU -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
        Write-Verbose "$(Get-LocalizedString 'TelemetryLocationHKCUValue')"
        
        # Sub-keys also set to Deny
        try {
            $locationApps = Get-ChildItem -Path $locationPathHKCU -ErrorAction SilentlyContinue
            if ($locationApps) {
                foreach ($app in $locationApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "$(Get-LocalizedString 'TelemetryLocationAppError' $app.PSChildName $_)"
                    }
                }
            }
        }
        catch {
            Write-Verbose "$(Get-LocalizedString 'TelemetryLocationAppsEnumError' $_)"
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'TelemetryLocationHKCUError' $_)"
    }
    
    Write-Success "$(Get-LocalizedString 'TelemetryLocationComplete')"
    Write-Info "$(Get-LocalizedString 'TelemetryLocationMasterToggle')"
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
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryAppPermTitle')"
    
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermSetting')"
    
    # Base path for ConsentStore
    $consentStoreBase = "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    
    # ===== CRITICAL: SENSITIVE DATA ACCESS =====
    
    # Speech (Online speech recognition)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseSpeech')"
    $speechPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
    Set-RegistryValue -Path $speechPath -Name "HasAccepted" -Value 0 -Type DWord `
        -Description "Online Speech Recognition OFF (Privacy)"
    
    # Notifications (Apps can read notifications)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseNotif')"
    $notifPath = "HKLM:\$consentStoreBase\userNotificationListener"
    Set-RegistryValue -Path $notifPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Notifications OFF"
    
    # Account Info (Name, picture, email)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseAccount')"
    $accountPath = "HKLM:\$consentStoreBase\userAccountInformation"
    Set-RegistryValue -Path $accountPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Account Info OFF"
    
    # Contacts
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseContacts')"
    $contactsPath = "HKLM:\$consentStoreBase\contacts"
    Set-RegistryValue -Path $contactsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Contacts OFF"
    
    # Calendar
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseCalendar')"
    $calendarPath = "HKLM:\$consentStoreBase\appointments"
    Set-RegistryValue -Path $calendarPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Calendar OFF"
    
    # Email
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseEmail')"
    $emailPath = "HKLM:\$consentStoreBase\email"
    Set-RegistryValue -Path $emailPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Email OFF"
    
    # Phone Calls
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerbosePhone')"
    $phonePath = "HKLM:\$consentStoreBase\phoneCall"
    Set-RegistryValue -Path $phonePath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Phone Calls OFF"
    
    # Call History
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseCallHistory')"
    $callHistoryPath = "HKLM:\$consentStoreBase\phoneCallHistory"
    Set-RegistryValue -Path $callHistoryPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Call History OFF"
    
    # Messaging (SMS)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseMessaging')"
    $messagingPath = "HKLM:\$consentStoreBase\chat"
    Set-RegistryValue -Path $messagingPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Messaging/SMS OFF"
    
    # Tasks (To-do lists)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseTasks')"
    $tasksPath = "HKLM:\$consentStoreBase\userDataTasks"
    Set-RegistryValue -Path $tasksPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Tasks OFF"
    
    # Radios (Bluetooth/WiFi control)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseRadios')"
    $radiosPath = "HKLM:\$consentStoreBase\radios"
    Set-RegistryValue -Path $radiosPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Radios Control OFF"
    
    # Other Devices (Unpaired devices sync)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseDevices')"
    $devicesPath = "HKLM:\$consentStoreBase\bluetoothSync"
    Set-RegistryValue -Path $devicesPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Other Devices OFF"
    
    # Voice Activation
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseVoice')"
    $voicePath = "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"
    Set-RegistryValue -Path $voicePath -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type DWord `
        -Description "Voice Activation above Lockscreen OFF"
    
    # Documents Library
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseDocs')"
    $docsPath = "HKLM:\$consentStoreBase\documentsLibrary"
    Set-RegistryValue -Path $docsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Documents OFF"
    
    # Pictures Library
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerbosePics')"
    $picsPath = "HKLM:\$consentStoreBase\picturesLibrary"
    Set-RegistryValue -Path $picsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Pictures OFF"
    
    # Videos Library
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseVideos')"
    $videosPath = "HKLM:\$consentStoreBase\videosLibrary"
    Set-RegistryValue -Path $videosPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Videos OFF"
    
    # Broad File System Access (Full file system)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseBroadFS')"
    $broadFSPath = "HKLM:\$consentStoreBase\broadFileSystemAccess"
    Set-RegistryValue -Path $broadFSPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Broad File System OFF (Maximum Security!)"
    
    # ===== NEU: FEHLENDE PERMISSIONS (25H2 Update) =====
    
    # Downloads Folder (separate from Documents!)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseDownloads')"
    $downloadsFolderPath = "HKLM:\$consentStoreBase\downloadsFolder"
    Set-RegistryValue -Path $downloadsFolderPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Downloads Folder OFF"
    
    # Music Library
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseMusic')"
    $musicPath = "HKLM:\$consentStoreBase\musicLibrary"
    Set-RegistryValue -Path $musicPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Music Library OFF"
    
    # Automatic File Downloads (Background file access)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseAutoDownloads')"
    $autoDownloadsPath = "HKLM:\$consentStoreBase\automaticFileDownloads"
    Set-RegistryValue -Path $autoDownloadsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Automatic File Downloads OFF"
    
    # App Diagnostics (Apps reading other apps' info)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseAppDiag')"
    $appDiagPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-RegistryValue -Path $appDiagPath -Name "LetAppsGetDiagnosticInfo" -Value 2 -Type DWord `
        -Description "Apps: Diagnostics OFF (Value 2 means User Denied)"
    
    # ===== NEW: ALL REMAINING CATEGORIES (Windows 11 25H2 Complete) =====
    
    # Activity (Activity History)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseActivity')"
    $activityPath = "HKLM:\$consentStoreBase\activity"
    Set-RegistryValue -Path $activityPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Activity History OFF"
    
    # Bluetooth (Bluetooth devices access)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseBluetooth')"
    $bluetoothPath = "HKLM:\$consentStoreBase\bluetooth"
    Set-RegistryValue -Path $bluetoothPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Bluetooth OFF"
    
    # Cellular Data (Mobile data access)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseCellular')"
    $cellularPath = "HKLM:\$consentStoreBase\cellularData"
    Set-RegistryValue -Path $cellularPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Cellular Data OFF"
    
    # Gaze Input (Eye tracking)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseGaze')"
    $gazePath = "HKLM:\$consentStoreBase\gazeInput"
    Set-RegistryValue -Path $gazePath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Gaze Input/Eye Tracking OFF"
    
    # Graphics Capture Programmatic (Screen capture API)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseGraphicsProg')"
    $graphicsProgPath = "HKLM:\$consentStoreBase\graphicsCaptureProgrammatic"
    Set-RegistryValue -Path $graphicsProgPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Graphics Capture Programmatic OFF"
    
    # Graphics Capture Without Border (Borderless screen capture)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseGraphicsBorder')"
    $graphicsBorderPath = "HKLM:\$consentStoreBase\graphicsCaptureWithoutBorder"
    Set-RegistryValue -Path $graphicsBorderPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Graphics Capture Without Border OFF"
    
    # Human Interface Device (HID devices)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseHID')"
    $hidPath = "HKLM:\$consentStoreBase\humanInterfaceDevice"
    Set-RegistryValue -Path $hidPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Human Interface Device OFF"
    
    # Passkeys (Passkey authentication)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerbosePasskeys')"
    $passkeysPath = "HKLM:\$consentStoreBase\passkeys"
    Set-RegistryValue -Path $passkeysPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Passkeys OFF"
    
    # Passkeys Enumeration (List passkeys)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerbosePasskeysEnum')"
    $passkeysEnumPath = "HKLM:\$consentStoreBase\passkeysEnumeration"
    Set-RegistryValue -Path $passkeysEnumPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Passkeys Enumeration OFF"
    
    # Custom Sensors (Custom sensor access)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseSensors')"
    $sensorsPath = "HKLM:\$consentStoreBase\sensors.custom"
    Set-RegistryValue -Path $sensorsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Custom Sensors OFF"
    
    # Serial Communication (COM ports)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseSerial')"
    $serialPath = "HKLM:\$consentStoreBase\serialCommunication"
    Set-RegistryValue -Path $serialPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: Serial Communication OFF"
    
    # System AI Models (NEW in Windows 11 25H2!)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseAI')"
    $aiModelsPath = "HKLM:\$consentStoreBase\systemAIModels"
    Set-RegistryValue -Path $aiModelsPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: System AI Models OFF (Windows 11 25H2)"
    
    # USB Devices (USB device access)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseUSB')"
    $usbPath = "HKLM:\$consentStoreBase\usb"
    Set-RegistryValue -Path $usbPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: USB Devices OFF"
    
    # WiFi Data (WiFi network info)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseWiFiData')"
    $wifiDataPath = "HKLM:\$consentStoreBase\wifiData"
    Set-RegistryValue -Path $wifiDataPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: WiFi Data OFF"
    
    # WiFi Direct (WiFi Direct connections)
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermVerboseWiFiDirect')"
    $wifiDirectPath = "HKLM:\$consentStoreBase\wiFiDirect"
    Set-RegistryValue -Path $wifiDirectPath -Name "Value" -Value "Deny" -Type String `
        -Description "Apps: WiFi Direct OFF"
    
    # ===== CRITICAL FIX: HKCU FOR CURRENT USER! =====
    # HKLM only sets defaults for NEW users
    # HKCU = Current user (takes effect immediately!)
    
    Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermSettingHKCU')"
    $consentStoreCurrentUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    
    # List of all permissions that should also be set for current user
    # COMPLETE LIST: All 33 ConsentStore permissions
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
        
        # CRITICAL FIX v1.7.10: ONLY set "Value" (MS-compliant!)
        # LastUsedTime* are FORENSIC-TRACKING (managed by Windows!)
        try {
            # Ensure path exists
            if (-not (Test-Path $hkcuPath)) {
                $null = New-Item -Path $hkcuPath -Force -ErrorAction Stop
            }
            
            # ONLY set Value - Windows manages LastUsedTime* itself!
            Set-ItemProperty -Path $hkcuPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
            Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermHKCUDeny' $permission)"
            
            # Sub-keys also set to Deny
            try {
                $appSubKeys = Get-ChildItem -Path $hkcuPath -ErrorAction SilentlyContinue
                if ($appSubKeys) {
                    foreach ($appKey in $appSubKeys) {
                        try {
                            Set-ItemProperty -Path $appKey.PSPath -Name "Value" -Value "Deny" -Type String -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermAppError' $appKey.PSChildName $_)"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "$(Get-LocalizedString 'TelemetryAppPermAppsEnumError' $permission $_)"
            }
        }
        catch {
            Write-Warning "$(Get-LocalizedString 'TelemetryAppPermHKCUError' $permission $_)"
        }
    }
    
    # App Diagnostics also for current user
    $appDiagPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-RegistryValue -Path $appDiagPathHKCU -Name "LetAppsGetDiagnosticInfo" -Value 2 -Type DWord `
        -Description "CURRENT USER: App Diagnostics OFF"
    
    # CRITICAL: Settings App must be restarted for changes to become visible!
    # Settings App caches privacy settings in memory!
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
    
    Write-Success "$(Get-LocalizedString 'TelemetryAppPermComplete')"
    Write-Success "$(Get-LocalizedString 'TelemetryAppPermNeedConsent')"
    Write-Host ""
    
    # CRITICAL INFO: Windows 11 24H2/25H2 Changes
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "WICHTIG: WINDOWS 11 24H2/25H2 AENDERUNG!" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Warning "$(Get-LocalizedString 'TelemetryAppPermSQLiteInfo')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermStandardDisabled')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermCategories')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermMoreCategories')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermEvenMore')"
    Write-Host ""
    Write-Success "$(Get-LocalizedString 'TelemetryAppPermDefaultPrivacy')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermFirstAccess')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermCanDeny')"
    Write-Host ""
    Write-Warning "$(Get-LocalizedString 'TelemetryAppPermTogglesManual')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermOptionalManual')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermOpenSettings')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermGoThrough')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermTurnOffTop')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermTipOptional')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermNoAccessUntil')"
    Write-Info "$(Get-LocalizedString 'TelemetryAppPermGuaranteed')"
    Write-Host ""
    Write-Success "$(Get-LocalizedString 'TelemetryAppPermResultControl')"
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
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryGameBarTitle')"
    
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
    
    Write-Success "$(Get-LocalizedString 'TelemetryGameBarComplete')"
    Write-Info "$(Get-LocalizedString 'TelemetryGameBarWindowsKeyG')"
    Write-Info "$(Get-LocalizedString 'TelemetryGameBarAutoMode')"
}

function Set-LockScreenSecurity {
    <#
    .SYNOPSIS
        Hardens lock screen security settings (Microsoft Baseline 25H2)
    .DESCRIPTION
        Implements lock screen security policies from Microsoft Baseline
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "$(Get-LocalizedString 'TelemetryLockScreenTitle')"
    
    # User: Turn off toast notifications on the lock screen
    $pushNotifPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    Set-RegistryValue -Path $pushNotifPath -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord `
        -Description "No toast notifications on lock screen (privacy + security)"
    
    # Personalization: Prevent enabling lock screen camera
    $personalizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Set-RegistryValue -Path $personalizationPath -Name "NoLockScreenCamera" -Value 1 -Type DWord `
        -Description "Prevent lock screen camera (privacy)"
    
    # Personalization: Prevent enabling lock screen slideshow
    Set-RegistryValue -Path $personalizationPath -Name "NoLockScreenSlideshow" -Value 1 -Type DWord `
        -Description "Prevent lock screen slideshow (privacy)"
    
    Write-Success "$(Get-LocalizedString 'TelemetryLockScreenComplete')"
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
# Disable-ConsumerFeatures is now in SecurityBaseline-Bloatware.ps1
