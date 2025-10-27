# =======================================================================================
# SecurityBaseline-Bloatware.ps1 - Remove Pre-Installed Bloatware
# =======================================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Remove-BloatwareApps {
    <#
    .SYNOPSIS
        Remove pre-installed bloatware and advertising apps
    .DESCRIPTION
        Removes commonly unwanted apps that come pre-installed with Windows
        Conservative approach - only removes obvious bloatware
        Does NOT remove system-critical apps
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Bloatware Removal (Conservative)"
    
    Write-Info "Bloatware wird entfuernt..."
    
    # List of bloatware apps to remove (CONSERVATIVE - only obvious junk)
    $bloatwareList = @(
        # Gaming (can be reinstalled from Store)
        "*Microsoft.XboxApp*"
        "*Microsoft.XboxGamingOverlay*"
        "*Microsoft.XboxGameOverlay*"
        "*Microsoft.XboxSpeechToTextOverlay*"
        "*Microsoft.XboxIdentityProvider*"
        "*Microsoft.Xbox.TCUI*"
        "*Microsoft.GamingApp*"  # NEW: Modern Xbox App (Windows 11 25H2)
        
        # Remote Tools
        "*MicrosoftCorporationII.QuickAssist*"  # Quick Assist (Remote Help)
        
        # Microsoft Teams & Collaboration
        "*MicrosoftTeams*"  # Microsoft Teams (legacy)
        "*Microsoft.Teams*"  # Microsoft Teams (modern, Windows 11)
        "*MSTeams*"  # Microsoft Teams variants
        
        # Microsoft Copilot
        "*Microsoft.Copilot*"  # Windows Copilot App
        "*Microsoft.Windows.Ai.Copilot.Provider*"  # Copilot Provider
        
        # Microsoft Family & Parental Controls
        "*Microsoft.MicrosoftFamily*"  # Family Safety (legacy)
        "*MicrosoftCorporationII.FamilySafety*"  # Family Safety (alternative package)
        "*MicrosoftCorporationII.Family*"  # Family App (Windows 11 modern)
        "*Microsoft.Family*"  # Family variants
        
        # Microsoft Clipchamp (Video Editor)
        "*Clipchamp.Clipchamp*"  # Clipchamp Video Editor
        
        # Microsoft To Do (Task Manager)
        "*Microsoft.Todos*"  # Microsoft To Do
        
        # Microsoft Office Hub (Office 365 App Launcher)
        "*Microsoft.MicrosoftOfficeHub*"  # Office Hub (Windows 11)
        "*Microsoft.Office.OneNote*"  # OneNote UWP
        "*Microsoft.Office.Desktop*"  # Office Desktop App
        "*Microsoft.Office.Sway*"  # Sway
        
        # Advertising & Trials
        "*king.com.CandyCrush*"
        "*king.com.BubbleWitch3Saga*"
        "*Microsoft.Advertising.Xaml*"
        
        # Social Media (can be reinstalled)
        "*Facebook*"
        "*Instagram*"
        "*Twitter*"
        "*LinkedIn*"
        
        # Games & Entertainment
        "*Microsoft.MinecraftUWP*"
        "*Solitaire*"
        "*Microsoft.MicrosoftSolitaireCollection*"
        "*Disney*"
        "*Netflix*" # Can be reinstalled from Store
        "*Spotify*" # Can be reinstalled from Store
        
        # Other Bloatware
        "*Flipboard*"
        "*Duolingo*"
        "*Plex*"
        "*Shazam*"
        # "*SoundRecorder*"  # User wants to keep this
        "*Microsoft.GetHelp*"
        "*Microsoft.Getstarted*"
        "*Microsoft.Messaging*"
        "*Microsoft.People*"
        "*Microsoft.Print3D*"
        "*Microsoft.SkypeApp*" # Skype UWP (not Desktop)
        "*Microsoft.Wallet*"
        "*Microsoft.WindowsFeedbackHub*"
        "*Microsoft.YourPhone*" # Phone Link (can be reinstalled)
        "*Microsoft.ZuneMusic*"
        "*Microsoft.ZuneVideo*"
        "*Microsoft.MixedReality.Portal*"
        
        # OEM Bloatware (common)
        "*ACGMediaPlayer*"
        "*ActiproSoftwareLLC*"
        "*Asphalt8Airborne*"
        "*AutodeskSketchBook*"
        "*CaesarsSlotsFreeCasino*"
        "*COOKINGFEVER*"
        "*DrawboardPDF*"
        "*EclipseManager*"
        "*FarmVille2CountryEscape*"
        "*Fitbit*"
        "*Flipboard*"
        "*GAMELOFTSA*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*iHeartRadio*"
        "*Keeper*"
        "*March.ofEmpires*"
        "*Netflix*"
        "*NYTCrossword*"
        "*OneConnect*"
        "*PandoraMediaInc*"
        "*PhototasticCollage*"
        "*PicsArt-PhotoStudio*"
        "*Plex*"
        "*PolarrPhotoEditorAcademicEdition*"
        "*Royal.Revolt*"
        "*Shazam*"
        "*Speed.Test*"
        "*Sway*"
        "*TuneInRadio*"
        "*WinZipUniversal*"
        "*XING*"
    )
    
    Write-Info "Scanne nach Bloatware..."
    Write-Host "  [i] Pruefe $($bloatwareList.Count) App-Muster..." -ForegroundColor Gray
    
    # PERFORMANCE FIX: Get-AppxProvisionedPackage -Online einmal laden statt 78x!
    Write-Host "  [i] Lade Provisioned Packages (einmalig, ~5 Sekunden)..." -ForegroundColor Gray
    
    # CRITICAL FIX: Try-Catch um Terminating Errors zu fangen
    # ErrorAction SilentlyContinue allein reicht NICHT bei Terminating Errors!
    $allProvisionedPackages = @()
    try {
        $allProvisionedPackages = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
        Write-Host "  [OK] $($allProvisionedPackages.Count) Provisioned Packages geladen" -ForegroundColor Green
    }
    catch {
        Write-Verbose "Get-AppxProvisionedPackage fehlgeschlagen: $_"
        Write-Host "  [!] Provisioned Packages konnten nicht geladen werden - wird uebersprungen" -ForegroundColor Yellow
    }
    Write-Host ""
    
    $removedCount = 0
    $failedCount = 0
    $currentIndex = 0
    
    foreach ($app in $bloatwareList) {
        $currentIndex++
        # Progress-Anzeige alle 10 Apps
        if ($currentIndex % 10 -eq 0) {
            Write-Host "     Fortschritt: $currentIndex/$($bloatwareList.Count) Apps geprueft..." -ForegroundColor DarkGray
        }
        Write-Verbose "Pruefe: $app"
        
        # Get all matching apps (schnell!)
        $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        
        foreach ($package in $packages) {
            try {
                Write-Verbose "     Entfuerne: $($package.Name)"
                Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop | Out-Null
                $removedCount++
            }
            catch {
                Write-Verbose "     Fehler: $_"
                $failedCount++
            }
        }
        
        # Filtern aus bereits geladener Liste (SCHNELL!)
        # Statt 78x Get-AppxProvisionedPackage -Online aufzurufen (LANGSAM!)
        $provisionedPackages = $allProvisionedPackages | Where-Object { $_.DisplayName -like $app }
        
        foreach ($provPackage in $provisionedPackages) {
            Write-Verbose "     Entfuerne Provisioned: $($provPackage.DisplayName)"
            Write-Verbose "     HINWEIS: Neue Benutzer erhalten diese App nicht mehr"
            
            # CRITICAL FIX v2: Unterdrücke TerminatingErrors komplett (auch im Transcript!)
            # PowerShell schreibt manche TerminatingErrors ins Transcript BEVOR Try-Catch greift
            # Lösung: $ErrorActionPreference temporär auf 'SilentlyContinue' setzen
            try {
                $previousErrorAction = $ErrorActionPreference
                $ErrorActionPreference = 'SilentlyContinue'
                
                Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName `
                    -WarningAction SilentlyContinue | Out-Null
                
                $ErrorActionPreference = $previousErrorAction
                
                # Prüfe ob erfolgreich (kein Error in $Error)
                if ($?) {
                    $removedCount++
                    Write-Verbose "     Provisioned Package erfolgreich entfernt"
                }
                else {
                    Write-Verbose "     Provisioned Package konnte nicht entfernt werden (Package existiert nicht oder geschuetzt)"
                    $failedCount++
                }
            }
            catch {
                $ErrorActionPreference = $previousErrorAction
                Write-Verbose "     Provisioned Package konnte nicht entfernt werden (Package existiert nicht oder geschuetzt)"
                $failedCount++
            }
        }
    }
    
    Write-Host ""
    Write-Host "     Abgeschlossen: $($bloatwareList.Count)/$($bloatwareList.Count) Apps geprueft" -ForegroundColor Green
    
    Write-Success "Bloatware-Removal abgeschlossen"
    Write-Info "Entfuernt: $removedCount Apps"
    if ($failedCount -gt 0) {
        Write-Warning "Fehlgeschlagen: $failedCount Apps (evtl. nicht installiert)"
    }
    
    Write-Info "HINWEIS: Entfuernte Apps koennen ueber Microsoft Store neu installiert werden"
    Write-Warning-Custom "WICHTIG: Provisioned Packages wurden entfernt - neue Benutzer-Profile haben diese Apps nicht!"
}

function Disable-ConsumerFeatures {
    <#
    .SYNOPSIS
        Disable Windows Consumer Features (auto-install apps)
    .DESCRIPTION
        Prevents Windows from automatically installing suggested apps
        Disables "consumer experience" that downloads bloatware
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Consumer Features (Auto-Install Bloatware)"
    
    Write-Info "Consumer Features und Promoted Apps werden deaktiviert..."
    
    # Disable consumer features (auto-install of suggested apps)
    $cloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord `
        -Description "Consumer Features deaktivieren (keine Auto-Install-Apps)"
    
    # Disable automatic app installation
    Set-RegistryValue -Path $cloudContentPath -Name "DisableSoftLanding" -Value 1 -Type DWord `
        -Description "Soft Landing deaktivieren (keine App-Vorschlaege)"
    
    # Disable cloud-optimized content
    Set-RegistryValue -Path $cloudContentPath -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord `
        -Description "Cloud-optimierte Inhalte deaktivieren"
    
    # WICHTIG: Stub-Apps (LinkedIn, etc.) aus Startmenu entfernen
    Set-RegistryValue -Path $cloudContentPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord `
        -Description "Drittanbieter-Vorschlaege im Startmenu deaktivieren"
    
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord `
        -Description "Windows Spotlight Features deaktivieren"
    
    # ContentDeliveryManager Settings (zusaetzlich zu CloudContent)
    $cdmPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord `
        -Description "Vorgeschlagene Apps im Startmenu deaktivieren (Stub-Apps)"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord `
        -Description "Tipps und Tricks deaktivieren"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord `
        -Description "App-Vorschlaege nach Windows Update deaktivieren"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-353698Enabled" -Value 0 -Type DWord `
        -Description "Timeline-Vorschlaege deaktivieren"
    
    Set-RegistryValue -Path $cdmPath -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord `
        -Description "Silent Installation von Apps deaktivieren"
    
    Set-RegistryValue -Path $cdmPath -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord `
        -Description "Vorschlaege in Einstellungen deaktivieren"
    
    Set-RegistryValue -Path $cdmPath -Name "PreInstalledAppsEnabled" -Value 0 -Type DWord `
        -Description "Vorinstallierte Apps-Werbung deaktivieren"
    
    Write-Success "Consumer Features und Promoted/Stub-Apps deaktiviert"
    Write-Info "  [OK] LinkedIn und andere Stub-Apps werden aus Startmenu entfernt"
    Write-Info "  [OK] Kein automatisches Installieren von Apps"
    Write-Info "  [!] HINWEIS: Neustart erforderlich um Startmenu zu aktualisieren!"
    Write-Info "Windows wird KEINE Apps mehr automatisch installieren"
}

function Remove-SpecificApps {
    <#
    .SYNOPSIS
        Remove specific high-impact bloatware apps
    .DESCRIPTION
        Removes specific apps that are commonly unwanted
        More aggressive than general bloatware removal
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Specific App Removal"
    
    Write-Info "Entfuerne spezifische Apps..."
    
    # Cortana App (Windows 11)
    try {
        $cortana = Get-AppxPackage -Name "Microsoft.549981C3F5F10" -AllUsers -ErrorAction SilentlyContinue
        if ($cortana) {
            Write-Info "Entfuerne Cortana App..."
            Remove-AppxPackage -Package $cortana.PackageFullName -ErrorAction Stop
            Write-Success "Cortana App entfuernt"
        }
    }
    catch {
        Write-Verbose "Cortana App nicht entfuernt: $_"
    }
    
    # Teams Chat (Windows 11)
    try {
        Write-Info "Deaktiviere Teams Chat Icon..."
        $teamsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
        Set-RegistryValue -Path $teamsPath -Name "ChatIcon" -Value 3 -Type DWord `
            -Description "Teams Chat Icon deaktivieren"
        Write-Success "Teams Chat Icon deaktiviert"
    }
    catch {
        Write-Verbose "Teams Chat nicht deaktiviert: $_"
    }
    
    # Windows Copilot (Windows 11 23H2+)
    try {
        Write-Info "Deaktiviere Windows Copilot..."
        $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        Set-RegistryValue -Path $copilotPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
            -Description "Windows Copilot deaktivieren"
        Write-Success "Windows Copilot deaktiviert"
    }
    catch {
        Write-Verbose "Windows Copilot nicht deaktiviert: $_"
    }
    
    # Widgets (Windows 11)
    try {
        Write-Info "Deaktiviere Widgets..."
        $widgetsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
        Set-RegistryValue -Path $widgetsPath -Name "AllowNewsAndInterests" -Value 0 -Type DWord `
            -Description "Widgets deaktivieren"
        Write-Success "Widgets deaktiviert"
    }
    catch {
        Write-Verbose "Widgets nicht deaktiviert: $_"
    }
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
