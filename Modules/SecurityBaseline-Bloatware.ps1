# =======================================================================================
# SecurityBaseline-Bloatware.ps1 - Remove Pre-Installed Bloatware
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
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
    
    Write-Info "$(Get-LocalizedString 'BloatwareRemoving')"
    
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
    
    Write-Info "$(Get-LocalizedString 'BloatwareScanning')"
    Write-Host ("  [i] " + (Get-LocalizedString 'BloatwareCheckingPatterns' $bloatwareList.Count)) -ForegroundColor Gray
    
    # PERFORMANCE FIX: Load Get-AppxProvisionedPackage -Online once instead of 78x!
    Write-Host ("  [i] " + (Get-LocalizedString 'BloatwareLoadingPackages')) -ForegroundColor Gray
    
    # CRITICAL FIX: Try-Catch to catch Terminating Errors
    # ErrorAction SilentlyContinue alone is NOT enough for Terminating Errors!
    $allProvisionedPackages = @()
    try {
        $allProvisionedPackages = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
        Write-Host ("  [OK] " + (Get-LocalizedString 'BloatwarePackagesLoaded' $allProvisionedPackages.Count)) -ForegroundColor Green
    }
    catch {
        Write-Verbose (Get-LocalizedString 'BloatwareLoadFailed' $_)
        Write-Host ("  [!] " + (Get-LocalizedString 'BloatwarePackagesSkipped')) -ForegroundColor Yellow
    }
    Write-Host ""
    
    $removedCount = 0
    $failedCount = 0
    $currentIndex = 0
    
    foreach ($app in $bloatwareList) {
        $currentIndex++
        # Progress display every 10 apps
        if ($currentIndex % 10 -eq 0) {
            Write-Host ("     " + (Get-LocalizedString 'BloatwareProgress' $currentIndex $bloatwareList.Count)) -ForegroundColor DarkGray
        }
        Write-Verbose "Checking: $app"
        
        # Get all matching apps (fast!)
        $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        
        foreach ($package in $packages) {
            try {
                Write-Verbose "     Removing: $($package.Name)"
                Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop | Out-Null
                $removedCount++
            }
            catch {
                Write-Verbose "     Error: $_"
                $failedCount++
            }
        }
        
        # Filter from already loaded list (FAST!)
        # Instead of calling Get-AppxProvisionedPackage -Online 78x (SLOW!)
        $provisionedPackages = $allProvisionedPackages | Where-Object { $_.DisplayName -like $app }
        
        foreach ($provPackage in $provisionedPackages) {
            Write-Verbose "     Removing Provisioned: $($provPackage.DisplayName)"
            Write-Verbose "     NOTE: New users will no longer receive this app"
            
            # CRITICAL FIX v3: Use ErrorAction Stop + try-catch + clear error record
            # TerminatingErrors from Remove-AppxProvisionedPackage appear in transcript before catch
            # Solution: Catch properly then remove the error record
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName `
                    -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                
                $removedCount++
                Write-Verbose "     Provisioned package successfully removed"
            }
            catch {
                # Remove the error record to prevent it from appearing in transcript
                if ($Error.Count -gt 0) { $Error.RemoveAt(0) }
                Write-Verbose "     Provisioned package could not be removed: $($_.Exception.Message)"
                $failedCount++
            }
        }
    }
    
    Write-Host ""
    Write-Host ("     " + (Get-LocalizedString 'BloatwareCompleted' $bloatwareList.Count $bloatwareList.Count)) -ForegroundColor Green
    
    Write-Success "$(Get-LocalizedString 'BloatwareRemovalDone')"
    Write-Info (Get-LocalizedString 'BloatwareRemoved' $removedCount)
    if ($failedCount -gt 0) {
        Write-Warning (Get-LocalizedString 'BloatwareFailed' $failedCount)
    }
    
    Write-Info "$(Get-LocalizedString 'BloatwareStoreNote')"
    Write-Warning-Custom "$(Get-LocalizedString 'BloatwareProvisionedNote')"
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
    
    Write-Info "$(Get-LocalizedString 'ConsumerFeaturesDisabling')"
    
    # Disable consumer features (auto-install of suggested apps)
    $cloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord `
        -Description "Disable Consumer Features (no auto-install apps)"
    
    # Disable automatic app installation
    Set-RegistryValue -Path $cloudContentPath -Name "DisableSoftLanding" -Value 1 -Type DWord `
        -Description "Disable Soft Landing (no app suggestions)"
    
    # Disable cloud-optimized content
    Set-RegistryValue -Path $cloudContentPath -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord `
        -Description "Disable cloud-optimized content"
    
    # IMPORTANT: Remove stub apps (LinkedIn, etc.) from Start Menu
    Set-RegistryValue -Path $cloudContentPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord `
        -Description "Disable third-party suggestions in Start Menu"
    
    Set-RegistryValue -Path $cloudContentPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord `
        -Description "Disable Windows Spotlight features"
    
    # ContentDeliveryManager Settings (in addition to CloudContent)
    $cdmPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord `
        -Description "Disable suggested apps in Start Menu (stub apps)"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord `
        -Description "Disable tips and tricks"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord `
        -Description "Disable app suggestions after Windows Update"
    
    Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-353698Enabled" -Value 0 -Type DWord `
        -Description "Disable Timeline suggestions"
    
    Set-RegistryValue -Path $cdmPath -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord `
        -Description "Disable silent installation of apps"
    
    Set-RegistryValue -Path $cdmPath -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord `
        -Description "Disable suggestions in Settings"
    
    Set-RegistryValue -Path $cdmPath -Name "PreInstalledAppsEnabled" -Value 0 -Type DWord `
        -Description "Disable pre-installed app advertising"
    
    Write-Success "$(Get-LocalizedString 'ConsumerFeaturesDisabled')"
    Write-Info "  $(Get-LocalizedString 'ConsumerFeaturesLinkedIn')"
    Write-Info "  $(Get-LocalizedString 'ConsumerFeaturesNoAutoInstall')"
    Write-Info "  $(Get-LocalizedString 'ConsumerFeaturesRestartNote')"
    Write-Info "$(Get-LocalizedString 'ConsumerFeaturesNoMoreAuto')"
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
    
    Write-Info "$(Get-LocalizedString 'SpecificAppsRemoving')"
    
    # Cortana App (Windows 11)
    try {
        $cortana = Get-AppxPackage -Name "Microsoft.549981C3F5F10" -AllUsers -ErrorAction SilentlyContinue
        if ($cortana) {
            Write-Info "$(Get-LocalizedString 'SpecificAppsCortanaRemoving')"
            Remove-AppxPackage -Package $cortana.PackageFullName -ErrorAction Stop
            Write-Success "$(Get-LocalizedString 'SpecificAppsCortanaRemoved')"
        }
    }
    catch {
        Write-Verbose "Cortana app not removed: $_"
    }
    
    # Teams Chat (Windows 11)
    try {
        Write-Info "$(Get-LocalizedString 'SpecificAppsTeamsDisabling')"
        $teamsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
        Set-RegistryValue -Path $teamsPath -Name "ChatIcon" -Value 3 -Type DWord `
            -Description "Disable Teams Chat icon"
        Write-Success "$(Get-LocalizedString 'SpecificAppsTeamsDisabled')"
    }
    catch {
        Write-Verbose "Teams Chat not disabled: $_"
    }
    
    # Windows Copilot (Windows 11 23H2+)
    try {
        Write-Info "$(Get-LocalizedString 'SpecificAppsCopilotDisabling')"
        $copilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        Set-RegistryValue -Path $copilotPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord `
            -Description "Disable Windows Copilot"
        Write-Success "$(Get-LocalizedString 'SpecificAppsCopilotDisabled')"
    }
    catch {
        Write-Verbose "Windows Copilot not disabled: $_"
    }
    
    # Widgets (Windows 11)
    try {
        Write-Info "$(Get-LocalizedString 'SpecificAppsWidgetsDisabling')"
        $widgetsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
        Set-RegistryValue -Path $widgetsPath -Name "AllowNewsAndInterests" -Value 0 -Type DWord `
            -Description "Disable Widgets"
        Write-Success "$(Get-LocalizedString 'SpecificAppsWidgetsDisabled')"
    }
    catch {
        Write-Verbose "Widgets not disabled: $_"
    }
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
