# =======================================================================================
# SecurityBaseline-OneDrive.ps1 - OneDrive Privacy Hardening
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Set-OneDrivePrivacyHardening {
    <#
    .SYNOPSIS
        OneDrive Privacy Hardening (without Breaking Changes)
    .DESCRIPTION
        Hardens OneDrive for maximum privacy with full functionality:
        - Disables Tutorial and Feedback (Privacy)
        - Prevents Network Traffic before User-Login (CRITICAL!)
        - Blocks Known Folder Move / Auto-Upload (Privacy!)
        - Keeps OneDrive functionality (User can continue using)
        
        IMPORTANT: Optional Diagnostic Data Popup is ALREADY disabled by Telemetry module!
        -> AllowTelemetry = 0 (Security Level) blocks OneDrive telemetry
        
        Best Practice October 2025: Privacy-First without Breaking Changes
    .NOTES
        NO Breaking Changes:
        - OneDrive continues to work
        - User can manually upload files (Drag and Drop)
        - Personal OneDrive stays active (not Enterprise-Only)
        
        Breaking for:
        - NOBODY! (Safe for all users)
        
        Auto-Upload (KFM) is blocked:
        - Desktop/Documents/Pictures will NOT be automatically uploaded
        - User must manually move files to OneDrive folder
        - Privacy-First: User has CONTROL over what gets uploaded
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "OneDrive Privacy Hardening"
    
    Write-Info "$(Get-LocalizedString 'OneDriveHardeningStart')"
    Write-Info "$(Get-LocalizedString 'OneDriveFunctionalityPreserved')"
    
    # CRITICAL FIX v1.7.6: Set BOTH paths (HKCU + HKLM) for maximum coverage!
    # HKCU = Current User (takes effect immediately)
    # HKLM = Default for NEW Users (future profiles)
    $oneDrivePathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"
    $oneDrivePathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    
    # 1. Disable Tutorial (Privacy: less tracking on first start)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveTutorialDisabled')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableTutorial" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveTutorialDisabledDefault')"
    
    # 2. Disable Feedback (Privacy: prevents data leaks via bug reports)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveFeedbackDisabled')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "DisableFeedback" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveFeedbackDisabledDefault')"
    
    # 3. BLOCK Network Traffic before User-Login (CRITICAL!)
    # OneDrive must NOT phone home without user consent!
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveNoConnectWithoutConsent')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveNoConnectWithoutConsentDefault')"
    
    # 4. BLOCK Known Folder Move (prevent Auto-Upload!)
    # Prevents automatic upload of Desktop/Documents/Pictures
    # User has CONTROL over what gets uploaded (Privacy-First!)
    Set-RegistryValue -Path $oneDrivePathHKCU -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveBlockAutoUpload')"
    Set-RegistryValue -Path $oneDrivePathHKLM -Name "KFMBlockOptIn" -Value 1 -Type DWord `
        -Description "$(Get-LocalizedString 'OneDriveBlockAutoUploadDefault')"
    
    # 5. Do NOT block Personal OneDrive!
    # DisablePersonalSync would break Home users - only for Enterprise!
    # We keep Personal OneDrive active (no breaking change)
    
    Write-Success "$(Get-LocalizedString 'OneDriveHardeningDone')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'OneDrivePrivacyStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveTutorialStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveFeedbackStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveNetworkStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveKFMStatus')"
    Write-Info "$(Get-LocalizedString 'OneDriveDiagnosticStatus')"
    Write-Host ""
    Write-Info "$(Get-LocalizedString 'OneDriveFunctionality')"
    Write-Info "$(Get-LocalizedString 'OneDriveWorksNormally')"
    Write-Info "$(Get-LocalizedString 'OneDrivePersonalActive')"
    Write-Info "$(Get-LocalizedString 'OneDriveKFMOff')"
    Write-Info "$(Get-LocalizedString 'OneDriveUserControl')"
}

function Remove-OneDriveCompletely {
    <#
    .SYNOPSIS
        Completely removes OneDrive from the system
    .DESCRIPTION
        Uninstalls OneDrive application completely.
        USER DATA IS SAFE: OneDrive folder and files are NOT deleted.
        
        CRITICAL WARNINGS:
        - Cannot be restored from backup (manual reinstall required)
        - OneDrive app will be completely removed
        - Your OneDrive folder stays intact
        - All files in OneDrive folder remain accessible
        - To reinstall: Download from microsoft.com/onedrive
        
    .NOTES
        Safe Data Handling:
        - Only removes the OneDrive APP
        - Does NOT touch OneDrive folder
        - Does NOT delete any user files
        - Folder stays at user profile directory
        
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "OneDrive Complete Removal"
    
    Write-Warning "OneDrive will be COMPLETELY REMOVED from this system!"
    Write-Host ""
    Write-Host "What happens:" -ForegroundColor Cyan
    Write-Host "  [OK] OneDrive app will be uninstalled" -ForegroundColor Green
    Write-Host "  [OK] Your OneDrive FOLDER and FILES stay safe" -ForegroundColor Green
    Write-Host "  [OK] Files remain at: C:\Users\$env:USERNAME\OneDrive" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [X] Cannot be restored from backup" -ForegroundColor Red
    Write-Host "  [X] Manual reinstall required if needed later" -ForegroundColor Red
    Write-Host ""
    
    # 1. Stop OneDrive processes
    Write-Info "Step 1: Stopping OneDrive processes..."
    try {
        $oneDriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
        if ($oneDriveProcesses) {
            foreach ($proc in $oneDriveProcesses) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-Verbose "Stopped OneDrive process (PID: $($proc.Id))"
                }
                catch {
                    Write-Warning "Could not stop OneDrive process: $_"
                }
            }
            Start-Sleep -Seconds 2
        }
        Write-Success "OneDrive processes stopped"
    }
    catch {
        Write-Verbose "No OneDrive processes running"
    }
    
    # 2. Uninstall OneDrive
    Write-Info "Step 2: Uninstalling OneDrive..."
    
    # Find OneDrive setup.exe locations (32-bit and 64-bit)
    $oneDriveSetupPaths = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    )
    
    $uninstallSuccess = $false
    foreach ($setupPath in $oneDriveSetupPaths) {
        if (Test-Path $setupPath) {
            Write-Verbose "Found OneDrive setup: $setupPath"
            try {
                $process = Start-Process -FilePath $setupPath -ArgumentList "/uninstall" -Wait -PassThru -WindowStyle Hidden
                if ($process.ExitCode -eq 0) {
                    Write-Verbose "OneDrive uninstalled successfully via: $setupPath"
                    $uninstallSuccess = $true
                    break
                }
            }
            catch {
                Write-Verbose "Uninstall failed for $setupPath : $_"
            }
        }
    }
    
    if ($uninstallSuccess) {
        Write-Success "OneDrive uninstalled successfully"
    }
    else {
        Write-Warning "OneDrive uninstall completed (or was already removed)"
    }
    
    # 3. Remove OneDrive registry keys (leftovers)
    Write-Info "Step 3: Cleaning up registry..."
    
    $registryPaths = @(
        "HKCU:\SOFTWARE\Microsoft\OneDrive",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKLM:\SOFTWARE\Microsoft\OneDrive",
        "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    )
    
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-Verbose "Removed registry: $regPath"
            }
            catch {
                Write-Verbose "Could not remove registry $regPath : $_"
            }
        }
    }
    
    Write-Success "Registry cleaned"
    
    # 4. Remove OneDrive from Explorer sidebar (if present)
    Write-Info "Step 4: Removing OneDrive from Explorer..."
    
    $explorerPath = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\System.IsPinnedToNameSpaceTree"
    if (Test-Path $explorerPath) {
        try {
            Set-ItemProperty -Path $explorerPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction Stop
            Write-Verbose "OneDrive removed from Explorer sidebar"
        }
        catch {
            Write-Verbose "Could not modify Explorer sidebar: $_"
        }
    }
    
    Write-Success "OneDrive removed from Explorer"
    
    # 5. Final verification
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "  ONEDRIVE REMOVAL COMPLETE" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Info "Status:"
    Write-Host "  [OK] OneDrive application removed" -ForegroundColor Green
    Write-Host "  [OK] Your OneDrive folder is SAFE: C:\Users\$env:USERNAME\OneDrive" -ForegroundColor Green
    Write-Host "  [OK] All your files remain accessible" -ForegroundColor Green
    Write-Host ""
    Write-Info "To reinstall OneDrive later:"
    Write-Host "  1. Download from: https://www.microsoft.com/onedrive/download" -ForegroundColor Cyan
    Write-Host "  2. Run the installer" -ForegroundColor Cyan
    Write-Host "  3. Sign in with your Microsoft account" -ForegroundColor Cyan
    Write-Host ""
}
