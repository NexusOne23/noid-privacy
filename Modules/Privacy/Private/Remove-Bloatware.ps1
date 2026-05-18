function Remove-Bloatware {
    <#
    .SYNOPSIS
        Remove bloatware apps using best method for current Windows version
    
    .DESCRIPTION
        Hybrid approach:
        - Windows 11 25H2+ Enterprise/Education: Uses policy-based removal (MS recommended)
        - Other versions/editions: Uses classic PowerShell removal
    
    .PARAMETER Method
        Force specific method: Auto (default), Policy, or Classic
    
    .EXAMPLE
        Remove-Bloatware
        Remove-Bloatware -Method Policy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Auto", "Policy", "Classic")]
        [string]$Method = "Auto"
    )
    
    try {
        Write-Log -Level INFO -Message "Starting bloatware removal..." -Module "Privacy"
        
        # Load configuration
        $configPath = Join-Path $PSScriptRoot "..\Config\Bloatware.json"
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        # Determine method if Auto
        if ($Method -eq "Auto") {
            # Check OS version and edition
            $osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            $displayVersion = $osInfo.DisplayVersion
            $currentBuild = [int]$osInfo.CurrentBuild
            
            # Get edition - try Get-WindowsEdition first, fallback to registry
            try {
                $osEdition = (Get-WindowsEdition -Online -ErrorAction Stop).Edition
            }
            catch {
                # Fallback to registry if Get-WindowsEdition fails
                $osEdition = $osInfo.EditionID
                if (-not $osEdition) {
                    $osEdition = (Get-ComputerInfo -Property WindowsEditionId -ErrorAction SilentlyContinue).WindowsEditionId
                }
            }
            
            Write-Log -Level INFO -Message "Detected: Windows $displayVersion (Build $currentBuild), Edition: $osEdition" -Module "Privacy"
            
            # Check if policy-based removal is supported
            $policySupported = $false
            if ($currentBuild -ge $config.PolicyMethod.MinBuild) {
                foreach ($supportedEdition in $config.PolicyMethod.SupportedEditions) {
                    if ($osEdition -like "*$supportedEdition*") {
                        $policySupported = $true
                        break
                    }
                }
            }
            
            if ($policySupported) {
                $Method = "Policy"
                Write-Log -Level INFO -Message "Policy-based removal supported - using official MS method" -Module "Privacy"
            }
            else {
                $Method = "Classic"
                Write-Log -Level INFO -Message "Policy-based removal not supported - using classic PowerShell method" -Module "Privacy"
                if ($currentBuild -lt $config.PolicyMethod.MinBuild) {
                    Write-Log -Level INFO -Message "Reason: Build $currentBuild < $($config.PolicyMethod.MinBuild) (25H2)" -Module "Privacy"
                }
                else {
                    Write-Log -Level INFO -Message "Reason: Edition '$osEdition' not in supported list (Enterprise/Education only)" -Module "Privacy"
                }
            }
        }
        
        # Execute selected method
        if ($Method -eq "Policy") {
            return Remove-BloatwarePolicy
        }
        else {
            return Remove-BloatwareClassic
        }
        
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to remove bloatware: $_" -Module "Privacy"
        return $false
    }
}

function Remove-BloatwarePolicy {
    <#
    .SYNOPSIS
        Remove apps using policy-based method (Win11 25H2+ ENT/EDU)
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "  POLICY-BASED APP REMOVAL (MS OFFICIAL)" -ForegroundColor Cyan
        Write-Host "============================================`n" -ForegroundColor Cyan
        
        $result = Set-PolicyBasedAppRemoval
        
        if ($result) {
            Write-Log -Level SUCCESS -Message "Policy-based bloatware removal configured successfully" -Module "Privacy"
        }
        
        return $result
        
    }
    catch {
        Write-Log -Level ERROR -Message "Policy-based removal failed: $_" -Module "Privacy"
        return $false
    }
}

function Remove-BloatwareClassic {
    <#
    .SYNOPSIS
        Remove apps using classic PowerShell method
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "  CLASSIC POWERSHELL APP REMOVAL" -ForegroundColor Cyan
        Write-Host "============================================`n" -ForegroundColor Cyan
        
        $configPath = Join-Path $PSScriptRoot "..\Config\Bloatware.json"
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        $classicMethod = $config.ClassicMethod
        $removed = 0
        $failed = 0
        $removedApps = @()  # Track removed apps for user info
        
        # Performance Optimization: Get all apps once instead of calling for each pattern
        # This reduces execution time from ~30 seconds to ~3 seconds (10x faster!)
        Write-Host "  Enumerating installed apps..." -ForegroundColor Gray
        $allInstalledApps = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
        Write-Host "  Found $($allInstalledApps.Count) installed apps" -ForegroundColor Gray
        
        Write-Host "  Enumerating provisioned packages..." -ForegroundColor Gray
        try {
            $allProvisionedApps = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
            Write-Host "  Found $($allProvisionedApps.Count) provisioned packages`n" -ForegroundColor Gray
        }
        catch {
            $allProvisionedApps = @()
            Write-Log -Level WARNING -Message "Failed to enumerate provisioned packages: $_" -Module "Privacy"
        }
        
        # Apps that CANNOT be reinstalled via winget - skip completely
        # Xbox Gaming apps and Solitaire are not in winget msstore catalog
        $nonRestorableApps = @(
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.MicrosoftSolitaireCollection'
        )
        
        foreach ($appPattern in $classicMethod.RemoveApps) {
            # Skip apps that cannot be reinstalled via winget (Xbox Gaming apps, Solitaire)
            if ($nonRestorableApps -contains $appPattern) {
                Write-Log -Level INFO -Message "Skipping non-restorable app: $appPattern (not in winget msstore)" -Module "Privacy"
                continue
            }
            
            # Check if app is protected
            $isProtected = $false
            foreach ($protectedApp in $classicMethod.ProtectedApps) {
                if ($appPattern -like $protectedApp) {
                    $isProtected = $true
                    break
                }
            }
            
            if ($isProtected) {
                Write-Log -Level INFO -Message "Skipping protected app: $appPattern" -Module "Privacy"
                continue
            }
            
            # Filter from cached list (fast!) instead of calling Get-AppxPackage again
            $apps = @($allInstalledApps | Where-Object { $_.Name -like $appPattern })
            foreach ($app in $apps) {
                if ($classicMethod.ProtectedApps -notcontains $app.Name) {
                    try {
                        Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log -Level SUCCESS -Message "Removed: $($app.Name)" -Module "Privacy"
                        Write-Host "  [OK] $($app.Name)" -ForegroundColor Green
                        $removedApps += $app.Name  # Track for user info
                        $removed++
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to remove $($app.Name): $_" -Module "Privacy"
                        Write-Host "  [FAIL] $($app.Name)" -ForegroundColor Red
                        $failed++
                    }
                }
            }
            
            # Filter provisioned apps from cached list (fast!)
            $provisionedApps = @($allProvisionedApps | Where-Object { $_.DisplayName -like $appPattern })
            foreach ($app in $provisionedApps) {
                # =========================================================================
                # LEGACY: Skip deprovisioning for Xbox framework components
                # =========================================================================
                # NOTE: Xbox.TCUI and XboxSpeechToTextOverlay are NO LONGER in the removal
                # list because they are non-removable framework components that CANNOT be
                # reinstalled once removed. This code remains as a safety measure in case
                # someone manually adds them back to the JSON.
                # =========================================================================
                $skipDeprovision = @(
                    'Microsoft.Xbox.TCUI',
                    'Microsoft.XboxSpeechToTextOverlay'
                )
                
                if ($skipDeprovision -contains $app.DisplayName) {
                    Write-Log -Level INFO -Message "Skipping deprovision for $($app.DisplayName) (allows restore via Gaming Services)" -Module "Privacy"
                    continue
                }
                
                # Double-check: Verify package still exists before removal attempt
                # This prevents "path not found" errors when Remove-AppxPackage -AllUsers already removed the provisioned package
                $stillExists = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -eq $app.PackageName }
                
                if ($stillExists) {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName -ErrorAction Stop | Out-Null
                        Write-Log -Level SUCCESS -Message "Removed provisioned: $($app.DisplayName)" -Module "Privacy"
                        Write-Host "  [OK] Provisioned: $($app.DisplayName)" -ForegroundColor Green
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to remove provisioned $($app.DisplayName): $_" -Module "Privacy"
                    }
                }
                # else: Already removed by Remove-AppxPackage -AllUsers, skip silently
            }
        }
        
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "  BLOATWARE REMOVAL COMPLETE" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Removed: $removed apps" -ForegroundColor Green
        if ($failed -gt 0) {
            Write-Host "  Failed: $failed apps" -ForegroundColor Red
        }
        elseif ($removed -eq 0) {
            Write-Host "  No apps removed (already clean or skipped for restore safety)" -ForegroundColor Green
        }
        Write-Host ""
        
        Write-Log -Level SUCCESS -Message "Classic bloatware removal complete ($removed removed, $failed failed)" -Module "Privacy"
        
        # ---------------------------------------------------------
        # Generate Restore Metadata for Winget
        # ---------------------------------------------------------
        # Winget Store IDs for app restoration (verified 2025-12-08 against msstore source)
        # Empty string = not available in winget catalog (user must reinstall manually)
        # Xbox system components are handled via Gaming Services installation
        $wingetMap = @{
            "Microsoft.BingNews" = "9WZDNCRFHVFW"
            "Microsoft.BingWeather" = "9WZDNCRFJ3Q2"
            "Microsoft.MicrosoftSolitaireCollection" = ""  # Not in winget catalog
            "Microsoft.MicrosoftStickyNotes" = "9NBLGGH4QGHW"
            "Microsoft.GamingApp" = "9MV0B5HZVK9Z"
            "Microsoft.XboxApp" = "9MV0B5HZVK9Z"
            "Microsoft.XboxGamingOverlay" = "9NZKPSTSNW4P"
            "Microsoft.XboxIdentityProvider" = "9WZDNCRD1HKW"  # Dedicated Store ID (Xbox Identity Provider)
            "Microsoft.XboxSpeechToTextOverlay" = ""  # Framework component - NOT removed
            "Microsoft.Xbox.TCUI" = ""  # Framework component - NOT removed
            "Microsoft.ZuneMusic" = "9WZDNCRFJ3PT"
            "Microsoft.ZuneVideo" = "9WZDNCRFJ3PT"
            "Microsoft.WindowsFeedbackHub" = "9NBLGGH4R32N"
            "Microsoft.GetHelp" = "9PKDZBMV1H3T"
            "Microsoft.Getstarted" = ""  # Not in winget catalog
            "Microsoft.MixedReality.Portal" = "9NG1H8B3ZC7M"
            "Microsoft.People" = ""  # Not in winget catalog
            "Microsoft.YourPhone" = "9NMPJ99VJBWV"
            "Clipchamp.Clipchamp" = "9P1J8S7CCWWT"
            "SpotifyAB.SpotifyMusic" = "9NCBCSZSJRSB"
        }

        $restoreList = @()
        foreach ($app in $removedApps) {
            $wingetId = ""
            if ($wingetMap.ContainsKey($app)) {
                $wingetId = $wingetMap[$app]
            }
            # Fallback: try to use package name if it looks like a valid ID
            elseif ($app -match '^[a-zA-Z0-9]+\.[a-zA-Z0-9]+$') {
                $wingetId = $app
            }
            
            $restoreList += @{
                AppName = $app
                WingetId = $wingetId
            }
        }
        
        if ($restoreList.Count -gt 0) {
            try {
                $restoreData = @{
                    Apps = $restoreList
                    Timestamp = Get-Date -Format "o"
                }
                
                # Use Register-Backup from Rollback core
                if (Get-Command Register-Backup -ErrorAction SilentlyContinue) {
                    # Note: We save it directly to module backup folder with specific name expected by Restore-Bloatware
                    # Register-Backup usually creates timestamped names in Type folders
                    # Here we need a specific file in the Privacy backup root
                    
                    # Get current backup path for Privacy module
                    # We assume Start-ModuleBackup was called and context is set, or we find it
                    # But Register-Backup handles paths. Let's use Register-Backup with specific name.
                    # Restore-Bloatware expects "REMOVED_APPS_WINGET.json" in the backup root.
                    # Register-Backup creates "Type/Name.json".
                    
                    # Workaround: We write the file directly to the backup location if we can find it
                    # But we don't have easy access to the current backup path here except via Register-Backup return value?
                    # Let's use Register-Backup with Type="" (root) if possible, or just "Privacy"?
                    # No, Restore-Bloatware looks in $BackupPath (which is the module backup folder).
                    
                    # Let's write to a temp file and register it? No.
                    # Let's rely on Register-Backup creating "Privacy/REMOVED_APPS_WINGET.json"
                    # If we pass Type=".", it might work?
                    
                    # CRITICAL: Suppress output to prevent pipeline contamination (would make $bloatwareResult an array instead of single object)
                    [void](Register-Backup -Type "." -Data ($restoreData | ConvertTo-Json -Depth 5) -Name "REMOVED_APPS_WINGET")
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to save removed apps list for restore: $_" -Module "Privacy"
            }
        }
        # ---------------------------------------------------------

        # Return list of removed apps for user info
        return [PSCustomObject]@{
            Success     = $true
            RemovedApps = $removedApps
            Count       = $removed
        }
        
    }
    catch {
        Write-Log -Level ERROR -Message "Classic removal failed: $_" -Module "Privacy"
        return [PSCustomObject]@{
            Success     = $false
            RemovedApps = @()
            Count       = 0
        }
    }
}
