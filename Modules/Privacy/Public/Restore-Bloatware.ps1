function Restore-Bloatware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    try {
        # List of apps that CANNOT be restored via winget (no package available in catalog)
        # These will be removed during Apply, but user must reinstall manually from Microsoft Store
        $nonRestorableApps = @(
            [PSCustomObject]@{ AppName = "Microsoft.GetHelp"; DisplayName = "Get Help" }
            [PSCustomObject]@{ AppName = "Microsoft.MicrosoftSolitaireCollection"; DisplayName = "Microsoft Solitaire Collection" }
        )
        
        Write-Log -Level INFO -Message "Checking for removed apps to restore via winget..." -Module "Privacy"

        $restoreInfoPath = Join-Path $BackupPath "REMOVED_APPS_WINGET.json"
        if (-not (Test-Path $restoreInfoPath)) {
            Write-Log -Level INFO -Message "No removed apps restore info found at $restoreInfoPath - skipping app restore" -Module "Privacy"
            return [PSCustomObject]@{
                Success = $true
                NonRestorableApps = @()
            }
        }

        $restoreInfo = Get-Content $restoreInfoPath -Raw | ConvertFrom-Json
        $apps = @($restoreInfo.Apps)

        if (-not $apps -or $apps.Count -eq 0) {
            Write-Log -Level INFO -Message "Removed apps list is empty - nothing to restore" -Module "Privacy"
            return [PSCustomObject]@{
                Success = $true
                NonRestorableApps = @()
            }
        }

        # Filter out non-restorable apps before attempting restore
        $nonRestorableAppNames = $nonRestorableApps.AppName
        $skippedNonRestorableApps = @($apps | Where-Object { $nonRestorableAppNames -contains $_.AppName })
        $appsToRestore = @($apps | Where-Object { $nonRestorableAppNames -notcontains $_.AppName })
        
        $appsWithWinget = $appsToRestore | Where-Object { $_.WingetId -and $_.WingetId -ne "" }
        $appsWithoutWinget = $appsToRestore | Where-Object { -not $_.WingetId -or $_.WingetId -eq "" }

        if (-not $appsWithWinget -or $appsWithWinget.Count -eq 0) {
            Write-Log -Level INFO -Message "No apps with valid WingetId to restore - skipping winget restore" -Module "Privacy"
            
            # Map skipped apps to display names
            $skippedDisplayNames = @()
            foreach ($skipped in $skippedNonRestorableApps) {
                $displayName = ($nonRestorableApps | Where-Object { $_.AppName -eq $skipped.AppName }).DisplayName
                if ($displayName) { $skippedDisplayNames += $displayName }
            }
            
            return [PSCustomObject]@{
                Success = $true
                NonRestorableApps = $skippedDisplayNames
            }
        }

        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            Write-Log -Level WARNING -Message "winget not found - cannot automatically restore removed apps" -Module "Privacy"
            
            # Map skipped apps to display names
            $skippedDisplayNames = @()
            foreach ($skipped in $skippedNonRestorableApps) {
                $displayName = ($nonRestorableApps | Where-Object { $_.AppName -eq $skipped.AppName }).DisplayName
                if ($displayName) { $skippedDisplayNames += $displayName }
            }
            
            return [PSCustomObject]@{
                Success = $true
                NonRestorableApps = $skippedDisplayNames
            }
        }

        # Force reset winget sources to ensure msstore is available
        try {
            Write-Log -Level INFO -Message "Resetting winget sources to ensure msstore availability..." -Module "Privacy"
            Start-Process -FilePath "winget" -ArgumentList @("source", "reset", "--force") -Wait -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
        } catch {}

        Write-Host "" 
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  RESTORING REMOVED APPS VIA WINGET" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Apps scheduled for reinstall: $($appsWithWinget.Count)" -ForegroundColor Green
        Write-Host "" 

        # Filter out hidden Xbox system components from "manual reinstall" list
        # These are handled automatically by Gaming Services install
        $hiddenXboxApps = @(
            "Microsoft.Xbox.TCUI", 
            "Microsoft.XboxIdentityProvider", 
            "Microsoft.XboxSpeechToTextOverlay"
        )
        
        $appsManualReinstall = @($appsWithoutWinget | Where-Object { $hiddenXboxApps -notcontains $_.AppName })
        $appsHandledByGamingServices = @($appsWithoutWinget | Where-Object { $hiddenXboxApps -contains $_.AppName })

        if ($appsManualReinstall -and $appsManualReinstall.Count -gt 0) {
            Write-Host "  NOTE: $($appsManualReinstall.Count) app(s) cannot be auto-restored (system components)" -ForegroundColor Yellow
            Write-Log -Level INFO -Message ("Apps without WingetId (manual reinstall required): " + ($appsManualReinstall.AppName -join ", ")) -Module "Privacy"
        }
        
        if ($appsHandledByGamingServices.Count -gt 0) {
            Write-Log -Level INFO -Message "Hidden Xbox components will be restored via Gaming Services: $($appsHandledByGamingServices.AppName -join ", ")" -Module "Privacy"
        }

        $successCount = 0
        $failCount = 0
        
        # SPECIAL HANDLING: Xbox/Gaming apps require Gaming Services to be installed first
        # This prevents user prompts when opening Gaming App for the first time
        $gamingApps = @($appsWithWinget | Where-Object { $_.AppName -match "Xbox|Gaming" })
        if ($gamingApps.Count -gt 0) {
            Write-Host "  [>] Detected Xbox/Gaming apps - installing Gaming Services first..." -ForegroundColor Cyan
            Write-Log -Level INFO -Message "Installing Gaming Services (framework) to prevent user prompts" -Module "Privacy"
            
            try {
                # Gaming Services Store ID: 9MWPM2CQNLHN
                $proc = Start-Process -FilePath "winget" -ArgumentList @("install", "--id", "9MWPM2CQNLHN", "--accept-package-agreements", "--accept-source-agreements", "--silent") -Wait -NoNewWindow -PassThru -ErrorAction Stop
                
                # Check for Success (0) OR Already Installed (-1978335189 / 0x8A15002B)
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq -1978335189) {
                    if ($proc.ExitCode -eq -1978335189) {
                        Write-Host "      [OK] Gaming Services (already installed)" -ForegroundColor Green
                        Write-Log -Level SUCCESS -Message "Gaming Services already present - Xbox framework ready" -Module "Privacy"
                    } else {
                        Write-Host "      [OK] Gaming Services (includes Xbox.TCUI, XboxSpeechToTextOverlay)" -ForegroundColor Green
                        Write-Log -Level SUCCESS -Message "Gaming Services installed - Xbox framework components ready" -Module "Privacy"
                    }
                }
                else {
                    Write-Host "      [WARN] Gaming Services install had issues - Gaming apps may prompt on first launch" -ForegroundColor Yellow
                    Write-Log -Level WARNING -Message "Gaming Services install failed (ExitCode: $($proc.ExitCode)) - continuing anyway" -Module "Privacy"
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Could not install Gaming Services: $_" -Module "Privacy"
            }
            
            Write-Host ""
        }

        foreach ($app in $appsWithWinget) {
            $id = $app.WingetId
            $name = $app.AppName

            Write-Host "  [>] Installing $name ($id)..." -ForegroundColor White

            try {
                # STEP 1: Check if app exists in winget catalog first (avoid unnecessary install attempts)
                $searchStdout = Join-Path $env:TEMP "winget_search_$([guid]::NewGuid()).txt"
                $searchStderr = Join-Path $env:TEMP "winget_search_err_$([guid]::NewGuid()).txt"
                
                $searchProc = Start-Process -FilePath "winget" `
                    -ArgumentList @("search", "--id", $id, "--exact") `
                    -Wait -NoNewWindow -PassThru `
                    -RedirectStandardOutput $searchStdout `
                    -RedirectStandardError $searchStderr `
                    -ErrorAction Stop
                
                # Cleanup temp files
                Remove-Item $searchStdout, $searchStderr -Force -ErrorAction SilentlyContinue
                
                # ExitCode -1978335212 = No package found
                if ($searchProc.ExitCode -eq -1978335212 -or $searchProc.ExitCode -ne 0) {
                    Write-Host "      [SKIP] $name (not available in winget catalog)" -ForegroundColor DarkGray
                    Write-Log -Level INFO -Message "App not available in winget catalog: $name ($id) - skipping" -Module "Privacy"
                    $failCount++  # Count as "failed" for summary, but not a real error
                    continue
                }
                
                # STEP 2: App exists - proceed with installation
                $proc = Start-Process -FilePath "winget" -ArgumentList @("install", "--id", $id, "--exact", "--source", "msstore", "--accept-package-agreements", "--accept-source-agreements", "--silent") -Wait -NoNewWindow -PassThru -ErrorAction Stop

                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq -1978335189) {
                    if ($proc.ExitCode -eq -1978335189) {
                        Write-Host "      [OK] $name (already installed)" -ForegroundColor Green
                        Write-Log -Level SUCCESS -Message "App already installed (winget): $name ($id)" -Module "Privacy"
                    } else {
                        Write-Host "      [OK] $name" -ForegroundColor Green
                        Write-Log -Level SUCCESS -Message "Restored app via winget: $name ($id)" -Module "Privacy"
                    }
                    $successCount++
                }
                else {
                    # Installation failed despite app being available
                    Write-Host "      [FAIL] $name (ExitCode: $($proc.ExitCode))" -ForegroundColor Yellow
                    Write-Log -Level WARNING -Message "Failed to restore app via winget: $name ($id) ExitCode=$($proc.ExitCode)" -Module "Privacy"
                    $failCount++
                }
            }
            catch {
                Write-Host "      [FAIL] $name (exception)" -ForegroundColor Red
                Write-Log -Level WARNING -Message "Exception when restoring app via winget: $name ($id) - $_" -Module "Privacy"
                $failCount++
            }
        }

        Write-Host "" 
        Write-Host "  Winget restore summary: $successCount succeeded, $failCount failed" -ForegroundColor Cyan

        # Map skipped non-restorable apps to display names for user notification
        $skippedDisplayNames = @()
        foreach ($skipped in $skippedNonRestorableApps) {
            $displayName = ($nonRestorableApps | Where-Object { $_.AppName -eq $skipped.AppName }).DisplayName
            if ($displayName) { $skippedDisplayNames += $displayName }
        }

        if ($failCount -gt 0) {
            return [PSCustomObject]@{
                Success = $false
                NonRestorableApps = $skippedDisplayNames
            }
        }

        return [PSCustomObject]@{
            Success = $true
            NonRestorableApps = $skippedDisplayNames
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore apps via winget: $_" -Module "Privacy"
        return [PSCustomObject]@{
            Success = $false
            NonRestorableApps = @()
        }
    }
}
