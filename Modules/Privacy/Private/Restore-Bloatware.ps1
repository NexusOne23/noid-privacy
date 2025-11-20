function Restore-Bloatware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    try {
        Write-Log -Level INFO -Message "Checking for removed apps to restore via winget..." -Module "Privacy"

        $restoreInfoPath = Join-Path $BackupPath "REMOVED_APPS_WINGET.json"
        if (-not (Test-Path $restoreInfoPath)) {
            Write-Log -Level INFO -Message "No removed apps restore info found at $restoreInfoPath - skipping app restore" -Module "Privacy"
            return $true
        }

        $restoreInfo = Get-Content $restoreInfoPath -Raw | ConvertFrom-Json
        $apps = @($restoreInfo.Apps)

        if (-not $apps -or $apps.Count -eq 0) {
            Write-Log -Level INFO -Message "Removed apps list is empty - nothing to restore" -Module "Privacy"
            return $true
        }

        $appsWithWinget = $apps | Where-Object { $_.WingetId -and $_.WingetId -ne "" }
        $appsWithoutWinget = $apps | Where-Object { -not $_.WingetId -or $_.WingetId -eq "" }

        if (-not $appsWithWinget -or $appsWithWinget.Count -eq 0) {
            Write-Log -Level INFO -Message "No apps with valid WingetId to restore - skipping winget restore" -Module "Privacy"
            return $true
        }

        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wingetCmd) {
            Write-Log -Level WARNING -Message "winget not found - cannot automatically restore removed apps" -Module "Privacy"
            return $true
        }

        Write-Host "" 
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  RESTORING REMOVED APPS VIA WINGET" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Apps scheduled for reinstall: $($appsWithWinget.Count)" -ForegroundColor Green
        Write-Host "" 

        if ($appsWithoutWinget -and $appsWithoutWinget.Count -gt 0) {
            Write-Host "  NOTE: $($appsWithoutWinget.Count) app(s) cannot be auto-restored (system components)" -ForegroundColor Yellow
            Write-Log -Level INFO -Message ("Apps without WingetId (manual reinstall required): " + ($appsWithoutWinget.AppName -join ", ")) -Module "Privacy"
        }

        $successCount = 0
        $failCount = 0

        foreach ($app in $appsWithWinget) {
            $id = $app.WingetId
            $name = $app.AppName

            Write-Host "  [>] Installing $name ($id)..." -ForegroundColor White

            try {
                # Note: Removed --source restriction to allow winget auto-detection (some apps not in msstore)
                $proc = Start-Process -FilePath "winget" -ArgumentList @("install", "--id", $id, "--accept-package-agreements", "--accept-source-agreements", "--silent") -Wait -NoNewWindow -PassThru -ErrorAction Stop

                if ($proc.ExitCode -eq 0) {
                    Write-Host "      [OK] $name" -ForegroundColor Green
                    Write-Log -Level SUCCESS -Message "Restored app via winget: $name ($id)" -Module "Privacy"
                    $successCount++
                }
                else {
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

        if ($failCount -gt 0) {
            return $false
        }

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore apps via winget: $_" -Module "Privacy"
        return $false
    }
}
