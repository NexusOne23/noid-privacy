function Restore-PrivacySettings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$BackupPath)
    
    try {
        Write-Log -Level INFO -Message "Restoring privacy settings from backup..." -Module "Privacy"
        
        $metadataFile = Join-Path $BackupPath "BackupMetadata.json"
        if (!(Test-Path $metadataFile)) {
            Write-Log -Level ERROR -Message "Backup metadata not found: $metadataFile" -Module "Privacy"
            return $false
        }
        
        $metadata = Get-Content $metadataFile -Raw | ConvertFrom-Json
        
        # Restore registry
        foreach ($regBackup in $metadata.RegistryKeys) {
            if ($regBackup.Existed -and (Test-Path $regBackup.File)) {
                $result = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$($regBackup.File)`"" -Wait -NoNewWindow -PassThru
                if ($result.ExitCode -eq 0) {
                    Write-Log -Level SUCCESS -Message "Restored: $($regBackup.Key)" -Module "Privacy"
                }
            } else {
                if (Test-Path $regBackup.Key) {
                    Remove-Item -Path $regBackup.Key -Recurse -Force
                    Write-Log -Level SUCCESS -Message "Removed (did not exist before): $($regBackup.Key)" -Module "Privacy"
                }
            }
        }
        
        # Restore services
        foreach ($svc in $metadata.Services) {
            Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction SilentlyContinue
            Write-Log -Level SUCCESS -Message "Restored service: $($svc.Name) to $($svc.StartType)" -Module "Privacy"
        }
        
        # Restore tasks
        foreach ($task in $metadata.ScheduledTasks) {
            if ($task.Enabled) {
                Enable-ScheduledTask -TaskPath (Split-Path $task.TaskPath -Parent) -TaskName (Split-Path $task.TaskPath -Leaf) -ErrorAction SilentlyContinue
                Write-Log -Level SUCCESS -Message "Restored task: $($task.TaskPath)" -Module "Privacy"
            }
        }
        
        Write-Log -Level SUCCESS -Message "Privacy settings restored successfully" -Module "Privacy"
        Write-Log -Level WARNING -Message "Note: Removed apps may be auto-restored via winget during session restore where mappings exist; some apps may still require manual reinstall from Microsoft Store." -Module "Privacy"
        
        # Check for removed apps list and inform user
        $removedAppsListPath = Join-Path $BackupPath "REMOVED_APPS_LIST.txt"
        if (Test-Path $removedAppsListPath) {
            Write-Host "`n============================================" -ForegroundColor Yellow
            Write-Host "  BLOATWARE APPS - RESTORE INFORMATION" -ForegroundColor Yellow
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  During hardening, some apps were removed." -ForegroundColor White
            Write-Host "  Where possible, these apps will be reinstalled automatically" -ForegroundColor White
            Write-Host "  during a session restore via winget (for mapped apps)." -ForegroundColor White
            Write-Host ""
            Write-Host "  A list of all removed apps has been saved:" -ForegroundColor Cyan
            Write-Host "    $removedAppsListPath" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  If some apps are still missing after restore, you can reinstall" -ForegroundColor White
            Write-Host "  them manually from Microsoft Store using this list:" -ForegroundColor White
            Write-Host "    1. Open the file above to see which apps were removed" -ForegroundColor Gray
            Write-Host "    2. Open Microsoft Store" -ForegroundColor Gray
            Write-Host "    3. Search and reinstall desired apps manually" -ForegroundColor Gray
            Write-Host ""
            Write-Log -Level INFO -Message "User informed about removed apps list: $removedAppsListPath" -Module "Privacy"
        }
        
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to restore: $_" -Module "Privacy"
        return $false
    }
}
