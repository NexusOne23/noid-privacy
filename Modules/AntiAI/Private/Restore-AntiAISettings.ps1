#Requires -Version 5.1

<#
.SYNOPSIS
    Restores all AntiAI settings to pre-hardening state.

.DESCRIPTION
    Restores registry settings from backup created by Backup-AntiAISettings.
    Performs 1:1 restoration of all modified registry keys.
    
    Restoration includes:
    - Generative AI settings (AppPrivacy)
    - All Recall settings (WindowsAI)
    - Copilot settings (WindowsCopilot, WindowsAI)
    - Click to Do, Settings Agent (WindowsAI)
    - Paint AI settings (Paint Policies)
    - Notepad AI settings (WindowsNotepad)
    
    WARNING: Recall component restoration requires reboot!

.PARAMETER BackupPath
    Directory path where backup files are stored.

.EXAMPLE
    Restore-AntiAISettings -BackupPath "C:\Backups\AntiAI"
#>
function Restore-AntiAISettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    Write-Log -Level DEBUG -Message "Starting AntiAI settings restore from: $BackupPath" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $true
        Restored = 0
        Errors = @()
        RequiresReboot = $false
    }
    
    try {
        # Verify backup directory exists
        if (-not (Test-Path $BackupPath)) {
            throw "Backup directory not found: $BackupPath"
        }
        
        # Load backup metadata
        $metadataFile = Join-Path $BackupPath "AntiAI_Backup_Metadata.json"
        if (-not (Test-Path $metadataFile)) {
            throw "Backup metadata not found: $metadataFile"
        }
        
        $metadata = Get-Content $metadataFile -Raw | ConvertFrom-Json
        Write-Log -Level DEBUG -Message "Backup created: $($metadata.Timestamp) on $($metadata.ComputerName)" -Module "AntiAI"
        
        # Restore each registry backup file
        foreach ($backupFile in $metadata.BackupFiles) {
            if (Test-Path $backupFile) {
                try {
                    Write-Log -Level DEBUG -Message "Restoring: $(Split-Path $backupFile -Leaf)" -Module "AntiAI"
                    
                    # Import registry file
                    $process = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$backupFile`"" -Wait -PassThru -NoNewWindow
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log -Level DEBUG -Message "Successfully restored: $backupFile" -Module "AntiAI"
                        $result.Restored++
                        
                        # Check if Recall settings were restored (requires reboot)
                        if ($backupFile -like "*WindowsAI*") {
                            $result.RequiresReboot = $true
                        }
                    }
                    else {
                        Write-Warning "Failed to restore $backupFile (exit code: $($process.ExitCode))"
                        $result.Errors += "Restore failed for $(Split-Path $backupFile -Leaf)"
                    }
                }
                catch {
                    Write-Warning "Error restoring $backupFile : $($_.Exception.Message)"
                    $result.Errors += "Error: $(Split-Path $backupFile -Leaf) - $($_.Exception.Message)"
                }
            }
            else {
                Write-Warning "Backup file not found: $backupFile"
                $result.Errors += "Backup file missing: $(Split-Path $backupFile -Leaf)"
            }
        }
        
        $result.Success = ($result.Errors.Count -eq 0)
        
        if ($result.Success) {
            Write-Log -Level DEBUG -Message "Restore completed successfully. Files restored: $($result.Restored)" -Module "AntiAI"
            
            if ($result.RequiresReboot) {
                Write-Warning "REBOOT REQUIRED to fully restore Recall component!"
            }
        }
        else {
            Write-Warning "Restore completed with errors: $($result.Errors.Count) error(s)"
        }
    }
    catch {
        $result.Success = $false
        $result.Errors += "Restore failed: $($_.Exception.Message)"
        Write-Error "AntiAI restore failed: $($_.Exception.Message)"
    }
    
    return $result
}
