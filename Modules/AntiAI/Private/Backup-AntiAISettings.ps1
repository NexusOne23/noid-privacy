#Requires -Version 5.1

<#
.SYNOPSIS
    [DEPRECATED] Backs up all AntiAI registry settings before modification.

.DESCRIPTION
    DEPRECATED: This function is no longer used. Backup is now handled by the central
    Session-based backup system in Core/Rollback.ps1.
    
    Previous functionality: Created comprehensive backup of all registry keys that will be modified by AntiAI module.
    Backup includes:
    - Generative AI settings (AppPrivacy)
    - All Recall settings (WindowsAI)
    - Copilot settings (WindowsCopilot, WindowsAI)
    - Click to Do, Settings Agent (WindowsAI)
    - Paint AI settings (Paint Policies)
    - Notepad AI settings (WindowsNotepad)

.PARAMETER BackupPath
    Directory path where backup files will be stored.

.EXAMPLE
    Backup-AntiAISettings -BackupPath "C:\Backups\AntiAI"
#>
function Backup-AntiAISettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    Write-Log -Level DEBUG -Message "Starting AntiAI settings backup to: $BackupPath" -Module "AntiAI"
    
    $result = @{
        Success = $true
        BackupFiles = @()
        Errors = @()
    }
    
    try {
        # Ensure backup directory exists
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }
        
        # Define registry paths to backup
        $registryPaths = @(
            @{
                Name = "AppPrivacy_GenerativeAI"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
            },
            @{
                Name = "CapabilityAccessManager_SystemAIModels"
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels"
            },
            @{
                Name = "WindowsAI_Device"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
            },
            @{
                Name = "WindowsAI_User"
                Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
            },
            @{
                Name = "WindowsCopilot_Device"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
            },
            @{
                Name = "WindowsCopilot_User"
                Path = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
            },
            @{
                Name = "Explorer_Copilot"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
            },
            @{
                Name = "Paint_Policies"
                Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint"
            },
            @{
                Name = "Notepad_Policies"
                Path = "HKLM:\SOFTWARE\Policies\WindowsNotepad"
            }
        )
        
        # Backup each registry path
        foreach ($regPath in $registryPaths) {
            $backupFile = Join-Path $BackupPath "$($regPath.Name)_PreAntiAI.reg"
            
            if (Test-Path $regPath.Path) {
                try {
                    # Export registry key
                    $regExportPath = $regPath.Path -replace 'HKLM:', 'HKEY_LOCAL_MACHINE' -replace 'HKCU:', 'HKEY_CURRENT_USER'
                    $process = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regExportPath`" `"$backupFile`" /y" -Wait -PassThru -NoNewWindow
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log -Level DEBUG -Message "Backed up: $($regPath.Name)" -Module "AntiAI"
                        $result.BackupFiles += $backupFile
                    }
                    else {
                        Write-Log -Level DEBUG -Message "Registry key does not exist or is empty: $($regPath.Name)" -Module "AntiAI"
                    }
                }
                catch {
                    Write-Warning "Failed to backup $($regPath.Name): $($_.Exception.Message)"
                    $result.Errors += "Backup failed for $($regPath.Name): $($_.Exception.Message)"
                }
            }
            else {
                Write-Log -Level DEBUG -Message "Registry path does not exist (will be created): $($regPath.Path)" -Module "AntiAI"
            }
        }
        
        # Create backup metadata
        $metadata = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            OSVersion = [System.Environment]::OSVersion.Version.ToString()
            BackupFiles = $result.BackupFiles
            ModuleVersion = "2.1.0"
        }
        
        $metadataFile = Join-Path $BackupPath "AntiAI_Backup_Metadata.json"
        $metadata | ConvertTo-Json -Depth 10 | Set-Content -Path $metadataFile -Encoding UTF8 | Out-Null
        Write-Log -Level DEBUG -Message "Created backup metadata: $metadataFile" -Module "AntiAI"
        
        $result.Success = ($result.Errors.Count -eq 0)
        Write-Log -Level DEBUG -Message "Backup completed. Files backed up: $($result.BackupFiles.Count)" -Module "AntiAI"
    }
    catch {
        $result.Success = $false
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Error "AntiAI backup failed: $($_.Exception.Message)"
    }
    
    return $result
}
