<#
.SYNOPSIS
    Backup current ASR registry settings
    
.DESCRIPTION
    Creates backup of ASR registry keys before modification
    
.PARAMETER BackupId
    Identifier for this backup
    
.OUTPUTS
    PSCustomObject with backup info
#>

function Backup-ASRRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupId = "ASR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    $result = [PSCustomObject]@{
        Success    = $true
        BackupPath = $null
        Errors     = @()
    }
    
    try {
        $asrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
        
        # BACKUP 1: Registry (for reference/verify)
        # CRITICAL FIX: Call Backup-RegistryKey unconditionally!
        # If key exists: Creates .reg backup
        # If key missing: Creates _EMPTY.json marker (Required for proper cleanup during restore)
        try {
            $regBackup = Backup-RegistryKey -KeyPath $asrPath -BackupName "ASR_Config"
            
            if ($regBackup) {
                if ($regBackup -match "_EMPTY\.json$") {
                    Write-Log -Level INFO -Message "ASR registry key does not exist - Created Empty Marker for cleanup" -Module "ASR"
                }
                else {
                    Write-Log -Level INFO -Message "ASR registry backed up with ID: $BackupId" -Module "ASR"
                }
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Registry backup failed: $_" -Module "ASR"
            $result.Errors += "Registry backup failed: $_"
        }
        
        # BACKUP 2: Get-MpPreference (CRITICAL for restore)
        # Registry-only restore doesn't work after Clear-ASRRules
        # We MUST save the active Defender configuration
        # IMPORTANT: We backup even if 0 rules are active (pre-hardening state)
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            
            $asrBackupData = @{
                BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                BackupId = $BackupId
                Rules = @()
            }
            
            # If rules exist, save them
            if ($mpPref.AttackSurfaceReductionRules_Ids -and $mpPref.AttackSurfaceReductionRules_Ids.Count -gt 0) {
                # Pair IDs with Actions
                for ($i = 0; $i -lt $mpPref.AttackSurfaceReductionRules_Ids.Count; $i++) {
                    $asrBackupData.Rules += @{
                        GUID = $mpPref.AttackSurfaceReductionRules_Ids[$i]
                        Action = $mpPref.AttackSurfaceReductionRules_Actions[$i]
                    }
                }
                Write-Log -Level INFO -Message "Backing up $($asrBackupData.Rules.Count) active ASR rules from Get-MpPreference" -Module "ASR"
            }
            else {
                Write-Log -Level INFO -Message "No active ASR rules in Get-MpPreference - backing up empty state (pre-hardening)" -Module "ASR"
            }
            
            # ALWAYS create the JSON file, even if Rules array is empty
            # This is critical for restore to know "system had 0 rules before hardening"
            $asrJson = $asrBackupData | ConvertTo-Json -Depth 5
            $backupFile = Register-Backup -Type "ASR" -Data $asrJson -Name "ASR_ActiveConfiguration"
            
            if ($backupFile) {
                Write-Log -Level SUCCESS -Message "ASR MpPreference configuration backed up ($($asrBackupData.Rules.Count) rules)" -Module "ASR"
            }
            else {
                Write-Log -Level WARNING -Message "Failed to register ASR MpPreference backup" -Module "ASR"
                $result.Errors += "MpPreference backup registration failed"
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Get-MpPreference backup failed: $_" -Module "ASR"
            $result.Errors += "MpPreference backup failed: $_"
        }
    }
    catch {
        $result.Success = $false
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "ASR backup failed: $($_.Exception.Message)" -Module "ASR"
    }
    
    return $result
}
