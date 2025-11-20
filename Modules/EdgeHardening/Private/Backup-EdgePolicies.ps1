<#
.SYNOPSIS
    Backup current Microsoft Edge policy settings
    
.DESCRIPTION
    Creates backup of existing Edge policy registry keys before applying baseline.
    Integrates with Core Rollback system (Backup-RegistryKey).
    
.PARAMETER BackupName
    Name for this backup (default: auto-generated timestamp)
    
.OUTPUTS
    PSCustomObject with backup status and path
    
.NOTES
    Backs up: HKLM:\Software\Policies\Microsoft\Edge (entire subtree)
#>

function Backup-EdgePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    $result = [PSCustomObject]@{
        Success      = $false
        BackupPath   = $null
        KeysBackedUp = 0
        Errors       = @()
    }
    
    try {
        Write-Log -Level DEBUG -Message "Backing up Edge policy settings..." -Module "EdgeHardening"
        
        # Edge policy root path
        $edgePolicyPath = "HKLM:\Software\Policies\Microsoft\Edge"
        
        # Check if Backup-RegistryKey is available (from Core/Rollback.ps1)
        if (-not (Get-Command Backup-RegistryKey -ErrorAction SilentlyContinue)) {
            Write-Warning "Backup-RegistryKey not available - using standalone backup"
            
            # Fallback: Export to .reg file
            if (-not $BackupName) {
                $BackupName = "EdgePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            }
            
            $backupFolder = Join-Path $env:TEMP "NoIDPrivacy_Backups"
            if (-not (Test-Path $backupFolder)) {
                New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
            }
            
            $backupFile = Join-Path $backupFolder "$BackupName.reg"
            
            if (Test-Path $edgePolicyPath) {
                # Export using reg.exe (built-in)
                $regPath = "HKLM\Software\Policies\Microsoft\Edge"
                $process = Start-Process -FilePath "reg.exe" `
                    -ArgumentList "export `"$regPath`" `"$backupFile`" /y" `
                    -Wait `
                    -NoNewWindow `
                    -PassThru
                
                if ($process.ExitCode -eq 0) {
                    $result.Success = $true
                    $result.BackupPath = $backupFile
                    $result.KeysBackedUp = 1
                    Write-Log -Level DEBUG -Message "Standalone backup created: $backupFile" -Module "EdgeHardening"
                }
                else {
                    $result.Errors += "reg.exe export failed with exit code: $($process.ExitCode)"
                }
            }
            else {
                # No existing Edge policies - nothing to backup
                $result.Success = $true
                $result.KeysBackedUp = 0
                Write-Log -Level DEBUG -Message "No existing Edge policies to backup" -Module "EdgeHardening"
            }
        }
        else {
            # Use Core Rollback system
            if (Test-Path $edgePolicyPath) {
                # IMPORTANT: Backup-RegistryKey returns a STRING (backup file path) on success, or $null on failure/not-found
                $backupResult = Backup-RegistryKey -KeyPath $edgePolicyPath -BackupName "EdgeHardening"
                
                # Check return value: String = success, $null = nothing to backup (normal)
                if ($backupResult) {
                    # Success: Backup-RegistryKey returned a file path (string)
                    $result.Success = $true
                    $result.BackupPath = $backupResult  # $backupResult is the file path string
                    $result.KeysBackedUp = 1
                    Write-Log -Level DEBUG -Message "Edge policies backed up via Core Rollback system: $backupResult" -Module "EdgeHardening"
                }
                else {
                    # $backupResult is $null - key doesn't exist yet (normal on fresh systems)
                    # This is NOT an error - it means "nothing to backup"
                    $result.Success = $true
                    $result.KeysBackedUp = 0
                    Write-Log -Level DEBUG -Message "Edge policies: nothing to backup (key doesn't exist yet)" -Module "EdgeHardening"
                }
            }
            else {
                # No existing Edge policies - nothing to backup
                $result.Success = $true
                $result.KeysBackedUp = 0
                Write-Log -Level DEBUG -Message "No existing Edge policies to backup" -Module "EdgeHardening"
            }
        }
        
    }
    catch {
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Backup failed: $_" -Module "EdgeHardening"
    }
    
    return $result
}
