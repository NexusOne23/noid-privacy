<#
.SYNOPSIS
    Restore Security Baseline settings from backup
    
.DESCRIPTION
    Restores all Security Baseline settings from a previous backup.
    Restores:
    - Registry Policies (Computer + User)
    - Security Template Settings
    - Audit Policies
    
.PARAMETER BackupFolder
    Path to backup folder created by Invoke-SecurityBaseline
    If not specified, uses most recent backup from TEMP
    
.EXAMPLE
    Restore-SecurityBaseline
    Restore from most recent backup
    
.EXAMPLE
    Restore-SecurityBaseline -BackupFolder "C:\Temp\SecurityBaseline_Backup_20250116_075000"
    Restore from specific backup
    
.OUTPUTS
    PSCustomObject with restore status
    
.NOTES
    Requires Administrator privileges
#>

function Restore-SecurityBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupFolder
    )
    
    begin {
        $moduleName = "SecurityBaseline"
        $startTime = Get-Date
        
        # Helper function for logging
        function Write-ModuleLog {
            param([string]$Level, [string]$Message, [string]$Module = "SecurityBaseline")
            
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level $Level -Message $Message -Module $Module
            }
            else {
                switch ($Level) {
                    "ERROR"   { Write-Host "ERROR: $Message" -ForegroundColor Red }
                    "WARNING" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
                    default   { Write-Log -Level DEBUG -Message $Message }
                }
            }
        }
        
        $result = [PSCustomObject]@{
            ModuleName = $moduleName
            Success = $false
            ItemsRestored = 0
            Errors = @()
            Duration = $null
        }
        
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "SECURITY BASELINE RESTORE" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
    }
    
    process {
        try {
            # Find backup folder if not specified
            if (-not $BackupFolder) {
                Write-ModuleLog -Level INFO -Message "Searching for most recent backup..." -Module $moduleName
                
                $backups = Get-ChildItem -Path $env:TEMP -Filter "SecurityBaseline_Backup_*" -Directory |
                           Sort-Object LastWriteTime -Descending
                
                if ($backups.Count -eq 0) {
                    throw "No backups found in $env:TEMP"
                }
                
                $BackupFolder = $backups[0].FullName
                Write-ModuleLog -Level INFO -Message "Using backup: $BackupFolder" -Module $moduleName
            }
            
            if (-not (Test-Path $BackupFolder)) {
                throw "Backup folder not found: $BackupFolder"
            }
            
            # Load backup info
            $backupInfoPath = Join-Path $BackupFolder "BackupInfo.json"
            if (Test-Path $backupInfoPath) {
                $backupInfo = Get-Content $backupInfoPath -Raw | ConvertFrom-Json
                Write-ModuleLog -Level INFO -Message "Backup created: $($backupInfo.Timestamp)" -Module $moduleName
            }
            
            # Restore 1: Registry Policies
            $regBackupPath = Join-Path $BackupFolder "RegistryPolicies.json"
            if (Test-Path $regBackupPath) {
                Write-ModuleLog -Level INFO -Message "Restoring registry policies..." -Module $moduleName
                $regRestore = Restore-RegistryPolicies -BackupPath $regBackupPath
                
                if ($regRestore.Success) {
                    $result.ItemsRestored += $regRestore.ItemsRestored
                    Write-ModuleLog -Level SUCCESS -Message "Registry: $($regRestore.ItemsRestored) items restored" -Module $moduleName
                }
                else {
                    $result.Errors += $regRestore.Errors
                }
            }
            
            # Restore 2: Security Template
            $secBackupPath = Join-Path $BackupFolder "SecurityTemplate.inf"
            if (Test-Path $secBackupPath) {
                Write-ModuleLog -Level INFO -Message "Restoring security template..." -Module $moduleName
                $secRestore = Restore-SecurityTemplate -BackupPath $secBackupPath
                
                if ($secRestore.Success) {
                    Write-ModuleLog -Level SUCCESS -Message "Security template restored" -Module $moduleName
                }
                else {
                    $result.Errors += $secRestore.Errors
                }
            }
            
            # Restore 3: Audit Policies
            $auditBackupPath = Join-Path $BackupFolder "AuditPolicies.csv"
            if (Test-Path $auditBackupPath) {
                Write-ModuleLog -Level INFO -Message "Restoring audit policies..." -Module $moduleName
                $auditRestore = Restore-AuditPolicies -BackupPath $auditBackupPath
                
                if ($auditRestore.Success) {
                    Write-ModuleLog -Level SUCCESS -Message "Audit policies restored" -Module $moduleName
                }
                else {
                    $result.Errors += $auditRestore.Errors
                }
            }
            
            # Restore 4: Xbox Task State
            $xboxTaskBackupPath = Join-Path $BackupFolder "XboxTask.json"
            if (Test-Path $xboxTaskBackupPath) {
                Write-ModuleLog -Level INFO -Message "Restoring Xbox task state..." -Module $moduleName
                $xboxTaskRestore = Restore-XboxTask -BackupPath $xboxTaskBackupPath
                
                if ($xboxTaskRestore.Success) {
                    Write-ModuleLog -Level SUCCESS -Message "Xbox task state restored" -Module $moduleName
                }
                else {
                    $result.Errors += $xboxTaskRestore.Errors
                }
            }
            
            $result.Success = ($result.Errors.Count -eq 0)
            
            if ($result.Success) {
                Write-ModuleLog -Level SUCCESS -Message "All settings restored successfully!" -Module $moduleName
            }
            else {
                Write-ModuleLog -Level WARNING -Message "Restore completed with $($result.Errors.Count) errors" -Module $moduleName
            }
            
        }
        catch {
            $result.Success = $false
            $result.Errors += "Restore failed: $($_.Exception.Message)"
            
            if (Get-Command Write-ErrorLog -ErrorAction SilentlyContinue) {
                Write-ErrorLog -Message "Security Baseline restore failed" -Module $moduleName -ErrorRecord $_
            }
            else {
                Write-Error "Security Baseline restore failed: $_"
            }
        }
    }
    
    end {
        $result.Duration = (Get-Date) - $startTime
        
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Items Restored: $($result.ItemsRestored)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Errors: $($result.Errors.Count)" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "Duration: $($result.Duration.TotalSeconds) seconds" -Module $moduleName
        Write-ModuleLog -Level INFO -Message "========================================" -Module $moduleName
        
        return $result
    }
}
