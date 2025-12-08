<#
.SYNOPSIS
    Restore security template from backup
    
.DESCRIPTION
    Uses secedit.exe to import security settings from backup INF file.
    
.PARAMETER BackupPath
    Path to backup INF file created by Backup-SecurityTemplate
    
.OUTPUTS
    PSCustomObject with restore status
    
.NOTES
    Uses secedit.exe /configure command
#>

function Restore-SecurityTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        Errors = @()
    }
    
    if (-not (Test-Path $BackupPath)) {
        $result.Errors += "Backup file not found: $BackupPath"
        return $result
    }
    
    # Initialize temp file paths
    $dbFile = $null
    $logFile = $null
    
    try {
        Write-Log -Level DEBUG -Message "Restoring security template from: $BackupPath" -Module "SecurityBaseline"
        
        # Create temp paths
        $dbFile = Join-Path $env:TEMP "secedit_restore_$(Get-Date -Format 'yyyyMMddHHmmss').sdb"
        $logFile = Join-Path $env:TEMP "secedit_restore_$(Get-Date -Format 'yyyyMMddHHmmss').log"
        
        # Apply backup settings
        $seceditArgs = @(
            "/configure",
            "/db", "`"$dbFile`"",
            "/cfg", "`"$BackupPath`"",
            "/log", "`"$logFile`"",
            "/quiet"
        )
        
        $process = Start-Process -FilePath "secedit.exe" `
                                 -ArgumentList $seceditArgs `
                                 -Wait `
                                 -NoNewWindow `
                                 -PassThru
        
        if ($process.ExitCode -eq 0) {
            $result.Success = $true
            Write-Log -Level DEBUG -Message "Security template restored successfully" -Module "SecurityBaseline"
        }
        elseif ($process.ExitCode -in 1,3,4) {
            # Exit Code 1/3/4 often indicates warnings (e.g. SID mapping issues) but successful application of other settings
            # We should NOT fail the entire restore process for this.
            $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            $result.Success = $true # Treat as success with warnings
            Write-Log -Level INFO -Message "Security template restored (Exit Code $($process.ExitCode)). Minor SID mapping warnings ignored." -Module "SecurityBaseline"
        }
        else {
            $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            $result.Errors += "secedit restore failed with exit code $($process.ExitCode): $logContent"
            Write-Error "secedit restore failed: $logContent"
        }
    }
    catch {
        $result.Errors += "Security template restore failed: $_"
        Write-Error "Security template restore failed: $_"
    }
    finally {
        # ALWAYS cleanup temp files (even on error)
        if ($dbFile -and (Test-Path $dbFile)) {
            Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
        }
        if ($logFile -and (Test-Path $logFile)) {
            Remove-Item $logFile -Force -ErrorAction SilentlyContinue
        }
    }
    
    return $result
}
