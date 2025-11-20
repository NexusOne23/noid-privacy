<#
.SYNOPSIS
    Backup current security template settings
    
.DESCRIPTION
    Uses secedit.exe to export current security settings to INF file.
    Backs up:
    - Password Policies
    - Account Policies
    - User Rights Assignments
    - Security Options
    - Event Log Settings
    
.PARAMETER BackupPath
    Path where backup INF will be saved
    
.OUTPUTS
    PSCustomObject with backup status
    
.NOTES
    Uses secedit.exe /export command
#>

function Backup-SecurityTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        BackupPath = $BackupPath
        Errors = @()
    }
    
    # Initialize temp file paths
    $dbFile = $null
    $logFile = $null
    
    try {
        Write-Log -Level DEBUG -Message "Backing up security template via secedit.exe..." -Module "SecurityBaseline"
        
        # Create temp paths
        $dbFile = Join-Path $env:TEMP "secedit_backup_$(Get-Date -Format 'yyyyMMddHHmmss').sdb"
        $logFile = Join-Path $env:TEMP "secedit_backup_$(Get-Date -Format 'yyyyMMddHHmmss').log"
        
        # Export current settings
        $seceditArgs = @(
            "/export",
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
            Write-Log -Level DEBUG -Message "Security template backup saved to: $BackupPath" -Module "SecurityBaseline"
        }
        else {
            $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            $result.Errors += "secedit export failed with exit code $($process.ExitCode): $logContent"
            Write-Error "secedit export failed: $logContent"
        }
    }
    catch {
        $result.Errors += "Security template backup failed: $_"
        Write-Error "Security template backup failed: $_"
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
