<#
.SYNOPSIS
    Restore audit policies from backup
    
.DESCRIPTION
    Uses auditpol.exe to import audit policy configuration from backup CSV.
    
.PARAMETER BackupPath
    Path to backup CSV file created by Backup-AuditPolicies
    
.OUTPUTS
    PSCustomObject with restore status
    
.NOTES
    Uses auditpol.exe /restore command
#>

function Restore-AuditPolicies {
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
    
    try {
        Write-Log -Level DEBUG -Message "Restoring audit policies from: $BackupPath" -Module "SecurityBaseline"
        
        # Restore audit settings
        $auditpolArgs = @(
            "/restore",
            "/file:`"$BackupPath`""
        )
        
        $process = Start-Process -FilePath "auditpol.exe" `
                                 -ArgumentList $auditpolArgs `
                                 -Wait `
                                 -NoNewWindow `
                                 -PassThru `
                                 -RedirectStandardOutput (Join-Path $env:TEMP "auditpol_restore_stdout.txt") `
                                 -RedirectStandardError (Join-Path $env:TEMP "auditpol_restore_stderr.txt")
        
        if ($process.ExitCode -eq 0) {
            $result.Success = $true
            Write-Log -Level DEBUG -Message "Audit policies restored successfully" -Module "SecurityBaseline"
        }
        else {
            $stderr = Get-Content (Join-Path $env:TEMP "auditpol_restore_stderr.txt") -Raw -ErrorAction SilentlyContinue
            $result.Errors += "auditpol restore failed with exit code $($process.ExitCode): $stderr"
            Write-Error "auditpol restore failed: $stderr"
        }
        
    }
    catch {
        $result.Errors += "Audit policies restore failed: $_"
        Write-Error "Audit policies restore failed: $_"
    }
    
    return $result
}
