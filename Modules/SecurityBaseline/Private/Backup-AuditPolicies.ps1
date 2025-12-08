<#
.SYNOPSIS
    Backup current audit policies
    
.DESCRIPTION
    Uses auditpol.exe to export current audit policy configuration.
    Backs up all Advanced Audit Policy settings.
    
.PARAMETER BackupPath
    Path where backup CSV will be saved
    
.OUTPUTS
    PSCustomObject with backup status
    
.NOTES
    Uses auditpol.exe /backup command
#>

function Backup-AuditPolicies {
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
    
    try {
        Write-Log -Level DEBUG -Message "Backing up audit policies via auditpol.exe..." -Module "SecurityBaseline"
        
        # Export current audit settings
        $auditpolArgs = @(
            "/backup",
            "/file:`"$BackupPath`""
        )
        
        $process = Start-Process -FilePath "auditpol.exe" `
                                 -ArgumentList $auditpolArgs `
                                 -Wait `
                                 -NoNewWindow `
                                 -PassThru `
                                 -RedirectStandardOutput (Join-Path $env:TEMP "auditpol_backup_stdout.txt") `
                                 -RedirectStandardError (Join-Path $env:TEMP "auditpol_backup_stderr.txt")
        
        if ($process.ExitCode -eq 0) {
            $result.Success = $true
            Write-Log -Level DEBUG -Message "Audit policies backup saved to: $BackupPath" -Module "SecurityBaseline"
        }
        else {
            $stderr = Get-Content (Join-Path $env:TEMP "auditpol_backup_stderr.txt") -Raw -ErrorAction SilentlyContinue
            $result.Errors += "auditpol backup failed with exit code $($process.ExitCode): $stderr"
            Write-Error "auditpol backup failed: $stderr"
        }
        
    }
    catch {
        $result.Errors += "Audit policies backup failed: $_"
        Write-Error "Audit policies backup failed: $_"
    }
    
    return $result
}
