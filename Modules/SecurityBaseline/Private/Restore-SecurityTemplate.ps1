<#
.SYNOPSIS
    Restore security template from backup

.DESCRIPTION
    Uses secedit.exe to import the filtered module-owned System Access and
    Privilege Rights prestate from the backup INF file. Registry values and
    services are restored by their separate exact typed artifacts.

.PARAMETER BackupPath
    Path to backup INF file created by Backup-SecurityTemplate

.OUTPUTS
    PSCustomObject with restore status

.NOTES
    Uses secedit.exe /configure command
#>

function Restore-SecurityTemplate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore SecurityTemplate')) {
        return
    }


    $result = [PSCustomObject]@{
        Success = $false
        Errors = @()
    }

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        $result.Errors += "Backup file not found: $BackupPath"
        return $result
    }

    # Initialize temp file paths
    $dbFile = $null
    $logFile = $null
    $verificationFile = $null
    $verificationLog = $null

    try {
        Write-Log -Level DEBUG -Message "Restoring security template from: $BackupPath" -Module "SecurityBaseline"

        # Create temp paths
        $operationId = [Guid]::NewGuid().ToString('N')
        $dbFile = Join-Path $env:TEMP "secedit_restore_$operationId.sdb"
        $logFile = Join-Path $env:TEMP "secedit_restore_$operationId.log"

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
                                 -PassThru `
                                 -ErrorAction Stop

        if ($process.ExitCode -eq 0) {
            $verificationFile = Join-Path $env:TEMP "secedit_verify_$operationId.inf"
            $verificationLog = Join-Path $env:TEMP "secedit_verify_$operationId.log"
            $verifyProcess = Start-Process -FilePath 'secedit.exe' `
                -ArgumentList @('/export', '/cfg', "`"$verificationFile`"", '/log', "`"$verificationLog`"", '/quiet') `
                -Wait -NoNewWindow -PassThru -ErrorAction Stop
            if ($verifyProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationFile -PathType Leaf)) {
                throw "secedit post-restore export failed with exit code $($verifyProcess.ExitCode)"
            }

            function Convert-SecurityInfToMap {
                param([string]$Path)
                $map = @{}
                $section = ''
                foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
                    $trimmed = $line.Trim()
                    if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
                    if ($trimmed -match '^\[(.+)\]$') {
                        $section = $Matches[1]
                        if (-not $map.ContainsKey($section)) { $map[$section] = @{} }
                        continue
                    }
                    if ($section -and $trimmed -match '^([^=]+?)\s*=\s*(.*)$') {
                        $map[$section][$Matches[1].Trim()] = $Matches[2].Trim()
                    }
                    elseif ($section -eq 'Service General Setting' -and
                        $trimmed -match '^"([^"]+)"\s*,\s*([0-9]+)\s*,') {
                        $map[$section][$Matches[1]] = $Matches[2]
                    }
                }
                return $map
            }

            $expectedMap = Convert-SecurityInfToMap -Path $BackupPath
            $actualMap = Convert-SecurityInfToMap -Path $verificationFile
            foreach ($section in @('System Access', 'Privilege Rights')) {
                if (-not $expectedMap.ContainsKey($section) -or -not $actualMap.ContainsKey($section)) {
                    throw "secedit verification is missing section [$section]"
                }
                foreach ($name in $expectedMap[$section].Keys) {
                    if (-not $actualMap[$section].ContainsKey($name)) {
                        if ($section -eq 'Privilege Rights' -and
                            [string]::IsNullOrWhiteSpace([string]$expectedMap[$section][$name])) {
                            # secedit may omit an explicitly cleared privilege
                            # from its export; missing and empty both mean no
                            # principals hold the right.
                            continue
                        }
                        throw "secedit post-restore mismatch: [$section] $name"
                    }
                    $expectedValue = [string]$expectedMap[$section][$name]
                    $actualValue = [string]$actualMap[$section][$name]
                    if ($section -eq 'Privilege Rights') {
                        $expectedValue = (@($expectedValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                        $actualValue = (@($actualValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                    }
                    if ($actualValue -cne $expectedValue) {
                        throw "secedit post-restore mismatch: [$section] $name"
                    }
                }
            }
            $result.Success = $true
            Write-Log -Level DEBUG -Message "Security template restored successfully" -Module "SecurityBaseline"
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
        if ($verificationFile -and (Test-Path $verificationFile)) {
            Remove-Item $verificationFile -Force -ErrorAction SilentlyContinue
        }
        if ($verificationLog -and (Test-Path $verificationLog)) {
            Remove-Item $verificationLog -Force -ErrorAction SilentlyContinue
        }
    }

    return $result
}
