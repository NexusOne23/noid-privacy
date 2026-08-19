<#
.SYNOPSIS
    Restores SecurityBaseline through the canonical sealed-session engine.

.DESCRIPTION
    This public entry point intentionally delegates to Restore-Session. Keeping
    a second, partial restore implementation caused drift (LocalGPO, service,
    audit, template and targeted registry state were restored differently).
#>
function Restore-SecurityBaseline {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupFolder
    )

    $startTime = Get-Date
    $result = [PSCustomObject]@{
        ModuleName    = 'SecurityBaseline'
        Success       = $false
        ItemsRestored = 0
        SessionPath   = $null
        Errors        = [System.Collections.Generic.List[string]]::new()
        Duration      = $null
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore SecurityBaseline from sealed session')) {
        $result.Errors.Add('Restore was not confirmed')
        $result.Duration = (Get-Date) - $startTime
        return $result
    }

    try {
        if (-not (Get-Command Restore-Session -ErrorAction SilentlyContinue)) {
            $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
            $loggerPath = Join-Path $repoRoot 'Core\Logger.ps1'
            $rollbackPath = Join-Path $repoRoot 'Core\Rollback.ps1'
            if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
                if (-not (Test-Path -LiteralPath $loggerPath -PathType Leaf)) {
                    throw "Core logger not found: $loggerPath"
                }
                . $loggerPath
            }
            if (-not (Test-Path -LiteralPath $rollbackPath -PathType Leaf)) {
                throw "Canonical restore engine not found: $rollbackPath"
            }
            . $rollbackPath
        }

        $sessionPath = $null
        if ($BackupFolder) {
            $candidate = [System.IO.Path]::GetFullPath($BackupFolder)
            if (Test-Path -LiteralPath (Join-Path $candidate 'manifest.json') -PathType Leaf) {
                $sessionPath = $candidate
            }
            elseif ((Split-Path $candidate -Leaf) -eq 'SecurityBaseline' -and
                (Test-Path -LiteralPath (Join-Path (Split-Path $candidate -Parent) 'manifest.json') -PathType Leaf)) {
                $sessionPath = Split-Path $candidate -Parent
            }
            else {
                throw 'BackupFolder must be a sealed session root or its SecurityBaseline subfolder'
            }
        }
        else {
            # Get-BackupSessions deliberately keeps non-restorable folders in the
            # list so the operator can see them, and a failed Backup phase leaves
            # 'Session_<newest>_Incomplete_SecurityBaseline' as the NEWEST entry with
            # Restorable = $false and no manifest.json. Matching on the module name
            # alone therefore selected that folder and made every subsequent module
            # rollback fail, while an intact sealed session sat one row below.
            # Quick Action sessions are excluded for the same reason: they carry a
            # single-action scope, not a module restore.
            $session = @(Get-BackupSessions | Where-Object {
                    [bool]$_.Restorable -and
                    [string]$_.SessionType -ne 'quickAction' -and
                    @($_.Modules.name) -contains 'SecurityBaseline'
                } | Select-Object -First 1)
            if ($session.Count -eq 0) {
                throw 'No sealed SecurityBaseline backup session was found'
            }
            $sessionPath = [string]$session[0].FolderPath
        }

        $manifest = Get-SessionManifest -SessionPath $sessionPath
        Assert-SessionManifest -SessionPath $sessionPath -Manifest $manifest -RequestedModules @('SecurityBaseline')
        $moduleInfo = @($manifest.modules | Where-Object { $_.name -eq 'SecurityBaseline' })
        if ($moduleInfo.Count -ne 1) {
            throw 'Selected session does not contain exactly one SecurityBaseline module record'
        }

        $result.SessionPath = $sessionPath
        $result.ItemsRestored = [int]$moduleInfo[0].itemsBackedUp
        $result.Success = [bool](Restore-Session -SessionPath $sessionPath -ModuleNames @('SecurityBaseline') -NoReboot)
        if (-not $result.Success) {
            $result.Errors.Add('Canonical SecurityBaseline restore reported one or more failures')
        }
    }
    catch {
        $result.Errors.Add("SecurityBaseline restore failed: $($_.Exception.Message)")
        $result.Success = $false
    }
    finally {
        $result.Duration = (Get-Date) - $startTime
    }

    return $result
}
