<#
.SYNOPSIS
    Restores SecurityBaseline through the canonical sealed-session engine.

.DESCRIPTION
    This public entry point delegates to the framework's canonical
    Restore-Session engine, so SecurityBaseline has exactly one restore
    implementation for GPO, service, audit, template and registry state.
    The engine, its mutation lock, receipts and cross-module overlap guards
    are provided by the NoID Privacy framework. Outside the framework this
    wrapper fails before touching system state; use Start-NoIDPrivacy.bat
    ([R] Restore from Backup) or NoIDPrivacy.ps1 -RestoreSessionPath instead.
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
        # A partial dot-source of Core files cannot provide the framework's
        # mutation lock, Quick Action receipts, intent state and module
        # dependency bridge. Refuse instead of starting an incomplete restore.
        $missingEngineCommands = @(foreach ($commandName in @(
                    'Restore-Session', 'Get-SessionManifest', 'Assert-SessionManifest', 'Get-BackupSessions')) {
                if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) { $commandName }
            })
        if ($missingEngineCommands.Count -gt 0) {
            throw ('The NoID Privacy restore engine is not loaded ({0}). Restore through Start-NoIDPrivacy.bat ' +
                '([R] Restore from Backup) or run .\NoIDPrivacy.ps1 -RestoreSessionPath <session> as Administrator.') -f
                ($missingEngineCommands -join ', ')
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
            # Get-BackupSessions deliberately lists non-restorable folders too,
            # including retained incomplete backups (Restorable = $false, no
            # sealed manifest). Select only the newest restorable module session;
            # Quick Action sessions carry a single-action scope, not a module restore.
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
