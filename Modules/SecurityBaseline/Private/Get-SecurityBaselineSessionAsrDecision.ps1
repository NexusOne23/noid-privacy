#Requires -Version 5.1

function Get-SecurityBaselineSessionAsrDecision {
    <#
    .SYNOPSIS
        Read an earlier ASR decision from this baseline's sealed backup session.
    .DESCRIPTION
        Durable intent is published after the complete module loop. An ASR
        choice already sealed earlier in that loop takes precedence over older
        durable intent and the baseline package's Audit default. This reader
        never changes the session or its recorded prestate.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionPath
    )

    $manifest = Get-SessionManifest -SessionPath $SessionPath
    $null = Assert-SessionManifest -SessionPath $SessionPath -Manifest $manifest
    $earlierAsr = $null
    $baselineFound = $false
    foreach ($module in @($manifest.modules)) {
        if ([string]$module.name -eq 'SecurityBaseline') {
            $baselineFound = $true
            break
        }
        if ([string]$module.name -eq 'ASR') { $earlierAsr = $module }
    }
    if (-not $baselineFound) {
        throw 'Current SecurityBaseline backup is missing from the sealed session'
    }
    if ($null -eq $earlierAsr) { return $null }

    $artifacts = @($earlierAsr.artifacts | Where-Object {
            [string]$_.type -eq 'ASR' -and [string]$_.name -eq 'ASR_ActiveConfiguration'
        })
    if ($artifacts.Count -ne 1) {
        throw 'Earlier ASR module must contain one sealed decision artifact'
    }
    $path = Resolve-SessionChildPath -SessionPath $SessionPath -RelativePath ([string]$artifacts[0].relativePath)
    $snapshot = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $decisionMatches = @($snapshot.Targets | Where-Object {
            [string]$_.GUID -eq 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        })
    if ($decisionMatches.Count -ne 1 -or [int]$decisionMatches[0].RequestedAction -notin @(1, 2)) {
        throw 'Earlier sealed ASR decision has no unique Block/Audit PSExec/WMI action'
    }
    return [PSCustomObject]@{
        Action = [int]$decisionMatches[0].RequestedAction
        Source = 'sealed ASR choice in the current session'
    }
}
