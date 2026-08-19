#Requires -Version 5.1

function Set-AntiAIRegistryTargets {
    <#
    .SYNOPSIS
        Applies the canonical config-derived AntiAI registry target inventory.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Targets,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$DeclaredCount,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $targetsToApply = @($Targets)
    $result = [PSCustomObject]@{
        Success        = $false
        Declared       = $DeclaredCount
        Applicable     = $targetsToApply.Count
        Applied        = 0
        Previewed      = 0
        FeatureGroups  = @($targetsToApply | ForEach-Object { [string]$_.Feature } | Sort-Object -Unique).Count
        Errors         = [System.Collections.Generic.List[string]]::new()
    }
    if ($DeclaredCount -ne 43 -or $targetsToApply.Count -gt $DeclaredCount) {
        $result.Errors.Add("Canonical AntiAI scope must declare 43 values and an applicable subset; got declared=$DeclaredCount, applicable=$($targetsToApply.Count)")
        return $result
    }
    if (-not $PSCmdlet.ShouldProcess("$($targetsToApply.Count) applicable of 43 declared AntiAI registry targets", 'Apply exact type/value state')) {
        $result.Errors.Add('Operation was not approved by ShouldProcess')
        return $result
    }

    foreach ($target in $targetsToApply) {
        try {
            $null = Set-AntiAIRegistryValue -Path ([string]$target.Path) -Name ([string]$target.Name) `
                -Type ([string]$target.Type) -Value $target.Value -DryRun:$DryRun
            if ($DryRun) { $result.Previewed++ } else { $result.Applied++ }
        }
        catch {
            $message = "$($target.Path)::$($target.Name): $($_.Exception.Message)"
            $result.Errors.Add($message)
            Write-Log -Level ERROR -Message "AntiAI target apply failed: $message" -Module 'AntiAI'
        }
    }
    $result.Success = ($result.Errors.Count -eq 0 -and
        (($DryRun -and $result.Previewed -eq $targetsToApply.Count) -or
         (-not $DryRun -and $result.Applied -eq $targetsToApply.Count)))
    return $result
}
