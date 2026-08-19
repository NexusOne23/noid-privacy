#Requires -Version 5.1

function Disable-CopilotURIHandlers {
    <#
    .SYNOPSIS
        Removes both Copilot URI protocols from their real machine/user sources.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory = $false)][switch]$DryRun)

    $userRoot = (Get-AntiAIUserContext).Root
    $paths = @(
        'HKLM:\SOFTWARE\Classes\ms-copilot',
        "$userRoot\Software\Classes\ms-copilot",
        'HKLM:\SOFTWARE\Classes\ms-edge-copilot',
        "$userRoot\Software\Classes\ms-edge-copilot"
    )
    $result = [PSCustomObject]@{
        Success   = $false
        Declared  = $paths.Count
        Removed   = 0
        Previewed = 0
        Verified  = 0
        Errors    = [System.Collections.Generic.List[string]]::new()
    }
    if (-not $PSCmdlet.ShouldProcess('Copilot URI source hives', 'Remove ms-copilot and ms-edge-copilot handlers')) {
        $result.Errors.Add('Operation was not approved by ShouldProcess')
        return $result
    }

    foreach ($path in $paths) {
        try {
            if ($DryRun) {
                $result.Previewed++
                continue
            }
            if (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                $result.Removed++
            }
            if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                throw 'source key remains present after removal'
            }
            $result.Verified++
        }
        catch {
            $message = "${path}: $($_.Exception.Message)"
            $result.Errors.Add($message)
            Write-Log -Level ERROR -Message "Copilot URI source removal failed: $message" -Module 'AntiAI'
        }
    }
    $result.Success = ($result.Errors.Count -eq 0 -and
        (($DryRun -and $result.Previewed -eq $paths.Count) -or
         (-not $DryRun -and $result.Verified -eq $paths.Count)))
    return $result
}
