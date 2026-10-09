function Invoke-ModuleTemplate {
    <#
    .SYNOPSIS
        Non-mutating scaffold for a new exact BAVR module.

    .DESCRIPTION
        This directory is a development scaffold, not an eighth production
        module. It deliberately refuses live execution until a maintainer has:

        1. copied and renamed the directory and regenerated its manifest GUID;
        2. added the new module name to Core/Rollback.ps1's sealed allow-list;
        3. implemented a complete, typed prestate snapshot for every owned target;
        4. reconciled that prestate immediately before and after sealing;
        5. applied only the sealed target inventory and verified exact type/data;
        6. added exact restore handlers, post-restore verification and tests.

        Use the seven production Invoke-* functions as executable reference
        implementations. This scaffold cannot accidentally demonstrate or ship
        the obsolete pattern "backup warning, then continue applying".

    .PARAMETER DryRun
        Return the scaffold plan without changing the system.

    .OUTPUTS
        PSCustomObject describing the non-mutating scaffold result.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $result = [PSCustomObject]@{
        ModuleName         = 'ModuleTemplate'
        Success            = $false
        Status             = 'ScaffoldOnly'
        ChangesApplied     = 0
        Errors             = @()
        Warnings           = @()
        BackupCreated      = $false
        VerificationPassed = $null
    }

    if (-not $DryRun) {
        $message = 'ModuleTemplate is a non-executable scaffold. Copy, rename and implement the complete sealed BAVR contract before live use.'
        $result.Errors += $message
        Write-Log -Level ERROR -Message $message -Module 'ModuleTemplate'
        return $result
    }

    Write-Log -Level INFO -Message '[DRY RUN] ModuleTemplate is scaffold-only; no backup, apply, verify or restore operation was attempted.' -Module 'ModuleTemplate'
    $result.Success = $true
    $result.Status = 'DryRun'
    return $result
}
