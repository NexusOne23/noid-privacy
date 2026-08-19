#Requires -Version 5.1

function Read-StandardUserElevationModeChoice {
    <#
    .SYNOPSIS
        Read the interactive machine-wide standard-user UAC decision.

    .DESCRIPTION
        Presents the same Y/N decision regardless of whether the currently
        interactive account is an administrator or a standard user. The policy
        governs every standard-user account on the computer; administrator
        membership therefore changes only the explanatory text, never whether
        the choice is offered.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$InteractiveAccountIsAdministrator,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ReadChoice = { Read-Host }
    )

    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "  Standard User - Administrator Elevation" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This machine-wide setting applies to every standard-user account." -ForegroundColor White
    if ($InteractiveAccountIsAdministrator) {
        Write-Host "Your everyday account is an administrator; choose for any standard" -ForegroundColor White
        Write-Host "accounts on this computer. Its own elevation prompts do not change." -ForegroundColor White
    }
    else {
        Write-Host "Your everyday account is a standard user; choose how it may request" -ForegroundColor White
        Write-Host "an individual elevated task using separate administrator credentials." -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Allow standard users to enter administrator credentials?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [N] NO - Keep Strict (Microsoft Baseline, Recommended)" -ForegroundColor Green
    Write-Host "      - Standard-user elevation requests are denied automatically" -ForegroundColor Gray
    Write-Host "      - A standard user must sign in to an administrator account to install" -ForegroundColor Gray
    Write-Host "      - Strongest separation between everyday and administrator accounts" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [Y] YES - Use secure-desktop administrator credential prompt" -ForegroundColor Cyan
    Write-Host "      - Standard users can enter separate administrator credentials" -ForegroundColor Gray
    Write-Host "        for an individual elevated task in their current session" -ForegroundColor Gray
    Write-Host "      - Credential entry uses the secure desktop" -ForegroundColor Gray
    Write-Host "      - Less isolation than a separate administrator sign-in" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Security Note: N keeps ConsentPromptBehaviorUser=0; Y uses value 1. This choice never changes an administrator account's own prompts." -ForegroundColor DarkGray
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    do {
        Write-Host "Your choice [Y/N] (default: N): " -ForegroundColor Yellow -NoNewline
        $uacChoice = [string](& $ReadChoice)
        if ([string]::IsNullOrWhiteSpace($uacChoice)) { $uacChoice = 'N' }
        $uacChoice = $uacChoice.ToUpperInvariant()
        if ($uacChoice -notin @('Y', 'N')) {
            Write-Host ""
            Write-Host 'Invalid input. Please enter Y or N.' -ForegroundColor Red
            Write-Host ""
        }
    } while ($uacChoice -notin @('Y', 'N'))

    if ($uacChoice -eq 'Y') { return 'SecureDesktop' }
    return 'Strict'
}
