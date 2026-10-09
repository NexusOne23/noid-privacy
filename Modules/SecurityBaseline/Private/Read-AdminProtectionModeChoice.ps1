#Requires -Version 5.1

function Read-AdminProtectionModeChoice {
    <#
    .SYNOPSIS
        Read the interactive Administrator protection decision.

    .DESCRIPTION
        Microsoft's Windows 11 26H2 baseline enables Administrator protection
        (TypeOfAdminApprovalMode=2): an elevation request asks for PIN,
        password or Windows Hello. Microsoft documents a Yes/No consent prompt
        for Administrator protection as the alternative
        (ConsentPromptBehaviorEnhancedAdmin=2) and lists Hyper-V, WSL and
        developer tools that must run elevated as reasons not to enable it.
        It needs Windows update KB5120998 (August 2026) or later; without it,
        administrators keep the classic Yes/No prompt.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [scriptblock]$ReadChoice = { Read-Host }
    )

    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "  Administrator Protection - Elevation Prompt" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Microsoft's baseline turns on Administrator protection: an app gets" -ForegroundColor White
    Write-Host "administrator rights only for the one task you approve, in a separate" -ForegroundColor White
    Write-Host "hidden account. Choose how you approve such a task." -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] PIN, password or Windows Hello (Microsoft Baseline, Recommended)" -ForegroundColor Green
    Write-Host "      - Enter your PIN or password, or use Windows Hello, when an app" -ForegroundColor Gray
    Write-Host "        asks for administrator rights" -ForegroundColor Gray
    Write-Host "      - Strongest protection, also against someone at your unlocked PC" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Yes/No confirmation" -ForegroundColor Cyan
    Write-Host "      - Administrator protection stays on; you confirm with Yes or No" -ForegroundColor Gray
    Write-Host "      - No need to enter your PIN or password again" -ForegroundColor Gray
    Write-Host "      - Someone at your unlocked PC can confirm without your password" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [3] Classic User Account Control (no Administrator protection)" -ForegroundColor Cyan
    Write-Host "      - Compatibility option for Hyper-V or problems with elevated" -ForegroundColor Gray
    Write-Host "        WSL/developer tools" -ForegroundColor Gray
    Write-Host "      - Yes/No confirmation; elevated apps run in your own account" -ForegroundColor Gray
    Write-Host "      - Deviates from the Microsoft baseline" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Security Note: A change takes effect after the next restart." -ForegroundColor DarkGray
    Write-Host "Administrator protection needs Windows update KB5120998 or later;" -ForegroundColor DarkGray
    Write-Host "without it, Windows keeps the classic Yes/No prompt." -ForegroundColor DarkGray
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    do {
        Write-Host "Select [1-3] (default: 1): " -ForegroundColor White -NoNewline
        $choice = [string](& $ReadChoice)
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }
        $choice = $choice.Trim()
        if ($choice -notin @('1', '2', '3')) {
            Write-Host ""
            Write-Host 'Invalid input. Please enter 1, 2 or 3.' -ForegroundColor Red
            Write-Host ""
        }
    } while ($choice -notin @('1', '2', '3'))

    switch ($choice) {
        '2' { return 'Consent' }
        '3' { return 'Classic' }
        default { return 'Credentials' }
    }
}
