#Requires -Version 5.1

function Assert-NoIDXboxAppUserContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExpectedSid, [Parameter(Mandatory)][int]$ExpectedSessionId)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($identity.User.Value -cne $ExpectedSid -or $sessionId -ne $ExpectedSessionId -or $sessionId -lt 1) {
        throw 'Xbox app recovery is not running as the original desktop user'
    }
    $user = Get-PrivacyUserContext -Refresh
    if ($user.Sid -cne $ExpectedSid -or $user.SessionId -ne $ExpectedSessionId) {
        throw 'Xbox app recovery desktop identity changed'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        $enableLua = $policy.PSObject.Properties['EnableLUA']
        $filterAdministrator = $policy.PSObject.Properties['FilterAdministratorToken']
        $unfiltered = ($null -ne $enableLua -and [int64]$enableLua.Value -eq 0) -or
            ($identity.User.Value -match '-500$' -and ($null -eq $filterAdministrator -or [int64]$filterAdministrator.Value -eq 0))
        if (-not $unfiltered) { throw 'Xbox app recovery unexpectedly received an elevated token' }
    }
}

function Get-NoIDXboxUserAppState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $definition = @((Get-NoIDXboxComponentCatalog).Apps | Where-Object Name -CEQ $Name)
    if ($definition.Count -ne 1) { throw 'Xbox recovery app identity is outside the closed catalog' }
    $packages = @(Get-AppxPackage -Name $Name -PackageTypeFilter @('Main','Bundle') -ErrorAction Stop)
    if (@($packages | Where-Object {
        [string]$_.Name -cne $Name -or [string]$_.PackageFamilyName -cne $definition[0].PackageFamilyName
    }).Count -gt 0) { throw 'Xbox recovery encountered an unexpected package publisher or identity' }
    return [pscustomobject]@{
        Present = $packages.Count -gt 0
        Healthy = $packages.Count -gt 0 -and @($packages | Where-Object { [string]$_.Status -cne 'Ok' }).Count -eq 0
    }
}

function Get-NoIDXboxRegisteredWinGetPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $packages = @(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -PackageTypeFilter Main -ErrorAction Stop |
        Where-Object { [string]$_.Name -ceq 'Microsoft.DesktopAppInstaller' -and [string]$_.PackageFamilyName -ceq 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe' -and [string]$_.Status -ceq 'Ok' })
    if ($packages.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$packages[0].InstallLocation)) {
        throw 'Xbox recovery requires a healthy Microsoft App Installer registration'
    }
    $path = Join-Path ([string]$packages[0].InstallLocation) 'winget.exe'
    if (-not [IO.File]::Exists($path)) { throw 'The registered Microsoft App Installer executable is unavailable' }
    return $path
}

function Get-NoIDXboxRecoveryTimeout {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)]$Timer, [int]$LimitSeconds, [int]$MaximumSeconds)

    $remaining = $LimitSeconds - [int][Math]::Ceiling($Timer.Elapsed.TotalSeconds)
    if ($remaining -lt 1) { throw 'Xbox app recovery reached its overall deadline' }
    return [int][Math]::Min($remaining, $MaximumSeconds)
}

function Invoke-NoIDXboxCurrentUserAppRecovery {
    <#
    .SYNOPSIS
        Recovers only the catalogued Xbox apps in the original user's token.
    .DESCRIPTION
        A staged signed package family is tried before the fixed Microsoft Store
        product. Current Store versions and required dependencies may be installed;
        this is not an exact app-version or app-data restore. No games are targeted.
        In-use applications are not forcibly closed by family registration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')][string]$ExpectedSid,
        [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
        [ValidateRange(30,1800)][int]$TimeoutSeconds=1200
    )

    Assert-NoIDXboxAppUserContext -ExpectedSid $ExpectedSid -ExpectedSessionId $ExpectedSessionId
    if (-not $PSCmdlet.ShouldProcess('Xbox apps for the current desktop user', 'Register missing Xbox packages or install their current Microsoft Store products')) {
        throw 'Xbox app recovery was not confirmed'
    }
    $ProgressPreference = 'SilentlyContinue'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $winget = $null
    $clientChecked = $false
    $sourceRefreshed = $false
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($app in (Get-NoIDXboxComponentCatalog).Apps) {
        $outcome = 'Failed'
        $before = $null
        $after = $null
        $errors = [Collections.Generic.List[string]]::new()
        try {
            $null = Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds $TimeoutSeconds -MaximumSeconds 600
            $before = Get-NoIDXboxUserAppState -Name $app.Name
            $after = $before
            if ($before.Healthy) { $outcome = 'AlreadyPresent' }
            else {
                try {
                    Add-AppxPackage -RegisterByFamilyName -MainPackage $app.PackageFamilyName -ErrorAction Stop
                }
                catch { $errors.Add('Local registration: '+$_.Exception.Message) }
                $after = Get-NoIDXboxUserAppState -Name $app.Name
                if ($after.Healthy) { $outcome = 'RegisteredLocally' }
                elseif (-not $app.StoreId) {
                    if (-not $app.RequiredWhenEnabled -and -not $after.Present) { $outcome = 'OptionalUnavailable' }
                    else { $errors.Add('No current Store product is available for this Xbox component') }
                }
                elseif (-not (Test-NoIDNetworkConnection)) {
                    $outcome = 'NeedsNetwork'
                }
                else {
                    if (-not $winget) { $winget = Get-NoIDXboxRegisteredWinGetPath }
                    if (-not $clientChecked) {
                        $clientChecked = $true
                        $timeout = Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds $TimeoutSeconds -MaximumSeconds 90
                        $probeExit = Invoke-PrivacyBoundedProcess -FilePath $winget -ArgumentList @(
                            'show','--id',$app.StoreId,'--exact','--source','msstore','--accept-source-agreements','--disable-interactivity'
                        ) -TimeoutSeconds $timeout
                        if ($probeExit -in @(-1978335230,-1978335176,-1978335170,-1978335138)) {
                            # Reuse the pinned Microsoft MSIX update already used
                            # by Privacy recovery. The supervising user-worker job
                            # also bounds this update and kills descendants on stop.
                            $null = Update-PrivacyWinGet -FilePath $winget -Confirm:$false
                            $winget = Get-NoIDXboxRegisteredWinGetPath
                        }
                    }
                    for ($attempt=1; $attempt -le 2 -and -not $after.Healthy; $attempt++) {
                        $timeout = Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds $TimeoutSeconds -MaximumSeconds 600
                        try {
                            $exitCode = Invoke-PrivacyBoundedProcess -FilePath $winget -ArgumentList @(
                                'install','--id',$app.StoreId,'--exact','--source','msstore',
                                '--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity'
                            ) -TimeoutSeconds $timeout
                            $after = Get-NoIDXboxUserAppState -Name $app.Name
                            if ($after.Healthy) { $outcome = 'InstalledFromStore' }
                            else { $errors.Add("Store attempt $attempt exited $exitCode without a healthy expected registration") }
                        }
                        catch { $errors.Add('Store recovery: '+$_.Exception.Message) }
                        if (-not $after.Healthy -and $attempt -eq 1 -and -not $sourceRefreshed) {
                            $sourceRefreshed = $true
                            $timeout = Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds $TimeoutSeconds -MaximumSeconds 90
                            $null = Invoke-PrivacyBoundedProcess -FilePath $winget -ArgumentList @(
                                'source','update','--name','msstore','--disable-interactivity'
                            ) -TimeoutSeconds $timeout
                        }
                    }
                }
            }
        }
        catch { $errors.Add($_.Exception.Message) }
        $errorText = if ($outcome -cin @('AlreadyPresent','RegisteredLocally','InstalledFromStore','OptionalUnavailable')) { '' }
            else { $errors -join '; ' }
        if ($errorText.Length -gt 8192) { $errorText = $errorText.Substring(0,8189) + '...' }
        $entries.Add([pscustomobject][ordered]@{
            Name=$app.Name
            Required=[bool]$app.RequiredWhenEnabled
            Outcome=$outcome
            BeforePresent=$(if ($null -eq $before) {$null} else {[bool]$before.Present})
            Present=$(if ($null -eq $after) {$null} else {[bool]$after.Present})
            Healthy=$(if ($null -eq $after) {$null} else {[bool]$after.Healthy})
            Error=$errorText
        })
    }
    $failed = @($entries | Where-Object { $_.Outcome -notin @('AlreadyPresent','RegisteredLocally','InstalledFromStore','OptionalUnavailable') })
    return [pscustomobject][ordered]@{
        SchemaVersion=1;UserSid=$ExpectedSid;SessionId=$ExpectedSessionId
        Success=($failed.Count -eq 0)
        Entries=$entries.ToArray()
    }
}
