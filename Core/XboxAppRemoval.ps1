#Requires -Version 5.1

. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\Get-PrivacyUserContext.ps1')
. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacyWindowsSearch.ps1')
. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacyAppxFirewall.ps1')
. (Join-Path $PSScriptRoot '..\Modules\Privacy\Private\PrivacyUserAppx.ps1')

function Assert-NoIDXboxRemovalRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    if ($Entries.Count -gt 100) { throw 'Xbox removal request exceeds its bounded package count' }
    $catalog = Get-NoIDXboxComponentCatalog
    $allowed = @($catalog.Apps | Where-Object RemoveWhenDisabled)
    $packages = @(foreach ($entry in $Entries) {
        Assert-NoIDXboxObjectFields $entry @('AppName','PackageFullName','PackageFamilyName')
        if ($entry.AppName -isnot [string] -or $entry.PackageFullName -isnot [string] -or
            $entry.PackageFamilyName -isnot [string] -or $entry.AppName -cnotin @($allowed.Name)) {
            throw 'Xbox removal request targets an app outside the six removable Xbox families'
        }
        [pscustomobject]@{
            Name=$entry.AppName;PackageFamilyName=$entry.PackageFamilyName;PackageFullName=$entry.PackageFullName
            IsBundle=($entry.PackageFullName -cmatch '_neutral_~_8wekyb3d8bbwe$')
        }
    })
    $parents = @(Get-NoIDXboxAppRemovalInventory -Packages $packages)
    if ($parents.Count -ne $Entries.Count) { throw 'Xbox removal request contains a child package instead of its Bundle parent' }
}

function Invoke-NoIDXboxAppRemoval {
    <#
    .SYNOPSIS
        Removes only the sealed Xbox parents using Privacy's original-user worker.
    .DESCRIPTION
        Shares Privacy's complete identity checks, bounded execution, independent
        AppX postcondition and preservation of other users' app firewall rules.
        Gaming Services and games cannot enter the removal request. Already
        absent apps need no worker. A new package/version is rejected before
        removal instead of silently expanding the selected scope.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]$User,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [ValidateRange(30,600)][int]$TimeoutSeconds=300
    )

    Assert-NoIDXboxRemovalRequest -Entries $Entries
    $currentUser = Get-PrivacyUserContext -Refresh
    if ($User.Sid -isnot [string] -or $User.SessionId -isnot [int] -or
        $currentUser.Sid -cne $User.Sid -or $currentUser.SessionId -ne $User.SessionId) {
        throw 'Xbox removal desktop identity changed'
    }
    $null = Assert-NoIDXboxUnmanagedDevice
    $before = Get-NoIDXboxComponentSnapshot -UserSid $currentUser.Sid
    $identities = @($Entries | ForEach-Object { $_.AppName+'|'+$_.PackageFullName })
    foreach ($package in $before.RemovablePackages) {
        if (($package.AppName+'|'+$package.PackageFullName) -cnotin $identities) {
            throw 'Xbox package inventory changed before removal; refresh its measured state'
        }
    }
    if (-not $PSCmdlet.ShouldProcess('Six Xbox app families for the current desktop user', 'Remove the measured Xbox apps; keep shared Gaming Services and games')) { return }
    $record = $null
    if (@($before.RemovablePackages).Count -gt 0) {
        try {
            $record = Invoke-PrivacyUserAppxRemoval -User $currentUser -Entries $Entries -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            # The shared removal engine can throw after a failed stop or
            # cleanup. A missing quiescence verdict must never authorize a
            # competing settings rollback while a worker could still mutate.
            if (-not $_.Exception.Data.Contains('WorkerQuiesced')) {
                $_.Exception.Data['WorkerQuiesced'] = $false
            }
            throw
        }
    }
    $after = Get-NoIDXboxComponentSnapshot -UserSid $currentUser.Sid
    $remaining = @($after.Apps | Where-Object {
        $_.Name -cin @((Get-NoIDXboxComponentCatalog).Apps | Where-Object RemoveWhenDisabled | ForEach-Object Name) -and $_.Present
    })
    return [pscustomobject][ordered]@{
        SchemaVersion=1
        Success=($remaining.Count -eq 0 -and ($null -eq $record -or [bool]$record.Success))
        AlreadyAbsent=($null -eq $record)
        RemainingApps=@($remaining | ForEach-Object Name)
        Entries=$(if ($null -eq $record) { @() } else { @($record.Entries) })
    }
}
