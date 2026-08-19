function Disable-WPAD {
    <#
    .SYNOPSIS
        Disable WPAD through the documented WinHTTP and WinINet control planes.

    .DESCRIPTION
        Sets Microsoft's documented machine-wide WinHTTP DisableWpad value and
        clears PROXY_TYPE_AUTO_DETECT through the documented WinINet API in the
        actual Explorer user's token. Other proxy flags are preserved.

        Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features
        Reference: https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags

        Undocumented scalar AutoDetect/WpadOverride values and HKU\.DEFAULT are
        deliberately not used. HKU\.DEFAULT is the logon desktop profile, not
        the Default User template.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [object[]]$WinInetUsers
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable WPAD')) {
        return
    }

    try {
        Write-Log -Level INFO -Message 'Disabling WPAD through WinHTTP and WinINet...' -Module 'AdvancedSecurity'

        $winHttpPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        if (-not (Test-Path -LiteralPath $winHttpPath -PathType Container)) {
            New-Item -Path $winHttpPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $winHttpPath -Name 'DisableWpad' -Value 1 `
            -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        $winHttpKey = Get-Item -LiteralPath $winHttpPath -ErrorAction Stop
        if ($winHttpKey.GetValueNames() -notcontains 'DisableWpad' -or
            $winHttpKey.GetValueKind('DisableWpad').ToString() -ne 'DWord' -or
            [int]$winHttpKey.GetValue('DisableWpad') -ne 1) {
            throw 'WinHTTP DisableWpad post-apply verification failed'
        }

        $users = @()
        if ($PSBoundParameters.ContainsKey('WinInetUsers')) {
            $users = @($WinInetUsers)
        }
        else {
            $currentUser = Get-AdvancedSecurityInteractiveUser -AllowNone
            if ($null -ne $currentUser) {
                $users = @($currentUser)
            }
        }

        foreach ($user in $users) {
            foreach ($property in @('Sid', 'SessionId')) {
                if (-not $user.PSObject.Properties[$property]) {
                    throw "WinINet target is missing '$property'"
                }
            }
            $setResult = Invoke-AdvancedSecurityWinInetUserState `
                -User $user `
                -Operation SetAutoDetect `
                -AutoDetectEnabled:$false
            if ([bool]$setResult.AutoDetectEnabled) {
                throw "WinINet AutoDetect remains enabled for SID $($user.Sid)"
            }
            Write-Log -Level DEBUG -Message "WinINet AutoDetect disabled for Explorer SID $($user.Sid); flags $($setResult.BeforeFlags) -> $($setResult.Flags)" -Module 'AdvancedSecurity'
        }

        if ($users.Count -eq 0) {
            Write-Log -Level INFO -Message 'No interactive Explorer user is present; the user-side WinINet target is NotApplicable for this run' -Module 'AdvancedSecurity'
        }
        Write-Log -Level SUCCESS -Message "WPAD disabled and verified (WinHTTP machine control + $($users.Count) interactive WinINet user target(s))" -Module 'AdvancedSecurity'
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable WPAD: $_" -Module 'AdvancedSecurity' -Exception $_.Exception
        return $false
    }
}
