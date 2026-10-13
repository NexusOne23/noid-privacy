function Test-WPAD {
    <#
    .SYNOPSIS
        Verify the documented WinHTTP and WinINet WPAD controls.
    #>
    [CmdletBinding()]
    param(
        [object[]]$WinInetUsers
    )

    try {
        $result = [PSCustomObject]@{
            Feature   = 'WPAD (Proxy Auto-Discovery)'
            Status    = 'Unknown'
            Details   = @()
            Compliant = $true
        }
        $issues = [System.Collections.Generic.List[string]]::new()

        $winHttpPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        try {
            $winHttpKey = Get-Item -LiteralPath $winHttpPath -ErrorAction Stop
            if ($winHttpKey.GetValueNames() -notcontains 'DisableWpad' -or
                $winHttpKey.GetValueKind('DisableWpad').ToString() -ne 'DWord' -or
                [int]$winHttpKey.GetValue('DisableWpad') -ne 1) {
                $issues.Add('WinHTTP DisableWpad is missing or not DWord/1')
            }
        }
        catch {
            $issues.Add("WinHTTP DisableWpad check failed: $($_.Exception.Message)")
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
            try {
                $state = Invoke-AdvancedSecurityWinInetUserState -User $user -Operation Query
                if ([bool]$state.AutoDetectEnabled) {
                    $issues.Add("WinINet AutoDetect remains enabled for SID $($user.Sid) (flags=$($state.Flags))")
                }
            }
            catch {
                $issues.Add("WinINet check failed for SID $($user.Sid): $($_.Exception.Message)")
            }
        }

        if ($issues.Count -eq 0) {
            $result.Status = 'Secure (Disabled)'
            $result.Details = @(
                'WinHTTP DisableWpad is DWord/1'
                $(if ($users.Count -gt 0) {
                    "WinINet AutoDetect is disabled for $($users.Count) interactive Explorer user target(s)"
                }
                else {
                    'No interactive Explorer user target is applicable in this session'
                })
            )
            $result.Compliant = $true
        }
        else {
            $result.Status = "Insecure ($($issues.Count) issue(s))"
            $result.Details = @($issues)
            $result.Compliant = $false
        }
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test WPAD: $_" -Module 'AdvancedSecurity'
        return [PSCustomObject]@{
            Feature='WPAD (Proxy Auto-Discovery)'; Status='Error'
            Details=@("Failed to test: $_"); Compliant=$false
        }
    }
}
