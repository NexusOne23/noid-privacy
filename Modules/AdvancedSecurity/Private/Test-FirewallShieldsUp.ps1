function Test-FirewallShieldsUp {
    <#
    .SYNOPSIS
        Test if Firewall Shields Up mode is enabled

    .DESCRIPTION
        Checks both the exact owned registry value and the effective ActiveStore
        Public firewall profile.
        Shields Up is an optional Maximum-profile feature. This helper only
        reports the live state (Pass/IsEnabled); the "intentionally not
        selected" case is decided by the caller, which gates this check on
        the Maximum profile and reports NotChecked otherwise.
    #>
    [CmdletBinding()]
    param()

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
    $valueName = "DoNotAllowExceptions"

    try {
        $key = if (Test-Path -LiteralPath $regPath -PathType Container) {
            Get-Item -LiteralPath $regPath -ErrorAction Stop
        } else { $null }
        $exists = $key -and $key.GetValueNames() -contains $valueName
        $value = if ($exists) { $key.GetValue($valueName) } else { $null }

        if (-not $exists -or $key.GetValueKind($valueName).ToString() -ne 'DWord' -or [int]$value -ne 1) {
            return @{
                Pass         = $false
                Message      = "Shields Up is not enabled"
                CurrentValue = if (-not $exists) { "Not Set" } else { $value }
                IsEnabled    = $false
            }
        }

        $effectiveProfile = @(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
        if ($effectiveProfile.Count -ne 1 -or
            [string]$effectiveProfile[0].DefaultInboundAction -ne 'Block' -or
            [string]$effectiveProfile[0].AllowInboundRules -ne 'False') {
            return @{
                Pass         = $false
                Message      = 'Shields Up registry value exists, but the effective Public firewall profile does not block all inbound traffic'
                CurrentValue = $value
                IsEnabled    = $false
            }
        }

        return @{
            Pass         = $true
            Message      = "Shields Up ENABLED (Public network blocks ALL incoming)"
            CurrentValue = 1
            IsEnabled    = $true
        }
    }
    catch {
        return @{
            Pass         = $false
            Message      = "Error checking Shields Up: $_"
            CurrentValue = "Error"
            IsEnabled    = $false
        }
    }
}
