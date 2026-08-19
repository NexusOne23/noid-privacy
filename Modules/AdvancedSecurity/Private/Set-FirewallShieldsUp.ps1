function Set-FirewallShieldsUp {
    <#
    .SYNOPSIS
        Enable "Shields Up" mode - Block ALL incoming connections on Public network

    .DESCRIPTION
        Uses the documented NetSecurity profile API to disable Public-profile
        inbound allow rules. With the required Block default inbound action,
        this blocks ALL incoming connections, even from allowed apps.
        Goes BEYOND Microsoft Security Baseline.

    .PARAMETER Enable
        Enable Shields Up mode (block all incoming on Public)

    .PARAMETER Disable
        Disable Shields Up mode (allow configured exceptions)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$Enable,
        [switch]$Disable
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set FirewallShieldsUp')) {
        return
    }


    $moduleName = "AdvancedSecurity"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
    $valueName = "DoNotAllowExceptions"

    try {
        if ($Enable) {
            Write-Log -Level INFO -Message "Enabling Firewall Shields Up mode (Public profile)..." -Module $moduleName

            # Microsoft documents AllowInboundRules=False as ignoring inbound
            # allow rules. It only constitutes Shields Up while the effective
            # default inbound action is Block, so prove that prerequisite before
            # mutation and then verify the ActiveStore (effective) view.
            $beforeProfile = @(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
            if ($beforeProfile.Count -ne 1 -or
                [string]$beforeProfile[0].DefaultInboundAction -ne 'Block') {
                throw 'Public firewall effective DefaultInboundAction is not Block; refusing to claim Shields Up'
            }
            Set-NetFirewallProfile -Profile Public -AllowInboundRules False -ErrorAction Stop

            # Preserve the exact registry/type contract used by BAVR while also
            # requiring the effective firewall engine view below.
            $key = Get-Item -LiteralPath $regPath -ErrorAction Stop
            if ($key.GetValueKind($valueName).ToString() -ne 'DWord' -or [int]$key.GetValue($valueName) -ne 1) {
                throw 'Shields Up registry post-apply mismatch'
            }
            $effectiveProfile = @(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
            if ($effectiveProfile.Count -ne 1 -or
                [string]$effectiveProfile[0].DefaultInboundAction -ne 'Block' -or
                [string]$effectiveProfile[0].AllowInboundRules -ne 'False') {
                throw 'Shields Up effective firewall profile verification failed'
            }

            Write-Log -Level SUCCESS -Message "Firewall Shields Up ENABLED - All incoming connections blocked on Public network" -Module $moduleName
            Write-Host ""
            Write-Host "  SHIELDS UP: Public network now blocks ALL incoming connections" -ForegroundColor Green
            Write-Host "  This includes allowed apps (Teams, Discord, etc. cannot receive calls)" -ForegroundColor Yellow
            Write-Host ""

            return $true
        }
        elseif ($Disable) {
            Write-Log -Level INFO -Message "Disabling Firewall Shields Up mode..." -Module $moduleName

            Set-NetFirewallProfile -Profile Public -AllowInboundRules True -ErrorAction Stop

            $key = Get-Item -LiteralPath $regPath -ErrorAction Stop
            if ($key.GetValueKind($valueName).ToString() -ne 'DWord' -or [int]$key.GetValue($valueName) -ne 0) {
                throw 'Shields Up disable registry post-apply mismatch'
            }
            $effectiveProfile = @(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
            if ($effectiveProfile.Count -ne 1 -or
                [string]$effectiveProfile[0].AllowInboundRules -ne 'True') {
                throw 'Shields Up disable effective firewall profile verification failed'
            }

            Write-Log -Level SUCCESS -Message "Firewall Shields Up disabled - Normal firewall exceptions apply" -Module $moduleName
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "No action specified for Set-FirewallShieldsUp" -Module $moduleName
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set Firewall Shields Up: $_" -Module $moduleName
        return $false
    }
}
