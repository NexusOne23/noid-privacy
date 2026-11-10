function Set-FirewallShieldsUp {
    <#
    .SYNOPSIS
        Enable "Shields Up" mode - Block unsolicited inbound traffic on Public

    .DESCRIPTION
        Uses the documented NetSecurity profile API to ignore Public-profile
        inbound rules. With the required Block default inbound action,
        this blocks unsolicited inbound traffic, including app exceptions.
        Replies to locally initiated traffic remain possible.
        Goes BEYOND Microsoft Security Baseline.

    .PARAMETER Enable
        Enable Shields Up mode (block unsolicited inbound traffic on Public)

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

            # Microsoft documents AllowInboundRules=False as ignoring all
            # inbound rules. It only constitutes Shields Up while the effective
            # default inbound action is Block, so prove that prerequisite before
            # mutation and then verify the ActiveStore (effective) view.
            $beforeProfile = @(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop)
            if ($beforeProfile.Count -ne 1 -or
                [string]$beforeProfile[0].Enabled -ne 'True' -or
                [string]$beforeProfile[0].DefaultInboundAction -ne 'Block') {
                throw 'Public firewall must be effectively enabled with DefaultInboundAction Block; refusing to claim Shields Up'
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
                [string]$effectiveProfile[0].Enabled -ne 'True' -or
                [string]$effectiveProfile[0].DefaultInboundAction -ne 'Block' -or
                [string]$effectiveProfile[0].AllowInboundRules -ne 'False') {
                throw 'Shields Up effective firewall profile verification failed'
            }

            Write-Log -Level SUCCESS -Message "Firewall Shields Up ENABLED - Unsolicited inbound traffic blocked on Public network" -Module $moduleName
            Write-NoIDDetail ""
            Write-NoIDDetail "  SHIELDS UP: Public network blocks unsolicited inbound traffic" -ForegroundColor Green
            Write-NoIDDetail "  Inbound app exceptions are ignored; replies to locally initiated traffic remain possible" -ForegroundColor Gray
            Write-NoIDDetail ""

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
