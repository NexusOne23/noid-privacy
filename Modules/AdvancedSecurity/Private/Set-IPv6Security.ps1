function Set-IPv6Security {
    <#
    .SYNOPSIS
        Configure the opt-in 0xFF IPv6 component-disable state.

    .DESCRIPTION
        Writes DisabledComponents=0xFF only after the explicit Maximum-profile
        choice. Microsoft documents 0xFF as disabling IPv6, while also warning
        that IPv6 cannot be completely disabled because Windows retains internal
        IPv6 functionality such as loopback. Microsoft does not recommend this
        configuration and recommends 0x20 (prefer IPv4) instead for normal use.

        The reduced network-facing IPv6 surface can limit DHCPv6/RA attack paths,
        but this registry state alone is not proof of complete mitm6 prevention.

        WARNING: Windows components and products that expect IPv6 can fail.

    .PARAMETER DisableCompletely
        If true, writes the documented broad-disable value 0xFF. The parameter
        name is retained for compatibility; internal IPv6/loopback remains.

    .EXAMPLE
        Set-IPv6Security -DisableCompletely

    .NOTES
        Registry: HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents
        Value 0xFF = documented IPv6 disable state; internal IPv6 remains

        REBOOT REQUIRED for changes to take effect.

        References:
        - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
        - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$DisableCompletely
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set IPv6Security')) {
        return
    }


    try {
        if (-not $DisableCompletely) {
            Write-Log -Level INFO -Message "IPv6 disable not requested - keeping default configuration" -Module "AdvancedSecurity"
            return $true
        }

        Write-Log -Level INFO -Message "Applying opt-in IPv6 component-disable state (DisabledComponents=0xFF); Microsoft recommends keeping IPv6 enabled for normal use" -Module "AdvancedSecurity"

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"

        # The targeted registry pre-state was sealed before Apply.
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }

        # Microsoft documents 0xFF as the IPv6-disable value, but also states
        # that Windows retains internal IPv6 functionality such as loopback.
        Remove-ItemProperty -LiteralPath $regPath -Name 'DisabledComponents' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $regPath -Name 'DisabledComponents' -Value 255 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

        Write-Log -Level SUCCESS -Message "IPv6 component-disable value applied (DisabledComponents = 0xFF)" -Module "AdvancedSecurity"

        # Verify
        $ipv6Key = Get-Item -LiteralPath $regPath -ErrorAction Stop
        $verifyValue = $ipv6Key.GetValue('DisabledComponents')
        if ($ipv6Key.GetValueKind('DisabledComponents').ToString() -eq 'DWord' -and $verifyValue -eq 255) {
            Write-Log -Level SUCCESS -Message "IPv6 component-disable registry state verified - REBOOT REQUIRED" -Module "AdvancedSecurity"

            Write-Host ""
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host "  IPv6 COMPONENT DISABLE SELECTED (0xFF)" -ForegroundColor Yellow
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Registry: DisabledComponents = 0xFF (255)" -ForegroundColor White
            Write-Host ""
            Write-Host "Exact boundary:" -ForegroundColor Cyan
            Write-Host "  - Reduces network-facing DHCPv6/RA attack surface after reboot" -ForegroundColor Gray
            Write-Host "  - Does not disable Windows' internal IPv6/loopback functionality" -ForegroundColor Gray
            Write-Host "  - Does not by itself prove complete mitm6/NTLM-relay prevention" -ForegroundColor Gray
            Write-Host "  - Microsoft recommends keeping IPv6 enabled for normal use" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "REBOOT REQUIRED for changes to take effect!" -ForegroundColor Red
            Write-Host ""

            return $true
        }
        else {
            Write-Log -Level ERROR -Message "IPv6 component-disable registry verification failed" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure IPv6 component-disable state: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
