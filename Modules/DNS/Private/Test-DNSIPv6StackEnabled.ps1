#Requires -Version 5.1

function Test-DNSIPv6StackEnabled {
    <#
    .SYNOPSIS
        Report whether the global IPv6 stack is effectively enabled.

    .DESCRIPTION
        AdvancedSecurity's opt-in IPv6 disable writes the documented
        DisabledComponents=0xFF value, which turns the IPv6 transport off
        without changing the per-adapter ms_tcpip6 binding. Effective IPv6
        resolver mutation is outside scope in that state; the independently
        sealed native DNS_INTERFACE_SETTINGS3 state can remain in scope so
        Windows Settings represents persisted IPv6 resolvers accurately.
        Only the exact documented full-disable mask is honored; every other
        DisabledComponents value keeps effective IPv6 resolution in scope.

    .OUTPUTS
        [bool] $true when IPv6 is effectively enabled, $false when the
        documented full-disable mask is active.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $parametersKey = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction SilentlyContinue
    if (-not $parametersKey) { return $true }
    try {
        if ($parametersKey.GetValueNames() -notcontains 'DisabledComponents') { return $true }
        return ((([long]$parametersKey.GetValue('DisabledComponents')) -band 0xFF) -ne 0xFF)
    }
    finally {
        $parametersKey.Close()
    }
}
