function Get-AdvancedSecuritySchema7RegistryTargets {
    <#
    .SYNOPSIS
        Returns the immutable registry-target contract for sealed schema-7
        AdvancedSecurity artifacts.

    .DESCRIPTION
        Restore validation must remain independent of the current Apply
        inventory. This helper is therefore a frozen compatibility allowlist:
        future target additions or changed Apply values require a new snapshot
        schema and must not modify this function. Schema 7 owns the Delivery
        Optimization policy on every edition, Home included.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipFirewallLayer,
        [switch]$DisableRDP,
        [switch]$AdminSharesDisabled,
        [switch]$DisableDiscoveryProtocolsCompletely,
        [switch]$DisableIPv6Completely,
        [switch]$EnableFirewallShieldsUp,
        [bool]$RdpHostSupported = $true,
        [bool]$ManagedPolicySupported = $true,
        [bool]$WirelessDisplaySupported = $true
    )

    $targets = [System.Collections.Generic.List[object]]::new()

    function Add-Schema7Value {
        param([string]$Path, [string]$Name)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $Name; KeyOnly = $false })
    }

    function Add-Schema7Key {
        param([string]$Path)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $null; KeyOnly = $true })
    }

    if ($RdpHostSupported) {
        Add-Schema7Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        Add-Schema7Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer'
        if ($DisableRDP) {
            Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        }
    }
    if ($AdminSharesDisabled) {
        Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
        Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
    }

    foreach ($version in @('TLS 1.0', 'TLS 1.1')) {
        Add-Schema7Key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version"
        foreach ($component in @('Server', 'Client')) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
            Add-Schema7Value $path 'Enabled'
            Add-Schema7Value $path 'DisabledByDefault'
        }
    }

    if ($DisableDiscoveryProtocolsCompletely) {
        Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    }
    Add-Schema7Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'

    if ($ManagedPolicySupported) {
        Add-Schema7Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'SetAllowOptionalContent'
        Add-Schema7Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'AllowOptionalContent'
    }
    Add-Schema7Value 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'IsContinuousInnovationOptedIn'
    Add-Schema7Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'

    if ($WirelessDisplaySupported) {
        $connectPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        # Only these two Connect values are Group Policy-backed. The complete
        # Wireless Display choice adds the service, adapters and firewall rules.
        foreach ($name in @('AllowProjectionToPC', 'RequirePinForPairing')) {
            Add-Schema7Value $connectPath $name
        }
    }

    if ($DisableIPv6Completely) {
        Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
    }
    if (-not $SkipFirewallLayer -and $EnableFirewallShieldsUp) {
        Add-Schema7Value 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' 'DoNotAllowExceptions'
    }

    return @($targets)
}
