function Get-AdvancedSecuritySchema6RegistryTargets {
    <#
    .SYNOPSIS
        Returns the immutable registry-target contract for sealed schema-6
        AdvancedSecurity artifacts.

    .DESCRIPTION
        Restore validation must remain independent of the current Apply
        inventory. This helper is therefore a frozen compatibility allowlist:
        future target additions or changed Apply values require a new snapshot
        schema and must not modify this function. Schema 6 adds
        AllowOptionalContent and no longer contains the legacy SRP values or
        the five Wireless Display values that are not Group Policy-backed.
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

    function Add-Schema6Value {
        param([string]$Path, [string]$Name)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $Name; KeyOnly = $false })
    }

    function Add-Schema6Key {
        param([string]$Path)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $null; KeyOnly = $true })
    }

    if ($RdpHostSupported) {
        Add-Schema6Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        Add-Schema6Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer'
        if ($DisableRDP) {
            Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        }
    }
    if ($AdminSharesDisabled) {
        Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
        Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
    }

    foreach ($version in @('TLS 1.0', 'TLS 1.1')) {
        Add-Schema6Key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version"
        foreach ($component in @('Server', 'Client')) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
            Add-Schema6Value $path 'Enabled'
            Add-Schema6Value $path 'DisabledByDefault'
        }
    }

    if ($DisableDiscoveryProtocolsCompletely) {
        Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    }
    Add-Schema6Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'

    if ($ManagedPolicySupported) {
        Add-Schema6Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'SetAllowOptionalContent'
        Add-Schema6Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'AllowOptionalContent'
    }
    Add-Schema6Value 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'IsContinuousInnovationOptedIn'
    if ($ManagedPolicySupported) {
        Add-Schema6Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'
    }

    if ($WirelessDisplaySupported) {
        $connectPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        # Only these two Connect values are Group Policy-backed. The complete
        # Wireless Display choice adds the service, adapters and firewall rules.
        foreach ($name in @('AllowProjectionToPC', 'RequirePinForPairing')) {
            Add-Schema6Value $connectPath $name
        }
    }

    if ($DisableIPv6Completely) {
        Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
    }
    if (-not $SkipFirewallLayer -and $EnableFirewallShieldsUp) {
        Add-Schema6Value 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' 'DoNotAllowExceptions'
    }

    return @($targets)
}
