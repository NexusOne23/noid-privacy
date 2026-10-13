function Get-AdvancedSecuritySchema5RegistryTargets {
    <#
    .SYNOPSIS
        Returns the immutable registry-target contract for sealed schema-5
        AdvancedSecurity artifacts.

    .DESCRIPTION
        Restore validation must remain independent of the current Apply
        inventory. This helper is therefore a frozen compatibility allowlist:
        future target additions or changed Apply values require a new snapshot
        schema and must not modify this function.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipFirewallLayer,
        [switch]$DisableRDP,
        [switch]$AdminSharesDisabled,
        [switch]$DisableWirelessDisplayCompletely,
        [switch]$DisableDiscoveryProtocolsCompletely,
        [switch]$DisableIPv6Completely,
        [switch]$EnableFirewallShieldsUp,
        [bool]$RdpHostSupported = $true,
        [bool]$ManagedPolicySupported = $true,
        [bool]$WirelessDisplaySupported = $true
    )

    $targets = [System.Collections.Generic.List[object]]::new()

    function Add-Schema5Value {
        param([string]$Path, [string]$Name)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $Name; KeyOnly = $false })
    }

    function Add-Schema5Key {
        param([string]$Path)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $null; KeyOnly = $true })
    }

    if ($RdpHostSupported) {
        Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer'
        if ($DisableRDP) {
            Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        }
    }
    if ($AdminSharesDisabled) {
        Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
        Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
    }

    foreach ($version in @('TLS 1.0', 'TLS 1.1')) {
        Add-Schema5Key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version"
        foreach ($component in @('Server', 'Client')) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
            Add-Schema5Value $path 'Enabled'
            Add-Schema5Value $path 'DisabledByDefault'
        }
    }

    if ($DisableDiscoveryProtocolsCompletely) {
        Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    }
    Add-Schema5Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'

    if ($ManagedPolicySupported) {
        Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'SetAllowOptionalContent'
    }
    Add-Schema5Value 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'IsContinuousInnovationOptedIn'
    if ($ManagedPolicySupported) {
        Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'
    }

    Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'DefaultLevel'
    Add-Schema5Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'TransparentEnabled'
    Add-Schema5Key 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    Add-Schema5Key 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0'
    Add-Schema5Key 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths'
    foreach ($ruleId in @(
            '{1D73F334-6A40-4A48-92B4-3C68B7F1D101}',
            '{1D73F334-6A40-4A48-92B4-3C68B7F1D102}'
        )) {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\$ruleId"
        Add-Schema5Value $path 'ItemData'
        Add-Schema5Value $path 'Description'
        Add-Schema5Value $path 'SaferFlags'
    }

    if ($WirelessDisplaySupported) {
        $connectPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        $wirelessDisplayValues = @('AllowProjectionToPC', 'RequirePinForPairing')
        if ($DisableWirelessDisplayCompletely) {
            $wirelessDisplayValues += @(
                'AllowProjectionFromPC', 'AllowMdnsAdvertisement', 'AllowMdnsDiscovery',
                'AllowProjectionFromPCOverInfrastructure', 'AllowProjectionToPCOverInfrastructure'
            )
        }
        foreach ($name in $wirelessDisplayValues) {
            Add-Schema5Value $connectPath $name
        }
    }

    if ($DisableIPv6Completely) {
        Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
    }
    if (-not $SkipFirewallLayer -and $EnableFirewallShieldsUp) {
        Add-Schema5Value 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' 'DoNotAllowExceptions'
    }

    return @($targets)
}
