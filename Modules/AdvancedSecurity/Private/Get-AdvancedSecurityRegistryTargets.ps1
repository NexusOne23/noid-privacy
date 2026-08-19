function Get-AdvancedSecurityRegistryTargets {
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

    function Add-ManagedValue {
        param([string]$Path, [string]$Name)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $Name; KeyOnly = $false })
    }

    function Add-ManagedKey {
        param([string]$Path)
        $targets.Add([PSCustomObject]@{ Path = $Path; Name = $null; KeyOnly = $true })
    }

    if ($RdpHostSupported) {
        Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer'
        if ($DisableRDP) {
            Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        }
    }
    if ($AdminSharesDisabled) {
        Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
        Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
    }

    foreach ($version in @('TLS 1.0', 'TLS 1.1')) {
        Add-ManagedKey "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version"
        foreach ($component in @('Server', 'Client')) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
            Add-ManagedValue $path 'Enabled'
            Add-ManagedValue $path 'DisabledByDefault'
        }
    }

    if ($DisableDiscoveryProtocolsCompletely) {
        Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    }
    Add-ManagedValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'

    if ($ManagedPolicySupported) {
        Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'SetAllowOptionalContent'
    }
    Add-ManagedValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'IsContinuousInnovationOptedIn'
    if ($ManagedPolicySupported) {
        Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'
    }

    Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'DefaultLevel'
    Add-ManagedValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'TransparentEnabled'
    $srpRuleIds = @(
        '{1D73F334-6A40-4A48-92B4-3C68B7F1D101}'
        '{1D73F334-6A40-4A48-92B4-3C68B7F1D102}'
    )
    Add-ManagedKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    Add-ManagedKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0'
    Add-ManagedKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths'
    foreach ($ruleId in $srpRuleIds) {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\$ruleId"
        Add-ManagedValue $path 'ItemData'
        Add-ManagedValue $path 'Description'
        Add-ManagedValue $path 'SaferFlags'
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
            Add-ManagedValue $connectPath $name
        }
    }

    if ($DisableIPv6Completely) {
        Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
    }
    if (-not $SkipFirewallLayer -and $EnableFirewallShieldsUp) {
        Add-ManagedValue 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' 'DoNotAllowExceptions'
    }

    return @($targets)
}
