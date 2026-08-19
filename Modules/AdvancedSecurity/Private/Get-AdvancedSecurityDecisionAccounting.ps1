#Requires -Version 5.1

function Get-AdvancedSecurityDecisionAccounting {
    <#
    .SYNOPSIS
        Reconciles one frozen AdvancedSecurity decision set against the
        canonical declared check counts for Apply, DryRun, and reporting.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Balanced', 'Enterprise', 'Maximum')]
        [string]$SecurityProfile,
        [Parameter(Mandatory = $true)][bool]$SkipFirewallLayer,
        [Parameter(Mandatory = $true)][bool]$DisableRDP,
        [Parameter(Mandatory = $true)][bool]$AdminSharesSelected,
        [Parameter(Mandatory = $true)][bool]$DisableUPnP,
        [Parameter(Mandatory = $true)][bool]$DisableWirelessDisplayCompletely,
        [Parameter(Mandatory = $true)][bool]$DisableDiscoveryProtocolsCompletely,
        [Parameter(Mandatory = $true)][bool]$DisableIPv6Completely,
        [Parameter(Mandatory = $true)][bool]$RdpHostSupported,
        [Parameter(Mandatory = $true)][bool]$ManagedPolicySupported,
        [Parameter(Mandatory = $true)][bool]$WirelessDisplaySupported,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1000)][int]$DeclaredCount,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1000)][int]$FirewallDeclaredCount,
        [bool]$LmhostsPresent = $true,
        [bool]$SsdpSrvPresent = $true,
        [bool]$UpnpHostPresent = $true,
        [bool]$FdResPubPresent = $true,
        [bool]$FdPHostPresent = $true,
        [bool]$WfdServicePresent = $true,
        [bool]$WfdAdapterPresent = $true,
        [bool]$WinInetUserPresent = $true
    )

    if ($FirewallDeclaredCount -gt $DeclaredCount) {
        throw 'Canonical AdvancedSecurity setting counts are invalid'
    }

    # Build one explicit row per declared verifier target. Counts are derived
    # from this closed inventory; no residual "declared minus everything else"
    # bucket can hide a stale increment or a newly added target.
    $targets = [System.Collections.Generic.List[object]]::new()
    function Add-DecisionTarget {
        param(
            [Parameter(Mandatory)][string]$Id,
            [Parameter(Mandatory)][bool]$Selected,
            [Parameter(Mandatory)][bool]$Applicable,
            [Parameter(Mandatory)][bool]$Firewall,
            [ValidateSet('Static','Edition','Runtime')][string]$ApplicabilitySource = 'Static'
        )
        $targets.Add([PSCustomObject]@{
                Id = $Id
                Selected = $Selected
                Applicable = $Applicable
                Firewall = $Firewall
                ApplicabilitySource = $ApplicabilitySource
            })
    }

    foreach ($id in @('RDP.SecurityLayer','RDP.UserAuthentication')) {
        Add-DecisionTarget $id $true $RdpHostSupported $false 'Edition'
    }
    Add-DecisionTarget 'RDP.Disable' $DisableRDP $RdpHostSupported $false 'Edition'
    foreach ($id in @('AdminShares.AutoShareWks','AdminShares.AutoShareServer')) {
        Add-DecisionTarget $id $AdminSharesSelected $true $false
    }
    foreach ($version in @('1.0','1.1')) {
        foreach ($side in @('Server','Client')) {
            foreach ($valueName in @('Enabled','DisabledByDefault')) {
                Add-DecisionTarget "TLS.$version.$side.$valueName" $true $true $false
            }
        }
    }
    Add-DecisionTarget 'Service.lmhosts' $true $LmhostsPresent $false 'Runtime'
    Add-DecisionTarget 'Service.SSDPSRV' $DisableUPnP $SsdpSrvPresent $false 'Runtime'
    Add-DecisionTarget 'Service.upnphost' $DisableUPnP $UpnpHostPresent $false 'Runtime'
    Add-DecisionTarget 'WPAD.WinHTTP' $true $true $false
    Add-DecisionTarget 'WPAD.WinINet' $true $WinInetUserPresent $false 'Runtime'
    foreach ($id in @(
            'SRP.DefaultLevel','SRP.TransparentEnabled',
            'SRP.Rule1.ItemData','SRP.Rule1.Description','SRP.Rule1.SaferFlags',
            'SRP.Rule2.ItemData','SRP.Rule2.Description','SRP.Rule2.SaferFlags'
        )) {
        Add-DecisionTarget $id $true $true $false
    }

    $discoverySelected = ($SecurityProfile -eq 'Maximum' -and $DisableDiscoveryProtocolsCompletely)
    Add-DecisionTarget 'Discovery.EnableMDNS' $discoverySelected $true $false
    Add-DecisionTarget 'Discovery.FDResPub' $discoverySelected $FdResPubPresent $false 'Runtime'
    Add-DecisionTarget 'Discovery.fdPHost' $discoverySelected $FdPHostPresent $false 'Runtime'
    Add-DecisionTarget 'WindowsUpdate.SetAllowOptionalContent' $true $ManagedPolicySupported $false 'Edition'
    Add-DecisionTarget 'WindowsUpdate.ContinuousInnovation' $true $true $false
    Add-DecisionTarget 'WindowsUpdate.DODownloadMode' $true $ManagedPolicySupported $false 'Edition'
    Add-DecisionTarget 'NetBIOS.Adapters' $true $true $false

    foreach ($id in @('WirelessDisplay.AllowProjectionToPC','WirelessDisplay.RequirePinForPairing')) {
        Add-DecisionTarget $id $true $WirelessDisplaySupported $false 'Edition'
    }
    foreach ($id in @(
            'WirelessDisplay.AllowProjectionFromPC','WirelessDisplay.AllowMdnsAdvertisement',
            'WirelessDisplay.AllowMdnsDiscovery','WirelessDisplay.AllowProjectionFromPCOverInfrastructure',
            'WirelessDisplay.AllowProjectionToPCOverInfrastructure'
        )) {
        Add-DecisionTarget $id $DisableWirelessDisplayCompletely $WirelessDisplaySupported $false 'Edition'
    }
    Add-DecisionTarget 'WirelessDisplay.WFDSConMgrSvc' $DisableWirelessDisplayCompletely `
        ($WirelessDisplaySupported -and $WfdServicePresent) $false `
        $(if ($WirelessDisplaySupported) { 'Runtime' } else { 'Edition' })
    Add-DecisionTarget 'WirelessDisplay.Adapters' $DisableWirelessDisplayCompletely `
        ($WirelessDisplaySupported -and $WfdAdapterPresent) $false `
        $(if ($WirelessDisplaySupported) { 'Runtime' } else { 'Edition' })
    Add-DecisionTarget 'IPv6.DisabledComponents' `
        ($SecurityProfile -eq 'Maximum' -and $DisableIPv6Completely) $true $false

    $firewallDefinitions = @(Get-AdvancedSecurityFirewallDefinitions)
    foreach ($definition in $firewallDefinitions) {
        $selected = switch ([string]$definition.Group) {
            'UPnP' { $DisableUPnP }
            'AdminShares' { $AdminSharesSelected }
            'Discovery' { $discoverySelected }
            'Miracast' { $DisableWirelessDisplayCompletely }
            default { $true }
        }
        $applicable = -not ([string]$definition.Group -eq 'Miracast' -and -not $WirelessDisplaySupported)
        Add-DecisionTarget "Firewall.$($definition.Name)" $selected $applicable $true `
            $(if ([string]$definition.Group -eq 'Miracast') { 'Edition' } else { 'Static' })
    }
    Add-DecisionTarget 'Firewall.ShieldsUp' ($SecurityProfile -eq 'Maximum') $true $true

    $duplicateTargets = @($targets | Group-Object Id | Where-Object Count -ne 1)
    $actualFirewallCount = @($targets | Where-Object Firewall).Count
    if ($duplicateTargets.Count -gt 0 -or $targets.Count -ne $DeclaredCount -or
        $actualFirewallCount -ne $FirewallDeclaredCount) {
        throw "AdvancedSecurity target inventory drift: total=$($targets.Count)/$DeclaredCount, firewall=$actualFirewallCount/$FirewallDeclaredCount, duplicates=$($duplicateTargets.Name -join ',')"
    }

    # Bind every selected registry-backed decision row to the exact canonical
    # Apply/restore inventory. Totals alone cannot detect a remove+add swap that
    # happens to preserve the same count.
    $registryIdentityByDecisionId = @{
        'RDP.SecurityLayer' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`0SecurityLayer"
        'RDP.UserAuthentication' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`0UserAuthentication"
        'RDP.Disable' = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server`0fDenyTSConnections"
        'AdminShares.AutoShareWks' = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`0AutoShareWks"
        'AdminShares.AutoShareServer' = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`0AutoShareServer"
        'WPAD.WinHTTP' = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`0DisableWpad"
        'Discovery.EnableMDNS' = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`0EnableMDNS"
        'WindowsUpdate.SetAllowOptionalContent' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`0SetAllowOptionalContent"
        'WindowsUpdate.ContinuousInnovation' = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`0IsContinuousInnovationOptedIn"
        'WindowsUpdate.DODownloadMode' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`0DODownloadMode"
        'SRP.DefaultLevel' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`0DefaultLevel"
        'SRP.TransparentEnabled' = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`0TransparentEnabled"
        'IPv6.DisabledComponents' = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`0DisabledComponents"
        'Firewall.ShieldsUp' = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`0DoNotAllowExceptions"
    }
    foreach ($version in @('1.0','1.1')) {
        foreach ($side in @('Server','Client')) {
            foreach ($valueName in @('Enabled','DisabledByDefault')) {
                $registryIdentityByDecisionId["TLS.$version.$side.$valueName"] =
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS $version\$side`0$valueName"
            }
        }
    }
    $srpRuleIds = @(
        '{1D73F334-6A40-4A48-92B4-3C68B7F1D101}',
        '{1D73F334-6A40-4A48-92B4-3C68B7F1D102}'
    )
    for ($ruleIndex = 0; $ruleIndex -lt $srpRuleIds.Count; $ruleIndex++) {
        foreach ($valueName in @('ItemData','Description','SaferFlags')) {
            $registryIdentityByDecisionId["SRP.Rule$($ruleIndex + 1).$valueName"] =
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\$($srpRuleIds[$ruleIndex])`0$valueName"
        }
    }
    foreach ($valueName in @(
            'AllowProjectionToPC','RequirePinForPairing','AllowProjectionFromPC',
            'AllowMdnsAdvertisement','AllowMdnsDiscovery',
            'AllowProjectionFromPCOverInfrastructure','AllowProjectionToPCOverInfrastructure'
        )) {
        $registryIdentityByDecisionId["WirelessDisplay.$valueName"] =
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect`0$valueName"
    }

    $decisionRegistryIdentities = @($targets | Where-Object {
            $_.Applicable -and $_.Selected -and
            -not ($_.Firewall -and $SkipFirewallLayer) -and
            $registryIdentityByDecisionId.ContainsKey([string]$_.Id)
        } | ForEach-Object {
            [string]$registryIdentityByDecisionId[[string]$_.Id]
        } | Sort-Object -Unique)
    $canonicalRegistryIdentities = @(Get-AdvancedSecurityRegistryTargets `
            -SkipFirewallLayer:$SkipFirewallLayer `
            -DisableRDP:$DisableRDP `
            -AdminSharesDisabled:$AdminSharesSelected `
            -DisableWirelessDisplayCompletely:$DisableWirelessDisplayCompletely `
            -DisableDiscoveryProtocolsCompletely:$DisableDiscoveryProtocolsCompletely `
            -DisableIPv6Completely:$DisableIPv6Completely `
            -EnableFirewallShieldsUp:($SecurityProfile -eq 'Maximum') `
            -RdpHostSupported:$RdpHostSupported `
            -ManagedPolicySupported:$ManagedPolicySupported `
            -WirelessDisplaySupported:$WirelessDisplaySupported |
        Where-Object { -not [bool]$_.KeyOnly } |
        ForEach-Object { "$([string]$_.Path)`0$([string]$_.Name)" } |
        Sort-Object -Unique)
    $registryDifference = @(Compare-Object `
            -ReferenceObject $canonicalRegistryIdentities `
            -DifferenceObject $decisionRegistryIdentities)
    if ($registryDifference.Count -ne 0) {
        throw "AdvancedSecurity decision/registry inventory identity drift: $($registryDifference.InputObject -join ', ')"
    }

    $notApplicableTargets = @($targets | Where-Object { -not $_.Applicable })
    $skippedTargets = @($targets | Where-Object { $_.Applicable -and $_.Firewall -and $SkipFirewallLayer })
    $attemptedTargets = @($targets | Where-Object {
            $_.Applicable -and -not ($_.Firewall -and $SkipFirewallLayer) -and $_.Selected
        })
    $notSelectedTargets = @($targets | Where-Object {
            $_.Applicable -and -not ($_.Firewall -and $SkipFirewallLayer) -and -not $_.Selected
        })
    # Targets ruled out by the Windows EDITION, as opposed to by what this
    # machine happens to have installed. The two were reported under the same
    # total, so a Pro desktop with no Wi-Fi Direct adapter logged "Not applicable
    # by edition (Professional): 2" AND "Not applicable by runtime inventory: 2"
    # for the same two targets - and the first statement was simply false.
    $editionNotApplicableTargets = @($notApplicableTargets | Where-Object {
            $_.ApplicabilitySource -eq 'Edition'
        })
    $runtimeNotApplicableSelectedTargets = @($notApplicableTargets | Where-Object {
            $_.ApplicabilitySource -eq 'Runtime' -and $_.Selected
        })
    $runtimeNotApplicableNotSelectedTargets = @($notApplicableTargets | Where-Object {
            $_.ApplicabilitySource -eq 'Runtime' -and -not $_.Selected
        })

    $attempted = $attemptedTargets.Count
    $skipped = $skippedTargets.Count
    $notApplicable = $notApplicableTargets.Count
    $notSelected = $notSelectedTargets.Count
    $selectedNonFirewall = @($attemptedTargets | Where-Object { -not $_.Firewall }).Count
    $selectedFirewall = @($attemptedTargets | Where-Object Firewall).Count
    $runtimeNotApplicableSelected = $runtimeNotApplicableSelectedTargets.Count
    $runtimeNotApplicableNotSelected = $runtimeNotApplicableNotSelectedTargets.Count
    if ($attempted -lt 0 -or $skipped -lt 0 -or $notApplicable -lt 0 -or $notSelected -lt 0 -or
        ($attempted + $skipped + $notApplicable + $notSelected) -ne $DeclaredCount) {
        throw "AdvancedSecurity decision accounting does not reconcile: attempted=$attempted, skipped=$skipped, notApplicable=$notApplicable, notSelected=$notSelected, declared=$DeclaredCount"
    }

    return [PSCustomObject]@{
        Declared = $DeclaredCount
        Attempted = $attempted
        Skipped = $skipped
        NotApplicable = $notApplicable
        EditionNotApplicable = $editionNotApplicableTargets.Count
        NotSelected = $notSelected
        SelectedNonFirewall = $selectedNonFirewall
        SelectedFirewall = $selectedFirewall
        RuntimeNotApplicable = $runtimeNotApplicableSelected + $runtimeNotApplicableNotSelected
        RuntimeNotApplicableSelected = $runtimeNotApplicableSelected
        RuntimeNotApplicableNotSelected = $runtimeNotApplicableNotSelected
        Targets = @($targets)
    }
}
