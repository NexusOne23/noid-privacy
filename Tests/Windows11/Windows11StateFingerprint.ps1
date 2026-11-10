#Requires -Version 5.1

function Test-Windows11OsOwnedVolatileRegistryEntry {
    <#
    .SYNOPSIS
        Identifies narrowly proven Windows-owned volatile registry state.

    .DESCRIPTION
        These values are diagnostic runtime mirrors, not NoID-owned policy.
        In particular, the two root-level DHCP values are aggregate caches for
        the currently selected DHCP adapter: hot-adding or removing a NIC can
        replace them asynchronously even when no NoID target changes.  Match
        only the proven root identities; nearby TCP/IP values remain gated.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Entry)

    # Key records and narrowly constructed test records do not necessarily
    # carry value-only Type/Data properties. Read every field through the ETS
    # property collection so StrictMode treats an absent optional field as an
    # empty non-match instead of aborting the independent BAVR fingerprint.
    $rootProperty = $Entry.PSObject.Properties['Root']
    $kindProperty = $Entry.PSObject.Properties['Kind']
    $pathProperty = $Entry.PSObject.Properties['Path']
    $nameProperty = $Entry.PSObject.Properties['Name']
    $typeProperty = $Entry.PSObject.Properties['Type']
    $dataProperty = $Entry.PSObject.Properties['Data']
    $root = if ($null -ne $rootProperty) { [string]$rootProperty.Value } else { '' }
    $kind = if ($null -ne $kindProperty) { [string]$kindProperty.Value } else { '' }
    $path = if ($null -ne $pathProperty) { [string]$pathProperty.Value } else { '' }
    $name = if ($null -ne $nameProperty) { [string]$nameProperty.Value } else { '' }
    $type = if ($null -ne $typeProperty) { [string]$typeProperty.Value } else { '' }
    $data = if ($null -ne $dataProperty) { [string]$dataProperty.Value } else { '' }

    if ($root -ieq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager') {
        # Windows creates and refreshes these content-impression/event records
        # asynchronously while the release harness and GUI are running. They
        # are derived delivery telemetry/cache state, not preference values.
        # Keep the exception closed to these two proven runtime subtrees; the
        # adjacent NoID-owned *Enabled values remain part of exact equality.
        if ($kind -cin @('Key', 'Value') -and (
                $path -ieq 'CreativeEventCache' -or
                $path -ilike 'CreativeEventCache\*' -or
                $path -ieq 'CreativeEvents' -or
                $path -ilike 'CreativeEvents\*')) {
            return $true
        }
        # Windows refreshes this delivery cache tuple asynchronously under a
        # numeric content-subscription identity.  The release matrix observed
        # these fields changing without a matching NoID target mutation. In
        # particular, AccelerateUpdatePlacementLastHandled advanced for five
        # Windows-owned subscription IDs during an isolated DNS BAVR cycle;
        # DNS has no ContentDeliveryManager target and its managed pre-state
        # restored exactly. Keep the exception closed to the exact value names,
        # registry types and observed data shapes; nearby subscription metadata
        # and the NoID-owned root preferences stay gated.
        if ($kind -ceq 'Value' -and
            $path -imatch '^Subscriptions\\[0-9]+$') {
            switch ($name) {
                'Availability' {
                    return $type -ceq 'DWord' -and $data -cmatch '^[02]$'
                }
                'ContentId' {
                    return $type -ceq 'String' -and
                        $data.Length -le 256 -and
                        $data -cmatch '^[0-9A-Za-z_`-]*$'
                }
                'HasContent' {
                    return $type -ceq 'DWord' -and $data -cmatch '^[01]$'
                }
                'LastUpdated' {
                    return $type -ceq 'QWord' -and $data -cmatch '^[0-9]+$'
                }
                'ShortContentId' {
                    return $type -ceq 'String' -and
                        $data -cmatch '^(?:|[0-9A-Fa-f]{32})$'
                }
                'UpdateDrivenByExpiration' {
                    return $type -ceq 'DWord' -and $data -cmatch '^[01]$'
                }
                { $_ -in @(
                        'AccelerateCacheRefreshLastDetected',
                        'AccelerateUpdatePlacementLastHandled',
                        'LastAccessed'
                    ) } {
                    return $type -ceq 'QWord' -and $data -cmatch '^[0-9]+$'
                }
            }
        }
        # This historical OS mirror appears after Content Delivery Manager has
        # first evaluated preinstalled-app delivery. It is not the similarly
        # named PreInstalledAppsEnabled preference and is not owned by NoID.
        if ($kind -ceq 'Value' -and [string]::IsNullOrEmpty($path) -and
            $name -ieq 'PreInstalledAppsEverEnabled' -and
            $type -ceq 'DWord' -and $data -cmatch '^[01]$') {
            return $true
        }
    }

    if ($kind -cne 'Value') { return $false }
    return (
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -and
            [string]::IsNullOrEmpty($path) -and
            $name -iin @('LsaPid', 'RunAsPPLBoot')) -or
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -and
            [string]::IsNullOrEmpty($path) -and $name -ieq 'Guid') -or
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -and (
                ([string]::IsNullOrEmpty($path) -and
                    $name -iin @('Health', 'DhcpDomain', 'DhcpNameServer')) -or
                ($path -like 'Interfaces\*' -and
                    ($name -like 'Dhcp*' -or
                     $name -iin @('Lease', 'LeaseObtainedTime', 'LeaseTerminatesTime', 'T1', 'T2')))
            )) -or
        # The v6 root needs the same per-interface runtime exclusions as v4:
        # toggling DisabledComponents (the exact scenario the root covers)
        # re-initializes the stack and rewrites DHCPv6/RA lease state, which
        # would otherwise diverge the gate hash after a provably exact restore.
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -and
            $path -like 'Interfaces\*' -and
            ($name -like 'Dhcpv6*' -or $name -like 'Dhcp*' -or
             $name -iin @('Lease', 'LeaseObtainedTime', 'LeaseTerminatesTime', 'T1', 'T2'))) -or
        # Windows updates this per-executable last-use timestamp when the
        # release harness starts PowerShell. It is not a Search preference and
        # NoID never owns the JumplistData subtree.
        ($root -ieq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -and
            $path -ieq 'JumplistData') -or
        # Windows Search replaces this opaque installed-package revision when
        # it assimilates a documented Search-setting refresh after AppX
        # catalog activity. It is an OS-owned derived cache, not one of the
        # user preference values applied or restored by NoID Privacy. Keep the
        # exclusion closed to the exact root value, type and GUID-shaped data.
        # The Win32 revision also changes on a clean reboot of the restored
        # VM, without any NoID Apply/Restore or package installation.
        ($root -ieq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -and
            [string]::IsNullOrEmpty($path) -and
            $name -iin @('InstalledPackagedAppsRevision', 'InstalledWin32AppsRevision') -and
            $type -ceq 'String' -and
            $data -cmatch '^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') -or
        # A clean reboot independently reproduces these two Windows-owned
        # runtime changes while every other stable component remains equal.
        # Neither identity is an Apply target or sealed recovery entry. Keep
        # adjacent Search preferences and RDP policy values in the exact gate.
        ($root -ieq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings' -and
            [string]::IsNullOrEmpty($path) -and
            $name -ieq 'WebProviderLastNotificationBehaviorTimestamp' -and
            $type -ceq 'QWord' -and $data -cmatch '^[0-9]+$') -or
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -and
            [string]::IsNullOrEmpty($path) -and $name -ieq 'InstanceID' -and
            $type -ceq 'String' -and
            $data -cmatch '^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{7}$') -or
        # Windows records the current console ("glass") session number here.
        # It follows the logon history since boot, for example an automatic
        # logon after setup, and is neither an Apply target nor sealed state.
        ($root -ieq 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -and
            [string]::IsNullOrEmpty($path) -and $name -ieq 'GlassSessionId' -and
            $type -ceq 'DWord' -and $data -cmatch '^[0-9]{1,5}$') -or
        # Content Delivery Manager refreshes these opaque health/evaluation
        # records asynchronously. NoID owns only the visible preference values
        # outside this runtime-health subtree.
        ($root -ieq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -and
            ($path -ieq 'Health' -or $path -ilike 'Health\*'))
    )
}

function Test-Windows11OsOwnedVolatileFirewallEntry {
    <#
    .SYNOPSIS
        Identifies a narrowly defined OS/vendor-owned volatile firewall rule.

    .DESCRIPTION
        Edge WebView2 Runtime can register an inbound mDNS rule while an
        unrelated BAVR case is running. Windows can also replace the two
        per-user Microsoft.SecHealthUI capability rules while servicing and
        re-registering its signed security application. These identities and
        versioned resource references are not NoID-owned configuration. Match
        only their complete semantic signatures; near matches remain gated.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Entry)

    if ([string]$Entry.Kind -cne 'Value' -or
        [string]$Entry.Path -cne 'FirewallRules' -or
        [string]$Entry.Type -cne 'String') {
        return $false
    }
    $name = [string]$Entry.Name
    $data = [string]$Entry.Data
    if ($name -cmatch '^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') {
        $webViewExecutable = '(?i:C:\\Program Files \(x86\)\\Microsoft\\EdgeWebView\\Application\\[0-9]+(?:\.[0-9]+){3}\\msedgewebview2\.exe)'
        $expectedPattern = '^v2\.33\|Action=Allow\|Active=TRUE\|Dir=In\|Protocol=17\|LPort=5353\|App=' +
            $webViewExecutable + '\|Name=Microsoft Edge \(mDNS-In\)\|EmbedCtxt=Microsoft Edge WebView2 Runtime\|\z'
        return $data -cmatch $expectedPattern
    }

    $secHealthNamePattern = '^Microsoft\.SecHealthUI_8wekyb3d8bbwe' +
        '(?<Sid>S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+)-' +
        '(?<Rule>In-Allow-ServerCapability|Out-Allow-AllCapabilities)$'
    if ($name -cnotmatch $secHealthNamePattern) { return $false }
    $sid = [string]$Matches.Sid
    $rule = [string]$Matches.Rule
    if ($data -cnotmatch '\|Name=@\{Microsoft\.SecHealthUI_(?<Version>[0-9]+(?:\.[0-9]+){3})_x64__8wekyb3d8bbwe\?ms-resource://Microsoft\.SecHealthUI/resources/PackageDisplayName\}\|') {
        return $false
    }
    $version = [string]$Matches.Version
    $displayResource = "@{Microsoft.SecHealthUI_${version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}"
    $descriptionResource = "@{Microsoft.SecHealthUI_${version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/ProductDescription}"
    $rulePrefix = if ($rule -ceq 'In-Allow-ServerCapability') {
        'v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|'
    }
    else {
        'v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|'
    }
    $expectedData = $rulePrefix + "Name=$displayResource|Desc=$descriptionResource|" +
        "PFN=Microsoft.SecHealthUI_8wekyb3d8bbwe|LUOwn=$sid|" +
        "EmbedCtxt=$displayResource|Platform=2:6:2|Platform2=GTEQ|"
    return $data -ceq $expectedData
}

function Get-Windows11StableFirewallFingerprintState {
    <#
    .SYNOPSIS
        Returns the deterministic, release-gated subset of a firewall export.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)

    $entries = @($State.Entries)
    if ([int]$State.SchemaVersion -ne 1 -or [int]$State.EntryCount -ne $entries.Count) {
        throw 'Firewall fingerprint input is malformed or uses an unsupported schema'
    }
    $stableEntries = @($entries | Where-Object {
            -not (Test-Windows11OsOwnedVolatileFirewallEntry -Entry $_)
        })
    return [PSCustomObject]@{
        SchemaVersion = 1
        EntryCount = $stableEntries.Count
        Entries = @($stableEntries)
    }
}

function Get-Windows11StableServiceFingerprintState {
    <#
    .SYNOPSIS
        Normalizes proven OS-owned manual-service runtime transitions.

    .DESCRIPTION
        SSDPSRV can be started or stopped by Windows/application discovery
        activity across a reboot even when NoID does not select or mutate the
        AdvancedSecurity UPnP layer. WerSvc can likewise demand-start for
        Windows error/diagnostic processing and return to Stopped while an
        unrelated module runs. Their persistent StartMode remains gated.
        Normalize only an explicitly unowned service's Running/Stopped state
        while StartMode is exactly Manual. Potentially owned runtime is exact
        by default; callers may narrow ownership for a known module scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Services,
        [AllowEmptyCollection()][string[]]$ExactRuntimeNames = @('SSDPSRV', 'WerSvc')
    )

    $stableServices = [System.Collections.Generic.List[object]]::new()
    $seenNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $runtimeManagedManualServices = @('SSDPSRV', 'WerSvc')
    foreach ($service in @($Services)) {
        foreach ($requiredProperty in @('Name', 'StartMode', 'State')) {
            if (-not $service.PSObject.Properties[$requiredProperty]) {
                throw "Service fingerprint entry lacks required property: $requiredProperty"
            }
        }
        $name = [string]$service.Name
        $startMode = [string]$service.StartMode
        $state = [string]$service.State
        if ([string]::IsNullOrWhiteSpace($name) -or -not $seenNames.Add($name)) {
            throw "Service fingerprint contains an empty or duplicate identity: $name"
        }
        if ($name -iin $runtimeManagedManualServices -and $name -notin $ExactRuntimeNames -and
            $startMode -ceq 'Manual' -and
            $state -cin @('Running', 'Stopped')) {
            $state = '<OS_RUNTIME_MANAGED>'
        }
        $stableServices.Add([PSCustomObject]@{
                Name = $name
                StartMode = $startMode
                State = $state
            })
    }
    return @($stableServices)
}
