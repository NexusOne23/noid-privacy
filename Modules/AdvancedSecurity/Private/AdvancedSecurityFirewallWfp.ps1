#Requires -Version 5.1

function Get-AdvancedSecurityFirewallWfpEvidence {
    [CmdletBinding()]
    param()

    # A read-only supplement for contradictory GroupPolicy enforcement
    # metadata. Capture current filters without enabling packet/event tracing.
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('NoIDWfp_' + [Guid]::NewGuid().ToString('N'))
    $path = Join-Path $directory 'filters.xml'
    $created = $false
    $policy = $null
    $process = $null
    $reader = $null
    try {
        $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
        $created = $true
        $policy = New-Object -ComObject HNetCfg.FwPolicy2 -ErrorAction Stop
        $profiles = @{}
        foreach ($fwProfile in @(@{Name='Domain';Mask=1}, @{Name='Private';Mask=2}, @{Name='Public';Mask=4})) {
            $profiles[$fwProfile.Name] = [pscustomobject]@{
                Enabled = [bool]$policy.FirewallEnabled($fwProfile.Mask)
                BlockAllInboundTraffic = [bool]$policy.BlockAllInboundTraffic($fwProfile.Mask)
                DefaultInboundAction = [int]$policy.DefaultInboundAction($fwProfile.Mask)
                HasExcludedInterfaces = @($policy.ExcludedInterfaces($fwProfile.Mask) |
                    Where-Object { $null -ne $_ }).Count -gt 0
            }
        }
        $currentProfileMask = [int]$policy.CurrentProfileTypes
        if ($currentProfileMask -lt 0 -or $currentProfileMask -gt 7) {
            throw 'Windows returned an unsupported active firewall profile mask'
        }

        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = Join-Path $env:SystemRoot 'System32\netsh.exe'
        $info.Arguments = "wfp show filters file=`"$path`" verbose=ON"
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'Cannot start Windows filter inspection' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'Windows filter inspection timed out'
        }
        $null = $stdout.Result, $stderr.Result
        if ($process.ExitCode -ne 0) { throw 'Windows filter inspection failed' }

        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 32MB
        $reader = [Xml.XmlReader]::Create($path, $settings)
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.SelectNodes('/wfpdiag/filters').Count -ne 1) {
            throw 'Windows filter evidence has an unsupported structure'
        }
        return [pscustomobject]@{ CurrentProfileMask=$currentProfileMask; Profiles=$profiles; Filters=$document }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $policy -and [Runtime.InteropServices.Marshal]::IsComObject($policy)) {
            $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)
        }
        if ($created) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            # No recursive cleanup: only this invocation's known file is ours.
            # Directory.Delete fails on foreign contents without prompting.
            [IO.Directory]::Delete($directory, $false)
        }
    }
}

function Test-AdvancedSecurityFirewallGpoEnforcement {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Rule,
        [Parameter(Mandatory = $true)]$Evidence
    )

    if ([string]$Rule.PolicyStoreSourceType -cne 'GroupPolicy' -or
        [string]$Rule.Group -cne 'NoIDPrivacy.ManagedFirewallMirror.v1') { return $false }
    $statuses = @($Rule.EnforcementStatus | ForEach-Object { [string]$_ })
    if ($statuses.Count -eq 0 -or @($statuses | Where-Object {
                $_ -cnotin @('Enforced', 'ProfileInactive', 'DisabledInProfile')
            }).Count -gt 0) { return $false }
    $mask = switch -Exact ([string]$Definition.Profile) {
        'Any' { 7 }; 'Domain' { 1 }; 'Private' { 2 }; 'Public' { 4 }; default { 0 }
    }
    if ($mask -eq 0 -or $Evidence.CurrentProfileMask -isnot [int] -or
        $Evidence.CurrentProfileMask -lt 0 -or $Evidence.CurrentProfileMask -gt 7) { return $false }
    foreach ($fwProfile in @(@{Name='Domain';Mask=1}, @{Name='Private';Mask=2}, @{Name='Public';Mask=4})) {
        if (($mask -band $fwProfile.Mask) -eq 0) { continue }
        if (-not $Evidence.Profiles.ContainsKey($fwProfile.Name)) { return $false }
        $state = $Evidence.Profiles[$fwProfile.Name]
        if ($state.Enabled -isnot [bool] -or -not $state.Enabled -or
            $state.HasExcludedInterfaces -isnot [bool] -or $state.HasExcludedInterfaces) { return $false }
    }
    if (($mask -band $Evidence.CurrentProfileMask) -eq 0) {
        # An inactive Public-only rule has no current packet filters to prove.
        # Independently establish inactivity; status 5 alone is insufficient.
        return 'ProfileInactive' -cin $statuses -and 'Enforced' -cnotin $statuses
    }
    if ('Enforced' -cnotin $statuses) { return $false }

    $protocol = switch -Exact ([string]$Definition.Protocol) { 'TCP' { '6' }; 'UDP' { '17' }; default { '' } }
    $layer = switch -Exact ([string]$Definition.Direction) {
        'Inbound' { 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_' }
        'Outbound' { 'FWPM_LAYER_ALE_AUTH_CONNECT_' }
        default { '' }
    }
    $portField = switch -Exact ([string]$Definition.PortProperty) {
        'LocalPort' { 'FWPM_CONDITION_IP_LOCAL_PORT' }
        'RemotePort' { 'FWPM_CONDITION_IP_REMOTE_PORT' }
        default { '' }
    }
    if (-not $protocol -or -not $layer -or -not $portField) { return $false }
    # Shields Up ignores individual inbound rules (including block rules).
    # Only accept its replacement when every currently active, covered profile
    # independently reports Shields Up with a Block default. Inactive profiles
    # still require the exact enabled rule/configuration checked by the caller.
    # NET_FW_ACTION_BLOCK is 0; never coerce missing/string evidence to a block.
    $shielded = [string]$Definition.Direction -ceq 'Inbound'
    foreach ($fwProfile in @(@{Name='Domain';Mask=1}, @{Name='Private';Mask=2}, @{Name='Public';Mask=4})) {
        if (($mask -band $Evidence.CurrentProfileMask -band $fwProfile.Mask) -eq 0) { continue }
        $state = $Evidence.Profiles[$fwProfile.Name]
        if ($null -eq $state.PSObject.Properties['BlockAllInboundTraffic'] -or
            $state.BlockAllInboundTraffic -isnot [bool] -or -not $state.BlockAllInboundTraffic -or
            $null -eq $state.PSObject.Properties['DefaultInboundAction'] -or
            $state.DefaultInboundAction -isnot [int] -or $state.DefaultInboundAction -ne 0) {
            $shielded = $false
        }
    }
    $families = @{}
    $shieldedFamilies = @{}
    foreach ($filter in @($Evidence.Filters.SelectNodes('/wfpdiag/filters/item'))) {
        $fields = @{}
        foreach ($field in @('displayData/name', 'displayData/description', 'providerKey', 'subLayerKey', 'action/type', 'layerKey')) {
            $nodes = @($filter.SelectNodes($field))
            if ($nodes.Count -eq 1) { $fields[$field] = [string]$nodes[0].InnerText }
        }
        if ($fields.Count -ne 6 -or
            $fields.providerKey -cne 'FWPM_PROVIDER_MPSSVC_WF' -or
            $fields.subLayerKey -cne 'FWPM_SUBLAYER_MPSSVC_WF' -or
            $fields['action/type'] -cne 'FWP_ACTION_BLOCK' -or
            $fields.layerKey -cnotin @(($layer + 'V4'), ($layer + 'V6'))) { continue }
        # INDEXED changes lookup performance, not the filter's traffic scope.
        # See Microsoft's FWPM_FILTER0 flags contract; disabled/unknown flags
        # remain insufficient evidence of an active block.
        if (@($filter.SelectNodes('flags/item') | Where-Object {
                    $_.InnerText -cnotin @('FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT',
                        'FWPM_FILTER_FLAG_HAS_FILTER_ORIGIN', 'FWPM_FILTER_FLAG_INDEXED')
                }).Count -gt 0) { continue }
        $conditions = @($filter.SelectNodes('filterCondition/item'))
        if ($shielded -and $filter.SelectNodes('filterCondition').Count -eq 1 -and
            [string]$filter.SelectSingleNode('filterCondition').GetAttribute('numItems') -cin @('', '0') -and
            $filter.SelectSingleNode('filterCondition').ChildNodes.Count -eq 0) {
            # Native netsh emits <filterCondition /> without numItems when
            # empty. Accept an absent count or explicit zero, never a nonzero
            # count or hidden child condition.
            # Require the compiled unconditional block in both address families
            # as well as the native profile evidence. Display labels are not an
            # API identity and may be localized; provider, layer, action and
            # complete condition scope establish what this filter actually does.
            $shieldedFamilies[$fields.layerKey] = $true
        }
        if ($fields['displayData/name'] -cne [string]$Definition.DisplayName -or
            $fields['displayData/description'] -cne [string]$Definition.Description) { continue }
        if ($conditions.Count -ne 2) { continue }
        $expected = @{
            FWPM_CONDITION_IP_PROTOCOL = @{Type='FWP_UINT8';ValueName='uint8';Value=$protocol}
        }
        $expected[$portField] = @{Type='FWP_UINT16';ValueName='uint16';Value=[string]$Definition.Port}
        $valid = $true
        foreach ($condition in $conditions) {
            $keyNodes = @($condition.SelectNodes('fieldKey'))
            if ($keyNodes.Count -ne 1) { $valid=$false; break }
            $key = [string]$keyNodes[0].InnerText
            if (-not $expected.ContainsKey($key)) { $valid=$false; break }
            $value = $expected[$key]
            foreach ($field in @(
                    @{Path='matchType';Value='FWP_MATCH_EQUAL'},
                    @{Path='conditionValue/type';Value=$value.Type},
                    @{Path=('conditionValue/' + $value.ValueName);Value=$value.Value}
                )) {
                $nodes = @($condition.SelectNodes($field.Path))
                if ($nodes.Count -ne 1 -or [string]$nodes[0].InnerText -cne $field.Value) { $valid=$false; break }
            }
            if (-not $valid) { break }
            $expected.Remove($key)
        }
        if ($valid -and $expected.Count -eq 0) { $families[$fields.layerKey] = $true }
    }
    # The complete filter scope must block both address families. A matching
    # display name, allow filter, one family or extra app/user/address condition
    # does not prove the module's promised all-app, all-address port block.
    return $families.Count -eq 2 -or $shieldedFamilies.Count -eq 2
}
