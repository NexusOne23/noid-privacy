function Get-AdvancedSecurityFirewallDefinitions {
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'RiskyPorts', 'AdminShares', 'Finger', 'Discovery', 'Miracast')]
        [string]$Feature = 'All'
    )

    $definitions = @(
        [PSCustomObject]@{ Name='NoID-Block-LLMNR-UDP-5355'; DisplayName='NoID Privacy - Block LLMNR UDP 5355'; Description='NoID Privacy owned rule: block inbound LLMNR UDP 5355'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='5355'; Profile='Any'; Group='Base'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-NetBIOS-UDP-137'; DisplayName='NoID Privacy - Block NetBIOS UDP 137'; Description='NoID Privacy owned rule: block inbound NetBIOS UDP 137'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='137'; Profile='Any'; Group='Base'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-NetBIOS-UDP-138'; DisplayName='NoID Privacy - Block NetBIOS UDP 138'; Description='NoID Privacy owned rule: block inbound NetBIOS UDP 138'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='138'; Profile='Any'; Group='Base'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-NetBIOS-TCP-139'; DisplayName='NoID Privacy - Block NetBIOS TCP 139'; Description='NoID Privacy owned rule: block inbound NetBIOS TCP 139'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='139'; Profile='Any'; Group='Base'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-SSDP-UDP-1900'; DisplayName='NoID Privacy - Block SSDP UDP 1900'; Description='NoID Privacy owned rule: block inbound SSDP UDP 1900'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='1900'; Profile='Any'; Group='UPnP'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-UPnP-TCP-2869'; DisplayName='NoID Privacy - Block UPnP TCP 2869'; Description='NoID Privacy owned rule: block inbound UPnP TCP 2869'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='2869'; Profile='Any'; Group='UPnP'; Feature='RiskyPorts' }
        [PSCustomObject]@{ Name='NoID-Block-AdminShares-TCP-445'; DisplayName='NoID Privacy - Block SMB TCP 445 on Public'; Description='NoID Privacy owned rule: block inbound SMB TCP 445 on Public networks'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='445'; Profile='Public'; Group='AdminShares'; Feature='AdminShares' }
        [PSCustomObject]@{ Name='NoID-Block-Finger-TCP-79'; DisplayName='NoID Privacy - Block Finger Protocol TCP 79'; Description='NoID Privacy owned rule: block outbound Finger TCP 79'; Direction='Outbound'; Protocol='TCP'; PortProperty='RemotePort'; Port='79'; Profile='Any'; Group='Base'; Feature='Finger' }
        [PSCustomObject]@{ Name='NoID-Block-WSD-UDP-3702'; DisplayName='NoID Privacy - Block WS-Discovery UDP 3702'; Description='NoID Privacy owned rule: block inbound WS-Discovery UDP 3702'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='3702'; Profile='Any'; Group='Discovery'; Feature='Discovery' }
        [PSCustomObject]@{ Name='NoID-Block-WSD-TCP-5357'; DisplayName='NoID Privacy - Block WS-Discovery TCP 5357'; Description='NoID Privacy owned rule: block inbound WS-Discovery TCP 5357'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='5357'; Profile='Any'; Group='Discovery'; Feature='Discovery' }
        [PSCustomObject]@{ Name='NoID-Block-WSD-TCP-5358'; DisplayName='NoID Privacy - Block WS-Discovery TCP 5358'; Description='NoID Privacy owned rule: block inbound WS-Discovery TCP 5358'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='5358'; Profile='Any'; Group='Discovery'; Feature='Discovery' }
        [PSCustomObject]@{ Name='NoID-Block-mDNS-UDP-5353'; DisplayName='NoID Privacy - Block mDNS UDP 5353'; Description='NoID Privacy owned rule: block inbound mDNS UDP 5353'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='5353'; Profile='Any'; Group='Discovery'; Feature='Discovery' }
        [PSCustomObject]@{ Name='NoID-Block-Miracast-TCP-7236'; DisplayName='NoID Privacy - Block Miracast TCP 7236'; Description='NoID Privacy owned rule: block inbound Miracast TCP 7236'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='7236'; Profile='Any'; Group='Miracast'; Feature='Miracast' }
        [PSCustomObject]@{ Name='NoID-Block-Miracast-TCP-7250'; DisplayName='NoID Privacy - Block Miracast TCP 7250'; Description='NoID Privacy owned rule: block inbound Miracast TCP 7250'; Direction='Inbound'; Protocol='TCP'; PortProperty='LocalPort'; Port='7250'; Profile='Any'; Group='Miracast'; Feature='Miracast' }
        [PSCustomObject]@{ Name='NoID-Block-Miracast-UDP-7236'; DisplayName='NoID Privacy - Block Miracast UDP 7236'; Description='NoID Privacy owned rule: block inbound Miracast UDP 7236'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='7236'; Profile='Any'; Group='Miracast'; Feature='Miracast' }
        [PSCustomObject]@{ Name='NoID-Block-Miracast-UDP-7250'; DisplayName='NoID Privacy - Block Miracast UDP 7250'; Description='NoID Privacy owned rule: block inbound Miracast UDP 7250'; Direction='Inbound'; Protocol='UDP'; PortProperty='LocalPort'; Port='7250'; Profile='Any'; Group='Miracast'; Feature='Miracast' }
    )

    if ($Feature -eq 'All') { return $definitions }
    return @($definitions | Where-Object { $_.Feature -eq $Feature })
}

function Get-AdvancedSecurityFirewallLocalMergePolicy {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # Direct policy writes can precede the firewall service's effective state
    # until restart. Preserve absence separately from an explicit merge ban;
    # ActiveStore alone must not certify a local rule in that interval.
    $policies = @{}
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $state = [pscustomobject]@{ Present=$false; Kind=$null; Value=$null }
        $key = $null
        try {
            $key = Get-Item -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${name}Profile" -ErrorAction Stop
            if ($key.GetValueNames() -contains 'AllowLocalPolicyMerge') {
                $state.Present = $true
                $state.Kind = [string]$key.GetValueKind('AllowLocalPolicyMerge')
                $state.Value = $key.GetValue('AllowLocalPolicyMerge')
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # An absent policy key imposes no additional merge restriction.
            $policies[$name] = $state
            continue
        }
        finally { if ($null -ne $key) { $key.Close() } }
        $policies[$name] = $state
    }
    return $policies
}

function Get-AdvancedSecurityLocalRuleBlockedProfile {
    <#
    .SYNOPSIS
        Profiles on which configured policy keeps local firewall rules from taking effect.

    .DESCRIPTION
        Editions without managed firewall policy (Home) apply the NoID Privacy
        firewall layer as local rules. A configured AllowLocalPolicyMerge that
        is not an explicit DWORD 1 - for example the Microsoft Security
        Baseline's Public-profile value 0 - keeps local rules ineffective on
        that profile, also after a policy refresh or restart, so the layer's
        exact verification cannot pass there. Editions with managed policy
        write the owned rules to the local GPO and are not affected.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ManagedPolicySupported
    )

    if ($ManagedPolicySupported) { return }
    $mergePolicy = Get-AdvancedSecurityFirewallLocalMergePolicy
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $policy = $mergePolicy[$profileName]
        if ($null -eq $policy -or
            ($policy.Present -and -not ($policy.Kind -ceq 'DWord' -and $policy.Value -is [int] -and $policy.Value -eq 1))) {
            $profileName
        }
    }
}

function Get-AdvancedSecurityFirewallFilterCache {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # One bulk enumeration per WFP filter type for the active store, keyed by
    # the owning rule's InstanceID. Verification sweeps over many rules pass
    # this cache to Test-AdvancedSecurityFirewallRuleDefinition. The additional
    # profile snapshot proves that an enabled rule belongs to enabled profiles.
    $cache = @{
        Port          = @{}
        Address       = @{}
        Application   = @{}
        Service       = @{}
        Interface     = @{}
        InterfaceType = @{}
        Security      = @{}
        Profile       = @{}
        LocalMergePolicy = Get-AdvancedSecurityFirewallLocalMergePolicy
    }
    $filterSets = @(
        @{ Key = 'Port';          Filters = @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'Address';       Filters = @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'Application';   Filters = @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'Service';       Filters = @(Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'Interface';     Filters = @(Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'InterfaceType'; Filters = @(Get-NetFirewallInterfaceTypeFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
        @{ Key = 'Security';      Filters = @(Get-NetFirewallSecurityFilter -All -PolicyStore ActiveStore -ErrorAction Stop) }
    )
    foreach ($filterSet in $filterSets) {
        $byRule = $cache[$filterSet.Key]
        foreach ($filter in $filterSet.Filters) {
            $ruleInstanceId = [string]$filter.InstanceID
            # First occurrence must start a fresh array: @($byRule[$missingKey])
            # would be @($null) and smuggle a null element into the list, which
            # the strict one-filter-per-rule count check then reports as 2.
            if ($byRule.ContainsKey($ruleInstanceId)) {
                $byRule[$ruleInstanceId] = @($byRule[$ruleInstanceId]) + $filter
            }
            else {
                $byRule[$ruleInstanceId] = @($filter)
            }
        }
    }
    foreach ($firewallProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        $name = [string]$firewallProfile.Name
        if ($cache.Profile.ContainsKey($name)) {
            $cache.Profile[$name] = @($cache.Profile[$name]) + $firewallProfile
        }
        else { $cache.Profile[$name] = @($firewallProfile) }
    }
    return $cache
}

function Test-AdvancedSecurityFirewallRuleDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        # Optional read-only snapshot pair for bulk verification: all rules of
        # ActiveStore plus the cache from Get-AdvancedSecurityFirewallFilterCache.
        # Both must be supplied together. Verification semantics are identical
        # to the live per-rule queries; only the transport changes. Apply-time
        # verification keeps querying live (no snapshot) for fresh reads.
        [AllowEmptyCollection()]
        [object[]]$RuleSet,

        [hashtable]$FilterCache,

        # Ownership checks inspect a supplied rule configuration even
        # when local-rule merging suppresses its runtime effect. This does not
        # certify enforcement and is never used by the hardening verifier.
        [switch]$ConfigurationOnly
    )

    $useSnapshot = $PSBoundParameters.ContainsKey('FilterCache')
    if ($useSnapshot -ne $PSBoundParameters.ContainsKey('RuleSet')) {
        throw 'Test-AdvancedSecurityFirewallRuleDefinition requires RuleSet and FilterCache together or neither.'
    }

    if ($ConfigurationOnly -and -not $useSnapshot) {
        throw 'Configuration-only verification requires an explicit native rule and filter snapshot'
    }

    $mismatches = [System.Collections.Generic.List[string]]::new()
    try {
        $rules = @(if ($useSnapshot) {
            $RuleSet | Where-Object { [string]$_.Name -ceq [string]$Definition.Name }
        }
        else {
            Get-NetFirewallRule -Name ([string]$Definition.Name) -PolicyStore ActiveStore -ErrorAction Stop
        })
        if ($rules.Count -ne 1) {
            throw "expected exactly one rule, found $($rules.Count)"
        }
        $rule = $rules[0]
        foreach ($expectation in @(
                @{ Name='DisplayName'; Actual=[string]$rule.DisplayName; Expected=[string]$Definition.DisplayName }
                @{ Name='Description'; Actual=[string]$rule.Description; Expected=[string]$Definition.Description }
                @{ Name='Enabled'; Actual=[string]$rule.Enabled; Expected='True' }
                @{ Name='Direction'; Actual=[string]$rule.Direction; Expected=[string]$Definition.Direction }
                @{ Name='Action'; Actual=[string]$rule.Action; Expected='Block' }
                @{ Name='Profile'; Actual=[string]$rule.Profile; Expected=[string]$Definition.Profile }
            )) {
            if ($expectation.Actual -cne $expectation.Expected) {
                $mismatches.Add("$($expectation.Name)=$($expectation.Actual), expected $($expectation.Expected)")
            }
        }
        if ([string]$Definition.Direction -eq 'Inbound' -and [string]$rule.EdgeTraversalPolicy -cne 'Block') {
            $mismatches.Add("EdgeTraversalPolicy=$($rule.EdgeTraversalPolicy), expected Block")
        }
        # These scopes live on the rule rather than its application/address
        # filters. Program=Any and RemoteAddress=Any alone do not rule them out.
        foreach ($scopeName in @('Owner', 'PackageFamilyName', 'Platforms', 'PolicyAppId', 'RemoteDynamicKeywordAddresses')) {
            $scope = $rule.PSObject.Properties[$scopeName]
            if ($null -ne $scope -and -not [string]::IsNullOrEmpty([string]$scope.Value)) {
                $mismatches.Add("$scopeName adds an undeclared rule scope")
            }
        }

        # Enabled in PersistentStore does not prove enforcement: a disabled
        # profile still retains the exact rule while traffic passes. Inspect
        # ActiveStore and reject unavailable or suppressed runtime evidence.
        $requiresIndependentGpoEvidence = $false
        if (-not $ConfigurationOnly) {
            $enforcement = @($rule.EnforcementStatus)
            if ($enforcement.Count -eq 0) { $mismatches.Add('active enforcement status is unavailable') }
            foreach ($status in $enforcement) {
                if ([string]$status -ceq 'DisabledInProfile' -and
                    [string]$rule.PolicyStoreSourceType -ceq 'GroupPolicy') {
                    $requiresIndependentGpoEvidence = $true
                }
                elseif ([string]$status -cnotin @('Enforced', 'ProfileInactive')) {
                    $mismatches.Add("active enforcement status=$status")
                }
            }
            $profileNames = if ([string]$Definition.Profile -ceq 'Any') {
                @('Domain', 'Private', 'Public')
            }
            else { @([string]$Definition.Profile) }
            $liveProfiles = if (-not $useSnapshot) {
                @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
            }
            else { @() }
            $localMergePolicy = if ([string]$rule.PolicyStoreSourceType -ceq 'Local') {
                if ($useSnapshot) {
                    if (-not $FilterCache.ContainsKey('LocalMergePolicy')) {
                        throw 'configured local firewall merge policy is unavailable in the snapshot'
                    }
                    $FilterCache.LocalMergePolicy
                }
                else { Get-AdvancedSecurityFirewallLocalMergePolicy }
            }
            else { $null }
            foreach ($profileName in $profileNames) {
                $profiles = @(if ($useSnapshot) {
                    if ($FilterCache.Profile.ContainsKey($profileName)) { $FilterCache.Profile[$profileName] }
                }
                else { $liveProfiles | Where-Object { [string]$_.Name -ceq $profileName } })
                if ($profiles.Count -ne 1 -or [string]$profiles[0].Enabled -cne 'True') {
                    $mismatches.Add("active $profileName firewall profile is disabled, missing or ambiguous")
                }
                elseif ([string]$rule.PolicyStoreSourceType -ceq 'Local' -and
                    [string]$profiles[0].AllowLocalFirewallRules -cne 'True') {
                    $mismatches.Add("active $profileName profile does not allow local firewall rules")
                }
                if ([string]$rule.PolicyStoreSourceType -ceq 'Local') {
                    if (-not $localMergePolicy.ContainsKey($profileName)) {
                        $mismatches.Add("configured $profileName local firewall merge policy is unavailable")
                    }
                    else {
                        $policy = $localMergePolicy[$profileName]
                        if ($policy.Present) {
                            if ($policy.Kind -cne 'DWord' -or $policy.Value -isnot [int] -or $policy.Value -notin @(0, 1)) {
                                $mismatches.Add("configured $profileName AllowLocalPolicyMerge is not a valid DWORD boolean")
                            }
                            elseif ($policy.Value -eq 0) {
                                $mismatches.Add("configured $profileName AllowLocalPolicyMerge=0 disallows local firewall rules, including after policy refresh or restart")
                            }
                        }
                    }
                }
            }
        }

        if ($useSnapshot) {
            $ruleInstanceId = [string]$rule.InstanceID
            # @(...) around the whole if-expression: assigning an if-expression
            # enumerates its pipeline output, so a one-element list would land
            # as the bare element and its .Count would be null (or throw under
            # StrictMode), silently skipping the per-filter value checks.
            $portFilters          = @(if ($FilterCache.Port.ContainsKey($ruleInstanceId))          { $FilterCache.Port[$ruleInstanceId] })
            $addressFilters       = @(if ($FilterCache.Address.ContainsKey($ruleInstanceId))       { $FilterCache.Address[$ruleInstanceId] })
            $applicationFilters   = @(if ($FilterCache.Application.ContainsKey($ruleInstanceId))   { $FilterCache.Application[$ruleInstanceId] })
            $serviceFilters       = @(if ($FilterCache.Service.ContainsKey($ruleInstanceId))       { $FilterCache.Service[$ruleInstanceId] })
            $interfaceFilters     = @(if ($FilterCache.Interface.ContainsKey($ruleInstanceId))     { $FilterCache.Interface[$ruleInstanceId] })
            $interfaceTypeFilters = @(if ($FilterCache.InterfaceType.ContainsKey($ruleInstanceId)) { $FilterCache.InterfaceType[$ruleInstanceId] })
            $securityFilters      = @(if ($FilterCache.Security.ContainsKey($ruleInstanceId))      { $FilterCache.Security[$ruleInstanceId] })
        }
        else {
            $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            $applicationFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
            $interfaceFilters = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
            $interfaceTypeFilters = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
            $securityFilters = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
        }
        foreach ($filterSet in @(
                @{ Name='port'; Values=$portFilters },
                @{ Name='address'; Values=$addressFilters },
                @{ Name='application'; Values=$applicationFilters },
                @{ Name='service'; Values=$serviceFilters },
                @{ Name='interface'; Values=$interfaceFilters },
                @{ Name='interface type'; Values=$interfaceTypeFilters },
                @{ Name='security'; Values=$securityFilters }
            )) {
            if (@($filterSet.Values).Count -ne 1) {
                $mismatches.Add("$($filterSet.Name) filter count=$(@($filterSet.Values).Count), expected 1")
            }
        }

        if ($portFilters.Count -eq 1) {
            $port = $portFilters[0]
            if ([string]$port.Protocol -cne [string]$Definition.Protocol) { $mismatches.Add("Protocol=$($port.Protocol)") }
            if ([string]$port.($Definition.PortProperty) -cne [string]$Definition.Port) { $mismatches.Add("$($Definition.PortProperty)=$($port.($Definition.PortProperty))") }
            $otherPortProperty = if ($Definition.PortProperty -eq 'LocalPort') { 'RemotePort' } else { 'LocalPort' }
            if ([string]$port.$otherPortProperty -cne 'Any') { $mismatches.Add("$otherPortProperty=$($port.$otherPortProperty)") }
        }
        if ($addressFilters.Count -eq 1 -and
            ([string]$addressFilters[0].LocalAddress -cne 'Any' -or [string]$addressFilters[0].RemoteAddress -cne 'Any')) {
            $mismatches.Add('address scope is not Any/Any')
        }
        if ($applicationFilters.Count -eq 1) {
            if ([string]$applicationFilters[0].Program -cne 'Any') { $mismatches.Add("Program=$($applicationFilters[0].Program)") }
            # Program=Any does not imply every app: Package is a separate scope.
            if ($null -eq $applicationFilters[0].PSObject.Properties['Package'] -or
                [string]$applicationFilters[0].Package -cnotin @('', 'Any')) {
                $mismatches.Add('application package scope is restricted or unavailable')
            }
        }
        if ($securityFilters.Count -eq 1) {
            foreach ($expectation in @(
                    @{ Name='Authentication'; Expected='NotRequired' },
                    @{ Name='Encryption'; Expected='NotRequired' },
                    @{ Name='OverrideBlockRules'; Expected='False' },
                    @{ Name='LocalUser'; Expected='Any' },
                    @{ Name='RemoteUser'; Expected='Any' },
                    @{ Name='RemoteMachine'; Expected='Any' }
                )) {
                if ([string]$securityFilters[0].($expectation.Name) -cne $expectation.Expected) {
                    $mismatches.Add("$($expectation.Name) security filter differs from $($expectation.Expected)")
                }
            }
        }
        if ($serviceFilters.Count -eq 1 -and [string]$serviceFilters[0].Service -cne 'Any') { $mismatches.Add("Service=$($serviceFilters[0].Service)") }
        if ($interfaceFilters.Count -eq 1 -and [string]$interfaceFilters[0].InterfaceAlias -cne 'Any') { $mismatches.Add("InterfaceAlias=$($interfaceFilters[0].InterfaceAlias)") }
        if ($interfaceTypeFilters.Count -eq 1 -and [string]$interfaceTypeFilters[0].InterfaceType -cne 'Any') { $mismatches.Add("InterfaceType=$($interfaceTypeFilters[0].InterfaceType)") }

        if ($requiresIndependentGpoEvidence -and $mismatches.Count -eq 0) {
            # Windows can return state 2 alongside real GPO enforcement. Do
            # not discard it: require independent profile and IPv4/IPv6 WFP
            # evidence after every ordinary rule/filter scope check passes.
            if (-not (Get-Command Get-AdvancedSecurityFirewallWfpEvidence -ErrorAction SilentlyContinue)) {
                . (Join-Path $PSScriptRoot 'AdvancedSecurityFirewallWfp.ps1')
            }
            $evidence = if ($useSnapshot) {
                if (-not $FilterCache.ContainsKey('WfpEvidence')) {
                    $FilterCache.WfpEvidence = Get-AdvancedSecurityFirewallWfpEvidence
                }
                $FilterCache.WfpEvidence
            }
            else { Get-AdvancedSecurityFirewallWfpEvidence }
            if (-not (Test-AdvancedSecurityFirewallGpoEnforcement -Definition $Definition -Rule $rule -Evidence $evidence)) {
                $mismatches.Add('independent profile/WFP evidence does not establish the reported GPO enforcement')
            }
        }
    }
    catch {
        $mismatches.Add($_.Exception.Message)
    }

    return [PSCustomObject]@{
        Name       = [string]$Definition.Name
        Compliant  = ($mismatches.Count -eq 0)
        Mismatches = @($mismatches)
    }
}

function Wait-AdvancedSecurityFirewallRuleDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition)

    # Group Policy persistence and firewall activation are separate operations.
    # Windows rebuilds its active rules and filters after registry notification;
    # a successful policy refresh does not make the first ActiveStore read final.
    # Retry only the complete read-only verification, never the policy writes.
    # Every scope and enforcement check must still pass in one fresh attempt.
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $Definition
        if ($verification.Compliant -or $attempt -eq 5) { return $verification }
        Write-Log -Level INFO -Message "Waiting for complete active firewall rule $($Definition.Name) (verification $attempt/5)" -Module 'AdvancedSecurity'
        Start-Sleep -Seconds 2
    }
}

function Set-AdvancedSecurityFirewallRuleDefinition {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        [ValidateSet('Auto', 'PersistentStore', 'localhost')]
        [string]$PolicyStore = 'Auto'
    )

    if (-not $PSCmdlet.ShouldProcess([string]$Definition.Name, 'Recreate exact module-owned firewall rule')) {
        return $false
    }

    if ($PolicyStore -eq 'Auto') {
        if (-not (Get-Command Get-AdvancedSecurityApplicability -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'Get-AdvancedSecurityApplicability.ps1')
        }
        $applicability = @(Get-AdvancedSecurityApplicability)
        if ($applicability.Count -ne 1 -or $applicability[0].ManagedPolicySupported -isnot [bool]) {
            throw 'Firewall Apply requires unambiguous native edition applicability'
        }
        $PolicyStore = if ($applicability[0].ManagedPolicySupported) { 'localhost' } else { 'PersistentStore' }
    }

    $parameters = @{
        Name=$Definition.Name; DisplayName=$Definition.DisplayName; Description=$Definition.Description
        Direction=$Definition.Direction; Protocol=$Definition.Protocol; Action='Block'
        Profile=$Definition.Profile; Enabled='True'; PolicyStore='PersistentStore'; ErrorAction='Stop'
    }
    if ([string]$Definition.Direction -eq 'Inbound') { $parameters.EdgeTraversalPolicy = 'Block' }
    $parameters[[string]$Definition.PortProperty] = [string]$Definition.Port

    if ($PolicyStore -eq 'localhost') {
        if (-not (Get-Command Get-AdvancedSecurityFirewallMirrorState -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'AdvancedSecurityFirewallMirrors.ps1')
        }
        # Commercial editions use a GPO rule even before SecurityBaseline is
        # applied: its later local-rule merge ban must not suppress this layer.
        # Keep the complete source in the existing WFW recovery contract.
        $state = Assert-AdvancedSecurityFirewallMirrorApplicability -Names @([string]$Definition.Name) -SelectedRulesOnly -PassThru
        $contract = Get-AdvancedSecurityFirewallMirrorContract
        $expectedNames = @(@($state.Sources.Keys) + [string]$Definition.Name | Sort-Object -Unique)
        $copyName = [string]$Definition.Name + $contract.Suffix
        if ($state.Sources.ContainsKey([string]$Definition.Name)) {
            $source = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $copyName -ErrorAction Stop)
            if ($source.Count -ne 1 -or [string]$source[0].Name -cne $copyName -or
                [string]$source[0].Group -cne $contract.Group) {
                throw "NoID firewall recovery-copy ownership changed before replacement: $copyName"
            }
            $source[0] | Remove-NetFirewallRule -ErrorAction Stop
        }
        $parameters.Name = $copyName
        $parameters.Group = $contract.Group
        New-NetFirewallRule @parameters | Out-Null
        if (-not (Sync-AdvancedSecurityFirewallMirrors -ExpectedNames $expectedNames -NamesToSynchronize @([string]$Definition.Name) -Confirm:$false)) {
            throw 'Firewall Apply did not synchronize its recoverable GPO rules'
        }
        # Remove an older canonical local rule only after the GPO copy exists.
        # Its full prior configuration remains in the sealed pre-Apply WFW.
        # Distinct source names avoid duplicate canonical ActiveStore objects.
        $legacy = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {
                [string]$_.Name -ceq [string]$Definition.Name
            })
        if ($legacy.Count -gt 0) { $legacy | Remove-NetFirewallRule -ErrorAction Stop }
    }
    else {
        $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {
                [string]$_.Name -ceq [string]$Definition.Name
            })
        if ($existing.Count -gt 0) { $existing | Remove-NetFirewallRule -ErrorAction Stop }
        New-NetFirewallRule @parameters | Out-Null
    }

    $verification = Wait-AdvancedSecurityFirewallRuleDefinition -Definition $Definition
    if (-not $verification.Compliant) {
        throw "Exact firewall-rule verification failed for $($Definition.Name): $($verification.Mismatches -join '; ')"
    }
    return $true
}
