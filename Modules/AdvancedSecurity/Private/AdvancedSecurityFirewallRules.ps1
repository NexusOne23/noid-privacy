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

function Get-AdvancedSecurityFirewallFilterCache {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # One bulk enumeration per WFP filter type for the whole store, keyed by
    # the owning rule's InstanceID. Verification sweeps over many rules pass
    # this cache to Test-AdvancedSecurityFirewallRuleDefinition: six queries
    # total replace six association queries per rule with identical data.
    $cache = @{
        Port          = @{}
        Address       = @{}
        Application   = @{}
        Service       = @{}
        Interface     = @{}
        InterfaceType = @{}
    }
    $filterSets = @(
        @{ Key = 'Port';          Filters = @(Get-NetFirewallPortFilter -All -ErrorAction Stop) }
        @{ Key = 'Address';       Filters = @(Get-NetFirewallAddressFilter -All -ErrorAction Stop) }
        @{ Key = 'Application';   Filters = @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop) }
        @{ Key = 'Service';       Filters = @(Get-NetFirewallServiceFilter -All -ErrorAction Stop) }
        @{ Key = 'Interface';     Filters = @(Get-NetFirewallInterfaceFilter -All -ErrorAction Stop) }
        @{ Key = 'InterfaceType'; Filters = @(Get-NetFirewallInterfaceTypeFilter -All -ErrorAction Stop) }
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
    return $cache
}

function Test-AdvancedSecurityFirewallRuleDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        # Optional read-only snapshot pair for bulk verification: all rules of
        # the store plus the cache from Get-AdvancedSecurityFirewallFilterCache.
        # Both must be supplied together. Verification semantics are identical
        # to the live per-rule queries; only the transport changes. Apply-time
        # verification keeps querying live (no snapshot) for fresh reads.
        [AllowEmptyCollection()]
        [object[]]$RuleSet,

        [hashtable]$FilterCache
    )

    $useSnapshot = $PSBoundParameters.ContainsKey('FilterCache')
    if ($useSnapshot -ne $PSBoundParameters.ContainsKey('RuleSet')) {
        throw 'Test-AdvancedSecurityFirewallRuleDefinition requires RuleSet and FilterCache together or neither.'
    }

    $mismatches = [System.Collections.Generic.List[string]]::new()
    try {
        $rules = @(if ($useSnapshot) {
            $RuleSet | Where-Object { [string]$_.Name -ceq [string]$Definition.Name }
        }
        else {
            Get-NetFirewallRule -Name ([string]$Definition.Name) -ErrorAction Stop
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
        }
        else {
            $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            $applicationFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
            $interfaceFilters = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
            $interfaceTypeFilters = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
        }
        foreach ($filterSet in @(
                @{ Name='port'; Values=$portFilters },
                @{ Name='address'; Values=$addressFilters },
                @{ Name='application'; Values=$applicationFilters },
                @{ Name='service'; Values=$serviceFilters },
                @{ Name='interface'; Values=$interfaceFilters },
                @{ Name='interface type'; Values=$interfaceTypeFilters }
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
        if ($applicationFilters.Count -eq 1 -and [string]$applicationFilters[0].Program -cne 'Any') { $mismatches.Add("Program=$($applicationFilters[0].Program)") }
        if ($serviceFilters.Count -eq 1 -and [string]$serviceFilters[0].Service -cne 'Any') { $mismatches.Add("Service=$($serviceFilters[0].Service)") }
        if ($interfaceFilters.Count -eq 1 -and [string]$interfaceFilters[0].InterfaceAlias -cne 'Any') { $mismatches.Add("InterfaceAlias=$($interfaceFilters[0].InterfaceAlias)") }
        if ($interfaceTypeFilters.Count -eq 1 -and [string]$interfaceTypeFilters[0].InterfaceType -cne 'Any') { $mismatches.Add("InterfaceType=$($interfaceTypeFilters[0].InterfaceType)") }
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

function Set-AdvancedSecurityFirewallRuleDefinition {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition
    )

    if (-not $PSCmdlet.ShouldProcess([string]$Definition.Name, 'Recreate exact module-owned firewall rule')) {
        return $false
    }

    $existing = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq [string]$Definition.Name
        })
    if ($existing.Count -gt 0) {
        $existing | Remove-NetFirewallRule -ErrorAction Stop
    }
    $parameters = @{
        Name=$Definition.Name; DisplayName=$Definition.DisplayName; Description=$Definition.Description
        Direction=$Definition.Direction; Protocol=$Definition.Protocol; Action='Block'
        Profile=$Definition.Profile; Enabled='True'; ErrorAction='Stop'
    }
    if ([string]$Definition.Direction -eq 'Inbound') { $parameters.EdgeTraversalPolicy = 'Block' }
    $parameters[[string]$Definition.PortProperty] = [string]$Definition.Port
    New-NetFirewallRule @parameters | Out-Null

    $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $Definition
    if (-not $verification.Compliant) {
        throw "Exact firewall-rule verification failed for $($Definition.Name): $($verification.Mismatches -join '; ')"
    }
    return $true
}
