#Requires -Version 5.1

function Test-DNSManagedTakeoverEvidence {
    <#
    .SYNOPSIS
        Detects an active or persisted NoID-managed DNS takeover signature.

    .DESCRIPTION
        Windows can ship dormant DoH catalog entries for public resolvers.
        Those registrations alone do not select a resolver and therefore are
        not takeover evidence. Evidence requires a supported provider address
        on an adapter (effective or persisted NameServer state), or an active
        managed DoH policy.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AdapterStates,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ProviderDefinitions,

        [bool]$ManagedDohPolicyPresent = $false
    )

    if ($ManagedDohPolicyPresent) { return $true }

    $providerAddresses = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($provider in $ProviderDefinitions) {
        foreach ($address in @(@($provider.IPv4) + @($provider.IPv6))) {
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse([string]$address, [ref]$parsed)) {
                $null = $providerAddresses.Add($parsed.ToString())
            }
        }
    }
    if ($providerAddresses.Count -eq 0) {
        throw 'DNS takeover evidence cannot be evaluated without provider addresses'
    }

    foreach ($adapterState in $AdapterStates) {
        $observedAddresses = [System.Collections.Generic.List[object]]::new()
        foreach ($propertyName in @('IPv4', 'IPv6')) {
            $property = $adapterState.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                foreach ($address in @($property.Value)) { $null = $observedAddresses.Add($address) }
            }
        }
        foreach ($propertyName in @('IPv4Registry', 'IPv6Registry')) {
            $registryProperty = $adapterState.PSObject.Properties[$propertyName]
            if ($null -eq $registryProperty -or $null -eq $registryProperty.Value) { continue }
            $addressesProperty = $registryProperty.Value.PSObject.Properties['Addresses']
            if ($null -ne $addressesProperty) {
                foreach ($address in @($addressesProperty.Value)) { $null = $observedAddresses.Add($address) }
            }
        }

        foreach ($address in $observedAddresses) {
            if ([string]::IsNullOrWhiteSpace([string]$address)) { continue }
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse([string]$address, [ref]$parsed) -and
                $providerAddresses.Contains($parsed.ToString())) {
                return $true
            }
        }
    }

    return $false
}
