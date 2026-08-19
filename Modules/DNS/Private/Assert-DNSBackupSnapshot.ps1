function Assert-DNSBackupSnapshot {
    <#
    .SYNOPSIS
        Validate the complete, mutation-bearing DNS backup contract.

    .DESCRIPTION
        Performs only data validation and has no system side effects. Backup,
        manifest sealing, and restore all use this same contract so malformed
        or internally inconsistent state is rejected before any DNS mutation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Snapshot
    )

    foreach ($property in @('SchemaVersion', 'Policy', 'DohEntries', 'Adapters')) {
        if (-not $Snapshot.PSObject.Properties[$property]) {
            throw "DNS pre-state is missing required property '$property'"
        }
    }
    $schemaVersion = [int]$Snapshot.SchemaVersion
    if ($schemaVersion -notin @(3, 4, 5)) {
        throw "Unsupported DNS pre-state schema: $($Snapshot.SchemaVersion)"
    }

    $policy = $Snapshot.Policy
    foreach ($property in @('Path', 'Name', 'KeyExisted', 'Exists', 'Type', 'Value')) {
        if (-not $policy.PSObject.Properties[$property]) {
            throw "DNS policy pre-state is missing required property '$property'"
        }
    }
    if ([string]$policy.Path -ne 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -or
        [string]$policy.Name -ne 'DoHPolicy') {
        throw 'DNS pre-state contains an invalid policy target'
    }
    if ($policy.KeyExisted -isnot [bool] -or $policy.Exists -isnot [bool]) {
        throw 'DNS policy existence flags must be Boolean values'
    }
    if ([bool]$policy.Exists -and -not [bool]$policy.KeyExisted) {
        throw 'DNS policy value cannot exist when its parent key did not exist'
    }
    if ([bool]$policy.Exists) {
        if ([string]$policy.Type -notin @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')) {
            throw "DNS pre-state contains an unsupported DoHPolicy type: $($policy.Type)"
        }
        switch ([string]$policy.Type) {
            'DWord' { $null = [Convert]::ToInt32($policy.Value, [Globalization.CultureInfo]::InvariantCulture) }
            'QWord' { $null = [Convert]::ToInt64($policy.Value, [Globalization.CultureInfo]::InvariantCulture) }
            'MultiString' {
                if ($null -eq $policy.Value) { throw 'DNS MultiString policy pre-state has no value' }
                foreach ($item in @($policy.Value)) {
                    if ($null -eq $item) { throw 'DNS MultiString policy pre-state contains a null element' }
                }
            }
            'Binary' {
                if ($null -eq $policy.Value) { throw 'DNS Binary policy pre-state has no value' }
                foreach ($item in @($policy.Value)) {
                    $number = [Convert]::ToInt32($item, [Globalization.CultureInfo]::InvariantCulture)
                    if ($number -lt 0 -or $number -gt 255) {
                        throw 'DNS Binary policy pre-state contains a value outside the byte range'
                    }
                }
            }
            default {
                if ($null -eq $policy.Value) { throw 'DNS string policy pre-state has no value' }
            }
        }
    }
    elseif ($null -ne $policy.Type -or $null -ne $policy.Value) {
        throw 'Absent DNS policy value must not carry stale type or value data'
    }

    $seenDoh = @{}
    foreach ($dohState in @($Snapshot.DohEntries)) {
        foreach ($property in @('ServerAddress', 'Exists', 'DohTemplate', 'AllowFallbackToUdp', 'AutoUpgrade')) {
            if (-not $dohState.PSObject.Properties[$property]) {
                throw "DNS DoH pre-state is missing required property '$property'"
            }
        }
        $parsedAddress = $null
        $address = [string]$dohState.ServerAddress
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsedAddress)) {
            throw "DNS pre-state contains an invalid DoH address: $address"
        }
        $canonicalAddress = $parsedAddress.ToString()
        if ($seenDoh.ContainsKey($canonicalAddress)) {
            throw "DNS pre-state contains a duplicate DoH address: $address"
        }
        $seenDoh[$canonicalAddress] = $true
        if ($dohState.Exists -isnot [bool]) {
            throw "DNS DoH existence flag must be Boolean: $address"
        }
        if ([bool]$dohState.Exists) {
            $template = $null
            if ([string]::IsNullOrWhiteSpace([string]$dohState.DohTemplate) -or
                -not [Uri]::TryCreate([string]$dohState.DohTemplate, [UriKind]::Absolute, [ref]$template) -or
                $template.Scheme -ne 'https') {
                throw "DNS DoH registration has an invalid HTTPS template: $address"
            }
            if ($dohState.AllowFallbackToUdp -isnot [bool] -or $dohState.AutoUpgrade -isnot [bool]) {
                throw "DNS DoH registration flags must be Boolean: $address"
            }
        }
        elseif ($null -ne $dohState.DohTemplate -or
            $null -ne $dohState.AllowFallbackToUdp -or
            $null -ne $dohState.AutoUpgrade) {
            throw "Absent DNS DoH registration carries stale configuration: $address"
        }
    }

    $adapters = @($Snapshot.Adapters)
    if ($adapters.Count -eq 0) {
        throw 'DNS pre-state contains no adapters'
    }
    $seenAdapters = @{}
    foreach ($adapterState in $adapters) {
        foreach ($property in @('InterfaceGuid', 'InterfaceDescription', 'Families')) {
            if (-not $adapterState.PSObject.Properties[$property]) {
                throw "DNS adapter pre-state is missing required property '$property'"
            }
        }
        $guid = [string]$adapterState.InterfaceGuid
        $parsedGuid = [Guid]::Empty
        if (-not $guid.StartsWith('{') -or -not $guid.EndsWith('}') -or
            -not [Guid]::TryParse($guid.Trim([char[]]@('{', '}')), [ref]$parsedGuid) -or
            $seenAdapters.ContainsKey($parsedGuid.ToString('D'))) {
            throw "DNS pre-state contains an invalid or duplicate InterfaceGuid: $guid"
        }
        $seenAdapters[$parsedGuid.ToString('D')] = $true

        $families = @($adapterState.Families)
        $familyIdentity = (@($families | ForEach-Object { [int]$_.AddressFamily } | Sort-Object -Unique) -join ',')
        if ($families.Count -ne 2 -or $familyIdentity -ne '2,23') {
            throw "DNS pre-state has invalid address-family records for $guid"
        }
        foreach ($familyState in $families) {
            foreach ($property in @(
                    'AddressFamily', 'Managed', 'ServerAddresses', 'RegistryPath',
                    'RegistryKeyExisted', 'NameServerExisted', 'NameServerType', 'NameServerValue'
                )) {
                if (-not $familyState.PSObject.Properties[$property]) {
                    throw "DNS family pre-state for $guid is missing required property '$property'"
                }
            }
            $family = [int]$familyState.AddressFamily
            if ($familyState.Managed -isnot [bool] -or
                $familyState.RegistryKeyExisted -isnot [bool] -or
                $familyState.NameServerExisted -isnot [bool]) {
                throw "DNS family existence/scope flags must be Boolean for $guid/$family"
            }
            if ($family -eq 2 -and -not [bool]$familyState.Managed) {
                throw "DNS pre-state does not mark IPv4 as managed for $guid"
            }
            if ($schemaVersion -eq 4 -and -not $familyState.PSObject.Properties['InterfaceDoh']) {
                throw "DNS schema-4 family pre-state lacks native interface DoH state for $guid/$family"
            }
            if ($schemaVersion -eq 5 -and
                (-not $familyState.PSObject.Properties['InterfaceDohManaged'] -or
                 $familyState.InterfaceDohManaged -isnot [bool] -or
                 -not $familyState.PSObject.Properties['InterfaceDoh'])) {
                throw "DNS schema-5 family pre-state lacks native interface DoH scope/state for $guid/$family"
            }
            if ($schemaVersion -eq 5 -and [bool]$familyState.Managed -and
                -not [bool]$familyState.InterfaceDohManaged) {
                throw "Managed DNS family is outside native DoH scope for $guid/$family"
            }
            if ($schemaVersion -eq 5 -and [bool]$familyState.InterfaceDohManaged -and
                -not [bool]$familyState.RegistryKeyExisted) {
                throw "Native DoH scope lacks an existing registry parent for $guid/$family"
            }
            $expectedRegistryPath = if ($family -eq 2) {
                "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
            }
            else {
                "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid"
            }
            if ([string]$familyState.RegistryPath -ne $expectedRegistryPath) {
                throw "DNS pre-state contains an invalid registry target: $($familyState.RegistryPath)"
            }
            if ([bool]$familyState.Managed -and -not [bool]$familyState.RegistryKeyExisted) {
                throw "DNS pre-state lacks a registry key for managed target $guid/$family"
            }
            if ([bool]$familyState.NameServerExisted -and -not [bool]$familyState.RegistryKeyExisted) {
                throw "DNS NameServer value cannot exist without its key for $guid/$family"
            }
            if ([bool]$familyState.NameServerExisted) {
                if ([string]$familyState.NameServerType -notin @('String', 'ExpandString')) {
                    throw "DNS pre-state contains an unsupported NameServer type for $guid/$family"
                }
                if ($null -eq $familyState.NameServerValue) {
                    throw "DNS NameServer pre-state has no value for $guid/$family"
                }
            }
            elseif ($null -ne $familyState.NameServerType -or $null -ne $familyState.NameServerValue) {
                throw "Absent DNS NameServer value carries stale data for $guid/$family"
            }

            $expectedFamily = if ($family -eq 2) {
                [System.Net.Sockets.AddressFamily]::InterNetwork
            }
            else {
                [System.Net.Sockets.AddressFamily]::InterNetworkV6
            }
            $seenServers = @{}
            foreach ($serverAddress in @($familyState.ServerAddresses)) {
                $parsedServerAddress = $null
                if ([string]::IsNullOrWhiteSpace([string]$serverAddress) -or
                    -not [System.Net.IPAddress]::TryParse([string]$serverAddress, [ref]$parsedServerAddress)) {
                    throw "DNS pre-state contains an invalid server address for $guid/$family`: $serverAddress"
                }
                if ($parsedServerAddress.AddressFamily -ne $expectedFamily) {
                    throw "DNS server address belongs to the wrong family for $guid/$family`: $serverAddress"
                }
                $canonicalServer = $parsedServerAddress.ToString()
                if ($seenServers.ContainsKey($canonicalServer)) {
                    throw "DNS pre-state contains a duplicate server for $guid/$family`: $serverAddress"
                }
                $seenServers[$canonicalServer] = $true
            }
            # This corroboration invariant holds only inside the managed scope:
            # on an unmanaged family (IPv6 binding disabled or the stack turned
            # off via DisabledComponents=0xFF) the DNS client reports no
            # effective servers while a static NameServer value legitimately
            # persists in the registry - that is the true, sealable pre-state.
            if ([bool]$familyState.Managed -and
                [bool]$familyState.NameServerExisted -and
                -not [string]::IsNullOrWhiteSpace([string]$familyState.NameServerValue) -and
                $seenServers.Count -eq 0) {
                throw "Static DNS pre-state has no effective server addresses for $guid/$family"
            }

            if ($schemaVersion -in @(4, 5)) {
                $interfaceDohManaged = if ($schemaVersion -eq 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if (-not $interfaceDohManaged) {
                    if ($null -ne $familyState.InterfaceDoh) {
                        throw "Unmanaged DNS family carries native interface DoH state for $guid/$family"
                    }
                    continue
                }
                $interfaceDoh = $familyState.InterfaceDoh
                foreach ($property in @('AddressFamily', 'NameServers', 'Properties')) {
                    if (-not $interfaceDoh.PSObject.Properties[$property]) {
                        throw "Native interface DoH pre-state is missing '$property' for $guid/$family"
                    }
                }
                if ([int]$interfaceDoh.AddressFamily -ne $family) {
                    throw "Native interface DoH family identity is inconsistent for $guid/$family"
                }
                $nativeServers = @($interfaceDoh.NameServers)
                $nativeSeen = @{}
                foreach ($server in $nativeServers) {
                    $parsedNativeServer = $null
                    if (-not [System.Net.IPAddress]::TryParse([string]$server, [ref]$parsedNativeServer) -or
                        $parsedNativeServer.AddressFamily -ne $expectedFamily -or
                        $nativeSeen.ContainsKey($parsedNativeServer.ToString())) {
                        throw "Native interface DoH server is invalid or duplicated for $guid/$family`: $server"
                    }
                    $nativeSeen[$parsedNativeServer.ToString()] = $true
                }
                $propertySeen = @{}
                foreach ($dohProperty in @($interfaceDoh.Properties)) {
                    foreach ($propertyName in @('Version', 'ServerIndex', 'Type', 'Flags', 'Template', 'Port')) {
                        if (-not $dohProperty.PSObject.Properties[$propertyName]) {
                            throw "Native interface DoH property is missing '$propertyName' for $guid/$family"
                        }
                    }
                    $serverIndex = [int]$dohProperty.ServerIndex
                    $flags = [uint64]$dohProperty.Flags
                    $propertyType = [int]$dohProperty.Type
                    $unsupportedFlagMask = [uint64]::MaxValue - [uint64]0x3F
                    if ([int]$dohProperty.Version -ne 1 -or $propertyType -ne 1 -or
                        $serverIndex -lt 0 -or $serverIndex -ge $nativeServers.Count -or
                        $propertySeen.ContainsKey($serverIndex) -or
                        ($flags -band $unsupportedFlagMask) -ne 0) {
                        throw "Native interface DoH property is invalid or duplicated for $guid/$family"
                    }
                    $propertySeen[$serverIndex] = $true
                    $enableAuto = ($flags -band 0x0001) -ne 0
                    $enableTemplate = ($flags -band 0x0002) -ne 0
                    if ($enableAuto -eq $enableTemplate) {
                        throw "Native interface secure-DNS enable flags are invalid for $guid/$family"
                    }
                    if ($enableAuto) {
                        if ($null -ne $dohProperty.Template) {
                            throw "Auto native interface DoH property carries a template for $guid/$family"
                        }
                    }
                    else {
                        $nativeUri = $null
                        if ([string]::IsNullOrWhiteSpace([string]$dohProperty.Template) -or
                            -not [Uri]::TryCreate([string]$dohProperty.Template, [UriKind]::Absolute, [ref]$nativeUri) -or
                            $nativeUri.Scheme -ne 'https') {
                            throw "Native interface DoH property has an invalid template for $guid/$family"
                        }
                    }
                    $port = [int]$dohProperty.Port
                    if ($port -ne 0) {
                        throw "Native interface secure-DNS property has an invalid port for $guid/$family"
                    }
                }
            }
        }
    }

    return $true
}
