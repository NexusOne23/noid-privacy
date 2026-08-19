#Requires -Version 5.1

function Assert-DNSPrestate {
    <#
    .SYNOPSIS
        Reconcile all DNS state sealed by the supported schema before Apply.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Snapshot
    )

    $null = Assert-DNSBackupSnapshot -Snapshot $Snapshot
    $artifacts = @($global:BackupIndex | Where-Object { [string]$_.Module -eq 'DNS' })
    if ($artifacts.Count -ne 1 -or [string]$artifacts[0].Type -ne 'DNS' -or
        [string]$artifacts[0].Name -ne 'DNS_PreState') {
        throw 'DNS backup inventory must contain exactly one canonical DNS_PreState artifact'
    }

    $policy = $Snapshot.Policy
    $policyKeyExists = Test-Path -LiteralPath ([string]$policy.Path) -PathType Container -ErrorAction Stop
    if ($policyKeyExists -ne [bool]$policy.KeyExisted) {
        throw 'DNS DoHPolicy parent-key existence changed after backup'
    }
    $policyExists = $false
    $policyType = $null
    $policyValue = $null
    if ($policyKeyExists) {
        $policyKey = Get-Item -LiteralPath ([string]$policy.Path) -ErrorAction Stop
        $policyExists = $policyKey.GetValueNames() -contains [string]$policy.Name
        if ($policyExists) {
            $policyType = $policyKey.GetValueKind([string]$policy.Name).ToString()
            $policyValue = $policyKey.GetValue(
                [string]$policy.Name,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        }
    }
    $expectedPolicyJson = ConvertTo-Json -InputObject @($policy.Value) -Compress -Depth 20
    $actualPolicyJson = ConvertTo-Json -InputObject @($policyValue) -Compress -Depth 20
    if ($policyExists -ne [bool]$policy.Exists -or
        ($policyExists -and
            ($policyType -cne [string]$policy.Type -or $actualPolicyJson -cne $expectedPolicyJson))) {
        throw 'DNS DoHPolicy value/type/data changed after backup'
    }

    $currentDohEntries = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
    foreach ($saved in @($Snapshot.DohEntries)) {
        $savedAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$saved.ServerAddress)
        $dohMatches = @($currentDohEntries | Where-Object {
                (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $savedAddress
            })
        if ($dohMatches.Count -gt 1) { throw "Duplicate current DoH registration for $savedAddress" }
        if (($dohMatches.Count -eq 1) -ne [bool]$saved.Exists) {
            throw "DoH registration existence changed after backup: $savedAddress"
        }
        if ($dohMatches.Count -eq 1) {
            $current = $dohMatches[0]
            if ([string]$current.DohTemplate -cne [string]$saved.DohTemplate -or
                [bool]$current.AllowFallbackToUdp -ne [bool]$saved.AllowFallbackToUdp -or
                [bool]$current.AutoUpgrade -ne [bool]$saved.AutoUpgrade) {
                throw "DoH registration changed after backup: $savedAddress"
            }
        }
    }

    $currentAdapters = @(Get-PhysicalAdapters -RequireVpnInspection)
    $savedAdapters = @($Snapshot.Adapters)
    if ($currentAdapters.Count -ne $savedAdapters.Count) {
        throw 'Physical DNS adapter count changed after backup'
    }
    $currentByGuid = @{}
    foreach ($adapter in $currentAdapters) {
        $guid = [string]$adapter.InterfaceGuid
        if (-not $guid.StartsWith('{')) { $guid = "{$guid}" }
        if ($currentByGuid.ContainsKey($guid)) { throw "Duplicate current DNS adapter GUID: $guid" }
        $currentByGuid[$guid] = $adapter
    }

    foreach ($savedAdapter in $savedAdapters) {
        $guid = [string]$savedAdapter.InterfaceGuid
        if (-not $currentByGuid.ContainsKey($guid)) {
            throw "Sealed DNS adapter is no longer present: $guid"
        }
        $currentAdapter = $currentByGuid[$guid]
        if ([string]$currentAdapter.InterfaceDescription -cne [string]$savedAdapter.InterfaceDescription) {
            throw "DNS adapter identity changed after backup: $guid"
        }
        $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $currentAdapter.InterfaceIndex -ErrorAction Stop)
        $ipv6Binding = $currentAdapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
        foreach ($savedFamily in @($savedAdapter.Families)) {
            $family = [int]$savedFamily.AddressFamily
            $instances = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq $family })
            if ($instances.Count -ne 1) {
                throw "DNS family state changed or is ambiguous for $guid/$family"
            }
            if ($family -eq 23 -and [bool]$savedFamily.Managed -ne ([bool]$ipv6Binding.Enabled -and (Test-DNSIPv6StackEnabled))) {
                throw "IPv6 binding applicability changed after DNS backup: $guid"
            }
            if ([int]$Snapshot.SchemaVersion -eq 5 -and $family -eq 23 -and
                [bool]$savedFamily.InterfaceDohManaged -ne [bool]$ipv6Binding.Enabled) {
                throw "IPv6 native DoH applicability changed after DNS backup: $guid"
            }
            $savedServers = @($savedFamily.ServerAddresses | ForEach-Object {
                    ConvertTo-DnsCanonicalAddress -Address ([string]$_)
                })
            $currentServers = @($instances[0].ServerAddresses | ForEach-Object {
                    ConvertTo-DnsCanonicalAddress -Address ([string]$_)
                })
            if (($savedServers -join [char]0) -cne ($currentServers -join [char]0)) {
                throw "DNS server order/state changed after backup: $guid/$family"
            }
            $interfaceDohManaged = if ([int]$Snapshot.SchemaVersion -eq 5) {
                [bool]$savedFamily.InterfaceDohManaged
            }
            else { [bool]$savedFamily.Managed }
            if ([int]$Snapshot.SchemaVersion -in @(4, 5) -and $interfaceDohManaged) {
                $currentInterfaceDoh = Get-DnsInterfaceDohState -InterfaceGuid $guid -AddressFamily $family
                if (($currentInterfaceDoh | ConvertTo-Json -Compress -Depth 8) -cne
                    ($savedFamily.InterfaceDoh | ConvertTo-Json -Compress -Depth 8)) {
                    throw "Native interface DoH state changed after DNS backup: $guid/$family"
                }
            }

            $registryPath = [string]$savedFamily.RegistryPath
            $keyExists = Test-Path -LiteralPath $registryPath -PathType Container -ErrorAction Stop
            if ($keyExists -ne [bool]$savedFamily.RegistryKeyExisted) {
                throw "DNS interface key existence changed after backup: $guid/$family"
            }
            $valueExists = $false
            $valueType = $null
            $value = $null
            if ($keyExists) {
                $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
                $valueExists = $key.GetValueNames() -contains 'NameServer'
                if ($valueExists) {
                    $valueType = $key.GetValueKind('NameServer').ToString()
                    $value = $key.GetValue(
                        'NameServer',
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                }
            }
            $expectedValueJson = ConvertTo-Json -InputObject @($savedFamily.NameServerValue) -Compress -Depth 20
            $actualValueJson = ConvertTo-Json -InputObject @($value) -Compress -Depth 20
            if ($valueExists -ne [bool]$savedFamily.NameServerExisted -or
                ($valueExists -and
                    ($valueType -cne [string]$savedFamily.NameServerType -or
                     $actualValueJson -cne $expectedValueJson))) {
                throw "DNS NameServer prestate changed after backup: $guid/$family"
            }
        }
    }
    return $true
}
