function Backup-DNSSettings {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$ManagedDohAddresses = @(),

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess('Selected physical network adapters', 'Back up exact DNS pre-state')) {
        return $null
    }

    try {
        $adapters = @(Get-PhysicalAdapters -RequireVpnInspection)
        if ($adapters.Count -eq 0) {
            throw 'No physical adapters were found for DNS backup'
        }

        $managedAddresses = @($ManagedDohAddresses |
            Where-Object { $_ } |
            ForEach-Object { ConvertTo-DnsCanonicalAddress -Address ([string]$_) } |
            Sort-Object -Unique)

        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $policyName = 'DoHPolicy'
        $policyKeyExisted = Test-Path -LiteralPath $policyPath
        $policyExisted = $false
        $policyType = $null
        $policyValue = $null
        if ($policyKeyExisted) {
            $policyKey = Get-Item -LiteralPath $policyPath -ErrorAction Stop
            $policyExisted = $policyKey.GetValueNames() -contains $policyName
            if ($policyExisted) {
                $policyType = $policyKey.GetValueKind($policyName).ToString()
                $policyValue = $policyKey.GetValue(
                    $policyName,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
            }
        }

        $currentDohEntries = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
        $dohStates = [System.Collections.Generic.List[object]]::new()
        foreach ($address in $managedAddresses) {
            $dohMatches = @($currentDohEntries | Where-Object {
                    (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq [string]$address
                })
            if ($dohMatches.Count -gt 1) {
                throw "Multiple DoH registrations exist for managed address $address"
            }
            $entry = if ($dohMatches.Count -eq 1) { $dohMatches[0] } else { $null }
            $dohStates.Add([PSCustomObject]@{
                    ServerAddress      = [string]$address
                    Exists             = [bool]($null -ne $entry)
                    DohTemplate        = if ($entry) { [string]$entry.DohTemplate } else { $null }
                    AllowFallbackToUdp = if ($entry) { [bool]$entry.AllowFallbackToUdp } else { $null }
                    AutoUpgrade        = if ($entry) { [bool]$entry.AutoUpgrade } else { $null }
                })
        }

        $adapterStates = [System.Collections.Generic.List[object]]::new()
        $seenAdapterGuids = @{}
        foreach ($adapter in $adapters) {
            $interfaceGuid = [string]$adapter.InterfaceGuid
            if ([string]::IsNullOrWhiteSpace($interfaceGuid)) {
                throw "Adapter has no stable InterfaceGuid: $($adapter.Name)"
            }
            if (-not $interfaceGuid.StartsWith('{')) { $interfaceGuid = "{$interfaceGuid}" }
            if ($seenAdapterGuids.ContainsKey($interfaceGuid)) {
                throw "Duplicate physical-adapter InterfaceGuid in DNS backup scope: $interfaceGuid"
            }
            $seenAdapterGuids[$interfaceGuid] = $true

            $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop)
            $ipv4Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 2 })
            $ipv6Instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq 23 })
            if ($ipv4Instance.Count -ne 1 -or $ipv6Instance.Count -ne 1) {
                throw "DNS client address-family state is incomplete for adapter $($adapter.Name)"
            }

            $ipv6Binding = $adapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
            # Resolver mutation and Windows' UI-visible native DoH properties
            # have different applicability. DisabledComponents=0xFF suppresses
            # effective IPv6 resolvers, but Windows still persists and displays
            # the static IPv6 NameServer plus Doh6 state. Seal that native state
            # whenever the adapter binding exists so Apply never leaves a visible
            # provider pair labelled unencrypted and Restore can reproduce the
            # exact prior state without claiming active IPv6 transport.
            $managedFamilies = if ($ipv6Binding.Enabled -and (Test-DNSIPv6StackEnabled)) { @(2, 23) } else { @(2) }
            $interfaceDohManagedFamilies = if ($ipv6Binding.Enabled) { @(2, 23) } else { @(2) }
            $familyStates = [System.Collections.Generic.List[object]]::new()
            foreach ($family in @(2, 23)) {
                $registryBase = if ($family -eq 2) {
                    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
                }
                else {
                    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces'
                }
                $registryPath = "$registryBase\$interfaceGuid"
                $keyExisted = Test-Path -LiteralPath $registryPath
                if (-not $keyExisted -and $family -in $interfaceDohManagedFamilies) {
                    throw "DNS interface registry key is unavailable for exact backup: $registryPath"
                }
                $valueExisted = $false
                $valueType = $null
                $value = $null
                if ($keyExisted) {
                    $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
                    $valueExisted = $key.GetValueNames() -contains 'NameServer'
                    if ($valueExisted) {
                        $valueType = $key.GetValueKind('NameServer').ToString()
                        $value = $key.GetValue(
                            'NameServer',
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )
                    }
                }
                $instance = if ($family -eq 2) { $ipv4Instance[0] } else { $ipv6Instance[0] }
                foreach ($serverAddress in @($instance.ServerAddresses | Where-Object { $_ })) {
                    $parsedServerAddress = $null
                    if (-not [System.Net.IPAddress]::TryParse([string]$serverAddress, [ref]$parsedServerAddress)) {
                        throw "Invalid DNS server address in current state for $interfaceGuid/$family`: $serverAddress"
                    }
                }
                if ($valueExisted -and $valueType -notin @('String', 'ExpandString')) {
                    throw "Unsupported NameServer registry type in current state for $interfaceGuid/$family`: $valueType"
                }
                $familyStates.Add([PSCustomObject]@{
                        AddressFamily        = $family
                        Managed              = ($family -in $managedFamilies)
                        InterfaceDohManaged  = ($family -in $interfaceDohManagedFamilies)
                        ServerAddresses      = @($instance.ServerAddresses)
                        InterfaceDoh         = if ($family -in $interfaceDohManagedFamilies) {
                            Get-DnsInterfaceDohState -InterfaceGuid $interfaceGuid -AddressFamily $family
                        }
                        else { $null }
                        RegistryPath         = $registryPath
                        RegistryKeyExisted   = [bool]$keyExisted
                        NameServerExisted    = [bool]$valueExisted
                        NameServerType       = $valueType
                        NameServerValue      = $value
                    })
            }

            $adapterStates.Add([PSCustomObject]@{
                    InterfaceGuid        = $interfaceGuid
                    InterfaceDescription = [string]$adapter.InterfaceDescription
                    Families             = @($familyStates)
                })
        }

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would back up DNS state for $($adapterStates.Count) adapter(s)" -Module $script:ModuleName
            return 'DRYRUN'
        }

        $snapshot = [PSCustomObject]@{
            SchemaVersion = 5
            Policy        = [PSCustomObject]@{
                Path       = $policyPath
                Name       = $policyName
                KeyExisted = [bool]$policyKeyExisted
                Exists     = [bool]$policyExisted
                Type       = $policyType
                Value      = $policyValue
            }
            DohEntries    = @($dohStates)
            Adapters      = @($adapterStates)
        }
        $null = Assert-DNSBackupSnapshot -Snapshot $snapshot
        $backupFile = Register-Backup -Type 'DNS' -Data $snapshot -Name 'DNS_PreState'
        if (-not $backupFile -or -not (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
            throw 'DNS pre-state registration did not create an artifact'
        }
        $roundTrip = Get-Content -LiteralPath $backupFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $null = Assert-DNSBackupSnapshot -Snapshot $roundTrip
        if (@($roundTrip.Adapters).Count -ne $adapterStates.Count) { throw 'DNS adapter count changed during artifact round-trip' }

        Write-Log -Level SUCCESS -Message "DNS pre-state backed up for $($adapterStates.Count) adapter(s) and $($dohStates.Count) managed DoH endpoint(s)" -Module $script:ModuleName
        return $backupFile
    }
    catch {
        Write-ErrorLog -Message 'Failed to create complete DNS pre-state backup' -Module $script:ModuleName -ErrorRecord $_
        return $null
    }
}
