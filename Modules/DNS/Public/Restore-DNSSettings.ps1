function Test-DNSCombinedSessionPolicyKeyAbsence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $DNSSnapshot,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityBaselineRegistryBackupPath
    )

    if (-not (Test-Path -LiteralPath $SecurityBaselineRegistryBackupPath -PathType Leaf)) {
        throw "SecurityBaseline registry prestate not found: $SecurityBaselineRegistryBackupPath"
    }
    $baseline = Get-Content -LiteralPath $SecurityBaselineRegistryBackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$baseline.SchemaVersion -notin @(3, 4) -or
        -not $baseline.PSObject.Properties['Computer'] -or
        -not $baseline.PSObject.Properties['ComputerClearKeys']) {
        throw 'SecurityBaseline registry prestate has an unsupported schema'
    }

    $policyKeyName = 'Software\Policies\Microsoft\Windows NT\DNSClient'
    $directStates = @($baseline.Computer | Where-Object {
            $normalizedKeyName = ([string]$_.KeyName) -replace '^\[', '' -replace '\]$', ''
            $normalizedKeyName.Equals($policyKeyName, [StringComparison]::OrdinalIgnoreCase)
        })
    $clearStates = @($baseline.ComputerClearKeys | Where-Object {
            $normalizedKeyName = ([string]$_.KeyName) -replace '^\[', '' -replace '\]$', ''
            $normalizedKeyName.Equals($policyKeyName, [StringComparison]::OrdinalIgnoreCase)
        })
    if ($directStates.Count -eq 0 -and $clearStates.Count -eq 0) {
        return $false
    }
    if ($clearStates.Count -gt 1) {
        throw 'SecurityBaseline registry prestate has duplicate DNS clear-key state'
    }

    $keyExistence = @(
        @($directStates | ForEach-Object {
                if (-not $_.PSObject.Properties['KeyExisted']) {
                    throw 'SecurityBaseline DNS value prestate has no key-existence state'
                }
                [bool]$_.KeyExisted
            })
        @($clearStates | ForEach-Object {
                if (-not $_.PSObject.Properties['KeyExisted']) {
                    throw 'SecurityBaseline DNS clear-key prestate has no key-existence state'
                }
                [bool]$_.KeyExisted
            })
    )
    $distinctKeyExistence = @($keyExistence | Select-Object -Unique)
    if ($distinctKeyExistence.Count -ne 1) {
        throw 'SecurityBaseline DNS key-existence prestate is inconsistent'
    }
    if ([bool]$distinctKeyExistence[0]) {
        return $false
    }
    if ([bool]$DNSSnapshot.Policy.Exists -or
        @($directStates | Where-Object { [bool]$_.Exists }).Count -gt 0 -or
        @($clearStates | Where-Object { @($_.Values).Count -gt 0 }).Count -gt 0) {
        throw 'Combined DNS session prestate records values under an absent policy key'
    }

    return -not (Test-NoIDRegistryKey -LiteralPath ([string]$DNSSnapshot.Policy.Path))
}

function Restore-DNSSettings {
    <#
    .SYNOPSIS
        Restores the exact DNS prestate captured before DNS Apply.

    .DESCRIPTION
        The DoH policy, the provider DoH registrations and every backed-up
        network adapter that is present are restored and verified. An adapter
        that is no longer present, cannot take DNS settings (disabled, no IP
        interface) or no longer resolves uniquely is left unchanged and named
        with its saved settings, so a sold dock or replaced Wi-Fi stick never
        blocks restoring the rest. Restoring again while it is connected
        completes it. Every step runs on its own; one failure is reported and
        never keeps the other steps from their prestate.

    .PARAMETER NoticeSink
        Receives notes (adapters left unchanged, kept keys). Without it the
        notes are written to the log as warnings.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityBaselineRegistryBackupPath,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.Generic.List[string]]$NoticeSink
    )

    if (-not $PSCmdlet.ShouldProcess('Selected physical network adapters', 'Restore exact DNS pre-state')) {
        return $false
    }

    $restoreErrors = [System.Collections.Generic.List[string]]::new()
    $notices = [System.Collections.Generic.List[string]]::new()
    $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $describeFamilyPrestate = {
        param($FamilyState)
        $label = if ([int]$FamilyState.AddressFamily -eq 2) { 'IPv4' } else { 'IPv6' }
        $addresses = @($FamilyState.ServerAddresses | Where-Object { $_ })
        if ([bool]$FamilyState.NameServerExisted -and
            -not [string]::IsNullOrWhiteSpace([string]$FamilyState.NameServerValue) -and $addresses.Count -gt 0) {
            "$label static DNS $($addresses -join ', ')"
        }
        else {
            "$label automatic DNS (from the router)"
        }
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupFilePath -PathType Leaf)) {
            throw "DNS pre-state artifact not found: $BackupFilePath"
        }
        $snapshot = Get-Content -LiteralPath $BackupFilePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $null = Assert-DNSBackupSnapshot -Snapshot $snapshot
        $dnsSchemaVersion = [int]$snapshot.SchemaVersion
        Write-Log -Level DEBUG -Message 'DNS restore snapshot schema and target inventory validated' -Module 'DNS'
        $combinedPolicyKeyAlreadyAbsent = (
            -not [string]::IsNullOrWhiteSpace($SecurityBaselineRegistryBackupPath) -and
            (Test-DNSCombinedSessionPolicyKeyAbsence `
                -DNSSnapshot $snapshot `
                -SecurityBaselineRegistryBackupPath $SecurityBaselineRegistryBackupPath)
        )

        # Resolve and validate every mutation dependency up front. An adapter
        # that cannot be restored is decided here and excluded as a whole;
        # unsupported sealed data fails before the first restore write. Checks
        # after a write only verify what Windows' own DNS APIs did.
        $policy = $snapshot.Policy
        $policyPropertyType = $null
        $policyRestoreValue = $null
        if ($combinedPolicyKeyAlreadyAbsent) {
            Write-Log -Level DEBUG -Message 'DNS policy key already holds the combined session prestate' -Module 'DNS'
        }
        elseif ([bool]$policy.Exists) {
            $policyPropertyType = switch ([string]$policy.Type) {
                'DWord'       { 'DWord' }
                'QWord'       { 'QWord' }
                'String'      { 'String' }
                'ExpandString'{ 'ExpandString' }
                'MultiString' { 'MultiString' }
                'Binary'      { 'Binary' }
                default { throw "Unsupported backed-up DoHPolicy type: $($policy.Type)" }
            }
            $policyRestoreValue = switch ([string]$policy.Type) {
                'DWord'       { [int]$policy.Value }
                'QWord'       { [long]$policy.Value }
                'MultiString' { [string[]]@($policy.Value) }
                'Binary'      { [byte[]]@($policy.Value) }
                default       { [string]$policy.Value }
            }
        }
        Write-Log -Level DEBUG -Message 'DNS restore policy preflight completed' -Module 'DNS'

        $currentDoh = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
        foreach ($dohState in @($snapshot.DohEntries)) {
            $address = [string]$dohState.ServerAddress
            $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address $address
            $currentMatches = @($currentDoh | Where-Object {
                    (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalAddress
                })
            if ($currentMatches.Count -gt 1) {
                throw "Multiple current DoH registrations exist for $address"
            }
            if ($dnsSchemaVersion -ge 6) {
                $null = Get-DnsDohEndpointRegistryState -Address $address
            }
        }
        Write-Log -Level DEBUG -Message 'DNS restore DoH preflight completed' -Module 'DNS'

        $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        $adapterRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterState in @($snapshot.Adapters)) {
            $adapterLabel = "'$($adapterState.InterfaceDescription)' ($($adapterState.InterfaceGuid))"
            $managedFamilies = @($adapterState.Families | Where-Object {
                    $interfaceDohManaged = if ($dnsSchemaVersion -ge 5) {
                        [bool]$_.InterfaceDohManaged
                    }
                    else { [bool]$_.Managed }
                    [bool]$_.Managed -or $interfaceDohManaged
                })
            $savedSettings = (@($managedFamilies | Where-Object { [bool]$_.Managed } |
                        ForEach-Object { & $describeFamilyPrestate $_ }) -join '; ')
            if ([string]::IsNullOrWhiteSpace($savedSettings)) { $savedSettings = 'its encrypted-DNS settings only' }
            $adapter = @($currentAdapters | Where-Object {
                    $currentGuid = [string]$_.InterfaceGuid
                    if (-not $currentGuid.StartsWith('{')) { $currentGuid = "{$currentGuid}" }
                    $currentGuid -eq [string]$adapterState.InterfaceGuid
                })
            # DNS servers are set through the live adapter. An unplugged or
            # not-present adapter (InterfaceOperationalStatus 6) cannot take
            # them; it is left unchanged and named with its saved settings.
            if ($adapter.Count -eq 0 -or
                ($adapter.Count -eq 1 -and [int]$adapter[0].InterfaceOperationalStatus -eq 6)) {
                $notices.Add("Network adapter $adapterLabel from the backup is not present, so its DNS settings were not changed. Before Apply it used $savedSettings. Reconnect it and run Restore again, or set this in Windows Settings.")
                continue
            }
            if ($adapter.Count -ne 1) {
                $restoreErrors.Add("Adapter identity no longer resolves uniquely, so its DNS settings were not changed: $($adapterState.InterfaceGuid)")
                continue
            }
            if ([string]$adapter[0].InterfaceDescription -cne [string]$adapterState.InterfaceDescription) {
                Write-Log -Level INFO -Message "Network adapter $($adapterState.InterfaceGuid) now reports '$($adapter[0].InterfaceDescription)' instead of '$($adapterState.InterfaceDescription)'; it is restored by its unchanged identity" -Module 'DNS'
            }
            try {
                $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].InterfaceIndex -ErrorAction Stop)
            }
            catch {
                $notices.Add("Network adapter $adapterLabel cannot take DNS settings right now (it is disabled or has no IP interface), so they were not changed. Before Apply it used $savedSettings. Enable it and run Restore again, or set this in Windows Settings.")
                continue
            }
            $skippedFamilies = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($familyState in $managedFamilies) {
                $family = [int]$familyState.AddressFamily
                $instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq $family })
                if ($instance.Count -ne 1) {
                    $null = $skippedFamilies.Add($family)
                    $notices.Add("Network adapter $adapterLabel has no $(if ($family -eq 2) { 'IPv4' } else { 'IPv6' }) DNS interface right now, so that part was not changed. Before Apply it used $(& $describeFamilyPrestate $familyState).")
                }
            }
            $adapterRestorePlans.Add([PSCustomObject]@{
                    Adapter         = $adapter[0]
                    AdapterState    = $adapterState
                    DnsInstances    = @($dnsInstances)
                    SkippedFamilies = $skippedFamilies
                })
        }
        $restoredFamilies = {
            param($AdapterPlan)
            @($AdapterPlan.AdapterState.Families | Where-Object {
                    -not $AdapterPlan.SkippedFamilies.Contains([int]$_.AddressFamily)
                })
        }
        # Family and native-DoH restore plans, including the static-address
        # check, are pure decisions and complete before the first write.
        $familyRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterPlan in $adapterRestorePlans) {
            $adapterState = $adapterPlan.AdapterState
            $dnsInstances = @($adapterPlan.DnsInstances)
            foreach ($familyState in @(& $restoredFamilies $adapterPlan | Where-Object { [bool]$_.Managed })) {
                $family = [int]$familyState.AddressFamily
                $instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq $family })
                $originalAddresses = @($familyState.ServerAddresses | Where-Object { $_ })
                $hasStaticOverride = [bool]$familyState.NameServerExisted -and
                    -not [string]::IsNullOrWhiteSpace([string]$familyState.NameServerValue)
                if ($hasStaticOverride -and $originalAddresses.Count -eq 0) {
                    throw "Static DNS pre-state has no addresses for $($adapterState.InterfaceGuid)/$family"
                }
                $familyRestorePlans.Add([PSCustomObject]@{
                        AdapterState      = $adapterState
                        FamilyState       = $familyState
                        Family            = $family
                        Instance          = $instance[0]
                        OriginalAddresses = @($originalAddresses)
                        HasStaticOverride = [bool]$hasStaticOverride
                })
            }
        }

        $interfaceDohRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterPlan in $adapterRestorePlans) {
            foreach ($familyState in @(& $restoredFamilies $adapterPlan)) {
                $interfaceDohManaged = if ($dnsSchemaVersion -ge 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if ($dnsSchemaVersion -ge 4 -and $interfaceDohManaged) {
                    $interfaceDohRestorePlans.Add([PSCustomObject]@{
                            AdapterState = $adapterPlan.AdapterState
                            FamilyState  = $familyState
                            Family       = [int]$familyState.AddressFamily
                        })
                }
            }
        }

        # Schema 6 reinstates raw registry state last. Read it now, so an
        # unreadable key or an unsupported value type fails before the first
        # write instead of after the API phase.
        if ($dnsSchemaVersion -ge 6) {
            foreach ($adapterPlan in $adapterRestorePlans) {
                $preflightGuid = [string]$adapterPlan.AdapterState.InterfaceGuid
                $preflightFamilies = @(& $restoredFamilies $adapterPlan | Where-Object { [bool]$_.InterfaceDohManaged } | ForEach-Object { [int]$_.AddressFamily })
                $null = @(Get-DnsInterfaceSpecificKeyInventory -InterfaceGuid $preflightGuid)
                $null = @(Get-DnsInterfaceDohRegistryValues -InterfaceGuid $preflightGuid -AddressFamilies $preflightFamilies)
            }
        }
        Write-Log -Level DEBUG -Message 'DNS restore adapter and address-family preflight completed' -Module 'DNS'

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would restore DNS state from schema v$dnsSchemaVersion artifact" -Module 'DNS'
            return ($restoreErrors.Count -eq 0)
        }

        # Restore the sole DNS policy value owned by this module.
        try {
            if ([bool]$policy.Exists) {
                if (-not (Test-Path -LiteralPath $policy.Path)) {
                    New-NoIDRegistryKey -LiteralPath $policy.Path | Out-Null
                }
                New-ItemProperty -LiteralPath $policy.Path -Name ([string]$policy.Name) `
                    -PropertyType $policyPropertyType -Value $policyRestoreValue `
                    -Force -ErrorAction Stop | Out-Null
            }
            elseif (Test-Path -LiteralPath $policy.Path) {
                $policyKey = Get-Item -LiteralPath $policy.Path -ErrorAction Stop
                if ($policyKey.GetValueNames() -contains [string]$policy.Name) {
                    Remove-ItemProperty -LiteralPath $policy.Path -Name ([string]$policy.Name) -ErrorAction Stop
                    $policyKey = Get-Item -LiteralPath $policy.Path -ErrorAction Stop
                }
                if (-not [bool]$policy.KeyExisted) {
                    $remainingPolicyValues = @($policyKey.GetValueNames())
                    $remainingPolicySubKeys = @($policyKey.GetSubKeyNames())
                    if ($remainingPolicyValues.Count -eq 0 -and $remainingPolicySubKeys.Count -eq 0) {
                        Remove-Item -LiteralPath $policy.Path -Force -ErrorAction Stop
                    }
                    else {
                        # The shared DNSClient policy key now holds policy this
                        # module does not own; it is kept instead of destroyed.
                        $null = $retainedKeys.Add([string]$policy.Path)
                        $notices.Add((Format-NoIDRetainedKeyNotice -Path ([string]$policy.Path) `
                                    -Values ([string[]]$remainingPolicyValues) -SubKeys ([string[]]$remainingPolicySubKeys)))
                    }
                }
            }
        }
        catch {
            $restoreErrors.Add("DoHPolicy could not be restored: $($_.Exception.Message)")
        }
        Write-Log -Level DEBUG -Message 'DNS restore policy mutation completed' -Module 'DNS'

        # Replace only the DoH registrations selected by the original Apply.
        foreach ($dohState in @($snapshot.DohEntries)) {
            $address = [string]$dohState.ServerAddress
            try {
                $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address $address
                $currentMatches = @($currentDoh | Where-Object {
                        (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalAddress
                    })
                if ($currentMatches.Count -gt 1) { throw "Multiple current DoH registrations exist for $address" }
                if ([bool]$dohState.Exists) {
                    $alreadyExact = ($currentMatches.Count -eq 1 -and
                        [string]$currentMatches[0].DohTemplate -ceq [string]$dohState.DohTemplate -and
                        [bool]$currentMatches[0].AllowFallbackToUdp -eq [bool]$dohState.AllowFallbackToUdp -and
                        [bool]$currentMatches[0].AutoUpgrade -eq [bool]$dohState.AutoUpgrade)
                    if ($alreadyExact) {
                        Write-Log -Level DEBUG -Message "DNS restore skipped unchanged DoH registration: $address" -Module 'DNS'
                        continue
                    }
                    $dohParameters = @{
                        ServerAddress      = $address
                        DohTemplate        = [string]$dohState.DohTemplate
                        AllowFallbackToUdp = [bool]$dohState.AllowFallbackToUdp
                        AutoUpgrade        = [bool]$dohState.AutoUpgrade
                        ErrorAction        = 'Stop'
                    }
                    if ($currentMatches.Count -eq 1) {
                        Set-DnsClientDohServerAddress @dohParameters | Out-Null
                    }
                    else {
                        Add-DnsClientDohServerAddress @dohParameters | Out-Null
                    }
                }
                elseif ($currentMatches.Count -eq 1) {
                    Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction Stop
                }
            }
            catch {
                $restoreErrors.Add("DoH registration $address could not be restored: $($_.Exception.Message)")
            }
        }
        Write-Log -Level DEBUG -Message 'DNS restore DoH mutation phase completed' -Module 'DNS'

        # Clear a schema-4+ native DoH state that was originally absent while
        # the applied provider server list is still available. The following
        # ResetServerAddresses call then returns the family to DHCP. Supplying
        # an empty NameServer to DNS_SETTING_DOH is not a valid Windows API
        # request, so this ordering is required for exact automatic-DNS state.
        if ($dnsSchemaVersion -ge 4) {
            foreach ($familyPlan in @($interfaceDohRestorePlans | Where-Object {
                        @($_.FamilyState.InterfaceDoh.Properties).Count -eq 0
                    })) {
                try {
                    $currentInterfaceDoh = Get-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$familyPlan.AdapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyPlan.Family)
                    if (@($currentInterfaceDoh.Properties).Count -eq 0) {
                        # Repeat restore: this family already holds the sealed
                        # property-free state. The resolver list may legitimately
                        # be empty (for example DHCP supplied no IPv6 resolver).
                        continue
                    }
                    $appliedServers = @($currentInterfaceDoh.NameServers)
                    $interfaceDohCleared = Clear-DnsInterfaceDohPropertiesForResolverReset `
                        -InterfaceGuid ([string]$familyPlan.AdapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyPlan.Family) `
                        -CurrentNameServers $appliedServers `
                        -Confirm:$false
                    if (-not $interfaceDohCleared) {
                        throw 'Native interface secure-DNS clear was not confirmed'
                    }
                }
                catch {
                    $restoreErrors.Add("$($_.Exception.Message): $($familyPlan.AdapterState.InterfaceGuid)/$($familyPlan.Family)")
                }
            }
        }

        # The DNS-client ResetServerAddresses CIM option is adapter-wide even
        # when its input identifies one family. Use the native family selector:
        # a binding-disabled, unowned IPv6 family must survive an IPv4 reset,
        # including any user changes made after this backup was taken.
        foreach ($familyPlan in @($familyRestorePlans | Where-Object { -not $_.HasStaticOverride })) {
            Write-Log -Level DEBUG -Message "Restoring automatic DNS family $($familyPlan.Family) on $($familyPlan.AdapterState.InterfaceGuid)" -Module 'DNS'
            try {
                if (-not (Reset-DnsInterfaceServerAddresses `
                        -InterfaceGuid ([string]$familyPlan.AdapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyPlan.Family) -Confirm:$false)) {
                    throw 'Native DNS family reset was not confirmed'
                }
            }
            catch {
                $restoreErrors.Add("$($_.Exception.Message): $($familyPlan.AdapterState.InterfaceGuid)/$($familyPlan.Family)")
            }
        }
        foreach ($familyPlan in @($familyRestorePlans | Where-Object { $_.HasStaticOverride })) {
            Write-Log -Level DEBUG -Message "Restoring static DNS family $($familyPlan.Family) on $($familyPlan.AdapterState.InterfaceGuid)" -Module 'DNS'
            try {
                Set-DnsClientServerAddress -InputObject $familyPlan.Instance `
                    -ServerAddresses $familyPlan.OriginalAddresses -ErrorAction Stop
            }
            catch {
                $restoreErrors.Add("Static DNS could not be restored on $($familyPlan.AdapterState.InterfaceGuid)/$($familyPlan.Family): $($_.Exception.Message)")
            }
        }

        # Schema 4+ seals Windows' native per-interface DoH properties. Replay
        # them only after the supported resolver cmdlets have completed their
        # adapter-wide writes, because those writes can clear this UI-visible
        # state. Schema 3 remains readable for already sealed 2.2.5 sessions.
        if ($dnsSchemaVersion -ge 4) {
            foreach ($familyPlan in @($interfaceDohRestorePlans | Where-Object {
                        @($_.FamilyState.InterfaceDoh.Properties).Count -gt 0
                    })) {
                try {
                    $savedInterfaceDoh = $familyPlan.FamilyState.InterfaceDoh
                    $interfaceDohRestored = Set-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$familyPlan.AdapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyPlan.Family) `
                        -NameServers @($savedInterfaceDoh.NameServers) `
                        -Properties @($savedInterfaceDoh.Properties) `
                        -Confirm:$false
                    if (-not $interfaceDohRestored) {
                        throw 'Native interface secure-DNS restore was not confirmed'
                    }
                }
                catch {
                    $restoreErrors.Add("$($_.Exception.Message): $($familyPlan.AdapterState.InterfaceGuid)/$($familyPlan.Family)")
                }
            }
        }

        # Reinstate exact registry existence/type/data only after all supported
        # DNS-client cmdlets have completed their adapter-wide side effects.
        $registryRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterPlan in $adapterRestorePlans) {
            foreach ($familyState in @(& $restoredFamilies $adapterPlan)) {
                $interfaceDohManaged = if ($dnsSchemaVersion -ge 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if ([bool]$familyState.Managed -or $interfaceDohManaged) {
                    $registryRestorePlans.Add([PSCustomObject]@{
                            AdapterState = $adapterPlan.AdapterState
                            FamilyState  = $familyState
                            Family       = [int]$familyState.AddressFamily
                        })
                }
            }
        }
        foreach ($familyPlan in $registryRestorePlans) {
            $adapterState = $familyPlan.AdapterState
            $familyState = $familyPlan.FamilyState
            $family = [int]$familyPlan.Family
            try {
                if (-not (Test-Path -LiteralPath $familyState.RegistryPath)) {
                    if ([bool]$familyState.RegistryKeyExisted -or [bool]$familyState.NameServerExisted) {
                        New-NoIDRegistryKey -LiteralPath $familyState.RegistryPath | Out-Null
                    }
                }
                if (Test-Path -LiteralPath $familyState.RegistryPath) {
                    $registryKey = Get-Item -LiteralPath $familyState.RegistryPath -ErrorAction Stop
                    if ([bool]$familyState.NameServerExisted) {
                        $propertyType = switch ([string]$familyState.NameServerType) {
                            'String'       { 'String' }
                            'ExpandString' { 'ExpandString' }
                            default { throw "Unsupported NameServer registry type: $($familyState.NameServerType)" }
                        }
                        $nameServerPresent = $registryKey.GetValueNames() -contains 'NameServer'
                        $currentType = if ($nameServerPresent) { $registryKey.GetValueKind('NameServer').ToString() } else { $null }
                        $currentValue = if ($nameServerPresent) {
                            [string]$registryKey.GetValue(
                                'NameServer', $null,
                                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                            )
                        }
                        else { $null }
                        if (-not $nameServerPresent -or $currentType -cne [string]$familyState.NameServerType -or
                            $currentValue -cne [string]$familyState.NameServerValue) {
                            New-ItemProperty -LiteralPath $familyState.RegistryPath -Name 'NameServer' `
                                -PropertyType $propertyType -Value ([string]$familyState.NameServerValue) `
                                -Force -ErrorAction Stop | Out-Null
                        }
                    }
                    elseif ($registryKey.GetValueNames() -contains 'NameServer') {
                        Remove-ItemProperty -LiteralPath $familyState.RegistryPath -Name 'NameServer' -ErrorAction Stop
                    }
                    if (-not [bool]$familyState.NameServerExisted -and -not [bool]$familyState.RegistryKeyExisted) {
                        $registryKey = Get-Item -LiteralPath $familyState.RegistryPath -ErrorAction Stop
                        $remainingValues = @($registryKey.GetValueNames())
                        $remainingSubKeys = @($registryKey.GetSubKeyNames())
                        if ($remainingValues.Count -gt 0 -or $remainingSubKeys.Count -gt 0) {
                            # Windows or another tool keeps its own settings in
                            # this key now; it is kept instead of destroyed.
                            $null = $retainedKeys.Add([string]$familyState.RegistryPath)
                            $notices.Add((Format-NoIDRetainedKeyNotice -Path ([string]$familyState.RegistryPath) `
                                        -Values ([string[]]$remainingValues) -SubKeys ([string[]]$remainingSubKeys)))
                        }
                        else {
                            Remove-Item -LiteralPath ([string]$familyState.RegistryPath) -Force -ErrorAction Stop
                        }
                    }
                }
            }
            catch {
                $restoreErrors.Add("DNS registry state could not be restored on $($adapterState.InterfaceGuid)/$family`: $($_.Exception.Message)")
            }
        }

        # Windows' DoH APIs cannot express an absent Flags value or remove the
        # keys they created; schema 6 reinstates that raw state last.
        if ($dnsSchemaVersion -ge 6) {
            foreach ($dohState in @($snapshot.DohEntries)) {
                try {
                    if (-not (Restore-DnsDohEndpointRegistryState -Address ([string]$dohState.ServerAddress) `
                            -Expected $dohState.Registry -Confirm:$false)) {
                        throw 'not confirmed'
                    }
                }
                catch {
                    $restoreErrors.Add("DoH endpoint registry restore failed for $($dohState.ServerAddress): $($_.Exception.Message)")
                }
            }
            foreach ($adapterPlan in $adapterRestorePlans) {
                $adapterState = $adapterPlan.AdapterState
                try {
                    $dohFamilies = @(& $restoredFamilies $adapterPlan | Where-Object { [bool]$_.InterfaceDohManaged } | ForEach-Object { [int]$_.AddressFamily })
                    $dohRegistryValues = @($adapterState.InterfaceDohRegistryValues | Where-Object {
                            -not $adapterPlan.SkippedFamilies.Contains([int]$_.AddressFamily)
                        })
                    if (-not (Restore-DnsInterfaceDohRegistryValues -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                            -AddressFamilies $dohFamilies -Expected $dohRegistryValues -Confirm:$false)) {
                        throw "DNS interface DoH registry values were not restored: $($adapterState.InterfaceGuid)"
                    }
                    if (-not (Remove-DnsInterfaceSpecificKeysOutsideInventory -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                            -Inventory @($adapterState.InterfaceSpecificKeys | ForEach-Object { [string]$_ }) -Confirm:$false)) {
                        throw "DNS interface-specific registry keys were not restored: $($adapterState.InterfaceGuid)"
                    }
                }
                catch {
                    $restoreErrors.Add($_.Exception.Message)
                }
            }
        }

        # Verify policy state.
        $policyPresent = $false
        $actualPolicy = $null
        $actualPolicyType = $null
        if (Test-Path -LiteralPath $policy.Path) {
            $policyKey = Get-Item -LiteralPath $policy.Path -ErrorAction Stop
            $policyPresent = $policyKey.GetValueNames() -contains [string]$policy.Name
            if ($policyPresent) {
                $actualPolicy = $policyKey.GetValue(
                    [string]$policy.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $actualPolicyType = $policyKey.GetValueKind([string]$policy.Name).ToString()
            }
        }
        $expectedPolicyJson = ConvertTo-Json -InputObject @($policy.Value) -Compress -Depth 10
        $actualPolicyJson = ConvertTo-Json -InputObject @($actualPolicy) -Compress -Depth 10
        $policyKeyPresent = Test-NoIDRegistryKey -LiteralPath ([string]$policy.Path)
        $expectedPolicyKeyPresent = if ($combinedPolicyKeyAlreadyAbsent) { $false } else { [bool]$policy.KeyExisted }
        if ($retainedKeys.Contains([string]$policy.Path)) { $expectedPolicyKeyPresent = $true }
        if ($policyKeyPresent -ne $expectedPolicyKeyPresent -or
            $policyPresent -ne [bool]$policy.Exists -or
            ($policyPresent -and ($actualPolicyType -ne [string]$policy.Type -or $actualPolicyJson -cne $expectedPolicyJson))) {
            $restoreErrors.Add('DoHPolicy key/value/type/data post-restore verification failed')
        }

        $verifiedDoh = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
        foreach ($dohState in @($snapshot.DohEntries)) {
            $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$dohState.ServerAddress)
            $dohMatches = @($verifiedDoh | Where-Object {
                    (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalAddress
                })
            $expectedMatchCount = if ([bool]$dohState.Exists) { 1 } else { 0 }
            if ($dohMatches.Count -ne $expectedMatchCount) {
                $restoreErrors.Add("DoH registration existence verification failed: $($dohState.ServerAddress)")
                continue
            }
            if ($dohMatches.Count -eq 1 -and
                ([string]$dohMatches[0].DohTemplate -cne [string]$dohState.DohTemplate -or
                    [bool]$dohMatches[0].AllowFallbackToUdp -ne [bool]$dohState.AllowFallbackToUdp -or
                    [bool]$dohMatches[0].AutoUpgrade -ne [bool]$dohState.AutoUpgrade)) {
                $restoreErrors.Add("DoH registration value verification failed: $($dohState.ServerAddress)")
                continue
            }
            if ($dnsSchemaVersion -ge 6 -and
                -not (Test-DnsDohEndpointRegistryStateExact `
                    -Actual (Get-DnsDohEndpointRegistryState -Address ([string]$dohState.ServerAddress)) `
                    -Expected $dohState.Registry)) {
                $restoreErrors.Add("DoH endpoint registry verification failed: $($dohState.ServerAddress)")
            }
        }

        foreach ($adapterPlan in $adapterRestorePlans) {
            $adapterState = $adapterPlan.AdapterState
            try {
                $verifiedInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapterPlan.Adapter.InterfaceIndex -ErrorAction Stop)
            }
            catch {
                $restoreErrors.Add("DNS effective-state verification failed: $($adapterState.InterfaceGuid): $($_.Exception.Message)")
                continue
            }
            $verifiedDohFamilies = @(& $restoredFamilies $adapterPlan | Where-Object { [bool]$_.InterfaceDohManaged } | ForEach-Object { [int]$_.AddressFamily })
            if ($dnsSchemaVersion -ge 6 -and
                -not (Test-DnsInterfaceSpecificKeysWithinInventory -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                    -Inventory @($adapterState.InterfaceSpecificKeys | ForEach-Object { [string]$_ }))) {
                $restoreErrors.Add("DNS interface-specific registry key verification failed: $($adapterState.InterfaceGuid)")
            }
            if ($dnsSchemaVersion -ge 6 -and
                -not (Test-DnsInterfaceDohRegistryValuesExact -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                    -AddressFamilies $verifiedDohFamilies `
                    -Expected @($adapterState.InterfaceDohRegistryValues | Where-Object {
                            -not $adapterPlan.SkippedFamilies.Contains([int]$_.AddressFamily)
                        }))) {
                $restoreErrors.Add("DNS interface DoH registry value verification failed: $($adapterState.InterfaceGuid)")
            }
            foreach ($familyState in @(& $restoredFamilies $adapterPlan | Where-Object {
                        $interfaceDohManaged = if ($dnsSchemaVersion -ge 5) {
                            [bool]$_.InterfaceDohManaged
                        }
                        else { [bool]$_.Managed }
                        [bool]$_.Managed -or $interfaceDohManaged
                    })) {
                $path = [string]$familyState.RegistryPath
                $actualRegistryKeyExists = Test-NoIDRegistryKey -LiteralPath $path
                if ($actualRegistryKeyExists -ne [bool]$familyState.RegistryKeyExisted -and -not $retainedKeys.Contains($path)) {
                    $restoreErrors.Add("DNS registry key existence verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                    continue
                }
                $present = $false
                $actualValue = $null
                $actualType = $null
                if ($actualRegistryKeyExists) {
                    $key = Get-Item -LiteralPath $path -ErrorAction Stop
                    $present = $key.GetValueNames() -contains 'NameServer'
                    if ($present) {
                        $actualValue = $key.GetValue('NameServer', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $actualType = $key.GetValueKind('NameServer').ToString()
                    }
                }
                if ($present -ne [bool]$familyState.NameServerExisted -or
                    ($present -and ($actualType -ne [string]$familyState.NameServerType -or
                        [string]$actualValue -cne [string]$familyState.NameServerValue))) {
                    $restoreErrors.Add("DNS registry pre-state verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                    continue
                }
                if ([bool]$familyState.Managed) {
                    $verifiedFamily = @($verifiedInstances | Where-Object {
                            [int]$_.AddressFamily -eq [int]$familyState.AddressFamily
                        })
                    if ($verifiedFamily.Count -ne 1) {
                        $restoreErrors.Add("DNS effective-state verification instance is missing: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                        continue
                    }

                    # DHCP-supplied resolver addresses are observations, not
                    # NoID Privacy-owned prestate. For an automatic family the
                    # exact restore contract is the sealed absence/emptiness of
                    # the NameServer override above; a router or network change
                    # may legitimately supply different live addresses. Only a
                    # non-empty static override owns an exact resolver list.
                    $hadStaticOverride = [bool]$familyState.NameServerExisted -and
                        -not [string]::IsNullOrWhiteSpace([string]$familyState.NameServerValue)
                    if ($hadStaticOverride) {
                        $expectedAddresses = @($familyState.ServerAddresses)
                        $actualAddresses = @($verifiedFamily[0].ServerAddresses)
                        if ($actualAddresses.Count -ne $expectedAddresses.Count) {
                            $restoreErrors.Add("DNS effective static server list count verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                            continue
                        }
                        $orderMismatch = $false
                        for ($addressIndex = 0; $addressIndex -lt $expectedAddresses.Count; $addressIndex++) {
                            $expectedAddress = [System.Net.IPAddress]::Parse([string]$expectedAddresses[$addressIndex])
                            $actualAddress = $null
                            if (-not [System.Net.IPAddress]::TryParse([string]$actualAddresses[$addressIndex], [ref]$actualAddress) -or
                                -not $expectedAddress.Equals($actualAddress)) {
                                $orderMismatch = $true
                            }
                        }
                        if ($orderMismatch) {
                            $restoreErrors.Add("DNS effective static server order/readback verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                            continue
                        }
                    }
                }
                $interfaceDohManaged = if ($dnsSchemaVersion -ge 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if ($dnsSchemaVersion -ge 4 -and $interfaceDohManaged) {
                    $actualInterfaceDoh = Get-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyState.AddressFamily)
                    if (-not (Test-DnsInterfaceDohStateExact `
                            -Actual $actualInterfaceDoh -Expected $familyState.InterfaceDoh)) {
                        $restoreErrors.Add("Native interface DoH post-restore verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)")
                    }
                }
            }
        }
    }
    catch {
        $restoreErrors.Add("DNS pre-state restore failed: $($_.Exception.Message)")
    }
    finally {
        foreach ($notice in $notices) {
            if ($null -ne $NoticeSink) { $NoticeSink.Add($notice) }
            else { Write-Log -Level WARNING -Message $notice -Module 'DNS' }
        }
    }

    if ($restoreErrors.Count -gt 0) {
        foreach ($restoreError in $restoreErrors) {
            Write-Log -Level ERROR -Message $restoreError -Module 'DNS'
        }
        return $false
    }
    Write-Log -Level SUCCESS -Message 'DNS settings restored and verified' -Module 'DNS'
    return $true
}
