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

    return -not (Test-Path -LiteralPath ([string]$DNSSnapshot.Policy.Path) -PathType Container -ErrorAction Stop)
}

function Restore-DNSSettings {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityBaselineRegistryBackupPath,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess('Selected physical network adapters', 'Restore exact DNS pre-state')) {
        return $false
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupFilePath -PathType Leaf)) {
            throw "DNS pre-state artifact not found: $BackupFilePath"
        }
        $snapshot = Get-Content -LiteralPath $BackupFilePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $null = Assert-DNSBackupSnapshot -Snapshot $snapshot
        $dnsSchemaVersion = [int]$snapshot.SchemaVersion
        Write-Log -Level INFO -Message 'DNS restore snapshot schema and target inventory validated' -Module 'DNS'
        $combinedPolicyKeyAlreadyAbsent = (
            -not [string]::IsNullOrWhiteSpace($SecurityBaselineRegistryBackupPath) -and
            (Test-DNSCombinedSessionPolicyKeyAbsence `
                -DNSSnapshot $snapshot `
                -SecurityBaselineRegistryBackupPath $SecurityBaselineRegistryBackupPath)
        )

        # Resolve and validate every mutation dependency up front. A missing
        # adapter, ambiguous DoH record, or unsupported registry conversion
        # must fail before the first restore write.
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

        # An originally absent shared policy key may be removed only when it
        # contains no later state outside the one DNS value owned here. Refuse
        # before the first restore write rather than destroying concurrent data.
        if (-not [bool]$policy.KeyExisted -and
            (Test-Path -LiteralPath ([string]$policy.Path) -PathType Container -ErrorAction Stop)) {
            $currentPolicyKey = Get-Item -LiteralPath ([string]$policy.Path) -ErrorAction Stop
            $unownedValues = @($currentPolicyKey.GetValueNames() | Where-Object {
                    [string]$_ -ne [string]$policy.Name
                })
            $unownedSubKeys = @(Get-ChildItem -LiteralPath ([string]$policy.Path) -ErrorAction Stop)
            if ($unownedValues.Count -gt 0 -or $unownedSubKeys.Count -gt 0) {
                throw 'Originally absent DNS policy key contains later unowned state; refusing destructive restore'
            }
        }
        Write-Log -Level INFO -Message 'DNS restore policy preflight completed' -Module 'DNS'

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
        }
        Write-Log -Level INFO -Message 'DNS restore DoH preflight completed' -Module 'DNS'

        $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        $adapterRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterState in @($snapshot.Adapters)) {
            $adapter = @($currentAdapters | Where-Object {
                    $currentGuid = [string]$_.InterfaceGuid
                    if (-not $currentGuid.StartsWith('{')) { $currentGuid = "{$currentGuid}" }
                    $currentGuid -eq [string]$adapterState.InterfaceGuid
                })
            if ($adapter.Count -ne 1) {
                throw "Adapter identity no longer resolves uniquely: $($adapterState.InterfaceGuid)"
            }
            if ([string]$adapter[0].InterfaceDescription -cne [string]$adapterState.InterfaceDescription) {
                throw "Adapter description no longer matches the sealed identity: $($adapterState.InterfaceGuid)"
            }
            $dnsInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].InterfaceIndex -ErrorAction Stop)
            foreach ($familyState in @($adapterState.Families | Where-Object {
                        $interfaceDohManaged = if ($dnsSchemaVersion -eq 5) {
                            [bool]$_.InterfaceDohManaged
                        }
                        else { [bool]$_.Managed }
                        [bool]$_.Managed -or $interfaceDohManaged
                    })) {
                $family = [int]$familyState.AddressFamily
                $instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq $family })
                if ($instance.Count -ne 1) {
                    throw "DNS address-family instance is unavailable for $($adapterState.InterfaceGuid)/$family"
                }
                if (-not [bool]$familyState.RegistryKeyExisted -and
                    (Test-Path -LiteralPath ([string]$familyState.RegistryPath) -PathType Container -ErrorAction Stop)) {
                    $currentFamilyKey = Get-Item -LiteralPath ([string]$familyState.RegistryPath) -ErrorAction Stop
                    $unownedFamilyValues = @($currentFamilyKey.GetValueNames() | Where-Object { [string]$_ -cne 'NameServer' })
                    $unownedFamilySubKeys = @(Get-ChildItem -LiteralPath ([string]$familyState.RegistryPath) -ErrorAction Stop)
                    if ($unownedFamilyValues.Count -gt 0 -or $unownedFamilySubKeys.Count -gt 0) {
                        throw "Originally absent DNS family key contains later unowned state: $($adapterState.InterfaceGuid)/$family"
                    }
                }
            }
            $adapterRestorePlans.Add([PSCustomObject]@{
                    Adapter      = $adapter[0]
                    AdapterState = $adapterState
                    DnsInstances = @($dnsInstances)
                })
        }
        Write-Log -Level INFO -Message 'DNS restore adapter and address-family preflight completed' -Module 'DNS'

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would restore DNS state from schema v$dnsSchemaVersion artifact" -Module 'DNS'
            return $true
        }

        # Restore the sole DNS policy value owned by this module.
        if ([bool]$policy.Exists) {
            if (-not (Test-Path -LiteralPath $policy.Path)) {
                New-Item -Path $policy.Path -Force -ErrorAction Stop | Out-Null
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
            if (-not [bool]$policy.KeyExisted -and $policyKey.GetValueNames().Count -eq 0 -and $policyKey.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $policy.Path -Force -ErrorAction Stop
            }
        }
        Write-Log -Level INFO -Message 'DNS restore policy mutation completed' -Module 'DNS'

        # Replace only the DoH registrations selected by the original Apply.
        foreach ($dohState in @($snapshot.DohEntries)) {
            $address = [string]$dohState.ServerAddress
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
        Write-Log -Level INFO -Message 'DNS restore DoH mutation phase completed' -Module 'DNS'

        $familyRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterPlan in $adapterRestorePlans) {
            $adapterState = $adapterPlan.AdapterState
            $dnsInstances = @($adapterPlan.DnsInstances)
            foreach ($familyState in @($adapterState.Families | Where-Object { [bool]$_.Managed })) {
                $family = [int]$familyState.AddressFamily
                $instance = @($dnsInstances | Where-Object { [int]$_.AddressFamily -eq $family })
                if ($instance.Count -ne 1) {
                    throw "DNS address-family instance is unavailable for $($adapterState.InterfaceGuid)/$family"
                }
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
            foreach ($familyState in @($adapterPlan.AdapterState.Families)) {
                $interfaceDohManaged = if ($dnsSchemaVersion -eq 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if ($dnsSchemaVersion -in @(4, 5) -and $interfaceDohManaged) {
                    $interfaceDohRestorePlans.Add([PSCustomObject]@{
                            AdapterState = $adapterPlan.AdapterState
                            FamilyState  = $familyState
                            Family       = [int]$familyState.AddressFamily
                        })
                }
            }
        }

        # Clear a schema-4/5 native DoH state that was originally absent while
        # the applied provider server list is still available. The following
        # ResetServerAddresses call then returns the family to DHCP. Supplying
        # an empty NameServer to DNS_SETTING_DOH is not a valid Windows API
        # request, so this ordering is required for exact automatic-DNS state.
        if ($dnsSchemaVersion -in @(4, 5)) {
            foreach ($familyPlan in @($interfaceDohRestorePlans | Where-Object {
                        @($_.FamilyState.InterfaceDoh.Properties).Count -eq 0
                    })) {
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
        }

        # Reset is adapter-wide on current Windows 11 builds even when the
        # input CIM object represents one address family. Perform every reset
        # before setting any static family so a later reset cannot erase it.
        foreach ($familyPlan in @($familyRestorePlans | Where-Object { -not $_.HasStaticOverride })) {
            Write-Log -Level DEBUG -Message "Restoring automatic DNS family $($familyPlan.Family) on $($familyPlan.AdapterState.InterfaceGuid)" -Module 'DNS'
            Set-DnsClientServerAddress -InputObject $familyPlan.Instance -ResetServerAddresses -ErrorAction Stop
        }
        foreach ($familyPlan in @($familyRestorePlans | Where-Object { $_.HasStaticOverride })) {
            Write-Log -Level DEBUG -Message "Restoring static DNS family $($familyPlan.Family) on $($familyPlan.AdapterState.InterfaceGuid)" -Module 'DNS'
            Set-DnsClientServerAddress -InputObject $familyPlan.Instance `
                -ServerAddresses $familyPlan.OriginalAddresses -ErrorAction Stop
        }

        # Schema 4/5 seals Windows' native per-interface DoH properties. Replay
        # them only after the supported resolver cmdlets have completed their
        # adapter-wide writes, because those writes can clear this UI-visible
        # state. Schema 3 remains readable for already sealed 2.2.5 sessions.
        if ($dnsSchemaVersion -in @(4, 5)) {
            foreach ($familyPlan in @($interfaceDohRestorePlans | Where-Object {
                        @($_.FamilyState.InterfaceDoh.Properties).Count -gt 0
                    })) {
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
        }

        # Reinstate exact registry existence/type/data only after all supported
        # DNS-client cmdlets have completed their adapter-wide side effects.
        $registryRestorePlans = [System.Collections.Generic.List[object]]::new()
        foreach ($adapterPlan in $adapterRestorePlans) {
            foreach ($familyState in @($adapterPlan.AdapterState.Families)) {
                $interfaceDohManaged = if ($dnsSchemaVersion -eq 5) {
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
            if (-not (Test-Path -LiteralPath $familyState.RegistryPath)) {
                if ([bool]$familyState.RegistryKeyExisted -or [bool]$familyState.NameServerExisted) {
                    New-Item -Path $familyState.RegistryPath -Force -ErrorAction Stop | Out-Null
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
                    $remainingSubKeys = @(Get-ChildItem -LiteralPath ([string]$familyState.RegistryPath) -ErrorAction Stop)
                    if ($remainingValues.Count -gt 0 -or $remainingSubKeys.Count -gt 0) {
                        throw "DNS family key acquired unowned state during restore; refusing destructive cleanup: $($adapterState.InterfaceGuid)/$family"
                    }
                    Remove-Item -LiteralPath ([string]$familyState.RegistryPath) -Force -ErrorAction Stop
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
        $policyKeyPresent = Test-Path -LiteralPath ([string]$policy.Path) -PathType Container -ErrorAction Stop
        $expectedPolicyKeyPresent = if ($combinedPolicyKeyAlreadyAbsent) { $false } else { [bool]$policy.KeyExisted }
        if ($policyKeyPresent -ne $expectedPolicyKeyPresent -or
            $policyPresent -ne [bool]$policy.Exists -or
            ($policyPresent -and ($actualPolicyType -ne [string]$policy.Type -or $actualPolicyJson -cne $expectedPolicyJson))) {
            throw 'DoHPolicy key/value/type/data post-restore verification failed'
        }

        $verifiedDoh = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
        foreach ($dohState in @($snapshot.DohEntries)) {
            $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$dohState.ServerAddress)
            $dohMatches = @($verifiedDoh | Where-Object {
                    (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalAddress
                })
            $expectedMatchCount = if ([bool]$dohState.Exists) { 1 } else { 0 }
            if ($dohMatches.Count -ne $expectedMatchCount) {
                throw "DoH registration existence verification failed: $($dohState.ServerAddress)"
            }
            if ($dohMatches.Count -eq 1 -and
                ([string]$dohMatches[0].DohTemplate -cne [string]$dohState.DohTemplate -or
                    [bool]$dohMatches[0].AllowFallbackToUdp -ne [bool]$dohState.AllowFallbackToUdp -or
                    [bool]$dohMatches[0].AutoUpgrade -ne [bool]$dohState.AutoUpgrade)) {
                throw "DoH registration value verification failed: $($dohState.ServerAddress)"
            }
        }

        foreach ($adapterState in @($snapshot.Adapters)) {
            $adapter = @($currentAdapters | Where-Object {
                    $currentGuid = [string]$_.InterfaceGuid
                    if (-not $currentGuid.StartsWith('{')) { $currentGuid = "{$currentGuid}" }
                    $currentGuid -eq [string]$adapterState.InterfaceGuid
                })
            if ($adapter.Count -ne 1) {
                throw "Adapter identity failed during DNS verification: $($adapterState.InterfaceGuid)"
            }
            $verifiedInstances = @(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].InterfaceIndex -ErrorAction Stop)
            foreach ($familyState in @($adapterState.Families | Where-Object {
                        $interfaceDohManaged = if ($dnsSchemaVersion -eq 5) {
                            [bool]$_.InterfaceDohManaged
                        }
                        else { [bool]$_.Managed }
                        [bool]$_.Managed -or $interfaceDohManaged
                    })) {
                $path = [string]$familyState.RegistryPath
                $actualRegistryKeyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
                if ($actualRegistryKeyExists -ne [bool]$familyState.RegistryKeyExisted) {
                    throw "DNS registry key existence verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
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
                    throw "DNS registry pre-state verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
                }
                if ([bool]$familyState.Managed) {
                    $verifiedFamily = @($verifiedInstances | Where-Object {
                            [int]$_.AddressFamily -eq [int]$familyState.AddressFamily
                        })
                    if ($verifiedFamily.Count -ne 1) {
                        throw "DNS effective-state verification instance is missing: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
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
                            throw "DNS effective static server list count verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
                        }
                        for ($addressIndex = 0; $addressIndex -lt $expectedAddresses.Count; $addressIndex++) {
                            $expectedAddress = [System.Net.IPAddress]::Parse([string]$expectedAddresses[$addressIndex])
                            $actualAddress = $null
                            if (-not [System.Net.IPAddress]::TryParse([string]$actualAddresses[$addressIndex], [ref]$actualAddress) -or
                                -not $expectedAddress.Equals($actualAddress)) {
                                throw "DNS effective static server order/readback verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
                            }
                        }
                    }
                }
                $interfaceDohManaged = if ($dnsSchemaVersion -eq 5) {
                    [bool]$familyState.InterfaceDohManaged
                }
                else { [bool]$familyState.Managed }
                if ($dnsSchemaVersion -in @(4, 5) -and $interfaceDohManaged) {
                    $actualInterfaceDoh = Get-DnsInterfaceDohState `
                        -InterfaceGuid ([string]$adapterState.InterfaceGuid) `
                        -AddressFamily ([int]$familyState.AddressFamily)
                    if (-not (Test-DnsInterfaceDohStateExact `
                            -Actual $actualInterfaceDoh -Expected $familyState.InterfaceDoh)) {
                        throw "Native interface DoH post-restore verification failed: $($adapterState.InterfaceGuid)/$($familyState.AddressFamily)"
                    }
                }
            }
        }

        Write-Log -Level SUCCESS -Message 'DNS pre-state restored and verified exactly for all managed targets' -Module 'DNS'
        return $true
    }
    catch {
        Write-ErrorLog -Message 'DNS pre-state restore failed' -Module 'DNS' -ErrorRecord $_
        return $false
    }
}
