#Requires -Version 5.1

$script:AdvancedSecurityNetBIOSRegistryRoot =
    'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'

function ConvertTo-AdvancedSecurityNetBIOSGuid {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)

    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse($Value, [ref]$parsed) -or $parsed -eq [Guid]::Empty) {
        throw "Invalid NetBIOS adapter GUID: '$Value'"
    }
    return '{' + $parsed.ToString('D').ToUpperInvariant() + '}'
}

function Get-AdvancedSecurityNetBIOSRegistryPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SettingID)

    $normalized = ConvertTo-AdvancedSecurityNetBIOSGuid -Value $SettingID
    return Join-Path $script:AdvancedSecurityNetBIOSRegistryRoot ("Tcpip_$normalized")
}

function Get-AdvancedSecurityNetBIOSRegistryState {
    <#
    .SYNOPSIS
        Read the typed NetBT value bound to one adapter GUID.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SettingID)

    $registryPath = Get-AdvancedSecurityNetBIOSRegistryPath -SettingID $SettingID
    $keyExisted = Test-NoIDRegistryKey -LiteralPath $registryPath
    $valueExists = $false
    $valueType = $null
    $value = $null
    if ($keyExisted) {
        $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
        $valueExists = $key.GetValueNames() -contains 'NetbiosOptions'
        if ($valueExists) {
            $valueType = $key.GetValueKind('NetbiosOptions').ToString()
            $value = $key.GetValue(
                'NetbiosOptions',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        }
    }
    return [PSCustomObject][ordered]@{
        RegistryPath        = $registryPath
        RegistryKeyExisted  = $keyExisted
        RegistryValueExists = $valueExists
        RegistryValueType   = $valueType
        RegistryValue       = $value
    }
}

function Get-AdvancedSecurityNetBIOSState {
    <#
    .SYNOPSIS
        Capture the typed NetBT state for every active configuration and every
        physical adapter Windows lists, including media-disconnected adapters
        and adapters Windows reports as not present.

    .DESCRIPTION
        A physical adapter without a Win32_NetworkAdapterConfiguration, such as
        a mobile-broadband interface whose modem is not present, is a
        registry-only target: its GUID-bound NetBT value is the native setting
        Windows applies when that adapter next connects.
    #>
    [CmdletBinding()]
    param()

    $configurations = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)
    $configurationsByGuid = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($configuration in $configurations) {
        if ([string]::IsNullOrWhiteSpace([string]$configuration.SettingID)) {
            if ([bool]$configuration.IPEnabled) {
                throw "IP-enabled adapter configuration $($configuration.Index) has no stable SettingID"
            }
            continue
        }
        $guid = ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$configuration.SettingID)
        if ($configurationsByGuid.ContainsKey($guid)) {
            throw "Duplicate Win32_NetworkAdapterConfiguration SettingID: $guid"
        }
        $configurationsByGuid.Add($guid, $configuration)
    }

    $physicalAdaptersByGuid = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                [bool]$_.HardwareInterface
            })) {
        if ([string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid)) {
            throw "Physical network adapter '$($adapter.Name)' has no stable InterfaceGuid"
        }
        $guid = ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$adapter.InterfaceGuid)
        if ($physicalAdaptersByGuid.ContainsKey($guid)) {
            throw "Duplicate physical network-adapter InterfaceGuid: $guid"
        }
        $physicalAdaptersByGuid.Add($guid, $adapter)
    }

    # Value: the matching configuration, or $null for a registry-only
    # physical adapter that has no configuration.
    $selected = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($entry in $configurationsByGuid.GetEnumerator()) {
        if ([bool]$entry.Value.IPEnabled) {
            $selected.Add($entry.Key, $entry.Value)
        }
    }
    foreach ($entry in $physicalAdaptersByGuid.GetEnumerator()) {
        if (-not $selected.ContainsKey($entry.Key)) {
            $configuration = $null
            if ($configurationsByGuid.ContainsKey($entry.Key)) {
                $configuration = $configurationsByGuid[$entry.Key]
            }
            $selected.Add($entry.Key, $configuration)
        }
    }
    if ($selected.Count -eq 0) {
        throw 'No IP-enabled configuration or physical network adapter was returned'
    }

    $records = [Collections.Generic.List[object]]::new()
    foreach ($guid in @($selected.Keys | Sort-Object)) {
        $configuration = $selected[$guid]
        $hasConfiguration = $null -ne $configuration
        $registry = Get-AdvancedSecurityNetBIOSRegistryState -SettingID $guid
        $physical = $physicalAdaptersByGuid.ContainsKey($guid)
        $physicalAdapter = if ($physical) { $physicalAdaptersByGuid[$guid] } else { $null }
        $records.Add([PSCustomObject][ordered]@{
                Description            = if ($hasConfiguration) {
                    [string]$configuration.Description
                }
                else {
                    [string]$physicalAdapter.InterfaceDescription
                }
                Index                  = if ($hasConfiguration) { [int]$configuration.Index } else { $null }
                InterfaceIndex         = if ($hasConfiguration) {
                    [int]$configuration.InterfaceIndex
                }
                else {
                    [int]$physicalAdapter.InterfaceIndex
                }
                SettingID              = $guid
                IPEnabled              = $hasConfiguration -and [bool]$configuration.IPEnabled
                PhysicalAdapter        = $physical
                PhysicalAdapterName    = if ($physical) { [string]$physicalAdapter.Name } else { $null }
                PhysicalAdapterStatus  = if ($physical) { [string]$physicalAdapter.Status } else { $null }
                TcpipNetbiosOptions    = if (-not $hasConfiguration -or
                    $null -eq $configuration.TcpipNetbiosOptions) {
                    $null
                }
                else {
                    [int]$configuration.TcpipNetbiosOptions
                }
                RegistryPath           = $registry.RegistryPath
                RegistryKeyExisted     = $registry.RegistryKeyExisted
                RegistryValueExists    = $registry.RegistryValueExists
                RegistryValueType      = $registry.RegistryValueType
                RegistryValue          = $registry.RegistryValue
            })
    }

    return [PSCustomObject][ordered]@{
        SchemaVersion = 2
        Adapters      = @($records)
    }
}

function Assert-AdvancedSecurityNetBIOSSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)

    if (-not ($Snapshot.PSObject.Properties.Name -contains 'SchemaVersion') -or
        [int]$Snapshot.SchemaVersion -ne 2 -or
        -not ($Snapshot.PSObject.Properties.Name -contains 'Adapters')) {
        throw 'NetBIOS adapter snapshot must use schema version 2'
    }
    $adapters = @($Snapshot.Adapters)
    if ($adapters.Count -eq 0) { throw 'NetBIOS adapter snapshot is empty' }
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $supportedTypes = @('Binary', 'DWord', 'ExpandString', 'MultiString', 'QWord', 'String')
    foreach ($adapter in $adapters) {
        foreach ($property in @(
                'SettingID', 'IPEnabled', 'PhysicalAdapter', 'RegistryPath',
                'RegistryKeyExisted', 'RegistryValueExists'
            )) {
            if (-not ($adapter.PSObject.Properties.Name -contains $property)) {
                throw "NetBIOS adapter snapshot is missing $property"
            }
        }
        $guid = ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$adapter.SettingID)
        if (-not $identities.Add($guid)) { throw "Duplicate NetBIOS adapter snapshot identity: $guid" }
        $expectedPath = Get-AdvancedSecurityNetBIOSRegistryPath -SettingID $guid
        if ([string]$adapter.RegistryPath -ine $expectedPath) {
            throw "NetBIOS registry path does not match SettingID $guid"
        }
        if ([bool]$adapter.RegistryValueExists -and -not [bool]$adapter.RegistryKeyExisted) {
            throw "NetBIOS value exists without its parent key for $guid"
        }
        if ([bool]$adapter.RegistryValueExists) {
            if (-not ($adapter.PSObject.Properties.Name -contains 'RegistryValueType') -or
                [string]$adapter.RegistryValueType -cnotin $supportedTypes -or
                -not ($adapter.PSObject.Properties.Name -contains 'RegistryValue')) {
                throw "NetBIOS value state is not exactly restorable for $guid"
            }
        }
        if (-not [bool]$adapter.IPEnabled -and -not [bool]$adapter.PhysicalAdapter) {
            throw "Inactive non-physical adapter is outside the NetBIOS target contract: $guid"
        }
    }
    return $Snapshot
}

function ConvertTo-AdvancedSecurityNetBIOSCanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [switch]$ConfigurationOnly
    )

    $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $Snapshot
    $canonical = @($Snapshot.Adapters | Sort-Object SettingID | ForEach-Object {
            $record = [PSCustomObject][ordered]@{
                Description           = [string]$_.Description
                Index                 = if ($null -eq $_.Index) { $null } else { [int]$_.Index }
                InterfaceIndex        = [int]$_.InterfaceIndex
                SettingID             = ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$_.SettingID)
                IPEnabled             = [bool]$_.IPEnabled
                PhysicalAdapter       = [bool]$_.PhysicalAdapter
                PhysicalAdapterName   = [string]$_.PhysicalAdapterName
                PhysicalAdapterStatus = [string]$_.PhysicalAdapterStatus
                TcpipNetbiosOptions   = $_.TcpipNetbiosOptions
                RegistryPath          = [string]$_.RegistryPath
                RegistryKeyExisted    = [bool]$_.RegistryKeyExisted
                RegistryValueExists   = [bool]$_.RegistryValueExists
                RegistryValueType     = [string]$_.RegistryValueType
                RegistryValue         = $_.RegistryValue
            }
            if ($ConfigurationOnly) {
                $record | Select-Object SettingID, RegistryPath, RegistryKeyExisted,
                    RegistryValueExists, RegistryValueType, RegistryValue
            }
            else { $record }
        })
    return ConvertTo-Json -InputObject @($canonical) -Depth 20 -Compress
}

function Test-AdvancedSecurityNetBIOSStateEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Reference,
        [Parameter(Mandatory = $true)]$Candidate,
        [switch]$ConfigurationOnly
    )

    return ((ConvertTo-AdvancedSecurityNetBIOSCanonicalJson -Snapshot $Reference -ConfigurationOnly:$ConfigurationOnly) -ceq
        (ConvertTo-AdvancedSecurityNetBIOSCanonicalJson -Snapshot $Candidate -ConfigurationOnly:$ConfigurationOnly))
}

function Write-AdvancedSecurityNetBIOSRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'QWord', 'String')]
        [string]$Type
    )

    if (-not (Test-NoIDRegistryKey -LiteralPath $Path)) {
        $null = New-NoIDRegistryKey -LiteralPath $Path
    }
    $typedValue = switch ($Type) {
        'Binary'       { [byte[]]@($Value) }
        'DWord'        { [int32]$Value }
        'ExpandString' { [string]$Value }
        'MultiString'  { [string[]]@($Value) }
        'QWord'        { [int64]$Value }
        'String'       { [string]$Value }
    }
    $null = New-ItemProperty -LiteralPath $Path -Name 'NetbiosOptions' -Value $typedValue `
        -PropertyType $Type -Force -ErrorAction Stop
}

function Invoke-AdvancedSecurityNetBIOSDisable {
    [CmdletBinding()]
    param(
        # The sealed NetBIOS_Adapters prestate. Apply changes exactly its
        # adapter identities, so Restore can return every changed value.
        [Parameter(Mandatory = $false)]$SealedSnapshot
    )

    $before = Get-AdvancedSecurityNetBIOSState
    $beforeIdentities = @($before.Adapters | ForEach-Object SettingID | Sort-Object)
    if ($null -ne $SealedSnapshot) {
        $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $SealedSnapshot
        $sealedIdentities = @($SealedSnapshot.Adapters | ForEach-Object {
                ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$_.SettingID)
            } | Sort-Object)
        if (($sealedIdentities -join '|') -cne ($beforeIdentities -join '|')) {
            throw 'NetBIOS adapter inventory changed after the sealed backup; run Apply again'
        }
    }
    $configurations = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)
    foreach ($adapter in @($before.Adapters)) {
        if ([bool]$adapter.IPEnabled) {
            $matchingConfigurations = @($configurations | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.SettingID) -and
                    (ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$_.SettingID)) -ieq
                        [string]$adapter.SettingID
                })
            if ($matchingConfigurations.Count -ne 1) {
                throw "Expected exactly one active NetBIOS adapter for SettingID $($adapter.SettingID), found $($matchingConfigurations.Count)"
            }
            $result = Invoke-CimMethod -InputObject $matchingConfigurations[0] -MethodName SetTcpipNetbios `
                -Arguments @{ TcpipNetbiosOptions = 2 } -ErrorAction Stop
            if ([int64]$result.ReturnValue -notin @(0, 1)) {
                throw "SetTcpipNetbios returned $($result.ReturnValue) for adapter $($adapter.SettingID)"
            }
        }
        elseif ([bool]$adapter.PhysicalAdapter) {
            Write-AdvancedSecurityNetBIOSRegistryValue -Path ([string]$adapter.RegistryPath) `
                -Value 2 -Type DWord
        }
        else {
            throw "NetBIOS target became inactive and is not physical: $($adapter.SettingID)"
        }
    }

    $after = Get-AdvancedSecurityNetBIOSState
    $afterIdentities = @($after.Adapters | ForEach-Object SettingID | Sort-Object)
    if (($beforeIdentities -join '|') -cne ($afterIdentities -join '|')) {
        throw 'NetBIOS adapter inventory changed during Apply'
    }
    foreach ($adapter in @($after.Adapters)) {
        $nativeDisabled = (
            [bool]$adapter.RegistryKeyExisted -and
            [bool]$adapter.RegistryValueExists -and
            [string]$adapter.RegistryValueType -ceq 'DWord' -and
            [int]$adapter.RegistryValue -eq 2
        )
        $providerDisabled = (-not [bool]$adapter.IPEnabled -or
            [int]$adapter.TcpipNetbiosOptions -eq 2)
        if (-not $nativeDisabled -or -not $providerDisabled) {
            throw "NetBIOS post-apply mismatch for adapter $($adapter.SettingID)"
        }
    }
    $offlineCount = @($after.Adapters | Where-Object { -not [bool]$_.IPEnabled }).Count
    if ($offlineCount -gt 0) {
        Write-Log -Level INFO -Message "NetBIOS disabled through the NetBT registry value on $offlineCount physical adapter(s) that are disconnected, disabled or not present; Windows applies it when the adapter connects" -Module 'AdvancedSecurity'
    }
    return $after
}

function Test-AdvancedSecurityNetBIOSDisabled {
    [CmdletBinding()]
    param()

    $state = Get-AdvancedSecurityNetBIOSState
    $nonCompliant = [Collections.Generic.List[object]]::new()
    foreach ($adapter in @($state.Adapters)) {
        $nativeDisabled = (
            [bool]$adapter.RegistryKeyExisted -and
            [bool]$adapter.RegistryValueExists -and
            [string]$adapter.RegistryValueType -ceq 'DWord' -and
            [int]$adapter.RegistryValue -eq 2
        )
        $providerDisabled = (-not [bool]$adapter.IPEnabled -or
            [int]$adapter.TcpipNetbiosOptions -eq 2)
        if (-not $nativeDisabled -or -not $providerDisabled) {
            $nonCompliant.Add([PSCustomObject]@{
                    SettingID           = [string]$adapter.SettingID
                    Description         = [string]$adapter.Description
                    IPEnabled           = [bool]$adapter.IPEnabled
                    ProviderValue       = $adapter.TcpipNetbiosOptions
                    RegistryKeyExisted  = [bool]$adapter.RegistryKeyExisted
                    RegistryValueExists = [bool]$adapter.RegistryValueExists
                    RegistryValueType   = [string]$adapter.RegistryValueType
                    RegistryValue       = $adapter.RegistryValue
                })
        }
    }
    return [PSCustomObject]@{
        Compliant    = ($nonCompliant.Count -eq 0)
        Adapters     = @($state.Adapters)
        NonCompliant = @($nonCompliant)
    }
}

function Restore-AdvancedSecurityNetBIOSState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)

    $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $Snapshot
    # Apply changes exactly the sealed identities. Each NetBT value is bound to
    # its adapter GUID, so Restore returns every sealed value even when that
    # adapter is unplugged or not present now. Adapters added after the backup
    # were never changed and stay untouched.
    $current = Get-AdvancedSecurityNetBIOSState
    $currentById = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($current.Adapters)) {
        $currentById.Add((ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$record.SettingID)), $record)
    }

    $currentConfigurations = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)
    $configurationIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($configuration in $currentConfigurations) {
        if (-not [string]::IsNullOrWhiteSpace([string]$configuration.SettingID)) {
            $null = $configurationIds.Add((ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$configuration.SettingID)))
        }
    }

    # Each adapter is restored on its own: one failing adapter is reported
    # and never keeps the others from their sealed prestate.
    $restoreErrors = [Collections.Generic.List[string]]::new()
    $restoreTargets = [Collections.Generic.List[object]]::new()
    $retainedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($saved in @($Snapshot.Adapters)) {
        $guid = ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$saved.SettingID)
        $path = [string]$saved.RegistryPath
        $currentRecord = if ($currentById.ContainsKey($guid)) { $currentById[$guid] } else { $null }
        if ($null -eq $currentRecord) {
            if (-not $configurationIds.Contains($guid) -and [bool]$saved.RegistryKeyExisted -and
                -not (Test-NoIDRegistryKey -LiteralPath $path)) {
                Write-Log -Level INFO -Message "NetBIOS adapter $guid and its NetBT key were removed from Windows after the backup; nothing of it remains to restore" -Module 'AdvancedSecurity'
                continue
            }
            Write-Log -Level INFO -Message "NetBIOS adapter $guid is not connected; restoring its NetBT value, which Windows applies when the adapter connects" -Module 'AdvancedSecurity'
        }
        $restoreTargets.Add($saved)

        try {
            $canUseProvider = (
                $null -ne $currentRecord -and
                [bool]$currentRecord.IPEnabled -and
                [bool]$saved.RegistryValueExists -and
                [string]$saved.RegistryValueType -ceq 'DWord' -and
                [int]$saved.RegistryValue -in @(0, 1, 2)
            )
            if ($canUseProvider) {
                $matchingConfigurations = @($currentConfigurations | Where-Object {
                        -not [string]::IsNullOrWhiteSpace([string]$_.SettingID) -and
                        (ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$_.SettingID)) -ieq $guid
                    })
                if ($matchingConfigurations.Count -ne 1) {
                    throw "Expected exactly one active restore adapter for $guid, found $($matchingConfigurations.Count)"
                }
                $result = Invoke-CimMethod -InputObject $matchingConfigurations[0] -MethodName SetTcpipNetbios `
                    -Arguments @{ TcpipNetbiosOptions = [int]$saved.RegistryValue } -ErrorAction Stop
                if ([int64]$result.ReturnValue -notin @(0, 1)) {
                    throw "SetTcpipNetbios restore returned $($result.ReturnValue) for adapter $guid"
                }
            }

            if ([bool]$saved.RegistryValueExists) {
                Write-AdvancedSecurityNetBIOSRegistryValue -Path $path -Value $saved.RegistryValue `
                    -Type ([string]$saved.RegistryValueType)
            }
            elseif (Test-NoIDRegistryKey -LiteralPath $path) {
                Remove-ItemProperty -LiteralPath $path -Name 'NetbiosOptions' -ErrorAction SilentlyContinue
            }

            if (-not [bool]$saved.RegistryKeyExisted -and
                (Test-NoIDRegistryKey -LiteralPath $path)) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $remainingValues = @($key.GetValueNames())
                $remainingSubKeys = @($key.GetSubKeyNames())
                $key = $null
                if ($remainingValues.Count -ne 0 -or $remainingSubKeys.Count -ne 0) {
                    # Windows or another program keeps its own NetBT settings
                    # here now; the key is kept instead of destroying them.
                    $null = $retainedPaths.Add($path)
                    Write-Log -Level WARNING -Message (Format-NoIDRetainedKeyNotice -Path $path `
                            -Values ([string[]]$remainingValues) -SubKeys ([string[]]$remainingSubKeys)) -Module 'AdvancedSecurity'
                }
                else {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
            }
            elseif ([bool]$saved.RegistryKeyExisted -and
                -not (Test-NoIDRegistryKey -LiteralPath $path)) {
                $null = New-NoIDRegistryKey -LiteralPath $path
            }
        }
        catch {
            $restoreErrors.Add("NetBIOS adapter $guid`: $($_.Exception.Message)")
        }
    }

    # Connection status, adapter labels and numeric indexes are observations,
    # not settings owned by this module. They may change between Backup and
    # Restore. The GUID-bound typed registry state must still match exactly;
    # backup sealing continues to use the full observation comparison. A key
    # kept above because it holds other settings is expected to exist.
    if ($restoreTargets.Count -gt 0) {
        $restoredRegistry = [PSCustomObject]@{
            SchemaVersion = 2
            Adapters      = @(foreach ($saved in $restoreTargets) {
                    $registry = Get-AdvancedSecurityNetBIOSRegistryState -SettingID ([string]$saved.SettingID)
                    [PSCustomObject][ordered]@{
                        SettingID           = [string]$saved.SettingID
                        IPEnabled           = [bool]$saved.IPEnabled
                        PhysicalAdapter     = [bool]$saved.PhysicalAdapter
                        RegistryPath        = $registry.RegistryPath
                        RegistryKeyExisted  = $registry.RegistryKeyExisted
                        RegistryValueExists = $registry.RegistryValueExists
                        RegistryValueType   = $registry.RegistryValueType
                        RegistryValue       = $registry.RegistryValue
                    }
                })
        }
        $sealedTargets = [PSCustomObject]@{
            SchemaVersion = 2
            Adapters      = @(foreach ($saved in $restoreTargets) {
                    $expected = $saved | Select-Object *
                    if ($retainedPaths.Contains([string]$saved.RegistryPath)) { $expected.RegistryKeyExisted = $true }
                    $expected
                })
        }
        foreach ($saved in @($sealedTargets.Adapters)) {
            $actual = @($restoredRegistry.Adapters | Where-Object { [string]$_.SettingID -ieq [string]$saved.SettingID })
            $single = [PSCustomObject]@{ SchemaVersion = 2; Adapters = @($saved) }
            $candidate = [PSCustomObject]@{ SchemaVersion = 2; Adapters = @($actual) }
            if ($actual.Count -ne 1 -or
                -not (Test-AdvancedSecurityNetBIOSStateEqual -Reference $single -Candidate $candidate -ConfigurationOnly)) {
                $restoreErrors.Add("NetBIOS typed adapter state did not return to the exact sealed prestate: $($saved.SettingID)")
            }
        }
    }

    $verified = Get-AdvancedSecurityNetBIOSState
    foreach ($saved in $restoreTargets) {
        $restored = @($verified.Adapters | Where-Object {
                [string]$_.SettingID -ieq [string]$saved.SettingID
            })
        if ($restored.Count -ne 1 -or -not [bool]$restored[0].IPEnabled) { continue }

        # A connected adapter must also expose the restored setting through
        # the native provider. An offline backup has no provider observation;
        # for the documented DWORD 0/1/2 settings its exact registry value is
        # the expected value when that adapter is connected during Restore.
        $expectedProvider = $null
        if ([bool]$saved.IPEnabled -and
            $saved.PSObject.Properties['TcpipNetbiosOptions'] -and
            $null -ne $saved.TcpipNetbiosOptions) {
            $expectedProvider = [int]$saved.TcpipNetbiosOptions
        }
        elseif ([bool]$saved.RegistryValueExists -and
            [string]$saved.RegistryValueType -ceq 'DWord' -and
            [int]$saved.RegistryValue -in @(0, 1, 2)) {
            $expectedProvider = [int]$saved.RegistryValue
        }
        if ($null -ne $expectedProvider -and
            ($null -eq $restored[0].TcpipNetbiosOptions -or
                [int]$restored[0].TcpipNetbiosOptions -ne $expectedProvider)) {
            $restoreErrors.Add("NetBIOS active adapter state did not return to the recorded configuration: $($saved.SettingID)")
        }
    }
    if ($restoreErrors.Count -gt 0) {
        throw ($restoreErrors -join '; ')
    }
    return $verified
}
