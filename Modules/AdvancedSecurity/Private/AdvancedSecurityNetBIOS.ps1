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

function Get-AdvancedSecurityNetBIOSState {
    <#
    .SYNOPSIS
        Capture the typed NetBT state for every active configuration and every
        present physical adapter, including media-disconnected adapters.
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
        if (-not $configurationsByGuid.ContainsKey($guid)) {
            throw "Physical network adapter '$($adapter.Name)' has no matching Win32_NetworkAdapterConfiguration for $guid"
        }
        $physicalAdaptersByGuid.Add($guid, $adapter)
    }

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
            $selected.Add($entry.Key, $configurationsByGuid[$entry.Key])
        }
    }
    if ($selected.Count -eq 0) {
        throw 'No IP-enabled configuration or present physical network adapter was returned'
    }

    $records = [Collections.Generic.List[object]]::new()
    foreach ($guid in @($selected.Keys | Sort-Object)) {
        $configuration = $selected[$guid]
        $registryPath = Get-AdvancedSecurityNetBIOSRegistryPath -SettingID $guid
        $keyExisted = Test-Path -LiteralPath $registryPath -PathType Container -ErrorAction Stop
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
        $physical = $physicalAdaptersByGuid.ContainsKey($guid)
        $physicalAdapter = if ($physical) { $physicalAdaptersByGuid[$guid] } else { $null }
        $records.Add([PSCustomObject][ordered]@{
                Description            = [string]$configuration.Description
                Index                  = [int]$configuration.Index
                InterfaceIndex         = [int]$configuration.InterfaceIndex
                SettingID              = $guid
                IPEnabled              = [bool]$configuration.IPEnabled
                PhysicalAdapter        = $physical
                PhysicalAdapterName    = if ($physical) { [string]$physicalAdapter.Name } else { $null }
                PhysicalAdapterStatus  = if ($physical) { [string]$physicalAdapter.Status } else { $null }
                TcpipNetbiosOptions    = if ($null -eq $configuration.TcpipNetbiosOptions) {
                    $null
                }
                else {
                    [int]$configuration.TcpipNetbiosOptions
                }
                RegistryPath           = $registryPath
                RegistryKeyExisted     = $keyExisted
                RegistryValueExists    = $valueExists
                RegistryValueType      = $valueType
                RegistryValue          = $value
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
    param([Parameter(Mandatory = $true)]$Snapshot)

    $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $Snapshot
    $canonical = @($Snapshot.Adapters | Sort-Object SettingID | ForEach-Object {
            [PSCustomObject][ordered]@{
                Description           = [string]$_.Description
                Index                 = [int]$_.Index
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
        })
    return ConvertTo-Json -InputObject @($canonical) -Depth 20 -Compress
}

function Test-AdvancedSecurityNetBIOSStateEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Reference,
        [Parameter(Mandatory = $true)]$Candidate
    )

    return ((ConvertTo-AdvancedSecurityNetBIOSCanonicalJson -Snapshot $Reference) -ceq
        (ConvertTo-AdvancedSecurityNetBIOSCanonicalJson -Snapshot $Candidate))
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

    if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop)) {
        $null = New-Item -Path $Path -Force -ErrorAction Stop
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
    param()

    $before = Get-AdvancedSecurityNetBIOSState
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
    $beforeIdentities = @($before.Adapters | ForEach-Object SettingID | Sort-Object)
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
    $current = Get-AdvancedSecurityNetBIOSState
    $savedIdentities = @($Snapshot.Adapters | ForEach-Object SettingID | Sort-Object)
    $currentIdentities = @($current.Adapters | ForEach-Object SettingID | Sort-Object)
    if (($savedIdentities -join '|') -cne ($currentIdentities -join '|')) {
        throw 'NetBIOS adapter inventory changed before Restore'
    }

    $currentConfigurations = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)
    foreach ($saved in @($Snapshot.Adapters)) {
        $currentRecord = @($current.Adapters | Where-Object {
                [string]$_.SettingID -ieq [string]$saved.SettingID
            })
        if ($currentRecord.Count -ne 1) {
            throw "Expected exactly one current NetBIOS record for $($saved.SettingID)"
        }

        $canUseProvider = (
            [bool]$currentRecord[0].IPEnabled -and
            [bool]$saved.RegistryValueExists -and
            [string]$saved.RegistryValueType -ceq 'DWord' -and
            [int]$saved.RegistryValue -in @(0, 1, 2)
        )
        if ($canUseProvider) {
            $matchingConfigurations = @($currentConfigurations | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.SettingID) -and
                    (ConvertTo-AdvancedSecurityNetBIOSGuid -Value ([string]$_.SettingID)) -ieq
                        [string]$saved.SettingID
                })
            if ($matchingConfigurations.Count -ne 1) {
                throw "Expected exactly one active restore adapter for $($saved.SettingID), found $($matchingConfigurations.Count)"
            }
            $result = Invoke-CimMethod -InputObject $matchingConfigurations[0] -MethodName SetTcpipNetbios `
                -Arguments @{ TcpipNetbiosOptions = [int]$saved.RegistryValue } -ErrorAction Stop
            if ([int64]$result.ReturnValue -notin @(0, 1)) {
                throw "SetTcpipNetbios restore returned $($result.ReturnValue) for adapter $($saved.SettingID)"
            }
        }

        $path = [string]$saved.RegistryPath
        if ([bool]$saved.RegistryValueExists) {
            Write-AdvancedSecurityNetBIOSRegistryValue -Path $path -Value $saved.RegistryValue `
                -Type ([string]$saved.RegistryValueType)
        }
        elseif (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop) {
            Remove-ItemProperty -LiteralPath $path -Name 'NetbiosOptions' -ErrorAction SilentlyContinue
        }

        if (-not [bool]$saved.RegistryKeyExisted -and
            (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)) {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            if (@($key.GetValueNames()).Count -ne 0 -or @($key.GetSubKeyNames()).Count -ne 0) {
                throw "Originally absent NetBIOS key gained unrelated state and cannot be removed safely: $path"
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
        elseif ([bool]$saved.RegistryKeyExisted -and
            -not (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)) {
            $null = New-Item -Path $path -Force -ErrorAction Stop
        }
    }

    $verified = Get-AdvancedSecurityNetBIOSState
    if (-not (Test-AdvancedSecurityNetBIOSStateEqual -Reference $Snapshot -Candidate $verified)) {
        throw 'NetBIOS typed adapter state did not return to the exact sealed prestate'
    }
    return $verified
}
