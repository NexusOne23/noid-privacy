#Requires -Version 5.1

# Raw registry state that Windows' DoH APIs cannot reproduce on their own: the
# DnsClient cmdlets write a Flags value where Windows shipped none and leave an
# empty endpoint key after Remove-DnsClientDohServerAddress; SetInterfaceDnsSettings
# leaves empty DohInterfaceSettings keys and stores an auto-template property
# without the DohTemplate value Windows Settings writes. Schema 6 seals this raw
# state and Restore reinstates it after the API calls.
$script:DnsDohEndpointRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers'
$script:DnsInterfaceSpecificRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
$script:DnsRegistryValueTypes = @('String', 'ExpandString', 'DWord', 'QWord', 'MultiString', 'Binary')

function ConvertTo-DnsDohEndpointRegistryData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'ExpandString', 'DWord', 'QWord', 'MultiString', 'Binary')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value) { throw "DoH registry value of type $Type has no data" }
    switch ($Type) {
        'DWord' { return [int][Convert]::ToInt64($Value, [Globalization.CultureInfo]::InvariantCulture) }
        'QWord' { return [long][Convert]::ToInt64($Value, [Globalization.CultureInfo]::InvariantCulture) }
        # The unary comma keeps one-element arrays intact on return.
        'MultiString' { return , [string[]]@($Value | ForEach-Object { [string]$_ }) }
        'Binary' {
            return , [byte[]]@($Value | ForEach-Object {
                    $number = [Convert]::ToInt32($_, [Globalization.CultureInfo]::InvariantCulture)
                    if ($number -lt 0 -or $number -gt 255) { throw 'DoH registry Binary value is outside the byte range' }
                    $number
                })
        }
        default { return [string]$Value }
    }
}

function Get-DnsRegistryValueSet {
    # All values of one key as Name/Type/Value records sorted by name.
    # Callers wrap the output in @().
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $key = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    $values = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @($key.GetValueNames() | Sort-Object)) {
        $type = $key.GetValueKind($name).ToString()
        if ($type -notin $script:DnsRegistryValueTypes) {
            throw "DoH registry value '$name' has an unsupported type: $type"
        }
        $data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $values.Add([PSCustomObject]@{
                Name  = [string]$name
                Type  = $type
                Value = ConvertTo-DnsDohEndpointRegistryData -Type $type -Value $data
            })
    }
    $values
}

function Test-DnsRegistryValueSetExact {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Actual,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Expected
    )

    $normalize = {
        param($Values)
        @($Values | Sort-Object { ([string]$_.Name).ToLowerInvariant() } | ForEach-Object {
                [PSCustomObject]@{
                    Name  = ([string]$_.Name).ToLowerInvariant()
                    Type  = [string]$_.Type
                    Value = ConvertTo-DnsDohEndpointRegistryData -Type ([string]$_.Type) -Value $_.Value
                }
            }) | ConvertTo-Json -Compress -Depth 6
    }
    return ((& $normalize $Actual) -ceq (& $normalize $Expected))
}

function Sync-DnsRegistryValueSet {
    # Makes the values of one existing key equal to Expected; writes only differences.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Expected
    )

    if (-not $PSCmdlet.ShouldProcess($LiteralPath, 'Restore exact registry values')) { return }
    $current = @(Get-DnsRegistryValueSet -LiteralPath $LiteralPath)
    $expectedNames = @($Expected | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
    foreach ($value in @($current | Where-Object { ([string]$_.Name).ToLowerInvariant() -notin $expectedNames })) {
        Remove-ItemProperty -LiteralPath $LiteralPath -Name ([string]$value.Name) -ErrorAction Stop
    }
    foreach ($value in @($Expected)) {
        $currentValue = @($current | Where-Object { ([string]$_.Name) -eq ([string]$value.Name) })
        if ($currentValue.Count -eq 1 -and (Test-DnsRegistryValueSetExact -Actual @($currentValue[0]) -Expected @($value))) {
            continue
        }
        New-ItemProperty -LiteralPath $LiteralPath -Name ([string]$value.Name) -PropertyType ([string]$value.Type) `
            -Value (ConvertTo-DnsDohEndpointRegistryData -Type ([string]$value.Type) -Value $value.Value) `
            -Force -ErrorAction Stop | Out-Null
    }
}

function Get-DnsDohEndpointRegistryState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $canonicalAddress = ConvertTo-DnsCanonicalAddress -Address $Address
    $keys = @()
    if (Test-NoIDRegistryKey -LiteralPath $script:DnsDohEndpointRegistryRoot) {
        $keys = @(Get-ChildItem -LiteralPath $script:DnsDohEndpointRegistryRoot -ErrorAction Stop | Where-Object {
                $parsedName = $null
                [System.Net.IPAddress]::TryParse([string]$_.PSChildName, [ref]$parsedName) -and
                $parsedName.ToString() -eq $canonicalAddress
            })
    }
    if ($keys.Count -gt 1) {
        throw "Multiple DoH endpoint registry keys exist for $canonicalAddress"
    }
    if ($keys.Count -eq 0) {
        return [PSCustomObject]@{ KeyName = $null; KeyExisted = $false; Values = @() }
    }
    if ($keys[0].SubKeyCount -gt 0) {
        throw "DoH endpoint registry key has unexpected subkeys: $canonicalAddress"
    }
    $path = Join-Path $script:DnsDohEndpointRegistryRoot ([string]$keys[0].PSChildName)
    return [PSCustomObject]@{
        KeyName    = [string]$keys[0].PSChildName
        KeyExisted = $true
        Values     = @(Get-DnsRegistryValueSet -LiteralPath $path)
    }
}

function Test-DnsDohEndpointRegistryStateExact {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        $Expected
    )

    if ([bool]$Actual.KeyExisted -ne [bool]$Expected.KeyExisted) { return $false }
    if (-not [bool]$Expected.KeyExisted) { return $true }
    return (Test-DnsRegistryValueSetExact -Actual @($Actual.Values) -Expected @($Expected.Values))
}

function Restore-DnsDohEndpointRegistryState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address,

        [Parameter(Mandatory = $true)]
        $Expected
    )

    if (-not $PSCmdlet.ShouldProcess($Address, 'Restore exact DoH endpoint registry state')) {
        return $false
    }

    $current = Get-DnsDohEndpointRegistryState -Address $Address
    if (Test-DnsDohEndpointRegistryStateExact -Actual $current -Expected $Expected) {
        return $true
    }

    if (-not [bool]$Expected.KeyExisted) {
        if (@($current.Values).Count -gt 0) {
            throw "Originally absent DoH endpoint key still holds values after its registration was removed: $Address"
        }
        Remove-Item -LiteralPath (Join-Path $script:DnsDohEndpointRegistryRoot ([string]$current.KeyName)) -Force -ErrorAction Stop
    }
    else {
        $keyName = if ([bool]$current.KeyExisted) { [string]$current.KeyName } else { [string]$Expected.KeyName }
        $path = Join-Path $script:DnsDohEndpointRegistryRoot $keyName
        if (-not [bool]$current.KeyExisted) {
            New-NoIDRegistryKey -LiteralPath $path | Out-Null
        }
        Sync-DnsRegistryValueSet -LiteralPath $path -Expected @($Expected.Values) -Confirm:$false
    }

    $restored = Get-DnsDohEndpointRegistryState -Address $Address
    if (-not (Test-DnsDohEndpointRegistryStateExact -Actual $restored -Expected $Expected)) {
        throw "DoH endpoint registry post-restore verification failed: $Address"
    }
    return $true
}

function Get-DnsInterfaceSpecificKeyInventory {
    # Relative names of every existing key below InterfaceSpecificParameters\{guid};
    # '' stands for the adapter key itself. Callers wrap the output in @().
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid
    )

    $root = Join-Path $script:DnsInterfaceSpecificRegistryRoot $InterfaceGuid
    if (-not (Test-NoIDRegistryKey -LiteralPath $root)) { return }
    $prefix = (Get-Item -LiteralPath $root -ErrorAction Stop).Name + '\'
    $names = [System.Collections.Generic.List[string]]::new()
    $names.Add('')
    foreach ($key in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop)) {
        $names.Add($key.Name.Substring($prefix.Length))
    }
    $names | Sort-Object -Unique
}

function Get-DnsInterfaceDohRegistryValues {
    # Value-carrying keys of the managed families' DohInterfaceSettings\Doh
    # (IPv4) and \Doh6 (IPv6) subtrees as Key/Values records. Callers wrap the
    # output in @().
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$AddressFamilies
    )

    $root = Join-Path $script:DnsInterfaceSpecificRegistryRoot $InterfaceGuid
    foreach ($family in @($AddressFamilies | Sort-Object -Unique)) {
        if ($family -notin @(2, 23)) { throw "Unsupported DNS address family: $family" }
        $familyKey = if ($family -eq 2) { 'DohInterfaceSettings\Doh' } else { 'DohInterfaceSettings\Doh6' }
        foreach ($name in @(Get-DnsInterfaceSpecificKeyInventory -InterfaceGuid $InterfaceGuid | Where-Object {
                    $_ -eq $familyKey -or $_.StartsWith("$familyKey\", [StringComparison]::OrdinalIgnoreCase)
                })) {
            $values = @(Get-DnsRegistryValueSet -LiteralPath (Join-Path $root $name))
            if ($values.Count -gt 0) {
                [PSCustomObject]@{ Key = $name; Values = $values }
            }
        }
    }
}

function Test-DnsInterfaceDohRegistryValuesExact {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$AddressFamilies,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Expected
    )

    $current = @(Get-DnsInterfaceDohRegistryValues -InterfaceGuid $InterfaceGuid -AddressFamilies $AddressFamilies)
    if ($current.Count -ne @($Expected).Count) { return $false }
    foreach ($entry in @($Expected)) {
        $match = @($current | Where-Object { ([string]$_.Key) -eq ([string]$entry.Key) })
        if ($match.Count -ne 1 -or
            -not (Test-DnsRegistryValueSetExact -Actual @($match[0].Values) -Expected @($entry.Values))) {
            return $false
        }
    }
    return $true
}

function Restore-DnsInterfaceDohRegistryValues {
    # Reinstates the sealed raw values below the managed families' DoH keys
    # after SetInterfaceDnsSettings restored the same native state.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$AddressFamilies,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Expected
    )

    if (-not $PSCmdlet.ShouldProcess($InterfaceGuid, 'Restore exact DoH interface registry values')) {
        return $false
    }
    $root = Join-Path $script:DnsInterfaceSpecificRegistryRoot $InterfaceGuid
    $expectedKeys = @($Expected | ForEach-Object { ([string]$_.Key).ToLowerInvariant() })
    foreach ($entry in @(Get-DnsInterfaceDohRegistryValues -InterfaceGuid $InterfaceGuid -AddressFamilies $AddressFamilies)) {
        if (([string]$entry.Key).ToLowerInvariant() -notin $expectedKeys) {
            Sync-DnsRegistryValueSet -LiteralPath (Join-Path $root ([string]$entry.Key)) -Expected @() -Confirm:$false
        }
    }
    foreach ($entry in @($Expected)) {
        $path = Join-Path $root ([string]$entry.Key)
        if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { New-NoIDRegistryKey -LiteralPath $path | Out-Null }
        Sync-DnsRegistryValueSet -LiteralPath $path -Expected @($entry.Values) -Confirm:$false
    }
    return (Test-DnsInterfaceDohRegistryValuesExact -InterfaceGuid $InterfaceGuid -AddressFamilies $AddressFamilies -Expected @($Expected))
}

function Remove-DnsInterfaceSpecificKeysOutsideInventory {
    # Deletes only keys that did not exist at backup time and hold neither
    # values nor subkeys, and recreates sealed keys an API call removed; later
    # data below the adapter key stays untouched.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Inventory
    )

    if (-not $PSCmdlet.ShouldProcess($InterfaceGuid, 'Remove empty DoH interface keys created after backup')) {
        return $false
    }
    $root = Join-Path $script:DnsInterfaceSpecificRegistryRoot $InterfaceGuid
    $sealed = @{}
    foreach ($name in $Inventory) { $sealed[$name.ToLowerInvariant()] = $true }
    $current = @(Get-DnsInterfaceSpecificKeyInventory -InterfaceGuid $InterfaceGuid)
    # Children first; the adapter key '' has depth 0.
    $depth = { if ($_ -eq '') { 0 } else { $_.Split('\').Count } }
    foreach ($name in @($current | Sort-Object $depth -Descending)) {
        if ($sealed.ContainsKey($name.ToLowerInvariant())) { continue }
        $path = if ($name -eq '') { $root } else { Join-Path $root $name }
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    foreach ($name in @($Inventory | Sort-Object $depth)) {
        $path = if ($name -eq '') { $root } else { Join-Path $root $name }
        if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { New-NoIDRegistryKey -LiteralPath $path | Out-Null }
    }
    return (Test-DnsInterfaceSpecificKeysWithinInventory -InterfaceGuid $InterfaceGuid -Inventory $Inventory)
}

function Test-DnsInterfaceSpecificKeysWithinInventory {
    # True when every sealed key exists and every key outside the sealed
    # inventory still carries data.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Inventory
    )

    $root = Join-Path $script:DnsInterfaceSpecificRegistryRoot $InterfaceGuid
    $sealed = @{}
    foreach ($name in $Inventory) { $sealed[$name.ToLowerInvariant()] = $true }
    foreach ($name in @(Get-DnsInterfaceSpecificKeyInventory -InterfaceGuid $InterfaceGuid)) {
        if ($sealed.ContainsKey($name.ToLowerInvariant())) { continue }
        $key = Get-Item -LiteralPath $(if ($name -eq '') { $root } else { Join-Path $root $name }) -ErrorAction Stop
        if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { return $false }
    }
    foreach ($name in $Inventory) {
        $path = if ($name -eq '') { $root } else { Join-Path $root $name }
        if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { return $false }
    }
    return $true
}
