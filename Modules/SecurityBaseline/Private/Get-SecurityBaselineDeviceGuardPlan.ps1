#Requires -Version 5.1

function Get-SecurityBaselineDeviceGuardPlan {
    <#
    .SYNOPSIS
        Bind native Device Guard processing to the complete baseline decision.
    .DESCRIPTION
        Receives the recoverable Apply plan, after its four firmware-lock
        mappings. The eight policy values remain unchanged. LocalBackupTargets
        describe additional prestate to capture before Windows processes them;
        they are not an alternative registry activation recipe or defaults for
        Restore. Historical snapshots keep their own recorded target inventory.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory)][object[]]$Policies)

    $policyKey = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    $expected = [ordered]@{
        EnableVirtualizationBasedSecurity = 1
        RequirePlatformSecurityFeatures = 1
        HypervisorEnforcedCodeIntegrity = 2
        HVCIMATRequired = 1
        LsaCfgFlags = 2
        MachineIdentityIsolation = 3
        ConfigureSystemGuardLaunch = 1
        ConfigureKernelShadowStacksLaunch = 1
    }
    $selected = @($Policies | Where-Object {
            [string]$_.KeyName -ieq $policyKey
        })
    if ($selected.Count -ne $expected.Count) {
        throw 'Device Guard requires the complete eight-policy baseline plan'
    }
    $nativePolicies = @(foreach ($name in $expected.Keys) {
            $matchesForName = @($selected | Where-Object {
                    [string]$_.ValueName -ceq $name
                })
            if ($matchesForName.Count -ne 1) {
                throw "Device Guard policy identity is missing or duplicated: $name"
            }
            $entry = $matchesForName[0]
            if ([string]$entry.Type -cne 'REG_DWORD' -or
                ($entry.Data -isnot [int] -and $entry.Data -isnot [long]) -or
                $entry.Data -ne $expected[$name]) {
                throw "Device Guard policy differs from the reviewed baseline decision: $name"
            }
            $entry.PSObject.Copy()
        })

    [PSCustomObject]@{
        PolicyKey = $policyKey.Substring(1)
        Policies = $nativePolicies
        LocalBackupTargets = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)
    }
}

function Get-SecurityBaselineDeviceGuardLocalBackupTargets {
    [CmdletBinding()]
    param()

    # Windows' Device Guard processor materializes local controls. Capture the
    # complete reviewed local boundary, including metadata seen during native
    # activation/restart. No values are inferred for an older backup.
    $parent = '[SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $localScopes = @(
        @{ Key = $parent; Names = @('EnableVirtualizationBasedSecurity', 'RequirePlatformSecurityFeatures', 'Locked', 'Mandatory', 'RequireMicrosoftSignedBootChain') }
        @{ Key = "$parent\Scenarios\HypervisorEnforcedCodeIntegrity"; Names = @('Enabled', 'Locked', 'WasEnabledBy', 'EnabledBootId', 'HVCIMATRequired') }
        @{ Key = "$parent\Scenarios\SystemGuard"; Names = @('Enabled', 'Locked', 'Managed') }
        @{ Key = "$parent\Scenarios\CredentialGuard"; Names = @('Enabled', 'Locked') }
        @{ Key = "$parent\Scenarios\KernelShadowStacks"; Names = @('Enabled', 'Locked', 'AuditModeEnabled', 'WasEnabledBy') }
        @{ Key = '[SYSTEM\CurrentControlSet\Control\Lsa'; Names = @('LsaCfgFlags') }
    )
    foreach ($scope in $localScopes) {
        foreach ($name in $scope.Names) {
            [PSCustomObject]@{
                KeyName = [string]$scope.Key
                ValueName = [string]$name
                Type = 'REG_DWORD'
            }
        }
    }
}

function Assert-SecurityBaselineDeviceGuardRegistryCoverage {
    <# New GPO artifacts require recorded local prestate; old sessions do not. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RegistrySnapshot, [Parameter(Mandatory)]$GpoSnapshot)

    if ([int]$RegistrySnapshot.SchemaVersion -ne 4 -or $RegistrySnapshot.Computer -isnot [array]) {
        throw 'Device Guard GPO recovery requires the complete schema-4 registry prestate'
    }
    $targets = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)
    $targets += @(foreach ($value in $GpoSnapshot.Values) {
            [PSCustomObject]@{
                KeyName = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
                ValueName = [string]$value.Name
            }
        })
    foreach ($target in $targets) {
        $entries = @($RegistrySnapshot.Computer | Where-Object {
                [string]$_.KeyName -ieq [string]$target.KeyName -and
                [string]$_.ValueName -ieq [string]$target.ValueName
            })
        if ($entries.Count -ne 1) {
            throw "Device Guard registry prestate is missing or duplicated: $($target.KeyName)\$($target.ValueName)"
        }
    }
    return $true
}

function Select-SecurityBaselineDeviceGuardLocalRestoreSnapshot {
    <#
    .SYNOPSIS
        Select the recorded local Device Guard boundary from a complete backup.
    .DESCRIPTION
        This is an in-memory view of existing records, not a backup migration.
        Missing prestate is an error. In particular, this helper cannot add the
        twenty local records that an original 2.2.5 backup never captured.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RegistrySnapshot)

    if (($RegistrySnapshot.SchemaVersion -isnot [int] -and $RegistrySnapshot.SchemaVersion -isnot [long]) -or
        $RegistrySnapshot.SchemaVersion -ne 4 -or
        $RegistrySnapshot.Computer -isnot [array] -or
        $RegistrySnapshot.AbsentAncestorKeys -isnot [array]) {
        throw 'Local Device Guard recovery requires recorded schema-4 prestate'
    }
    $fullCount = @($RegistrySnapshot.Computer).Count + @($RegistrySnapshot.User).Count +
        @($RegistrySnapshot.ComputerClearKeys).Count + @($RegistrySnapshot.UserClearKeys).Count
    if (($RegistrySnapshot.DirectiveCount -isnot [int] -and $RegistrySnapshot.DirectiveCount -isnot [long]) -or
        $RegistrySnapshot.DirectiveCount -ne $fullCount) {
        throw 'Local Device Guard recovery source has an inconsistent directive count'
    }

    $selected = @(foreach ($target in @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)) {
            $entries = @($RegistrySnapshot.Computer | Where-Object {
                    [string]$_.KeyName -ieq [string]$target.KeyName -and
                    [string]$_.ValueName -ieq [string]$target.ValueName
                })
            if ($entries.Count -ne 1) {
                throw "Recorded local Device Guard target is missing or duplicated: $($target.KeyName)\$($target.ValueName)"
            }
            $entry = $entries[0]
            foreach ($field in @('KeyName', 'ValueName', 'KeyExisted', 'Exists', 'Type', 'OriginalValue', 'OriginalValueName')) {
                if (-not $entry.PSObject.Properties[$field]) { throw "Recorded local Device Guard entry is missing $field" }
            }
            if ($entry.KeyName -isnot [string] -or $entry.ValueName -isnot [string] -or
                $entry.KeyExisted -isnot [bool] -or $entry.Exists -isnot [bool] -or $entry.Type -isnot [string]) {
                throw 'Recorded local Device Guard entry has invalid primitive types'
            }
            if (-not $entry.Exists) {
                if ($null -ne $entry.OriginalValue -or $null -ne $entry.OriginalValueName) {
                    throw 'Absent local Device Guard value contains invented prestate'
                }
            }
            else {
                if (-not $entry.KeyExisted -or $entry.OriginalValueName -isnot [string] -or
                    -not $entry.OriginalValueName.Equals($entry.ValueName, [StringComparison]::OrdinalIgnoreCase) -or
                    $null -eq $entry.OriginalValue) {
                    throw 'Recorded local Device Guard value has inconsistent existence or name evidence'
                }
                $value = $entry.OriginalValue
                $validData = switch -CaseSensitive ($entry.Type) {
                    'REG_DWORD' { ($value -is [int] -or $value -is [long]) -and $value -ge [int]::MinValue -and $value -le [int]::MaxValue }
                    'REG_QWORD' { $value -is [int] -or $value -is [long] }
                    'REG_SZ' { $value -is [string] }
                    'REG_EXPAND_SZ' { $value -is [string] }
                    'REG_BINARY' { $value -is [array] -and @($value | Where-Object { ($_ -isnot [int] -and $_ -isnot [long] -and $_ -isnot [byte]) -or $_ -lt 0 -or $_ -gt 255 }).Count -eq 0 }
                    'REG_MULTI_SZ' { $value -is [array] -and @($value | Where-Object { $_ -isnot [string] }).Count -eq 0 }
                    default { $false }
                }
                if (-not $validData) { throw 'Recorded local Device Guard value has invalid typed data' }
            }
            # Retain the original type, data, spelling and existence evidence.
            $entry.PSObject.Copy()
        })
    $paths = @($selected | ForEach-Object { 'HKLM:\' + ([string]$_.KeyName).Substring(1) })
    $ancestors = @(foreach ($ancestor in $RegistrySnapshot.AbsentAncestorKeys) {
            if ($ancestor -isnot [string]) { throw 'Recorded registry ancestor is not a string' }
            if (@($paths | Where-Object {
                        $_.StartsWith($ancestor.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
                    }).Count -gt 0) { $ancestor }
        })

    [PSCustomObject]@{
        SchemaVersion = $RegistrySnapshot.SchemaVersion
        UserRegistryRoot = $RegistrySnapshot.UserRegistryRoot
        Computer = $selected
        User = @()
        ComputerClearKeys = @()
        UserClearKeys = @()
        AbsentAncestorKeys = $ancestors
        DirectiveCount = $selected.Count
    }
}
