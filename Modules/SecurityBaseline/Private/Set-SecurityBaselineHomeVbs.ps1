#Requires -Version 5.1

function Get-SecurityBaselineHomeVbsTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$OperatingSystemSku, [Parameter(Mandatory)][object[]]$Policies)

    if (($OperatingSystemSku -isnot [int] -and $OperatingSystemSku -isnot [long] -and
         $OperatingSystemSku -isnot [uint32]) -or $OperatingSystemSku -le 0) {
        throw 'Windows edition evidence is required for Device Guard activation'
    }
    # PRODUCT_CORE_N, CORE_COUNTRYSPECIFIC, CORE_SINGLELANGUAGE and CORE.
    # https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
    if ($OperatingSystemSku -notin @(98, 99, 100, 101)) { return }
    $null = Get-SecurityBaselineDeviceGuardPlan -Policies $Policies

    # Windows Home does not process the Device Guard policy values, even after
    # a restart. Microsoft's local activation path provides VBS/HVCI there:
    # https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry
    # Retain the baseline's MAT requirement, documented in Microsoft's lab and
    # written to this same local path when Enterprise processes the policy:
    # https://github.com/microsoft/MSLab/blob/master/Scenarios/DeviceGuard/VBS/readme.md
    # These six controls are already in the twenty-value recovery inventory.
    # The full eight-policy plan and its four reviewed firmware mappings stay
    # unchanged; this does not activate edition-restricted Credential Guard.
    $parent = '[SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $hvci = "$parent\Scenarios\HypervisorEnforcedCodeIntegrity"
    foreach ($item in @(
            @{ Key = $parent; Name = 'EnableVirtualizationBasedSecurity'; Data = 1 }
            @{ Key = $parent; Name = 'RequirePlatformSecurityFeatures'; Data = 1 }
            @{ Key = $parent; Name = 'Locked'; Data = 0 }
            @{ Key = $hvci; Name = 'Enabled'; Data = 1 }
            @{ Key = $hvci; Name = 'Locked'; Data = 0 }
            @{ Key = $hvci; Name = 'HVCIMATRequired'; Data = 1 }
        )) {
        [pscustomobject]@{ KeyName = $item.Key; ValueName = $item.Name; Data = $item.Data }
    }
}

function Set-SecurityBaselineHomeVbs {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]$OperatingSystemSku,
        [Parameter(Mandatory)][object[]]$Policies,
        [Parameter(Mandatory)]$RegistrySnapshot
    )

    $targets = @(Get-SecurityBaselineHomeVbsTargets -OperatingSystemSku $OperatingSystemSku -Policies $Policies)
    if ($targets.Count -eq 0) { return $false }
    $local = Select-SecurityBaselineDeviceGuardLocalRestoreSnapshot -RegistrySnapshot $RegistrySnapshot
    $operations = @(foreach ($target in $targets) {
            $entry = @($local.Computer | Where-Object {
                    $_.KeyName -ieq $target.KeyName -and $_.ValueName -ieq $target.ValueName
                })[0]
            [pscustomobject]@{
                Path = 'HKLM:\' + $target.KeyName.Substring(1)
                Target = $target
                Before = $entry
                # Preserve original spelling/data; the preflight below rejects
                # any existing lock except the documented DWORD zero.
                Preserve = ($target.ValueName -ceq 'Locked' -and $entry.Exists)
            }
        })
    if (-not $PSCmdlet.ShouldProcess('Windows Home VBS and memory integrity', 'Configure the recorded local activation controls')) {
        return $false
    }

    # Validate all six prestates before the first write. The caller has already
    # sealed/reconciled the complete backup and retained the first supplement.
    foreach ($operation in $operations) {
        $entry = $operation.Before
        $keyExists = Test-NoIDRegistryKey -LiteralPath $operation.Path
        if ($keyExists -ne $entry.KeyExisted) { throw "Home VBS key existence changed after backup: $($operation.Path)" }
        $names = @()
        if ($keyExists) {
            $key = Get-Item -LiteralPath $operation.Path -ErrorAction Stop
            $names = @($key.GetValueNames() | Where-Object { $_ -ieq $entry.ValueName })
        }
        if (($names.Count -eq 1) -ne $entry.Exists) { throw 'Home VBS value existence changed after backup' }
        if ($entry.Exists) {
            $kind = ConvertTo-RegistryTypeString -Kind $key.GetValueKind($names[0])
            $actual = $key.GetValue($names[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($names[0] -cne $entry.OriginalValueName -or $kind -cne $entry.Type -or
                (ConvertTo-Json -InputObject @($actual) -Compress -Depth 20) -cne
                (ConvertTo-Json -InputObject @($entry.OriginalValue) -Compress -Depth 20)) {
                throw 'Home VBS typed prestate changed after backup'
            }
        }
    }
    # Locked=1 can be a pending request, not evidence of an existing firmware
    # binding. Enabling VBS/HVCI while retaining that request could create a new
    # lock on restart. Do not clear it or guess from Enabled/runtime state.
    # Only original absence or a recorded DWORD zero permits local activation.
    foreach ($operation in $operations) {
        if ($operation.Preserve -and
            ($operation.Before.Type -cne 'REG_DWORD' -or $operation.Before.OriginalValue -ne 0)) {
            throw 'Windows Home VBS activation blocked by existing local UEFI-lock configuration. No activation controls were changed; lock values are retained. See Docs/SECURITY-BASELINE-RECOVERY.md.'
        }
    }
    foreach ($operation in $operations) {
        if ($operation.Preserve) { continue }
        if (-not (Test-NoIDRegistryKey -LiteralPath $operation.Path)) {
            $null = New-NoIDRegistryKey -LiteralPath $operation.Path
        }
        $target = $operation.Target
        $null = New-ItemProperty -LiteralPath $operation.Path -Name $target.ValueName `
            -Value ([int]$target.Data) -PropertyType DWord -Force -ErrorAction Stop
        $key = Get-Item -LiteralPath $operation.Path -ErrorAction Stop
        if ($key.GetValueKind($target.ValueName) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
            $key.GetValue($target.ValueName) -ne $target.Data) {
            throw 'Home VBS local activation verification failed'
        }
    }
    return $true
}
