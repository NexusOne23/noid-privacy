<#
.SYNOPSIS
    Captures the exact prestate of every registry value changed or deleted by
    the parsed Security Baseline policies.
#>
function Backup-RegistryPolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerPoliciesPath,

        [Parameter(Mandatory = $false)]
        [string]$UserPoliciesPath,

        [Parameter(Mandatory = $true)]
        [string]$UserRegistryRoot,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        # Additional local controls owned by native policy processing. This is
        # capture-only input, never an Apply recipe or historical Restore default.
        [Parameter(Mandatory = $false)]
        [object[]]$AdditionalComputerTargets = @()
    )

    $result = [PSCustomObject]@{
        Success       = $false
        BackupPath    = $BackupPath
        ItemsBackedUp = 0
        Errors        = [System.Collections.Generic.List[string]]::new()
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Backup RegistryPolicies')) {
        return $result
    }

    $backup = [ordered]@{
        SchemaVersion     = 4
        Timestamp         = (Get-Date).ToString('o')
        UserRegistryRoot  = $UserRegistryRoot
        DirectiveCount    = 0
        AbsentAncestorKeys = @()
        Computer          = @()
        User              = @()
        ComputerClearKeys = @()
        UserClearKeys     = @()
    }

    try {
        foreach ($requiredCommand in @('Get-RegistryHierarchyPrestate', 'Get-ExactRegistryValueName')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                throw "Required registry hierarchy helper is unavailable: $requiredCommand"
            }
        }
        if ($UserRegistryRoot -notmatch '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+$' -or
            -not (Test-NoIDRegistryKey -LiteralPath $UserRegistryRoot)) {
            throw "Interactive user registry root is invalid or not loaded: $UserRegistryRoot"
        }
        $sources = @(
            [PSCustomObject]@{
                Scope        = 'Computer'
                PoliciesPath = $ComputerPoliciesPath
                Hive         = 'HKLM:'
                RootPattern  = '^(SOFTWARE|SYSTEM)\\'
                ClearBucket  = 'ComputerClearKeys'
            },
            [PSCustomObject]@{
                Scope        = 'User'
                PoliciesPath = $UserPoliciesPath
                Hive         = $UserRegistryRoot
                RootPattern  = '^SOFTWARE\\'
                ClearBucket  = 'UserClearKeys'
            }
        )
        $absentAncestorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        $additionalIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($target in $AdditionalComputerTargets) {
            if ($null -eq $target -or
                [string]$target.KeyName -notmatch '^\[SYSTEM\\CurrentControlSet\\Control\\' -or
                [string]::IsNullOrWhiteSpace([string]$target.ValueName) -or
                ([string]$target.ValueName).StartsWith('**', [StringComparison]::Ordinal) -or
                [string]$target.Type -cne 'REG_DWORD' -or
                -not $additionalIdentities.Add("$($target.KeyName)`0$($target.ValueName)")) {
                throw 'Additional registry backup targets contain an invalid or duplicate local control'
            }
        }

        foreach ($source in $sources) {
            $policies = @()
            if (-not [string]::IsNullOrWhiteSpace($source.PoliciesPath)) {
                if (-not (Test-Path -LiteralPath $source.PoliciesPath -PathType Leaf)) {
                    throw "$($source.Scope) policy file not found: $($source.PoliciesPath)"
                }
                # PS5.1 emits a JSON array as one pipeline object. Normalize
                # after assignment, preserving the old reader's flat inventory.
                $policies = Get-Content -LiteralPath $source.PoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                $policies = @($policies)
                if ($policies.Count -eq 0) {
                    throw "$($source.Scope) policy file contains no policies: $($source.PoliciesPath)"
                }
            }
            if ([string]$source.Scope -eq 'Computer' -and $AdditionalComputerTargets.Count -gt 0) {
                foreach ($policy in $policies) {
                    if ($additionalIdentities.Contains("$($policy.KeyName)`0$($policy.ValueName)")) {
                        throw 'Additional registry backup target duplicates a parsed policy target'
                    }
                }
                $policies += $AdditionalComputerTargets
            }
            if ($policies.Count -eq 0) { continue }

            foreach ($policy in $policies) {
                try {
                    $keyName = [string]$policy.KeyName
                    $keyPath = $keyName -replace '^\[', '' -replace '\]$', ''
                    if ($keyPath -notmatch $source.RootPattern) {
                        throw "Unsupported registry root in $keyName"
                    }
                    $fullPath = "$($source.Hive)\$keyPath"
                    $boundaryPath = if ([string]$source.Scope -eq 'User') {
                        "$UserRegistryRoot\SOFTWARE"
                    }
                    elseif ($keyPath.StartsWith('SOFTWARE\', [StringComparison]::OrdinalIgnoreCase)) {
                        'HKLM:\SOFTWARE'
                    }
                    else {
                        'HKLM:\SYSTEM'
                    }
                    foreach ($ancestorPath in @(Get-RegistryHierarchyPrestate `
                                -TargetPath $fullPath -BoundaryPath $boundaryPath)) {
                        $null = $absentAncestorKeys.Add([string]$ancestorPath)
                    }
                    $keyExisted = Test-Path -LiteralPath $fullPath -ErrorAction Stop

                    if ([string]$policy.ValueName -eq '**delvals.') {
                        $values = [System.Collections.Generic.List[object]]::new()
                        if ($keyExisted) {
                            $key = Get-Item -LiteralPath $fullPath -ErrorAction Stop
                            foreach ($valueName in $key.GetValueNames()) {
                                $values.Add([PSCustomObject]@{
                                        Name  = $valueName
                                        Type  = ConvertTo-RegistryTypeString -Kind $key.GetValueKind($valueName)
                                        Value = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                    })
                            }
                        }
                        $backup[[string]$source.ClearBucket] += [PSCustomObject]@{
                            KeyName    = $keyName
                            KeyExisted = $keyExisted
                            Values     = @($values)
                        }
                        $result.ItemsBackedUp++
                        continue
                    }

                    $targetName = if ([string]$policy.ValueName -match '^\*\*del\.(.+)$') {
                        $Matches[1]
                    }
                    else {
                        [string]$policy.ValueName
                    }
                    if ([string]::IsNullOrWhiteSpace($targetName)) {
                        throw "Policy has an empty target value name: $keyName"
                    }

                    $exists = $false
                    $value = $null
                    $type = [string]$policy.Type
                    $originalValueName = $null
                    if ($keyExisted) {
                        $key = Get-Item -LiteralPath $fullPath -ErrorAction Stop
                        $exists = $key.GetValueNames() -contains $targetName
                        if ($exists) {
                            $originalValueName = Get-ExactRegistryValueName -Key $key -Name $targetName
                            $value = $key.GetValue($originalValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            $type = ConvertTo-RegistryTypeString -Kind $key.GetValueKind($originalValueName)
                        }
                    }

                    $backup[[string]$source.Scope] += [PSCustomObject]@{
                        KeyName      = $keyName
                        ValueName    = $targetName
                        Type         = $type
                        OriginalValue = $value
                        OriginalValueName = $originalValueName
                        KeyExisted   = $keyExisted
                        Exists       = $exists
                    }
                    $result.ItemsBackedUp++
                }
                catch {
                    $result.Errors.Add("Failed to back up $($source.Scope) policy $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)")
                }
            }
        }

        if ($result.ItemsBackedUp -eq 0) {
            throw 'No registry policy state was captured'
        }
        if ($result.Errors.Count -gt 0) {
            throw ($result.Errors -join '; ')
        }
        $backup.DirectiveCount = $result.ItemsBackedUp
        $backup.AbsentAncestorKeys = @($absentAncestorKeys | Sort-Object)

        [System.IO.File]::WriteAllText(
            $BackupPath,
            ($backup | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false)
        )
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw 'RegistryPolicies backup artifact was not created'
        }
        $roundTrip = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $roundTripDirectiveCount = @($roundTrip.Computer).Count + @($roundTrip.User).Count +
            @($roundTrip.ComputerClearKeys).Count + @($roundTrip.UserClearKeys).Count
        if ([int]$roundTrip.SchemaVersion -ne 4 -or
            [string]$roundTrip.UserRegistryRoot -cne $UserRegistryRoot -or
            [int]$roundTrip.DirectiveCount -ne $result.ItemsBackedUp -or
            @($roundTrip.AbsentAncestorKeys).Count -ne $absentAncestorKeys.Count -or
            $roundTripDirectiveCount -ne $result.ItemsBackedUp) {
            throw 'RegistryPolicies backup failed round-trip completeness validation'
        }
        $result.Success = $true
        Write-Log -Level DEBUG -Message "Registry policy prestate saved: $($result.ItemsBackedUp) directives" -Module 'SecurityBaseline'
    }
    catch {
        if ($result.Errors.Count -eq 0 -or $result.Errors[-1] -ne $_.Exception.Message) {
            $result.Errors.Add("Registry policy backup failed: $($_.Exception.Message)")
        }
        $result.Success = $false
    }

    return $result
}
