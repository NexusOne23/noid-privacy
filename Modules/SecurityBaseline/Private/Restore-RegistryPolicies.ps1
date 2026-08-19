<#
.SYNOPSIS
    Restores and verifies the exact registry-policy prestate captured before
    SecurityBaseline Apply.
#>
function Restore-RegistryPolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success       = $false
        ItemsRestored = 0
        ItemsVerified = 0
        Errors        = [System.Collections.Generic.List[string]]::new()
    }
    $mountedUserHives = [System.Collections.Generic.List[object]]::new()
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore exact RegistryPolicies prestate')) {
        return $result
    }

    function Convert-PolicyTypeToRegistryKind {
        param([string]$Type)
        switch ($Type) {
            'REG_DWORD'     { [Microsoft.Win32.RegistryValueKind]::DWord }
            'REG_QWORD'     { [Microsoft.Win32.RegistryValueKind]::QWord }
            'REG_SZ'        { [Microsoft.Win32.RegistryValueKind]::String }
            'REG_EXPAND_SZ' { [Microsoft.Win32.RegistryValueKind]::ExpandString }
            'REG_BINARY'    { [Microsoft.Win32.RegistryValueKind]::Binary }
            'REG_MULTI_SZ'  { [Microsoft.Win32.RegistryValueKind]::MultiString }
            default { throw "Unsupported registry backup type: $Type" }
        }
    }

    function Convert-RegistryBackupValue {
        param($Value, [Microsoft.Win32.RegistryValueKind]$Kind)
        switch ($Kind.ToString()) {
            'DWord'       { [int]$Value }
            'QWord'       { [long]$Value }
            'Binary'      { [byte[]]@($Value | ForEach-Object { [byte]$_ }) }
            'MultiString' { [string[]]@($Value) }
            default       { [string]$Value }
        }
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "RegistryPolicies backup file not found: $BackupPath"
        }
        $backup = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $schemaVersion = [int]$backup.SchemaVersion
        if ($schemaVersion -notin @(3, 4)) {
            throw "Unsupported RegistryPolicies backup schema: $($backup.SchemaVersion)"
        }
        if ($schemaVersion -eq 4 -and -not $backup.PSObject.Properties['AbsentAncestorKeys']) {
            throw 'RegistryPolicies schema 4 backup has no absent-ancestor inventory'
        }
        $userRoot = [string]$backup.UserRegistryRoot
        if ($userRoot -notmatch '^HKU:\\(S-1-(?:5-21|12-1)-[0-9-]+)$') {
            throw "Original interactive user hive is invalid: $userRoot"
        }
        if (-not (Get-Command 'Mount-UserRegistryHiveForRestore' -ErrorAction SilentlyContinue)) {
            throw 'Core user-hive restore helper is unavailable'
        }
        $mountedUserHives.Add((Mount-UserRegistryHiveForRestore -Sid $Matches[1]))
        if (-not (Test-Path -LiteralPath $userRoot -PathType Container)) {
            throw "Original interactive user hive could not be loaded: $userRoot"
        }

        $valueStates = @{}
        $keyStates = @{}
        $clearKeys = @{}

        function Add-KeyState {
            param([string]$Path, [bool]$Existed)
            $identity = $Path.ToLowerInvariant()
            if ($keyStates.ContainsKey($identity) -and [bool]$keyStates[$identity].Existed -ne $Existed) {
                throw "Inconsistent SecurityBaseline key-existence prestate: $Path"
            }
            if (-not $keyStates.ContainsKey($identity)) {
                $keyStates[$identity] = [PSCustomObject]@{ Path = $Path; Existed = $Existed }
            }
        }

        function Add-ValueState {
            param(
                [string]$Path,
                [string]$Name,
                [bool]$Exists,
                [string]$Type,
                $Value
            )
            if ([string]::IsNullOrWhiteSpace($Name)) {
                throw "SecurityBaseline registry prestate contains an empty value name at $Path"
            }
            if ($Exists) {
                $kind = Convert-PolicyTypeToRegistryKind -Type $Type
                $normalizedValue = Convert-RegistryBackupValue -Value $Value -Kind $kind
            }
            else {
                $kind = $null
                $normalizedValue = $null
            }
            $identity = "$($Path.ToLowerInvariant())`0$($Name.ToLowerInvariant())"
            $candidate = [PSCustomObject]@{
                Path = $Path; Name = $Name; Exists = $Exists
                Type = $Type; Kind = $kind; Value = $normalizedValue
            }
            if ($valueStates.ContainsKey($identity)) {
                $existingJson = $valueStates[$identity] | Select-Object Exists, Type, Value |
                    ConvertTo-Json -Compress -Depth 20
                $candidateJson = $candidate | Select-Object Exists, Type, Value |
                    ConvertTo-Json -Compress -Depth 20
                if ($existingJson -cne $candidateJson) {
                    throw "Conflicting duplicate SecurityBaseline prestate: $Path\$Name"
                }
                return
            }
            $valueStates[$identity] = $candidate
        }

        $scopes = @(
            [PSCustomObject]@{
                Hive = 'HKLM:'; RootPattern = '^(SOFTWARE|SYSTEM)\\'
                Items = @($backup.Computer); Clears = @($backup.ComputerClearKeys)
            },
            [PSCustomObject]@{
                Hive = $userRoot; RootPattern = '^SOFTWARE\\'
                Items = @($backup.User); Clears = @($backup.UserClearKeys)
            }
        )

        foreach ($scope in $scopes) {
            foreach ($clearState in $scope.Clears) {
                $keyPath = ([string]$clearState.KeyName) -replace '^\[', '' -replace '\]$', ''
                if ($keyPath -notmatch $scope.RootPattern -or -not $clearState.PSObject.Properties['KeyExisted']) {
                    throw "Invalid SecurityBaseline clear-key prestate: $($clearState.KeyName)"
                }
                $fullPath = "$($scope.Hive)\$keyPath"
                Add-KeyState -Path $fullPath -Existed ([bool]$clearState.KeyExisted)
                $clearKeyIdentity = $fullPath.ToLowerInvariant()
                if ($clearKeys.ContainsKey($clearKeyIdentity)) {
                    throw "Duplicate SecurityBaseline clear-key prestate: $fullPath"
                }
                $clearKeys[$clearKeyIdentity] = [PSCustomObject]@{
                    Path = $fullPath
                    ExpectedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
                foreach ($valueState in @($clearState.Values)) {
                    $name = [string]$valueState.Name
                    if (-not $clearKeys[$clearKeyIdentity].ExpectedNames.Add($name)) {
                        throw "Duplicate value in SecurityBaseline clear-key prestate: $fullPath\$name"
                    }
                    Add-ValueState -Path $fullPath -Name $name -Exists $true `
                        -Type ([string]$valueState.Type) -Value $valueState.Value
                }
            }

            foreach ($item in $scope.Items) {
                $keyPath = ([string]$item.KeyName) -replace '^\[', '' -replace '\]$', ''
                if ($keyPath -notmatch $scope.RootPattern -or
                    -not $item.PSObject.Properties['ValueName'] -or
                    -not $item.PSObject.Properties['KeyExisted'] -or
                    -not $item.PSObject.Properties['Exists']) {
                    throw "Invalid SecurityBaseline registry prestate: $($item.KeyName)\$($item.ValueName)"
                }
                $fullPath = "$($scope.Hive)\$keyPath"
                if ([bool]$item.Exists -and -not [bool]$item.KeyExisted) {
                    throw "Existing value is recorded under an originally absent key: $fullPath\$($item.ValueName)"
                }
                $restoreName = [string]$item.ValueName
                if ($schemaVersion -eq 4) {
                    if (-not $item.PSObject.Properties['OriginalValueName']) {
                        throw "RegistryPolicies schema 4 entry has no original value name: $fullPath\$restoreName"
                    }
                    if ([bool]$item.Exists) {
                        if ([string]::IsNullOrWhiteSpace([string]$item.OriginalValueName) -or
                            -not ([string]$item.OriginalValueName).Equals($restoreName, [StringComparison]::OrdinalIgnoreCase)) {
                            throw "RegistryPolicies original value-name identity is invalid: $fullPath\$restoreName"
                        }
                        $restoreName = [string]$item.OriginalValueName
                    }
                    elseif ($null -ne $item.OriginalValueName) {
                        throw "Absent RegistryPolicies value has an original value name: $fullPath\$restoreName"
                    }
                }
                Add-KeyState -Path $fullPath -Existed ([bool]$item.KeyExisted)
                Add-ValueState -Path $fullPath -Name $restoreName `
                    -Exists ([bool]$item.Exists) -Type ([string]$item.Type) -Value $item.OriginalValue
            }
        }

        if ($schemaVersion -eq 4) {
            $declaredTargetPaths = @($keyStates.Values | ForEach-Object { [string]$_.Path })
            $seenAncestorPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $escapedUserRoot = [regex]::Escape($userRoot)
            foreach ($ancestorPathValue in @($backup.AbsentAncestorKeys)) {
                $ancestorPath = ([string]$ancestorPathValue).TrimEnd('\')
                if ([string]::IsNullOrWhiteSpace($ancestorPath) -or
                    -not $seenAncestorPaths.Add($ancestorPath) -or
                    ($ancestorPath -notmatch '(?i)^HKLM:\\(SOFTWARE|SYSTEM)\\' -and
                     $ancestorPath -notmatch "(?i)^$escapedUserRoot\\SOFTWARE\\")) {
                    throw "Invalid or duplicate RegistryPolicies absent ancestor: $ancestorPath"
                }
                $ownedDescendants = @($declaredTargetPaths | Where-Object {
                        $_.StartsWith("$ancestorPath\", [StringComparison]::OrdinalIgnoreCase)
                    })
                if ($ownedDescendants.Count -eq 0) {
                    throw "RegistryPolicies absent ancestor owns no declared target: $ancestorPath"
                }
                Add-KeyState -Path $ancestorPath -Existed $false
            }
        }

        if ($keyStates.Count -eq 0 -or $valueStates.Count -eq 0) {
            throw 'RegistryPolicies backup contains no restorable state'
        }
        $directiveRecordCount = @($backup.Computer).Count + @($backup.User).Count +
            @($backup.ComputerClearKeys).Count + @($backup.UserClearKeys).Count
        if (-not $backup.PSObject.Properties['DirectiveCount'] -or
            [int]$backup.DirectiveCount -ne $directiveRecordCount) {
            throw 'RegistryPolicies directive count is inconsistent with captured directives'
        }

        # Fail before mutation if an originally absent key contains current
        # state that is not owned by the baseline snapshot.
        # HKLM:\...\Policies\System is shared with the sibling SecurityBaseline
        # restore routines. Sibling-owned values are not unowned state: their
        # owners remove them later in the same restore session, and the sibling
        # that restores last (Restore-UACStandardUserElevation) enforces final
        # key absence. Owners: SecurityTemplates.json-derived values
        # (Restore-SecurityTemplateRegistryState) + ConsentPromptBehaviorUser
        # (Restore-UACStandardUserElevation).
        $sharedUacPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $siblingOwnedUacPolicyValues = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($siblingName in @(
                'EnableInstallerDetection', 'EnableSecureUIAPaths', 'TypeOfAdminApprovalMode',
                'ConsentPromptBehaviorEnhancedAdmin', 'EnableLUA', 'EnableVirtualization',
                'FilterAdministratorToken', 'ConsentPromptBehaviorAdmin', 'InactivityTimeoutSecs',
                'ConsentPromptBehaviorUser'
            )) { $null = $siblingOwnedUacPolicyValues.Add($siblingName) }
        $managedPaths = @($keyStates.Values | ForEach-Object { [string]$_.Path })
        foreach ($keyState in @($keyStates.Values | Where-Object { -not [bool]$_.Existed })) {
            $path = [string]$keyState.Path
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            $subtreeItems = @(
                Get-Item -LiteralPath $path -ErrorAction Stop
                Get-ChildItem -LiteralPath $path -Recurse -ErrorAction Stop
            )
            foreach ($subtreeItem in $subtreeItems) {
                $nativeName = [string]$subtreeItem.Name
                $currentPath = if ($nativeName -match '^HKEY_LOCAL_MACHINE\\(.+)$') {
                    "HKLM:\$($Matches[1])"
                }
                elseif ($nativeName -match '^HKEY_USERS\\(.+)$') {
                    "HKU:\$($Matches[1])"
                }
                else {
                    throw "Unsupported registry key identity in SecurityBaseline restore: $nativeName"
                }
                $isManagedPath = @($managedPaths | Where-Object {
                        $_.Equals($currentPath, [StringComparison]::OrdinalIgnoreCase)
                    }).Count -eq 1
                $isManagedAncestor = @($managedPaths | Where-Object {
                        $_.StartsWith("$currentPath\", [StringComparison]::OrdinalIgnoreCase)
                    }).Count -gt 0
                if (-not $isManagedPath -and -not $isManagedAncestor) {
                    throw "Originally absent SecurityBaseline key contains unowned subkey: $currentPath"
                }
                if ($clearKeys.ContainsKey($currentPath.ToLowerInvariant())) { continue }
                $ownedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($state in @($valueStates.Values | Where-Object {
                            ([string]$_.Path).Equals($currentPath, [StringComparison]::OrdinalIgnoreCase)
                        })) {
                    $null = $ownedNames.Add([string]$state.Name)
                }
                $unownedValues = @($subtreeItem.GetValueNames() | Where-Object {
                        -not $ownedNames.Contains([string]$_) -and
                        -not ($currentPath.Equals($sharedUacPolicyPath, [StringComparison]::OrdinalIgnoreCase) -and
                            $siblingOwnedUacPolicyValues.Contains([string]$_))
                    })
                if ($unownedValues.Count -gt 0) {
                    throw "Originally absent SecurityBaseline key contains unowned values: $currentPath"
                }
            }
        }

        foreach ($keyState in $keyStates.Values) {
            if ([bool]$keyState.Existed -and
                -not (Test-Path -LiteralPath ([string]$keyState.Path) -PathType Container)) {
                New-Item -Path ([string]$keyState.Path) -Force -ErrorAction Stop | Out-Null
                $result.ItemsRestored++
            }
        }

        # A **delvals. directive owns the complete value set of its key.
        foreach ($clearState in $clearKeys.Values) {
            $path = [string]$clearState.Path
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                New-Item -Path $path -Force -ErrorAction Stop | Out-Null
            }
            $currentNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
            foreach ($currentName in $currentNames) {
                Remove-ItemProperty -LiteralPath $path -Name ([string]$currentName) -Force -ErrorAction Stop
            }
            foreach ($state in @($valueStates.Values | Where-Object {
                        [string]$_.Path -eq $path -and [bool]$_.Exists
                    })) {
                New-ItemProperty -Path $path -Name ([string]$state.Name) -Value $state.Value `
                    -PropertyType ([string]$state.Kind) -Force -ErrorAction Stop | Out-Null
            }
            $result.ItemsRestored++
        }

        foreach ($state in $valueStates.Values) {
            $path = [string]$state.Path
            if ($clearKeys.ContainsKey($path.ToLowerInvariant())) { continue }
            if ([bool]$state.Exists) {
                if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                }
                $currentNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
                if ($currentNames -contains [string]$state.Name) {
                    Remove-ItemProperty -LiteralPath $path -Name ([string]$state.Name) -Force -ErrorAction Stop
                }
                New-ItemProperty -Path $path -Name ([string]$state.Name) -Value $state.Value `
                    -PropertyType ([string]$state.Kind) -Force -ErrorAction Stop | Out-Null
            }
            elseif (Test-Path -LiteralPath $path -PathType Container) {
                $currentNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
                if ($currentNames -contains [string]$state.Name) {
                    Remove-ItemProperty -LiteralPath $path -Name ([string]$state.Name) -Force -ErrorAction Stop
                }
            }
            $result.ItemsRestored++
        }

        $cleanupPaths = @($keyStates.Values | Where-Object { -not [bool]$_.Existed } |
                ForEach-Object { [string]$_.Path } | Sort-Object { $_.Length } -Descending)
        foreach ($path in $cleanupPaths) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            $cleanupKey = Get-Item -LiteralPath $path -ErrorAction Stop
            $remainingValues = @($cleanupKey.GetValueNames())
            if ($path.Equals($sharedUacPolicyPath, [StringComparison]::OrdinalIgnoreCase) -and
                $cleanupKey.SubKeyCount -eq 0 -and
                $remainingValues.Count -gt 0 -and
                @($remainingValues | Where-Object { -not $siblingOwnedUacPolicyValues.Contains([string]$_) }).Count -eq 0) {
                # Only sibling-owned values remain; deletion of the shared key is
                # deferred to the sibling that restores last in this session.
                continue
            }
            if ($remainingValues.Count -ne 0 -or $cleanupKey.SubKeyCount -ne 0) {
                throw "Originally absent SecurityBaseline key contains state after managed values were restored: $path"
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $path -PathType Container) {
                throw "Originally absent SecurityBaseline key remains after restore: $path"
            }
        }

        foreach ($state in $valueStates.Values) {
            $path = [string]$state.Path
            $present = $false
            $actual = $null
            $actualKind = $null
            if (Test-Path -LiteralPath $path -PathType Container) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $matchingNames = @($key.GetValueNames() | Where-Object {
                        ([string]$_).Equals([string]$state.Name, [StringComparison]::OrdinalIgnoreCase)
                    })
                $present = $matchingNames.Count -eq 1
                if ($present) {
                    if ($schemaVersion -eq 4 -and [string]$matchingNames[0] -cne [string]$state.Name) {
                        throw "Registry value-name casing mismatch: $path\$($state.Name)"
                    }
                    $actual = $key.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $actualKind = $key.GetValueKind([string]$matchingNames[0])
                }
            }
            if ($present -ne [bool]$state.Exists) {
                throw "Registry value-existence mismatch: $path\$($state.Name)"
            }
            if ($present) {
                $expectedJson = ConvertTo-Json -InputObject @($state.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actual) -Compress -Depth 20
                if ($actualKind -ne $state.Kind -or $actualJson -cne $expectedJson) {
                    throw "Registry type/value mismatch: $path\$($state.Name)"
                }
            }
            $result.ItemsVerified++
        }

        foreach ($clearState in $clearKeys.Values) {
            $path = [string]$clearState.Path
            $actualNames = @()
            if (Test-Path -LiteralPath $path -PathType Container) {
                $actualNames = @((Get-Item -LiteralPath $path -ErrorAction Stop).GetValueNames())
            }
            if ($actualNames.Count -ne $clearState.ExpectedNames.Count -or
                @($actualNames | Where-Object { -not $clearState.ExpectedNames.Contains([string]$_) }).Count -gt 0) {
                throw "Registry clear-key value-set mismatch: $path"
            }
        }

        foreach ($keyState in $keyStates.Values) {
            $statePath = [string]$keyState.Path
            $keyExists = Test-Path -LiteralPath $statePath -PathType Container
            if ($keyExists -and -not [bool]$keyState.Existed -and
                $statePath.Equals($sharedUacPolicyPath, [StringComparison]::OrdinalIgnoreCase)) {
                $sharedKey = Get-Item -LiteralPath $statePath -ErrorAction Stop
                if ($sharedKey.SubKeyCount -eq 0 -and
                    @(@($sharedKey.GetValueNames()) | Where-Object {
                            -not $siblingOwnedUacPolicyValues.Contains([string]$_)
                        }).Count -eq 0) {
                    # Sibling-owned values still pending their own restore step;
                    # the last shared-key owner verifies final absence.
                    continue
                }
            }
            if ($keyExists -ne [bool]$keyState.Existed) {
                throw "Registry key-existence mismatch: $statePath"
            }
        }

        $result.Success = ($result.ItemsVerified -eq $valueStates.Count)
    }
    catch {
        $result.Errors.Add("Registry policy restore failed: $($_.Exception.Message) [Stack: $($_.ScriptStackTrace)]")
        $result.Success = $false
    }
    finally {
        Remove-Variable -Name key, clearKey, registryKey -ErrorAction SilentlyContinue
        foreach ($mount in @($mountedUserHives | Sort-Object { [string]$_.Sid } -Descending)) {
            if (-not (Dismount-UserRegistryHiveAfterRestore -Mount $mount)) {
                $result.Errors.Add("Temporary SecurityBaseline user hive could not be unloaded: $($mount.Sid)")
                $result.Success = $false
            }
        }
    }
    return $result
}
