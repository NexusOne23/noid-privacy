function Restore-UACStandardUserElevation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{ Success = $false; Errors = @(); Warnings = @(); RetainedKeys = @() }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore ConsentPromptBehaviorUser')) {
        return $result
    }

    $expectedPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $expectedName = 'ConsentPromptBehaviorUser'
    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "UAC backup artifact not found: $BackupPath"
        }
        $backup = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $schemaVersion = [int]$backup.SchemaVersion
        if ($schemaVersion -notin @(2, 3) -or
            [string]$backup.Path -cne $expectedPath -or
            [string]$backup.Name -cne $expectedName -or
            $backup.KeyExisted -isnot [bool] -or $backup.Exists -isnot [bool] -or
            ([bool]$backup.Exists -and -not [bool]$backup.KeyExisted) -or
            ([bool]$backup.Exists -and ([string]$backup.Type -cne 'DWord' -or $null -eq $backup.Value)) -or
            (-not [bool]$backup.Exists -and ($null -ne $backup.Type -or $null -ne $backup.Value))) {
            throw 'UAC backup artifact has an invalid schema, target or state'
        }
        $restoreName = $expectedName
        $absentAncestorKeys = @()
        if ($schemaVersion -eq 3) {
            if (-not $backup.PSObject.Properties['OriginalName'] -or
                -not $backup.PSObject.Properties['AbsentAncestorKeys']) {
                throw 'UAC schema 3 backup has no exact name or absent-ancestor inventory'
            }
            if ([bool]$backup.Exists) {
                if ([string]::IsNullOrWhiteSpace([string]$backup.OriginalName) -or
                    -not ([string]$backup.OriginalName).Equals($expectedName, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'UAC original value-name identity is invalid'
                }
                $restoreName = [string]$backup.OriginalName
            }
            elseif ($null -ne $backup.OriginalName) {
                throw 'Absent UAC value has an original value name'
            }
            $seenAncestors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($ancestorPathValue in @($backup.AbsentAncestorKeys)) {
                $ancestorPath = ([string]$ancestorPathValue).TrimEnd('\')
                if ([string]::IsNullOrWhiteSpace($ancestorPath) -or
                    -not $seenAncestors.Add($ancestorPath) -or
                    $ancestorPath -notmatch '(?i)^HKLM:\\SOFTWARE\\' -or
                    -not $expectedPath.StartsWith("$ancestorPath\", [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Invalid or duplicate UAC absent ancestor: $ancestorPath"
                }
            }
            $absentAncestorKeys = @($seenAncestors)
        }

        if ([bool]$backup.KeyExisted -and -not (Test-NoIDRegistryKey -LiteralPath $expectedPath)) {
            New-NoIDRegistryKey -LiteralPath $expectedPath | Out-Null
        }

        if ([bool]$backup.Exists) {
            $currentNames = @((Get-Item -LiteralPath $expectedPath -ErrorAction Stop).GetValueNames())
            if ($currentNames -contains $expectedName) {
                Remove-ItemProperty -LiteralPath $expectedPath -Name $expectedName -Force -ErrorAction Stop
            }
            New-ItemProperty -Path $expectedPath -Name $restoreName -Value ([int]$backup.Value) `
                -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        elseif (Test-NoIDRegistryKey -LiteralPath $expectedPath) {
            $currentNames = @((Get-Item -LiteralPath $expectedPath -ErrorAction Stop).GetValueNames())
            if ($currentNames -contains $expectedName) {
                Remove-ItemProperty -LiteralPath $expectedPath -Name $expectedName -Force -ErrorAction Stop
            }
        }

        # This function restores last of the SecurityBaseline routines that
        # share this key: Computer-RegistryPolicies.json direct values
        # (Restore-RegistryPolicies) and SecurityTemplates.json-derived values
        # (Restore-SecurityTemplateRegistryState). A sibling value still present
        # here means that sibling already reported its own error. An originally
        # absent key (and ancestor) is removed when empty; one that now holds
        # data NoID Privacy does not own is kept and reported instead of
        # destroying that data.
        $siblingOwnedUacPolicyValues = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($siblingName in @(
                'MSAOptional', 'DisableAutomaticRestartSignOn', 'LocalAccountTokenFilterPolicy',
                'EnableMPR', 'EnableInstallerDetection', 'EnableSecureUIAPaths',
                'TypeOfAdminApprovalMode', 'ConsentPromptBehaviorEnhancedAdmin', 'EnableLUA',
                'EnableVirtualization', 'FilterAdministratorToken', 'ConsentPromptBehaviorAdmin',
                'InactivityTimeoutSecs'
            )) { $null = $siblingOwnedUacPolicyValues.Add($siblingName) }
        $retainedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cleanupPaths = @()
        if (-not [bool]$backup.KeyExisted) { $cleanupPaths += $expectedPath }
        $cleanupPaths += @($absentAncestorKeys | Sort-Object { $_.Length } -Descending)
        foreach ($cleanupPath in $cleanupPaths) {
            if (-not (Test-NoIDRegistryKey -LiteralPath $cleanupPath)) { continue }
            $cleanupKey = Get-Item -LiteralPath $cleanupPath -ErrorAction Stop
            $remainingValues = @($cleanupKey.GetValueNames())
            if ($remainingValues.Count -ne 0 -or $cleanupKey.SubKeyCount -ne 0) {
                $foreignSubKeys = @($cleanupKey.GetSubKeyNames() | Where-Object {
                        -not $retainedKeys.Contains("$cleanupPath\$_")
                    })
                $foreignValues = @($remainingValues | Where-Object {
                        -not ($cleanupPath -eq $expectedPath -and $siblingOwnedUacPolicyValues.Contains([string]$_))
                    })
                $null = $retainedKeys.Add($cleanupPath)
                $result.RetainedKeys += $cleanupPath
                if ($foreignValues.Count -gt 0 -or $foreignSubKeys.Count -gt 0) {
                    $result.Warnings += (Format-NoIDRetainedKeyNotice -Path $cleanupPath `
                            -Values ([string[]]$foreignValues) -SubKeys ([string[]]$foreignSubKeys))
                }
                continue
            }
            Remove-Item -LiteralPath $cleanupPath -Force -ErrorAction Stop
        }

        $keyExists = Test-NoIDRegistryKey -LiteralPath $expectedPath
        if ($keyExists -ne [bool]$backup.KeyExisted -and -not $retainedKeys.Contains($expectedPath)) {
            throw 'UAC key-existence verification failed'
        }
        $valueExists = $false
        $actualValue = $null
        $actualType = $null
        if ($keyExists) {
            $key = Get-Item -LiteralPath $expectedPath -ErrorAction Stop
            $matchingNames = @($key.GetValueNames() | Where-Object {
                    ([string]$_).Equals($restoreName, [StringComparison]::OrdinalIgnoreCase)
                })
            $valueExists = $matchingNames.Count -eq 1
            if ($valueExists) {
                if ($schemaVersion -eq 3 -and [string]$matchingNames[0] -cne $restoreName) {
                    throw 'UAC value-name casing verification failed'
                }
                $actualValue = $key.GetValue([string]$matchingNames[0])
                $actualType = $key.GetValueKind([string]$matchingNames[0]).ToString()
            }
        }
        if ($valueExists -ne [bool]$backup.Exists -or
            ($valueExists -and ($actualType -ne 'DWord' -or [int]$actualValue -ne [int]$backup.Value))) {
            throw 'UAC value/type verification failed'
        }
        foreach ($ancestorPath in $absentAncestorKeys) {
            if ((Test-NoIDRegistryKey -LiteralPath $ancestorPath) -and -not $retainedKeys.Contains($ancestorPath)) {
                throw "UAC absent ancestor remains after restore: $ancestorPath"
            }
        }
        $result.Success = $true
    }
    catch {
        $result.Errors += "ConsentPromptBehaviorUser restore failed: $($_.Exception.Message)"
    }
    return $result
}
