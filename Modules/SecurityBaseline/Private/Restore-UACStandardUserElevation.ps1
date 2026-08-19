function Restore-UACStandardUserElevation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{ Success = $false; Errors = @() }
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

        if (-not [bool]$backup.KeyExisted -and (Test-Path -LiteralPath $expectedPath -PathType Container)) {
            # Sibling SecurityBaseline restore routines share this key; their
            # owned values are not unowned state (each sibling removes its own
            # values in this session). This function restores last in Rollback
            # order and still enforces final key absence in the verification
            # below. Owners: Computer-RegistryPolicies.json direct values
            # (Restore-RegistryPolicies) + SecurityTemplates.json-derived values
            # (Restore-SecurityTemplateRegistryState).
            $siblingOwnedUacPolicyValues = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($siblingName in @(
                    'MSAOptional', 'DisableAutomaticRestartSignOn', 'LocalAccountTokenFilterPolicy',
                    'EnableMPR', 'EnableInstallerDetection', 'EnableSecureUIAPaths',
                    'TypeOfAdminApprovalMode', 'ConsentPromptBehaviorEnhancedAdmin', 'EnableLUA',
                    'EnableVirtualization', 'FilterAdministratorToken', 'ConsentPromptBehaviorAdmin',
                    'InactivityTimeoutSecs'
                )) { $null = $siblingOwnedUacPolicyValues.Add($siblingName) }
            $key = Get-Item -LiteralPath $expectedPath -ErrorAction Stop
            $unownedValues = @($key.GetValueNames() | Where-Object {
                    [string]$_ -ne $expectedName -and
                    -not $siblingOwnedUacPolicyValues.Contains([string]$_)
                })
            if ($unownedValues.Count -gt 0 -or $key.SubKeyCount -gt 0) {
                throw 'Originally absent UAC key contains unowned state; refusing destructive restore'
            }
        }
        if ([bool]$backup.KeyExisted -and -not (Test-Path -LiteralPath $expectedPath -PathType Container)) {
            New-Item -Path $expectedPath -Force -ErrorAction Stop | Out-Null
        }

        if ([bool]$backup.Exists) {
            $currentNames = @((Get-Item -LiteralPath $expectedPath -ErrorAction Stop).GetValueNames())
            if ($currentNames -contains $expectedName) {
                Remove-ItemProperty -LiteralPath $expectedPath -Name $expectedName -Force -ErrorAction Stop
            }
            New-ItemProperty -Path $expectedPath -Name $restoreName -Value ([int]$backup.Value) `
                -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        elseif (Test-Path -LiteralPath $expectedPath -PathType Container) {
            $currentNames = @((Get-Item -LiteralPath $expectedPath -ErrorAction Stop).GetValueNames())
            if ($currentNames -contains $expectedName) {
                Remove-ItemProperty -LiteralPath $expectedPath -Name $expectedName -Force -ErrorAction Stop
            }
        }

        if (-not [bool]$backup.KeyExisted -and (Test-Path -LiteralPath $expectedPath -PathType Container)) {
            $key = Get-Item -LiteralPath $expectedPath -ErrorAction Stop
            if (@($key.GetValueNames()).Count -eq 0 -and $key.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $expectedPath -Force -ErrorAction Stop
            }
        }
        foreach ($ancestorPath in @($absentAncestorKeys | Sort-Object { $_.Length } -Descending)) {
            if (-not (Test-Path -LiteralPath $ancestorPath -PathType Container)) { continue }
            $ancestorKey = Get-Item -LiteralPath $ancestorPath -ErrorAction Stop
            if (@($ancestorKey.GetValueNames()).Count -ne 0 -or $ancestorKey.SubKeyCount -ne 0) {
                throw "Originally absent UAC ancestor contains state after restore: $ancestorPath"
            }
            Remove-Item -LiteralPath $ancestorPath -Force -ErrorAction Stop
        }

        $keyExists = Test-Path -LiteralPath $expectedPath -PathType Container
        if ($keyExists -ne [bool]$backup.KeyExisted) {
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
            if (Test-Path -LiteralPath $ancestorPath -PathType Container) {
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
