<#
.SYNOPSIS
    Apply registry policies from parsed Security Baseline JSON

.DESCRIPTION
    Native PowerShell registry application without LGPO.exe dependency.
    Applies Computer (HKLM) and User (HKCU) registry settings from JSON configs.

    Supports all registry types:
    - REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_MULTI_SZ

.PARAMETER ComputerPoliciesPath
    Path to Computer-RegistryPolicies.json

.PARAMETER UserPoliciesPath
    Path to User-RegistryPolicies.json

.PARAMETER DryRun
    Preview changes without applying

.OUTPUTS
    PSCustomObject with applied count and errors

.NOTES
    This replaces LGPO.exe for registry policy application
    Uses native PowerShell New-Item/Set-ItemProperty
#>

function Set-RegistryPolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerPoliciesPath,

        [Parameter(Mandatory = $false)]
        [string]$UserPoliciesPath,

        [Parameter(Mandatory = $true)]
        [string]$UserRegistryRoot,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set RegistryPolicies')) {
        return
    }


    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
        Details = @{
            Computer = 0
            User = 0
        }
    }
    $expectedDirectives = 0

    try {
        if ($UserRegistryRoot -notmatch '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+$' -or
            -not (Test-Path -LiteralPath $UserRegistryRoot -PathType Container)) {
            throw "Interactive user registry root is invalid or not loaded: $UserRegistryRoot"
        }
        # Apply Computer policies (HKLM)
        if ($ComputerPoliciesPath) {
            if (-not (Test-Path -LiteralPath $ComputerPoliciesPath -PathType Leaf)) {
                throw "Computer registry-policy file not found: $ComputerPoliciesPath"
            }
            Write-Log -Level DEBUG -Message "Applying Computer registry policies..." -Module "SecurityBaseline"

            $computerPolicies = Get-Content -LiteralPath $ComputerPoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ($computerPolicies.Count -eq 0) { throw 'Computer registry-policy file contains no directives' }
            $expectedDirectives += $computerPolicies.Count

            foreach ($policy in $computerPolicies) {
                try {
                    # Parse key path: [SOFTWARE\... -> HKLM:\SOFTWARE\...
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''

                    # Determine registry root
                    if ($keyPath -match '^(SOFTWARE|SYSTEM)\\') {
                        $fullPath = "HKLM:\$keyPath"
                    }
                    else {
                        throw "Unsupported Computer registry root: $keyPath"
                    }

                    # GPO PReg delete-directives: '**del.<ValueName>' = delete that value;
                    # '**delvals.' = clear ALL values under the key. secedit/LGPO interpret these
                    # as DELETIONS -- the native apply must NOT create a literal value named
                    # "**del.X" (that would be junk + miss the intended deletion). Mirrors the
                    # Restore-RegistryPolicies + Set-EdgePolicies handling of the same markers.
                    if ($policy.ValueName -match '^\*\*del') {
                        if ($DryRun) {
                            Write-Log -Level DEBUG -Message "[DRYRUN] Would process delete-directive '$($policy.ValueName)' @ $fullPath" -Module "SecurityBaseline"
                        }
                        elseif (Test-Path $fullPath) {
                            $existingNames = @((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames())
                            if ($policy.ValueName -eq '**delvals.') {
                                foreach ($vn in $existingNames) {
                                    Remove-ItemProperty -LiteralPath $fullPath -Name ([string]$vn) -Force -ErrorAction Stop
                                }
                                if (@((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames()).Count -ne 0) {
                                    throw "**delvals. verification failed for $fullPath"
                                }
                            }
                            else {
                                $targetValue = $policy.ValueName -replace '^\*\*del\.', ''
                                if ($existingNames -contains $targetValue) {
                                    Remove-ItemProperty -LiteralPath $fullPath -Name $targetValue -Force -ErrorAction Stop
                                }
                                if (@((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames()) -contains $targetValue) {
                                    throw "Delete-directive verification failed for $fullPath\$targetValue"
                                }
                            }
                        }
                        $result.Applied++
                        $result.Details.Computer++
                        continue
                    }

                    if ($DryRun) {
                        Write-Log -Level DEBUG -Message "[DRYRUN] Would set: $fullPath\$($policy.ValueName) = $($policy.Data)" -Module "SecurityBaseline"
                        $result.Applied++
                        $result.Details.Computer++
                        continue
                    }

                    # Exact key/value prestate was sealed before Apply.
                    if (-not (Test-Path $fullPath)) {
                        New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                    }

                    # Convert registry type
                    $regType = switch ($policy.Type) {
                        "REG_DWORD" { "DWord" }
                        "REG_QWORD" { "QWord" }
                        "REG_SZ" { "String" }
                        "REG_EXPAND_SZ" { "ExpandString" }
                        "REG_BINARY" { "Binary" }
                        "REG_MULTI_SZ" { "MultiString" }
                        default {
                            throw "Unsupported registry type: $($policy.Type) for $($policy.ValueName)"
                        }
                    }

                    # Apply setting (create or update with correct type)
                    $currentNames = @((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains [string]$policy.ValueName) {
                        Remove-ItemProperty -LiteralPath $fullPath -Name ([string]$policy.ValueName) -Force -ErrorAction Stop
                    }
                    New-ItemProperty -Path $fullPath `
                                     -Name $policy.ValueName `
                                     -Value $policy.Data `
                                     -PropertyType $regType `
                                     -Force `
                                     -ErrorAction Stop | Out-Null
                    $appliedKey = Get-Item -LiteralPath $fullPath -ErrorAction Stop
                    if ($appliedKey.GetValueKind([string]$policy.ValueName).ToString() -ne $regType) {
                        throw "Registry type verification failed for $fullPath\$($policy.ValueName)"
                    }
                    $expectedJson = ConvertTo-Json -InputObject $policy.Data -Compress -Depth 10
                    $actualJson = ConvertTo-Json -InputObject $appliedKey.GetValue([string]$policy.ValueName) -Compress -Depth 10
                    if ($actualJson -cne $expectedJson) {
                        throw "Registry value verification failed for $fullPath\$($policy.ValueName)"
                    }

                    $result.Applied++
                    $result.Details.Computer++

                }
                catch {
                    $result.Errors += "Failed to set $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)"
                    Write-Log -Level DEBUG -Message "Failed to set $($policy.KeyName)\$($policy.ValueName): $_" -Module "SecurityBaseline"
                }
            }

            Write-Log -Level DEBUG -Message "Applied $($result.Details.Computer) Computer registry policies" -Module "SecurityBaseline"
        }

        # Apply User policies (HKCU)
        if ($UserPoliciesPath) {
            if (-not (Test-Path -LiteralPath $UserPoliciesPath -PathType Leaf)) {
                throw "User registry-policy file not found: $UserPoliciesPath"
            }
            Write-Log -Level DEBUG -Message "Applying User registry policies..." -Module "SecurityBaseline"

            $userPolicies = Get-Content -LiteralPath $UserPoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ($userPolicies.Count -eq 0) { throw 'User registry-policy file contains no directives' }
            $expectedDirectives += $userPolicies.Count

            foreach ($policy in $userPolicies) {
                try {
                    # Parse key path
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''

                    # Bind user policies to the interactive desktop account.
                    if ($keyPath -match '^SOFTWARE\\') {
                        $fullPath = "$UserRegistryRoot\$keyPath"
                    }
                    else {
                        throw "Unsupported User registry root: $keyPath"
                    }

                    # GPO PReg delete-directives (see Computer loop above for rationale):
                    # '**del.<ValueName>' deletes that value; '**delvals.' clears all values.
                    if ($policy.ValueName -match '^\*\*del') {
                        if ($DryRun) {
                            Write-Log -Level DEBUG -Message "[DRYRUN] Would process delete-directive '$($policy.ValueName)' @ $fullPath" -Module "SecurityBaseline"
                        }
                        elseif (Test-Path $fullPath) {
                            $existingNames = @((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames())
                            if ($policy.ValueName -eq '**delvals.') {
                                foreach ($vn in $existingNames) {
                                    Remove-ItemProperty -LiteralPath $fullPath -Name ([string]$vn) -Force -ErrorAction Stop
                                }
                                if (@((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames()).Count -ne 0) {
                                    throw "**delvals. verification failed for $fullPath"
                                }
                            }
                            else {
                                $targetValue = $policy.ValueName -replace '^\*\*del\.', ''
                                if ($existingNames -contains $targetValue) {
                                    Remove-ItemProperty -LiteralPath $fullPath -Name $targetValue -Force -ErrorAction Stop
                                }
                                if (@((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames()) -contains $targetValue) {
                                    throw "Delete-directive verification failed for $fullPath\$targetValue"
                                }
                            }
                        }
                        $result.Applied++
                        $result.Details.User++
                        continue
                    }

                    if ($DryRun) {
                        Write-Log -Level DEBUG -Message "[DRYRUN] Would set: $fullPath\$($policy.ValueName) = $($policy.Data)" -Module "SecurityBaseline"
                        $result.Applied++
                        $result.Details.User++
                        continue
                    }

                    # Exact key/value prestate was sealed before Apply.
                    if (-not (Test-Path $fullPath)) {
                        New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                    }

                    # Convert registry type
                    $regType = switch ($policy.Type) {
                        "REG_DWORD" { "DWord" }
                        "REG_QWORD" { "QWord" }
                        "REG_SZ" { "String" }
                        "REG_EXPAND_SZ" { "ExpandString" }
                        "REG_BINARY" { "Binary" }
                        "REG_MULTI_SZ" { "MultiString" }
                        default { throw "Unsupported registry type: $($policy.Type) for $($policy.ValueName)" }
                    }

                    # Apply setting (create or update with correct type)
                    $currentNames = @((Get-Item -LiteralPath $fullPath -ErrorAction Stop).GetValueNames())
                    if ($currentNames -contains [string]$policy.ValueName) {
                        Remove-ItemProperty -LiteralPath $fullPath -Name ([string]$policy.ValueName) -Force -ErrorAction Stop
                    }
                    New-ItemProperty -Path $fullPath `
                                     -Name $policy.ValueName `
                                     -Value $policy.Data `
                                     -PropertyType $regType `
                                     -Force `
                                     -ErrorAction Stop | Out-Null
                    $appliedKey = Get-Item -LiteralPath $fullPath -ErrorAction Stop
                    if ($appliedKey.GetValueKind([string]$policy.ValueName).ToString() -ne $regType) {
                        throw "Registry type verification failed for $fullPath\$($policy.ValueName)"
                    }
                    $expectedJson = ConvertTo-Json -InputObject $policy.Data -Compress -Depth 10
                    $actualJson = ConvertTo-Json -InputObject $appliedKey.GetValue([string]$policy.ValueName) -Compress -Depth 10
                    if ($actualJson -cne $expectedJson) {
                        throw "Registry value verification failed for $fullPath\$($policy.ValueName)"
                    }

                    $result.Applied++
                    $result.Details.User++

                }
                catch {
                    $result.Errors += "Failed to set User $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)"
                    Write-Log -Level DEBUG -Message "Failed to set User $($policy.KeyName)\$($policy.ValueName): $_" -Module "SecurityBaseline"
                }
            }

            Write-Log -Level DEBUG -Message "Applied $($result.Details.User) User registry policies" -Module "SecurityBaseline"
        }

    }
    catch {
        $result.Errors += "Registry policy application failed: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Registry policy application failed: $_" -Module "SecurityBaseline"
    }

    $result.Success = ($result.Errors.Count -eq 0 -and
        $expectedDirectives -gt 0 -and
        $result.Applied -eq $expectedDirectives)
    if (-not $result.Success -and $result.Errors.Count -eq 0) {
        $result.Errors += "Registry policy completeness mismatch: expected $expectedDirectives directives, applied $($result.Applied)"
    }
    return $result
}
