function Test-WindowsUpdate {
    <#
    .SYNOPSIS
        Verifies the edition-applicable documented Windows Update registry values

    .DESCRIPTION
        Tests the early-rollout UX preference on every supported edition and
        additionally tests the user-selected optional-content and HTTP-only
        Delivery Optimization policies on Pro, Enterprise, Education and IoT
        Enterprise. The Microsoft-product update preference is intentionally
        outside the owned target set and remains untouched.

    .EXAMPLE
        Test-WindowsUpdate

    .OUTPUTS
        PSCustomObject with compliance results
    #>

    [CmdletBinding()]
    param(
        [bool]$ManagedPoliciesSupported = $true
    )

    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\WindowsUpdate.json"

        if (-not (Test-Path $configPath)) {
            return [PSCustomObject]@{
                Feature = "Windows Update"
                Status = "Not Configured"
                Compliant = $false
                Details = "WindowsUpdate.json not found"
            }
        }

        $config = Get-Content $configPath -Raw | ConvertFrom-Json

        $settingsConfigured = 0
        $settingsNotChecked = 0
        $settingsTotal = 0
        $details = @()

        # Check every canonical setting/value from config.
        foreach ($settingProperty in $config.Settings.PSObject.Properties) {
            $setting = $settingProperty.Value
            if ([bool]$setting.RequiresManagedPolicyEdition -and -not $ManagedPoliciesSupported) {
                $details += "$($setting.Name): NOT APPLICABLE on this edition"
                continue
            }
            $regPath = $setting.RegistryPath

            foreach ($valueName in $setting.Values.PSObject.Properties.Name) {
                $valueData = $setting.Values.$valueName
                $settingsTotal++

                if (Test-Path $regPath) {
                    $registryKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                    $valueExists = $registryKey.GetValueNames() -contains [string]$valueName
                    $actualValue = if ($valueExists) { $registryKey.GetValue([string]$valueName) } else { $null }

                    if ($valueExists -and $registryKey.GetValueKind([string]$valueName).ToString() -eq 'DWord' -and
                        [int]$actualValue -eq [int]$valueData.Value) {
                        $settingsConfigured++
                        $details += "$($setting.Name): OK"
                    }
                    elseif ($valueName -ceq 'IsContinuousInnovationOptedIn' -and
                        $valueExists -and $registryKey.GetValueKind([string]$valueName).ToString() -eq 'DWord' -and
                        [int]$actualValue -eq 1 -and
                        $registryKey.GetValueNames() -contains 'CIOptinModified') {
                        $settingsNotChecked++
                        $details += "$($setting.Name): NOT CHECKED (stored manual Windows Settings opt-in preserved; turn the toggle off in Settings to select the hardened state)"
                        Write-Log -Level INFO -Message "Windows Update user choice NotChecked: stored manual continuous-innovation opt-in is active" -Module 'AdvancedSecurity'
                    }
                    else {
                        $details += "$($setting.Name): NOT SET"
                        Write-Log -Level WARNING -Message "Windows Update Check Failed: $($setting.Name)" -Module "AdvancedSecurity"
                        if (-not $valueExists) {
                            Write-Log -Level WARNING -Message "  - Value '$valueName' not found in $regPath" -Module "AdvancedSecurity"
                        } else {
                            Write-Log -Level WARNING -Message "  - Value '$valueName' type/value mismatch. Expected: DWord/$($valueData.Value), Actual: $($registryKey.GetValueKind([string]$valueName))/$actualValue" -Module "AdvancedSecurity"
                        }
                    }
                }
                else {
                    $details += "$($setting.Name): NOT SET (reg path missing)"
                    Write-Log -Level WARNING -Message "Windows Update Check Failed: $($setting.Name)" -Module "AdvancedSecurity"
                    Write-Log -Level WARNING -Message "  - Registry Path Missing: $regPath" -Module "AdvancedSecurity"
                }
            }
        }

        if ($settingsTotal -eq 0) {
            # Fail closed: a scope where no value was applicable must never
            # report a vacuous 0/0 success.
            return [PSCustomObject]@{
                Feature = "Windows Update"
                Status = "NotApplicable"
                Compliant = $false
                Details = "No applicable Windows Update values in scope. $(if ($details) { $details -join ', ' })"
            }
        }
        $settingsFailed = $settingsTotal - $settingsConfigured - $settingsNotChecked
        if ($settingsFailed -lt 0) {
            throw 'Windows Update verification accounting is invalid'
        }
        $allNotChecked = ($settingsConfigured -eq 0 -and $settingsNotChecked -gt 0 -and $settingsFailed -eq 0)
        $compliant = if ($allNotChecked) { $null } else { $settingsFailed -eq 0 }

        return [PSCustomObject]@{
            Feature = "Windows Update"
            Status = if ($settingsFailed -gt 0) { "Incomplete" }
                elseif ($allNotChecked) { "NotChecked" }
                elseif ($settingsNotChecked -gt 0) { "Configured ($settingsNotChecked user choice NotChecked)" }
                else { "Configured" }
            Compliant = $compliant
            CheckState = if ($allNotChecked) { 'NotChecked' } else { $null }
            ConfiguredCount = $settingsConfigured
            NotCheckedCount = $settingsNotChecked
            FailedCount = $settingsFailed
            TotalCount = $settingsTotal
            Details = "$settingsConfigured verified, $settingsNotChecked not checked, $settingsFailed failed of $settingsTotal. $(if ($details) { $details -join ', ' })"
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature = "Windows Update"
            Status = "Error"
            Compliant = $false
            Details = "Test failed: $_"
        }
    }
}
