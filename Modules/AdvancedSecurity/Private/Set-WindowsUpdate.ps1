function Set-WindowsUpdate {
    <#
    .SYNOPSIS
        Configures Windows Update using simple GUI-equivalent settings

    .DESCRIPTION
        Configures three documented policy values and one Windows Settings UX
        preference for three user-facing outcomes:
        1. Keep optional non-security updates user-selected (policy enabled,
           choice 3)
        2. Keep the early continuous-innovation rollout off unless a stamped
           manual Windows Settings opt-in is already active (UX preference)
        3. Disable Delivery Optimization peer-to-peer caching (HTTP-only policy)

        NO forced schedules and NO auto-reboot policies are configured.
        Regular security updates remain enabled. The existing Microsoft-product
        update preference is preserved because changing update-source enrollment can
        trigger downstream installations that a configuration restore cannot uninstall.
        Where policies are used, Windows indicates that the setting is managed.

    .PARAMETER DryRun
        Preview changes without applying them

    .PARAMETER ManagedPoliciesSupported
        Whether the current edition supports the managed policy CSP values.
        Windows Home applies only the documented continuous-innovation UX preference.

    .EXAMPLE
        Set-WindowsUpdate

    .NOTES
        Author: NexusOne23
        Version: 2.2.6
        Requires: Administrator privileges
        Based on: Windows Settings > Windows Update > Advanced options
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [bool]$ManagedPoliciesSupported = $true,

        [object]$Configuration
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set WindowsUpdate')) {
        return
    }


    try {
        $config = Get-AdvancedSecurityConfig -Name WindowsUpdate -Configuration $Configuration

        Write-Log -Level INFO -Message "Configuring documented Windows Update policy/preferences..." -Module "AdvancedSecurity"

        # Windows stores a manual click on the Settings toggle "Get the latest
        # updates as soon as they're available" as a stamped opt-in intent
        # (CIOptinModified) and the Update Session Orchestrator re-commits that
        # intent over IsContinuousInnovationOptedIn at boot and on Settings/USO
        # activity. On such a device the hardened 0 cannot stick until the user
        # turns the toggle off in Settings itself, so that case is detected and
        # reported honestly instead of silently losing the write.
        $ciUserOptedIn = $false
        $ciOptInStamp = $null
        try {
            $uxSettingsPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            if (Test-Path -LiteralPath $uxSettingsPath -ErrorAction Stop) {
                $uxSettingsKey = Get-Item -LiteralPath $uxSettingsPath -ErrorAction Stop
                if ($uxSettingsKey.GetValueNames() -contains 'CIOptinModified' -and
                    [int]$uxSettingsKey.GetValue('IsContinuousInnovationOptedIn', 0) -eq 1) {
                    $ciUserOptedIn = $true
                    # The stamp is display-only; an unexpected Windows format must
                    # not turn a detected user choice into an Apply failure.
                    try {
                        $ciOptInStamp = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$uxSettingsKey.GetValue('CIOptinModified')).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
                    }
                    catch { $ciOptInStamp = $null }
                }
            }
        }
        catch {
            throw "Continuous-innovation opt-in intent could not be inspected; refusing to overwrite the Windows-owned choice: $($_.Exception.Message)"
        }
        if ($ciUserOptedIn) {
            Write-Log -Level INFO -Message "Continuous-innovation opt-in intent detected (Settings toggle was turned on manually$(if ($ciOptInStamp) { ", stamped $ciOptInStamp" })): preserving the authoritative Windows Settings choice as NotChecked; turn OFF 'Get the latest updates as soon as they're available' under Settings > Windows Update to select the hardened state" -Module 'AdvancedSecurity'
        }

        $applicableSettings = @($config.Settings.PSObject.Properties | Where-Object {
                -not [bool]$_.Value.RequiresManagedPolicyEdition -or $ManagedPoliciesSupported
            })
        $applicableValueCount = @($applicableSettings | ForEach-Object { $_.Value.Values.PSObject.Properties }).Count
        if ($applicableValueCount -notin @(1, 4)) {
            throw "Windows Update applicable target count is invalid: $applicableValueCount"
        }

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure $applicableValueCount documented Windows Update registry values" -Module "AdvancedSecurity"
            return $true
        }

        $settingsApplied = 0
        $settingsNotChecked = 0

        foreach ($settingProperty in $applicableSettings) {
            $setting = $settingProperty.Value
            $regPath = $setting.RegistryPath

            # The targeted registry pre-state was sealed before Apply.
            if (-not (Test-Path $regPath)) {
                Write-Log -Level DEBUG -Message "Creating registry path: $regPath" -Module "AdvancedSecurity"
                New-NoIDRegistryKey -LiteralPath $regPath | Out-Null
            }

            # Apply each value in this setting
            foreach ($valueName in $setting.Values.PSObject.Properties.Name) {
                $valueData = $setting.Values.$valueName

                # This raw UX value is not an administrative policy. When the
                # Windows-owned intent stamp and value prove that the user
                # enabled the Settings toggle, USO re-commits 1 over a direct
                # registry write. Preserve that authoritative user choice and
                # report it as NotChecked instead of performing a transient,
                # misleading write that cannot remain in force.
                if ($ciUserOptedIn -and $valueName -ceq 'IsContinuousInnovationOptedIn') {
                    Write-Log -Level INFO -Message "NotChecked: preserved stored manual Windows Update early-rollout opt-in; no registry write was attempted for $valueName" -Module 'AdvancedSecurity'
                    $settingsNotChecked++
                    continue
                }

                # Always use New-ItemProperty with -Force to ensure correct type and value
                # -Force will overwrite existing keys
                Remove-ItemProperty -LiteralPath $regPath -Name $valueName -ErrorAction SilentlyContinue
                New-ItemProperty -Path $regPath -Name $valueName -Value ([int]$valueData.Value) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                $updateKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                if ($updateKey.GetValueKind($valueName).ToString() -ne 'DWord' -or
                    [int]$updateKey.GetValue($valueName) -ne [int]$valueData.Value) {
                    throw "Windows Update registry post-apply mismatch: $regPath\$valueName"
                }

                Write-Log -Level SUCCESS -Message "$($setting.Name): $valueName = $($valueData.Value)" -Module "AdvancedSecurity"
                $settingsApplied++
            }
        }

        Write-Log -Level SUCCESS -Message "Windows Update configured: $settingsApplied registry value(s) set; $settingsNotChecked user-owned value(s) NotChecked" -Module "AdvancedSecurity"

        Write-Log -Level INFO -Message 'Windows Update service was not restarted; policy refresh remains Windows-managed and no unbacked runtime service state is changed' -Module 'AdvancedSecurity'

        Write-NoIDDetail ""
        Write-NoIDDetail "===================================================================" -ForegroundColor Green
        Write-NoIDDetail "  Windows Update Configured ($settingsApplied Applied, $settingsNotChecked NotChecked)" -ForegroundColor Green
        Write-NoIDDetail "===================================================================" -ForegroundColor Green
        Write-NoIDDetail ""
        if ($ManagedPoliciesSupported) {
            Write-NoIDDetail "[Policy] Optional updates + CFRs:     USER SELECTS" -ForegroundColor Gray
        }
        else {
            Write-NoIDDetail "[N/A] Optional-updates policy:        Edition does not support this policy CSP" -ForegroundColor Gray
        }
        if ($ciUserOptedIn) {
            Write-NoIDDetail "[Choice] Early non-security rollout:  USER OPT-IN PRESERVED (NotChecked)" -ForegroundColor Cyan
        }
        else {
            Write-NoIDDetail "[UX] Early non-security rollout:      OFF" -ForegroundColor Gray
        }
        Write-NoIDDetail "[Kept] Microsoft product updates:     unchanged" -ForegroundColor Gray
        if ($ManagedPoliciesSupported) {
            Write-NoIDDetail "[Policy] P2P Delivery Optimization:   OFF / HTTP-only" -ForegroundColor Gray
        }
        else {
            Write-NoIDDetail "[N/A] Delivery Optimization policy:   Edition does not support this policy CSP" -ForegroundColor Gray
        }
        Write-NoIDDetail ""
        Write-NoIDDetail "Regular security updates remain enabled; optional non-security updates stay user-selected." -ForegroundColor White
        Write-NoIDDetail "No forced schedules, deadlines, or auto-reboot policies are configured." -ForegroundColor White
        Write-NoIDDetail "Windows will indicate where settings are managed by policy in the GUI." -ForegroundColor White
        Write-NoIDDetail ""
        if ($ciUserOptedIn) {
            Write-Log -Level INFO -Message "Note: You turned on 'Get the latest updates as soon as they're available' in Windows Settings$(if ($ciOptInStamp) { " ($ciOptInStamp)" }); NoID Privacy keeps your choice. To use the hardened setting, turn it off under Settings > Windows Update; until then Verify lists it as by choice." -Module 'AdvancedSecurity'
        }

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure Windows Update: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
