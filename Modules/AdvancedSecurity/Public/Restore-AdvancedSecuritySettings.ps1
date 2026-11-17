function Restore-AdvancedSecuritySettings {
    <#
    .SYNOPSIS
        Restore Advanced Security settings from backup

    .DESCRIPTION
        Restores the explicitly declared Advanced Security artifacts that are
        not handled by Core registry/service restore logic.

    .PARAMETER BackupFilePath
        Path to the JSON backup file

    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath,

        [Parameter(Mandatory = $true)]
        [ValidateSet('AdvancedSecurity_FirewallPolicy', 'PowerShellV2', 'WiFiDirect_Adapters', 'NetBIOS_Adapters')]
        [string]$ArtifactName
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore AdvancedSecuritySettings')) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $BackupFilePath -PathType Leaf)) {
        Write-Log -Level ERROR -Message "Backup file not found: $BackupFilePath" -Module "AdvancedSecurity"
        return $false
    }

    try {
        $filename = Split-Path $BackupFilePath -Leaf
        Write-Log -Level DEBUG -Message "Processing Advanced Security backup: $filename" -Module "AdvancedSecurity"

        if ($ArtifactName -eq 'AdvancedSecurity_FirewallPolicy') {
            if ([System.IO.Path]::GetExtension($BackupFilePath) -ine '.wfw') {
                throw "Firewall policy artifact does not use the expected .wfw format: $filename"
            }
            return [bool](Restore-FirewallPolicy -BackupFilePath $BackupFilePath -Confirm:$false)
        }

        if ([System.IO.Path]::GetExtension($BackupFilePath) -ine '.json') {
            throw "AdvancedSecurity JSON artifact does not use the expected .json format: $filename"
        }
        # Backup artifacts are UTF-8 without BOM; Windows PowerShell 5.1 would
        # otherwise decode them with the ANSI code page.
        $backupData = Get-Content -LiteralPath $BackupFilePath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop

        switch ($ArtifactName) {
            'PowerShellV2'        { return [bool](Restore-PowerShellV2 -BackupData $backupData) }
            'NetBIOS_Adapters'    { return [bool](Restore-NetBIOSAdapters -BackupData $backupData) }
            'WiFiDirect_Adapters' { return [bool](Restore-WiFiDirectAdapters -BackupData $backupData) }
            default { throw "Unsupported AdvancedSecurity artifact identity: $ArtifactName" }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore Advanced Security settings: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}

function Restore-FirewallPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath,

        # Absent in 2.2.5 schema-5 prestates, which predate NoID GPO mirrors.
        [bool]$SealedEditorRegistration
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Import complete pre-hardening firewall policy')) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $BackupFilePath -PathType Leaf)) {
        Write-Log -Level ERROR -Message "Firewall policy backup not found: $BackupFilePath" -Module 'AdvancedSecurity'
        return $false
    }

    $verificationExport = Join-Path $env:TEMP "NoID_FirewallVerify_$([Guid]::NewGuid().ToString('N')).wfw"
    try {
        foreach ($dependency in @(
                @{ Command='Get-AdvancedSecurityFirewallPolicyState'; File='AdvancedSecurityFirewallPolicyState.ps1' },
                @{ Command='Get-AdvancedSecurityFirewallMirrorRestorePlan'; File='AdvancedSecurityFirewallMirrors.ps1' }
            )) {
            if (-not (Get-Command $dependency.Command -ErrorAction SilentlyContinue)) {
                . (Join-Path $PSScriptRoot ('../Private/' + $dependency.File))
            }
        }
        # Validate the future mirror set and GPO ownership before importing the
        # sealed WFW. No additional artifact is required by 2.2.5+ backups.
        $mirrorPlan = Get-AdvancedSecurityFirewallMirrorRestorePlan -PolicyFilePath $BackupFilePath
        $importResidue = @(Get-AdvancedSecurityFirewallImportResidueState)
        $import = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') `
            -ArgumentList @('advfirewall', 'import', "`"$BackupFilePath`"") `
            -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
        if ($import.ExitCode -ne 0) {
            throw "netsh advfirewall import failed with exit code $($import.ExitCode)"
        }

        $synchronize = @{ ExpectedNames=$mirrorPlan.Names; Confirm=$false }
        if ($PSBoundParameters.ContainsKey('SealedEditorRegistration')) {
            $synchronize.SealedEditorRegistration = $SealedEditorRegistration
        }
        if (-not (Sync-AdvancedSecurityFirewallMirrors @synchronize)) {
            throw 'NoID firewall GPO mirror synchronization did not complete'
        }

        $export = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') `
            -ArgumentList @('advfirewall', 'export', "`"$verificationExport`"") `
            -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
        if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationExport -PathType Leaf)) {
            throw "Post-restore firewall export failed with exit code $($export.ExitCode)"
        }
        $null = Assert-AdvancedSecurityFirewallPolicyEquivalent `
            -ReferenceFilePath $BackupFilePath `
            -CandidateFilePath $verificationExport `
            -Context 'Post-restore firewall policy verification' `
            -AllowNativeAuditModeDefault
        Restore-AdvancedSecurityFirewallImportResidue -Expected $importResidue -Confirm:$false
        Write-Log -Level SUCCESS -Message 'Firewall settings restored and verified' -Module 'AdvancedSecurity'
        return $true
    }
    catch {
        # CIM exceptions often expose only provider callback frames. Retain the
        # caller's source location without adding installation paths or values.
        $failureLocation = ''
        if ($null -ne $_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber -gt 0) {
            $failureLocation = ' [' + [IO.Path]::GetFileName($_.InvocationInfo.ScriptName) +
                ':' + $_.InvocationInfo.ScriptLineNumber + ']'
        }
        Write-Log -Level ERROR -Message "Complete firewall policy restore failed${failureLocation}: $_" -Module 'AdvancedSecurity' -Exception $_.Exception
        return $false
    }
    finally {
        Remove-Item -LiteralPath $verificationExport -Force -ErrorAction SilentlyContinue
    }
}

function Get-AdvancedSecurityFirewallImportResidueState {
    # netsh advfirewall import leaves the policy equivalent but adds empty legacy
    # AuthorizedApplications/GloballyOpenPorts keys and rewrites LogFilePath as
    # REG_SZ. Apply never touches these details, so the state just before the
    # import is the one to keep.
    [CmdletBinding()]
    param(
        [string]$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    )

    foreach ($profileName in @('DomainProfile', 'PublicProfile', 'StandardProfile')) {
        $profilePath = Join-Path $Root $profileName
        $legacyKeys = @(@('AuthorizedApplications', 'GloballyOpenPorts') | Where-Object {
                Test-NoIDRegistryKey -LiteralPath (Join-Path $profilePath $_)
            })
        $logKind = $null
        $logData = $null
        $loggingPath = Join-Path $profilePath 'Logging'
        if (Test-NoIDRegistryKey -LiteralPath $loggingPath) {
            $loggingKey = Get-Item -LiteralPath $loggingPath -ErrorAction Stop
            if ($loggingKey.GetValueNames() -contains 'LogFilePath') {
                $logKind = $loggingKey.GetValueKind('LogFilePath').ToString()
                $logData = [string]$loggingKey.GetValue('LogFilePath', $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        [PSCustomObject]@{
            ProfilePath     = $profilePath
            LegacyKeys      = @($legacyKeys)
            LogFilePathKind = $logKind
            LogFilePathData = $logData
        }
    }
}

function Restore-AdvancedSecurityFirewallImportResidue {
    # Removes only empty legacy keys the import created and restores the
    # LogFilePath value kind when the imported path text is unchanged.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Expected
    )

    if (-not $PSCmdlet.ShouldProcess('Windows Firewall local store', 'Remove netsh import residue')) { return }
    foreach ($profileState in @($Expected)) {
        foreach ($name in @('AuthorizedApplications', 'GloballyOpenPorts')) {
            if ($name -in @($profileState.LegacyKeys)) { continue }
            $path = Join-Path ([string]$profileState.ProfilePath) $name
            if (-not (Test-NoIDRegistryKey -LiteralPath $path)) { continue }
            $legacyKey = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($legacyKey.ValueCount -eq 0 -and $legacyKey.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            }
        }
        if ([string]$profileState.LogFilePathKind -ne 'ExpandString') { continue }
        $loggingPath = Join-Path ([string]$profileState.ProfilePath) 'Logging'
        if (-not (Test-NoIDRegistryKey -LiteralPath $loggingPath)) { continue }
        $loggingKey = Get-Item -LiteralPath $loggingPath -ErrorAction Stop
        if ($loggingKey.GetValueNames() -notcontains 'LogFilePath' -or
            $loggingKey.GetValueKind('LogFilePath').ToString() -ne 'String') { continue }
        $currentData = [string]$loggingKey.GetValue('LogFilePath', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($currentData -cne [string]$profileState.LogFilePathData) { continue }
        New-ItemProperty -LiteralPath $loggingPath -Name 'LogFilePath' -PropertyType ExpandString `
            -Value $currentData -Force -ErrorAction Stop | Out-Null
    }
}

function Restore-PowerShellV2 {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param($BackupData)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore PowerShellV2')) {
        return
    }


    Write-Log -Level INFO -Message "Restoring PowerShell v2 state..." -Module "AdvancedSecurity"

    try {
        $shouldEnable = ($BackupData.State -eq "Enabled")

        # Use the same authoritative optional-feature state for backup, restore,
        # and verification; registry remnants do not prove feature enablement.
        $featureName = [string]$BackupData.FeatureName
        if ($featureName -ne 'MicrosoftWindowsPowerShellV2Root') {
            throw "Unexpected PowerShell v2 feature name in backup: $featureName"
        }
        # Microsoft removed PowerShell 2.0 from updated Windows 11 images in
        # August 2025 (DISM then reports the feature name as unknown,
        # 0x800F080C). A removed component has no state left to restore.
        $currentFeature = $null
        try {
            $currentFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
        }
        catch {
            if ([int]$_.Exception.HResult -ne [int]0x800F080C) { throw }
        }
        if ($null -eq $currentFeature) {
            Write-Log -Level WARNING -Message "PowerShell 2.0 is no longer part of this Windows version, so its saved state ($($BackupData.State)) cannot be restored; nothing else depends on it." -Module 'AdvancedSecurity'
            return $true
        }
        $isEnabled = ([string]$currentFeature.State -eq 'Enabled')

        if ($shouldEnable -and -not $isEnabled) {
            Write-Log -Level INFO -Message "Re-enabling PowerShell v2 (via DISM)..." -Module "AdvancedSecurity"
            Enable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop | Out-Null
        }
        elseif (-not $shouldEnable -and $isEnabled) {
            Write-Log -Level INFO -Message "Disabling PowerShell v2 (via DISM)..." -Module "AdvancedSecurity"
            Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop | Out-Null
        }
        else {
            Write-Log -Level INFO -Message "PowerShell v2 state already matches backup ($($BackupData.State))" -Module "AdvancedSecurity"
        }

        $verifiedFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
        $verifiedEnabled = ([string]$verifiedFeature.State -eq 'Enabled')
        if ($verifiedEnabled -ne $shouldEnable) {
            throw "PowerShell v2 feature verification failed: expected enabled=$shouldEnable, got enabled=$verifiedEnabled ($($verifiedFeature.State))"
        }
        Write-Log -Level SUCCESS -Message "PowerShell v2 feature state restored and verified: $($verifiedFeature.State)" -Module 'AdvancedSecurity'
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore PowerShell v2: $_" -Module "AdvancedSecurity"
        return $false
    }
}

function Restore-WiFiDirectAdapters {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param($BackupData)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore Wi-Fi Direct adapter administrative states')) {
        return $false
    }

    try {
        $failedCount = 0
        $backedUpAdapters = @($BackupData.Adapters)
        if ($backedUpAdapters.Count -eq 0) {
            Write-Log -Level SUCCESS -Message 'No Wi-Fi Direct adapters existed in the backup; no adapter restore is required' -Module 'AdvancedSecurity'
            return $true
        }

        $plans = foreach ($backupAdapter in $backedUpAdapters) {
            # The sealed artifact records AdminStatus by name; Rollback
            # validation admits only 'Up' and 'Down'.
            $savedAdminStatus = if ($backupAdapter.PSObject.Properties.Name -contains 'AdminStatus' -and $null -ne $backupAdapter.AdminStatus) {
                switch -CaseSensitive ([string]$backupAdapter.AdminStatus) {
                    'Up' { 'Up'; break }
                    'Down' { 'Down'; break }
                    default { throw "Unsupported sealed Wi-Fi Direct AdminStatus '$($backupAdapter.AdminStatus)' for $($backupAdapter.InterfaceGuid)" }
                }
            }
            elseif ([string]$backupAdapter.Status -ne 'Disabled') { 'Up' }
            else { 'Down' }
            [PSCustomObject]@{
                InterfaceGuid = [string]$backupAdapter.InterfaceGuid
                ShouldBeEnabled = ($savedAdminStatus -ceq 'Up')
                SavedAdminStatus = $savedAdminStatus
                # Windows numbers later Wi-Fi Direct instances "#2", "#3", ...;
                # the role adapters it creates on demand come after the
                # adapter they belong to.
                Order = if ([string]$backupAdapter.InterfaceDescription -match '#(\d+)$') { [int]$Matches[1] } else { 0 }
            }
        }
        $plans = @($plans | Sort-Object Order)

        $restorePresent = {
            param($Plan, $CurrentAdapters)
            $targetMatches = @($CurrentAdapters | Where-Object {
                    [string]$_.InterfaceGuid -eq $Plan.InterfaceGuid
                })
            if ($targetMatches.Count -eq 0) { return 'Missing' }
            if ($targetMatches.Count -ne 1) {
                Write-Log -Level ERROR -Message "Wi-Fi Direct adapter identity mismatch for InterfaceGuid $($Plan.InterfaceGuid): expected one, found $($targetMatches.Count)" -Module 'AdvancedSecurity'
                return 'Failed'
            }
            $target = $targetMatches[0]
            # Windows cannot change the administrative state of an adapter it
            # reports as not present (InterfaceOperationalStatus 6).
            if ([int]$target.InterfaceOperationalStatus -eq 6) {
                if (([string]$target.AdminStatus -eq 'Up') -ne $Plan.ShouldBeEnabled) {
                    Write-Log -Level ERROR -Message "Wi-Fi Direct adapter $($target.InterfaceGuid) is not present, so its saved state cannot be applied now; reconnect its Wi-Fi adapter and run Restore again" -Module 'AdvancedSecurity'
                    return 'Failed'
                }
                return 'Restored'
            }
            if (([string]$target.AdminStatus -eq 'Up') -ne $Plan.ShouldBeEnabled) {
                if ($Plan.ShouldBeEnabled) {
                    Enable-NetAdapter -InputObject $target -Confirm:$false -ErrorAction Stop
                }
                else {
                    Disable-NetAdapter -InputObject $target -Confirm:$false -ErrorAction Stop
                }
                Wait-NoIDWiFiDirectAdapterSettle
            }
            $verified = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                    [string]$_.InterfaceGuid -eq $Plan.InterfaceGuid
                })
            if ($verified.Count -ne 1 -or ([string]$verified[0].AdminStatus -eq 'Up') -ne $Plan.ShouldBeEnabled) {
                Write-Log -Level ERROR -Message "Wi-Fi Direct adapter state verification failed for $($Plan.InterfaceGuid)" -Module 'AdvancedSecurity'
                return 'Failed'
            }
            return 'Restored'
        }

        $missingPlans = [System.Collections.Generic.List[object]]::new()
        foreach ($plan in $plans) {
            $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                    [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
                })
            switch (& $restorePresent $plan $currentAdapters) {
                'Missing' { $missingPlans.Add($plan) }
                'Failed' { $failedCount++ }
            }
        }

        # Windows removes the Wi-Fi Direct role adapters it created on demand
        # when another Wi-Fi Direct adapter is disabled, and creates them again
        # when needed. A device's disabled state persists while it is absent,
        # so an absent adapter matches the backup when that state matches.
        foreach ($plan in $missingPlans) {
            $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                    [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
                })
            $outcome = & $restorePresent $plan $currentAdapters
            if ($outcome -ceq 'Failed') { $failedCount++; continue }
            if ($outcome -ceq 'Restored') { continue }
            $deviceDisabled = Get-NoIDNetAdapterDeviceDisabled -InterfaceGuid $plan.InterfaceGuid
            if ($null -eq $deviceDisabled) {
                Write-Log -Level INFO -Message "Wi-Fi Direct adapter $($plan.InterfaceGuid) was removed from Windows after the backup; nothing of it remains to restore" -Module 'AdvancedSecurity'
            }
            elseif ($deviceDisabled -ne $plan.ShouldBeEnabled) {
                Write-Log -Level INFO -Message "Wi-Fi Direct adapter $($plan.InterfaceGuid) is not present; its device keeps the saved $($plan.SavedAdminStatus) state for when Windows creates it again" -Module 'AdvancedSecurity'
            }
            else {
                Write-Log -Level ERROR -Message "Wi-Fi Direct adapter $($plan.InterfaceGuid) from the backup is not present and its saved state cannot be applied now; reconnect its Wi-Fi adapter and run Restore again" -Module 'AdvancedSecurity'
                $failedCount++
            }
        }

        if ($failedCount -gt 0) { return $false }
        Write-Log -Level SUCCESS -Message 'Wi-Fi Direct adapter administrative states restored and verified' -Module 'AdvancedSecurity'
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Wi-Fi Direct adapter restore failed: $_" -Module 'AdvancedSecurity' -Exception $_.Exception
        return $false
    }
}

function Restore-NetBIOSAdapters {
    <#
    .SYNOPSIS
        Restore NetBIOS over TCP/IP settings on network adapters

    .DESCRIPTION
        Restores the typed, existence-aware native NetBT state on each sealed
        network adapter. Legacy version-1 array artifacts remain readable.

        TcpipNetbiosOptions values:
        - 0 = Default (use DHCP option)
        - 1 = Enable NetBIOS over TCP/IP
        - 2 = Disable NetBIOS over TCP/IP (set by hardening)

    .PARAMETER BackupData
        JSON backup data containing adapter descriptions and their original TcpipNetbiosOptions
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param($BackupData)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore NetBIOSAdapters')) {
        return
    }


    Write-Log -Level DEBUG -Message "Restoring NetBIOS over TCP/IP settings on network adapters..." -Module "AdvancedSecurity"

    try {
        if ($BackupData.PSObject.Properties.Name -contains 'SchemaVersion' -and
            [int]$BackupData.SchemaVersion -eq 2 -and
            $BackupData.PSObject.Properties.Name -contains 'Adapters') {
            $null = Restore-AdvancedSecurityNetBIOSState -Snapshot $BackupData
            Write-Log -Level SUCCESS -Message "NetBIOS settings restored for $(@($BackupData.Adapters).Count) sealed network adapter(s)" -Module 'AdvancedSecurity'
            return $true
        }

        # BackupData can be an array directly or have a nested structure
        $adaptersToRestore = if ($BackupData -is [Array]) { $BackupData } else { @($BackupData) }

        if ($adaptersToRestore.Count -eq 0) {
            Write-Log -Level INFO -Message "No NetBIOS adapter settings to restore" -Module "AdvancedSecurity"
            return $true
        }

        $restoredCount = 0
        $failedCount = 0

        # Get current adapters
        $currentAdapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop)

        foreach ($backupAdapter in $adaptersToRestore) {
            try {
                # SettingID is the stable adapter GUID exposed by this CIM
                # class. A current sealed artifact must never fall through to
                # a potentially reused Index when its GUID no longer exists.
                $targetAdapter = $null
                $hasStableIdentity = ($backupAdapter.PSObject.Properties.Name -contains 'SettingID' -and
                    -not [string]::IsNullOrWhiteSpace([string]$backupAdapter.SettingID))
                if ($hasStableIdentity) {
                    $stableMatches = @($currentAdapters | Where-Object {
                        [string]$_.SettingID -eq [string]$backupAdapter.SettingID
                    })
                    if ($stableMatches.Count -ne 1) {
                        throw "Expected exactly one adapter for SettingID $($backupAdapter.SettingID), found $($stableMatches.Count)"
                    }
                    $targetAdapter = $stableMatches[0]
                }
                else {
                    $legacyMatches = @($currentAdapters | Where-Object {
                        $_.Index -eq $backupAdapter.Index -and $_.Description -eq $backupAdapter.Description
                    })
                    if ($legacyMatches.Count -ne 1) {
                        throw "Expected exactly one legacy adapter for Index/Description, found $($legacyMatches.Count)"
                    }
                    $targetAdapter = $legacyMatches[0]
                }

                if ($targetAdapter) {
                    $originalSetting = $backupAdapter.TcpipNetbiosOptions

                    # Only restore if different from current
                    if ($targetAdapter.TcpipNetbiosOptions -ne $originalSetting) {
                        $result = Invoke-CimMethod -InputObject $targetAdapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = $originalSetting }

                        if ($result.ReturnValue -eq 0) {
                            $verifiedAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index = $($targetAdapter.Index)" -ErrorAction Stop
                            if ($verifiedAdapter.TcpipNetbiosOptions -eq $originalSetting) {
                                Write-Log -Level DEBUG -Message "Restored NetBIOS setting on adapter '$($targetAdapter.Description)' to $originalSetting" -Module "AdvancedSecurity"
                                $restoredCount++
                            }
                            else {
                                Write-Log -Level ERROR -Message "NetBIOS restore verification failed on '$($targetAdapter.Description)': expected $originalSetting, got $($verifiedAdapter.TcpipNetbiosOptions)" -Module 'AdvancedSecurity'
                                $failedCount++
                            }
                        }
                        else {
                            Write-Log -Level WARNING -Message "SetTcpipNetbios returned $($result.ReturnValue) for adapter '$($targetAdapter.Description)'" -Module "AdvancedSecurity"
                            $failedCount++
                        }
                    }
                    else {
                        Write-Log -Level DEBUG -Message "NetBIOS setting on adapter '$($targetAdapter.Description)' already matches backup ($originalSetting)" -Module "AdvancedSecurity"
                        $restoredCount++
                    }
                }
                else {
                    Write-Log -Level WARNING -Message "Adapter not found for restore: Index=$($backupAdapter.Index), Description='$($backupAdapter.Description)'" -Module "AdvancedSecurity"
                    $failedCount++
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to restore NetBIOS on adapter '$($backupAdapter.Description)': $_" -Module "AdvancedSecurity"
                $failedCount++
            }
        }

        if ($failedCount -eq 0) {
            Write-Log -Level SUCCESS -Message "NetBIOS settings restored on $restoredCount adapter(s)" -Module "AdvancedSecurity"
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "NetBIOS restore completed with issues: $restoredCount succeeded, $failedCount failed" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore NetBIOS adapter settings: $_" -Module "AdvancedSecurity"
        return $false
    }
}
