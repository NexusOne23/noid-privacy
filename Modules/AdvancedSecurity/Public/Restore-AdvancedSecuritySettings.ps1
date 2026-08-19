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
        Write-Log -Level INFO -Message "Processing Advanced Security backup: $filename" -Module "AdvancedSecurity"

        if ($ArtifactName -eq 'AdvancedSecurity_FirewallPolicy') {
            if ([System.IO.Path]::GetExtension($BackupFilePath) -ine '.wfw') {
                throw "Firewall policy artifact does not use the expected .wfw format: $filename"
            }
            return [bool](Restore-FirewallPolicy -BackupFilePath $BackupFilePath -Confirm:$false)
        }

        if ([System.IO.Path]::GetExtension($BackupFilePath) -ine '.json') {
            throw "AdvancedSecurity JSON artifact does not use the expected .json format: $filename"
        }
        $backupData = Get-Content -LiteralPath $BackupFilePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

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
        [string]$BackupFilePath
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
        $import = Start-Process -FilePath 'netsh.exe' `
            -ArgumentList @('advfirewall', 'import', "`"$BackupFilePath`"") `
            -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
        if ($import.ExitCode -ne 0) {
            throw "netsh advfirewall import failed with exit code $($import.ExitCode)"
        }

        $export = Start-Process -FilePath 'netsh.exe' `
            -ArgumentList @('advfirewall', 'export', "`"$verificationExport`"") `
            -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
        if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationExport -PathType Leaf)) {
            throw "Post-restore firewall export failed with exit code $($export.ExitCode)"
        }
        $null = Assert-AdvancedSecurityFirewallPolicyEquivalent `
            -ReferenceFilePath $BackupFilePath `
            -CandidateFilePath $verificationExport `
            -Context 'Post-restore firewall policy verification'
        Write-Log -Level SUCCESS -Message 'Complete pre-hardening firewall policy imported and semantically verified exactly' -Module 'AdvancedSecurity'
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Complete firewall policy restore failed: $_" -Module 'AdvancedSecurity' -Exception $_.Exception
        return $false
    }
    finally {
        Remove-Item -LiteralPath $verificationExport -Force -ErrorAction SilentlyContinue
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
        $currentFeature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
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
        $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
        })
        foreach ($backupAdapter in $backedUpAdapters) {
            $targetMatches = @($currentAdapters | Where-Object {
                [string]$_.InterfaceGuid -eq [string]$backupAdapter.InterfaceGuid
            })

            if ($targetMatches.Count -ne 1) {
                Write-Log -Level ERROR -Message "Wi-Fi Direct adapter identity mismatch for InterfaceGuid $($backupAdapter.InterfaceGuid): expected one, found $($targetMatches.Count)" -Module 'AdvancedSecurity'
                $failedCount++
                continue
            }
            $target = $targetMatches[0]

            $shouldBeEnabled = if ($backupAdapter.PSObject.Properties.Name -contains 'AdminStatus' -and $null -ne $backupAdapter.AdminStatus) {
                [string]$backupAdapter.AdminStatus -eq 'Up'
            }
            else {
                [string]$backupAdapter.Status -ne 'Disabled'
            }

            if ($shouldBeEnabled) {
                Enable-NetAdapter -Name $target.Name -Confirm:$false -ErrorAction Stop
            }
            else {
                Disable-NetAdapter -Name $target.Name -Confirm:$false -ErrorAction Stop
            }

            $verified = Get-NetAdapter -Name $target.Name -IncludeHidden -ErrorAction Stop
            $isEnabled = [string]$verified.AdminStatus -eq 'Up'
            if ($isEnabled -ne $shouldBeEnabled) {
                Write-Log -Level ERROR -Message "Wi-Fi Direct adapter state verification failed for $($target.InterfaceGuid)" -Module 'AdvancedSecurity'
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


    Write-Log -Level INFO -Message "Restoring NetBIOS over TCP/IP settings on network adapters..." -Module "AdvancedSecurity"

    try {
        if ($BackupData.PSObject.Properties.Name -contains 'SchemaVersion' -and
            [int]$BackupData.SchemaVersion -eq 2 -and
            $BackupData.PSObject.Properties.Name -contains 'Adapters') {
            $restoredState = Restore-AdvancedSecurityNetBIOSState -Snapshot $BackupData
            Write-Log -Level SUCCESS -Message "Exact typed NetBIOS state restored on $(@($restoredState.Adapters).Count) adapter(s)" -Module 'AdvancedSecurity'
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
