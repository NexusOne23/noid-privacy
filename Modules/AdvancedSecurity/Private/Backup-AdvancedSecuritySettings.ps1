function Backup-AdvancedSecuritySettings {
    <#
    .SYNOPSIS
        Create a comprehensive backup of all Advanced Security settings

    .DESCRIPTION
        Backs up all registry keys, services, firewall rules, and Windows features
        that will be modified by the AdvancedSecurity module.

        This is called automatically by Invoke-AdvancedSecurity before applying changes.

    .EXAMPLE
        Backup-AdvancedSecuritySettings

    .NOTES
        Uses the Core/Rollback.ps1 backup system
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$SkipFirewallLayer,
        [switch]$DisableRDP,
        [switch]$AdminSharesDisabled,
        [switch]$DisableUPnP,
        [switch]$DisableWirelessDisplayCompletely,
        [switch]$DisableDiscoveryProtocolsCompletely,
        [switch]$DisableIPv6Completely,
        [switch]$EnableFirewallShieldsUp,
        [bool]$RdpHostSupported = $true,
        [bool]$ManagedPolicySupported = $true,
        [bool]$WirelessDisplaySupported = $true,
        [ValidateSet('Home', 'Professional', 'Enterprise', 'Education', 'IoTEnterprise')]
        [string]$EditionFamily = 'Professional'
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Backup AdvancedSecuritySettings')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Creating comprehensive backup of Advanced Security settings..." -Module "AdvancedSecurity"

        $backupCount = 0
        $backupFailures = [System.Collections.Generic.List[string]]::new()

        # Start module backup session
        $backupSession = Start-ModuleBackup -ModuleName "AdvancedSecurity"

        if (-not $backupSession) {
            Write-Log -Level ERROR -Message "Failed to start backup session" -Module "AdvancedSecurity"
            return [PSCustomObject]@{ Success=$false; Count=0; Failures=@('Failed to start backup session') }
        }

        # Registry state is captured once, value-by-value, in the sealed
        # AdvancedSecurity_PreState artifact below. Broad .reg exports are not
        # created because merge restore would overwrite unrelated later changes.

        # 1. Services (including WiFi Direct for Wireless Display and WS-Discovery)
        Write-Log -Level DEBUG -Message "Backing up risky services state..." -Module "AdvancedSecurity"
        # Note: Computer Browser (Browser) is deprecated in Win10/11 - not included
        $services = @('lmhosts')
        if ($DisableUPnP) { $services += @('SSDPSRV', 'upnphost') }
        if ($WirelessDisplaySupported -and $DisableWirelessDisplayCompletely) { $services += 'WFDSConMgrSvc' }
        if ($DisableDiscoveryProtocolsCompletely) { $services += @('FDResPub', 'fdPHost') }

        $installedServices = @(Get-Service -ErrorAction Stop)
        foreach ($svc in $services) {
            $serviceMatches = @($installedServices | Where-Object { [string]$_.Name -eq $svc })
            if ($serviceMatches.Count -gt 1) {
                throw "Service identity is ambiguous during backup: $svc"
            }
            if ($serviceMatches.Count -eq 0) {
                Write-Log -Level DEBUG -Message "Service is not installed; no backup or mutation required: $svc" -Module "AdvancedSecurity"
                continue
            }
            $svcBackup = Backup-ServiceConfiguration -ServiceName $svc
            if ($svcBackup.Success -and $svcBackup.Exists) { $backupCount++ }
            else { $backupFailures.Add("Service backup failed after installed-service precheck: $svc ($($svcBackup.Error))") }
        }

        # 2. Firewall Rules Snapshot. No firewall artifact is required when the
        # layer was explicitly skipped because no firewall mutation may follow.
        if ($SkipFirewallLayer) {
            Write-Log -Level INFO -Message "Firewall backup skipped because the Windows Firewall layer is explicitly skipped" -Module 'AdvancedSecurity'
        }
        else {
            Write-Host ""
            Write-Host "  Creating complete firewall policy snapshot..." -ForegroundColor Cyan
            Write-Log -Level INFO -Message "Exporting complete local firewall policy before mutation" -Module "AdvancedSecurity"

            $firewallPolicyPath = Join-Path $backupSession 'AdvancedSecurity_FirewallPolicy.wfw'
            $firewallVerificationPath = Join-Path $env:TEMP "NoID_FirewallBackupVerify_$([Guid]::NewGuid().ToString('N')).wfw"
            try {
                $firewallExport = Start-Process -FilePath 'netsh.exe' `
                    -ArgumentList @('advfirewall', 'export', "`"$firewallPolicyPath`"") `
                    -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
                if ($firewallExport.ExitCode -ne 0 -or
                    -not (Test-Path -LiteralPath $firewallPolicyPath -PathType Leaf) -or
                    (Get-Item -LiteralPath $firewallPolicyPath -ErrorAction Stop).Length -lt 1) {
                    throw "netsh advfirewall export failed with exit code $($firewallExport.ExitCode)"
                }

                # A .wfw file is a registry hive whose binary housekeeping
                # metadata changes on every export. Compare every represented
                # key and typed value instead of comparing unstable file bytes.
                $verificationExport = Start-Process -FilePath 'netsh.exe' `
                    -ArgumentList @('advfirewall', 'export', "`"$firewallVerificationPath`"") `
                    -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
                if ($verificationExport.ExitCode -ne 0 -or
                    -not (Test-Path -LiteralPath $firewallVerificationPath -PathType Leaf)) {
                    throw "Firewall verification export failed with exit code $($verificationExport.ExitCode)"
                }
                $null = Assert-AdvancedSecurityFirewallPolicyEquivalent `
                    -ReferenceFilePath $firewallPolicyPath `
                    -CandidateFilePath $firewallVerificationPath `
                    -Context 'Consecutive firewall backup exports'
                $firewallRegistration = Register-BackupFile -FilePath $firewallPolicyPath -Type 'FirewallPolicy' -Name 'AdvancedSecurity_FirewallPolicy' -Target 'LocalFirewallPolicy'
                if (-not $firewallRegistration) {
                    throw 'Complete firewall policy snapshot registration failed'
                }
                $backupCount++
                Write-Host "  [OK] Complete firewall policy backup created" -ForegroundColor Green
            }
            catch {
                $backupFailures.Add("Complete firewall policy export failed: $($_.Exception.Message)")
            }
            finally {
                Remove-Item -LiteralPath $firewallVerificationPath -Force -ErrorAction SilentlyContinue
            }
            Write-Host ""
        }

        if ($WirelessDisplaySupported -and $DisableWirelessDisplayCompletely) {
            try {
                $wifiDirectAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                    Where-Object { [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*' } |
                    Select-Object Name, InterfaceGuid, InterfaceDescription, Status, AdminStatus)
                if (@($wifiDirectAdapters | Where-Object {
                            [string]::IsNullOrWhiteSpace([string]$_.InterfaceGuid) -or
                            [string]::IsNullOrWhiteSpace([string]$_.InterfaceDescription) -or
                            [string]$_.AdminStatus -notin @('Up', 'Down')
                        }).Count -gt 0 -or
                    @($wifiDirectAdapters | Group-Object { ([string]$_.InterfaceGuid).ToLowerInvariant() } |
                        Where-Object { $_.Count -gt 1 }).Count -gt 0) {
                    throw 'Wi-Fi Direct adapter inventory contains invalid or duplicate stable identities'
                }
                $wifiBackup = Register-Backup -Type 'AdvancedSecurity' -Data @{
                    Adapters = $wifiDirectAdapters
                    BackupDate = Get-Date -Format 'o'
                } -Name 'WiFiDirect_Adapters'
                if ($wifiBackup) { $backupCount++ } else { $backupFailures.Add('Wi-Fi Direct adapter snapshot registration failed') }
            }
            catch {
                $backupFailures.Add("Wi-Fi Direct adapter snapshot failed: $($_.Exception.Message)")
            }
        }

        try {
            $netbiosSnapshot = Get-AdvancedSecurityNetBIOSState
            $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $netbiosSnapshot
            $netbiosBackup = Register-Backup -Type 'AdvancedSecurity' -Data $netbiosSnapshot -Name 'NetBIOS_Adapters'
            if ($netbiosBackup) { $backupCount++ } else { $backupFailures.Add('NetBIOS adapter snapshot registration failed') }
        }
        catch {
            $backupFailures.Add("NetBIOS adapter snapshot failed: $($_.Exception.Message)")
        }

        # 5. Capture only the exact values this module can mutate. Every target
        # receives an entry even when absent so restore can remove tattooed values
        # without clearing unrelated Windows or third-party configuration.
        Write-Log -Level INFO -Message "Creating targeted AdvancedSecurity registry pre-state snapshot..." -Module "AdvancedSecurity"
        try {
            $winInetUsers = [System.Collections.Generic.List[object]]::new()
            $interactiveUser = Get-AdvancedSecurityInteractiveUser -AllowNone
            if ($null -ne $interactiveUser) {
                $winInetState = Invoke-AdvancedSecurityWinInetUserState -User $interactiveUser -Operation Query
                $winInetUsers.Add([PSCustomObject]@{
                        Account           = [string]$interactiveUser.Account
                        Sid               = [string]$interactiveUser.Sid
                        SessionId         = [int]$interactiveUser.SessionId
                        AutoDetectEnabled = [bool]$winInetState.AutoDetectEnabled
                    })
            }

            $preStateSnapshot = [System.Collections.Generic.List[object]]::new()
            $managedTargets = @(Get-AdvancedSecurityRegistryTargets `
                -SkipFirewallLayer:$SkipFirewallLayer `
                -DisableRDP:$DisableRDP `
                -AdminSharesDisabled:$AdminSharesDisabled `
                -DisableWirelessDisplayCompletely:$DisableWirelessDisplayCompletely `
                -DisableDiscoveryProtocolsCompletely:$DisableDiscoveryProtocolsCompletely `
                -DisableIPv6Completely:$DisableIPv6Completely `
                -EnableFirewallShieldsUp:$EnableFirewallShieldsUp `
                -RdpHostSupported:$RdpHostSupported `
                -ManagedPolicySupported:$ManagedPolicySupported `
                -WirelessDisplaySupported:$WirelessDisplaySupported)
            foreach ($target in $managedTargets) {
                $keyExisted = Test-Path -LiteralPath $target.Path
                $valueExisted = $false
                $value = $null
                $valueType = $null

                if ($keyExisted -and -not $target.KeyOnly) {
                    $registryKey = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                    $valueExisted = $registryKey.GetValueNames() -contains $target.Name
                    if ($valueExisted) {
                        $value = $registryKey.GetValue(
                            $target.Name,
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )
                        $valueType = $registryKey.GetValueKind($target.Name).ToString()
                    }
                }

                $preStateSnapshot.Add([PSCustomObject]@{
                        Path       = $target.Path
                        Name       = $target.Name
                        KeyOnly    = [bool]$target.KeyOnly
                        KeyExisted = $keyExisted
                        Exists     = $valueExisted
                        Value      = $value
                        Type       = $valueType
                    })
            }

            $preStateDocument = [PSCustomObject]@{
                SchemaVersion     = 5
                CapturedAt        = (Get-Date).ToUniversalTime().ToString('o')
                EditionFamily     = $EditionFamily
                RdpHostSupported  = [bool]$RdpHostSupported
                ManagedPolicySupported = [bool]$ManagedPolicySupported
                WirelessDisplaySupported = [bool]$WirelessDisplaySupported
                SkipFirewallLayer = [bool]$SkipFirewallLayer
                DisableRDP        = [bool]$DisableRDP
                AdminSharesDisabled = [bool]$AdminSharesDisabled
                DisableUPnP       = [bool]$DisableUPnP
                DisableWirelessDisplayCompletely = [bool]$DisableWirelessDisplayCompletely
                DisableDiscoveryProtocolsCompletely = [bool]$DisableDiscoveryProtocolsCompletely
                DisableIPv6Completely = [bool]$DisableIPv6Completely
                EnableFirewallShieldsUp = [bool]$EnableFirewallShieldsUp
                WinInetUsers      = @($winInetUsers)
                TargetCount       = $preStateSnapshot.Count
                Entries           = @($preStateSnapshot)
            }
            $null = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $preStateDocument
            $result = Register-Backup -Type 'AdvancedSecurity' -Data $preStateDocument -Name 'AdvancedSecurity_PreState'
            if (-not $result) {
                throw 'Targeted registry pre-state registration returned no artifact'
            }
            $backupCount++
            Write-Log -Level SUCCESS -Message "AdvancedSecurity targeted pre-state created ($($preStateSnapshot.Count) managed values)" -Module "AdvancedSecurity"
        }
        catch {
            $backupFailures.Add("Targeted AdvancedSecurity pre-state failed: $($_.Exception.Message)")
        }

        $requiredArtifacts = @(
            'NetBIOS_Adapters',
            'AdvancedSecurity_PreState'
        )
        if ($WirelessDisplaySupported -and $DisableWirelessDisplayCompletely) {
            $requiredArtifacts += 'WiFiDirect_Adapters'
        }
        if (-not $SkipFirewallLayer) {
            $requiredArtifacts += 'AdvancedSecurity_FirewallPolicy'
        }
        $registeredNames = @($global:BackupIndex | Where-Object { $_.Module -eq 'AdvancedSecurity' } | ForEach-Object { $_.Name })
        foreach ($requiredArtifact in $requiredArtifacts) {
            if ($requiredArtifact -notin $registeredNames) {
                $backupFailures.Add("Required backup artifact missing: $requiredArtifact")
            }
        }

        # Reconcile every selected live target once more immediately before the
        # caller seals the module. This catches service/adapter/registry/firewall
        # drift that occurred while the sequential backup steps were running.
        try {
            $currentServiceInventory = @(Get-Service -ErrorAction Stop)
            foreach ($svc in $services) {
                $serviceArtifact = @($global:BackupIndex | Where-Object {
                        $_.Module -eq 'AdvancedSecurity' -and $_.Type -eq 'Service' -and $_.ServiceName -eq $svc
                    })
                $currentService = @($currentServiceInventory | Where-Object { [string]$_.Name -eq $svc })
                if ($serviceArtifact.Count -eq 0) {
                    if ($currentService.Count -gt 0) { throw "Service appeared after backup inventory: $svc" }
                    continue
                }
                if ($serviceArtifact.Count -ne 1 -or $currentService.Count -ne 1) {
                    throw "Service inventory drift for $svc"
                }
                $savedService = Get-Content -LiteralPath $serviceArtifact[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                if ([string]$currentService[0].Status -ne [string]$savedService.Status -or
                    [string]$currentService[0].StartType -ne [string]$savedService.StartType) {
                    throw "Service state changed during backup: $svc"
                }
                $serviceKey = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -ErrorAction Stop
                $delayedExists = $serviceKey.GetValueNames() -contains 'DelayedAutoStart'
                if ($delayedExists -ne [bool]$savedService.DelayedAutoStartExists -or
                    ($delayedExists -and
                        ($serviceKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord' -or
                         [int]$serviceKey.GetValue('DelayedAutoStart') -ne [int]$savedService.DelayedAutoStart))) {
                    throw "Service delayed-start state changed during backup: $svc"
                }
            }

            if (-not $SkipFirewallLayer) {
                $finalFirewallExport = Join-Path $env:TEMP "NoID_FirewallSealVerify_$([Guid]::NewGuid().ToString('N')).wfw"
                try {
                    $firewallCheck = Start-Process -FilePath 'netsh.exe' `
                        -ArgumentList @('advfirewall', 'export', "`"$finalFirewallExport`"") `
                        -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
                    if ($firewallCheck.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $finalFirewallExport -PathType Leaf)) {
                        throw "Final firewall prestate export failed with exit code $($firewallCheck.ExitCode)"
                    }
                    $null = Assert-AdvancedSecurityFirewallPolicyEquivalent `
                        -ReferenceFilePath $firewallPolicyPath `
                        -CandidateFilePath $finalFirewallExport `
                        -Context 'Firewall policy changed while AdvancedSecurity backup was running'
                }
                finally {
                    Remove-Item -LiteralPath $finalFirewallExport -Force -ErrorAction SilentlyContinue
                }
            }

            if ($WirelessDisplaySupported -and $DisableWirelessDisplayCompletely) {
                $currentWifi = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                    Where-Object { [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*' } |
                    Select-Object InterfaceGuid, InterfaceDescription, AdminStatus)
                $savedWifiIdentity = @($wifiDirectAdapters | Select-Object InterfaceGuid, InterfaceDescription, AdminStatus |
                    Sort-Object InterfaceGuid | ConvertTo-Json -Compress)
                $currentWifiIdentity = @($currentWifi | Sort-Object InterfaceGuid | ConvertTo-Json -Compress)
                if (($savedWifiIdentity -join '') -cne ($currentWifiIdentity -join '')) {
                    throw 'Wi-Fi Direct adapter inventory/state changed during backup'
                }
            }

            $currentNetbios = Get-AdvancedSecurityNetBIOSState
            if (-not (Test-AdvancedSecurityNetBIOSStateEqual `
                    -Reference $netbiosSnapshot -Candidate $currentNetbios)) {
                throw 'NetBIOS adapter inventory/state changed during backup'
            }

            $savedInteractiveUsers = @($winInetUsers)
            $currentInteractiveUser = Get-AdvancedSecurityInteractiveUser -AllowNone
            # Windows PowerShell 5.1 unwraps a one-item array emitted from an
            # if-expression. Initialize and assign the array explicitly so
            # Count is always an integer (0 or 1), never a missing property on
            # a scalar PSCustomObject.
            $currentInteractiveUsers = @()
            if ($null -ne $currentInteractiveUser) {
                $currentInteractiveUsers = @($currentInteractiveUser)
            }
            if ($savedInteractiveUsers.Count -ne $currentInteractiveUsers.Count -or
                ($savedInteractiveUsers.Count -eq 1 -and
                    ([string]$savedInteractiveUsers[0].Sid -cne [string]$currentInteractiveUsers[0].Sid -or
                     [int]$savedInteractiveUsers[0].SessionId -ne [int]$currentInteractiveUsers[0].SessionId))) {
                $sidMatch = $savedInteractiveUsers.Count -eq 1 -and
                    $currentInteractiveUsers.Count -eq 1 -and
                    [string]$savedInteractiveUsers[0].Sid -ceq [string]$currentInteractiveUsers[0].Sid
                $sessionMatch = $savedInteractiveUsers.Count -eq 1 -and
                    $currentInteractiveUsers.Count -eq 1 -and
                    [int]$savedInteractiveUsers[0].SessionId -eq [int]$currentInteractiveUsers[0].SessionId
                throw "Interactive Explorer user changed during AdvancedSecurity backup " +
                    "(savedCount=$($savedInteractiveUsers.Count); currentCount=$($currentInteractiveUsers.Count); " +
                    "sidMatch=$sidMatch; sessionMatch=$sessionMatch)"
            }
            if ($savedInteractiveUsers.Count -eq 1) {
                $currentWinInet = Invoke-AdvancedSecurityWinInetUserState -User $currentInteractiveUsers[0] -Operation Query
                if ([bool]$currentWinInet.AutoDetectEnabled -ne [bool]$savedInteractiveUsers[0].AutoDetectEnabled) {
                    throw 'WinINet AutoDetect state changed during AdvancedSecurity backup'
                }
            }

            $liveRegistryEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($target in $managedTargets) {
                $keyExisted = Test-Path -LiteralPath $target.Path -PathType Container
                $valueExisted = $false; $value = $null; $valueType = $null
                if ($keyExisted -and -not $target.KeyOnly) {
                    $liveKey = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                    $valueExisted = $liveKey.GetValueNames() -contains $target.Name
                    if ($valueExisted) {
                        $value = $liveKey.GetValue($target.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $valueType = $liveKey.GetValueKind($target.Name).ToString()
                    }
                }
                $liveRegistryEntries.Add([PSCustomObject]@{
                        Path=$target.Path; Name=$target.Name; KeyOnly=[bool]$target.KeyOnly
                        KeyExisted=$keyExisted; Exists=$valueExisted; Value=$value; Type=$valueType
                    })
            }
            if ((@($preStateSnapshot) | ConvertTo-Json -Compress -Depth 20) -cne
                (@($liveRegistryEntries) | ConvertTo-Json -Compress -Depth 20)) {
                throw 'Managed registry prestate changed during AdvancedSecurity backup'
            }
        }
        catch {
            $backupFailures.Add("Pre-seal live-state reconciliation failed: $($_.Exception.Message)")
        }

        $success = ($backupFailures.Count -eq 0 -and $backupCount -gt 0)
        if ($success) {
            Write-Log -Level SUCCESS -Message "Advanced Security backup completed: $backupCount items backed up" -Module "AdvancedSecurity"
        }
        else {
            Write-Log -Level ERROR -Message "Advanced Security backup incomplete: $($backupFailures -join '; ')" -Module "AdvancedSecurity"
        }
        return [PSCustomObject]@{
            Success  = $success
            Count    = $backupCount
            Failures = @($backupFailures)
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to backup Advanced Security settings: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Success  = $false
            Count    = 0
            Failures = @($_.Exception.Message)
        }
    }
}
