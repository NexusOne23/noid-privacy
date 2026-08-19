function Set-WirelessDisplaySecurity {
    <#
    .SYNOPSIS
        Applies the declared Wireless Display (Miracast) policy profile.

    .DESCRIPTION
        Configures exact Wireless Display policy values. The default blocks
        receiving projections and requires PIN pairing. The optional disable
        profile additionally sets send/infrastructure/mDNS policies, selected
        firewall rules, Wi-Fi Direct service state and virtual-adapter state.
        Registry/firewall readback is not described as proof against every
        network or screen-capture attack.

    .PARAMETER DisableCompletely
        If specified, applies the module's complete-disable target set.
        Default: Only hardens (blocks receiving, requires PIN) but allows sending.

    .PARAMETER SkipFirewallChanges
        Applies the selected Wireless Display policy/service changes without
        creating Windows Firewall rules.

    .EXAMPLE
        Set-WirelessDisplaySecurity
        # Applies default hardening (blocks receiving, requires PIN)

    .EXAMPLE
        Set-WirelessDisplaySecurity -DisableCompletely
        # Applies the complete-disable target set
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$DisableCompletely,
        [switch]$SkipFirewallChanges
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set WirelessDisplaySecurity')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Applying Wireless Display security hardening (DisableCompletely: $DisableCompletely)..." -Module "AdvancedSecurity"

        $changesApplied = 0

        # Registry path for Wireless Display policies
        $connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"

        # The targeted registry pre-state was sealed before Apply.
        if (-not (Test-Path $connectPath)) {
            New-Item -Path $connectPath -Force -ErrorAction Stop | Out-Null
            Write-Log -Level INFO -Message "Created registry key: $connectPath" -Module "AdvancedSecurity"
        }

        # ============================================
        # ALWAYS APPLIED (Default hardening for all profiles)
        # ============================================

        # 1. AllowProjectionToPC = 0 (block receiving projections)
        Remove-ItemProperty -LiteralPath $connectPath -Name 'AllowProjectionToPC' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $connectPath -Name 'AllowProjectionToPC' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level INFO -Message "Set AllowProjectionToPC = 0 (Block receiving)" -Module "AdvancedSecurity"
        $changesApplied++

        # 2. RequirePinForPairing = 2 (always require PIN)
        Remove-ItemProperty -LiteralPath $connectPath -Name 'RequirePinForPairing' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $connectPath -Name 'RequirePinForPairing' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level INFO -Message "Set RequirePinForPairing = 2 (Always require PIN)" -Module "AdvancedSecurity"
        $changesApplied++

        # ============================================
        # OPTIONAL: Complete disable (user choice)
        # ============================================

        if ($DisableCompletely) {
            Write-Log -Level INFO -Message "Applying complete Wireless Display disable..." -Module "AdvancedSecurity"

            foreach ($name in @(
                    'AllowProjectionFromPC', 'AllowMdnsAdvertisement', 'AllowMdnsDiscovery',
                    'AllowProjectionFromPCOverInfrastructure', 'AllowProjectionToPCOverInfrastructure'
                )) {
                Remove-ItemProperty -LiteralPath $connectPath -Name $name -ErrorAction SilentlyContinue
                New-ItemProperty -Path $connectPath -Name $name -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Write-Log -Level INFO -Message "Set $name = 0 (complete Wireless Display disable)" -Module "AdvancedSecurity"
                $changesApplied++
            }

            # 8. Block Miracast ports via Windows Firewall (7236, 7250), unless
            # the user explicitly skipped the AdvancedSecurity firewall layer.
            $firewallRules = @(Get-AdvancedSecurityFirewallDefinitions -Feature Miracast)
            if ($firewallRules.Count -ne 4) { throw "Expected four canonical Miracast firewall rules, found $($firewallRules.Count)" }

            if ($SkipFirewallChanges) {
                Write-Log -Level INFO -Message "Miracast firewall rules skipped by explicit firewall-layer choice" -Module "AdvancedSecurity"
            }
            else {
                foreach ($rule in $firewallRules) {
                    if (-not (Set-AdvancedSecurityFirewallRuleDefinition -Definition $rule)) {
                        throw "Miracast firewall rule application failed: $($rule.Name)"
                    }
                    $changesApplied++
                }
            }

            # 9. Disable the selected Wi-Fi Direct service when it exists.
            $wfdServiceMatches = @(Get-Service -ErrorAction Stop | Where-Object { [string]$_.Name -eq 'WFDSConMgrSvc' })
            if ($wfdServiceMatches.Count -gt 1) { throw 'WFDSConMgrSvc service identity is ambiguous' }
            if ($wfdServiceMatches.Count -eq 1) {
                $wfdService = $wfdServiceMatches[0]
                if ($wfdService.Status -eq 'Running') {
                    Stop-Service -Name "WFDSConMgrSvc" -ErrorAction Stop
                    $wfdService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
                    Write-Log -Level INFO -Message "Stopped WiFi Direct Service (WFDSConMgrSvc)" -Module "AdvancedSecurity"
                }

                if ($wfdService.StartType -ne 'Disabled') {
                    Set-Service -Name "WFDSConMgrSvc" -StartupType Disabled -ErrorAction Stop
                    Write-Log -Level INFO -Message "Disabled WiFi Direct Service (WFDSConMgrSvc) - survives reboot" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                $wfdService = Get-Service -Name 'WFDSConMgrSvc' -ErrorAction Stop
                if ($wfdService.Status -ne 'Stopped' -or $wfdService.StartType -ne 'Disabled') {
                    throw "WFDSConMgrSvc post-apply mismatch: $($wfdService.StartType)/$($wfdService.Status)"
                }
            }

            # 10. Disable WiFi Direct Virtual Adapters (immediate effect)
            $wfdAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                    [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
                })
            if ($wfdAdapters) {
                foreach ($adapter in @($wfdAdapters | Where-Object { $_.Status -ne 'Disabled' })) {
                    Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                    Write-Log -Level INFO -Message "Disabled WiFi Direct adapter: $($adapter.Name)" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                            [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
                        })) {
                    if ([string]$adapter.Status -ne 'Disabled') { throw "Wi-Fi Direct adapter remains enabled: $($adapter.Name)" }
                }
            }
        }

        $requiredValues = @{
            AllowProjectionToPC = 0
            RequirePinForPairing = 2
        }
        if ($DisableCompletely) {
            $requiredValues.AllowProjectionFromPC = 0
            $requiredValues.AllowMdnsAdvertisement = 0
            $requiredValues.AllowMdnsDiscovery = 0
            $requiredValues.AllowProjectionFromPCOverInfrastructure = 0
            $requiredValues.AllowProjectionToPCOverInfrastructure = 0
        }
        $connectKey = Get-Item -LiteralPath $connectPath -ErrorAction Stop
        foreach ($name in $requiredValues.Keys) {
            if ($connectKey.GetValueNames() -notcontains $name -or
                $connectKey.GetValueKind($name).ToString() -ne 'DWord' -or
                [int]$connectKey.GetValue($name) -ne [int]$requiredValues[$name]) {
                throw "Wireless Display registry post-apply mismatch: $name"
            }
        }

        if ($changesApplied -eq 0) {
            Write-Log -Level SUCCESS -Message "Wireless Display security already configured (no changes needed)" -Module "AdvancedSecurity"
        }
        else {
            Write-Log -Level SUCCESS -Message "Wireless Display security applied ($changesApplied changes)" -Module "AdvancedSecurity"
        }
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to apply Wireless Display security: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
