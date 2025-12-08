function Set-WirelessDisplaySecurity {
    <#
    .SYNOPSIS
        Hardens Wireless Display (Miracast) settings to prevent screen interception attacks.
    
    .DESCRIPTION
        Configures Windows Wireless Display policies to prevent attackers from:
        - Setting up rogue Miracast receivers to capture your screen
        - Using your PC as an unauthorized display receiver
        - Intercepting screen content via mDNS spoofing
        
        Default (always applied): Blocks receiving projections, requires PIN for pairing
        Full disable: Also blocks sending projections and mDNS discovery
    
    .PARAMETER DisableCompletely
        If specified, completely disables all Wireless Display functionality.
        Default: Only hardens (blocks receiving, requires PIN) but allows sending.
    
    .EXAMPLE
        Set-WirelessDisplaySecurity
        # Applies default hardening (blocks receiving, requires PIN)
    
    .EXAMPLE
        Set-WirelessDisplaySecurity -DisableCompletely
        # Completely disables all Wireless Display functionality
    #>
    [CmdletBinding()]
    param(
        [switch]$DisableCompletely
    )
    
    try {
        Write-Log -Level INFO -Message "Applying Wireless Display security hardening (DisableCompletely: $DisableCompletely)..." -Module "AdvancedSecurity"
        
        $changesApplied = 0
        
        # Registry path for Wireless Display policies
        $connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
        
        # Create key if it doesn't exist
        if (-not (Test-Path $connectPath)) {
            New-Item -Path $connectPath -Force | Out-Null
            Write-Log -Level INFO -Message "Created registry key: $connectPath" -Module "AdvancedSecurity"
        }
        
        # ============================================
        # ALWAYS APPLIED (Default hardening for all profiles)
        # ============================================
        
        # 1. AllowProjectionToPC = 0 (Block receiving projections - prevents rogue receiver attacks)
        $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowProjectionToPC" -ErrorAction SilentlyContinue
        if ($null -eq $currentValue -or $currentValue.AllowProjectionToPC -ne 0) {
            Set-ItemProperty -Path $connectPath -Name "AllowProjectionToPC" -Value 0 -Type DWord -Force
            Write-Log -Level INFO -Message "Set AllowProjectionToPC = 0 (Block receiving)" -Module "AdvancedSecurity"
            $changesApplied++
        }
        
        # 2. RequirePinForPairing = 2 (Always require PIN - prevents unauthorized pairing)
        $currentValue = Get-ItemProperty -Path $connectPath -Name "RequirePinForPairing" -ErrorAction SilentlyContinue
        if ($null -eq $currentValue -or $currentValue.RequirePinForPairing -ne 2) {
            Set-ItemProperty -Path $connectPath -Name "RequirePinForPairing" -Value 2 -Type DWord -Force
            Write-Log -Level INFO -Message "Set RequirePinForPairing = 2 (Always require PIN)" -Module "AdvancedSecurity"
            $changesApplied++
        }
        
        # ============================================
        # OPTIONAL: Complete disable (user choice)
        # ============================================
        
        if ($DisableCompletely) {
            Write-Log -Level INFO -Message "Applying complete Wireless Display disable..." -Module "AdvancedSecurity"
            
            # 3. AllowProjectionFromPC = 0 (Block sending projections)
            $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowProjectionFromPC" -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or $currentValue.AllowProjectionFromPC -ne 0) {
                Set-ItemProperty -Path $connectPath -Name "AllowProjectionFromPC" -Value 0 -Type DWord -Force
                Write-Log -Level INFO -Message "Set AllowProjectionFromPC = 0 (Block sending)" -Module "AdvancedSecurity"
                $changesApplied++
            }
            
            # 4. AllowMdnsAdvertisement = 0 (Don't advertise as receiver)
            $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowMdnsAdvertisement" -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or $currentValue.AllowMdnsAdvertisement -ne 0) {
                Set-ItemProperty -Path $connectPath -Name "AllowMdnsAdvertisement" -Value 0 -Type DWord -Force
                Write-Log -Level INFO -Message "Set AllowMdnsAdvertisement = 0 (No mDNS ads)" -Module "AdvancedSecurity"
                $changesApplied++
            }
            
            # 5. AllowMdnsDiscovery = 0 (Don't discover receivers via mDNS)
            $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowMdnsDiscovery" -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or $currentValue.AllowMdnsDiscovery -ne 0) {
                Set-ItemProperty -Path $connectPath -Name "AllowMdnsDiscovery" -Value 0 -Type DWord -Force
                Write-Log -Level INFO -Message "Set AllowMdnsDiscovery = 0 (No mDNS discovery)" -Module "AdvancedSecurity"
                $changesApplied++
            }
            
            # 6. AllowProjectionFromPCOverInfrastructure = 0 (Block infrastructure projection)
            $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowProjectionFromPCOverInfrastructure" -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or $currentValue.AllowProjectionFromPCOverInfrastructure -ne 0) {
                Set-ItemProperty -Path $connectPath -Name "AllowProjectionFromPCOverInfrastructure" -Value 0 -Type DWord -Force
                Write-Log -Level INFO -Message "Set AllowProjectionFromPCOverInfrastructure = 0" -Module "AdvancedSecurity"
                $changesApplied++
            }
            
            # 7. AllowProjectionToPCOverInfrastructure = 0 (Block infrastructure receiving)
            $currentValue = Get-ItemProperty -Path $connectPath -Name "AllowProjectionToPCOverInfrastructure" -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or $currentValue.AllowProjectionToPCOverInfrastructure -ne 0) {
                Set-ItemProperty -Path $connectPath -Name "AllowProjectionToPCOverInfrastructure" -Value 0 -Type DWord -Force
                Write-Log -Level INFO -Message "Set AllowProjectionToPCOverInfrastructure = 0" -Module "AdvancedSecurity"
                $changesApplied++
            }
            
            # 8. Block Miracast ports via Windows Firewall (7236, 7250)
            $firewallRules = @(
                @{
                    Name = "NoID-Block-Miracast-TCP-7236"
                    DisplayName = "NoID Privacy - Block Miracast TCP 7236"
                    Direction = "Inbound"
                    Protocol = "TCP"
                    LocalPort = 7236
                },
                @{
                    Name = "NoID-Block-Miracast-TCP-7250"
                    DisplayName = "NoID Privacy - Block Miracast TCP 7250"
                    Direction = "Inbound"
                    Protocol = "TCP"
                    LocalPort = 7250
                },
                @{
                    Name = "NoID-Block-Miracast-UDP-7236"
                    DisplayName = "NoID Privacy - Block Miracast UDP 7236"
                    Direction = "Inbound"
                    Protocol = "UDP"
                    LocalPort = 7236
                },
                @{
                    Name = "NoID-Block-Miracast-UDP-7250"
                    DisplayName = "NoID Privacy - Block Miracast UDP 7250"
                    Direction = "Inbound"
                    Protocol = "UDP"
                    LocalPort = 7250
                }
            )
            
            foreach ($rule in $firewallRules) {
                $existingRule = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                if (-not $existingRule) {
                    New-NetFirewallRule -Name $rule.Name `
                        -DisplayName $rule.DisplayName `
                        -Direction $rule.Direction `
                        -Protocol $rule.Protocol `
                        -LocalPort $rule.LocalPort `
                        -Action Block `
                        -Profile Any `
                        -Enabled True | Out-Null
                    Write-Log -Level INFO -Message "Created firewall rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                    $changesApplied++
                }
            }
            
            # 9. Disable WiFi Direct Service (WFDSConMgrSvc) - CRITICAL for complete Miracast block
            # Registry policies alone don't block WiFi Direct P2P discovery!
            $wfdService = Get-Service -Name "WFDSConMgrSvc" -ErrorAction SilentlyContinue
            if ($wfdService) {
                if ($wfdService.Status -eq 'Running') {
                    Stop-Service -Name "WFDSConMgrSvc" -Force -ErrorAction SilentlyContinue
                    Write-Log -Level INFO -Message "Stopped WiFi Direct Service (WFDSConMgrSvc)" -Module "AdvancedSecurity"
                }
                
                if ($wfdService.StartType -ne 'Disabled') {
                    Set-Service -Name "WFDSConMgrSvc" -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log -Level INFO -Message "Disabled WiFi Direct Service (WFDSConMgrSvc) - survives reboot" -Module "AdvancedSecurity"
                    $changesApplied++
                }
            }
            
            # 10. Disable WiFi Direct Virtual Adapters (immediate effect)
            $wfdAdapters = Get-NetAdapter -InterfaceDescription "Microsoft Wi-Fi Direct Virtual*" -IncludeHidden -ErrorAction SilentlyContinue
            if ($wfdAdapters) {
                $wfdAdapters | Where-Object { $_.Status -ne 'Disabled' } | ForEach-Object {
                    Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Log -Level INFO -Message "Disabled WiFi Direct adapter: $($_.Name)" -Module "AdvancedSecurity"
                    $changesApplied++
                }
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
