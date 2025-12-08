function Set-DiscoveryProtocolsSecurity {
    <#
    .SYNOPSIS
        Completely hardens discovery protocols (WS-Discovery + mDNS) for air-gapped systems.

    .DESCRIPTION
        This function is designed for the AdvancedSecurity **Maximum** profile.

        It applies the following changes:
        - Disables OS-level mDNS client resolution
        - Stops and disables WS-Discovery related services
        - Adds explicit Windows Firewall BLOCK rules for WS-Discovery and mDNS ports

        Protocols/ports affected:
        - WS-Discovery: UDP 3702, TCP 5357/5358
        - mDNS: UDP 5353

        NOTE: Backup for services, registry and firewall rules is handled centrally by
              Backup-AdvancedSecuritySettings and the Core rollback system.
    
    .PARAMETER DisableCompletely
        When present, applies full discovery protocol hardening. Currently this
        function is only called with -DisableCompletely in Maximum profile.

    .EXAMPLE
        Set-DiscoveryProtocolsSecurity -DisableCompletely
        # Completely disables WS-Discovery and mDNS on this host.
    #>
    [CmdletBinding()]
    param(
        [switch]$DisableCompletely
    )

    try {
        Write-Log -Level INFO -Message "Applying discovery protocol security (WS-Discovery + mDNS)... DisableCompletely: $DisableCompletely" -Module "AdvancedSecurity"

        if (-not $DisableCompletely) {
            Write-Log -Level INFO -Message "Set-DiscoveryProtocolsSecurity called without -DisableCompletely. No changes applied." -Module "AdvancedSecurity"
            return $true
        }

        $changesApplied = 0

        # =============================
        # 1) Disable mDNS via DNS Client parameters
        # =============================
        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

        if (-not (Test-Path $dnsParamsPath)) {
            New-Item -Path $dnsParamsPath -Force | Out-Null
            Write-Log -Level INFO -Message "Created registry key: $dnsParamsPath" -Module "AdvancedSecurity"
        }

        $mdnsProps = Get-ItemProperty -Path $dnsParamsPath -ErrorAction SilentlyContinue
        $currentEnableMdns = if ($mdnsProps) { $mdnsProps.EnableMDNS } else { $null }

        if ($currentEnableMdns -ne 0) {
            New-ItemProperty -Path $dnsParamsPath -Name "EnableMDNS" -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Log -Level INFO -Message "Set EnableMDNS = 0 (Disable OS mDNS resolver)" -Module "AdvancedSecurity"
            $changesApplied++
        }

        # =============================
        # 2) Stop and disable WS-Discovery related services
        # =============================
        $wsdServices = @(
            @{ Name = "FDResPub"; DisplayName = "Function Discovery Resource Publication" },
            @{ Name = "fdPHost";  DisplayName = "Function Discovery Provider Host" }
        )

        foreach ($svc in $wsdServices) {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Log -Level INFO -Message "Service $($svc.Name) not found (may not be installed)" -Module "AdvancedSecurity"
                continue
            }

            if ($service.Status -eq 'Running') {
                try {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Log -Level INFO -Message "Stopped service: $($svc.Name) ($($svc.DisplayName))" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                catch {
                    Write-Log -Level WARNING -Message "Failed to stop service $($svc.Name): $_" -Module "AdvancedSecurity"
                }
            }

            if ($service.StartType -ne 'Disabled') {
                try {
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                    Write-Log -Level INFO -Message "Set service $($svc.Name) StartupType = Disabled" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                catch {
                    Write-Log -Level WARNING -Message "Failed to set StartupType=Disabled for $($svc.Name): $_" -Module "AdvancedSecurity"
                }
            }
        }

        # =============================
        # 3) Add firewall BLOCK rules for WS-Discovery and mDNS
        # =============================
        $firewallRules = @(
            @{ Name = "NoID-Block-WSD-UDP-3702";   DisplayName = "NoID Privacy - Block WS-Discovery UDP 3702"; Protocol = "UDP"; LocalPort = 3702 },
            @{ Name = "NoID-Block-WSD-TCP-5357";   DisplayName = "NoID Privacy - Block WS-Discovery HTTP TCP 5357"; Protocol = "TCP"; LocalPort = 5357 },
            @{ Name = "NoID-Block-WSD-TCP-5358";   DisplayName = "NoID Privacy - Block WS-Discovery HTTPS TCP 5358"; Protocol = "TCP"; LocalPort = 5358 },
            @{ Name = "NoID-Block-mDNS-UDP-5353";  DisplayName = "NoID Privacy - Block mDNS UDP 5353"; Protocol = "UDP"; LocalPort = 5353 }
        )

        foreach ($rule in $firewallRules) {
            try {
                $existing = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-NetFirewallRule -Name $rule.Name `
                        -DisplayName $rule.DisplayName `
                        -Direction Inbound `
                        -Protocol $rule.Protocol `
                        -LocalPort $rule.LocalPort `
                        -Action Block `
                        -Profile Any `
                        -Enabled True | Out-Null
                    Write-Log -Level INFO -Message "Created firewall rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                else {
                    # Ensure rule is enabled and blocking
                    Set-NetFirewallRule -Name $rule.Name -Enabled True -Action Block -ErrorAction SilentlyContinue
                    Write-Log -Level DEBUG -Message "Firewall rule already exists and was enforced: $($rule.DisplayName)" -Module "AdvancedSecurity"
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to ensure firewall rule $($rule.DisplayName): $_" -Module "AdvancedSecurity"
            }
        }

        if ($changesApplied -eq 0) {
            Write-Log -Level SUCCESS -Message "Discovery protocol security already configured (no changes needed)" -Module "AdvancedSecurity"
        }
        else {
            Write-Log -Level SUCCESS -Message "Discovery protocol security applied ($changesApplied changes)" -Module "AdvancedSecurity"
        }

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to apply discovery protocol security (WS-Discovery/mDNS): $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
