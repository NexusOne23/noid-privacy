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

    .PARAMETER SkipFirewallChanges
        Applies the registry and service hardening without creating or enforcing
        Windows Firewall rules.

    .EXAMPLE
        Set-DiscoveryProtocolsSecurity -DisableCompletely
        # Completely disables WS-Discovery and mDNS on this host.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$DisableCompletely,
        [switch]$SkipFirewallChanges
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set DiscoveryProtocolsSecurity')) {
        return
    }


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

        # The targeted registry pre-state was sealed before Apply.
        if (-not (Test-Path $dnsParamsPath)) {
            New-Item -Path $dnsParamsPath -Force -ErrorAction Stop | Out-Null
            Write-Log -Level INFO -Message "Created registry key: $dnsParamsPath" -Module "AdvancedSecurity"
        }

        Remove-ItemProperty -LiteralPath $dnsParamsPath -Name 'EnableMDNS' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $dnsParamsPath -Name 'EnableMDNS' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level INFO -Message "Set EnableMDNS = 0 (Disable OS mDNS resolver)" -Module "AdvancedSecurity"
        $changesApplied++

        # =============================
        # 2) Stop and disable WS-Discovery related services
        # =============================
        $wsdServices = @(
            @{ Name = "FDResPub"; DisplayName = "Function Discovery Resource Publication" },
            @{ Name = "fdPHost";  DisplayName = "Function Discovery Provider Host" }
        )

        $installedServices = @(Get-Service -ErrorAction Stop)
        foreach ($svc in $wsdServices) {
            $serviceMatches = @($installedServices | Where-Object { [string]$_.Name -eq [string]$svc.Name })
            if ($serviceMatches.Count -gt 1) {
                throw "Discovery service identity is ambiguous: $($svc.Name)"
            }
            if ($serviceMatches.Count -eq 0) {
                Write-Log -Level INFO -Message "Service $($svc.Name) not found (may not be installed)" -Module "AdvancedSecurity"
                continue
            }
            $service = $serviceMatches[0]

            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
                Write-Log -Level INFO -Message "Stopped service: $($svc.Name) ($($svc.DisplayName))" -Module "AdvancedSecurity"
                $changesApplied++
            }

            if ($service.StartType -ne 'Disabled') {
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Log -Level INFO -Message "Set service $($svc.Name) StartupType = Disabled" -Module "AdvancedSecurity"
                $changesApplied++
            }
            $service = Get-Service -Name $svc.Name -ErrorAction Stop
            if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') {
                throw "Discovery service post-apply mismatch for $($svc.Name): $($service.StartType)/$($service.Status)"
            }
        }

        # =============================
        # 3) Add firewall BLOCK rules for WS-Discovery and mDNS
        # =============================
        $firewallRules = @(Get-AdvancedSecurityFirewallDefinitions -Feature Discovery)
        if ($firewallRules.Count -ne 4) { throw "Expected four canonical discovery firewall rules, found $($firewallRules.Count)" }

        if ($SkipFirewallChanges) {
            Write-Log -Level INFO -Message "Discovery-protocol firewall rules skipped by explicit firewall-layer choice" -Module "AdvancedSecurity"
        }
        else {
            foreach ($rule in $firewallRules) {
                try {
                    $null = Set-AdvancedSecurityFirewallRuleDefinition -Definition $rule
                    Write-Log -Level INFO -Message "Recreated and verified exact firewall rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                    $changesApplied++
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to ensure firewall rule $($rule.DisplayName): $_" -Module "AdvancedSecurity" -Exception $_.Exception
                    throw
                }
            }
        }

        $dnsKey = Get-Item -LiteralPath $dnsParamsPath -ErrorAction Stop
        if ($dnsKey.GetValueKind('EnableMDNS').ToString() -ne 'DWord' -or [int]$dnsKey.GetValue('EnableMDNS') -ne 0) {
            throw 'EnableMDNS post-apply type/value mismatch'
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
