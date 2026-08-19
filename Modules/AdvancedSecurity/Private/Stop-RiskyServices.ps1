function Stop-RiskyServices {
    <#
    .SYNOPSIS
        Stop and disable risky network services

    .DESCRIPTION
        Stops and disables network services that pose security risks:

        - SSDPSRV (SSDP Discovery) - Port 1900 UDP
        - upnphost (UPnP Device Host) - Port 2869 TCP
        - lmhosts (TCP/IP NetBIOS Helper) - Port 139 TCP

        Defense in Depth: Firewall blocks external access, but services
        still run and listen locally. Stopping services completely closes ports.

        Service Dependencies:
        upnphost depends on SSDPSRV, so upnphost must be stopped FIRST.

    .EXAMPLE
        Stop-RiskyServices
        Stops all risky network services

    .NOTES
        Impact:
        - Smart home device auto-discovery may not work
        - DLNA/casting features may require manual configuration
        - NetBIOS name resolution disabled (already disabled via registry)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$SkipUPnP
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Stop RiskyServices')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Stopping risky network services..." -Module "AdvancedSecurity"

        $services = @(
            @{
                Name = "upnphost"
                DisplayName = "UPnP Device Host"
                Port = 2869
                Protocol = "TCP"
                Risk = "MEDIUM"
                Impact = "DLNA/casting features may require manual configuration"
            },
            @{
                Name = "SSDPSRV"
                DisplayName = "SSDP Discovery"
                Port = 1900
                Protocol = "UDP"
                Risk = "MEDIUM"
                Impact = "Smart home device auto-discovery may not work"
            },
            @{
                Name = "lmhosts"
                DisplayName = "TCP/IP NetBIOS Helper"
                Port = 139
                Protocol = "TCP"
                Risk = "MEDIUM"
                Impact = "NetBIOS name resolution disabled"
            }
            # Note: Computer Browser (Browser) service is DEPRECATED in Win10/11
            # It's tied to SMB1 which is not installed by default
            # Removing from list to avoid errors on modern systems
        )
        if ($SkipUPnP) {
            $services = @($services | Where-Object { $_.Name -eq 'lmhosts' })
            Write-Log -Level INFO -Message 'UPnP/SSDP services preserved by explicit user choice; only lmhosts is disabled' -Module 'AdvancedSecurity'
        }

        # Stop and disable services
        $stoppedCount = 0
        $errors = @()
        $serviceInventory = @(Get-Service -ErrorAction Stop)

        # CRITICAL: Stop upnphost FIRST (it depends on SSDPSRV)
        foreach ($svc in $services) {
            Write-Log -Level INFO -Message "Processing service: $($svc.DisplayName) ($($svc.Name))..." -Module "AdvancedSecurity"

            $serviceMatches = @($serviceInventory | Where-Object { [string]$_.Name -eq [string]$svc.Name })
            if ($serviceMatches.Count -gt 1) { throw "Service inventory is ambiguous: $($svc.Name)" }
            if ($serviceMatches.Count -eq 0) {
                Write-Log -Level INFO -Message "Service $($svc.Name) not found (may not be installed)" -Module "AdvancedSecurity"
                continue
            }
            $service = $serviceMatches[0]

            try {
                # Stop service if running
                if ($service.Status -eq 'Running') {
                    Write-Log -Level INFO -Message "Stopping $($svc.Name)..." -Module "AdvancedSecurity"
                    # Do not use -Force: it could stop dependent services whose
                    # runtime state is outside this sealed BAVR artifact set.
                    Stop-Service -Name $svc.Name -ErrorAction Stop
                    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
                    Write-Log -Level SUCCESS -Message "Stopped $($svc.Name)" -Module "AdvancedSecurity"
                }
                else {
                    Write-Log -Level INFO -Message "$($svc.Name) already stopped" -Module "AdvancedSecurity"
                }

                # Disable service
                Write-Log -Level INFO -Message "Disabling $($svc.Name)..." -Module "AdvancedSecurity"
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                $service = Get-Service -Name $svc.Name -ErrorAction Stop
                if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') {
                    throw "Service post-apply mismatch: $($service.StartType)/$($service.Status)"
                }
                Write-Log -Level SUCCESS -Message "Disabled $($svc.Name) (StartupType = Disabled)" -Module "AdvancedSecurity"

                $stoppedCount++
            }
            catch {
                $errors += "$($svc.Name): $_"
                Write-Log -Level WARNING -Message "Failed to stop/disable $($svc.Name): $_" -Module "AdvancedSecurity"
            }
        }

        # Verify ports are closed
        Write-Log -Level INFO -Message "Verifying ports are closed..." -Module "AdvancedSecurity"

        Start-Sleep -Seconds 2  # Give services time to fully stop

        $portsClosed = @()
        $portsStillOpen = @()
        $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $udpListeners = @(Get-NetUDPEndpoint -ErrorAction Stop)

        # Check TCP ports
        $tcpPortsToObserve = if ($SkipUPnP) { @(139) } else { @(139, 2869) }
        foreach ($port in $tcpPortsToObserve) {
            $listener = @($tcpListeners | Where-Object { [int]$_.LocalPort -eq $port })
            if (-not $listener) {
                $portsClosed += "TCP $port"
                Write-Log -Level SUCCESS -Message "Port TCP $port is CLOSED" -Module "AdvancedSecurity"
            }
            else {
                $portsStillOpen += "TCP $port"
                Write-Log -Level WARNING -Message "Port TCP $port is still LISTENING!" -Module "AdvancedSecurity"
            }
        }

        # Check UDP port 1900
        if (-not $SkipUPnP) {
            $udpListener = @($udpListeners | Where-Object { [int]$_.LocalPort -eq 1900 })
            if (-not $udpListener) {
                $portsClosed += "UDP 1900"
                Write-Log -Level SUCCESS -Message "Port UDP 1900 is CLOSED" -Module "AdvancedSecurity"
            }
            else {
                $portsStillOpen += "UDP 1900"
                Write-Log -Level WARNING -Message "UDP 1900 is still listening locally; service state is verified separately and reachability is not inferred from the listener alone" -Module "AdvancedSecurity"
            }
        }

        # Summary
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  RISKY SERVICES STOPPED" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Services stopped: $stoppedCount" -ForegroundColor White
        $serviceSummaryInventory = @(Get-Service -ErrorAction Stop)
        foreach ($svc in $services) {
            $serviceMatches = @($serviceSummaryInventory | Where-Object { [string]$_.Name -eq [string]$svc.Name })
            if ($serviceMatches.Count -gt 1) { throw "Service summary inventory is ambiguous: $($svc.Name)" }
            if ($serviceMatches.Count -eq 1) {
                $service = $serviceMatches[0]
                $status = if ($service.Status -eq 'Stopped') { "STOPPED" } else { $service.Status }
                $startType = $service.StartType
                Write-Host "  $($svc.DisplayName): $status (StartType: $startType)" -ForegroundColor Gray
            }
        }
        Write-Host ""
        Write-Host "Ports closed: $($portsClosed.Count)" -ForegroundColor White
        foreach ($port in $portsClosed) {
            Write-Host "  $port" -ForegroundColor Green
        }

        if ($portsStillOpen.Count -gt 0) {
            Write-Host ""
            Write-Host "Ports still open: $($portsStillOpen.Count)" -ForegroundColor Yellow
            foreach ($port in $portsStillOpen) {
                Write-Host "  $port" -ForegroundColor Yellow
            }
            if ($portsStillOpen -contains "UDP 1900") {
                Write-Host ""
                Write-Host "Note: a listener alone does not prove remote reachability; service and firewall verification are reported separately." -ForegroundColor Gray
            }
        }

        if ($errors.Count -gt 0) {
            Write-Host ""
            Write-Host "Errors: $($errors.Count)" -ForegroundColor Red
            foreach ($errorMsg in $errors) {
                Write-Host "  $errorMsg" -ForegroundColor Red
            }
        }

        Write-Host ""

        if ($errors.Count -eq 0) {
            Write-Log -Level SUCCESS -Message "All risky services stopped and disabled successfully" -Module "AdvancedSecurity"
            return $true
        }
        else {
            Write-Log -Level ERROR -Message "Risky-service hardening failed with $($errors.Count) error(s)" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to stop risky services: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
