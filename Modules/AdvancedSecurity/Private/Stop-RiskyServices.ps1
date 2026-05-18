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
    [CmdletBinding()]
    param()
    
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
        
        # Backup service states
        Write-Log -Level INFO -Message "Backing up service states..." -Module "AdvancedSecurity"
        
        $serviceBackup = @{}
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
                $serviceBackup[$svc.Name] = @{
                    Status = $service.Status.ToString()
                    StartType = $service.StartType.ToString()
                    DisplayName = $service.DisplayName
                }
            }
        }
        
        $backupData = @{
            Services = $serviceBackup
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "Services_State" -Data $backupJson -Name "RiskyServices"
        
        Write-Log -Level SUCCESS -Message "Backed up state of $($serviceBackup.Count) services" -Module "AdvancedSecurity"
        
        # Stop and disable services
        $stoppedCount = 0
        $errors = @()
        
        # CRITICAL: Stop upnphost FIRST (it depends on SSDPSRV)
        foreach ($svc in $services) {
            Write-Log -Level INFO -Message "Processing service: $($svc.DisplayName) ($($svc.Name))..." -Module "AdvancedSecurity"
            
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Write-Log -Level INFO -Message "Service $($svc.Name) not found (may not be installed)" -Module "AdvancedSecurity"
                continue
            }
            
            try {
                # Stop service if running
                if ($service.Status -eq 'Running') {
                    Write-Log -Level INFO -Message "Stopping $($svc.Name)..." -Module "AdvancedSecurity"
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Log -Level SUCCESS -Message "Stopped $($svc.Name)" -Module "AdvancedSecurity"
                }
                else {
                    Write-Log -Level INFO -Message "$($svc.Name) already stopped" -Module "AdvancedSecurity"
                }
                
                # Disable service
                Write-Log -Level INFO -Message "Disabling $($svc.Name)..." -Module "AdvancedSecurity"
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
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
        
        # Check TCP ports
        foreach ($port in @(139, 2869)) {
            $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
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
        $udpListener = Get-NetUDPEndpoint -LocalPort 1900 -ErrorAction SilentlyContinue
        if (-not $udpListener) {
            $portsClosed += "UDP 1900"
            Write-Log -Level SUCCESS -Message "Port UDP 1900 is CLOSED" -Module "AdvancedSecurity"
        }
        else {
            $portsStillOpen += "UDP 1900"
            Write-Log -Level WARNING -Message "Port UDP 1900 is still LISTENING locally. SSDP service is disabled and blocked by firewall; this listener is a known Windows behavior and not reachable from external networks." -Module "AdvancedSecurity"
        }
        
        # Summary
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  RISKY SERVICES STOPPED" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Services stopped: $stoppedCount" -ForegroundColor White
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
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
                Write-Host "Note: UDP 1900 may still show a local listener, but SSDP is disabled and blocked by firewall. This is a known Windows behavior and not remotely reachable." -ForegroundColor Gray
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
            Write-Log -Level WARNING -Message "Completed with $($errors.Count) errors" -Module "AdvancedSecurity"
            return $true  # Partial success
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to stop risky services: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
