function Disable-RiskyPorts {
    <#
    .SYNOPSIS
        Disable risky firewall ports (LLMNR, NetBIOS, UPnP/SSDP)
    
    .DESCRIPTION
        Closes firewall ports that are commonly exploited for MITM attacks,
        network enumeration, and credential theft:
        
        - LLMNR (Port 5355) - HIGH RISK: Responder poisoning, credential theft
        - NetBIOS (Port 137-139) - MEDIUM RISK: Network enumeration
        - UPnP/SSDP (Port 1900, 2869) - MEDIUM RISK: Port forwarding vulnerabilities
        
        Uses language-independent port-based filtering to avoid DisplayName issues.
    
    .PARAMETER SkipUPnP
        Skip disabling UPnP/SSDP ports (for users who need DLNA/media streaming)
    
    .EXAMPLE
        Disable-RiskyPorts
        Disables all risky firewall ports including UPnP
    
    .EXAMPLE
        Disable-RiskyPorts -SkipUPnP
        Disables LLMNR and NetBIOS but keeps UPnP enabled
    
    .NOTES
        Defense in Depth: Security Baseline disables protocols via registry,
        but firewall rules may still be active. This function closes the ports
        at the firewall level for additional protection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$SkipUPnP
    )
    
    try {
        Write-Log -Level INFO -Message "Disabling risky firewall ports..." -Module "AdvancedSecurity"
        
        $disabledRules = 0
        $errors = @()
        
        # PERFORMANCE FIX: Batch query instead of per-rule queries
        # Old approach: foreach { Get-NetFirewallPortFilter } = 300+ queries × 200ms = 60s+
        # New approach: Get all port filters once via hashtable = 2-5s total
        Write-Log -Level INFO -Message "Loading firewall rules for analysis..." -Module "AdvancedSecurity"
        $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq $true }
        
        # Get all port filters in one batch query and build hashtable by InstanceID
        $allPortFilters = @{}
        Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $allPortFilters[$_.InstanceID] = $_
        }
        
        # Build cache with fast hashtable lookup
        $rulesWithPorts = @()
        foreach ($rule in $allRules) {
            $portFilter = $allPortFilters[$rule.InstanceID]
            if ($portFilter) {
                $rulesWithPorts += [PSCustomObject]@{
                    Rule       = $rule
                    LocalPort  = $portFilter.LocalPort
                    RemotePort = $portFilter.RemotePort
                }
            }
        }
        
        Write-Log -Level INFO -Message "Analyzed $($rulesWithPorts.Count) firewall rules with port filters" -Module "AdvancedSecurity"
        
        # Backup firewall rules
        Write-Log -Level INFO -Message "Backing up firewall rules..." -Module "AdvancedSecurity"
        $backupData = @{
            FirewallRules = $allRules | Select-Object Name, DisplayName, Enabled, Direction, Action
            BackupDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "Firewall_Rules" -Data $backupJson -Name "RiskyPorts_Firewall"
        
        # 1. LLMNR (Port 5355 UDP) - HIGH RISK
        Write-Log -Level INFO -Message "Disabling LLMNR firewall rules (Port 5355)..." -Module "AdvancedSecurity"
        
        try {
            # Filter from pre-loaded cache (ONLY ALLOW rules - keep NoID block rules enabled)
            $llmnrRules = $rulesWithPorts | Where-Object {
                ($_.LocalPort -eq 5355 -or $_.RemotePort -eq 5355) -and $_.Rule.Action -eq 'Allow'
            } | Select-Object -ExpandProperty Rule
            
            foreach ($rule in $llmnrRules) {
                Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                Write-Log -Level DEBUG -Message "Disabled LLMNR rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                $disabledRules++
            }
            
            if ($llmnrRules.Count -eq 0) {
                Write-Log -Level INFO -Message "No active LLMNR rules found (already disabled or not present)" -Module "AdvancedSecurity"
            }
            else {
                Write-Log -Level SUCCESS -Message "Disabled $($llmnrRules.Count) LLMNR firewall rules" -Module "AdvancedSecurity"
            }
        }
        catch {
            $errors += "LLMNR: $_"
            Write-Log -Level WARNING -Message "Failed to disable some LLMNR rules: $_" -Module "AdvancedSecurity"
        }
        
        # 2. NetBIOS (Port 137-139) - MEDIUM RISK
        Write-Log -Level INFO -Message "Disabling NetBIOS firewall rules (Port 137-139)..." -Module "AdvancedSecurity"
        
        try {
            # Filter from pre-loaded cache (ONLY ALLOW rules - keep NoID block rules enabled)
            $netbiosRules = $rulesWithPorts | Where-Object {
                ($_.LocalPort -in @(137, 138, 139)) -or ($_.RemotePort -in @(137, 138, 139))
            } | Where-Object { $_.Rule.Action -eq 'Allow' } | Select-Object -ExpandProperty Rule
            
            foreach ($rule in $netbiosRules) {
                Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                Write-Log -Level DEBUG -Message "Disabled NetBIOS rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                $disabledRules++
            }
            
            if ($netbiosRules.Count -eq 0) {
                Write-Log -Level INFO -Message "No active NetBIOS rules found (already disabled or not present)" -Module "AdvancedSecurity"
            }
            else {
                Write-Log -Level SUCCESS -Message "Disabled $($netbiosRules.Count) NetBIOS firewall rules" -Module "AdvancedSecurity"
            }
        }
        catch {
            $errors += "NetBIOS: $_"
            Write-Log -Level WARNING -Message "Failed to disable some NetBIOS rules: $_" -Module "AdvancedSecurity"
        }
        
        # Also disable NetBIOS over TCP/IP on all network adapters
        Write-Log -Level INFO -Message "Disabling NetBIOS over TCP/IP on all adapters..." -Module "AdvancedSecurity"
        
        try {
            $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
            $adaptedCount = 0
            
            foreach ($adapter in $adapters) {
                try {
                    $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2 }
                    if ($result.ReturnValue -eq 0) {
                        Write-Log -Level DEBUG -Message "Disabled NetBIOS on adapter: $($adapter.Description)" -Module "AdvancedSecurity"
                        $adaptedCount++
                    }
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not disable NetBIOS on adapter $($adapter.Description): $_" -Module "AdvancedSecurity"
                }
            }
            
            Write-Log -Level SUCCESS -Message "Disabled NetBIOS over TCP/IP on $adaptedCount adapters" -Module "AdvancedSecurity"
        }
        catch {
            $errors += "NetBIOS TCP/IP: $_"
            Write-Log -Level WARNING -Message "Failed to disable NetBIOS over TCP/IP: $_" -Module "AdvancedSecurity"
        }
        
        # 3. UPnP/SSDP (Port 1900, 2869) - MEDIUM RISK (conditional)
        if (-not $SkipUPnP) {
            Write-Log -Level INFO -Message "Disabling UPnP/SSDP firewall rules (Port 1900, 2869)..." -Module "AdvancedSecurity"
            
            try {
                # Filter from pre-loaded cache (ONLY ALLOW rules - keep NoID block rules enabled)
                $upnpRules = $rulesWithPorts | Where-Object {
                    ($_.LocalPort -in @(1900, 2869)) -or ($_.RemotePort -in @(1900, 2869))
                } | Where-Object { $_.Rule.Action -eq 'Allow' } | Select-Object -ExpandProperty Rule
            
                foreach ($rule in $upnpRules) {
                    Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                    Write-Log -Level DEBUG -Message "Disabled UPnP/SSDP rule: $($rule.DisplayName)" -Module "AdvancedSecurity"
                    $disabledRules++
                }
            
                if ($upnpRules.Count -eq 0) {
                    Write-Log -Level INFO -Message "No active UPnP/SSDP rules found (already disabled or not present)" -Module "AdvancedSecurity"
                }
                else {
                    Write-Log -Level SUCCESS -Message "Disabled $($upnpRules.Count) UPnP/SSDP firewall rules" -Module "AdvancedSecurity"
                }
            }
            catch {
                $errors += "UPnP/SSDP: $_"
                Write-Log -Level WARNING -Message "Failed to disable some UPnP/SSDP rules: $_" -Module "AdvancedSecurity"
            }
            
            # Ensure a dedicated inbound block rule exists for SSDP (UDP 1900)
            try {
                $ssdpRuleName = "NoID Privacy - Block SSDP (UDP 1900)"
                $existingSsdpRule = Get-NetFirewallRule -DisplayName $ssdpRuleName -ErrorAction SilentlyContinue
                
                if (-not $existingSsdpRule) {
                    New-NetFirewallRule -DisplayName $ssdpRuleName `
                        -Direction Inbound `
                        -Action Block `
                        -Enabled True `
                        -Protocol UDP `
                        -LocalPort 1900 `
                        -Profile Any `
                        -ErrorAction Stop | Out-Null
                    Write-Log -Level SUCCESS -Message "Created SSDP block rule: $ssdpRuleName" -Module "AdvancedSecurity"
                }
                else {
                    Write-Log -Level INFO -Message "SSDP block rule already exists: $ssdpRuleName" -Module "AdvancedSecurity"
                }
            }
            catch {
                $errors += "SSDP BlockRule: $_"
                Write-Log -Level WARNING -Message "Failed to ensure SSDP block rule: $_" -Module "AdvancedSecurity"
            }
        }
        else {
            Write-Log -Level INFO -Message "UPnP/SSDP blocking skipped (user choice for DLNA compatibility)" -Module "AdvancedSecurity"
        }
        
        # Summary
        if ($errors.Count -eq 0) {
            if ($disabledRules -gt 0) {
                Write-Log -Level SUCCESS -Message "Disabled $disabledRules risky firewall rules" -Module "AdvancedSecurity"
            }
            else {
                Write-Log -Level SUCCESS -Message "No risky firewall rules required changes (system already protected at firewall level)" -Module "AdvancedSecurity"
            }
            Write-Host ""
            Write-Host "Risky Firewall Ports Disabled: $disabledRules rules" -ForegroundColor Green
            if ($disabledRules -eq 0) {
                Write-Host "  System already protected - no risky ALLOW rules were found for these ports:" -ForegroundColor Gray
            }
            Write-Host "  - LLMNR (5355)" -ForegroundColor Gray
            Write-Host "  - NetBIOS (137-139)" -ForegroundColor Gray
            if (-not $SkipUPnP) {
                Write-Host "  - UPnP/SSDP (1900, 2869)" -ForegroundColor Gray
            }
            else {
                Write-Host "  - UPnP/SSDP (1900, 2869) - SKIPPED" -ForegroundColor Yellow
            }
            Write-Host ""
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "Completed with $($errors.Count) errors. Disabled $disabledRules rules." -Module "AdvancedSecurity"
            return $true  # Partial success is still success
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable risky ports: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
