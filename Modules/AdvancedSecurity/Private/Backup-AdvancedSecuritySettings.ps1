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
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Creating comprehensive backup of Advanced Security settings..." -Module "AdvancedSecurity"
        
        $backupCount = 0
        
        # Start module backup session
        $backupSession = Start-ModuleBackup -ModuleName "AdvancedSecurity"
        
        if (-not $backupSession) {
            Write-Log -Level ERROR -Message "Failed to start backup session" -Module "AdvancedSecurity"
            return $false
        }
        
        # 1. RDP Settings
        Write-Log -Level DEBUG -Message "Backing up RDP settings..." -Module "AdvancedSecurity"
        $rdpBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -BackupName "RDP_Settings"
        if ($rdpBackup) { $backupCount++ }
        
        # CRITICAL: Create JSON backup for RDP (Rollback fallback)
        # .reg import often fails for RDP keys due to permissions, so we need values for PowerShell restore
        try {
            $rdpData = @{}
            
            # System Settings
            $systemPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            if (Test-Path $systemPath) {
                $val = Get-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                if ($val) { $rdpData["System_fDenyTSConnections"] = $val.fDenyTSConnections }
            }
            
            # Policy Settings
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (Test-Path $policyPath) {
                $val1 = Get-ItemProperty -Path $policyPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
                if ($val1) { $rdpData["Policy_UserAuthentication"] = $val1.UserAuthentication }
                
                $val2 = Get-ItemProperty -Path $policyPath -Name "SecurityLayer" -ErrorAction SilentlyContinue
                if ($val2) { $rdpData["Policy_SecurityLayer"] = $val2.SecurityLayer }
            }
            
            if ($rdpData.Count -gt 0) {
                $rdpJson = $rdpData | ConvertTo-Json
                $rdpJsonBackup = Register-Backup -Type "AdvancedSecurity" -Data $rdpJson -Name "RDP_Hardening"
                if ($rdpJsonBackup) { 
                    Write-Log -Level DEBUG -Message "Created RDP JSON backup for rollback fallback" -Module "AdvancedSecurity"
                    $backupCount++ 
                }
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to create RDP JSON backup: $_" -Module "AdvancedSecurity"
        }
        
        # 2. WDigest Settings
        Write-Log -Level DEBUG -Message "Backing up WDigest settings..." -Module "AdvancedSecurity"
        $wdigestBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -BackupName "WDigest_Settings"
        if ($wdigestBackup) { $backupCount++ }

        # Discovery Protocol Settings (mDNS resolver)
        Write-Log -Level DEBUG -Message "Backing up discovery protocol settings (mDNS)" -Module "AdvancedSecurity"
        $mdnsBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -BackupName "DiscoveryProtocols_DnscacheParameters"
        if ($mdnsBackup) { $backupCount++ }
        
        # 3. Admin Shares Settings
        Write-Log -Level DEBUG -Message "Backing up Admin Shares settings..." -Module "AdvancedSecurity"
        $adminSharesBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -BackupName "AdminShares_Settings"
        if ($adminSharesBackup) { $backupCount++ }
        
        # 4. TLS Settings
        Write-Log -Level DEBUG -Message "Backing up TLS settings..." -Module "AdvancedSecurity"
        $tlsVersions = @("TLS 1.0", "TLS 1.1")
        $components = @("Server", "Client")
        
        foreach ($version in $tlsVersions) {
            foreach ($component in $components) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"
                $tlsBackup = Backup-RegistryKey -KeyPath $regPath -BackupName "TLS_${version}_${component}".Replace(" ", "_").Replace(".", "")
                if ($tlsBackup) { $backupCount++ }
            }
        }
        
        # 5. WPAD Settings (3 paths: WinHttp for official MS key, Wpad for legacy, Internet Settings for AutoDetect)
        Write-Log -Level DEBUG -Message "Backing up WPAD settings..." -Module "AdvancedSecurity"
        
        $wpadPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",  # Official MS DisableWpad key
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",     # Legacy WpadOverride
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"           # AutoDetect
        )
        
        foreach ($wpadPath in $wpadPaths) {
            $pathName = $wpadPath.Split('\')[-1]
            $wpadBackup = Backup-RegistryKey -KeyPath $wpadPath -BackupName "WPAD_${pathName}"
            if ($wpadBackup) { $backupCount++ }
        }
        
        # CRITICAL: Create JSON backup for WPAD (Rollback fallback) - all paths combined
        try {
            $wpadData = @{}
            
            foreach ($wpadPath in $wpadPaths) {
                if (Test-Path $wpadPath) {
                    $wpadProps = Get-ItemProperty -Path $wpadPath -ErrorAction SilentlyContinue
                    
                    # Capture all relevant properties in format expected by Rollback.ps1
                    # Format: "FullPath\ValueName" = Value
                    foreach ($prop in $wpadProps.PSObject.Properties) {
                        if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
                            $fullKey = "$wpadPath\$($prop.Name)"
                            $wpadData[$fullKey] = $prop.Value
                        }
                    }
                }
            }
            
            if ($wpadData.Count -gt 0) {
                $wpadJson = $wpadData | ConvertTo-Json
                $wpadJsonBackup = Register-Backup -Type "AdvancedSecurity" -Data $wpadJson -Name "WPAD"
                if ($wpadJsonBackup) {
                    Write-Log -Level DEBUG -Message "Created WPAD JSON backup for rollback fallback ($($wpadData.Count) values)" -Module "AdvancedSecurity"
                    $backupCount++
                }
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to create WPAD JSON backup: $_" -Module "AdvancedSecurity"
        }
        
        # 6. Services (including WiFi Direct for Wireless Display and WS-Discovery)
        Write-Log -Level DEBUG -Message "Backing up risky services state..." -Module "AdvancedSecurity"
        # Note: Computer Browser (Browser) is deprecated in Win10/11 - not included
        $services = @("SSDPSRV", "upnphost", "lmhosts", "WFDSConMgrSvc", "FDResPub", "fdPHost")
        
        foreach ($svc in $services) {
            $svcBackup = Backup-ServiceConfiguration -ServiceName $svc
            if ($svcBackup) { $backupCount++ }
        }
        
        # 7. PowerShell v2 Feature State
        Write-Log -Level DEBUG -Message "Backing up PowerShell v2 feature state..." -Module "AdvancedSecurity"
        
        # Canonical detection: use Windows Optional Feature state
        $psv2Feature = $null
        try {
            $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
        }
        catch {
            $psv2Feature = $null
        }
        
        if (-not $psv2Feature -or $psv2Feature.State -ne 'Enabled') {
            # Feature not present or not enabled – nothing to back up
            Write-Log -Level INFO -Message "PowerShell v2 optional feature not enabled/present - skipping feature backup" -Module "AdvancedSecurity"
        }
        else {
            $psv2Data = @{
                FeatureName     = $psv2Feature.FeatureName
                State           = $psv2Feature.State
                DetectionMethod = "WindowsOptionalFeature"
                BackupDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            } | ConvertTo-Json
            
            $psv2Backup = Register-Backup -Type "WindowsFeature" -Data $psv2Data -Name "PowerShellV2"
            if ($psv2Backup) { $backupCount++ }
        }
        
        # 8. Firewall Rules Snapshot
        Write-Host ""
        Write-Host "  ============================================" -ForegroundColor Cyan
        Write-Host "  FIREWALL RULES BACKUP - PLEASE WAIT" -ForegroundColor Cyan
        Write-Host "  ============================================" -ForegroundColor Cyan
        Write-Host "  Creating snapshot for risky ports..." -ForegroundColor White
        Write-Host "  Ports: 79, 137-139, 1900, 2869, 5355, 3702, 5353, 5357, 5358" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [!] This operation takes 60-120 seconds" -ForegroundColor Yellow
        Write-Host "  System is working - do not interrupt!" -ForegroundColor Yellow
        Write-Host "  ============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Log -Level INFO -Message "Backing up firewall rules snapshot for risky ports (79, 137, 138, 139, 1900, 2869, 5355, 3702, 5353, 5357, 5358)..." -Module "AdvancedSecurity"
        $firewallRules = Get-NetFirewallRule | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter
            (($portFilter.LocalPort -in @(79, 137, 138, 139, 1900, 2869, 5355, 3702, 5353, 5357, 5358)) -or 
            ($portFilter.RemotePort -in @(79, 137, 138, 139, 1900, 2869, 5355, 3702, 5353, 5357, 5358))) -and
            ($_.Direction -eq 'Inbound' -or $_.Direction -eq 'Outbound')
        } | Select-Object Name, DisplayName, Enabled, Direction, Action
        
        $firewallData = @{
            Rules      = $firewallRules
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RuleCount  = $firewallRules.Count
        } | ConvertTo-Json -Depth 10
        
        $firewallBackup = Register-Backup -Type "Firewall_Rules" -Data $firewallData -Name "RiskyPorts_Firewall"
        if ($firewallBackup) { $backupCount++ }
        
        Write-Host "  [OK] Firewall rules backup completed ($($firewallRules.Count) rules processed)" -ForegroundColor Green
        Write-Host ""
        
        # 9. SMB Shares Snapshot
        Write-Log -Level DEBUG -Message "Backing up SMB shares snapshot..." -Module "AdvancedSecurity"
        
        # Check if LanmanServer service is running (required for Get-SmbShare)
        $serverService = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
        if (-not $serverService -or $serverService.Status -ne 'Running') {
            Write-Log -Level INFO -Message "LanmanServer service is not running - no SMB shares to backup" -Module "AdvancedSecurity"
            $adminShares = @()
        }
        else {
            try {
                $adminShares = Get-SmbShare | Where-Object { $_.Name -match '^[A-Z]\$$|^ADMIN\$$' } | 
                    Select-Object Name, Path, Description
            }
            catch {
                Write-Log -Level INFO -Message "Could not query SMB shares: $($_.Exception.Message)" -Module "AdvancedSecurity"
                $adminShares = @()
            }
        }
        
        $sharesData = @{
            Shares     = $adminShares
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ShareCount = $adminShares.Count
        } | ConvertTo-Json -Depth 10
        
        $sharesBackup = Register-Backup -Type "SMB_Shares" -Data $sharesData -Name "AdminShares"
        if ($sharesBackup) { $backupCount++ }

        $netbiosAdapters = @()
        try {
            $netbiosAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue
        }
        catch {
            $netbiosAdapters = @()
        }
        if ($netbiosAdapters) {
            $netbiosSnapshot = @()
            foreach ($adapter in $netbiosAdapters) {
                $netbiosSnapshot += [PSCustomObject]@{
                    Description         = $adapter.Description
                    Index               = $adapter.Index
                    TcpipNetbiosOptions = $adapter.TcpipNetbiosOptions
                }
            }
            if ($netbiosSnapshot.Count -gt 0) {
                $netbiosJson = $netbiosSnapshot | ConvertTo-Json -Depth 5
                $netbiosBackup = Register-Backup -Type "AdvancedSecurity" -Data $netbiosJson -Name "NetBIOS_Adapters"
                if ($netbiosBackup) { $backupCount++ }
            }
        }
        
        # 10. Windows Update Settings (3 simple GUI settings)
        Write-Log -Level DEBUG -Message "Backing up Windows Update settings..." -Module "AdvancedSecurity"
        
        # Setting 1: Get latest updates immediately
        $wuUXBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -BackupName "WindowsUpdate_UX_Settings"
        if ($wuUXBackup) { $backupCount++ }

        # Setting 1 Policy: Windows Update optional content/config updates
        $wuPoliciesBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -BackupName "WindowsUpdate_Policies"
        if ($wuPoliciesBackup) { $backupCount++ }
        
        # Setting 2: Microsoft Update for other products (moved to UX\Settings - same as Setting 1)
        # No separate backup needed - already backed up in WindowsUpdate_UX_Settings
        
        # Setting 3: Delivery Optimization
        $wuDOBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -BackupName "WindowsUpdate_DeliveryOptimization"
        if ($wuDOBackup) { $backupCount++ }
        
        # 11. SRP (Software Restriction Policies) Settings
        Write-Log -Level DEBUG -Message "Backing up SRP settings..." -Module "AdvancedSecurity"
        $srpBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -BackupName "SRP_Settings"
        if ($srpBackup) { $backupCount++ }
        
        # 12. CRITICAL: Create comprehensive JSON Pre-State Snapshot (counter Registry tattooing)
        # This captures EXACT state of ALL AdvancedSecurity registry keys before hardening
        Write-Log -Level INFO -Message "Creating AdvancedSecurity registry pre-state snapshot (JSON)..." -Module "AdvancedSecurity"
        $preStateSnapshot = @()
        
        # All registry keys that AdvancedSecurity modifies
        $allAdvSecKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",  # Official MS DisableWpad key
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",     # Legacy WpadOverride
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",          # AutoDetect
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect",  # Wireless Display / Miracast
            "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",  # Firewall Shields Up
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"  # IPv6 disable (mitm6 mitigation)
        )
        
        foreach ($keyPath in $allAdvSecKeys) {
            if (Test-Path $keyPath) {
                try {
                    # Get all properties for this key
                    $properties = Get-ItemProperty -Path $keyPath -ErrorAction Stop
                    $propertyNames = $properties.PSObject.Properties.Name | Where-Object { 
                        $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') 
                    }
                    
                    foreach ($propName in $propertyNames) {
                        $propValue = $properties.$propName
                        
                        # Get value type
                        try {
                            $propType = (Get-Item $keyPath).GetValueKind($propName)
                        }
                        catch {
                            $propType = "String"  # Default fallback
                        }
                        
                        $preStateSnapshot += [PSCustomObject]@{
                            Path = $keyPath
                            Name = $propName
                            Value = $propValue
                            Type = $propType.ToString()
                            Exists = $true
                        }
                    }
                }
                catch {
                    Write-Log -Level DEBUG -Message "Could not read properties from $keyPath : $_" -Module "AdvancedSecurity"
                }
            }
            # If key doesn't exist, we don't add it to snapshot (only existing values are tracked)
        }
        
        # Save JSON snapshot
        try {
            $snapshotJson = $preStateSnapshot | ConvertTo-Json -Depth 5
            $result = Register-Backup -Type "AdvancedSecurity" -Data $snapshotJson -Name "AdvancedSecurity_PreState"
            if ($result) {
                $backupCount++
                Write-Log -Level SUCCESS -Message "AdvancedSecurity pre-state snapshot created ($($preStateSnapshot.Count) registry values)" -Module "AdvancedSecurity"
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to create AdvancedSecurity pre-state snapshot: $_" -Module "AdvancedSecurity"
        }
        
        Write-Log -Level SUCCESS -Message "Advanced Security backup completed: $backupCount items backed up" -Module "AdvancedSecurity"
        
        return $backupCount
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to backup Advanced Security settings: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
