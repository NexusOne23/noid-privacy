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
        
        # 2. WDigest Settings
        Write-Log -Level DEBUG -Message "Backing up WDigest settings..." -Module "AdvancedSecurity"
        $wdigestBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -BackupName "WDigest_Settings"
        if ($wdigestBackup) { $backupCount++ }
        
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
        
        # 5. WPAD Settings
        Write-Log -Level DEBUG -Message "Backing up WPAD settings..." -Module "AdvancedSecurity"
        $wpadBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -BackupName "WPAD_Settings"
        if ($wpadBackup) { $backupCount++ }
        
        # 6. Services
        Write-Log -Level DEBUG -Message "Backing up risky services state..." -Module "AdvancedSecurity"
        $services = @("SSDPSRV", "upnphost", "lmhosts")
        
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
        Write-Host "  [AdvancedSecurity] Creating firewall rules snapshot for risky ports (79, 137-139, 1900, 2869, 5355)..." -ForegroundColor Yellow
        Write-Host "  [AdvancedSecurity] This step may take up to 60 seconds on some systems..." -ForegroundColor DarkYellow
        Write-Log -Level INFO -Message "Backing up firewall rules snapshot for risky ports (79, 137, 138, 139, 1900, 2869, 5355)..." -Module "AdvancedSecurity"
        $firewallRules = Get-NetFirewallRule | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter
            (($portFilter.LocalPort -in @(79, 137, 138, 139, 1900, 2869, 5355)) -or 
            ($portFilter.RemotePort -in @(79, 137, 138, 139, 1900, 2869, 5355))) -and
            ($_.Direction -eq 'Inbound' -or $_.Direction -eq 'Outbound')
        } | Select-Object Name, DisplayName, Enabled, Direction, Action
        
        $firewallData = @{
            Rules      = $firewallRules
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RuleCount  = $firewallRules.Count
        } | ConvertTo-Json -Depth 10
        
        $firewallBackup = Register-Backup -Type "Firewall_Rules" -Data $firewallData -Name "RiskyPorts_Firewall"
        if ($firewallBackup) { $backupCount++ }
        
        # 9. SMB Shares Snapshot
        Write-Log -Level DEBUG -Message "Backing up SMB shares snapshot..." -Module "AdvancedSecurity"
        $adminShares = Get-SmbShare | Where-Object { $_.Name -match '^[A-Z]\$$|^ADMIN\$$' } | 
        Select-Object Name, Path, Description
        
        $sharesData = @{
            Shares     = $adminShares
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ShareCount = $adminShares.Count
        } | ConvertTo-Json -Depth 10
        
        $sharesBackup = Register-Backup -Type "SMB_Shares" -Data $sharesData -Name "AdminShares"
        if ($sharesBackup) { $backupCount++ }
        
        # 10. Windows Update Settings (3 simple GUI settings)
        Write-Log -Level DEBUG -Message "Backing up Windows Update settings..." -Module "AdvancedSecurity"
        
        # Setting 1: Get latest updates immediately
        $wuUXBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -BackupName "WindowsUpdate_UX_Settings"
        if ($wuUXBackup) { $backupCount++ }
        
        # Setting 2: Microsoft Update for other products
        $wuAUBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -BackupName "WindowsUpdate_AU_Settings"
        if ($wuAUBackup) { $backupCount++ }
        
        # Setting 3: Delivery Optimization
        $wuDOBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -BackupName "WindowsUpdate_DeliveryOptimization"
        if ($wuDOBackup) { $backupCount++ }
        
        # 11. SRP (Software Restriction Policies) Settings
        Write-Log -Level DEBUG -Message "Backing up SRP settings..." -Module "AdvancedSecurity"
        $srpBackup = Backup-RegistryKey -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -BackupName "SRP_Settings"
        if ($srpBackup) { $backupCount++ }
        
        Write-Log -Level SUCCESS -Message "Advanced Security backup completed: $backupCount items backed up" -Module "AdvancedSecurity"
        
        return $backupCount
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to backup Advanced Security settings: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
