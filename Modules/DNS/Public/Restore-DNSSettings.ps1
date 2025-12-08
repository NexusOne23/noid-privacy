function Restore-DNSSettings {
    <#
    .SYNOPSIS
        Restore DNS settings from backup
        
    .DESCRIPTION
        Restores DNS configuration from backup file including:
        - DNS server addresses (IPv4 and IPv6)
        - DHCP configuration (if applicable)
        - DoH configuration removal
        
        CRITICAL: Properly handles DHCP vs static DNS restoration.
        
    .PARAMETER BackupFilePath
        Path to backup file created by Backup-DNSSettings
        
    .PARAMETER DryRun
        Show what would be restored without applying changes
        
    .EXAMPLE
        Restore-DNSSettings -BackupFilePath "C:\Rollback\DNS_20250116_030000.json"
        
    .OUTPUTS
        System.Boolean - $true if successful, $false otherwise
        
    .NOTES
        Uses Set-DnsClientServerAddress with -ResetServerAddresses for DHCP restore
        Uses Remove-DnsClientDohServerAddress to clean up DoH configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath,
        
        [Parameter()]
        [switch]$DryRun
    )
    
    try {
        if (-not (Test-Path $BackupFilePath)) {
            Write-Log -Level ERROR -Message "Backup file not found: $BackupFilePath" -Module $script:ModuleName
            return $false
        }
        
        Write-Log -Level INFO -Message "Restoring DNS settings from backup..." -Module $script:ModuleName
        
        # Load backup data
        $backupJson = Get-Content -Path $BackupFilePath -Raw -ErrorAction Stop
        $backupData = $backupJson | ConvertFrom-Json
        
        Write-Log -Level INFO -Message "Backup from: $($backupData.Timestamp)" -Module $script:ModuleName
        Write-Log -Level DEBUG -Message "Restoring $($backupData.Adapters.Count) adapter(s)" -Module $script:ModuleName
        
        # First: Clean all current netsh DoH entries
        if (-not $DryRun) {
            Write-Log -Level DEBUG -Message "Cleaning current netsh DoH entries..." -Module $script:ModuleName
            try {
                # Get all current DoH entries
                $currentDohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
                foreach ($dohServer in $currentDohServers) {
                    try {
                        # Remove via netsh (more reliable than PowerShell cmdlet)
                        netsh dnsclient delete encryption server=$($dohServer.ServerAddress) 2>&1 | Out-Null
                        Write-Log -Level DEBUG -Message "  Removed netsh DoH entry: $($dohServer.ServerAddress)" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level DEBUG -Message "  Could not remove netsh DoH entry: $($dohServer.ServerAddress)" -Module $script:ModuleName
                    }
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not clean netsh DoH entries: $_" -Module $script:ModuleName
            }
            
            # Clean all current DohFlags registry entries (both Doh and Doh6)
            Write-Log -Level DEBUG -Message "Cleaning current DohFlags registry entries..." -Module $script:ModuleName
            try {
                $dohFlagsBasePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters"
                if (Test-Path $dohFlagsBasePath) {
                    Get-ChildItem $dohFlagsBasePath -ErrorAction SilentlyContinue | ForEach-Object {
                        $adapterPath = $_.PSPath
                        
                        # Remove entire DohInterfaceSettings (contains both Doh and Doh6 branches)
                        if (Test-Path "$adapterPath\DohInterfaceSettings") {
                            Remove-Item "$adapterPath\DohInterfaceSettings" -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log -Level DEBUG -Message "  Cleaned DohInterfaceSettings for adapter: $($_.PSChildName)" -Module $script:ModuleName
                        }
                    }
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not clean DohFlags entries: $_" -Module $script:ModuleName
            }
        }
        
        # Restore DoH Policy Registry settings
        if ($backupData.DohPolicySettings -and $backupData.DohPolicySettings.Count -gt 0) {
            if ($DryRun) {
                Write-Log -Level INFO -Message "[DRYRUN] Would restore $($backupData.DohPolicySettings.Count) DoH policy settings" -Module $script:ModuleName
            }
            else {
                Write-Log -Level DEBUG -Message "Restoring DoH policy settings..." -Module $script:ModuleName
                
                try {
                    # Restore DoHPolicy
                    if ($backupData.DohPolicySettings.ContainsKey('DoHPolicy')) {
                        $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                        if (-not (Test-Path $dnsClientPath)) {
                            New-Item -Path $dnsClientPath -Force | Out-Null
                        }
                        $existing = Get-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -ErrorAction SilentlyContinue
                        if ($null -ne $existing) {
                            Set-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -Value $backupData.DohPolicySettings['DoHPolicy'] -Force
                        } else {
                            New-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -Value $backupData.DohPolicySettings['DoHPolicy'] -PropertyType DWord -Force | Out-Null
                        }
                        Write-Log -Level DEBUG -Message "  Restored DoHPolicy = $($backupData.DohPolicySettings['DoHPolicy'])" -Module $script:ModuleName
                    }
                    else {
                        # Remove DoHPolicy if it wasn't set before
                        $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                        if (Test-Path $dnsClientPath) {
                            Remove-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -ErrorAction SilentlyContinue
                            Write-Log -Level DEBUG -Message "  Removed DoHPolicy (was not set in backup)" -Module $script:ModuleName
                            
                            # CLEANUP: Remove key if empty (created by us)
                            $keyContent = Get-ChildItem $dnsClientPath -ErrorAction SilentlyContinue
                            $keyProps = Get-ItemProperty $dnsClientPath -ErrorAction SilentlyContinue
                            # Count properties (exclude PS metadata like PSPath, etc.)
                            $propCount = ($keyProps.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }).Count
                            
                            if (($null -eq $keyContent -or $keyContent.Count -eq 0) -and $propCount -eq 0) {
                                Remove-Item $dnsClientPath -Force -ErrorAction SilentlyContinue
                                Write-Log -Level DEBUG -Message "  Removed empty registry key: $dnsClientPath" -Module $script:ModuleName
                            }
                        }
                    }
                    
                    # Restore EnableAutoDoh
                    if ($backupData.DohPolicySettings.ContainsKey('EnableAutoDoh')) {
                        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                        $existing = Get-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
                        if ($null -ne $existing) {
                            Set-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value $backupData.DohPolicySettings['EnableAutoDoh'] -Force
                        } else {
                            New-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value $backupData.DohPolicySettings['EnableAutoDoh'] -PropertyType DWord -Force | Out-Null
                        }
                        Write-Log -Level DEBUG -Message "  Restored EnableAutoDoh = $($backupData.DohPolicySettings['EnableAutoDoh'])" -Module $script:ModuleName
                    }
                    else {
                        # Remove EnableAutoDoh if it wasn't set before
                        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                        Remove-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
                        Write-Log -Level DEBUG -Message "  Removed EnableAutoDoh (was not set in backup)" -Module $script:ModuleName
                        
                        # CLEANUP: Remove key if empty (unlikely for Parameters, but safe to check)
                        if (Test-Path $dnsParamsPath) {
                            $keyContent = Get-ChildItem $dnsParamsPath -ErrorAction SilentlyContinue
                            $keyProps = Get-ItemProperty $dnsParamsPath -ErrorAction SilentlyContinue
                            $propCount = ($keyProps.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }).Count
                            
                            if (($null -eq $keyContent -or $keyContent.Count -eq 0) -and $propCount -eq 0) {
                                Remove-Item $dnsParamsPath -Force -ErrorAction SilentlyContinue
                                Write-Log -Level DEBUG -Message "  Removed empty registry key: $dnsParamsPath" -Module $script:ModuleName
                            }
                        }
                    }
                    
                    # Restore DohFlags (global)
                    if ($backupData.DohPolicySettings.ContainsKey('DohFlags')) {
                        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                        $existing = Get-ItemProperty -Path $dnsParamsPath -Name "DohFlags" -ErrorAction SilentlyContinue
                        if ($null -ne $existing) {
                            Set-ItemProperty -Path $dnsParamsPath -Name "DohFlags" -Value $backupData.DohPolicySettings['DohFlags'] -Force
                        } else {
                            New-ItemProperty -Path $dnsParamsPath -Name "DohFlags" -Value $backupData.DohPolicySettings['DohFlags'] -PropertyType DWord -Force | Out-Null
                        }
                        Write-Log -Level DEBUG -Message "  Restored DohFlags (global) = $($backupData.DohPolicySettings['DohFlags'])" -Module $script:ModuleName
                    }
                    else {
                        # Remove DohFlags if it wasn't set before
                        $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                        Remove-ItemProperty -Path $dnsParamsPath -Name "DohFlags" -ErrorAction SilentlyContinue
                        Write-Log -Level DEBUG -Message "  Removed DohFlags (global) (was not set in backup)" -Module $script:ModuleName
                    }
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not restore DoH policy settings: $_" -Module $script:ModuleName
                }
            }
        }
        else {
            # No DoH policy settings in backup - remove them
            if (-not $DryRun) {
                Write-Log -Level DEBUG -Message "No DoH policy settings in backup - removing current settings" -Module $script:ModuleName
                try {
                    $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                    if (Test-Path $dnsClientPath) {
                        Remove-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -ErrorAction SilentlyContinue
                    }
                    $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                    Remove-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $dnsParamsPath -Name "DohFlags" -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log -Level DEBUG -Message "Could not remove DoH policy settings: $_" -Module $script:ModuleName
                }
            }
        }
        
        # Restore netsh global DoH state
        if ($backupData.NetshGlobalDoh) {
            if ($DryRun) {
                Write-Log -Level INFO -Message "[DRYRUN] Would restore netsh global DoH: $($backupData.NetshGlobalDoh)" -Module $script:ModuleName
            }
            else {
                Write-Log -Level DEBUG -Message "Restoring netsh global DoH state: $($backupData.NetshGlobalDoh)" -Module $script:ModuleName
                try {
                    netsh dnsclient set global doh=$($backupData.NetshGlobalDoh) 2>&1 | Out-Null
                    Write-Log -Level DEBUG -Message "  netsh global DoH restored" -Module $script:ModuleName
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not restore netsh global DoH: $_" -Module $script:ModuleName
                }
            }
        }
        else {
            # If no global DoH state in backup, it means it wasn't configured or we couldn't read it.
            # Since we enable it in Apply, we should disable it here to be safe.
            if (-not $DryRun) {
                Write-Log -Level DEBUG -Message "No global DoH state in backup - resetting to default (doh=no)" -Module $script:ModuleName
                try {
                    netsh dnsclient set global doh=no 2>&1 | Out-Null
                    Write-Log -Level DEBUG -Message "  netsh global DoH reset to 'no'" -Module $script:ModuleName
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not reset netsh global DoH: $_" -Module $script:ModuleName
                }
            }
        }
        
        # Restore netsh DoH entries
        if ($backupData.DohEntries -and $backupData.DohEntries.Count -gt 0) {
            if ($DryRun) {
                Write-Log -Level INFO -Message "[DRYRUN] Would restore $($backupData.DohEntries.Count) DoH entries from snapshot" -Module $script:ModuleName
            }
            else {
                Write-Log -Level DEBUG -Message "Restoring $($backupData.DohEntries.Count) DoH entries from snapshot..." -Module $script:ModuleName
                foreach ($entry in $backupData.DohEntries) {
                    $server = $entry.ServerAddress
                    $template = $entry.DohTemplate
                    if (-not $server -or -not $template) {
                        continue
                    }
                    try {
                        try {
                            Add-DnsClientDohServerAddress -ServerAddress $server `
                                                         -DohTemplate $template `
                                                         -AllowFallbackToUdp ([bool]$entry.AllowFallbackToUdp) `
                                                         -AutoUpgrade ([bool]$entry.AutoUpgrade) `
                                                         -ErrorAction Stop
                        }
                        catch {
                            Write-Log -Level DEBUG -Message "  Add-DnsClientDohServerAddress failed for ${server}: $_" -Module $script:ModuleName
                        }
                        
                        $udpFallback = if ($entry.AllowFallbackToUdp) { 'yes' } else { 'no' }
                        $autoupgrade = if ($entry.AutoUpgrade) { 'yes' } else { 'no' }
                        
                        netsh dnsclient add encryption `
                            server=$server `
                            dohtemplate=$template `
                            autoupgrade=$autoupgrade `
                            udpfallback=$udpFallback 2>&1 | Out-Null
                        
                        Write-Log -Level DEBUG -Message "  Restored DoH entry: $server" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Could not restore DoH entry for ${server}: $_" -Module $script:ModuleName
                    }
                }
            }
        }
        elseif ($backupData.NetshDohEntries -and $backupData.NetshDohEntries.Count -gt 0) {
            if ($DryRun) {
                Write-Log -Level INFO -Message "[DRYRUN] Would restore $($backupData.NetshDohEntries.Count) netsh DoH entries" -Module $script:ModuleName
            }
            else {
                Write-Log -Level DEBUG -Message "Restoring $($backupData.NetshDohEntries.Count) netsh DoH entries..." -Module $script:ModuleName
                foreach ($entry in $backupData.NetshDohEntries) {
                    try {
                        $autoupgrade = if ($entry.AutoUpgrade -eq 'yes') { 'yes' } else { 'no' }
                        $udpfallback = if ($entry.UdpFallback -eq 'yes') { 'yes' } else { 'no' }
                        
                        netsh dnsclient add encryption `
                            server=$($entry.Server) `
                            dohtemplate=$($entry.Template) `
                            autoupgrade=$autoupgrade `
                            udpfallback=$udpfallback 2>&1 | Out-Null
                        
                        Write-Log -Level DEBUG -Message "  Restored netsh DoH: $($entry.Server)" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Could not restore netsh DoH for $($entry.Server): $_" -Module $script:ModuleName
                    }
                }
            }
        }
        
        $success = $true
        
        foreach ($adapterBackup in $backupData.Adapters) {
            $adapterName = $adapterBackup.InterfaceAlias
            $interfaceIndex = $adapterBackup.InterfaceIndex
            
            Write-Log -Level INFO -Message "Restoring adapter: $adapterName" -Module $script:ModuleName
            
            # Verify adapter still exists
            $adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -ErrorAction SilentlyContinue
            if (-not $adapter) {
                Write-Log -Level WARNING -Message "  Adapter no longer exists - skipping" -Module $script:ModuleName
                continue
            }
            
            if ($DryRun) {
                if ($adapterBackup.IsDHCP) {
                    Write-Log -Level INFO -Message "[DRYRUN] Would reset $adapterName to DHCP" -Module $script:ModuleName
                }
                else {
                    Write-Log -Level INFO -Message "[DRYRUN] Would restore static DNS on $adapterName" -Module $script:ModuleName
                    Write-Log -Level DEBUG -Message "[DRYRUN]   IPv4: $($adapterBackup.IPv4Addresses -join ', ')" -Module $script:ModuleName
                    Write-Log -Level DEBUG -Message "[DRYRUN]   IPv6: $($adapterBackup.IPv6Addresses -join ', ')" -Module $script:ModuleName
                    if ($adapterBackup.DohFlags -and $adapterBackup.DohFlags.Count -gt 0) {
                        Write-Log -Level DEBUG -Message "[DRYRUN]   DohFlags: $($adapterBackup.DohFlags.Count) registry entries" -Module $script:ModuleName
                    }
                    if ($null -ne $adapterBackup.DhcpOverrideDisabled) {
                        $overrideStatus = if ($adapterBackup.DhcpOverrideDisabled) { "disabled" } else { "enabled" }
                        Write-Log -Level DEBUG -Message "[DRYRUN]   DHCP Override: $overrideStatus" -Module $script:ModuleName
                    }
                }
                continue
            }
            
            # Remove DoH configuration first (if any)
            if ($adapterBackup.DoHConfiguration.Count -gt 0) {
                Write-Log -Level DEBUG -Message "  Removing DoH configuration..." -Module $script:ModuleName
                
                foreach ($dohConfig in $adapterBackup.DoHConfiguration) {
                    try {
                        Remove-DnsClientDohServerAddress -ServerAddress $dohConfig.ServerAddress -ErrorAction SilentlyContinue
                        Write-Log -Level DEBUG -Message "    Removed DoH for $($dohConfig.ServerAddress)" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level DEBUG -Message "    Could not remove DoH for $($dohConfig.ServerAddress): $_" -Module $script:ModuleName
                    }
                }
            }
            
            # Restore DNS configuration
            if ($adapterBackup.IsDHCP) {
                # Reset to DHCP
                Write-Log -Level INFO -Message "  Resetting to DHCP..." -Module $script:ModuleName
                
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses -ErrorAction Stop
                    Write-Log -Level SUCCESS -Message "  DNS reset to DHCP successfully" -Module $script:ModuleName
                }
                catch {
                    Write-Log -Level ERROR -Message "  Failed to reset to DHCP: $_" -Module $script:ModuleName
                    $success = $false
                }
            }
            else {
                # Restore static DNS
                Write-Log -Level INFO -Message "  Restoring static DNS..." -Module $script:ModuleName
                
                # Restore IPv4
                if ($adapterBackup.IPv4Addresses.Count -gt 0) {
                    try {
                        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex `
                                                  -ServerAddresses $adapterBackup.IPv4Addresses `
                                                  -ErrorAction Stop
                        Write-Log -Level SUCCESS -Message "  IPv4 DNS restored: $($adapterBackup.IPv4Addresses -join ', ')" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level ERROR -Message "  Failed to restore IPv4 DNS: $_" -Module $script:ModuleName
                        $success = $false
                    }
                }
                
                # Restore IPv6 (if was configured)
                if ($adapterBackup.IPv6Addresses.Count -gt 0) {
                    try {
                        # Use netsh for IPv6 (PowerShell cmdlet limitation)
                        $primaryIPv6 = $adapterBackup.IPv6Addresses[0]
                        & netsh interface ipv6 set dnsservers name="$adapterName" source=static address=$primaryIPv6 validate=no 2>&1 | Out-Null
                        
                        if ($adapterBackup.IPv6Addresses.Count -gt 1) {
                            $secondaryIPv6 = $adapterBackup.IPv6Addresses[1]
                            & netsh interface ipv6 add dnsservers name="$adapterName" address=$secondaryIPv6 index=2 validate=no 2>&1 | Out-Null
                        }
                        
                        Write-Log -Level SUCCESS -Message "  IPv6 DNS restored: $($adapterBackup.IPv6Addresses -join ', ')" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level WARNING -Message "  Could not restore IPv6 DNS (non-fatal): $_" -Module $script:ModuleName
                    }
                }
                
                # Restore DoH configuration (if was configured)
                if ($adapterBackup.DoHConfiguration.Count -gt 0) {
                    Write-Log -Level DEBUG -Message "  Restoring DoH configuration..." -Module $script:ModuleName
                    
                    foreach ($dohConfig in $adapterBackup.DoHConfiguration) {
                        try {
                            Add-DnsClientDohServerAddress -ServerAddress $dohConfig.ServerAddress `
                                                         -DohTemplate $dohConfig.DohTemplate `
                                                         -AllowFallbackToUdp $dohConfig.AllowFallbackToUdp `
                                                         -AutoUpgrade $dohConfig.AutoUpgrade `
                                                         -ErrorAction Stop
                            Write-Log -Level DEBUG -Message "    Restored DoH for $($dohConfig.ServerAddress)" -Module $script:ModuleName
                        }
                        catch {
                            Write-Log -Level DEBUG -Message "    Could not restore DoH for $($dohConfig.ServerAddress): $_" -Module $script:ModuleName
                        }
                    }
                }
                
                # Restore DohFlags registry settings (if was configured)
                if ($adapterBackup.DohFlags -and $adapterBackup.DohFlags.Count -gt 0) {
                    Write-Log -Level DEBUG -Message "  Restoring DohFlags registry settings..." -Module $script:ModuleName
                    
                    $interfaceGuid = $adapterBackup.InterfaceGuid
                    if (-not $interfaceGuid) {
                        # Fallback: get current GUID
                        $currentAdapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -ErrorAction SilentlyContinue
                        $interfaceGuid = $currentAdapter.InterfaceGuid
                    }
                    
                    if ($interfaceGuid) {
                        foreach ($dnsIP in $adapterBackup.DohFlags.Keys) {
                            try {
                                $flagValue = $adapterBackup.DohFlags[$dnsIP]
                                $dohFlagsPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$interfaceGuid\DohInterfaceSettings\Doh\$dnsIP"
                                
                                # Create path if needed
                                if (-not (Test-Path $dohFlagsPath)) {
                                    New-Item -Path $dohFlagsPath -Force -ErrorAction Stop | Out-Null
                                }
                                
                                # Restore DohFlags value
                                New-ItemProperty -Path $dohFlagsPath -Name "DohFlags" -Value $flagValue -PropertyType QWORD -Force -ErrorAction Stop | Out-Null
                                Write-Log -Level DEBUG -Message "    Restored DohFlags for $dnsIP = $flagValue" -Module $script:ModuleName
                            }
                            catch {
                                Write-Log -Level DEBUG -Message "    Could not restore DohFlags for $dnsIP : $_" -Module $script:ModuleName
                            }
                        }
                    }
                    else {
                        Write-Log -Level WARNING -Message "  Could not restore DohFlags: Interface GUID not available" -Module $script:ModuleName
                    }
                }
                
                # Restore DHCP DNS Override setting
                if ($null -ne $adapterBackup.DhcpOverrideDisabled) {
                    Write-Log -Level DEBUG -Message "  Restoring DHCP DNS override setting..." -Module $script:ModuleName
                    
                    try {
                        # DhcpOverrideDisabled=true means RegisterThisConnectionsAddress=false
                        $registerThisConnection = -not $adapterBackup.DhcpOverrideDisabled
                        
                        Set-DnsClient -InterfaceIndex $interfaceIndex `
                                     -RegisterThisConnectionsAddress $registerThisConnection `
                                     -ErrorAction Stop
                        
                        $statusText = if ($adapterBackup.DhcpOverrideDisabled) { "disabled" } else { "enabled" }
                        Write-Log -Level DEBUG -Message "    DHCP DNS override: $statusText" -Module $script:ModuleName
                    }
                    catch {
                        Write-Log -Level WARNING -Message "  Could not restore DHCP override setting: $_" -Module $script:ModuleName
                    }
                }
            }
        }
        
        if ($success) {
            Write-Log -Level SUCCESS -Message "DNS settings restored successfully" -Module $script:ModuleName
        }
        else {
            Write-Log -Level WARNING -Message "DNS settings restored with some errors" -Module $script:ModuleName
        }
        
        return $success
    }
    catch {
        Write-ErrorLog -Message "Failed to restore DNS settings from backup" -Module $script:ModuleName -ErrorRecord $_
        return $false
    }
}
