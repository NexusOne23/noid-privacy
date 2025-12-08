function Disable-AdminShares {
    <#
    .SYNOPSIS
        Disable administrative shares (C$, ADMIN$, etc.) to prevent lateral movement
    
    .DESCRIPTION
        Disables the automatic creation of administrative shares and removes existing shares.
        Administrative shares (C$, D$, ADMIN$) are used by attackers for:
        - Lateral movement (WannaCry, NotPetya propagation)
        - Remote file access with stolen credentials
        - Pass-the-Hash attacks
        - Automated malware propagation
        
        CRITICAL: Includes domain-safety check. On domain-joined systems, admin shares
        are often required for Group Policy, SCCM, and remote management tools.
        
        REQUIRES REBOOT to prevent share recreation.
    
    .PARAMETER Force
        Force disable even on domain-joined systems (NOT RECOMMENDED for enterprise!)
    
    .EXAMPLE
        Disable-AdminShares
        Disables admin shares with domain-safety check
    
    .EXAMPLE
        Disable-AdminShares -Force
        Forces disable even on domain-joined systems (DANGEROUS!)
    
    .NOTES
        Impact:
        - Home/Workgroup: Highly recommended
        - Enterprise Domain: May break management tools - TEST FIRST!
        - IPC$ cannot be removed (required by Windows)
        
        Shares will NOT be recreated after reboot (if registry values set to 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        Write-Log -Level INFO -Message "Configuring administrative shares disable..." -Module "AdvancedSecurity"
        
        # CRITICAL: Check if system is domain-joined
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        
        if ($computerSystem.PartOfDomain -and -not $Force) {
            Write-Log -Level WARNING -Message "Domain-joined system detected. Admin shares disable SKIPPED." -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "Admin shares are often required for:" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - Group Policy management" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - SCCM/Management tools" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "  - Remote administration" -Module "AdvancedSecurity"
            Write-Log -Level WARNING -Message "Use -Force to override (NOT RECOMMENDED!)" -Module "AdvancedSecurity"
            
            Write-Host ""
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host "  DOMAIN-JOINED SYSTEM DETECTED" -ForegroundColor Yellow
            Write-Host "================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Administrative shares are often required for:" -ForegroundColor White
            Write-Host "  - Group Policy remote management" -ForegroundColor Gray
            Write-Host "  - SCCM and other management tools" -ForegroundColor Gray
            Write-Host "  - Remote administration via WMI/PowerShell" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Skipping admin shares disable to prevent breakage." -ForegroundColor Green
            Write-Host "Use -DisableAdminShares -Force to override (NOT RECOMMENDED)." -ForegroundColor Red
            Write-Host ""
            
            return $true  # Not an error, just skipped
        }
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        # Check if LanmanServer service is running (required for Get-SmbShare)
        $serverService = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
        $serviceRunning = $serverService -and $serverService.Status -eq 'Running'
        
        # Backup current shares and registry settings
        Write-Log -Level INFO -Message "Backing up current administrative shares..." -Module "AdvancedSecurity"
        
        if (-not $serviceRunning) {
            # Server service not running - admin shares are already effectively disabled
            Write-Log -Level INFO -Message "LanmanServer service is not running - admin shares already disabled" -Module "AdvancedSecurity"
            $currentShares = @()
        }
        else {
            try {
                $currentShares = Get-SmbShare | Where-Object { $_.Name -match '^[A-Z]\$$|^ADMIN\$$' } | 
                    Select-Object Name, Path, Description
            }
            catch {
                Write-Log -Level INFO -Message "Could not query SMB shares: $($_.Exception.Message)" -Module "AdvancedSecurity"
                $currentShares = @()
            }
        }
        
        $backupData = @{
            Shares = $currentShares
            AutoShareWks = (Get-ItemProperty -Path $regPath -Name "AutoShareWks" -ErrorAction SilentlyContinue).AutoShareWks
            AutoShareServer = (Get-ItemProperty -Path $regPath -Name "AutoShareServer" -ErrorAction SilentlyContinue).AutoShareServer
            DomainJoined = $computerSystem.PartOfDomain
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Register backup
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "AdminShares_Settings" -Data $backupJson -Name "AdminShares_Disable"
        
        Write-Log -Level INFO -Message "Backed up $($currentShares.Count) administrative shares" -Module "AdvancedSecurity"
        
        # Disable automatic creation
        Write-Log -Level INFO -Message "Disabling automatic administrative share creation..." -Module "AdvancedSecurity"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Disable for Workstation (Home/Pro)
        $existing = Get-ItemProperty -Path $regPath -Name "AutoShareWks" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "Disabled AutoShareWks (Workstation shares)" -Module "AdvancedSecurity"
        
        # Disable for Server editions
        $existing = Get-ItemProperty -Path $regPath -Name "AutoShareServer" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "Disabled AutoShareServer (Server edition shares)" -Module "AdvancedSecurity"
        
        # Remove existing shares
        Write-Log -Level INFO -Message "Removing existing administrative shares..." -Module "AdvancedSecurity"
        
        $removedCount = 0
        $skippedShares = @()
        
        foreach ($share in $currentShares) {
            try {
                Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop
                Write-Log -Level SUCCESS -Message "Removed share: $($share.Name) ($($share.Path))" -Module "AdvancedSecurity"
                $removedCount++
            }
            catch {
                # ADMIN$ and C$ cannot be removed while system is running (expected behavior)
                # They will NOT be recreated after reboot due to registry settings
                Write-Log -Level INFO -Message "Share $($share.Name) protected by system (will not be recreated after reboot)" -Module "AdvancedSecurity"
                $skippedShares += $share.Name
            }
        }
        
        if ($skippedShares.Count -gt 0) {
            Write-Log -Level INFO -Message "System-protected shares: $($skippedShares -join ', ') - Will NOT be recreated after reboot" -Module "AdvancedSecurity"
        }
        
        Write-Log -Level SUCCESS -Message "Removed $removedCount administrative shares, $($skippedShares.Count) protected by system" -Module "AdvancedSecurity"
        
        # Add firewall protection for Public networks
        Write-Log -Level INFO -Message "Adding firewall protection for SMB on Public networks..." -Module "AdvancedSecurity"
        
        $firewallRuleName = "Block Admin Shares - NoID Privacy"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log -Level INFO -Message "Firewall rule already exists, updating..." -Module "AdvancedSecurity"
            Remove-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
        }
        
        # Create new firewall rule
        New-NetFirewallRule -DisplayName $firewallRuleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 445 `
            -Profile Public `
            -Action Block `
            -ErrorAction Stop | Out-Null
        
        Write-Log -Level SUCCESS -Message "Firewall rule created: Block SMB (port 445) on Public networks" -Module "AdvancedSecurity"
        
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  ADMINISTRATIVE SHARES DISABLED" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Registry settings:" -ForegroundColor White
        Write-Host "  AutoShareWks:    0 (Disabled)" -ForegroundColor Gray
        Write-Host "  AutoShareServer: 0 (Disabled)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Removed shares: $removedCount" -ForegroundColor White
        if ($skippedShares.Count -gt 0) {
            Write-Host "Protected shares: $($skippedShares -join ', ') (cannot be removed while running)" -ForegroundColor Gray
        }
        Write-Host "Firewall:       SMB blocked on Public networks" -ForegroundColor White
        Write-Host ""
        Write-Host "IMPORTANT: REBOOT REQUIRED" -ForegroundColor Yellow

        $exampleShares = if ($skippedShares.Count -gt 0) { $skippedShares -join ', ' } else { 'C$, ADMIN$' }
        Write-Host "All admin shares (including $exampleShares) will NOT be recreated after reboot." -ForegroundColor Green
        Write-Host ""
        Write-Host "Note: IPC$ cannot be removed (required by Windows)" -ForegroundColor Gray
        Write-Host "Note: Explicit file shares will still work" -ForegroundColor Gray
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable administrative shares: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
