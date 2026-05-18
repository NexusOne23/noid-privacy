function Enable-RdpNLA {
    <#
    .SYNOPSIS
        Enforce Network Level Authentication (NLA) for Remote Desktop Protocol
    
    .DESCRIPTION
        HYBRID ENFORCEMENT APPROACH (Best of Security + Usability):
        
        LEVEL 1 - ENFORCED VIA POLICIES (admin cannot disable):
        - NLA (Network Level Authentication) = REQUIRED
        - SSL/TLS encryption = REQUIRED
        Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
        
        LEVEL 2 - USER CONTROL VIA SYSTEM (admin can change in Settings):
        - RDP Enable/Disable = User choice
        Path: HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server
        
        Attack Prevention:
        - Prevents brute-force attacks before login screen appears
        - Forces SSL/TLS encryption for RDP traffic (cannot be disabled)
        - Requires authentication at network level (cannot be disabled)
    
    .PARAMETER DisableRDP
        Optionally completely disable RDP (for air-gapped systems)
    
    .PARAMETER Force
        Force RDP disable even on domain-joined systems (NOT RECOMMENDED)
    
    .EXAMPLE
        Enable-RdpNLA
        Enforces NLA and SSL/TLS for RDP
    
    .EXAMPLE
        Enable-RdpNLA -DisableRDP -Force
        Completely disables RDP (air-gapped mode)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DisableRDP,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        Write-Log -Level INFO -Message "Configuring RDP hardening (Hybrid Enforcement)..." -Module "AdvancedSecurity"
        
        # POLICIES PATH (enforced - admin cannot change via GUI)
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        
        # SYSTEM PATH (user control - admin can change via Settings)
        $systemPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        
        # Backup current settings from BOTH paths
        $backupData = @{
            Policy_UserAuthentication = $null
            Policy_SecurityLayer = $null
            System_fDenyTSConnections = $null
        }
        
        # Backup Policies path (if exists)
        if (Test-Path $policyPath) {
            $backupData.Policy_UserAuthentication = (Get-ItemProperty -Path $policyPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
            $backupData.Policy_SecurityLayer = (Get-ItemProperty -Path $policyPath -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer
        }
        
        # Backup System path (if exists)
        if (Test-Path $systemPath) {
            $backupData.System_fDenyTSConnections = (Get-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
        }
        
        # Register backup
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "RDP_Settings" -Data $backupJson -Name "RDP_Hardening"
        
        # ========================================
        # LEVEL 1: ENFORCE NLA + SSL/TLS (Policies)
        # ========================================
        Write-Log -Level INFO -Message "LEVEL 1: Enforcing NLA + SSL/TLS via Policies (admin cannot disable)..." -Module "AdvancedSecurity"
        
        # Create Policies path if not exists
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created Policies registry path" -Module "AdvancedSecurity"
        }
        
        # ENFORCE NLA (cannot be disabled by admin via GUI)
        $existing = Get-ItemProperty -Path $policyPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $policyPath -Name "UserAuthentication" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $policyPath -Name "UserAuthentication" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "NLA ENFORCED via Policies (UserAuthentication = 1)" -Module "AdvancedSecurity"
        
        # ENFORCE SSL/TLS (cannot be disabled by admin via GUI)
        $existing = Get-ItemProperty -Path $policyPath -Name "SecurityLayer" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $policyPath -Name "SecurityLayer" -Value 2 -Force | Out-Null
        } else {
            New-ItemProperty -Path $policyPath -Name "SecurityLayer" -Value 2 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "SSL/TLS ENFORCED via Policies (SecurityLayer = 2)" -Module "AdvancedSecurity"
        
        # ========================================
        # LEVEL 2: RDP ENABLE/DISABLE (System - User Control)
        # ========================================
        Write-Log -Level INFO -Message "LEVEL 2: Setting RDP enable/disable (user CAN change in Settings)..." -Module "AdvancedSecurity"
        
        # Create System path if not exists
        if (-not (Test-Path $systemPath)) {
            New-Item -Path $systemPath -Force | Out-Null
        }
        
        if ($DisableRDP) {
            # Check if domain-joined
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            
            if ($computerSystem.PartOfDomain -and -not $Force) {
                Write-Log -Level WARNING -Message "Domain-joined system detected. RDP disable skipped." -Module "AdvancedSecurity"
                Write-Log -Level WARNING -Message "Use -Force to override (NOT RECOMMENDED for enterprise!)" -Module "AdvancedSecurity"
                Write-Host ""
                Write-Host "WARNING: Domain-joined system detected!" -ForegroundColor Yellow
                Write-Host "Skipping RDP complete disable (may be required for management)." -ForegroundColor Yellow
                Write-Host "Use -DisableRDP -Force to override (NOT RECOMMENDED)." -ForegroundColor Yellow
                Write-Host ""
            }
            else {
                # Set RDP DISABLED as default (user CAN re-enable)
                $existing = Get-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -Value 1 -Force | Out-Null
                } else {
                    New-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -Value 1 -PropertyType DWord -Force | Out-Null
                }
                Write-Log -Level SUCCESS -Message "RDP DISABLED by default (user CAN re-enable via Settings)" -Module "AdvancedSecurity"
                Write-Log -Level INFO -Message "Windows will automatically adjust RDP firewall rules" -Module "AdvancedSecurity"
                
                Write-Host ""
                Write-Host "RDP Status: DISABLED by default" -ForegroundColor Yellow
                Write-Host "  You CAN re-enable RDP anytime via:" -ForegroundColor White
                Write-Host "  -> Settings > System > Remote Desktop > Enable Remote Desktop" -ForegroundColor Gray
                Write-Host "  [OK] NLA + SSL/TLS will remain ENFORCED (secure!)" -ForegroundColor Green
                Write-Host ""
            }
        }
        else {
            # Set RDP ENABLED (with NLA+SSL enforced)
            $existing = Get-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Set-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -Value 0 -Force | Out-Null
            } else {
                New-ItemProperty -Path $systemPath -Name "fDenyTSConnections" -Value 0 -PropertyType DWord -Force | Out-Null
            }
            Write-Log -Level SUCCESS -Message "RDP ENABLED with enforced NLA+SSL (user CAN disable via Settings)" -Module "AdvancedSecurity"
            
            Write-Host ""
            Write-Host "RDP Status: ENABLED with enforced security" -ForegroundColor Green
            Write-Host "  [ENFORCED] NLA (Network Level Authentication)" -ForegroundColor Green
            Write-Host "  [ENFORCED] SSL/TLS encryption" -ForegroundColor Green
            Write-Host "  You CAN disable RDP anytime via Settings if not needed" -ForegroundColor White
            Write-Host ""
        }
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure RDP hardening: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
