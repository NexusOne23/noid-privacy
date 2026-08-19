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
        - RDP is disabled only by explicit choice; otherwise its current state is preserved
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DisableRDP,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable RdpNLA')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Configuring RDP hardening (Hybrid Enforcement)..." -Module "AdvancedSecurity"

        # POLICIES PATH (enforced - admin cannot change via GUI)
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

        # SYSTEM PATH (user control - admin can change via Settings)
        $systemPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

        # ========================================
        # LEVEL 1: ENFORCE NLA + SSL/TLS (Policies)
        # ========================================
        Write-Log -Level INFO -Message "LEVEL 1: Enforcing NLA + SSL/TLS via Policies (admin cannot disable)..." -Module "AdvancedSecurity"

        # The targeted pre-state was sealed before Apply; do not mutate the
        # backup index from an apply function.
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
            Write-Log -Level DEBUG -Message "Created Policies registry path" -Module "AdvancedSecurity"
        }

        # ENFORCE NLA (cannot be disabled by admin via GUI)
        Remove-ItemProperty -LiteralPath $policyPath -Name 'UserAuthentication' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $policyPath -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level SUCCESS -Message "NLA ENFORCED via Policies (UserAuthentication = 1)" -Module "AdvancedSecurity"

        # ENFORCE SSL/TLS (cannot be disabled by admin via GUI)
        Remove-ItemProperty -LiteralPath $policyPath -Name 'SecurityLayer' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $policyPath -Name 'SecurityLayer' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log -Level SUCCESS -Message "SSL/TLS ENFORCED via Policies (SecurityLayer = 2)" -Module "AdvancedSecurity"

        # ========================================
        # LEVEL 2: RDP ENABLE/DISABLE (System - User Control)
        # ========================================
        Write-Log -Level INFO -Message "LEVEL 2: Setting RDP enable/disable (user CAN change in Settings)..." -Module "AdvancedSecurity"

        if ($DisableRDP -and -not (Test-Path $systemPath)) {
            New-Item -Path $systemPath -Force -ErrorAction Stop | Out-Null
        }

        $rdpDisableApplied = $false
        if ($DisableRDP) {
            # Check if domain-joined
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

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
                Remove-ItemProperty -LiteralPath $systemPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
                New-ItemProperty -Path $systemPath -Name 'fDenyTSConnections' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                $rdpDisableApplied = $true
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
            # Hardening NLA/TLS must not invert an unselected optional disable
            # into an RDP enable operation. Preserve fDenyTSConnections exactly.
            Write-Log -Level SUCCESS -Message "RDP enable/disable state preserved; NLA+SSL/TLS enforced" -Module "AdvancedSecurity"

            Write-Host ""
            Write-Host "RDP Status: Existing enable/disable state preserved" -ForegroundColor Green
            Write-Host "  [ENFORCED] NLA (Network Level Authentication)" -ForegroundColor Green
            Write-Host "  [ENFORCED] SSL/TLS encryption" -ForegroundColor Green
            Write-Host "  NoID Privacy did not enable Remote Desktop" -ForegroundColor White
            Write-Host ""
        }

        # Post-apply expectations may only cover writes that actually happened;
        # the domain-safety skip path leaves fDenyTSConnections untouched.
        $policyKey = Get-Item -LiteralPath $policyPath -ErrorAction Stop
        $systemKey = if ($rdpDisableApplied) { Get-Item -LiteralPath $systemPath -ErrorAction Stop } else { $null }
        $expectations = @(
                @{ Key=$policyKey; Name='UserAuthentication'; Value=1 }
                @{ Key=$policyKey; Name='SecurityLayer'; Value=2 }
            )
        if ($rdpDisableApplied) {
            $expectations += @{ Key=$systemKey; Name='fDenyTSConnections'; Value=1 }
        }
        foreach ($expectation in $expectations) {
            if ($expectation.Key.GetValueNames() -notcontains $expectation.Name -or
                $expectation.Key.GetValueKind($expectation.Name).ToString() -ne 'DWord' -or
                [int]$expectation.Key.GetValue($expectation.Name) -ne [int]$expectation.Value) {
                throw "RDP registry post-apply mismatch: $($expectation.Name)"
            }
        }
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure RDP hardening: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
