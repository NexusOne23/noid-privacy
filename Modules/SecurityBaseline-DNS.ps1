# =======================================================================================
# SecurityBaseline-DNS.ps1 - DNS Security & Cloudflare DoH
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Enable-DNSSEC {
    <#
    .SYNOPSIS
        Enable DNSSEC validation for DNS queries
    .DESCRIPTION
        Configures Windows DNS Client to validate DNSSEC signatures
        Prevents DNS spoofing and cache poisoning attacks
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "DNSSEC Validation"
    
    Write-Info "$(Get-LocalizedString 'DNSSECActivating')"
    
    # Enable DNSSEC validation
    $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    
    # Enable DNSSEC validation
    Set-RegistryValue -Path $dnsPath -Name "EnableDnssec" -Value 1 -Type DWord `
        -Description "Enable DNSSEC Validation"
    
    # DNSSEC Mode: Opportunistic (Mode 1 - Best Practice 25H2)
    # Mode 1 = Opportunistic (validate if available, don't fail if not)
    # Mode 2 = Require validation (can break DNS if misconfigured)
    # Best Practice: Mode 1 for client systems, Mode 2 only for servers
    
    Set-RegistryValue -Path $dnsPath -Name "DnssecMode" -Value 1 -Type DWord `
        -Description "DNSSEC Mode: 1 = Opportunistic (validate if available)"
    
    Write-Info "$(Get-LocalizedString 'DNSSECModeOpportunistic')"
    
    # Enable DNSSEC for IPv6
    Set-RegistryValue -Path $dnsPath -Name "EnableDnssecIPv6" -Value 1 -Type DWord `
        -Description "DNSSEC for IPv6"
    
    Write-Success "$(Get-LocalizedString 'DNSSECActivated')"
    Write-Info "$(Get-LocalizedString 'DNSSECResponsesValidated')"
}

function Install-DNSBlocklist {
    <#
    .SYNOPSIS
        Install DNS-based blocklist via Windows HOSTS file
    .DESCRIPTION
        Installs Steven Black's unified hosts file (80K+ domains) from local project directory.
        The hosts file is included with the script - no internet connection needed!
        Blocks malware, tracking, advertising domains at DNS level.
        
        LOGIC (SIMPLE!):
        1. Check if already installed (idempotency)
        2. Backup original hosts file
        3. Copy local hosts file (80K+ domains) to System32
        4. Flush DNS Cache
        5. DONE!
        
        Source: https://github.com/StevenBlack/hosts
        Last Update: 17 October 2025 (80,101 Domains)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "DNS Blocklist (Malware/Tracking/Ads)"
    
    Write-Info "$(Get-LocalizedString 'DNSBlocklistInstalling')"
    Write-Info "$(Get-LocalizedString 'DNSBlocklistOptimization')"
    Write-Info "$(Get-LocalizedString 'DNSBlocklistCompressed')"
    
    # IMPORTANT: Bitdefender/Antivirus warning
    Write-Warning "$(Get-LocalizedString 'DNSAntivirusCompatibility')"
    Write-Warning "$(Get-LocalizedString 'DNSBitdefenderWarning')"
    Write-Warning "$(Get-LocalizedString 'DNSInternetBlock')"
    
    # Check if Steven Black's Hosts is already installed (idempotency)
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $currentHosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $alreadyInstalled = $currentHosts | Select-String "# Title: StevenBlack/hosts"
    
    if ($alreadyInstalled) {
        Write-Info "$(Get-LocalizedString 'DNSAlreadyInstalled')"
        Write-Verbose "$(Get-LocalizedString 'DNSSkipDownload')"
        return
    }
    
    # Backup current hosts file
    $hostsBackup = "$hostsPath.backup-original"
    
    if (-not (Test-Path $hostsBackup)) {
        try {
            Copy-Item -Path $hostsPath -Destination $hostsBackup -Force
            Write-Verbose (Get-LocalizedString 'DNSBackupOriginal' $hostsBackup)
        }
        catch {
            Write-Warning (Get-LocalizedString 'DNSBackupFailed' $_)
        }
    }
    else {
        Write-Verbose (Get-LocalizedString 'DNSBackupExists' $hostsBackup)
    }
    
    # Best Practice 25H2: Use LOCAL hosts file from project directory!
    # No internet connection needed - everything is local!
    
    # Find script directory (ROBUST!)
    $scriptDir = $null
    
    # Method 1: $PSCommandPath (when module called directly)
    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
        Write-Verbose "Script-Dir via PSCommandPath: $scriptDir"
    }
    
    # Method 2: $PSScriptRoot (when script is running)
    if (-not $scriptDir -and $PSScriptRoot) {
        $scriptDir = $PSScriptRoot
        Write-Verbose "Script-Dir via PSScriptRoot: $scriptDir"
    }
    
    # Method 3: MyInvocation (Fallback)
    if (-not $scriptDir) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        Write-Verbose "Script-Dir via MyInvocation: $scriptDir"
    }
    
    # Method 4: Working directory (last fallback)
    if (-not $scriptDir) {
        $scriptDir = Get-Location
        Write-Verbose "Script-Dir via Get-Location (Fallback): $scriptDir"
    }
    
    # Go up one directory (from Modules\ to project root)
    $projectRoot = Split-Path -Parent $scriptDir
    $localHostsFile = Join-Path $projectRoot "hosts"
    
    Write-Verbose "Project-Root: $projectRoot"
    
    Write-Info "$(Get-LocalizedString 'DNSUsingLocal')"
    Write-Verbose "Path: $localHostsFile"
    
    # Check if local file exists
    if (-not (Test-Path $localHostsFile)) {
        Write-Error "$(Get-LocalizedString 'DNSCriticalError')"
        Write-Error (Get-LocalizedString 'DNSExpected' $localHostsFile)
        Write-Error "$(Get-LocalizedString 'DNSCannotInstall')"
        return
    }
    
    try {
        # Validate local file
        $localContent = Get-Content $localHostsFile -TotalCount 10 -ErrorAction Stop
        $hasValidHeader = $localContent | Where-Object { $_ -match "# Title: StevenBlack/hosts" }
        
        if (-not $hasValidHeader) {
            Write-Error "$(Get-LocalizedString 'DNSInvalidHeader')"
            Write-Error "$(Get-LocalizedString 'DNSExpectedHeader')"
            return
        }
        
        # Count blocked domains
        # CRITICAL FIX v1.7.11: hosts file is optimized (9 domains per line)
        # We count lines and multiply by 9 for actual domain count
        $allContent = Get-Content $localHostsFile -ErrorAction Stop
        $blockedDomains = ($allContent | Where-Object { $_ -match '^0\.0\.0\.0\s+' }).Count * 9
        
        Write-Success (Get-LocalizedString 'DNSValidated' $blockedDomains)
        Write-Verbose "File-Size: $([Math]::Round((Get-Item $localHostsFile).Length / 1MB, 2)) MB"
        
        # Install via ATOMIC REPLACE (Best Practice 25H2)
        Write-Info "$(Get-LocalizedString 'DNSInstalling')"
        
        $hostsTemp = "$hostsPath.new"
        try {
            # Copy to temp file
            Copy-Item -Path $localHostsFile -Destination $hostsTemp -Force -ErrorAction Stop
            
            # Validate copy
            $newContent = Get-Content $hostsTemp -ErrorAction Stop
            if ($newContent.Count -lt 1000) {
                throw (Get-LocalizedString 'DNSFileTooSmall' $newContent.Count)
            }
            
            # Atomic replace: temp -> final
            Move-Item -Path $hostsTemp -Destination $hostsPath -Force -ErrorAction Stop
            Write-Verbose "$(Get-LocalizedString 'DNSAtomicSuccess')"
        }
        catch {
            # Cleanup temp file on error
            if (Test-Path $hostsTemp) {
                Remove-Item $hostsTemp -Force -ErrorAction SilentlyContinue
            }
            throw (Get-LocalizedString 'DNSInstallFailed' $_)
        }
        
        # Flush DNS cache (with timeout - prevents hang)
        Write-Info "$(Get-LocalizedString 'DNSFlushingCache')"
        $dnsJob = $null
        try {
            $dnsJob = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
            $null = Wait-Job $dnsJob -Timeout 10
            
            if ($dnsJob.State -eq 'Completed') {
                $null = Receive-Job $dnsJob -ErrorAction SilentlyContinue
                Write-Verbose "$(Get-LocalizedString 'DNSCacheFlushed')"
            }
            elseif ($dnsJob.State -eq 'Running') {
                Stop-Job $dnsJob -ErrorAction SilentlyContinue
                Write-Warning "$(Get-LocalizedString 'DNSFlushTimeout')"
            }
        }
        catch {
            Write-Verbose (Get-LocalizedString 'DNSFlushError' $_)
        }
        finally {
            # Guaranteed job cleanup
            if ($dnsJob) {
                Remove-Job $dnsJob -Force -ErrorAction SilentlyContinue
            }
        }
        
        # SUCCESS!
        Write-Success (Get-LocalizedString 'DNSBlocklistInstalled' $blockedDomains)
        Write-Info "$(Get-LocalizedString 'DNSBlockedTypes')"
        Write-Info "$(Get-LocalizedString 'DNSSource')"
        Write-Warning "$(Get-LocalizedString 'DNSLegitimateWarning')"
    }
    catch {
        Write-Error (Get-LocalizedString 'DNSInstallationFailed' $_)
        Write-Error "$(Get-LocalizedString 'DNSNotInstalled')"
    }
}

# DELIVERY OPTIMIZATION MOVED!
#
# The Set-DeliveryOptimization function was moved to SecurityBaseline-WindowsUpdate.ps1
# and renamed to Set-DeliveryOptimizationDefaults.
#
# Reason: User wants NO Group Policy (would grey out toggle)
#         Instead: Default setting that user can change
#
# OLD VERSION (here, with Policy):
#   HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization
#   -> Group Policy = User cannot change
#
# NEW VERSION (WindowsUpdate.ps1, without Policy):
#   HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config
#   -> User Setting = User can change in Settings
#
# See: SecurityBaseline-WindowsUpdate.ps1 -> Set-DeliveryOptimizationDefaults

function Set-StrictInboundFirewall {
    <#
    .SYNOPSIS
        Configure strict INBOUND firewall rules (block all incoming)
    .DESCRIPTION
        Blocks ALL inbound connections by default
        Allows outbound (you can access internet)
        Essential security hardening!
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    # Dynamic section header based on firewall mode
    if ($script:StrictFirewall) {
        Write-Section "Strict Inbound Firewall (BLOCK ALL INCOMING)"
    }
    else {
        Write-Section "Inbound Firewall (Standard Mode - Localhost Allowed)"
    }
    
    Write-Info "$(Get-LocalizedString 'FirewallConfiguring')"
    
    # CHANGED: Firewall strictness now configurable (for Docker/LLM/localhost services)
    # Default: $script:StrictFirewall = $true (block everything including localhost)
    # Interactive: User can choose to allow localhost (for remote servers, development)
    
    # Set firewall to block ALL inbound (Maximum Security!)
    foreach ($firewallProfile in @('Domain', 'Private', 'Public')) {
        try {
            Write-Verbose "Configuring ${firewallProfile} profile..."
            
            # Block all inbound by default
            Set-NetFirewallProfile -Name $firewallProfile -DefaultInboundAction Block -ErrorAction Stop
            
            # CONFIGURABLE: Block ALL incoming OR allow firewall rules (for localhost)
            if ($script:StrictFirewall) {
                # Maximum Security: Block even allowed apps (kills Docker/LLM/localhost!)
                Set-NetFirewallProfile -Name $firewallProfile -AllowInboundRules False -ErrorAction Stop
                Write-Verbose "     ${firewallProfile}: Ultra-Strict Mode (AllowInboundRules=False)"
            }
            else {
                # Allow Remote/Local Services: Firewall rules work (Docker/LLM/localhost OK)
                Set-NetFirewallProfile -Name $firewallProfile -AllowInboundRules True -ErrorAction Stop
                Write-Verbose "     ${firewallProfile}: Standard Mode (AllowInboundRules=True, localhost functional)"
            }
            
            # Allow all outbound (you can still access internet)
            Set-NetFirewallProfile -Name $firewallProfile -DefaultOutboundAction Allow -ErrorAction Stop
            
            # Enable firewall
            Set-NetFirewallProfile -Name $firewallProfile -Enabled True -ErrorAction Stop
            
            # ===========================
            # LOGGING & NOTIFICATION SETTINGS (Microsoft Baseline 25H2)
            # ===========================
            
            # Disable notifications (no popup on block)
            Set-NetFirewallProfile -Name $firewallProfile -NotifyOnListen False -ErrorAction Stop
            
            # Log file size: 16384 KB (16 MB)
            Set-NetFirewallProfile -Name $firewallProfile -LogMaxSizeKilobytes 16384 -ErrorAction Stop
            
            # Log dropped packets (blocked connections)
            Set-NetFirewallProfile -Name $firewallProfile -LogBlocked True -ErrorAction Stop
            
            # Log successful connections (allowed traffic)
            Set-NetFirewallProfile -Name $firewallProfile -LogAllowed True -ErrorAction Stop
            
            # Public Profile: Additional restrictions (no local firewall/IPsec rules)
            if ($firewallProfile -eq 'Public') {
                Set-NetFirewallProfile -Name $firewallProfile -AllowLocalFirewallRules False -ErrorAction Stop
                Set-NetFirewallProfile -Name $firewallProfile -AllowLocalIPsecRules False -ErrorAction Stop
                Write-Verbose "     ${firewallProfile}: Local FW/IPsec rules BLOCKED"
            }
            
            Write-Verbose "     ${firewallProfile}: Inbound=BLOCK ALL, Outbound=ALLOW, Logging=ENABLED"
        }
        catch {
            Write-Warning (Get-LocalizedString 'FirewallProfileError' $firewallProfile $_)
        }
    }
    
    Write-Success "$(Get-LocalizedString 'FirewallActivated')"
    Write-Info "$(Get-LocalizedString 'FirewallOutbound')"
    
    # Mode-specific messages
    if ($script:StrictFirewall) {
        # Ultra-Strict Mode
        Write-Info "$(Get-LocalizedString 'FirewallInbound')"
        Write-Warning "$(Get-LocalizedString 'FirewallMaxSecurity')"
        Write-Warning "$(Get-LocalizedString 'FirewallCheckbox')"
    }
    else {
        # Standard Mode (Allow localhost)
        Write-Info "Inbound: Default BLOCK, but firewall rules work (localhost/Docker/LLM OK)"
        Write-Success "Localhost connections allowed (AllowInboundRules=True)"
        Write-Info "Remote servers, Docker, LLM services can communicate"
    }
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
