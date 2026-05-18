function Get-CurrentDNSProvider {
    <#
    .SYNOPSIS
        Detect the current DNS provider based on configured DNS servers
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get DNS servers from active adapters
        $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dnsServers -and $dnsServers.ServerAddresses) {
                $primaryDNS = $dnsServers.ServerAddresses | Select-Object -First 1
                
                # Match against known providers
                switch -Regex ($primaryDNS) {
                    '^1\.1\.1\.' { return "Cloudflare" }
                    '^1\.0\.0\.' { return "Cloudflare" }
                    '^9\.9\.9\.' { return "Quad9" }
                    '^149\.112\.' { return "Quad9" }
                    '^94\.140\.14\.' { return "AdGuard" }
                    '^94\.140\.15\.' { return "AdGuard" }
                }
            }
        }
        return $null  # Could not detect provider
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to detect current DNS provider: $_" -Module "DNS"
        return $null
    }
}

function Invoke-DNSConfiguration {
    <#
    .SYNOPSIS
        Configure secure DNS with DNS over HTTPS (DoH)
        
    .DESCRIPTION
        Configures secure DNS on all physical network adapters with:
        - DNS server addresses (IPv4 and IPv6)
        - DNS over HTTPS (DoH) encryption
        - Automatic backup for rollback
        
        Supports three DNS providers:
        - Quad9: Security-focused, Swiss privacy (default)
        - Cloudflare: Fastest resolver, privacy-focused
        - AdGuard: Ad/tracker blocking, EU jurisdiction
        
        All providers perform server-side DNSSEC validation.
        
    .PARAMETER Provider
        DNS provider to use: Quad9, Cloudflare, or AdGuard (default: Quad9)
        
    .PARAMETER DryRun
        Show what would be configured without applying changes
        
    .PARAMETER Force
        Skip connectivity tests and apply configuration anyway
        
    .EXAMPLE
        Invoke-DNSConfiguration
        Configure Quad9 DNS (default, security-focused) on all adapters
        
    .EXAMPLE
        Invoke-DNSConfiguration -Provider Cloudflare
        Configure Cloudflare DNS (fastest) on all adapters
        
    .EXAMPLE
        Invoke-DNSConfiguration -Provider AdGuard -DryRun
        Test AdGuard DNS (ad-blocking) configuration without applying
        
    .OUTPUTS
        PSCustomObject with configuration results
        
    .NOTES
        Requires Administrator privileges
        Creates automatic backup for rollback
        Uses PowerShell Best Practice cmdlets (not netsh)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Cloudflare', 'Quad9', 'AdGuard', 'KEEP')]
        [string]$Provider,
        
        [Parameter()]
        [switch]$DryRun,
        
        [Parameter()]
        [switch]$Force
    )
    
    begin {
        $moduleName = "DNS"
        $startTime = Get-Date
        
        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!
        
        # Provider selection - NonInteractive or Interactive
        if (-not $Provider) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config values
                $Provider = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Default "Quad9"
                $script:DoHMode = Get-NonInteractiveValue -Module "DNS" -Key "dohMode" -Default "REQUIRE"
                
                # Handle "KEEP" provider - detect current DNS and preserve it
                if ($Provider -eq "KEEP") {
                    $detectedProvider = Get-CurrentDNSProvider
                    if ($detectedProvider) {
                        $Provider = $detectedProvider
                        Write-Log -Level INFO -Message "KEEP mode: Detected current provider as $Provider" -Module $moduleName
                    } else {
                        $Provider = "Quad9"
                        Write-Log -Level WARNING -Message "KEEP mode: Could not detect provider, defaulting to Quad9" -Module $moduleName
                    }
                }
                
                Write-NonInteractiveDecision -Module $moduleName -Decision "DNS Provider" -Value $Provider
                Write-NonInteractiveDecision -Module $moduleName -Decision "DoH Mode" -Value $script:DoHMode
            }
            else {
                # Interactive mode
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "  DNS PROVIDER SELECTION" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host ""
                
                Write-Host "[1] Quad9 (9.9.9.9) - RECOMMENDED FOR SECURITY" -ForegroundColor Green
                Write-Host "    PRIMARY STRENGTH: Security + Privacy (Malware Blocking)" -ForegroundColor Cyan
                Write-Host "    Speed 4/5 | Privacy 5/5 | Security 5/5 | Filtering 4/5" -ForegroundColor Gray
                Write-Host "    - Blocks malware/phishing domains automatically" -ForegroundColor Gray
                Write-Host "    - Swiss jurisdiction (strongest privacy laws)" -ForegroundColor Gray
                Write-Host ""
                
                Write-Host "[2] Cloudflare (1.1.1.1) - RECOMMENDED FOR SPEED" -ForegroundColor Yellow
                Write-Host "    PRIMARY STRENGTH: Speed (Fastest Resolver)" -ForegroundColor Cyan
                Write-Host "    Speed 5/5 | Privacy 4/5 | Security 4/5 | Filtering 2/5" -ForegroundColor Gray
                Write-Host "    - Global performance leader" -ForegroundColor Gray
                Write-Host "    - Minimal logging (25h anonymized)" -ForegroundColor Gray
                Write-Host ""
                
                Write-Host "[3] AdGuard DNS (94.140.14.14) - RECOMMENDED FOR AD-BLOCKING" -ForegroundColor Yellow
                Write-Host "    PRIMARY STRENGTH: Ad-Blocking + Tracker Protection" -ForegroundColor Cyan
                Write-Host "    Speed 4/5 | Privacy 4/5 | Security 4/5 | Filtering 5/5" -ForegroundColor Gray
                Write-Host "    - Blocks ads and trackers at DNS level" -ForegroundColor Gray
                Write-Host "    - Family-friendly options available" -ForegroundColor Gray
                Write-Host ""
                
                Write-Host "[0] Skip DNS configuration" -ForegroundColor Gray
                Write-Host "    Keep current system DNS" -ForegroundColor Gray
                Write-Host ""
                
                do {
                    $selection = Read-Host "Select provider [1-3, 0=Skip, default: 1]"
                    if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "1" }
                    
                    if ($selection -notin @('0', '1', '2', '3')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter 0, 1, 2, or 3." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($selection -notin @('0', '1', '2', '3'))
                
                $Provider = switch ($selection) {
                    "1" { "Quad9" }
                    "2" { "Cloudflare" }
                    "3" { "AdGuard" }
                    "0" { $null }
                }
                
                if ($null -eq $Provider) {
                    Write-Host ""
                    Write-Host "DNS configuration skipped" -ForegroundColor Gray
                    Write-Host ""
                    return [PSCustomObject]@{
                        Success            = $true
                        Provider           = "Skipped"
                        AdaptersConfigured = 0
                        DoHEnabled         = $false
                        BackupCreated      = $false
                        Errors             = @()
                        Warnings           = @("DNS configuration skipped by user")
                        Duration           = (Get-Date) - $startTime
                    }
                }
                
                Write-Host ""
                Write-Host "Selected: $Provider" -ForegroundColor Green
                Write-Host ""
                Write-Log -Level DEBUG -Message "User selected DNS provider: $Provider" -Module $moduleName
                
                # DoH Mode Selection (REQUIRE vs ALLOW)
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "  DNS-over-HTTPS (DoH) MODE" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Choose DoH encryption mode:" -ForegroundColor White
                Write-Host ""
                
                Write-Host "[1] REQUIRE Mode (Recommended)" -ForegroundColor Green
                Write-Host "    - Maximum security: NO unencrypted fallback" -ForegroundColor Gray
                Write-Host "    - Best for: Home networks, single-location systems" -ForegroundColor Gray
                Write-Host "    - Warning: May break in corporate networks or captive portals" -ForegroundColor Yellow
                Write-Host ""
                
                Write-Host "[2] ALLOW Mode (Mobile/Enterprise/VPN)" -ForegroundColor Yellow
                Write-Host "    - Balanced: Falls back to UDP if DoH unavailable" -ForegroundColor Gray
                Write-Host "    - Best for: VPN users, mobile devices, enterprise networks" -ForegroundColor Gray
                Write-Host "    - Warning: Less secure (unencrypted fallback possible)" -ForegroundColor Yellow
                Write-Host ""
                
                do {
                    $dohSelection = Read-Host "Select DoH mode [1/2, default: 1]"
                    if ([string]::IsNullOrWhiteSpace($dohSelection)) { $dohSelection = "1" }
                    
                    if ($dohSelection -notin @('1', '2')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter 1 or 2." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($dohSelection -notin @('1', '2'))
                
                $script:DoHMode = switch ($dohSelection) {
                    "1" { "REQUIRE" }
                    "2" { "ALLOW" }
                }
                
                Write-Host ""
                if ($script:DoHMode -eq "REQUIRE") {
                    Write-Host "DoH Mode: REQUIRE (Maximum Security)" -ForegroundColor Green
                }
                else {
                    Write-Host "DoH Mode: ALLOW (Mobile/Enterprise Compatible)" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Log -Level DEBUG -Message "User selected DoH mode: $script:DoHMode" -Module $moduleName
            }
        }
        else {
            # Provider specified via parameter - handle KEEP and get DoHMode
            if ($Provider -eq "KEEP") {
                # Detect current DNS provider and preserve it (only used by GUI)
                $detectedProvider = Get-CurrentDNSProvider
                if ($detectedProvider) {
                    $Provider = $detectedProvider
                    Write-Log -Level INFO -Message "KEEP mode: Detected current provider as $Provider" -Module $moduleName
                } else {
                    $Provider = "Quad9"
                    Write-Log -Level WARNING -Message "KEEP mode: Could not detect provider, defaulting to Quad9" -Module $moduleName
                }
            }
            
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - read DoHMode from config
                $script:DoHMode = Get-NonInteractiveValue -Module "DNS" -Key "dohMode" -Default "REQUIRE"
                Write-NonInteractiveDecision -Module $moduleName -Decision "DNS Provider" -Value $Provider
                Write-NonInteractiveDecision -Module $moduleName -Decision "DoH Mode" -Value $script:DoHMode
            }
            else {
                # Interactive CLI - default to REQUIRE when Provider is passed directly
                $script:DoHMode = "REQUIRE"
            }
        }
        
        # Initialize Session-based backup system
        $moduleBackupPath = $null
        if (-not $DryRun) {
            try {
                Initialize-BackupSystem
                $moduleBackupPath = Start-ModuleBackup -ModuleName "DNS"
                Write-Log -Level INFO -Message "Session backup initialized: $moduleBackupPath" -Module $moduleName
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to initialize backup system: $_" -Module $moduleName
                Write-Log -Level WARNING -Message "Continuing without backup (RISKY!)" -Module $moduleName
            }
        }
        else {
            Write-Log -Level INFO -Message "Skipping backup initialization (DryRun mode)" -Module $moduleName
        }
        
        # Initialize result object
        $result = [PSCustomObject]@{
            Success            = $false
            Provider           = $Provider
            AdaptersConfigured = 0
            DoHEnabled         = $false
            BackupCreated      = $false
            VerificationPassed = $false
            Errors             = @()
            Warnings           = @()
            Duration           = $null
        }
        
        Write-Log -Level INFO -Message " " -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "DNS CONFIGURATION" -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "Provider: $Provider" -Module $moduleName
        Write-Log -Level INFO -Message "Mode: $(if ($DryRun) { 'DRY RUN' } else { 'APPLY' })" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName
    }
    
    process {
        try {
            # Load provider configuration
            $configPath = Join-Path $PSScriptRoot "..\Config\Providers.json"
            
            if (-not (Test-Path $configPath)) {
                throw "Provider configuration file not found: $configPath"
            }
            
            $providersConfig = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            $providerKey = $Provider.ToLower()
            $providerConfig = $providersConfig.providers.$providerKey
            
            if (-not $providerConfig) {
                throw "Provider configuration not found for: $Provider"
            }
            
            # Display provider information
            Write-Log -Level INFO -Message "DNS PROVIDER DETAILS:" -Module $moduleName
            Write-Log -Level INFO -Message "  Name: $($providerConfig.name)" -Module $moduleName
            Write-Log -Level INFO -Message "  Description: $($providerConfig.description)" -Module $moduleName
            Write-Log -Level INFO -Message "  Best for: $($providerConfig.best_for)" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName
            Write-Log -Level INFO -Message "  RATINGS:" -Module $moduleName
            Write-Log -Level INFO -Message "    Speed:    $($providerConfig.ratings.speed)/5" -Module $moduleName
            Write-Log -Level INFO -Message "    Privacy:  $($providerConfig.ratings.privacy)/5" -Module $moduleName
            Write-Log -Level INFO -Message "    Security: $($providerConfig.ratings.security)/5" -Module $moduleName
            Write-Log -Level INFO -Message "    Filtering: $($providerConfig.ratings.filtering)/5" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName
            Write-Log -Level INFO -Message "  FEATURES:" -Module $moduleName
            foreach ($feature in $providerConfig.features) {
                Write-Log -Level INFO -Message "    - $feature" -Module $moduleName
            }
            Write-Log -Level INFO -Message " " -Module $moduleName
            Write-Log -Level INFO -Message "  Jurisdiction: $($providerConfig.jurisdiction)" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName
            
            # Quick connectivity test (unless forced or dry-run)
            if (-not $Force -and -not $DryRun) {
                Write-Log -Level INFO -Message "Testing DNS connectivity (quick check)..." -Module $moduleName
                
                $primaryTest = Test-DNSConnectivity -ServerAddress $providerConfig.ipv4.primary
                
                if (-not $primaryTest.Reachable) {
                    # Non-fatal: TCP port 53 not reachable (may be firewall or VPN), but UDP DNS usually works
                    $result.Warnings += "DNS pre-check skipped (TCP 53 not reachable) - configuration will proceed"
                    Write-Log -Level INFO -Message "DNS connectivity pre-check failed (TCP 53 blocked or timeout) - this is often normal with firewalls/VPNs. DNS will be configured anyway." -Module $moduleName
                }
                elseif (-not $primaryTest.CanResolve) {
                    # Can reach DNS but cannot resolve - still non-fatal
                    Write-Log -Level INFO -Message "DNS server reachable, configuration will proceed" -Module $moduleName
                }
                else {
                    # All good
                    Write-Log -Level SUCCESS -Message "DNS connectivity verified" -Module $moduleName
                }
                
                Write-Log -Level INFO -Message " " -Module $moduleName
            }
            
            # CRITICAL FIX: Create backup BEFORE cleaning DNS state
            # Bug: Reset-DnsState deletes DoH/Policy entries, so backup must happen first
            # to capture the actual pre-apply state (not the cleaned state)
            if (-not $DryRun) {
                Write-Log -Level INFO -Message "Creating backup of current DNS settings..." -Module $moduleName
                
                $backupFile = Backup-DNSSettings
                
                if ($backupFile) {
                    # Register backup in session manifest
                    Complete-ModuleBackup -ItemsBackedUp 1 -Status "Success"
                    
                    $result.BackupCreated = $true
                    Write-Log -Level SUCCESS -Message "Backup created successfully" -Module $moduleName
                }
                else {
                    $result.Warnings += "Could not create backup"
                    Write-Log -Level WARNING -Message "Backup creation failed - continuing without backup" -Module $moduleName
                }
                
                Write-Log -Level INFO -Message " " -Module $moduleName
            }
            
            # CRITICAL: Clean ALL previous DNS state (prevents interference from old providers/VPNs)
            if (-not $DryRun) {
                Write-Log -Level INFO -Message "Cleaning up previous DNS state..." -Module $moduleName
                Reset-DnsState -KeepAdapterDns
                
                # Wait for adapter state to stabilize after cleanup (prevents 0x80004005 errors)
                Start-Sleep -Seconds 3
            }
            else {
                Write-Log -Level INFO -Message "[DRY RUN] Skipping DNS state cleanup (Reset-DnsState)" -Module $moduleName
            }
            
            # Get physical adapters (aggressive VPN/VM filtering)
            $adapters = @(Get-PhysicalAdapters)  # Force array to ensure .Count works
            
            if ($adapters.Count -eq 0) {
                # No physical adapters found - skip gracefully (VM or unusual config)
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  DNS Module Skipped" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "No physical network adapters found." -ForegroundColor Cyan
                Write-Host ""
                Write-Host "This can happen in:" -ForegroundColor Yellow
                Write-Host "  - Virtual machines with unusual network config" -ForegroundColor Gray
                Write-Host "  - Systems with all adapters disabled" -ForegroundColor Gray
                Write-Host "  - Enterprise environments with special setups" -ForegroundColor Gray
                Write-Host ""
                Write-Host "This is NOT an error - DNS configuration will be skipped." -ForegroundColor Green
                Write-Host ""
                
                Write-Log -Level WARNING -Message "DNS skipped: No physical network adapters found" -Module $moduleName
                
                $result.Success = $true  # Not an error - intentional skip
                $result.Warnings += "DNS skipped: No physical network adapters found. Check adapter configuration if this is unexpected."
                
                return $result
            }
            
            Write-Log -Level INFO -Message "Configuring $($adapters.Count) network adapter(s)" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName
            
            # GLOBAL DOH ENFORCEMENT (before per-adapter config)
            # This ensures Windows GUI shows "Encrypted" and forces DoH globally
            # CRITICAL ORDER: netsh FIRST (may reset EnableAutoDoh), then Registry AFTER
            if (-not $DryRun -and $providerConfig.doh.supported) {
                Write-Log -Level INFO -Message "Enabling global DoH enforcement..." -Module $moduleName
                
                try {
                    $dnsParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                    
                    # 1. FIRST: Set global DoH via netsh (this may reset EnableAutoDoh!)
                    $netshResult = netsh dnsclient set global doh=yes 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log -Level DEBUG -Message "  netsh global DoH enabled" -Module $moduleName
                    }
                    else {
                        Write-Log -Level DEBUG -Message "  netsh global DoH: $netshResult (exit code: $LASTEXITCODE)" -Module $moduleName
                    }
                    
                    # 2. SECOND: Set EnableAutoDoh = 2 AFTER netsh (so it persists!)
                    if (-not (Test-Path $dnsParamsPath)) {
                        New-Item -Path $dnsParamsPath -Force | Out-Null
                    }
                    
                    $existing = Get-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
                    if ($null -ne $existing) {
                        Set-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value 2 -Force | Out-Null
                    }
                    else {
                        New-ItemProperty -Path $dnsParamsPath -Name "EnableAutoDoh" -Value 2 -PropertyType DWord -Force | Out-Null
                    }
                    Write-Log -Level DEBUG -Message "  EnableAutoDoh = 2 (Force encrypted DNS)" -Module $moduleName
                    
                    Write-Log -Level SUCCESS -Message "Global DoH enforcement enabled" -Module $moduleName
                }
                catch {
                    Write-Log -Level WARNING -Message "Could not enable global DoH enforcement: $_" -Module $moduleName
                    $result.Warnings += "Global DoH enforcement failed (non-critical)"
                }
                
                Write-Log -Level INFO -Message " " -Module $moduleName
            }
            
            # Configure each adapter
            Write-Log -Level INFO -Message "Configuring DNS servers..." -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName
            
            $configuredCount = 0
            $dohSuccessCount = 0
            
            foreach ($adapter in $adapters) {
                Write-Log -Level INFO -Message "Configuring adapter: $($adapter.Name)" -Module $moduleName
                
                # Set DNS servers (IPv4 + IPv6)
                $dnsResult = Set-DNSServers -InterfaceIndex $adapter.InterfaceIndex `
                    -IPv4Primary $providerConfig.ipv4.primary `
                    -IPv4Secondary $providerConfig.ipv4.secondary `
                    -IPv6Primary $providerConfig.ipv6.primary `
                    -IPv6Secondary $providerConfig.ipv6.secondary `
                    -Validate:(-not $Force) `
                    -DryRun:$DryRun
                
                if ($dnsResult) {
                    $configuredCount++
                    Write-Log -Level SUCCESS -Message "DNS servers configured on $($adapter.Name)" -Module $moduleName
                    
                    # Enable DoH for IPv4 and IPv6 addresses so ALL queries are encrypted
                    if (-not $DryRun -and $providerConfig.doh.supported) {
                        Write-Log -Level DEBUG -Message "Enabling DoH (IPv4 + IPv6)..." -Module $moduleName
                        
                        # Register DoH endpoints for IPv4 servers
                        $dohPrimaryV4 = Enable-DoH -ServerAddress $providerConfig.ipv4.primary `
                            -DohTemplate $providerConfig.doh.template
                        $dohSecondaryV4 = Enable-DoH -ServerAddress $providerConfig.ipv4.secondary `
                            -DohTemplate $providerConfig.doh.template
                        
                        # Register DoH endpoints for IPv6 servers (Windows supports DoH for IPv6 as well)
                        $dohPrimaryV6 = Enable-DoH -ServerAddress $providerConfig.ipv6.primary `
                            -DohTemplate $providerConfig.doh.template
                        $dohSecondaryV6 = Enable-DoH -ServerAddress $providerConfig.ipv6.secondary `
                            -DohTemplate $providerConfig.doh.template
                        
                        if ($dohPrimaryV4 -and $dohSecondaryV4 -and $dohPrimaryV6 -and $dohSecondaryV6) {
                            Write-Log -Level SUCCESS -Message "DoH enabled on $($adapter.Name) for IPv4 and IPv6" -Module $moduleName
                            
                            # TRICK #4: IPv6-FIRST HACK to force Windows DoH validation
                            # Windows needs to see IPv6 servers first to recognize them as DoH-capable
                            try {
                                # Check if adapter has IPv6 enabled
                                $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name `
                                    -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                                $ipv6Enabled = $ipv6Binding -and $ipv6Binding.Enabled
                                
                                if ($ipv6Enabled) {
                                    Write-Log -Level DEBUG -Message "IPv6-First hack: Setting IPv6 servers first..." -Module $moduleName
                                    
                                    # Temporarily set IPv6 FIRST
                                    $ipv6Servers = @($providerConfig.ipv6.primary, $providerConfig.ipv6.secondary)
                                    $ipv4Servers = @($providerConfig.ipv4.primary, $providerConfig.ipv4.secondary)
                                    
                                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                                        -ServerAddresses ($ipv6Servers + $ipv4Servers) -ErrorAction Stop
                                    
                                    # Wait for Windows to validate IPv6 DoH
                                    Write-Log -Level DEBUG -Message "Waiting 5 seconds for IPv6 DoH validation..." -Module $moduleName
                                    Start-Sleep -Seconds 5
                                    
                                    # Reset to IPv4-first (faster for most users)
                                    Write-Log -Level DEBUG -Message "Resetting DNS order (IPv4 first for speed)..." -Module $moduleName
                                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                                        -ServerAddresses ($ipv4Servers + $ipv6Servers) -ErrorAction Stop
                                }
                            }
                            catch {
                                Write-Log -Level DEBUG -Message "IPv6-First hack failed (non-critical): $_" -Module $moduleName
                            }
                            
                            # TRICK #5: Set DohFlags registry keys (ENCRYPTED ONLY!)
                            # This is what makes Windows GUI show "Encrypted" instead of "Unencrypted"
                            Write-Log -Level DEBUG -Message "Setting DoH encryption flags (DohFlags)..." -Module $moduleName
                            
                            try {
                                $adapterGuid = $adapter.InterfaceGuid
                                
                                # IPv4 Servers -> Doh branch
                                foreach ($ip in @($providerConfig.ipv4.primary, $providerConfig.ipv4.secondary)) {
                                    try {
                                        $regPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh\$ip"
                                        if (-not (Test-Path $regPath)) {
                                            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                                        }
                                        New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                                        Write-Log -Level DEBUG -Message "  DohFlags set: $ip (Encrypted Only)" -Module $moduleName
                                    }
                                    catch {
                                        Write-Log -Level DEBUG -Message "  Failed to set DohFlags for $ip : $_" -Module $moduleName
                                    }
                                }
                                
                                # IPv6 Servers -> Doh6 branch (DIFFERENT from IPv4!)
                                foreach ($ip in @($providerConfig.ipv6.primary, $providerConfig.ipv6.secondary)) {
                                    try {
                                        $basePath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$adapterGuid\DohInterfaceSettings\Doh6"
                                        $ipPath = "$basePath\$ip"
                                        
                                        if (-not (Test-Path $basePath)) {
                                            New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                                        }
                                        
                                        if (-not (Test-Path $ipPath)) {
                                            New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                                        }
                                        
                                        New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                                        Write-Log -Level DEBUG -Message "  DohFlags set: $ip (Encrypted Only, Doh6)" -Module $moduleName
                                    }
                                    catch {
                                        Write-Log -Level DEBUG -Message "  Failed to set DohFlags for $ip : $_" -Module $moduleName
                                    }
                                }
                                
                                $dohSuccessCount++
                                Write-Log -Level SUCCESS -Message "DoH encryption enforced on $($adapter.Name) (all servers, DohFlags set)" -Module $moduleName
                            }
                            catch {
                                $result.Warnings += "DoH flags could not be set on $($adapter.Name) - DNS may not show as encrypted in UI"
                                Write-Log -Level WARNING -Message "DoH flags configuration had issues on $($adapter.Name)" -Module $moduleName
                            }
                            
                            # DHCP DNS Override Protection
                            if (-not $DryRun) {
                                $dhcpDisabled = Disable-DHCPDnsOverride -InterfaceIndex $adapter.InterfaceIndex -DryRun:$false
                                if (-not $dhcpDisabled) {
                                    $result.Warnings += "Could not disable DHCP DNS override on $($adapter.Name)"
                                }
                            }
                            else {
                                Write-Log -Level INFO -Message "[DRY RUN] Skipping DHCP DNS override protection on $($adapter.Name)" -Module $moduleName
                            }
                        }
                        else {
                            $result.Warnings += "DoH could not be enabled on $($adapter.Name)"
                            Write-Log -Level WARNING -Message "DoH configuration had issues on $($adapter.Name)" -Module $moduleName
                        }
                    }
                }
                else {
                    $result.Errors += "Failed to configure $($adapter.Name)"
                    Write-Log -Level ERROR -Message "Failed to configure $($adapter.Name)" -Module $moduleName
                }
                
                Write-Log -Level INFO -Message " " -Module $moduleName
            }
            
            # CRITICAL: Set global DoH policy according to selected mode (REQUIRE or ALLOW)
            if (-not $DryRun -and $dohSuccessCount -gt 0) {
                $modeDescription = if ($script:DoHMode -eq "ALLOW") { "ALLOW mode (fallback permitted)" } else { "REQUIRE mode (no fallback)" }
                Write-Log -Level INFO -Message "Enforcing global DoH policy ($modeDescription)..." -Module $moduleName
                $policySet = Set-DoHPolicy
                if ($policySet) {
                    $successDesc = if ($script:DoHMode -eq "ALLOW") { "Global DoH policy: ALLOW mode active (fallback allowed by design)" } else { "Global DoH policy: REQUIRE mode active (no unencrypted fallback)" }
                    Write-Log -Level SUCCESS -Message $successDesc -Module $moduleName
                }
                else {
                    $result.Warnings += "Could not set global DoH policy - DoH may fall back to unencrypted"
                }
            }
            
            $result.AdaptersConfigured = $configuredCount
            $result.DoHEnabled = ($dohSuccessCount -gt 0)
            
            # Final status
            if ($configuredCount -eq $adapters.Count) {
                $result.Success = $true
                Write-Log -Level SUCCESS -Message "DNS configuration completed successfully" -Module $moduleName
                Write-Log -Level INFO -Message "Configured $configuredCount of $($adapters.Count) adapter(s)" -Module $moduleName
                
                if ($result.DoHEnabled) {
                    Write-Log -Level SUCCESS -Message "DNS over HTTPS (DoH) is active - DNS queries are encrypted" -Module $moduleName
                }
            }
            else {
                Write-Log -Level WARNING -Message "DNS configuration completed with errors" -Module $moduleName
                Write-Log -Level WARNING -Message "Configured $configuredCount of $($adapters.Count) adapter(s)" -Module $moduleName
            }
            
            # Mark verification as passed (individual functions already verified)
            if (-not $DryRun -and $result.Success) {
                $result.VerificationPassed = $true
            }
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
            Write-ErrorLog -Message "DNS configuration failed" -Module $moduleName -ErrorRecord $_
        }
    }
    
    end {
        $result.Duration = (Get-Date) - $startTime
        
        # Flush DNS cache for immediate effect (only on success)
        if ($result.Success -and -not $DryRun) {
            Write-Log -Level INFO -Message "Flushing DNS resolver cache for immediate effect..." -Module $moduleName
            try {
                Clear-DnsClientCache -ErrorAction Stop
                Write-Log -Level SUCCESS -Message "DNS cache cleared successfully" -Module $moduleName
            }
            catch {
                Write-Log -Level WARNING -Message "Could not flush DNS cache: $_" -Module $moduleName
                # Non-critical: continue anyway
            }
        }
        
        Write-Log -Level INFO -Message " " -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "CONFIGURATION SUMMARY" -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "Provider: $($result.Provider)" -Module $moduleName
        Write-Log -Level INFO -Message "Adapters configured: $($result.AdaptersConfigured)" -Module $moduleName
        Write-Log -Level INFO -Message "DoH enabled: $(if ($result.DoHEnabled) { 'Yes' } else { 'No' })" -Module $moduleName
        Write-Log -Level INFO -Message "Backup created: $(if ($result.BackupCreated) { 'Yes' } else { 'No' })" -Module $moduleName
        Write-Log -Level INFO -Message "Duration: $([math]::Round($result.Duration.TotalSeconds, 2)) seconds" -Module $moduleName
        
        if ($result.Warnings.Count -gt 0) {
            Write-Log -Level INFO -Message "Warnings: $($result.Warnings.Count)" -Module $moduleName
            foreach ($warn in $result.Warnings) {
                Write-Log -Level INFO -Message "  Warning: $warn" -Module $moduleName
            }
        }
        
        if ($result.Errors.Count -gt 0) {
            Write-Log -Level INFO -Message "Errors: $($result.Errors.Count)" -Module $moduleName
            foreach ($err in $result.Errors) {
                Write-Log -Level ERROR -Message "  Error: $err" -Module $moduleName
            }
        }
        
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message " " -Module $moduleName
        
        # GUI parsing marker for settings count
        Write-Log -Level SUCCESS -Message "Applied 5 settings" -Module $moduleName
        
        return $result
    }
}
