function Test-CurrentDnsUsesLanResolver {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $addresses = @(Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object { $_.Status -eq 'Up' } |
            ForEach-Object { Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ErrorAction Stop } |
            ForEach-Object { $_.ServerAddresses } |
            Where-Object { $_ })

        foreach ($address in $addresses) {
            $parsedAddress = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$address, [ref]$parsedAddress)) { continue }
            $bytes = $parsedAddress.GetAddressBytes()
            if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                if ($bytes[0] -eq 10 -or $bytes[0] -eq 127 -or
                    ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                    ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
                    ($bytes[0] -eq 169 -and $bytes[1] -eq 254)) {
                    return $true
                }
            }
            elseif ($parsedAddress.Equals([System.Net.IPAddress]::IPv6Loopback) -or
                ($bytes[0] -band 0xFE) -eq 0xFC -or
                ($bytes[0] -eq 0xFE -and ($bytes[1] -band 0xC0) -eq 0x80)) {
                return $true
            }
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Could not inspect current DNS resolver scope: $($_.Exception.Message)" -Module 'DNS'
        throw 'Current DNS resolver scope could not be inspected; refusing to replace network DNS without that safety check'
    }
    return $false
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
        - Quad9: Threat-domain blocking, Swiss foundation (default)
        - Cloudflare: Unfiltered resolver with audited privacy commitments
        - AdGuard: Ad/tracker/malicious-domain blocking, Cyprus controller

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
        Configure the unfiltered Cloudflare resolver on all adapters

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
        $dnsCheckCount = Get-DnsDeclaredCheckCount
        $currentDnsUsesLanResolver = $false
        $resolverScopeInspected = $false
        $lanResolverNoticeShown = $false
        $resolverScopeWarning = ''
        $resolverConnectivityProven = $false
        $skipResult = $null

        # Core/Rollback.ps1 is loaded by Framework.ps1 - DO NOT load again here
        # Loading it twice would reset $script:BackupBasePath and break the backup system!

        # Provider selection - NonInteractive or Interactive
        if (-not $Provider) {
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - use config values
                $Provider = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Required
                $script:DoHMode = Get-NonInteractiveValue -Module "DNS" -Key "dohMode" -Required

                Write-NonInteractiveDecision -Module $moduleName -Decision "DNS Provider" -Value $Provider
                Write-NonInteractiveDecision -Module $moduleName -Decision "DoH Mode" -Value $script:DoHMode
            }
            else {
                # Interactive mode
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  DNS PROVIDER SELECTION" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host ""

                # Put the device-specific resolver evidence before the user's
                # choice, where it can actually influence KEEP versus replace.
                # A failed read does not block KEEP; a replacement attempt
                # repeats the probe below and fails closed before mutation.
                try {
                    $currentDnsUsesLanResolver = Test-CurrentDnsUsesLanResolver
                    $resolverScopeInspected = $true
                    if ($currentDnsUsesLanResolver) {
                        Write-Host "This device currently receives DNS from a router or LAN resolver." -ForegroundColor Cyan
                        Write-Host "Choose [0] KEEP to preserve it, or [1-3] to replace it." -ForegroundColor Cyan
                        Write-Host ""
                        $lanResolverNoticeShown = $true
                    }
                }
                catch {
                    $resolverScopeWarning = 'Current router/LAN DNS could not be inspected. KEEP remains safe; selecting a replacement will repeat this check and fail closed if it is still unavailable.'
                    Write-Host $resolverScopeWarning -ForegroundColor Yellow
                    Write-Host ""
                }

                Write-Host "[1] Quad9 (9.9.9.9) - RECOMMENDED FOR SECURITY" -ForegroundColor Green
                Write-Host "    - Blocks domains identified as malicious by multiple threat feeds" -ForegroundColor Gray
                Write-Host "    - Swiss non-profit; ordinary query logs do not retain client IPs" -ForegroundColor Gray
                Write-Host ""

                Write-Host "[2] Cloudflare (1.1.1.1) - UNFILTERED RESOLVER" -ForegroundColor Yellow
                Write-Host "    - Selected endpoints do not block content" -ForegroundColor Gray
                Write-Host "    - Limited resolver logs and truncated IPs are deleted within 25 hours" -ForegroundColor Gray
                Write-Host ""

                Write-Host "[3] AdGuard DNS (94.140.14.14) - RECOMMENDED FOR AD-BLOCKING" -ForegroundColor Yellow
                Write-Host "    - Blocks ads, trackers, and domains classified as malicious" -ForegroundColor Gray
                Write-Host "    - Policy: aggregated metrics; anonymous requested-domain set kept 24 hours" -ForegroundColor Gray
                Write-Host ""

                Write-Host "[0] Skip DNS configuration" -ForegroundColor Gray
                Write-Host "    Keep current system DNS" -ForegroundColor Gray
                Write-Host "    Selecting [1-3] replaces current network DNS; [0] Skip preserves it." -ForegroundColor Cyan
                Write-Host ""

                do {
                    Write-Host "Select provider [1-3, 0=Skip] (default: 1): " -ForegroundColor Yellow -NoNewline
                    $selection = Read-Host
                    if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "1" }

                    if ($selection -notin @('0', '1', '2', '3')) {
                        Write-Host ""
                        Write-Host "Invalid input. Please enter 0, 1, 2, or 3." -ForegroundColor Red
                        Write-Host ""
                    }
                } while ($selection -notin @('0', '1', '2', '3'))

                # The mapping is a tested pure function; the loop above only
                # guarantees the input is one of its four accepted selections.
                # The result must NOT be assigned to $Provider directly: its
                # ValidateSet is re-applied by PowerShell 5.1 on every later
                # assignment, so writing the $null skip signal into it throws
                # before the skip branch below can run.
                $resolvedProvider = Resolve-DnsProviderSelection -Selection $selection

                if ($null -eq $resolvedProvider) {
                    Write-Host ""
                    Write-Host "DNS configuration skipped" -ForegroundColor Gray
                    Write-Host ""
                    $skipResult = [PSCustomObject]@{
                        # KEEP is a successfully honored no-mutation decision,
                        # not a failed module. This lets a complete Apply finish
                        # successfully while the verifier still reports the five
                        # DNS checks as deliberately not selected.
                        Success            = $true
                        Status             = 'Success'
                        Provider           = 'KEEP'
                        DoHMode            = 'KEEP'
                        AdaptersConfigured = 0
                        AdaptersPreviewed  = 0
                        DoHEnabled         = $false
                        BackupCreated      = $false
                        VerificationPassed = $null
                        ChecksSkipped      = $dnsCheckCount
                        Errors             = @()
                        Warnings           = @("DNS configuration skipped by user")
                        Duration           = (Get-Date) - $startTime
                    }
                    return
                }
                $Provider = $resolvedProvider

                Write-Host ""
                Write-Host "Selected: $Provider" -ForegroundColor Green
                Write-Host ""
                Write-Log -Level DEBUG -Message "User selected DNS provider: $Provider" -Module $moduleName

                # DoH Mode Selection (REQUIRE vs ALLOW)
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "  DNS-over-HTTPS (DoH) MODE" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
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
                    Write-Host "Select DoH mode [1/2] (default: 1): " -ForegroundColor Yellow -NoNewline
                    $dohSelection = Read-Host
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
            # Provider specified via parameter; KEEP is handled as a true skip below.
            if (Test-NonInteractiveMode) {
                # NonInteractive mode (GUI) - read DoHMode from config
                $script:DoHMode = Get-NonInteractiveValue -Module "DNS" -Key "dohMode" -Required
                Write-NonInteractiveDecision -Module $moduleName -Decision "DNS Provider" -Value $Provider
                Write-NonInteractiveDecision -Module $moduleName -Decision "DoH Mode" -Value $script:DoHMode
            }
            else {
                # Interactive CLI - default to REQUIRE when Provider is passed directly
                $script:DoHMode = "REQUIRE"
            }
        }

        if ($Provider -eq 'KEEP') {
            $skipMessage = 'DNS configuration skipped; current resolver state preserved.'
            Write-Log -Level INFO -Message $skipMessage -Module $moduleName
            if (Test-NonInteractiveMode) {
                Write-NonInteractiveDecision -Module $moduleName -Decision 'DNS Provider' -Value 'KEEP (Skip)'
            }
            $skipResult = [PSCustomObject]@{
                Success            = $true
                Status             = 'Success'
                Provider           = 'KEEP'
                DoHMode            = 'KEEP'
                AdaptersConfigured = 0
                AdaptersPreviewed  = 0
                DoHEnabled         = $false
                BackupCreated      = $false
                VerificationPassed = $null
                ChecksSkipped      = $dnsCheckCount
                Errors             = @()
                Warnings           = @('DNS configuration skipped; current network DNS was preserved')
                Duration           = (Get-Date) - $startTime
            }
            return
        }

        if ($Provider -notin @('Cloudflare', 'Quad9', 'AdGuard')) {
            throw "Unsupported DNS provider: $Provider"
        }
        if ($script:DoHMode -notin @('REQUIRE', 'ALLOW')) {
            throw "Unsupported DNS-over-HTTPS mode: $($script:DoHMode)"
        }

        # Resolver inspection is a pre-mutation safety gate, not a prerequisite
        # for KEEP or for a non-mutating preview. A live Apply must prove this
        # scope; DryRun reports an unavailable probe without pretending that a
        # LAN resolver was absent.
        if (-not $resolverScopeInspected) {
            try {
                $currentDnsUsesLanResolver = Test-CurrentDnsUsesLanResolver
                $resolverScopeInspected = $true
                $resolverScopeWarning = ''
            }
            catch {
                if (-not $DryRun) { throw }
                $resolverScopeWarning = 'DryRun could not inspect whether current DNS is supplied by a router or LAN resolver; no changes were made.'
                Write-Log -Level WARNING -Message $resolverScopeWarning -Module $moduleName
            }
        }
        if ($currentDnsUsesLanResolver) {
            $lanResolverNote = 'This selection replaces router/LAN DNS; choosing KEEP preserves that resolver unchanged.'
            Write-Log -Level INFO -Message "LAN resolver note: $lanResolverNote" -Module $moduleName
            if (Test-NonInteractiveMode) {
                Write-NonInteractiveDecision -Module $moduleName -Decision 'LAN resolver note' -Value $lanResolverNote
            }
            elseif (-not $lanResolverNoticeShown) { Write-Host $lanResolverNote -ForegroundColor Cyan }
        }

        # Initialize the result before backup setup so an initialization failure
        # is returned as a structured module failure instead of dereferencing null.
        $result = [PSCustomObject]@{
            Success            = $false
            Status             = 'Failed'
            Provider           = $Provider
            DoHMode            = [string]$script:DoHMode
            AdaptersConfigured = 0
            AdaptersPreviewed  = 0
            DoHEnabled         = $false
            BackupCreated      = $false
            VerificationPassed = $false
            ChecksApplied       = 0
            ChecksSkipped      = 0
            Errors             = @()
            Warnings           = @()
            Duration           = $null
        }
        if (-not [string]::IsNullOrWhiteSpace($resolverScopeWarning)) {
            $result.Warnings += $resolverScopeWarning
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
        if ($null -ne $skipResult) { return }
        try {
            # Load provider configuration
            $providersConfig = Get-DnsProviderConfiguration
            $providerKey = $Provider.ToLowerInvariant()
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
            Write-Log -Level INFO -Message "  FEATURES:" -Module $moduleName
            foreach ($feature in $providerConfig.features) {
                Write-Log -Level INFO -Message "    - $feature" -Module $moduleName
            }
            Write-Log -Level INFO -Message " " -Module $moduleName
            Write-Log -Level INFO -Message "  Jurisdiction: $($providerConfig.jurisdiction)" -Module $moduleName
            Write-Log -Level INFO -Message "  Source: $($providerConfig.documentation)" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName

            # Quick connectivity test (unless forced or dry-run)
            if (-not $Force -and -not $DryRun) {
                Write-Log -Level INFO -Message "Testing DNS connectivity (quick check)..." -Module $moduleName

                $primaryTest = Test-DNSConnectivity -ServerAddress $providerConfig.ipv4.primary

                if ([bool]$primaryTest.SkippedByDohRequirePolicy) {
                    $tcpNote = if ($primaryTest.Reachable) { 'TCP 53 reachable' } else { 'TCP 53 probe unavailable' }
                    Write-Log -Level INFO -Message "Pre-apply classic DNS probe skipped: the active DoH REQUIRE policy forbids unencrypted queries ($tcpNote). Apply relies on exact readback and DoH verification." -Module $moduleName
                }
                elseif (-not $primaryTest.CanResolve) {
                    $precheckWarning = "Selected resolver did not answer the pre-apply DNS query; Apply will still use the Windows DNS-client validation unless Force was selected. Detail: $($primaryTest.ErrorMessage)"
                    $result.Warnings += $precheckWarning
                    Write-Log -Level WARNING -Message $precheckWarning -Module $moduleName
                }
                else {
                    # Resolve-DnsName queried this exact resolver explicitly.
                    # Repeating Set-DnsClientServerAddress -Validate is not a
                    # stronger proof and can fail with a generic CIM error
                    # after SecurityBaseline has already hardened the host in
                    # an Apply-All run. Exact post-write readback and DoH
                    # verification still gate success below.
                    $resolverConnectivityProven = $true
                    $transportNote = if ($primaryTest.Reachable) { 'DNS answer and TCP 53 confirmed' } else { 'DNS answer confirmed; TCP 53 probe unavailable' }
                    Write-Log -Level SUCCESS -Message "DNS connectivity pre-check passed ($transportNote)" -Module $moduleName
                }

                Write-Log -Level INFO -Message " " -Module $moduleName
            }

            # Start and seal BAVR only after provider validation and before the
            # first mutation.
            if (-not $DryRun) {
                if (-not (Initialize-BackupSystem)) {
                    throw 'Backup system initialization returned failure'
                }
                $moduleBackupPath = Start-ModuleBackup -ModuleName 'DNS'
                if (-not $moduleBackupPath) {
                    throw 'DNS module backup folder was not created'
                }
                Write-Log -Level INFO -Message "Session backup initialized: $moduleBackupPath" -Module $moduleName
                Write-Log -Level INFO -Message "Creating backup of current DNS settings..." -Module $moduleName

                $managedDohAddresses = if ($providerConfig.doh.supported) {
                    @(
                        $providerConfig.ipv4.primary,
                        $providerConfig.ipv4.secondary,
                        $providerConfig.ipv6.primary,
                        $providerConfig.ipv6.secondary
                    )
                }
                else { @() }
                $backupFile = Backup-DNSSettings -ManagedDohAddresses $managedDohAddresses

                if ($backupFile) {
                    $dnsBackupState = Get-Content -LiteralPath $backupFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $null = Assert-DNSBackupSnapshot -Snapshot $dnsBackupState
                    $null = Assert-DNSPrestate -Snapshot $dnsBackupState
                    # Seal the exact registered artifact set, not a hard-coded
                    # count that could let an incomplete backup appear complete.
                    $registeredArtifacts = @($global:BackupIndex | Where-Object { $_.Module -eq 'DNS' })
                    $backupCompleted = Complete-ModuleBackup -ItemsBackedUp $registeredArtifacts.Count -Status "Success"
                    if (-not $backupCompleted) {
                        throw 'DNS backup manifest completion failed'
                    }
                    $null = Assert-DNSPrestate -Snapshot $dnsBackupState

                    $result.BackupCreated = $true
                    Write-Log -Level SUCCESS -Message "Backup created successfully" -Module $moduleName
                }
                else {
                    throw 'Could not create complete DNS backup'
                }

                Write-Log -Level INFO -Message " " -Module $moduleName
            }

            # Get physical adapters (aggressive VPN/VM filtering)
            $adapters = @(Get-PhysicalAdapters -RequireVpnInspection)  # Force array to ensure .Count works

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
                Write-Host "DNS configuration cannot be verified without a target adapter." -ForegroundColor Red
                Write-Host ""

                Write-Log -Level WARNING -Message "DNS skipped: No physical network adapters found" -Module $moduleName

                $result.Success = $false
                throw 'DNS skipped: No physical network adapters found'
            }

            if (-not $DryRun) {
                $currentAdapterGuids = @($adapters | ForEach-Object {
                        $guid = [string]$_.InterfaceGuid
                        if (-not $guid.StartsWith('{')) { $guid = "{$guid}" }
                        $guid
                    } | Sort-Object)
                $backedUpAdapterGuids = @($dnsBackupState.Adapters | ForEach-Object {
                        [string]$_.InterfaceGuid
                    } | Sort-Object)
                if (@(Compare-Object -ReferenceObject $backedUpAdapterGuids -DifferenceObject $currentAdapterGuids).Count -gt 0) {
                    throw 'Physical adapter set changed after DNS backup; Apply aborted before mutation'
                }
            }

            Write-Log -Level INFO -Message "Configuring $($adapters.Count) network adapter(s)" -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName

            # Configure each adapter
            Write-Log -Level INFO -Message "Configuring DNS servers..." -Module $moduleName
            Write-Log -Level INFO -Message " " -Module $moduleName

            $configuredCount = 0
            $policySet = $true

            foreach ($adapter in $adapters) {
                Write-Log -Level INFO -Message "Configuring adapter: $($adapter.Name)" -Module $moduleName

                if ($DryRun) {
                    $ipv6Binding = $adapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
                    $configureIPv6 = [bool]($ipv6Binding -and $ipv6Binding.Enabled -and (Test-DNSIPv6StackEnabled))
                }
                else {
                    $adapterGuid = [string]$adapter.InterfaceGuid
                    if (-not $adapterGuid.StartsWith('{')) { $adapterGuid = "{$adapterGuid}" }
                    $sealedAdapterState = @($dnsBackupState.Adapters | Where-Object {
                            [string]$_.InterfaceGuid -eq $adapterGuid
                        })
                    if ($sealedAdapterState.Count -ne 1) {
                        throw "Adapter is not represented exactly once in the sealed DNS backup: $adapterGuid"
                    }
                    $configureIPv6 = [bool](@($sealedAdapterState[0].Families | Where-Object {
                                [int]$_.AddressFamily -eq 23
                            })[0].Managed)
                }

                # Set DNS servers (IPv4 + IPv6)
                $dnsResult = Set-DNSServers -InterfaceIndex $adapter.InterfaceIndex `
                    -IPv4Primary $providerConfig.ipv4.primary `
                    -IPv4Secondary $providerConfig.ipv4.secondary `
                    -IPv6Primary $providerConfig.ipv6.primary `
                    -IPv6Secondary $providerConfig.ipv6.secondary `
                    -ConfigureIPv6 $configureIPv6 `
                    -Validate:(-not $Force -and -not $resolverConnectivityProven) `
                    -DryRun:$DryRun

                if ($dnsResult) {
                    $configuredCount++
                    Write-Log -Level SUCCESS -Message "DNS servers configured on $($adapter.Name)" -Module $moduleName

                }
                else {
                    $result.Errors += "Failed to configure $($adapter.Name)"
                    Write-Log -Level ERROR -Message "Failed to configure $($adapter.Name)" -Module $moduleName
                }

                Write-Log -Level INFO -Message " " -Module $moduleName
            }

            # DoH registrations are global, not per adapter. Configure each
            # selected endpoint exactly once after all adapter DNS writes pass.
            $dohRegistrationPassed = -not [bool]$providerConfig.doh.supported
            if (-not $DryRun -and $providerConfig.doh.supported -and $configuredCount -eq $adapters.Count) {
                $dohRegistrationPassed = $true
                foreach ($serverAddress in @(
                        $providerConfig.ipv4.primary,
                        $providerConfig.ipv4.secondary,
                        $providerConfig.ipv6.primary,
                        $providerConfig.ipv6.secondary
                    )) {
                    if (-not (Enable-DoH -ServerAddress $serverAddress -DohTemplate $providerConfig.doh.template)) {
                        $result.Errors += "DoH registration failed for $serverAddress"
                        $dohRegistrationPassed = $false
                    }
                }
            }

            # Windows' global endpoint list and DoHPolicy control transport,
            # but its Settings UI labels a resolver as encrypted only when the
            # documented per-interface DNS_SETTING_DOH properties also exist.
            # Derive these internal targets from the existing ALLOW/REQUIRE
            # choice; this intentionally adds no new UX question.
            $interfaceDohPassed = -not [bool]$providerConfig.doh.supported
            if (-not $DryRun -and $providerConfig.doh.supported -and $dohRegistrationPassed) {
                $interfaceDohPassed = $true
                $allowInterfaceFallback = ($script:DoHMode -eq 'ALLOW')
                foreach ($adapter in $adapters) {
                    $adapterGuid = [string]$adapter.InterfaceGuid
                    if (-not $adapterGuid.StartsWith('{')) { $adapterGuid = "{$adapterGuid}" }
                    $sealedAdapterState = @($dnsBackupState.Adapters | Where-Object {
                            [string]$_.InterfaceGuid -eq $adapterGuid
                        })
                    if ($sealedAdapterState.Count -ne 1) {
                        throw "Adapter native DoH state is missing from sealed DNS backup: $adapterGuid"
                    }
                    foreach ($familyState in @($sealedAdapterState[0].Families | Where-Object {
                                [bool]$_.InterfaceDohManaged
                            })) {
                        $family = [int]$familyState.AddressFamily
                        $familyServers = if ($family -eq 2) {
                            @($providerConfig.ipv4.primary, $providerConfig.ipv4.secondary)
                        }
                        else { @($providerConfig.ipv6.primary, $providerConfig.ipv6.secondary) }
                        $targetState = ConvertTo-DnsInterfaceDohTargetState `
                            -AddressFamily $family `
                            -NameServers $familyServers `
                            -DohTemplate ([string]$providerConfig.doh.template) `
                            -AllowFallbackToUdp $allowInterfaceFallback
                        try {
                            $interfaceDohSet = Set-DnsInterfaceDohState `
                                -InterfaceGuid $adapterGuid `
                                -AddressFamily $family `
                                -NameServers @($targetState.NameServers) `
                                -Properties @($targetState.Properties) `
                                -Confirm:$false
                            if (-not $interfaceDohSet) {
                                throw 'Native per-interface DoH mutation was not confirmed'
                            }
                        }
                        catch {
                            $interfaceDohPassed = $false
                            $result.Errors += "Per-adapter DoH configuration failed for $($adapter.Name)/$family`: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Set the documented DNS Client DoH policy according to the selected mode.
            if (-not $DryRun -and $providerConfig.doh.supported -and $dohRegistrationPassed) {
                $modeDescription = if ($script:DoHMode -eq "ALLOW") { "ALLOW mode (fallback permitted)" } else { "REQUIRE mode (no fallback)" }
                Write-Log -Level INFO -Message "Enforcing global DoH policy ($modeDescription)..." -Module $moduleName
                $policySet = Set-DoHPolicy
                if ($policySet) {
                    $successDesc = if ($script:DoHMode -eq "ALLOW") { "Global DoH policy: ALLOW mode active (fallback allowed by design)" } else { "Global DoH policy: REQUIRE mode active (no unencrypted fallback)" }
                    Write-Log -Level SUCCESS -Message $successDesc -Module $moduleName
                }
                else {
                    $result.Errors += "Could not set global DoH policy"
                    $policySet = $false
                }
            }

            if ($DryRun) {
                $result.AdaptersPreviewed = $configuredCount
                $result.AdaptersConfigured = 0
            }
            else {
                $result.AdaptersConfigured = $configuredCount
            }
            $result.DoHEnabled = [bool]($providerConfig.doh.supported -and $dohRegistrationPassed -and $policySet)

            $dohApplyPassed = (-not $providerConfig.doh.supported) -or $DryRun -or
                ($dohRegistrationPassed -and $interfaceDohPassed -and $policySet)
            $applyPassed = ($configuredCount -eq $adapters.Count -and $result.Errors.Count -eq 0 -and
                $dohApplyPassed -and ($DryRun -or $result.BackupCreated))

            if ($DryRun) {
                $result.Success = $applyPassed
                $result.VerificationPassed = $null
            }
            elseif ($applyPassed) {
                $expectedIPv4 = @($providerConfig.ipv4.primary, $providerConfig.ipv4.secondary)
                $expectedIPv6 = @($providerConfig.ipv6.primary, $providerConfig.ipv6.secondary)
                $expectedAddresses = @($expectedIPv4 + $expectedIPv6)
                $verificationPassed = $true

                foreach ($adapter in $adapters) {
                    $adapterGuid = [string]$adapter.InterfaceGuid
                    if (-not $adapterGuid.StartsWith('{')) { $adapterGuid = "{$adapterGuid}" }
                    $sealedAdapterState = @($dnsBackupState.Adapters | Where-Object {
                            [string]$_.InterfaceGuid -eq $adapterGuid
                        })
                    if ($sealedAdapterState.Count -ne 1) {
                        throw "Adapter verification state is missing from sealed DNS backup: $adapterGuid"
                    }
                    $verifyIPv6 = [bool](@($sealedAdapterState[0].Families | Where-Object {
                                [int]$_.AddressFamily -eq 23
                            })[0].Managed)
                    $verifiedFamilies = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop)
                    $familyExpectations = @([PSCustomObject]@{ Family = 2; Addresses = $expectedIPv4; Label = 'IPv4' })
                    if ($verifyIPv6) {
                        $familyExpectations += [PSCustomObject]@{ Family = 23; Addresses = $expectedIPv6; Label = 'IPv6' }
                    }
                    foreach ($familyExpectation in $familyExpectations) {
                        $actualFamily = @($verifiedFamilies | Where-Object { [int]$_.AddressFamily -eq $familyExpectation.Family })
                        $familyMatches = ($actualFamily.Count -eq 1 -and
                            @($actualFamily[0].ServerAddresses).Count -eq $familyExpectation.Addresses.Count)
                        if ($familyMatches) {
                            for ($addressIndex = 0; $addressIndex -lt $familyExpectation.Addresses.Count; $addressIndex++) {
                                $expectedAddress = [System.Net.IPAddress]::Parse([string]$familyExpectation.Addresses[$addressIndex])
                                $actualAddress = $null
                                if (-not [System.Net.IPAddress]::TryParse([string]$actualFamily[0].ServerAddresses[$addressIndex], [ref]$actualAddress) -or
                                    -not $expectedAddress.Equals($actualAddress)) {
                                    $familyMatches = $false
                                    break
                                }
                            }
                        }
                        if (-not $familyMatches) {
                            Write-Log -Level ERROR -Message "$($familyExpectation.Label) DNS server order/readback verification failed on $($adapter.Name)" -Module $moduleName
                            $verificationPassed = $false
                        }
                    }
                }

                if ($providerConfig.doh.supported) {
                    $registeredDoh = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
                    $expectedFallback = ($script:DoHMode -eq 'ALLOW')
                    foreach ($expectedAddress in $expectedAddresses) {
                        $canonicalExpectedAddress = ConvertTo-DnsCanonicalAddress -Address ([string]$expectedAddress)
                        $dohMatch = @($registeredDoh | Where-Object {
                                (ConvertTo-DnsCanonicalAddress -Address ([string]$_.ServerAddress)) -eq $canonicalExpectedAddress
                            })
                        if ($dohMatch.Count -ne 1 -or
                            [string]$dohMatch[0].DohTemplate -cne [string]$providerConfig.doh.template -or
                            [bool]$dohMatch[0].AllowFallbackToUdp -ne $expectedFallback -or
                            -not [bool]$dohMatch[0].AutoUpgrade) {
                            Write-Log -Level ERROR -Message "DoH registration verification failed for $expectedAddress" -Module $moduleName
                            $verificationPassed = $false
                        }
                    }

                    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                    $policyKey = Get-Item -LiteralPath $policyPath -ErrorAction Stop
                    $expectedPolicy = if ($script:DoHMode -eq 'ALLOW') { 2 } else { 3 }
                    if ($policyKey.GetValueKind('DoHPolicy').ToString() -ne 'DWord' -or
                        [int]$policyKey.GetValue('DoHPolicy') -ne $expectedPolicy) {
                        Write-Log -Level ERROR -Message 'DoHPolicy verification failed' -Module $moduleName
                        $verificationPassed = $false
                    }

                    $expectedInterfaceFallback = ($script:DoHMode -eq 'ALLOW')
                    foreach ($adapter in $adapters) {
                        $adapterGuid = [string]$adapter.InterfaceGuid
                        if (-not $adapterGuid.StartsWith('{')) { $adapterGuid = "{$adapterGuid}" }
                        $sealedAdapterState = @($dnsBackupState.Adapters | Where-Object {
                                [string]$_.InterfaceGuid -eq $adapterGuid
                            })
                        foreach ($familyState in @($sealedAdapterState[0].Families | Where-Object {
                                    [bool]$_.InterfaceDohManaged
                                })) {
                            $family = [int]$familyState.AddressFamily
                            $familyServers = if ($family -eq 2) { $expectedIPv4 } else { $expectedIPv6 }
                            $expectedInterface = ConvertTo-DnsInterfaceDohTargetState `
                                -AddressFamily $family `
                                -NameServers $familyServers `
                                -DohTemplate ([string]$providerConfig.doh.template) `
                                -AllowFallbackToUdp $expectedInterfaceFallback
                            $actualInterface = Get-DnsInterfaceDohState `
                                -InterfaceGuid $adapterGuid -AddressFamily $family
                            if (-not (Test-DnsInterfaceDohStateExact `
                                    -Actual $actualInterface -Expected $expectedInterface)) {
                                Write-Log -Level ERROR -Message "Per-adapter DoH verification failed on $($adapter.Name)/$family" -Module $moduleName
                                $verificationPassed = $false
                            }
                        }
                    }
                }

                $result.VerificationPassed = $verificationPassed
                $result.Success = $verificationPassed
                if ($verificationPassed) { $result.Status = 'Success' }
            }
            else {
                $result.Success = $false
                $result.VerificationPassed = $false
            }

            if ($result.Success) {
                $result.Status = if ($DryRun) { 'DryRun' } else { 'Success' }
                $result.ChecksApplied = if ($DryRun) { 0 } else { $dnsCheckCount }
                Write-Log -Level $(if ($DryRun) { 'INFO' } else { 'SUCCESS' }) -Message $(if ($DryRun) { 'DNS DryRun preview completed successfully' } else { 'DNS Apply and Verify completed successfully' }) -Module $moduleName
            }
            else {
                Write-Log -Level ERROR -Message "DNS Apply and Verify did not meet completion criteria" -Module $moduleName
            }
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
            Write-ErrorLog -Message "DNS configuration failed" -Module $moduleName -ErrorRecord $_
            if (-not $DryRun -and [string]$global:CurrentModule -eq $moduleName) {
                try {
                    if (-not (Save-IncompleteModuleBackup -ModuleName $moduleName -Confirm:$false)) {
                        $result.Errors += 'Failed to retain/classify the incomplete DNS backup'
                    }
                }
                catch {
                    $result.Errors += "Incomplete DNS backup retention failed: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        if ($null -ne $skipResult) {
            return $skipResult
        }
        $result.Duration = (Get-Date) - $startTime

        # Flush DNS cache for immediate effect (only on success)
        if ($result.Success -and -not $DryRun) {
            Write-Log -Level INFO -Message "Flushing DNS resolver cache for immediate effect..." -Module $moduleName
            try {
                Clear-DnsClientCache -ErrorAction Stop
                Write-Log -Level SUCCESS -Message "DNS cache cleared successfully" -Module $moduleName
            }
            catch {
                $cacheWarning = "Could not flush the transient DNS resolver cache: $($_.Exception.Message)"
                $result.Warnings += $cacheWarning
                Write-Log -Level WARNING -Message $cacheWarning -Module $moduleName
                # Non-critical: continue anyway
            }
        }

        Write-Log -Level INFO -Message " " -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "CONFIGURATION SUMMARY" -Module $moduleName
        Write-Log -Level INFO -Message "========================================" -Module $moduleName
        Write-Log -Level INFO -Message "Provider: $($result.Provider)" -Module $moduleName
        Write-Log -Level INFO -Message "Adapters configured: $($result.AdaptersConfigured); previewed: $($result.AdaptersPreviewed)" -Module $moduleName
        Write-Log -Level INFO -Message "DoH configuration verified: $(if ($result.DoHEnabled) { 'Yes' } else { 'No' })" -Module $moduleName
        Write-Log -Level INFO -Message "Backup created: $(if ($result.BackupCreated) { 'Yes' } else { 'No' })" -Module $moduleName
        Write-Log -Level INFO -Message "Duration: $([math]::Round($result.Duration.TotalSeconds, 1)) seconds" -Module $moduleName

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

        if ($result.Status -eq 'Skipped') {
            Write-Log -Level INFO -Message "NotChecked: $dnsCheckCount DNS checks (module skipped)" -Module $moduleName
        }
        elseif ($DryRun -and $result.Success) {
            # DryRun takes no backup, writes no adapter, skips Enable-DoH /
            # Set-DoHPolicy / Set-DnsInterfaceDohState and bypasses the entire
            # verification block, deliberately leaving VerificationPassed = $null
            # and ChecksApplied = 0. $result.Success is still $true, so the
            # success branch below claimed all five declared checks had been
            # verified for a preview that measured nothing at all. A FAILED
            # preview must keep the closing ERROR marker: gating on Success
            # here stops the preview branch from swallowing it.
            Write-Log -Level INFO -Message "NotChecked: $dnsCheckCount DNS checks (DryRun preview; nothing applied or verified)" -Module $moduleName
        }
        elseif ($result.Success) {
            Write-Log -Level SUCCESS -Message "Verified $dnsCheckCount DNS checks" -Module $moduleName
        }
        else {
            Write-Log -Level ERROR -Message "DNS verification incomplete: $dnsCheckCount declared checks were not all proven" -Module $moduleName
        }

        return $result
    }
}
