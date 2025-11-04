# ============================================================================
# SecurityBaseline-Advanced.ps1
# NoID Privacy - Advanced Security Controls (Baseline 25H2 compliant)
# ============================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

#region WINDOWS LAPS

function Enable-WindowsLAPS {
    <#
    .SYNOPSIS
        Configure Windows LAPS (Local Admin Password Solution)
    .DESCRIPTION
        Activates Windows LAPS with 30-day rotation, 20-character passwords and Entra/AD backup.
        Best Practice 25H2: Feature availability check before configuration.
    .EXAMPLE
        Enable-WindowsLAPS
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Windows LAPS (Local Admin Password Solution)"
    
    # Check if Windows LAPS is available (not available in Home edition)
    # Best Practice 25H2: Feature detection before configuration
    $lapsAvailable = $false
    
    # Check for LAPS cmdlets
    if (Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue) {
        $lapsAvailable = $true
        Write-Verbose "Windows LAPS cmdlets detected"
    }
    
    # Alternative check: Registry key for LAPS feature
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS") {
        $lapsAvailable = $true
        Write-Verbose "Windows LAPS registry path exists"
    }
    
    if (-not $lapsAvailable) {
        Write-Warning "$(Get-LocalizedString 'AdvancedLAPSNotAvailable')"
        Write-Info "$(Get-LocalizedString 'AdvancedLAPSSkipped')"
        Write-Info "$(Get-LocalizedString 'AdvancedLAPSHint')"
        return
    }
    
    $lapsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
    
    # Enable LAPS
    Set-RegistryValue -Path $lapsPath -Name "Enabled" -Value 1 -Type DWord -Description "Enable LAPS"
    
    # Password Rotation (30 days)
    Set-RegistryValue -Path $lapsPath -Name "PasswordAgeDays" -Value 30 -Type DWord -Description "PW rotation every 30 days"
    
    # Password Complexity (128-bit)
    Set-RegistryValue -Path $lapsPath -Name "PasswordComplexity" -Value 4 -Type DWord -Description "Max complexity"
    Set-RegistryValue -Path $lapsPath -Name "PasswordLength" -Value 20 -Type DWord -Description "PW length 20 characters"
    
    # Backup to Entra ID / AD
    Set-RegistryValue -Path $lapsPath -Name "BackupDirectory" -Value 2 -Type DWord -Description "Backup to AD/Entra"
    
    # Post-Authentication Actions
    Set-RegistryValue -Path $lapsPath -Name "PostAuthenticationActions" -Value 3 -Type DWord -Description "Reset PW after auth"
    
    Write-Success "$(Get-LocalizedString 'AdvancedLAPSConfigured')"
    Write-Info "$(Get-LocalizedString 'AdvancedLAPSModule')"
}

#endregion

#region ADVANCED AUDITING

function Enable-AdvancedAuditing {
    <#
    .SYNOPSIS
        Activates advanced audit policies for security monitoring
    .DESCRIPTION
        Configures Advanced Auditing for Logon, Object Access, Policy Change, etc.
        Sets Event Log sizes and activates PowerShell Logging.
        Best Practice 25H2: CmdletBinding + auditpol Exit-Code Checks.
    .EXAMPLE
        Enable-AdvancedAuditing
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Advanced Auditing"
    
    Write-Info "$(Get-LocalizedString 'AdvancedAuditSetting')"
    
    # ===========================
    # FORCE ADVANCED AUDIT POLICY (Microsoft Baseline 25H2)
    # ===========================
    # Audit: Force audit policy subcategory settings to override legacy audit policy
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegistryValue -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord `
        -Description "Force advanced audit subcategory settings (override legacy)"
    
    # Best Practice 25H2: Use GUIDs for subcategories to avoid locale issues
    # Error 0x00000057 = ERROR_INVALID_PARAMETER with wrong names
    $auditCategories = @(
        @{ Name = "Logon"; GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Logoff"; GUID = "{0CCE9216-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Account Lockout"; GUID = "{0CCE9217-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Special Logon"; GUID = "{0CCE921B-69AE-11D9-BED3-505054503030}" },
        @{ Name = "File Share"; GUID = "{0CCE9224-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Detailed File Share"; GUID = "{0CCE9244-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Removable Storage"; GUID = "{0CCE9245-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Audit Policy Change"; GUID = "{0CCE922F-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Authentication Policy Change"; GUID = "{0CCE9230-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Sensitive Privilege Use"; GUID = "{0CCE9228-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Security State Change"; GUID = "{0CCE9218-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Security System Extension"; GUID = "{0CCE9219-69AE-11D9-BED3-505054503030}" },
        @{ Name = "System Integrity"; GUID = "{0CCE921A-69AE-11D9-BED3-505054503030}" },
        @{ Name = "User Account Management"; GUID = "{0CCE9235-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Security Group Management"; GUID = "{0CCE9237-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Directory Service Access"; GUID = "{0CCE923B-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Directory Service Changes"; GUID = "{0CCE923C-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Process Creation"; GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}" },
        @{ Name = "PNP Activity"; GUID = "{0CCE9248-69AE-11D9-BED3-505054503030}" },
        # ADDITIONAL AUDIT POLICIES (Microsoft Baseline 25H2)
        @{ Name = "Credential Validation"; GUID = "{0CCE923F-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Group Membership"; GUID = "{0CCE9249-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Other Object Access Events"; GUID = "{0CCE9227-69AE-11D9-BED3-505054503030}" },
        @{ Name = "MPSSVC Rule-Level Policy Change"; GUID = "{0CCE9232-69AE-11D9-BED3-505054503030}" },
        # LOW PRIORITY AUDIT POLICIES (catch-all categories)
        @{ Name = "Other Policy Change Events"; GUID = "{0CCE9234-69AE-11D9-BED3-505054503030}" },
        @{ Name = "Other System Events"; GUID = "{0CCE9214-69AE-11D9-BED3-505054503030}" }
    )
    
    $successCount = 0
    $failCount = 0
    
    foreach ($category in $auditCategories) {
        try {
            # Use GUID instead of localized name - fixes 0x00000057 error
            $result = & auditpol.exe /set /subcategory:"$($category.GUID)" /success:enable /failure:enable 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "     Activated: $($category.Name)"
                $successCount++
            }
            else {
                Write-Verbose "     Error with $($category.Name) (Exit: $LASTEXITCODE): $result"
                $failCount++
            }
        }
        catch {
            Write-Verbose "     Exception with $($category.Name): $_"
            $failCount++
        }
    }
    
    if ($successCount -gt 0) {
        Write-Verbose "Audit Policies: $successCount successful, $failCount failed"
    }
    else {
        Write-Warning-Custom "$(Get-LocalizedString 'AdvancedAuditPoliciesFailed')"
        Write-Info "$(Get-LocalizedString 'AdvancedAuditPoliciesGPO')"
    }
    
    # Event Log sizes and retention
    $logSizes = @{
        "Security"    = 524288000   # 500 MB (statt 2 GB)
        "System"      = 104857600   # 100 MB (statt 512 MB)
        "Application" = 104857600   # 100 MB (statt 512 MB)
        "Microsoft-Windows-PowerShell/Operational" = 52428800  # 50 MB (statt 256 MB)
    }
    
    foreach ($logName in $logSizes.Keys) {
        try {
            $logObj = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($logObj) {
                $logObj.MaximumSizeInBytes = $logSizes[$logName]
                $logObj.IsEnabled = $true
                $logObj.SaveChanges()
                
                Write-Verbose "     Event Log $($logName): MaxSize=$($logSizes[$logName]/1MB) MB"
            }
        }
        catch {
            Write-Verbose "  Log $logName not available or error"
        }
    }
    
    # PowerShell Script Block Logging
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    Set-RegistryValue -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord `
        -Description "PowerShell Script Block Logging"
    
    # PowerShell Transcription
    $psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    Set-RegistryValue -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord `
        -Description "PowerShell Transcription"
    Set-RegistryValue -Path $psTransPath -Name "EnableInvocationHeader" -Value 1 -Type DWord `
        -Description "Invocation Header"
    $transcriptDir = Join-Path $env:ProgramData "PSTranscripts"
    Set-RegistryValue -Path $psTransPath -Name "OutputDirectory" -Value $transcriptDir -Type String `
        -Description "Transcript Output Dir"
    
    # Ensure that Transcript-Dir exists
    try {
        if (-not (Test-Path $transcriptDir)) {
            $null = New-Item -Path $transcriptDir -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose "     PSTranscripts directory created"
        }
    }
    catch {
        Write-Warning (Get-LocalizedString 'AdvancedAuditTranscriptError' $_)
    }
    
    Write-Success "$(Get-LocalizedString 'AdvancedAuditActivated')"
    Write-Info "$(Get-LocalizedString 'AdvancedAuditLogSizes')"
}

#endregion

#region NTLM AUDITING

function Enable-NTLMAuditing {
    <#
    .SYNOPSIS
        Activates NTLM Authentication Auditing
    .DESCRIPTION
        Microsoft Security Baseline 25H2: Enable NTLM Auditing to detect legacy NTLM usage.
        Helps with migration to Kerberos and detection of Pass-the-Hash attacks.
    .EXAMPLE
        Enable-NTLMAuditing
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "NTLM Authentication Auditing"
    
    Write-Info "$(Get-LocalizedString 'AdvancedNTLMActivating')"
    
    # NTLM Auditing in Domain
    $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    # AuditNTLMInDomain = 7 (Audit all NTLM authentication in domain)
    # Values: 0=Off, 1=Audit DC, 2=Audit DC accounts, 4=Audit trusted domains, 7=All
    Set-RegistryValue -Path $netlogonPath -Name "AuditNTLMInDomain" -Value 7 -Type DWord `
        -Description "NTLM Auditing: Track all NTLM auth in domain"
    
    # RestrictNTLMInDomain = 1 (Audit only, no blocking)
    # Werte: 0=Off, 1=Audit, 2-7=Various blocking levels
    Set-RegistryValue -Path $netlogonPath -Name "RestrictNTLMInDomain" -Value 1 -Type DWord `
        -Description "NTLM Restriction: Audit-Only (no blocking)"
    
    # NTLM Auditing for Outbound (Client-Side)
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Set-RegistryValue -Path $lsaPath -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord `
        -Description "Audit incoming NTLM traffic (2=Enable)"
    
    Set-RegistryValue -Path $lsaPath -Name "RestrictReceivingNTLMTraffic" -Value 1 -Type DWord `
        -Description "NTLM Restriction Outbound: Audit-Only"
    
    Write-Success "$(Get-LocalizedString 'AdvancedNTLMActivated')"
    Write-Info "$(Get-LocalizedString 'AdvancedNTLMEventIDs')"
    Write-Info "$(Get-LocalizedString 'AdvancedNTLMGoal')"
    Write-Warning-Custom "$(Get-LocalizedString 'AdvancedNTLMNotBlocked')"
}

#endregion

#region TLS/SSL HARDENING

function Set-TLSHardening {
    <#
    .SYNOPSIS
        Hardens TLS/SSL configuration (TLS 1.2+ only, GCM/CHACHA Ciphers, SHA-2)
    .DESCRIPTION
        Disables weak protocols (SSL 2/3, TLS 1.0/1.1), weak ciphers (RC4, 3DES, CBC).
        Enables only TLS 1.2 + 1.3 with AEAD ciphers (GCM/CHACHA only, no CBC).
        Best Practice 25H2: Smaller attack surface, no legacy CBC edges.
    .EXAMPLE
        Set-TLSHardening
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "TLS/SSL Hardening"
    
    # Disable weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
    $weakProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    
    foreach ($protocol in $weakProtocols) {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        
        Set-RegistryValue -Path $serverPath -Name "Enabled" -Value 0 -Type DWord -Description "Disable $protocol Server"
        Set-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord -Description "$protocol Server default off"
        
        Set-RegistryValue -Path $clientPath -Name "Enabled" -Value 0 -Type DWord -Description "Disable $protocol Client"
        Set-RegistryValue -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord -Description "$protocol Client default off"
    }
    
    # Enable and enforce TLS 1.2 and TLS 1.3
    $strongProtocols = @("TLS 1.2", "TLS 1.3")
    
    foreach ($protocol in $strongProtocols) {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        
        Set-RegistryValue -Path $serverPath -Name "Enabled" -Value 1 -Type DWord -Description "Enable $protocol Server"
        Set-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord -Description "$protocol Server default on"
        
        Set-RegistryValue -Path $clientPath -Name "Enabled" -Value 1 -Type DWord -Description "Enable $protocol Client"
        Set-RegistryValue -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord -Description "$protocol Client default on"
    }
    
    # Disable weak ciphers
    $weakCiphers = @(
        "DES 56/56",
        "NULL",
        "RC2 128/128",
        "RC2 40/128",
        "RC2 56/128",
        "RC4 128/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "Triple DES 168"
    )
    
    foreach ($cipher in $weakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord -Description "Disable $cipher"
    }
    
    # Enable strong ciphers
    $strongCiphers = @(
        "AES 128/128",
        "AES 256/256"
    )
    
    foreach ($cipher in $strongCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "Enable $cipher"
    }
    
    # Cipher Suite Order (Best Practice for 2025 - GCM/CHACHA only)
    # Rationale: Smaller attack surface, no legacy CBC edges, AEAD ciphers only
    $cipherSuiteOrder = @(
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ) -join ","
    
    $cipherSuitePath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    Set-RegistryValue -Path $cipherSuitePath -Name "Functions" -Value $cipherSuiteOrder -Type String `
        -Description "Cipher Suite Order (TLS 1.3 + 1.2 GCM/CHACHA only, no CBC)"
    
    # SHA-1 ONLY for TLS/SSL disabled (NOT for code signing!)
    # Best Practice 25H2: SHA-1 in TLS is insecure (SHATTERED attack)
    # BUT: Legacy code signing certificates still use SHA-1 - do NOT block these!
    Write-Warning-Custom "$(Get-LocalizedString 'AdvancedTLSSHA1Warning')"
    Write-Info "$(Get-LocalizedString 'AdvancedTLSCodeSigningOK')"
    
    # SCHANNEL Hashes (TLS/SSL only, NOT code signing)
    $hashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    Set-RegistryValue -Path "$hashPath\SHA" -Name "Enabled" -Value 0 -Type DWord -Description "Disable SHA-1 for TLS/SSL"
    Set-RegistryValue -Path "$hashPath\SHA256" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "Enable SHA-256"
    Set-RegistryValue -Path "$hashPath\SHA384" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "Enable SHA-384"
    Set-RegistryValue -Path "$hashPath\SHA512" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "Enable SHA-512"
    
    Write-Info "$(Get-LocalizedString 'AdvancedTLSSHA1Scope')"
    Write-Info "$(Get-LocalizedString 'AdvancedTLSLegacyWebsites')"
    
    # .NET Framework Strong Crypto
    $dotNetPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    
    foreach ($path in $dotNetPaths) {
        Set-RegistryValue -Path $path -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Description ".NET Strong Crypto"
        Set-RegistryValue -Path $path -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -Description ".NET System TLS Versions"
    }
    
    # Enable Schannel Event Logging (Transparency/Audit)
    $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    Set-RegistryValue -Path $schannelPath -Name "EventLogging" -Value 7 -Type DWord `
        -Description "Schannel Event Logging (all events)"
    
    Write-Success "$(Get-LocalizedString 'AdvancedTLSCompleted')"
    Write-Success "$(Get-LocalizedString 'AdvancedTLSEventLogging')"
}

#endregion

#region WINDOWS UPDATE

# WINDOWS UPDATE POLICIES REMOVED!
# 
# Grund: User moechte Windows Update selbst kontrollieren
#
# What this means:
# - Windows uses STANDARD behavior (Settings App control)
# - User can configure themselves in Settings | Windows Update
# - NO forced updates, NO deadlines, NO auto-reboots
# - User retains full control over update timing
#
# Empfehlung:
# - Go to Settings | Windows Update | Advanced options
# - Configure as needed:
#   * Set "Active hours" (prevents restart during work)
#   * "Download over metered connections" as desired
#   * "Get me up to date" for quick updates
#   * "Pause updates" if needed
#
# Windows Update continues to work NORMALLY, but without policy enforcement!

#endregion

# HTML Compliance Report REMOVED - unreliable checks with false positives
# Use Verify-SecurityBaseline.ps1 for manual verification instead

#region WDIGEST AUTHENTICATION (CREDENTIAL PROTECTION)

function Disable-WDigest {
    <#
    .SYNOPSIS
        Disables WDigest Authentication to prevent plaintext password storage in memory
    .DESCRIPTION
        WDigest is a legacy authentication protocol that stores passwords in PLAINTEXT in RAM.
        This makes it trivial for attackers to extract passwords using Mimikatz.
        
        CRITICAL: Disable WDigest to prevent credential theft!
        
        Registry: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
        Value: UseLogonCredential = 0 (disabled)
    .NOTES
        Default in Windows 10/11: Disabled (but can be re-enabled by malware)
        This function ensures it stays disabled even if tampered with
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "WDigest Authentication (Credential Protection)"
    
    Write-Info "$(Get-LocalizedString 'AdvancedWDigestDisabling')"
    
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    
    # Disable WDigest (UseLogonCredential = 0)
    # Value 0 = Passwords NOT stored in plaintext in RAM
    # Value 1 = Passwords stored in plaintext (DANGEROUS!)
    Set-RegistryValue -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWord `
        -Description "WDigest disabled (no plaintext passwords in RAM)"
    
    Write-Success "$(Get-LocalizedString 'AdvancedWDigestDisabled')"
    Write-Info "$(Get-LocalizedString 'AdvancedWDigestProtected')"
    Write-Warning "$(Get-LocalizedString 'AdvancedWDigestNote')"
}

#endregion

#region EFSRPC BLOCKING (AUTH COERCION PROTECTION)

function Disable-EFSRPC {
    <#
    .SYNOPSIS
        Disables EFS RPC to prevent auth coercion attacks
    .DESCRIPTION
        Blocks the Encrypting File System RPC interface which can be abused
        for NTLM relay and auth coercion attacks (similar to PrinterBug, DFSCoerce).
        
        CRITICAL: Blocks EfsRpcOpenFileRaw and related RPC calls
        
        CVE-2025-59287, CVE-2025-33073 - NTLM Relay Protection
    .NOTES
        EFS (Encrypting File System) is legacy. Modern systems use BitLocker.
        This does NOT affect BitLocker.
    .EXAMPLE
        Disable-EFSRPC
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "EFS RPC Blocking (Auth Coercion Protection)"
    
    Write-Info "$(Get-LocalizedString 'AdvancedEFSDisabling')"
    
    # Block EFS RPC Interface
    $efsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EFS"
    Set-RegistryValue -Path $efsPath -Name "Start" -Value 4 -Type DWord `
        -Description "EFS Service disabled (NTLM relay protection)"
    
    # Additional: Disable EFS Driver
    $efsDriverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\EFS"
    Set-RegistryValue -Path $efsDriverPath -Name "Disabled" -Value 1 -Type DWord `
        -Description "EFS Driver disabled"
    
    Write-Success "$(Get-LocalizedString 'AdvancedEFSDisabled')"
    Write-Info "$(Get-LocalizedString 'AdvancedEFSBitLockerOK')"
    Write-Warning "$(Get-LocalizedString 'AdvancedEFSNote')"
}

#endregion

#region WEBCLIENT/WEBDAV BLOCKING (AUTH COERCION PROTECTION)

function Disable-WebClient {
    <#
    .SYNOPSIS
        Disables WebClient/WebDAV service to prevent auth coercion attacks
    .DESCRIPTION
        Disables the WebClient service which provides WebDAV functionality.
        WebDAV can be abused for NTLM relay and auth coercion attacks.
        
        CRITICAL: Blocks WebDAV-based auth coercion (similar to PrinterBug, DFSCoerce, EfsRpc)
        
        Auth Coercion Protection
    .NOTES
        WebDAV (Web Distributed Authoring and Versioning) is rarely used by home users.
        Most users access cloud storage via native apps or web browsers.
        This does NOT affect OneDrive, Dropbox, or other modern cloud services.
    .EXAMPLE
        Disable-WebClient
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "WebClient/WebDAV Service Blocking (Auth Coercion Protection)"
    
    Write-Info "$(Get-LocalizedString 'AdvancedWebClientDisabling')"
    
    try {
        # Stop WebClient service
        $service = Get-Service -Name WebClient -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($service.Status -eq 'Running') {
                Stop-Service -Name WebClient -Force -ErrorAction Stop
                Write-Verbose "$(Get-LocalizedString 'AdvancedWebClientStopped')"
            }
            
            # Disable service
            Set-Service -Name WebClient -StartupType Disabled -ErrorAction Stop
            Write-Success "$(Get-LocalizedString 'AdvancedWebClientDisabled')"
        } else {
            Write-Info "$(Get-LocalizedString 'AdvancedWebClientNotFound')"
        }
    }
    catch {
        Write-Warning (Get-LocalizedString 'AdvancedWebClientError' $_)
    }
    
    Write-Info "$(Get-LocalizedString 'AdvancedWebClientRedirector')"
    Write-Info "$(Get-LocalizedString 'AdvancedWebClientCloudOK')"
    Write-Warning "$(Get-LocalizedString 'AdvancedWebClientNote')"
}

#endregion

#region PRINT SPOOLER USER RIGHTS (MS BASELINE 25H2)

function Add-PrintSpoolerUserRight {
    <#
    .SYNOPSIS
        Adds Print Spooler Service to "Impersonate a client" User Right
    .DESCRIPTION
        Microsoft Security Baseline Windows 11 25H2 requirement:
        User Right "Impersonate a client after authentication" must
        contain RESTRICTED SERVICES\PrintSpoolerService for Windows Protected Print.
        Best Practice January 2026: Forward-Compatibility with WPP
    .EXAMPLE
        Add-PrintSpoolerUserRight
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Print Spooler User Rights Assignment"
    
    Write-Info "$(Get-LocalizedString 'AdvancedPrintAdding')"
    
    try {
        # Export current security policy
        $tempFile = "$env:TEMP\secpol_$(Get-Date -Format 'yyyyMMdd_HHmmss').cfg"
        $null = secedit /export /cfg $tempFile /quiet
        
        if (-not (Test-Path $tempFile)) {
            Write-Warning-Custom "$(Get-LocalizedString 'AdvancedPrintExportFailed')"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintNotCritical')"
            return
        }
        
        # Read file content
        $content = Get-Content $tempFile -Encoding Unicode
        
        # Find SeImpersonatePrivilege line
        $impersonateLine = $content | Where-Object { $_ -match '^SeImpersonatePrivilege\s*=' }
        
        if (-not $impersonateLine) {
            Write-Warning-Custom "$(Get-LocalizedString 'AdvancedPrintNotFound')"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintDefaultsKept')"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }
        
        # Check if PrintSpoolerService SID already present
        # SID Format: *S-1-5-99-0-0-0-0 (can vary by system)
        if ($impersonateLine -match 'S-1-5-99') {
            Write-Info "$(Get-LocalizedString 'AdvancedPrintAlreadyPresent')"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }
        
        # Add PrintSpoolerService SID to the line
        # Standard SIDs that should already be present:
        # *S-1-5-19 = NT AUTHORITY\LOCAL SERVICE
        # *S-1-5-20 = NT AUTHORITY\NETWORK SERVICE
        # *S-1-5-32-544 = BUILTIN\Administrators
        # *S-1-5-6 = NT AUTHORITY\SERVICE
        
        $newLine = $impersonateLine.TrimEnd() + ',*S-1-5-99-0-0-0-0'
        Write-Verbose "Old line: $impersonateLine"
        Write-Verbose "New line: $newLine"
        
        # Replace line in content
        $newContent = $content -replace [regex]::Escape($impersonateLine), $newLine
        
        # Write back to file (MUST be Unicode encoding for secedit!)
        $newContent | Set-Content $tempFile -Encoding Unicode -Force
        
        # Import modified security policy
        Write-Verbose "Importing modified Security Policy..."
        $importResult = secedit /configure /db secedit.sdb /cfg $tempFile /quiet 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$(Get-LocalizedString 'AdvancedPrintAdded')"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintUserRight')"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintSIDAdded')"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintPurpose')"
            Write-Host ""
            Write-Info "$(Get-LocalizedString 'AdvancedPrintBaseline')"
        }
        else {
            Write-Warning-Custom (Get-LocalizedString 'AdvancedPrintImportFailed' $LASTEXITCODE)
            Write-Verbose "secedit Output: $importResult"
            Write-Info "$(Get-LocalizedString 'AdvancedPrintPrintingWorks')"
        }
        
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\security\database\secedit.sdb" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning-Custom (Get-LocalizedString 'AdvancedPrintAssignmentFailed' $_)
        Write-Info "$(Get-LocalizedString 'AdvancedPrintStandardPerms')"
        
        # Cleanup on error
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region AUTHENTICATION HARDENING

function Enable-WindowsHelloPINComplexity {
    <#
    .SYNOPSIS
        Configures Windows Hello PIN Complexity Requirements
    
    .DESCRIPTION
        Enforces strong PIN requirements for Windows Hello sign-in.
        Works on ALL systems (no special hardware needed).
        
        Requirements:
        - TPM 2.0 (standard since 2019)
        - No biometric hardware needed
        
        Best Practice 25H2: Strong Authentication
        
    .EXAMPLE
        Enable-WindowsHelloPINComplexity
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'AdvancedPINTitle')
    
    # Check TPM 2.0
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (-not $tpm -or $tpm.TpmPresent -eq $false) {
            Write-Warning (Get-LocalizedString 'AdvancedPINNoTPM')
            Write-Info (Get-LocalizedString 'AdvancedPINSkipped')
            return
        }
        
        if ($tpm.TpmReady -eq $false) {
            Write-Warning (Get-LocalizedString 'AdvancedPINTPMNotReady')
            Write-Info (Get-LocalizedString 'AdvancedPINSkipped')
            return
        }
    }
    catch {
        Write-Warning (Get-LocalizedString 'AdvancedPINCheckFailed' $_)
        Write-Info (Get-LocalizedString 'AdvancedPINSkipped')
        return
    }
    
    Write-Info (Get-LocalizedString 'AdvancedPINConfiguring')
    
    $pinPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
    
    try {
        # Minimum PIN Length: 6 digits
        [void](Set-RegistryValue -Path $pinPath -Name "MinimumPINLength" -Value 6 -Type DWord `
            -Description "Windows Hello: Minimum PIN length (6 digits)")
        
        # Maximum PIN Length: 127
        [void](Set-RegistryValue -Path $pinPath -Name "MaximumPINLength" -Value 127 -Type DWord `
            -Description "Windows Hello: Maximum PIN length")
        
        # Require Digits
        [void](Set-RegistryValue -Path $pinPath -Name "Digits" -Value 1 -Type DWord `
            -Description "Windows Hello: Require digits in PIN")
        
        # PIN Expiration: Never
        [void](Set-RegistryValue -Path $pinPath -Name "Expiration" -Value 0 -Type DWord `
            -Description "Windows Hello: PIN never expires")
        
        # PIN History: Remember last 5
        [void](Set-RegistryValue -Path $pinPath -Name "History" -Value 5 -Type DWord `
            -Description "Windows Hello: Remember last 5 PINs")
        
        Write-Success (Get-LocalizedString 'AdvancedPINConfigured')
        Write-Info (Get-LocalizedString 'AdvancedPINVBSProtected')
        Write-Info (Get-LocalizedString 'AdvancedPINAppliesNew')
        Write-Warning-Custom (Get-LocalizedString 'AdvancedPINWeakWarning')
        Write-Info (Get-LocalizedString 'AdvancedPINBestPractices')
        
    }
    catch {
        Write-Warning (Get-LocalizedString 'AdvancedPINFailed' $_)
        Write-Verbose "Error details: $_"
    }
}

#endregion

#region POWER MANAGEMENT & SCREEN LOCK

function Set-SecurePowerManagement {
    <#
    .SYNOPSIS
        Configures secure power management settings for maximum security
        
    .DESCRIPTION
        Sets power scheme to balanced security and usability:
        - Display off: 10 minutes (AC + Battery)
        - Auto-lock: 15 minutes (via InactivityTimeoutSecs + Password enforcement)
        - Sleep: Never (we use Hibernate instead)
        - Hibernate: 30 minutes (AC + Battery)
        
        IMPORTANT: Uses ONLY InactivityTimeoutSecs (Microsoft Baseline 25H2 compliant)
        No screensaver timeout to avoid double-lock confusion.
        
    .EXAMPLE
        Set-SecurePowerManagement
    #>
    
    [CmdletBinding()]
    param()
    
    Write-Section "Power Management & Physical Access Protection"
    
    # Get current power scheme GUID
    $currentScheme = powercfg /getactivescheme
    if ($currentScheme -match '([0-9a-f-]{36})') {
        $schemeGUID = $matches[1]
    } else {
        Write-Warning "Could not detect active power scheme, using default balanced scheme"
        $schemeGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"  # Balanced
    }
    
    Write-Verbose "Configuring Power Settings (Physical Access Protection)..."
    
    # ==========================================
    # DISPLAY SETTINGS
    # ==========================================
    
    # Display timeout: 10 minutes
    Write-Verbose "Setting display timeout: 10 minutes"
    powercfg /change monitor-timeout-ac 10 2>&1 | Out-Null
    powercfg /change monitor-timeout-dc 10 2>&1 | Out-Null
    
    # ==========================================
    # SLEEP/HIBERNATE SETTINGS
    # ==========================================
    
    # Sleep: Never (using Hibernate for better security)
    Write-Verbose "Disabling Sleep (using Hibernate instead for RAM protection)"
    powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
    powercfg /change standby-timeout-dc 0 2>&1 | Out-Null
    
    # Enable Hibernate
    Write-Verbose "Enabling Hibernate..."
    powercfg /hibernate on 2>&1 | Out-Null
    
    # Hibernate: 30 minutes
    Write-Verbose "Setting hibernate timeout: 30 minutes"
    powercfg /change hibernate-timeout-ac 30 2>&1 | Out-Null
    powercfg /change hibernate-timeout-dc 30 2>&1 | Out-Null
    
    # ==========================================
    # LOCK SCREEN PASSWORD ENFORCEMENT
    # ==========================================
    
    # IMPORTANT: InactivityTimeoutSecs (15 min) is already set in RegistryChanges-Definition.ps1
    # Path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    # Name: InactivityTimeoutSecs = 900 (15 minutes)
    
    # CRITICAL: Enforce password requirement on lock screen (Machine Policy)
    # Without this, the lock screen appears but NO PASSWORD is required!
    Write-Verbose "Enforcing password requirement on lock screen..."
    
    $lockScreenPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    [void](Set-RegistryValue -Path $lockScreenPolicyPath -Name "ScreenSaverIsSecure" -Value "1" -Type String `
        -Description "MACHINE POLICY: Require password on lock screen (CRITICAL!)")
    
    # Require password on wake from sleep/hibernate (via powercfg)
    Write-Verbose "Requiring password on wake from sleep/hibernate..."
    powercfg /SETACVALUEINDEX $schemeGUID SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    powercfg /SETDCVALUEINDEX $schemeGUID SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    
    # Apply changes
    powercfg /SETACTIVE $schemeGUID 2>&1 | Out-Null
    
    Write-Success "Power Management configured successfully!"
    Write-Info "  - Display Off: 10 minutes"
    Write-Info "  - Auto-Lock: 15 minutes (InactivityTimeoutSecs + Password enforced)"
    Write-Info "  - Hibernate: 30 minutes (RAM cleared, protects against Cold Boot Attacks)"
    Write-Info "  - Sleep: Disabled (using Hibernate for better security)"
    Write-Host ""
    Write-Info "TIMELINE:"
    Write-Info "  10 Min → Display turns off"
    Write-Info "  15 Min → Lock screen + Password required (Machine Policy)"
    Write-Info "  30 Min → Hibernate (RAM cleared)"
    Write-Warning-Custom "System will hibernate after 30 minutes of inactivity (security feature)"
    Write-Host ""
    Write-Info "SECURITY BENEFIT:"
    Write-Info "  - Physical Access Attack Window: Minimized"
    Write-Info "  - Evil Maid Attack: Harder (RAM cleared on hibernate)"
    Write-Info "  - DMA Attacks: Mitigated (RAM cleared, not just sleeping)"
    Write-Info "  - Microsoft Baseline 25H2: Compliant"
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
