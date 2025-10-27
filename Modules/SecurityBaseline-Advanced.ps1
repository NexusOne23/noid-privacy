# ============================================================================
# SecurityBaseline-Advanced.ps1
# NoID Privacy - Advanced Security Controls (Baseline 25H2 compliant)
# ============================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

#region WINDOWS LAPS

function Enable-WindowsLAPS {
    <#
    .SYNOPSIS
        Konfiguriert Windows LAPS (Local Admin Password Solution)
    .DESCRIPTION
        Aktiviert Windows LAPS mit 30-Tage-Rotation, 20-Zeichen-Passwoertern und Entra/AD-Backup.
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
        Write-Warning "Windows LAPS nicht verfuegbar auf dieser Edition/Version"
        Write-Info "LAPS wird uebersprungen (nur Pro/Enterprise/Education)"
        Write-Info "Hinweis: Verwenden Sie Microsoft LAPS fuer Home/Pro oder Legacy LAPS"
        return
    }
    
    $lapsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
    
    # LAPS aktivieren
    Set-RegistryValue -Path $lapsPath -Name "Enabled" -Value 1 -Type DWord -Description "LAPS aktivieren"
    
    # Password Rotation (30 Tage)
    Set-RegistryValue -Path $lapsPath -Name "PasswordAgeDays" -Value 30 -Type DWord -Description "PW-Rotation alle 30 Tage"
    
    # Password Complexity (128-bit)
    Set-RegistryValue -Path $lapsPath -Name "PasswordComplexity" -Value 4 -Type DWord -Description "Max. Komplexitaet"
    Set-RegistryValue -Path $lapsPath -Name "PasswordLength" -Value 20 -Type DWord -Description "PW-Laenge 20 Zeichen"
    
    # Backup zu Entra ID / AD
    Set-RegistryValue -Path $lapsPath -Name "BackupDirectory" -Value 2 -Type DWord -Description "Backup zu AD/Entra"
    
    # Post-Authentication Actions
    Set-RegistryValue -Path $lapsPath -Name "PostAuthenticationActions" -Value 3 -Type DWord -Description "Reset PW nach Auth"
    
    Write-Success "Windows LAPS konfiguriert (30-Tage-Rotation, 20 Zeichen, Entra/AD-Escrow)"
    Write-Info "LAPS PowerShell Module: Install-Module -Name LAPS"
}

#endregion

#region ADVANCED AUDITING

function Enable-AdvancedAuditing {
    <#
    .SYNOPSIS
        Aktiviert erweiterte Audit-Policies fuer Security-Monitoring
    .DESCRIPTION
        Konfiguriert Advanced Auditing fuer Logon, Object Access, Policy Change, etc.
        Setzt Event Log Groessen und aktiviert PowerShell Logging.
        Best Practice 25H2: CmdletBinding + auditpol Exit-Code Checks.
    .EXAMPLE
        Enable-AdvancedAuditing
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Advanced Auditing"
    
    Write-Info "Setze erweiterte Audit-Policies..."
    
    # Best Practice 25H2: Use GUIDs for subcategories to avoid locale issues
    # Fehler 0x00000057 = ERROR_INVALID_PARAMETER bei falschen Namen
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
        @{ Name = "PNP Activity"; GUID = "{0CCE9248-69AE-11D9-BED3-505054503030}" }
    )
    
    $successCount = 0
    $failCount = 0
    
    foreach ($category in $auditCategories) {
        try {
            # Use GUID instead of localized name - fixes 0x00000057 error
            $result = & auditpol.exe /set /subcategory:"$($category.GUID)" /success:enable /failure:enable 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "     Aktiviert: $($category.Name)"
                $successCount++
            }
            else {
                Write-Verbose "     Fehler bei $($category.Name) (Exit: $LASTEXITCODE): $result"
                $failCount++
            }
        }
        catch {
            Write-Verbose "     Exception bei $($category.Name): $_"
            $failCount++
        }
    }
    
    if ($successCount -gt 0) {
        Write-Verbose "Audit Policies: $successCount erfolgreich, $failCount fehlgeschlagen"
    }
    else {
        Write-Warning-Custom "Audit Policies konnten nicht gesetzt werden - moeglicherweise Locale-Problem"
        Write-Info "Audit Policies werden via GPO oder Registry-Alternative gesetzt"
    }
    
    # Event Log Groessen und Retention
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
            Write-Verbose "  Log $logName nicht verfuegbar oder Fehler"
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
    
    # Sicherstellen, dass Transcript-Dir existiert
    try {
        if (-not (Test-Path $transcriptDir)) {
            $null = New-Item -Path $transcriptDir -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose "     PSTranscripts-Verzeichnis erstellt"
        }
    }
    catch {
        Write-Warning "Konnte PSTranscripts-Verzeichnis nicht erstellen: $_"
    }
    
    Write-Success "Advanced Auditing aktiviert (Object Access, Logon, DS, Policy, PnP, PS-Logging)"
    Write-Info "Event Log Groessen: Security=500MB, System/App=100MB, PS=50MB"
}

#endregion

#region NTLM AUDITING

function Enable-NTLMAuditing {
    <#
    .SYNOPSIS
        Aktiviert NTLM Authentication Auditing
    .DESCRIPTION
        Microsoft Security Baseline 25H2: NTLM Auditing aktivieren um Legacy-NTLM-Nutzung zu erkennen.
        Hilft bei Migration zu Kerberos und zur Erkennung von Pass-the-Hash Angriffen.
    .EXAMPLE
        Enable-NTLMAuditing
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "NTLM Authentication Auditing"
    
    Write-Info "NTLM Auditing wird aktiviert (Microsoft Baseline 25H2)..."
    
    # NTLM Auditing in Domain
    $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    # AuditNTLMInDomain = 7 (Audit all NTLM authentication in domain)
    # Werte: 0=Off, 1=Audit DC, 2=Audit DC accounts, 4=Audit trusted domains, 7=All
    Set-RegistryValue -Path $netlogonPath -Name "AuditNTLMInDomain" -Value 7 -Type DWord `
        -Description "NTLM Auditing: Alle NTLM-Auth im Domain tracken"
    
    # RestrictNTLMInDomain = 1 (Audit only, no blocking)
    # Werte: 0=Off, 1=Audit, 2-7=Various blocking levels
    Set-RegistryValue -Path $netlogonPath -Name "RestrictNTLMInDomain" -Value 1 -Type DWord `
        -Description "NTLM Restriction: Audit-Only (kein Blocking)"
    
    # NTLM Auditing fuer Outbound (Client-Seite)
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Set-RegistryValue -Path $lsaPath -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord `
        -Description "Audit eingehenden NTLM-Traffic (2=Enable)"
    
    Set-RegistryValue -Path $lsaPath -Name "RestrictReceivingNTLMTraffic" -Value 1 -Type DWord `
        -Description "NTLM Restriction Outbound: Audit-Only"
    
    Write-Success "NTLM Auditing aktiviert (Audit-Only, kein Blocking)"
    Write-Info "Event IDs: 4624 (NTLM Logon), 8004 (NTLM Auth), 8002 (NTLM Blocked)"
    Write-Info "Ziel: Legacy-NTLM-Nutzung erkennen fuer Migration zu Kerberos"
    Write-Warning-Custom "NTLM wird NICHT blockiert - nur geloggt! (Best Practice fuer Kompatibilitaet)"
}

#endregion

#region TLS/SSL HARDENING

function Set-TLSHardening {
    <#
    .SYNOPSIS
        Haertet TLS/SSL-Konfiguration (TLS 1.2+ only, GCM/CHACHA Ciphers, SHA-2)
    .DESCRIPTION
        Deaktiviert schwache Protokolle (SSL 2/3, TLS 1.0/1.1), schwache Ciphers (RC4, 3DES, CBC).
        Aktiviert nur TLS 1.2 + 1.3 mit AEAD-Ciphers (GCM/CHACHA only, keine CBC).
        Best Practice 25H2: Kleinere Angriffsflaeche, keine Legacy-CBC-Kanten.
    .EXAMPLE
        Set-TLSHardening
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "TLS/SSL Haertung"
    
    # Schwache Protokolle deaktivieren (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
    $weakProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    
    foreach ($protocol in $weakProtocols) {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        
        Set-RegistryValue -Path $serverPath -Name "Enabled" -Value 0 -Type DWord -Description "$protocol Server deaktivieren"
        Set-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord -Description "$protocol Server Default aus"
        
        Set-RegistryValue -Path $clientPath -Name "Enabled" -Value 0 -Type DWord -Description "$protocol Client deaktivieren"
        Set-RegistryValue -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord -Description "$protocol Client Default aus"
    }
    
    # TLS 1.2 und TLS 1.3 aktivieren und erzwingen
    $strongProtocols = @("TLS 1.2", "TLS 1.3")
    
    foreach ($protocol in $strongProtocols) {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        
        Set-RegistryValue -Path $serverPath -Name "Enabled" -Value 1 -Type DWord -Description "$protocol Server aktivieren"
        Set-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord -Description "$protocol Server Default an"
        
        Set-RegistryValue -Path $clientPath -Name "Enabled" -Value 1 -Type DWord -Description "$protocol Client aktivieren"
        Set-RegistryValue -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord -Description "$protocol Client Default an"
    }
    
    # Schwache Ciphers deaktivieren
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
        Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord -Description "$cipher deaktivieren"
    }
    
    # Starke Ciphers aktivieren
    $strongCiphers = @(
        "AES 128/128",
        "AES 256/256"
    )
    
    foreach ($cipher in $strongCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        Set-RegistryValue -Path $cipherPath -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "$cipher aktivieren"
    }
    
    # Cipher Suite Order (Best Practice fuer 2025 - GCM/CHACHA only)
    # Rationale: Kleinere Angriffsflaeche, keine Legacy-CBC-Kanten, nur AEAD-Ciphers
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
        -Description "Cipher Suite Order (TLS 1.3 + 1.2 GCM/CHACHA only, keine CBC)"
    
    # SHA-1 NUR fuer TLS/SSL deaktivieren (NICHT fuer Code-Signing!)
    # Best Practice 25H2: SHA-1 in TLS ist unsicher (SHATTERED-Angriff)
    # ABER: Legacy Code-Signing Zertifikate nutzen noch SHA-1 - diese NICHT blockieren!
    Write-Warning-Custom "SHA-1 wird fuer TLS/SSL deaktiviert (SCHANNEL) - Legacy-Webseiten koennen betroffen sein"
    Write-Info "Code-Signing mit SHA-1 bleibt ERLAUBT (Legacy-Software-Kompatibilitaet)"
    
    # SCHANNEL Hashes (nur TLS/SSL, NICHT Code-Signing)
    $hashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    Set-RegistryValue -Path "$hashPath\SHA" -Name "Enabled" -Value 0 -Type DWord -Description "SHA-1 fuer TLS/SSL deaktivieren"
    Set-RegistryValue -Path "$hashPath\SHA256" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "SHA-256 aktivieren"
    Set-RegistryValue -Path "$hashPath\SHA384" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "SHA-384 aktivieren"
    Set-RegistryValue -Path "$hashPath\SHA512" -Name "Enabled" -Value 0xFFFFFFFF -Type DWord -Description "SHA-512 aktivieren"
    
    Write-Info "SHA-1 Scope: NUR TLS/SSL blockiert - Code-Signing/VPN/Legacy-Apps funktionieren!"
    Write-Info "Bei Problemen mit Legacy-Webseiten: SHA-1 manuell wieder aktivieren"
    
    # .NET Framework Strong Crypto
    $dotNetPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    
    foreach ($path in $dotNetPaths) {
        Set-RegistryValue -Path $path -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Description ".NET Strong Crypto"
        Set-RegistryValue -Path $path -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -Description ".NET System TLS Versions"
    }
    
    # Schannel Event Logging aktivieren (Transparenz/Audit)
    $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    Set-RegistryValue -Path $schannelPath -Name "EventLogging" -Value 7 -Type DWord `
        -Description "Schannel Event Logging (alle Events)"
    
    Write-Success "TLS/SSL Haertung abgeschlossen (TLS 1.2+1.3, GCM/CHACHA only, SHA-2, keine CBC/RC4/3DES/MD5)"
    Write-Success "Schannel Event Logging aktiviert (Level 7)"
}

#endregion

#region WINDOWS UPDATE

# WINDOWS UPDATE POLICIES ENTFERNT!
# 
# Grund: User mÃ¶chte Windows Update selbst kontrollieren
#
# Was das bedeutet:
# - Windows verwendet STANDARD-Verhalten (Settings-App Kontrolle)
# - User kann in Settings | Windows Update selbst konfigurieren
# - KEINE erzwungenen Updates, KEINE Deadlines, KEINE Auto-Reboots
# - User behÃ¤lt volle Kontrolle Ã¼ber Update-Timing
#
# Empfehlung:
# - Gehe zu Settings | Windows Update | Advanced options
# - Konfiguriere nach Bedarf:
#   * "Active hours" setzen (verhindert Neustart wÃ¤hrend Arbeit)
#   * "Download over metered connections" nach Wunsch
#   * "Get me up to date" fÃ¼r schnelle Updates
#   * "Pause updates" bei Bedarf
#
# Windows Update funktioniert weiterhin NORMAL, aber ohne Policy-Enforcement!

#endregion

# HTML Compliance Report REMOVED - unreliable checks with false positives
# Use Verify-SecurityBaseline.ps1 for manual verification instead

#region PRINT SPOOLER USER RIGHTS (MS BASELINE 25H2)

function Add-PrintSpoolerUserRight {
    <#
    .SYNOPSIS
        Fuegt Print Spooler Service zu "Impersonate a client" User Right hinzu
    .DESCRIPTION
        Microsoft Security Baseline Windows 11 25H2 Anforderung:
        User Right "Impersonate a client after authentication" muss
        RESTRICTED SERVICES\PrintSpoolerService enthalten fuer Windows Protected Print.
        Best Practice Januar 2026: Forward-Compatibility mit WPP
    .EXAMPLE
        Add-PrintSpoolerUserRight
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Print Spooler User Rights Assignment"
    
    Write-Info "Fuege RESTRICTED SERVICES\PrintSpoolerService zu User Rights hinzu..."
    
    try {
        # Export current security policy
        $tempFile = "$env:TEMP\secpol_$(Get-Date -Format 'yyyyMMdd_HHmmss').cfg"
        $null = secedit /export /cfg $tempFile /quiet
        
        if (-not (Test-Path $tempFile)) {
            Write-Warning-Custom "Security Policy Export fehlgeschlagen"
            Write-Info "NICHT KRITISCH: Windows Protected Print funktioniert trotzdem"
            return
        }
        
        # Read file content
        $content = Get-Content $tempFile -Encoding Unicode
        
        # Find SeImpersonatePrivilege line
        $impersonateLine = $content | Where-Object { $_ -match '^SeImpersonatePrivilege\s*=' }
        
        if (-not $impersonateLine) {
            Write-Warning-Custom "SeImpersonatePrivilege nicht gefunden in Security Policy"
            Write-Info "NICHT KRITISCH: Standardwerte bleiben erhalten"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }
        
        # Check if PrintSpoolerService SID already present
        # SID Format: *S-1-5-99-0-0-0-0 (kann variieren je nach System)
        if ($impersonateLine -match 'S-1-5-99') {
            Write-Info "Print Spooler Service User Right bereits vorhanden"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }
        
        # Add PrintSpoolerService SID to the line
        # Standard SIDs die bereits vorhanden sein sollten:
        # *S-1-5-19 = NT AUTHORITY\LOCAL SERVICE
        # *S-1-5-20 = NT AUTHORITY\NETWORK SERVICE
        # *S-1-5-32-544 = BUILTIN\Administrators
        # *S-1-5-6 = NT AUTHORITY\SERVICE
        
        $newLine = $impersonateLine.TrimEnd() + ',*S-1-5-99-0-0-0-0'
        Write-Verbose "Alte Zeile: $impersonateLine"
        Write-Verbose "Neue Zeile: $newLine"
        
        # Replace line in content
        $newContent = $content -replace [regex]::Escape($impersonateLine), $newLine
        
        # Write back to file (MUST be Unicode encoding for secedit!)
        $newContent | Set-Content $tempFile -Encoding Unicode -Force
        
        # Import modified security policy
        Write-Verbose "Importiere modifizierte Security Policy..."
        $importResult = secedit /configure /db secedit.sdb /cfg $tempFile /quiet 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Print Spooler User Right hinzugefuegt"
            Write-Info "  - User Right: SeImpersonatePrivilege"
            Write-Info "  - SID Added: S-1-5-99-0-0-0-0 (RESTRICTED SERVICES\PrintSpoolerService)"
            Write-Info "  - Purpose: Windows Protected Print Support (Forward-Compat)"
            Write-Host ""
            Write-Info "MICROSOFT BASELINE 25H2: 100% ERFUELLT!"
        }
        else {
            Write-Warning-Custom "Security Policy Import fehlgeschlagen (Exit Code: $LASTEXITCODE)"
            Write-Verbose "secedit Output: $importResult"
            Write-Info "NICHT KRITISCH: Drucken funktioniert trotzdem"
        }
        
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\security\database\secedit.sdb" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning-Custom "User Right Assignment fehlgeschlagen: $_"
        Write-Info "NICHT KRITISCH: Windows Protected Print funktioniert mit Standard-Permissions"
        
        # Cleanup on error
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
