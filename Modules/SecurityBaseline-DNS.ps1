# =======================================================================================
# SecurityBaseline-DNS.ps1 - DNS Security & Cloudflare DoH
# =======================================================================================

# Best Practice 25H2: Strict Mode aktivieren
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
    
    Write-Info "DNSSEC wird aktiviert (DNS-Spoofing-Schutz)..."
    
    # Enable DNSSEC validation
    $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    
    # Enable DNSSEC validation
    Set-RegistryValue -Path $dnsPath -Name "EnableDnssec" -Value 1 -Type DWord `
        -Description "DNSSEC Validation aktivieren"
    
    # DNSSEC Mode: Opportunistic (Mode 1 - Best Practice 25H2)
    # Mode 1 = Opportunistic (validate if available, don't fail if not)
    # Mode 2 = Require validation (can break DNS if misconfigured)
    # Best Practice: Mode 1 fuer Client-Systeme, Mode 2 nur fuer Server
    
    Set-RegistryValue -Path $dnsPath -Name "DnssecMode" -Value 1 -Type DWord `
        -Description "DNSSEC Mode: 1 = Opportunistic (validate if available)"
    
    Write-Info "DNSSEC Mode: Opportunistic (sicher + kompatibel)"
    
    # Enable DNSSEC for IPv6
    Set-RegistryValue -Path $dnsPath -Name "EnableDnssecIPv6" -Value 1 -Type DWord `
        -Description "DNSSEC fuer IPv6"
    
    Write-Success "DNSSEC Validation aktiviert"
    Write-Info "DNS-Antworten werden auf Authentizitaet geprueft (Anti-Spoofing)"
}

function Install-DNSBlocklist {
    <#
    .SYNOPSIS
        Install DNS-based blocklist via Windows HOSTS file
    .DESCRIPTION
        Installiert Steven Black's unified hosts file (80K+ domains) aus dem lokalen Projektverzeichnis.
        Die hosts-Datei wird mit dem Script ausgeliefert - keine Internet-Verbindung nötig!
        Blocks malware, tracking, advertising domains at DNS level.
        
        LOGIK (EINFACH!):
        1. Prüfe ob bereits installiert (Idempotenz)
        2. Backup Original hosts-Datei
        3. Kopiere lokale hosts-Datei (80K+ Domains) nach System32
        4. Flush DNS Cache
        5. FERTIG!
        
        Source: https://github.com/StevenBlack/hosts
        Last Update: 17 October 2025 (80,101 Domains)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "DNS Blocklist (Malware/Tracking/Ads)"
    
    Write-Info "DNS Blocklist wird installiert (80K+ Domains)..."
    Write-Info "OPTIMIERUNG: 9 Domains pro Zeile (DNS-Cache-optimiert)"
    Write-Info "Steven Black's unified hosts - komprimiert fuer Performance"
    
    # WICHTIG: Bitdefender/Antivirus Warnung
    Write-Warning "ANTIVIRUS-KOMPATIBILITAET: hosts-Datei mit 80K+ Eintraegen"
    Write-Warning "Bitdefender-User: Protection | Vulnerability | Settings | 'Scan hosts file' DEAKTIVIEREN!"
    Write-Warning "Sonst kann Internet-Zugriff blockiert werden!"
    
    # Check if Steven Black's Hosts is already installed (idempotency)
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $currentHosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $alreadyInstalled = $currentHosts | Select-String "# Title: StevenBlack/hosts"
    
    if ($alreadyInstalled) {
        Write-Info "Steven Black's Hosts ist bereits installiert"
        Write-Verbose "Ueberspringe Download (idempotent)"
        return
    }
    
    # Backup current hosts file
    $hostsBackup = "$hostsPath.backup-original"
    
    if (-not (Test-Path $hostsBackup)) {
        try {
            Copy-Item -Path $hostsPath -Destination $hostsBackup -Force
            Write-Verbose "Original Hosts-File gesichert: $hostsBackup"
        }
        catch {
            Write-Warning "Hosts-File Backup fehlgeschlagen: $_"
        }
    }
    else {
        Write-Verbose "Original Backup existiert bereits: $hostsBackup"
    }
    
    # Best Practice 25H2: Verwende LOKALE hosts-Datei aus Projektverzeichnis!
    # Keine Internet-Verbindung nötig - alles ist lokal!
    
    # Finde Script-Verzeichnis (ROBUST!)
    $scriptDir = $null
    
    # Methode 1: $PSCommandPath (wenn Modul direkt aufgerufen)
    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
        Write-Verbose "Script-Dir via PSCommandPath: $scriptDir"
    }
    
    # Methode 2: $PSScriptRoot (wenn Script läuft)
    if (-not $scriptDir -and $PSScriptRoot) {
        $scriptDir = $PSScriptRoot
        Write-Verbose "Script-Dir via PSScriptRoot: $scriptDir"
    }
    
    # Methode 3: MyInvocation (Fallback)
    if (-not $scriptDir) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        Write-Verbose "Script-Dir via MyInvocation: $scriptDir"
    }
    
    # Methode 4: Arbeitsverzeichnis (letzter Fallback)
    if (-not $scriptDir) {
        $scriptDir = Get-Location
        Write-Verbose "Script-Dir via Get-Location (Fallback): $scriptDir"
    }
    
    # Gehe ein Verzeichnis hoch (aus Modules\ raus ins Projekt-Root)
    $projectRoot = Split-Path -Parent $scriptDir
    $localHostsFile = Join-Path $projectRoot "hosts"
    
    Write-Verbose "Projekt-Root: $projectRoot"
    
    Write-Info "Verwende lokale hosts-Datei aus Projektverzeichnis..."
    Write-Verbose "Pfad: $localHostsFile"
    
    # Check ob lokale Datei existiert
    if (-not (Test-Path $localHostsFile)) {
        Write-Error "KRITISCHER FEHLER: Lokale hosts-Datei nicht gefunden!"
        Write-Error "Erwartet: $localHostsFile"
        Write-Error "DNS-Blocklist kann NICHT installiert werden!"
        return
    }
    
    try {
        # Validiere lokale Datei
        $localContent = Get-Content $localHostsFile -TotalCount 10 -ErrorAction Stop
        $hasValidHeader = $localContent | Where-Object { $_ -match "# Title: StevenBlack/hosts" }
        
        if (-not $hasValidHeader) {
            Write-Error "Lokale hosts-Datei hat ungueltigen Header!"
            Write-Error "Erwartet: '# Title: StevenBlack/hosts'"
            return
        }
        
        # Zähle blockierte Domains
        $allContent = Get-Content $localHostsFile -ErrorAction Stop
        $blockedDomains = ($allContent | Where-Object { $_ -match '^0\.0\.0\.0\s+' }).Count
        
        Write-Success "Lokale hosts-Datei validiert: $blockedDomains Domains"
        Write-Verbose "Datei-Groesse: $([Math]::Round((Get-Item $localHostsFile).Length / 1MB, 2)) MB"
        
        # Installiere via ATOMARER REPLACE (Best Practice 25H2)
        Write-Info "Installiere hosts-Datei (atomarer Replace)..."
        
        $hostsTemp = "$hostsPath.new"
        try {
            # Kopiere zu temp-File
            Copy-Item -Path $localHostsFile -Destination $hostsTemp -Force -ErrorAction Stop
            
            # Validiere Kopie
            $newContent = Get-Content $hostsTemp -ErrorAction Stop
            if ($newContent.Count -lt 1000) {
                throw "Kopierte Datei zu klein ($($newContent.Count) Zeilen < 1000)!"
            }
            
            # Atomarer Replace: temp -> final
            Move-Item -Path $hostsTemp -Destination $hostsPath -Force -ErrorAction Stop
            Write-Verbose "Atomarer Replace erfolgreich"
        }
        catch {
            # Cleanup temp file bei Fehler
            if (Test-Path $hostsTemp) {
                Remove-Item $hostsTemp -Force -ErrorAction SilentlyContinue
            }
            throw "Hosts-Datei Installation fehlgeschlagen: $_"
        }
        
        # Flush DNS cache (mit Timeout - verhindert Hang)
        Write-Info "DNS-Cache wird geleert..."
        $dnsJob = $null
        try {
            $dnsJob = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
            $null = Wait-Job $dnsJob -Timeout 10
            
            if ($dnsJob.State -eq 'Completed') {
                $null = Receive-Job $dnsJob -ErrorAction SilentlyContinue
                Write-Verbose "DNS Cache erfolgreich geleert"
            }
            elseif ($dnsJob.State -eq 'Running') {
                Stop-Job $dnsJob -ErrorAction SilentlyContinue
                Write-Warning "DNS Cache Flush Timeout (10s) - wird uebersprungen"
            }
        }
        catch {
            Write-Verbose "DNS Cache Flush Fehler (nicht kritisch): $_"
        }
        finally {
            # Garantierter Job-Cleanup
            if ($dnsJob) {
                Remove-Job $dnsJob -Force -ErrorAction SilentlyContinue
            }
        }
        
        # ERFOLG!
        Write-Success "Steven Black's Blocklist installiert ($blockedDomains Domains)"
        Write-Info "Blockiert: Malware, Tracking, Werbung, Coin-Miner, Phishing"
        Write-Info "Quelle: Lokale Datei (NoID Privacy Project)"
        Write-Warning "Einige legitime Websites koennen betroffen sein!"
    }
    catch {
        Write-Error "Installation fehlgeschlagen: $_"
        Write-Error "DNS-Blocklist wurde NICHT installiert!"
    }
}

# DELIVERY OPTIMIZATION WURDE VERSCHOBEN!
#
# Die Funktion Set-DeliveryOptimization wurde nach SecurityBaseline-WindowsUpdate.ps1 verschoben
# und in Set-DeliveryOptimizationDefaults umbenannt.
#
# Grund: User möchte KEINE Group Policy (würde Toggle ausgrauen)
#        Stattdessen: Default-Setting das User ändern kann
#
# ALTE VERSION (hier, mit Policy):
#   HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization
#   -> Group Policy = User kann nicht ändern
#
# NEUE VERSION (WindowsUpdate.ps1, ohne Policy):
#   HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config
#   -> User Setting = User kann in Settings ändern
#
# Siehe: SecurityBaseline-WindowsUpdate.ps1 -> Set-DeliveryOptimizationDefaults

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
    
    Write-Section "Strict Inbound Firewall (BLOCK ALL INCOMING)"
    
    Write-Info "Firewall wird auf Maximum Inbound Security gesetzt..."
    
    # Set firewall to block ALL inbound (Maximum Security!)
    foreach ($firewallProfile in @('Domain', 'Private', 'Public')) {
        try {
            Write-Verbose "Konfiguriere ${firewallProfile} Profil..."
            
            # Block all inbound by default
            Set-NetFirewallProfile -Name $firewallProfile -DefaultInboundAction Block -ErrorAction Stop
            
            # CRITICAL: Block ALL incoming - even allowed apps (Maximum Security!)
            Set-NetFirewallProfile -Name $firewallProfile -AllowInboundRules False -ErrorAction Stop
            
            # Allow all outbound (you can still access internet)
            Set-NetFirewallProfile -Name $firewallProfile -DefaultOutboundAction Allow -ErrorAction Stop
            
            # Enable firewall
            Set-NetFirewallProfile -Name $firewallProfile -Enabled True -ErrorAction Stop
            
            Write-Verbose "     ${firewallProfile}: Inbound=BLOCK ALL (incl. allowed apps), Outbound=ALLOW"
        }
        catch {
            Write-Warning "Konnte Firewall-Profil $firewallProfile nicht konfigurieren: $_"
        }
    }
    
    Write-Success "Strict Inbound Firewall aktiviert"
    Write-Info "Eingehend: ALLES BLOCKIERT (auch erlaubte Apps!)"
    Write-Info "Ausgehend: ALLES ERLAUBT (Internet funktioniert normal)"
    Write-Warning "MAXIMUM SECURITY: NICHTS kann von aussen rein!"
    Write-Warning "Checkbox 'Blockiert alle eingehenden Verbindungen' ist jetzt AKTIV!"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
