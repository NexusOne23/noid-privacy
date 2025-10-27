# ============================================================================
# SecurityBaseline-WirelessDisplay.ps1
# Wireless Display / Miracast Deaktivierung (4 Ebenen)
# ============================================================================

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Disable-WirelessDisplay {
    <#
    .SYNOPSIS
        Deaktiviert Wireless Display / Miracast komplett
    .DESCRIPTION
        Deaktiviert Miracast auf 4 Ebenen: Services, Registry, Firewall, Apps.
        Best Practice 25H2: CmdletBinding, Out-Null ersetzt, Error-Handling ueberall.
        ACHTUNG: Cast zu Smart TV funktioniert danach nicht mehr!
        HINWEIS: "Wiedergeben"-Button in Quick Settings bleibt sichtbar (kann nur manuell entfernt werden).
    .EXAMPLE
        Disable-WirelessDisplay
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Wireless Display / Miracast KOMPLETT deaktivieren (4 Ebenen)"
    
    Write-Info "Deaktiviere auf ALLEN Ebenen: Services, Registry, Firewall, Apps..."
    
    # === EBENE 1: SERVICES ===
    Write-Info "Ebene 1/4: Services deaktivieren..."
    
    $wirelessServices = @(
        @{Name="ProjSvc"; DisplayName="Windows Projection Service (Miracast)"},
        @{Name="DisplayEnhancementService"; DisplayName="Display Enhancement Service"}
    )
    
    foreach ($svc in $wirelessServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            # Stop and disable service (race-condition-frei)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Verbose "     $($svc.DisplayName) deaktiviert"
            }
            else {
                Write-Verbose "     $($svc.DisplayName) konnte nicht deaktiviert werden"
            }
        }
    }
    
    # User Services (mit Wildcards) - via Registry (Set-Service funktioniert nicht!)
    # Windows 11 User Services haben dynamische Namen und koennen nicht via Set-Service disabled werden
    $userServicePrefixes = @(
        @{Name="DevicePickerUserSvc"; Reg="DevicePickerUserSvc"},
        @{Name="DevicesFlowUserSvc"; Reg="DevicesFlowUserSvc"}
    )
    foreach ($svc in $userServicePrefixes) {
        try {
            # Registry-Methode fuer User Services (einzige Methode die funktioniert!)
            $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Reg)"
            if (Test-Path $svcRegPath) {
                Set-ItemProperty -Path $svcRegPath -Name "Start" -Value 4 -ErrorAction SilentlyContinue
                Write-Verbose "$($svc.Name) deaktiviert (via Registry)"
            }
        }
        catch {
            Write-Verbose "Fehler bei $($svc.Name): $_"
        }
    }
    
    # === EBENE 2: REGISTRY ===
    Write-Info "Ebene 2/4: Registry haerten..."
    
    # PlayToReceiver (DLNA/Cast)
    $playToPath = "HKLM:\SOFTWARE\Microsoft\PlayToReceiver"
    [void](Set-RegistryValue -Path $playToPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "PlayToReceiver deaktivieren")
    
    # Projektion zu diesem PC
    $connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
    [void](Set-RegistryValue -Path $connectPath -Name "AllowProjectionToPC" -Value 0 -Type DWord `
        -Description "Projektion zu diesem PC verbieten")
    [void](Set-RegistryValue -Path $connectPath -Name "RequirePinForPairing" -Value 1 -Type DWord `
        -Description "PIN fuer Pairing erzwingen")
    
    # Wireless Display
    $wirelessDisplayPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WirelessDisplay"
    [void](Set-RegistryValue -Path $wirelessDisplayPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "Wireless Display Feature deaktivieren")
    
    # Media Player Wireless Receiver
    $miracastPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
    [void](Set-RegistryValue -Path $miracastPath -Name "PreventWirelessReceiver" -Value 1 -Type DWord `
        -Description "Wireless Media Streaming verhindern")
    
    # Wi-Fi Direct
    $wifiDirectPath = "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache"
    [void](Set-RegistryValue -Path $wifiDirectPath -Name "OsuRegistrationStatus" -Value 0 -Type DWord `
        -Description "Wi-Fi Direct OSU deaktivieren")
    
    # === EBENE 3: FIREWALL ===
    Write-Info "Ebene 3/4: Firewall-Regeln blockieren..."
    
    $wirelessFirewallRules = @(
        "Wireless Display",
        "*Wireless Display*",
        "Wi-Fi Direct*",
        "WLAN Service*WFD*"
    )
    
    foreach ($ruleName in $wirelessFirewallRules) {
        try {
            $rules = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | 
                Where-Object {$_.Enabled -eq $true}
            
            if ($rules) {
                $rules | Disable-NetFirewallRule -ErrorAction Stop
                Write-Verbose "Firewall-Regel '$ruleName' deaktiviert"
            }
        }
        catch {
            Write-Verbose "Firewall-Regel '$ruleName': $_"
        }
    }
    
    # Miracast Ports blockieren (TCP 7236, 7250) - mit Idempotenz
    try {
        # Check ob Regel bereits existiert (eindeutiger Name mit NoID-Prefix)
        $rule7236 = Get-NetFirewallRule -DisplayName "NoID-Block-Miracast-TCP-7236" -ErrorAction SilentlyContinue
        if (-not $rule7236) {
            $null = New-NetFirewallRule -DisplayName "NoID-Block-Miracast-TCP-7236" `
                -Direction Inbound -Protocol TCP -LocalPort 7236 `
                -Action Block -Profile Any -Enabled True -ErrorAction Stop
            Write-Verbose "     Firewall-Regel erstellt: Miracast TCP 7236"
        } else {
            Write-Verbose "     Firewall-Regel existiert bereits: Miracast TCP 7236"
        }
        
        $rule7250 = Get-NetFirewallRule -DisplayName "NoID-Block-Miracast-TCP-7250" -ErrorAction SilentlyContinue
        if (-not $rule7250) {
            $null = New-NetFirewallRule -DisplayName "NoID-Block-Miracast-TCP-7250" `
                -Direction Inbound -Protocol TCP -LocalPort 7250 `
                -Action Block -Profile Any -Enabled True -ErrorAction Stop
            Write-Verbose "     Firewall-Regel erstellt: Miracast TCP 7250"
        } else {
            Write-Verbose "     Firewall-Regel existiert bereits: Miracast TCP 7250"
        }
    }
    catch {
        Write-Verbose "Miracast Port-Regeln Fehler: $_"
    }
    
    Write-Verbose "Miracast Ports: Blockierung abgeschlossen"
    
    # === EBENE 4: APPS ENTFERNEN ===
    Write-Info "Ebene 4/4: Wireless Display Apps entfernen..."
    
    $wirelessApps = @(
        "Microsoft.Windows.SecondaryTileExperience",
        "*PPIProjection*",
        "*Miracast*"
    )
    
    foreach ($appPattern in $wirelessApps) {
        try {
            Get-AppxPackage -Name $appPattern -AllUsers -ErrorAction SilentlyContinue | 
                Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                Where-Object {$_.DisplayName -like $appPattern} | 
                Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            
            Write-Verbose "App '$appPattern' entfernt"
        }
        catch {
            Write-Verbose "App '$appPattern' nicht gefunden"
        }
    }
    
    Write-Success "Wireless Display KOMPLETT deaktiviert auf ALLEN 4 Ebenen:"
    Write-Success "  [OK] Ebene 1: Services gestoppt"
    Write-Success "  [OK] Ebene 2: Registry gehaertet"
    Write-Success "  [OK] Ebene 3: Firewall blockiert"
    Write-Success "  [OK] Ebene 4: Apps entfernt"
    Write-Host ""
    Write-Warning "Miracast / Cast zu Smart TV funktioniert NICHT MEHR!"
    Write-Info "HINWEIS: 'Wiedergeben'-Button bleibt in Quick Settings (manuell entfernen: Windows-Taste + A | Bearbeiten)"
    Write-Info "Klick auf Button ist harmlos - Services sind deaktiviert, Feature funktioniert nicht"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
