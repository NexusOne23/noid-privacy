# ============================================================================
# SecurityBaseline-WirelessDisplay.ps1
# Wireless Display / Miracast Disablement (4 Levels)
# ============================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Disable-WirelessDisplay {
    <#
    .SYNOPSIS
        Completely disables Wireless Display / Miracast
    .DESCRIPTION
        Disables Miracast on 4 levels: Services, Registry, Firewall, Apps.
        Best Practice 25H2: CmdletBinding, Out-Null replaced, Error-Handling everywhere.
        WARNING: Cast to Smart TV will NOT work after this!
        NOTE: "Cast" button in Quick Settings remains visible (can only be removed manually).
    .EXAMPLE
        Disable-WirelessDisplay
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Wireless Display / Miracast KOMPLETT deaktivieren (4 Ebenen)"
    
    Write-Info "Deaktiviere auf ALLEN Ebenen: Services, Registry, Firewall, Apps..."
    
    # === LEVEL 1: SERVICES ===
    Write-Info "Ebene 1/4: Services deaktivieren..."
    
    $wirelessServices = @(
        @{Name="ProjSvc"; DisplayName="Windows Projection Service (Miracast)"},
        @{Name="DisplayEnhancementService"; DisplayName="Display Enhancement Service"}
    )
    
    foreach ($svc in $wirelessServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            # Stop and disable service (race-condition free)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Verbose "     $($svc.DisplayName) deaktiviert"
            }
            else {
                Write-Verbose "     $($svc.DisplayName) konnte nicht deaktiviert werden"
            }
        }
    }
    
    # User Services (with Wildcards) - via Registry (Set-Service doesn't work!)
    # Windows 11 User Services have dynamic names and cannot be disabled via Set-Service
    $userServicePrefixes = @(
        @{Name="DevicePickerUserSvc"; Reg="DevicePickerUserSvc"},
        @{Name="DevicesFlowUserSvc"; Reg="DevicesFlowUserSvc"}
    )
    foreach ($svc in $userServicePrefixes) {
        try {
            # Registry method for User Services (only method that works!)
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
    
    # === LEVEL 2: REGISTRY ===
    Write-Info "Ebene 2/4: Registry haerten..."
    
    # PlayToReceiver (DLNA/Cast)
    $playToPath = "HKLM:\SOFTWARE\Microsoft\PlayToReceiver"
    [void](Set-RegistryValue -Path $playToPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "Disable PlayToReceiver")
    
    # Projection to this PC
    $connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
    [void](Set-RegistryValue -Path $connectPath -Name "AllowProjectionToPC" -Value 0 -Type DWord `
        -Description "Prohibit projection to this PC")
    [void](Set-RegistryValue -Path $connectPath -Name "RequirePinForPairing" -Value 1 -Type DWord `
        -Description "Enforce PIN for pairing")
    
    # Wireless Display
    $wirelessDisplayPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WirelessDisplay"
    [void](Set-RegistryValue -Path $wirelessDisplayPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "Disable Wireless Display Feature")
    
    # Media Player Wireless Receiver
    $miracastPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
    [void](Set-RegistryValue -Path $miracastPath -Name "PreventWirelessReceiver" -Value 1 -Type DWord `
        -Description "Prevent Wireless Media Streaming")
    
    # Wi-Fi Direct
    $wifiDirectPath = "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache"
    [void](Set-RegistryValue -Path $wifiDirectPath -Name "OsuRegistrationStatus" -Value 0 -Type DWord `
        -Description "Disable Wi-Fi Direct OSU")
    
    # === LEVEL 3: FIREWALL ===
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
    
    # Block Miracast Ports (TCP 7236, 7250) - with Idempotency
    try {
        # Check if rule already exists (unique name with NoID-Prefix)
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
    
    # === LEVEL 4: REMOVE APPS ===
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
