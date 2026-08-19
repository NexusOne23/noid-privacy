function Test-RdpSecurity {
    <#
    .SYNOPSIS
        Test RDP security hardening compliance

    .DESCRIPTION
        Verifies that RDP is properly hardened:
        - NLA (Network Level Authentication) is enforced
        - SSL/TLS encryption is required
        - Optionally checks if RDP is completely disabled

    .EXAMPLE
        Test-RdpSecurity
        Returns compliance status for RDP hardening

    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()

    try {
        # Enable-RdpNLA owns NLA + SSL/TLS only in the GPO path
        # (Policies\Microsoft\Windows NT\Terminal Services). The station values
        # are read only for diagnostics and never substitute for an absent or
        # mistyped module-owned policy value.
        $rdpGpoPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        $rdpStationPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        $rdpServerPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

        $result = [PSCustomObject]@{
            Feature = "RDP Security"
            Status = "Unknown"
            Details = @()
            NLA_Enabled = $false
            SSL_TLS_Enabled = $false
            NLA_GpoValue = $null
            SecurityLayer_GpoValue = $null
            RDP_Disabled = $false
            RDP_DenyValue = $null
            RDP_DenyType = $null
            Compliant = $false
        }

        # GPO path values take effective precedence; fall back to station-level keys.
        $userAuthGpo = $null; $secLayerGpo = $null; $userAuthGpoType = $null; $secLayerGpoType = $null
        if (Test-Path -LiteralPath $rdpGpoPath -PathType Container) {
            $gpoKey = Get-Item -LiteralPath $rdpGpoPath -ErrorAction Stop
            if ($gpoKey.GetValueNames() -contains 'UserAuthentication') {
                $userAuthGpo = $gpoKey.GetValue('UserAuthentication')
                $userAuthGpoType = $gpoKey.GetValueKind('UserAuthentication').ToString()
            }
            if ($gpoKey.GetValueNames() -contains 'SecurityLayer') {
                $secLayerGpo = $gpoKey.GetValue('SecurityLayer')
                $secLayerGpoType = $gpoKey.GetValueKind('SecurityLayer').ToString()
            }
        }
        $result.NLA_GpoValue = $userAuthGpo
        $result.SecurityLayer_GpoValue = $secLayerGpo

        $userAuthStation = if (Test-Path $rdpStationPath) {
            (Get-ItemProperty -Path $rdpStationPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        } else { $null }

        $secLayerStation = if (Test-Path $rdpStationPath) {
            (Get-ItemProperty -Path $rdpStationPath -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer
        } else { $null }

        if ($userAuthGpoType -eq 'DWord' -and $userAuthGpo -eq 1) {
            $result.NLA_Enabled = $true
            $result.Details += "NLA enforced by the module-owned GPO value (UserAuthentication = 1)"
        }
        else {
            $result.Details += "NLA NOT enforced (GPO=$userAuthGpo, WinStations=$userAuthStation)"
        }

        if ($secLayerGpoType -eq 'DWord' -and $secLayerGpo -eq 2) {
            $result.SSL_TLS_Enabled = $true
            $result.Details += "SSL/TLS enforced by the module-owned GPO value (SecurityLayer = 2)"
        }
        else {
            $result.Details += "SSL/TLS NOT enforced (GPO=$secLayerGpo, WinStations=$secLayerStation)"
        }

        if (-not (Test-Path $rdpGpoPath) -and -not (Test-Path $rdpStationPath)) {
            $result.Details += "RDP registry paths not found"
        }

        # Check if RDP is completely disabled
        if (Test-Path $rdpServerPath) {
            $serverKey = Get-Item -LiteralPath $rdpServerPath -ErrorAction Stop
            $rdpDisabled = if ($serverKey.GetValueNames() -contains 'fDenyTSConnections') { $serverKey.GetValue('fDenyTSConnections') } else { $null }
            $result.RDP_DenyValue = $rdpDisabled
            if ($null -ne $rdpDisabled) { $result.RDP_DenyType = $serverKey.GetValueKind('fDenyTSConnections').ToString() }

            if ($result.RDP_DenyType -eq 'DWord' -and $rdpDisabled -eq 1) {
                $result.RDP_Disabled = $true
                $result.Details += "RDP completely disabled (fDenyTSConnections = 1)"
            }
        }

        # Determine compliance
        if ($result.RDP_Disabled -and $result.NLA_Enabled -and $result.SSL_TLS_Enabled) {
            $result.Status = "Secure (RDP Disabled)"
            $result.Compliant = $true
        }
        elseif ($result.NLA_Enabled -and $result.SSL_TLS_Enabled) {
            $result.Status = "Secure (NLA + SSL/TLS)"
            $result.Compliant = $true
        }
        else {
            $result.Status = "Insecure"
            $result.Compliant = $false
        }

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test RDP security: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature = "RDP Security"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
