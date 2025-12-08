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
        $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        $rdpServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        
        $result = [PSCustomObject]@{
            Feature = "RDP Security"
            Status = "Unknown"
            Details = @()
            NLA_Enabled = $false
            SSL_TLS_Enabled = $false
            RDP_Disabled = $false
            Compliant = $false
        }
        
        # Check NLA
        if (Test-Path $rdpRegPath) {
            $userAuth = (Get-ItemProperty -Path $rdpRegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
            $secLayer = (Get-ItemProperty -Path $rdpRegPath -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer
            
            if ($userAuth -eq 1) {
                $result.NLA_Enabled = $true
                $result.Details += "NLA enforced (UserAuthentication = 1)"
            }
            else {
                $result.Details += "NLA NOT enforced (UserAuthentication = $userAuth)"
            }
            
            if ($secLayer -eq 2) {
                $result.SSL_TLS_Enabled = $true
                $result.Details += "SSL/TLS enforced (SecurityLayer = 2)"
            }
            else {
                $result.Details += "SSL/TLS NOT enforced (SecurityLayer = $secLayer)"
            }
        }
        else {
            $result.Details += "RDP registry path not found"
        }
        
        # Check if RDP is completely disabled
        if (Test-Path $rdpServerPath) {
            $rdpDisabled = (Get-ItemProperty -Path $rdpServerPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
            
            if ($rdpDisabled -eq 1) {
                $result.RDP_Disabled = $true
                $result.Details += "RDP completely disabled (fDenyTSConnections = 1)"
            }
        }
        
        # Determine compliance
        if ($result.RDP_Disabled) {
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
