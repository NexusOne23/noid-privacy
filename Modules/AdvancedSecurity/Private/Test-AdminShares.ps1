function Test-AdminShares {
    <#
    .SYNOPSIS
        Test administrative shares compliance
    
    .DESCRIPTION
        Checks if administrative shares (C$, ADMIN$, etc.) are disabled
    
    .EXAMPLE
        Test-AdminShares
    #>
    [CmdletBinding()]
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        $result = [PSCustomObject]@{
            Feature = "Admin Shares"
            Status = "Unknown"
            Details = @()
            AutoShareWks = $null
            AutoShareServer = $null
            ActiveShares = @()
            Compliant = $false
        }
        
        # Check registry settings
        if (Test-Path $regPath) {
            $result.AutoShareWks = (Get-ItemProperty -Path $regPath -Name "AutoShareWks" -ErrorAction SilentlyContinue).AutoShareWks
            $result.AutoShareServer = (Get-ItemProperty -Path $regPath -Name "AutoShareServer" -ErrorAction SilentlyContinue).AutoShareServer
            
            if ($result.AutoShareWks -eq 0 -and $result.AutoShareServer -eq 0) {
                $result.Details += "Registry: AutoShareWks = 0, AutoShareServer = 0 (Disabled)"
            }
            else {
                $result.Details += "Registry: AutoShareWks = $($result.AutoShareWks), AutoShareServer = $($result.AutoShareServer)"
            }
        }
        
        # Check for active admin shares
        $adminShares = Get-SmbShare | Where-Object { $_.Name -match '^[A-Z]\$$|^ADMIN\$$' }
        $result.ActiveShares = $adminShares | Select-Object -ExpandProperty Name
        
        if ($adminShares.Count -eq 0) {
            $result.Details += "No administrative shares found (C$, ADMIN$ removed)"
            
            if ($result.AutoShareWks -eq 0 -and $result.AutoShareServer -eq 0) {
                $result.Status = "Secure"
                $result.Compliant = $true
            }
            else {
                $result.Status = "Partially Secure"
                $result.Compliant = $false
                $result.Details += "WARNING: Shares removed but AutoShare registry not set (will recreate on reboot!)"
            }
        }
        else {
            $result.Status = "Insecure"
            $result.Compliant = $false
            $result.Details += "Active admin shares: $($adminShares.Name -join ', ')"
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test admin shares: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature = "Admin Shares"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
