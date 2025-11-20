function Test-WDigest {
    <#
    .SYNOPSIS
        Test WDigest credential protection compliance
    
    .DESCRIPTION
        Verifies that WDigest is configured to NOT store plaintext credentials in LSASS memory.
        Checks the UseLogonCredential registry value.
        
        Expected: UseLogonCredential = 0 (Secure)
        Insecure: UseLogonCredential = 1 (Plaintext credentials in memory!)
    
    .EXAMPLE
        Test-WDigest
        Returns compliance status for WDigest protection
    
    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()
    
    try {
        $wdigestRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        $result = [PSCustomObject]@{
            Feature = "WDigest Protection"
            Status = "Unknown"
            Details = @()
            UseLogonCredential = $null
            Compliant = $false
            Windows_Version = ""
            Deprecated = $false
        }
        
        # Get Windows version
        $osVersion = [System.Environment]::OSVersion.Version
        $isWin11 = $osVersion.Major -ge 10 -and $osVersion.Build -ge 22000
        $isWin11_24H2Plus = $isWin11 -and $osVersion.Build -ge 26100
        
        if ($isWin11) {
            $result.Windows_Version = "Windows 11 (Build $($osVersion.Build))"
            if ($isWin11_24H2Plus) {
                $result.Deprecated = $true
                $result.Details += "Windows 11 24H2+ detected - WDigest setting is deprecated"
            }
        }
        elseif ($osVersion.Major -eq 10) {
            $result.Windows_Version = "Windows 10 (Build $($osVersion.Build))"
        }
        else {
            $result.Windows_Version = "Windows $($osVersion.Major).$($osVersion.Minor) (Build $($osVersion.Build))"
        }
        
        # Check registry value
        if (Test-Path $wdigestRegPath) {
            $useLogonCred = (Get-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
            
            if ($null -ne $useLogonCred) {
                $result.UseLogonCredential = $useLogonCred
                
                if ($useLogonCred -eq 0) {
                    $result.Status = "Secure"
                    $result.Compliant = $true
                    $result.Details += "UseLogonCredential = 0 (Plaintext credentials NOT stored)"
                    
                    if ($result.Deprecated) {
                        $result.Details += "Note: Setting is deprecated but explicitly configured for backwards compatibility"
                    }
                }
                elseif ($useLogonCred -eq 1) {
                    $result.Status = "INSECURE!"
                    $result.Compliant = $false
                    $result.Details += "WARNING: UseLogonCredential = 1 (Plaintext credentials IN MEMORY!)"
                    $result.Details += "VULNERABLE to Mimikatz, WCE, and other credential dumping tools!"
                }
                else {
                    $result.Status = "Unknown Value"
                    $result.Compliant = $false
                    $result.Details += "UseLogonCredential = $useLogonCred (Unknown value)"
                }
            }
            else {
                # Value not set - default depends on OS version
                if ($osVersion.Major -eq 6 -and $osVersion.Minor -le 2) {
                    # Windows 7/8 - default is 1 (INSECURE!)
                    $result.Status = "Insecure (Default)"
                    $result.Compliant = $false
                    $result.Details += "UseLogonCredential not set - Windows 7/8 default is 1 (INSECURE!)"
                }
                else {
                    # Windows 8.1+ - default is 0 (Secure)
                    $result.Status = "Secure (Default)"
                    $result.Compliant = $true
                    $result.Details += "UseLogonCredential not set - Windows 8.1+ default is 0 (Secure)"
                    
                    if ($result.Deprecated) {
                        $result.Details += "Windows 11 24H2+: Setting is hardcoded secure (deprecated)"
                    }
                }
            }
        }
        else {
            # Registry path doesn't exist
            if ($osVersion.Major -eq 6 -and $osVersion.Minor -le 2) {
                # Windows 7/8
                $result.Status = "Insecure (No Config)"
                $result.Compliant = $false
                $result.Details += "WDigest registry path not found - Windows 7/8 default is INSECURE!"
            }
            else {
                # Windows 8.1+
                $result.Status = "Secure (Default)"
                $result.Compliant = $true
                $result.Details += "WDigest registry path not found - Windows 8.1+ default is secure"
            }
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test WDigest protection: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature = "WDigest Protection"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
