function Test-WindowsUpdate {
    <#
    .SYNOPSIS
        Verifies Windows Update configuration (3 simple GUI settings)
        
    .DESCRIPTION
        Tests whether the 3 Windows Update GUI settings are properly configured:
        1. Get latest updates immediately
        2. Microsoft Update for other products
        3. Delivery Optimization disabled
        
    .EXAMPLE
        Test-WindowsUpdate
        
    .OUTPUTS
        PSCustomObject with compliance results
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\WindowsUpdate.json"
        
        if (-not (Test-Path $configPath)) {
            return [PSCustomObject]@{
                Feature = "Windows Update"
                Status = "Not Configured"
                Compliant = $false
                Details = "WindowsUpdate.json not found"
            }
        }
        
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        $settingsConfigured = 0
        $settingsTotal = 0
        $details = @()
        
        # Check all 3 settings from config
        foreach ($settingKey in $config.Settings.PSObject.Properties.Name) {
            $setting = $config.Settings.$settingKey
            $regPath = $setting.RegistryPath
            
            foreach ($valueName in $setting.Values.PSObject.Properties.Name) {
                $valueData = $setting.Values.$valueName
                $settingsTotal++
                
                if (Test-Path $regPath) {
                    $actual = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $actual -and $actual.$valueName -eq $valueData.Value) {
                        $settingsConfigured++
                        $details += "$($setting.Name): OK"
                    }
                    else {
                        $details += "$($setting.Name): NOT SET"
                        Write-Log -Level WARNING -Message "Windows Update Check Failed: $($setting.Name)" -Module "AdvancedSecurity"
                        if ($null -eq $actual) {
                            Write-Log -Level WARNING -Message "  - Value '$valueName' not found in $regPath" -Module "AdvancedSecurity"
                        } else {
                            Write-Log -Level WARNING -Message "  - Value '$valueName' mismatch. Expected: $($valueData.Value), Actual: $($actual.$valueName)" -Module "AdvancedSecurity"
                        }
                    }
                }
                else {
                    $details += "$($setting.Name): NOT SET (reg path missing)"
                    Write-Log -Level WARNING -Message "Windows Update Check Failed: $($setting.Name)" -Module "AdvancedSecurity"
                    Write-Log -Level WARNING -Message "  - Registry Path Missing: $regPath" -Module "AdvancedSecurity"
                }
            }
        }
        
        $compliant = ($settingsConfigured -eq $settingsTotal)
        
        return [PSCustomObject]@{
            Feature = "Windows Update"
            Status = if ($compliant) { "Configured" } else { "Incomplete" }
            Compliant = $compliant
            Details = "$settingsConfigured/$settingsTotal settings OK. $(if ($details) { $details -join ', ' })"
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature = "Windows Update"
            Status = "Error"
            Compliant = $false
            Details = "Test failed: $_"
        }
    }
}
