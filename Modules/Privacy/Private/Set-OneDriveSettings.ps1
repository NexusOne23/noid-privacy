function Set-OneDriveSettings {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Applying OneDrive + Store settings..." -Module "Privacy"
        
        $configPath = Join-Path $PSScriptRoot "..\Config\OneDrive.json"
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        foreach ($keyPath in $config.OneDrivePolicies.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $config.OneDrivePolicies.$keyPath.PSObject.Properties.Name) {
                $valueData = $config.OneDrivePolicies.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        foreach ($keyPath in $config.StorePolicies.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $config.StorePolicies.$keyPath.PSObject.Properties.Name) {
                $valueData = $config.StorePolicies.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        Write-Log -Level SUCCESS -Message "OneDrive + Store settings applied" -Module "Privacy"
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed: $_" -Module "Privacy"
        return $false
    }
}
