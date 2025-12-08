function Set-AppPrivacySettings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][PSCustomObject]$Config)
    
    try {
        Write-Log -Level INFO -Message "Applying App Privacy + Search + Sync settings..." -Module "Privacy"
        
        # Search & Cloud
        foreach ($keyPath in $Config.SearchAndCloud.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $Config.SearchAndCloud.$keyPath.PSObject.Properties.Name) {
                $valueData = $Config.SearchAndCloud.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        # Input & Sync
        foreach ($keyPath in $Config.InputAndSync.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $Config.InputAndSync.$keyPath.PSObject.Properties.Name) {
                $valueData = $Config.InputAndSync.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        # Location & App Privacy
        foreach ($keyPath in $Config.LocationAndAppPrivacy.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $Config.LocationAndAppPrivacy.$keyPath.PSObject.Properties.Name) {
                $valueData = $Config.LocationAndAppPrivacy.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        Write-Log -Level SUCCESS -Message "App Privacy settings applied" -Module "Privacy"
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed: $_" -Module "Privacy"
        return $false
    }
}
