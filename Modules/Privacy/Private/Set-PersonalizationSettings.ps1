function Set-PersonalizationSettings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][PSCustomObject]$Config)
    
    try {
        Write-Log -Level INFO -Message "Applying personalization settings..." -Module "Privacy"
        
        foreach ($keyPath in $Config.Personalization.PSObject.Properties.Name) {
            if (!(Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
            foreach ($valueName in $Config.Personalization.$keyPath.PSObject.Properties.Name) {
                $valueData = $Config.Personalization.$keyPath.$valueName
                $existing = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = if ($valueData.Type -eq "DWord") { "DWord" } else { "String" }
                    New-ItemProperty -Path $keyPath -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
            }
        }
        
        Write-Log -Level SUCCESS -Message "Personalization settings applied" -Module "Privacy"
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed: $_" -Module "Privacy"
        return $false
    }
}
