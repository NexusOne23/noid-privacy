function Set-TelemetrySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    try {
        Write-Log -Level INFO -Message "Applying telemetry settings ($($Config.Mode) mode)..." -Module "Privacy"
        
        # Debug: Check if DataCollection exists
        if (-not $Config.DataCollection) {
            Write-Log -Level ERROR -Message "DataCollection is NULL or empty in config!" -Module "Privacy"
            Write-Log -Level DEBUG -Message "Config properties: $($Config.PSObject.Properties.Name -join ', ')" -Module "Privacy"
            return $false
        }
        
        $keyCount = @($Config.DataCollection.PSObject.Properties.Name).Count
        Write-Log -Level DEBUG -Message "DataCollection has $keyCount registry keys to process" -Module "Privacy"
        
        foreach ($keyPath in $Config.DataCollection.PSObject.Properties.Name) {
            $key = $keyPath
            $values = $Config.DataCollection.$keyPath
            
            if (!(Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
                Write-Log -Level INFO -Message "Created registry key: $key" -Module "Privacy"
            }
            
            foreach ($valueName in $values.PSObject.Properties.Name) {
                $valueData = $values.$valueName
                $existing = Get-ItemProperty -Path $key -Name $valueName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $key -Name $valueName -Value $valueData.Value -Force | Out-Null
                } else {
                    $propType = switch ($valueData.Type) {
                        "DWord" { "DWord" }
                        "String" { "String" }
                        default { "DWord" }
                    }
                    New-ItemProperty -Path $key -Name $valueName -Value $valueData.Value -PropertyType $propType -Force | Out-Null
                }
                Write-Log -Level INFO -Message "Set $key\$valueName = $($valueData.Value) ($($valueData.Description))" -Module "Privacy"
            }
        }
        
        Write-Log -Level SUCCESS -Message "Telemetry settings applied successfully" -Module "Privacy"
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to apply telemetry settings: $_" -Module "Privacy"
        return $false
    }
}
