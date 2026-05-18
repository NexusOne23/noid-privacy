function Disable-TelemetryServices {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][array]$Services)
    
    try {
        Write-Log -Level INFO -Message "Disabling telemetry services..." -Module "Privacy"
        
        foreach ($serviceConfig in $Services) {
            $service = Get-Service -Name $serviceConfig.Name -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $serviceConfig.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $serviceConfig.Name -StartupType Disabled -ErrorAction Stop
                Write-Log -Level SUCCESS -Message "Disabled service: $($serviceConfig.Name)" -Module "Privacy"
            }
        }
        
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to disable services: $_" -Module "Privacy"
        return $false
    }
}
