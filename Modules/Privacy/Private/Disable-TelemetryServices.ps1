function Disable-TelemetryServices {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory = $true)][array]$Services)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable TelemetryServices')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Disabling telemetry services..." -Module "Privacy"

        $serviceInventory = @(Get-Service -ErrorAction Stop)
        foreach ($serviceConfig in $Services) {
            $serviceMatches = @($serviceInventory | Where-Object { [string]$_.Name -eq [string]$serviceConfig.Name })
            if ($serviceMatches.Count -ne 1) {
                throw "Sealed Privacy service identity no longer resolves exactly once: $($serviceConfig.Name)"
            }
            $service = $serviceMatches[0]
                if ($service.Status -ne 'Stopped') {
                    # A forced stop would also mutate dependent services that
                    # are not part of this module's sealed prestate.
                    Stop-Service -Name $serviceConfig.Name -ErrorAction Stop
                    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
                }
                Set-Service -Name $serviceConfig.Name -StartupType Disabled -ErrorAction Stop
                $service = Get-Service -Name $serviceConfig.Name -ErrorAction Stop
                if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') {
                    throw "Service post-apply mismatch for $($serviceConfig.Name): $($service.StartType)/$($service.Status)"
                }
            Write-Log -Level SUCCESS -Message "Disabled service: $($serviceConfig.Name)" -Module "Privacy"
        }

        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to disable services: $_" -Module "Privacy"
        return $false
    }
}
