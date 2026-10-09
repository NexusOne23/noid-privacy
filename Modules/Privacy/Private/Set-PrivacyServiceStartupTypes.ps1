function Set-PrivacyServiceStartupTypes {
    <#
    .SYNOPSIS
        Applies the sealed startup type of each Privacy service.

    .DESCRIPTION
        Disabled stops the service and disables it. Manual sets the Windows
        default start type and leaves the run state to Windows, which starts
        such a service on demand. Paranoid uses Manual for WerSvc: with WerSvc
        disabled, Windows still queued and sent error reports and a crashing
        .NET program hung, so error reporting is turned off by policy instead.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory = $true)][array]$Services)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set Privacy service startup types')) {
        return
    }

    try {
        Write-Log -Level INFO -Message "Setting Privacy service startup types..." -Module "Privacy"

        $serviceInventory = @(Get-Service -ErrorAction Stop)
        foreach ($serviceConfig in $Services) {
            $startupType = [string]$serviceConfig.StartupType
            if ($startupType -cnotin @('Disabled', 'Manual')) {
                throw "Sealed Privacy service startup type is invalid for $($serviceConfig.Name): '$startupType'"
            }
            $serviceMatches = @($serviceInventory | Where-Object { [string]$_.Name -eq [string]$serviceConfig.Name })
            if ($serviceMatches.Count -ne 1) {
                throw "Sealed Privacy service identity no longer resolves exactly once: $($serviceConfig.Name)"
            }
            $service = $serviceMatches[0]
            if ($startupType -eq 'Disabled' -and $service.Status -ne 'Stopped') {
                # A forced stop would also mutate dependent services that
                # are not part of this module's sealed prestate.
                Stop-Service -Name $serviceConfig.Name -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
            }
            Set-Service -Name $serviceConfig.Name -StartupType $startupType -ErrorAction Stop
            $service = Get-Service -Name $serviceConfig.Name -ErrorAction Stop
            if ([string]$service.StartType -ne $startupType -or
                ($startupType -eq 'Disabled' -and $service.Status -ne 'Stopped')) {
                throw "Service post-apply mismatch for $($serviceConfig.Name): $($service.StartType)/$($service.Status)"
            }
            Write-Log -Level SUCCESS -Message "Service $($serviceConfig.Name): $startupType" -Module "Privacy"
        }

        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed to set Privacy service startup types: $_" -Module "Privacy"
        return $false
    }
}
