#Requires -Version 5.1

function Get-PrivacyUcpdProtectionState {
    <#
    .SYNOPSIS
        Reports whether Windows User Choice Protection currently blocks the
        PowerShell-owned Widgets policy target used by Privacy Strict/Paranoid.

    .DESCRIPTION
        Windows 11 UCPD protects SOFTWARE\Policies\Microsoft\Dsh and
        AllowNewsAndInterests from direct writes by PowerShell and other
        command-line registry tools. A running or indeterminate driver state
        must therefore fail closed: applying the value could create a key that
        the same elevated process cannot restore exactly.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $servicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\UCPD'
    if (-not (Test-Path -LiteralPath $servicePath -PathType Container)) {
        return [PSCustomObject]@{
            StateKnown = $true
            Installed = $false
            Active = $false
            Status = 'Absent'
            Error = $null
            Source = 'Service registry and ServiceController'
        }
    }

    try {
        $service = Get-Service -Name 'UCPD' -ErrorAction Stop
        $status = [string]$service.Status
        return [PSCustomObject]@{
            StateKnown = $true
            Installed = $true
            # StartPending/StopPending are treated as protected. Only a proven
            # stopped driver is safe for a direct, exactly reversible write.
            Active = $status -ne 'Stopped'
            Status = $status
            Error = $null
            Source = 'Service registry and ServiceController'
        }
    }
    catch {
        return [PSCustomObject]@{
            StateKnown = $false
            Installed = $true
            Active = $true
            Status = 'Unknown'
            Error = $_.Exception.Message
            Source = 'Service registry and ServiceController'
        }
    }
}
