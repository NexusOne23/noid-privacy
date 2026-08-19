#Requires -Version 5.1

function Get-AdvancedSecurityRuntimeApplicability {
    <#
    .SYNOPSIS
        Captures the exact runtime inventory used to classify selected
        AdvancedSecurity targets as applicable or NotApplicable.

    .DESCRIPTION
        Edition applicability alone is insufficient for optional Windows
        services and device-backed targets.  This helper
        fails closed on provider or identity ambiguity and returns only exact
        inventory facts.  Decision accounting remains in
        Get-AdvancedSecurityDecisionAccounting so Apply, DryRun, and reports
        use one classification contract.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $allServices = @(Get-Service -ErrorAction Stop)
    $servicePresence = [ordered]@{}
    foreach ($serviceName in @('lmhosts', 'SSDPSRV', 'upnphost', 'FDResPub', 'fdPHost', 'WFDSConMgrSvc')) {
        $serviceMatches = @($allServices | Where-Object { [string]$_.Name -eq $serviceName })
        if ($serviceMatches.Count -gt 1) {
            throw "AdvancedSecurity service identity is ambiguous during runtime applicability detection: $serviceName"
        }
        $servicePresence[$serviceName] = ($serviceMatches.Count -eq 1)
    }

    $wfdAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*'
        })
    $interactiveUser = Get-AdvancedSecurityInteractiveUser -AllowNone

    return [PSCustomObject]@{
        LmhostsPresent      = [bool]$servicePresence['lmhosts']
        SsdpSrvPresent      = [bool]$servicePresence['SSDPSRV']
        UpnpHostPresent     = [bool]$servicePresence['upnphost']
        FdResPubPresent     = [bool]$servicePresence['FDResPub']
        FdPHostPresent      = [bool]$servicePresence['fdPHost']
        WfdServicePresent   = [bool]$servicePresence['WFDSConMgrSvc']
        WfdAdapterPresent   = ($wfdAdapters.Count -gt 0)
        WinInetUserPresent  = ($null -ne $interactiveUser)
    }
}
