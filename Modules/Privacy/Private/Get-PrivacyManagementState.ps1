#Requires -Version 5.1

function Test-PrivacyMdmRegistration {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not ('NoIDPrivacyMdmRegistrationInspector' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NoIDPrivacyMdmRegistrationInspector
{
    [DllImport("MDMRegistration.dll", CharSet = CharSet.Unicode)]
    private static extern int IsDeviceRegisteredWithManagement(
        [MarshalAs(UnmanagedType.Bool)] out bool isRegistered,
        uint upnBufferLength,
        IntPtr upnBuffer);

    public static bool IsRegistered()
    {
        bool registered;
        int hr = IsDeviceRegisteredWithManagement(out registered, 0, IntPtr.Zero);
        if (hr != 0) Marshal.ThrowExceptionForHR(hr);
        return registered;
    }
}
'@ -ErrorAction Stop
    }
    return [bool][NoIDPrivacyMdmRegistrationInspector]::IsRegistered()
}

function Get-PrivacyManagementState {
    <#
    .SYNOPSIS
        Detects policy-controller ownership for Privacy policies and services.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $errors = [System.Collections.Generic.List[string]]::new()
    $domainKnown = $false
    $domainJoined = $false
    try {
        $computers = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
        if ($computers.Count -ne 1 -or $null -eq $computers[0] -or
            -not $computers[0].PSObject.Properties['PartOfDomain'] -or
            $computers[0].PartOfDomain -isnot [bool]) {
            throw 'Win32_ComputerSystem returned incomplete or ambiguous domain-membership evidence.'
        }
        $computer = $computers[0]
        $domainJoined = [bool]$computer.PartOfDomain
        $domainKnown = $true
    }
    catch { $errors.Add("Domain-join query failed: $($_.Exception.Message)") }

    $mdmKnown = $false
    $mdmRegistered = $false
    try {
        $mdmRegistered = Test-PrivacyMdmRegistration
        $mdmKnown = $true
    }
    catch { $errors.Add("MDM-registration query failed: $($_.Exception.Message)") }

    $stateKnown = ($domainKnown -and $mdmKnown)
    if (-not $stateKnown -and (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        Write-Log -Level WARNING -Message "Device management could not be checked. Privacy policies, services and tasks will remain unchanged: $($errors -join '; ')" -Module 'Privacy'
    }
    return [PSCustomObject]@{
        StateKnown = $stateKnown
        DomainJoinKnown = $domainKnown
        MdmRegistrationKnown = $mdmKnown
        DomainJoined = $domainJoined
        MdmRegistered = [bool]$mdmRegistered
        # Unknown ownership never grants permission to replace policy-controller
        # settings. Non-policy user preferences remain available.
        ExternallyManaged = (-not $stateKnown) -or $domainJoined -or [bool]$mdmRegistered
        QueryErrors = @($errors)
    }
}
