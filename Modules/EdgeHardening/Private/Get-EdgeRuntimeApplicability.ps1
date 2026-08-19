#Requires -Version 5.1

function Test-EdgeMdmRegistration {
    <#
    .SYNOPSIS
        Query Windows' documented MDM registration API without collecting UPN.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not ('NoIDMdmRegistrationInspector' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NoIDMdmRegistrationInspector
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

    return [bool][NoIDMdmRegistrationInspector]::IsRegistered()
}

function Get-EdgeRuntimeApplicability {
    <#
    .SYNOPSIS
        Resolve the documented managed-Windows prerequisite for Edge policies.

    .DESCRIPTION
        Four Edge SmartScreen policies are available only to an AD-domain
        joined Windows device or a Pro/Enterprise device registered with an MDM
        service. Domain state comes from Win32_ComputerSystem and MDM state from
        IsDeviceRegisteredWithManagement in MDMRegistration.dll. Both queries
        fail closed; registry writability is never used as applicability proof.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $editionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $editionId = [string]$editionKey.GetValue('EditionID', '')
    $sku = [int]$os.OperatingSystemSKU

    $homeSkus = @(2, 3, 5, 26, 98, 99, 100, 101)
    $professionalSkus = @(6, 16, 48, 49, 103, 161, 162, 164)
    $enterpriseSkus = @(4, 27, 70, 72, 84, 125, 126, 129, 130, 175)
    $educationSkus = @(121, 122)
    $iotEnterpriseSkus = @(188, 191)
    $family = if ($sku -in $homeSkus) { 'Home' }
        elseif ($sku -in $professionalSkus) { 'Professional' }
        elseif ($sku -in $enterpriseSkus) { 'Enterprise' }
        elseif ($sku -in $educationSkus) { 'Education' }
        elseif ($sku -in $iotEnterpriseSkus) { 'IoTEnterprise' }
        elseif ($editionId -match '^Core') { 'Home' }
        elseif ($editionId -match '^Professional') { 'Professional' }
        elseif ($editionId -match '^Enterprise') { 'Enterprise' }
        elseif ($editionId -match '^Education') { 'Education' }
        elseif ($editionId -match '^IoTEnterprise') { 'IoTEnterprise' }
        else { 'Unknown' }
    if ($family -eq 'Unknown') {
        throw "Unsupported or unknown Edge edition applicability: SKU=$sku, EditionID='$editionId'"
    }

    $domainJoined = [bool]$computer.PartOfDomain
    $mdmRegistered = Test-EdgeMdmRegistration
    $mdmEditionEligible = $family -in @('Professional', 'Enterprise')
    $managedWindowsEligible = $domainJoined -or ($mdmRegistered -and $mdmEditionEligible)
    $source = if ($domainJoined) { 'ActiveDirectoryDomainJoin' }
        elseif ($mdmRegistered -and $mdmEditionEligible) { 'WindowsMdmRegistrationApi' }
        elseif ($mdmRegistered) { 'MdmRegisteredButEditionIneligible' }
        else { 'UnmanagedWindows' }

    return [PSCustomObject]@{
        SchemaVersion          = 1
        EditionFamily         = $family
        OperatingSystemSKU    = $sku
        EditionID              = $editionId
        DomainJoined           = $domainJoined
        MdmRegistered          = [bool]$mdmRegistered
        MdmEditionEligible     = $mdmEditionEligible
        ManagedWindowsEligible = $managedWindowsEligible
        EvidenceSource         = $source
    }
}
