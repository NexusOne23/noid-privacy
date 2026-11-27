#Requires -Version 5.1

# Read-only runtime evidence, separate from the declared policy-check counters.
# Microsoft documents these fields and current-boot WinInit event 12 at:
# https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
# https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
#
# A protection that is not running is named as "requirement not met" only on
# positive evidence that this PC lacks a documented requirement:
# - Credential Guard is licensed for Windows Enterprise and Education
#   (https://learn.microsoft.com/windows/security/identity-protection/credential-guard/),
#   read from the documented product SKU of a Home or Pro edition.
# - Kernel-mode Hardware-enforced Stack Protection needs a processor with
#   shadow stacks (Intel CET, AMD Zen 3 and newer;
#   https://learn.microsoft.com/windows-server/security/kernel-mode-hardware-stack-protection),
#   read from Windows' own answer whether hardware-enforced stack protection
#   is available (IsUserCetAvailableInEnvironment).
# An unknown edition or an answer that cannot be obtained leaves "Not running".
function Get-SecurityBaselineStackProtectionAvailability {
    <#
    .SYNOPSIS
        Windows' answer whether hardware-enforced stack protection is available.
    .OUTPUTS
        $true or $false from the documented Win32 query; $null when the query
        cannot be made on this Windows build.
    #>
    [CmdletBinding()]
    [OutputType([Nullable[bool]])]
    param()

    try {
        if (-not ('NoIDPrivacy.StackProtectionQuery' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace NoIDPrivacy
{
    public static class StackProtectionQuery
    {
        // sysinfoapi.h; USER_CET_ENVIRONMENT_WIN32_PROCESS is 0.
        [DllImport("kernel32.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsUserCetAvailableInEnvironment(UInt32 userCetEnvironment);
    }
}
'@
        }
        return [bool][NoIDPrivacy.StackProtectionQuery]::IsUserCetAvailableInEnvironment([uint32]0)
    }
    catch {
        return $null
    }
}

function Get-SecurityBaselineRuntimeStatus {
    [CmdletBinding()]
    param()

    $features = @(
        [pscustomobject]@{ Id='VBS'; Name='VBS'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='HVCI'; Name='Memory integrity (HVCI)'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='CredentialGuard'; Name='Credential Guard'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='SecureLaunch'; Name='Secure Launch'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='KernelStack'; Name='Kernel stack protection'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='LSA'; Name='LSA protection'; State='Unavailable'; Label='Could not read'; LabelId='Unavailable'; EvidenceSource='CurrentBootWinInit12' }
    )
    try {
        # Do not substitute an MDM bridge query: observation must not process
        # or materialize policy. Only the documented read-only runtime class.
        $guard = @(Get-CimInstance -ClassName Win32_DeviceGuard `
                -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop)
        if ($guard.Count -ne 1) { throw 'Ambiguous Device Guard result' }
        $vbs = $guard[0].VirtualizationBasedSecurityStatus
        $running = @($guard[0].SecurityServicesRunning)
        foreach ($value in @($vbs) + $running) {
            if ($null -eq $value -or $value -is [bool] -or
                $value -isnot [ValueType] -or $value -is [char] -or
                [decimal]$value -lt 0 -or [decimal]$value -gt [uint32]::MaxValue -or
                [decimal]$value -ne [math]::Truncate([decimal]$value)) {
                throw 'Invalid Device Guard runtime value'
            }
        }
        if ($vbs -notin @(0,1,2) -or $running.Count -eq 0 -or
            (0 -in $running -and $running.Count -gt 1) -or
            ($vbs -ne 2 -and (1 -in $running -or 2 -in $running))) {
            throw 'Incomplete or inconsistent Device Guard runtime evidence'
        }
        $features[0].State = if ($vbs -eq 2) { 'Running' } else { 'NotRunning' }
        $features[0].Label = switch ($vbs) { 0 { 'Not running' }; 1 { 'Enabled, not running' }; 2 { 'Running' } }
        # Stable ids let the HTML report translate the label it shows.
        $features[0].LabelId = switch ($vbs) { 0 { 'NotRunning' }; 1 { 'EnabledNotRunning' }; 2 { 'Running' } }
        $serviceIds = @(2,1,3,5)
        for ($index = 1; $index -le 4; $index++) {
            $active = $serviceIds[$index - 1] -in $running
            $features[$index].State = if ($active) { 'Running' } else { 'NotRunning' }
            $features[$index].Label = if ($active) { 'Running' } else { 'Not running' }
            $features[$index].LabelId = if ($active) { 'Running' } else { 'NotRunning' }
        }
        if (6 -in $running -and 5 -notin $running) {
            $features[4].State = 'Audit'
            $features[4].Label = 'Audit mode'
            $features[4].LabelId = 'Audit'
        }
    }
    catch {
        # No raw exception text: it can contain machine or account identifiers.
        # Missing/invalid evidence stays unavailable, never disabled or passed.
        foreach ($feature in $features[0..4]) {
            $feature.State = 'Unavailable'
            $feature.Label = 'Could not read'
            $feature.LabelId = 'Unavailable'
        }
    }

    # One operating-system query serves the edition evidence and the boot time.
    $os = @()
    try {
        $os = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop)
    }
    catch {
        $os = @()
    }

    # Documented requirements this PC observably does not meet. The product SKU
    # uses the GetProductInfo PRODUCT_* identifiers of the Home and Pro families
    # (the same lists as Get-WindowsEditionInfo); any other or unreadable SKU
    # makes no statement.
    if ($features[2].State -eq 'NotRunning' -and $os.Count -eq 1) {
        $sku = $os[0].PSObject.Properties['OperatingSystemSKU']
        $homeAndProSkus = @(2, 3, 5, 26, 98, 99, 100, 101, 6, 16, 48, 49, 103, 161, 162, 164)
        if ($null -ne $sku -and $null -ne $sku.Value -and $sku.Value -isnot [bool] -and
            $sku.Value -is [ValueType] -and $sku.Value -isnot [char] -and
            [decimal]$sku.Value -in $homeAndProSkus) {
            $features[2].State = 'RequirementNotMet'
            $features[2].Label = 'Needs Windows Enterprise or Education'
            $features[2].LabelId = 'NeedsEnterpriseEdition'
            $features[2].EvidenceSource = 'Win32_OperatingSystem.OperatingSystemSKU'
        }
    }
    if ($features[4].State -eq 'NotRunning' -and
        (Get-SecurityBaselineStackProtectionAvailability) -eq $false) {
        $features[4].State = 'RequirementNotMet'
        $features[4].Label = 'Not available on this processor'
        $features[4].LabelId = 'NoProcessorSupport'
        $features[4].EvidenceSource = 'IsUserCetAvailableInEnvironment'
    }

    $bootTimeUtc = $null
    try {
        if ($os.Count -ne 1 -or $os[0].LastBootUpTime -isnot [datetime]) {
            throw 'Current Windows boot time unavailable'
        }
        $boot = $os[0].LastBootUpTime
        if ($boot -gt (Get-Date)) { throw 'Windows boot time is in the future' }
        $bootTimeUtc = $boot.ToUniversalTime().ToString('o')
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                    LogName='System'; ProviderName='Microsoft-Windows-Wininit'
                    Id=12; StartTime=$boot
                } -MaxEvents 1 -ErrorAction Stop)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        }
        # Retain only the attestation, never the event message or payload.
        $protected = @($events | Where-Object {
                $_.Id -eq 12 -and $_.ProviderName -eq 'Microsoft-Windows-Wininit' -and
                $_.TimeCreated -is [datetime] -and $_.TimeCreated -ge $boot
            }).Count -gt 0
        $features[5].State = if ($protected) { 'ProtectedAtBoot' } else { 'NoEvidence' }
        $features[5].Label = if ($protected) { 'Protected at this boot' } else { 'No current-boot evidence' }
        $features[5].LabelId = if ($protected) { 'ProtectedAtBoot' } else { 'NoEvidence' }
    }
    catch {
        # Keep LSA evidence unavailable independently of Device Guard evidence.
        $features[5].State = 'Unavailable'
        $features[5].Label = 'Could not read'
        $features[5].LabelId = 'Unavailable'
    }

    [pscustomobject]@{
        ObservedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        BootTimeUtc = $bootTimeUtc
        Features = $features
        Notice = 'Passed policy checks confirm configuration; runtime protection is shown separately.'
        NoticeId = 'RuntimeNotice'
        GuidanceId = 'RuntimeGuidance'
        Guidance = 'For newly applied protection, restart Windows and verify again. If it remains inactive, check hardware, drivers and Windows edition requirements.'
    }
}
