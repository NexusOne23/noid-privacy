#Requires -Version 5.1

# Read-only runtime evidence, separate from the declared policy-check counters.
# Microsoft documents these fields and current-boot WinInit event 12 at:
# https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
# https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
function Get-SecurityBaselineRuntimeStatus {
    [CmdletBinding()]
    param()

    $features = @(
        [pscustomobject]@{ Id='VBS'; Name='VBS'; State='Unavailable'; Label='Could not read'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='HVCI'; Name='Memory integrity (HVCI)'; State='Unavailable'; Label='Could not read'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='CredentialGuard'; Name='Credential Guard'; State='Unavailable'; Label='Could not read'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='SecureLaunch'; Name='Secure Launch'; State='Unavailable'; Label='Could not read'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='KernelStack'; Name='Kernel stack protection'; State='Unavailable'; Label='Could not read'; EvidenceSource='Win32_DeviceGuard' }
        [pscustomobject]@{ Id='LSA'; Name='LSA protection'; State='Unavailable'; Label='Could not read'; EvidenceSource='CurrentBootWinInit12' }
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
        $serviceIds = @(2,1,3,5)
        for ($index = 1; $index -le 4; $index++) {
            $active = $serviceIds[$index - 1] -in $running
            $features[$index].State = if ($active) { 'Running' } else { 'NotRunning' }
            $features[$index].Label = if ($active) { 'Running' } else { 'Not running' }
        }
        if (6 -in $running -and 5 -notin $running) {
            $features[4].State = 'Audit'
            $features[4].Label = 'Audit mode'
        }
    }
    catch {
        # No raw exception text: it can contain machine or account identifiers.
        # Missing/invalid evidence stays unavailable, never disabled or passed.
        foreach ($feature in $features[0..4]) {
            $feature.State = 'Unavailable'
            $feature.Label = 'Could not read'
        }
    }

    $bootTimeUtc = $null
    try {
        $os = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop)
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
    }
    catch {
        # Keep LSA evidence unavailable independently of Device Guard evidence.
        $features[5].State = 'Unavailable'
        $features[5].Label = 'Could not read'
    }

    [pscustomobject]@{
        ObservedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        BootTimeUtc = $bootTimeUtc
        Features = $features
        Notice = 'Passed policy checks confirm configuration; runtime protection is shown separately.'
        Guidance = 'For newly applied protection, restart Windows and verify again. If it remains inactive, check hardware, drivers and Windows edition requirements.'
    }
}
