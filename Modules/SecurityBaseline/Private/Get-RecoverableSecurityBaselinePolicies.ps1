#Requires -Version 5.1

function Get-RecoverableSecurityBaselinePolicies {
    <#
    .SYNOPSIS
        Build the registry plan without firmware locks or native format metadata.
    .DESCRIPTION
        The hash-bound Microsoft source uses 1 for these four directives.
        NoID Privacy applies the documented enabled-without-UEFI-lock value 2.
        This requests enabled protection but omits firmware persistence that
        registry BAVR cannot reverse. Existing EFI variables are not removed.
        The input/source profile and historical backup artifacts stay intact.
        WindowsFirewall PolicyVersion is the policy-store schema version, not
        a hardening setting. Leave it to the native firewall writer; copying
        the package's 538 (0x021A) would downgrade newer local-GPO metadata.
        This mapping alone does not prove post-reboot runtime restoration;
        see Docs/SECURITY-BASELINE-RECOVERY.md for that evidence boundary.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory)][object[]]$Policies)

    $targets = @(
        @{ Key = '[Software\Policies\Microsoft\Windows\System'; Name = 'RunAsPPL' }
        @{ Key = '[SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL' }
        @{ Key = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags' }
        @{ Key = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'HypervisorEnforcedCodeIntegrity' }
    )
    $indices = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($target in $targets) {
        $matchesForTarget = @(for ($index = 0; $index -lt $Policies.Count; $index++) {
                $policy = $Policies[$index]
                if ([string]$policy.KeyName -ieq $target.Key -and
                    [string]$policy.ValueName -ieq $target.Name) { $index }
            })
        if ($matchesForTarget.Count -ne 1) {
            throw "Expected exactly one firmware protection source directive: $($target.Key)::$($target.Name)"
        }
        $matchedIndex = [int]$matchesForTarget[0]
        $policy = $Policies[$matchedIndex]
        if ([string]$policy.Type -cne 'REG_DWORD' -or [string]$policy.Data -cne '1') {
            throw "Firmware protection source directive must be REG_DWORD 1: $($target.Key)::$($target.Name)"
        }
        $null = $indices.Add($matchedIndex)
    }

    $metadataIndices = @(for ($index = 0; $index -lt $Policies.Count; $index++) {
            if ([string]$Policies[$index].KeyName -ieq '[Software\Policies\Microsoft\WindowsFirewall' -and
                [string]$Policies[$index].ValueName -ieq 'PolicyVersion') { $index }
        })
    if ($metadataIndices.Count -ne 1) { throw 'Expected exactly one firewall policy-format source entry' }
    $metadataIndex = [int]$metadataIndices[0]
    $metadata = $Policies[$metadataIndex]
    if ([string]$metadata.Type -cne 'REG_DWORD' -or
        ($metadata.Data -isnot [int] -and $metadata.Data -isnot [long]) -or $metadata.Data -ne 538) {
        throw 'Firewall policy-format source entry must be REG_DWORD 538; review an upstream format change explicitly'
    }

    # Validate the complete mapping before returning any plan. Copy each record
    # so neither success nor failure rewrites the source object used by callers.
    for ($index = 0; $index -lt $Policies.Count; $index++) {
        if ($index -eq $metadataIndex) { continue }
        $copy = $Policies[$index].PSObject.Copy()
        if ($indices.Contains($index)) { $copy.Data = 2 }
        $copy
    }
}
