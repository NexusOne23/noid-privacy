function Get-AdvancedSecurityComputerSystem {
    <#
    .SYNOPSIS
        Reads authoritative domain membership before planning or changing remote access.
    #>
    [CmdletBinding()]
    param()

    $instances = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
    if ($instances.Count -ne 1 -or $null -eq $instances[0] -or
        -not $instances[0].PSObject.Properties['PartOfDomain'] -or
        $instances[0].PartOfDomain -isnot [bool]) {
        throw 'AdvancedSecurity domain-membership evidence must contain exactly one computer system with a native Boolean PartOfDomain value'
    }
    return $instances[0]
}
