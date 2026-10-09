#Requires -Version 5.1

function Test-DNSKeepDecision {
    <#
    .SYNOPSIS
        Resolves the canonical DNS no-takeover decision from Apply config or
        durable intent without conflating their different schemas.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object]$FrameworkConfig,

        [AllowNull()]
        [object]$DnsIntent
    )

    function Get-OptionalPropertyValue {
        param(
            [AllowNull()][object]$InputObject,
            [Parameter(Mandatory)][string]$Name
        )
        if ($null -eq $InputObject) { return $null }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    $modules = Get-OptionalPropertyValue -InputObject $FrameworkConfig -Name 'modules'
    $dnsConfig = Get-OptionalPropertyValue -InputObject $modules -Name 'DNS'
    $configProvider = [string](Get-OptionalPropertyValue -InputObject $dnsConfig -Name 'provider')

    # Config validation intentionally stores REQUIRE/ALLOW even for KEEP. The
    # module ignores that dormant choice and emits canonical KEEP/KEEP intent.
    $configKeepsDns = ($configProvider -ceq 'KEEP')
    $intentProvider = [string](Get-OptionalPropertyValue -InputObject $DnsIntent -Name 'provider')
    $intentDohMode = [string](Get-OptionalPropertyValue -InputObject $DnsIntent -Name 'dohMode')
    $intentKeepsDns = ($intentProvider -ceq 'KEEP' -and $intentDohMode -ceq 'KEEP')

    return [bool]($configKeepsDns -or $intentKeepsDns)
}
