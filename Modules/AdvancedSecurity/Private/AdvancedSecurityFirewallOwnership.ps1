#Requires -Version 5.1

function Test-AdvancedSecurityOwnedFirewallConfiguration {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Rule
    )

    # A known name alone never authorizes deleting a customized/foreign rule.
    # Legacy Quick Actions used a different description but the same scope.
    if ([string]$Rule.Description -cnotin @([string]$Definition.Description, 'NoID Privacy Quick Action v1')) {
        return $false
    }
    $expected = $Definition.PSObject.Copy()
    $expected.Name = [string]$Rule.Name
    $expected.Description = [string]$Rule.Description
    $cache = @{}
    foreach ($set in @(
        @{ Key='Port'; Values=@($Rule | Get-NetFirewallPortFilter -ErrorAction Stop) },
        @{ Key='Address'; Values=@($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop) },
        @{ Key='Application'; Values=@($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop) },
        @{ Key='Service'; Values=@($Rule | Get-NetFirewallServiceFilter -ErrorAction Stop) },
        @{ Key='Interface'; Values=@($Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop) },
        @{ Key='InterfaceType'; Values=@($Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop) },
        @{ Key='Security'; Values=@($Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop) }
    )) {
        $cache[$set.Key] = @{ ([string]$Rule.InstanceID) = @($set.Values) }
    }
    $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $expected `
        -RuleSet @($Rule) -FilterCache $cache -ConfigurationOnly
    return [bool]$verification.Compliant
}
