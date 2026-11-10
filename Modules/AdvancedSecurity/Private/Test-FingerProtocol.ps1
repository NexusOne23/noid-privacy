function Test-FingerProtocol {
    <#
    .SYNOPSIS
        Test if Finger Protocol (TCP 79) is blocked

    .DESCRIPTION
        Verifies the exact module-owned Windows Firewall rule blocking outbound
        TCP port 79. No broader malware-prevention conclusion is inferred.

    .OUTPUTS
        PSCustomObject with compliance result
    #>
    [CmdletBinding()]
    param()

    try {
        $definitions = @(Get-AdvancedSecurityFirewallDefinitions -Feature Finger)
        if ($definitions.Count -ne 1) { throw "Expected one canonical Finger firewall rule, found $($definitions.Count)" }
        $verification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definitions[0]
        $compliant = [bool]$verification.Compliant
        $status = if ($compliant) { 'Finger Protocol blocked (exact outbound TCP 79 rule)' } else { 'Mismatch: ' + ($verification.Mismatches -join '; ') }

        return [PSCustomObject]@{
            Feature   = "Finger Protocol Block"
            Compliant = $compliant
            Status    = $status
            Details   = "Rule: $($definitions[0].Name)"
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature   = "Finger Protocol Block"
            Compliant = $false
            Status    = "Error checking: $($_.Exception.Message)"
            Details   = $null
        }
    }
}
