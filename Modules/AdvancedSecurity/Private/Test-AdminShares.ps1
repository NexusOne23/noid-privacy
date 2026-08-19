function Test-AdminShares {
    <#
    .SYNOPSIS
        Test administrative shares compliance

    .DESCRIPTION
        Checks if administrative shares (C$, ADMIN$, etc.) are disabled

    .EXAMPLE
        Test-AdminShares
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipFirewallChecks
    )

    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

        $result = [PSCustomObject]@{
            Feature = "Admin Shares"
            Status = "Unknown"
            Details = @()
            AutoShareWks = $null
            AutoShareServer = $null
            ActiveShares = @()
            Compliant = $false
            FirewallCheckState = $(if ($SkipFirewallChecks) { 'NotChecked' } else { 'Checked' })
            FirewallRuleExact = $null
        }

        # Check registry settings
        if (Test-Path $regPath) {
            $lanmanKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
            $result.AutoShareWks = if ($lanmanKey.GetValueNames() -contains 'AutoShareWks') { $lanmanKey.GetValue('AutoShareWks') } else { $null }
            $result.AutoShareServer = if ($lanmanKey.GetValueNames() -contains 'AutoShareServer') { $lanmanKey.GetValue('AutoShareServer') } else { $null }

            if ($lanmanKey.GetValueNames() -contains 'AutoShareWks' -and
                $lanmanKey.GetValueKind('AutoShareWks').ToString() -eq 'DWord' -and
                [int]$result.AutoShareWks -eq 0 -and
                $lanmanKey.GetValueNames() -contains 'AutoShareServer' -and
                $lanmanKey.GetValueKind('AutoShareServer').ToString() -eq 'DWord' -and
                [int]$result.AutoShareServer -eq 0) {
                $policyExact = $true
                $result.Details += "Registry: AutoShareWks = 0, AutoShareServer = 0 (Disabled)"
            }
            else {
                $policyExact = $false
                $result.Details += "Registry: AutoShareWks = $($result.AutoShareWks), AutoShareServer = $($result.AutoShareServer)"
            }
        }
        else { $policyExact = $false }

        # Check for active admin shares (requires LanmanServer service)
        $serverServiceMatches = @(Get-Service -ErrorAction Stop | Where-Object { [string]$_.Name -eq 'LanmanServer' })
        if ($serverServiceMatches.Count -gt 1) { throw 'LanmanServer service identity is ambiguous' }
        $serverService = if ($serverServiceMatches.Count -eq 1) { $serverServiceMatches[0] } else { $null }
        if (-not $serverService -or $serverService.Status -ne 'Running') {
            # Server service is stopped/disabled - admin shares are effectively disabled
            $result.Details += "LanmanServer service is not running (admin shares cannot exist)"
            $adminShares = @()
        }
        else {
            $adminShares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -match '^(?i:[A-Z]\$|ADMIN\$)$' })
        }
        $result.ActiveShares = $adminShares | Select-Object -ExpandProperty Name

        if (-not $SkipFirewallChecks) {
            $firewallDefinition = @(Get-AdvancedSecurityFirewallDefinitions -Feature AdminShares)
            if ($firewallDefinition.Count -ne 1) { throw "Expected one canonical admin-share firewall rule, found $($firewallDefinition.Count)" }
            $firewallVerification = Test-AdvancedSecurityFirewallRuleDefinition -Definition $firewallDefinition[0]
            $result.FirewallRuleExact = [bool]$firewallVerification.Compliant
            if (-not $result.FirewallRuleExact) {
                $result.Details += "Firewall mismatch: $($firewallVerification.Mismatches -join '; ')"
            }
        }
        $firewallRequirementMet = $SkipFirewallChecks -or [bool]$result.FirewallRuleExact

        if ($adminShares.Count -eq 0) {
            $result.Details += "No system-managed drive/ADMIN$ shares are active"

            if ($policyExact -and $firewallRequirementMet) {
                $result.Status = "Secure"
                $result.Compliant = $true
            }
            else {
                $result.Status = "Partially Secure"
                $result.Compliant = $false
                $result.Details += "WARNING: Shares are absent but the exact automatic-share policy is not configured"
            }
        }
        else {
            # Shares are present, check if Registry is configured to disable them
            if ($policyExact -and $firewallRequirementMet) {
                # Config is correct, just needs a reboot
                $result.Status = "Pending Reboot"
                $result.Compliant = $true
                $result.Details += "Active system-managed shares: $($adminShares.Name -join ', ') (policy becomes effective after reboot)"
            }
            else {
                # Config is NOT correct
                $result.Status = "Insecure"
                $result.Compliant = $false
                $result.Details += "Active admin shares: $($adminShares.Name -join ', ')"
            }
        }

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test admin shares: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature = "Admin Shares"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
