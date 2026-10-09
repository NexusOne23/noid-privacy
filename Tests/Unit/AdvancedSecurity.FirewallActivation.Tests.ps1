#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallRules.ps1')
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module)
        $null = $Level, $Message, $Module
    }
}

Describe 'AdvancedSecurity waits for complete active firewall verification' {
    BeforeEach {
        $script:Definition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        $script:Reads = 0
        Mock Start-Sleep {}
        Mock Write-Log {}
    }

    It 'returns immediately when the first complete verification passes' {
        Mock Test-AdvancedSecurityFirewallRuleDefinition {
            [pscustomobject]@{ Compliant=$true; Mismatches=@() }
        }
        (Wait-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition).Compliant | Should -BeTrue
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'requires a fresh complete verification after <Pending> becomes visible' -TestCases @(
        @{ Pending='a rule missing from ActiveStore' },
        @{ Pending='filters still being replaced' },
        @{ Pending='enforcement not yet established' }
    ) {
        param($Pending)
        $script:Pending = $Pending
        Mock Test-AdvancedSecurityFirewallRuleDefinition {
            $script:Reads++
            [pscustomobject]@{
                Compliant=($script:Reads -eq 3)
                Mismatches=$(if ($script:Reads -lt 3) { @($script:Pending) } else { @() })
            }
        }
        $result = Wait-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition
        $result.Compliant | Should -BeTrue
        $result.Mismatches | Should -BeNullOrEmpty
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 3 -Exactly -ParameterFilter {
            $Definition -eq $script:Definition -and -not $PSBoundParameters.ContainsKey('RuleSet') -and
                -not $PSBoundParameters.ContainsKey('FilterCache')
        }
        Should -Invoke Start-Sleep -Times 2 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'retains the final failure after bounded reads: <Failure>' -TestCases @(
        @{ Failure='missing rule' }, @{ Failure='restricted package scope' },
        @{ Failure='disabled profile' }, @{ Failure='missing WFP enforcement' }
    ) {
        param($Failure)
        $script:Failure = $Failure
        Mock Test-AdvancedSecurityFirewallRuleDefinition {
            [pscustomobject]@{ Compliant=$false; Mismatches=@($script:Failure) }
        }
        $result = Wait-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition
        $result.Compliant | Should -BeFalse
        $result.Mismatches | Should -Be @($Failure)
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 5 -Exactly
        Should -Invoke Start-Sleep -Times 4 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'does not hide unexpected verifier failures behind polling' {
        Mock Test-AdvancedSecurityFirewallRuleDefinition { throw 'Unexpected verifier failure' }
        { Wait-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition } |
            Should -Throw '*Unexpected verifier failure*'
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
}
