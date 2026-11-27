#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallRules.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallWfp.ps1')
}

Describe 'AdvancedSecurity verifies active firewall protection' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:Definition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        # Native association cmdlets bind only CimInstance pipeline objects,
        # including when Pester mocks their transport. This client-only object
        # never creates a provider class or changes a live firewall rule.
        $script:Rule = New-CimInstance -Namespace root/standardcimv2 `
            -ClassName MSFT_NetFirewallRule -ClientOnly -Property @{
            InstanceID=$script:Definition.Name
            DisplayName=$script:Definition.DisplayName; Description=$script:Definition.Description
            Enabled=[uint16]1; Direction=[uint16]2; Action=[uint16]4; Profiles=[uint16]0
            EnforcementStatus=[uint16[]]@(5, 1); PolicyStoreSourceType=[uint16]1
        }
        $script:Filters = @{
            Port = @{ Protocol='TCP'; RemotePort='79'; LocalPort='Any' }
            Address = @{ LocalAddress='Any'; RemoteAddress='Any' }
            Application = @{ Program='Any'; Package='' }
            Service = @{ Service='Any' }
            Interface = @{ InterfaceAlias='Any' }
            InterfaceType = @{ InterfaceType='Any' }
            Security = @{ Authentication='NotRequired'; Encryption='NotRequired'; OverrideBlockRules='False'; LocalUser='Any'; RemoteUser='Any'; RemoteMachine='Any' }
        }
        $script:Cache = @{ Profile=@{}; LocalMergePolicy=@{} }
        foreach ($key in $script:Filters.Keys) {
            $script:Cache[$key] = @{ $script:Rule.InstanceID = [pscustomobject]$script:Filters[$key] }
        }
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $script:Cache.Profile[$name] = [pscustomobject]@{ Name=$name; Enabled='True'; AllowLocalFirewallRules='True' }
            $script:Cache.LocalMergePolicy[$name] = [pscustomobject]@{ Present=$false; Kind=$null; Value=$null }
        }
        Mock Get-AdvancedSecurityFirewallLocalMergePolicy { $script:Cache.LocalMergePolicy }
        Mock Get-NetFirewallRule { throw 'Only ActiveStore may prove protection' }
        Mock Get-NetFirewallRule { $script:Rule } -ParameterFilter { $PolicyStore -ceq 'ActiveStore' }
        Mock Get-NetFirewallProfile { throw 'Only ActiveStore may prove profile state' }
        Mock Get-NetFirewallProfile { $script:Cache.Profile.Values } -ParameterFilter { $PolicyStore -ceq 'ActiveStore' }
        Mock Get-NetFirewallPortFilter { [pscustomobject]$script:Filters.Port }
        Mock Get-NetFirewallAddressFilter { [pscustomobject]$script:Filters.Address }
        Mock Get-NetFirewallApplicationFilter { [pscustomobject]$script:Filters.Application }
        Mock Get-NetFirewallServiceFilter { [pscustomobject]$script:Filters.Service }
        Mock Get-NetFirewallInterfaceFilter { [pscustomobject]$script:Filters.Interface }
        Mock Get-NetFirewallInterfaceTypeFilter { [pscustomobject]$script:Filters.InterfaceType }
        Mock Get-NetFirewallSecurityFilter { [pscustomobject]$script:Filters.Security }
        $script:IndependentProof = $false
        Mock Get-AdvancedSecurityFirewallWfpEvidence { [pscustomobject]@{Collected=$true} }
        Mock Test-AdvancedSecurityFirewallGpoEnforcement { $script:IndependentProof }
    }

    It 'reports <Case> identically through live and cached reads' -TestCases @(
        @{ Case='enabled profiles'; Expected=$true },
        @{ Case='no active network'; Expected=$true },
        @{ Case='disabled Public'; Expected=$false },
        @{ Case='disabled Domain'; Expected=$false },
        @{ Case='disabled Private'; Expected=$false },
        @{ Case='missing profile'; Expected=$false },
        @{ Case='duplicate profile'; Expected=$false },
        @{ Case='local rules disallowed'; Expected=$false },
        @{ Case='unknown merge state'; Expected=$false },
        @{ Case='disabled runtime'; Expected=$false },
        @{ Case='suppressed runtime'; Expected=$false },
        @{ Case='unknown runtime'; Expected=$false },
        @{ Case='missing runtime'; Expected=$false },
        @{ Case='Public rule with disabled Domain'; Expected=$true },
        @{ Case='GPO rule with local merge disabled'; Expected=$true },
        @{ Case='configured merge ban pending restart'; Expected=$false },
        @{ Case='configured merge allowed'; Expected=$true },
        @{ Case='malformed merge policy type'; Expected=$false },
        @{ Case='malformed merge policy value'; Expected=$false },
        @{ Case='Public rule with Domain merge ban'; Expected=$true },
        @{ Case='GPO rule with configured local merge ban'; Expected=$true },
        @{ Case='mixed GPO status with independent proof'; Expected=$true },
        @{ Case='mixed GPO status without independent proof'; Expected=$false },
        @{ Case='mixed GPO status with failed inspection'; Expected=$false },
        @{ Case='mixed GPO status with restricted package'; Expected=$false }
    ) {
        param($Case, $Expected)
        if ($Case -like 'mixed GPO status*') {
            $script:Rule.CimInstanceProperties['PolicyStoreSourceType'].Value=[uint16]2
            $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@(2,5,1)
        }
        switch -Exact ($Case) {
            'mixed GPO status with independent proof' { $script:IndependentProof=$true }
            'mixed GPO status with failed inspection' { Mock Get-AdvancedSecurityFirewallWfpEvidence { throw 'Injected inspection failure' } }
            'mixed GPO status with restricted package' {
                $script:IndependentProof=$true
                $script:Filters.Application.Package='Restricted'
                $script:Cache.Application[$script:Rule.InstanceID].Package='Restricted'
            }
            'no active network' { $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@(5) }
            'disabled Public' { $script:Cache.Profile.Public.Enabled='False' }
            'disabled Domain' { $script:Cache.Profile.Domain.Enabled='False' }
            'disabled Private' { $script:Cache.Profile.Private.Enabled='False' }
            'missing profile' { $script:Cache.Profile.Remove('Public') }
            'duplicate profile' { $script:Cache.Profile.Public=@($script:Cache.Profile.Public, $script:Cache.Profile.Public) }
            'local rules disallowed' { $script:Cache.Profile.Public.AllowLocalFirewallRules='False' }
            'unknown merge state' { $script:Cache.Profile.Public.AllowLocalFirewallRules='NotConfigured' }
            'disabled runtime' { $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@(2, 5) }
            'suppressed runtime' { $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@(16, 5) }
            'unknown runtime' { $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@(65535) }
            'missing runtime' { $script:Rule.CimInstanceProperties['EnforcementStatus'].Value=[uint16[]]@() }
            'Public rule with disabled Domain' {
                $script:Definition.Profile='Public'; $script:Rule.CimInstanceProperties['Profiles'].Value=[uint16]4
                $script:Cache.Profile.Domain.Enabled='False'
            }
            'GPO rule with local merge disabled' {
                $script:Rule.CimInstanceProperties['PolicyStoreSourceType'].Value=[uint16]2
                $script:Cache.Profile.Public.AllowLocalFirewallRules='False'
            }
            'configured merge ban pending restart' {
                $script:Cache.LocalMergePolicy.Public=[pscustomobject]@{Present=$true;Kind='DWord';Value=0}
            }
            'configured merge allowed' {
                $script:Cache.LocalMergePolicy.Public=[pscustomobject]@{Present=$true;Kind='DWord';Value=1}
            }
            'malformed merge policy type' {
                $script:Cache.LocalMergePolicy.Public=[pscustomobject]@{Present=$true;Kind='String';Value='1'}
            }
            'malformed merge policy value' {
                $script:Cache.LocalMergePolicy.Public=[pscustomobject]@{Present=$true;Kind='DWord';Value=2}
            }
            'Public rule with Domain merge ban' {
                $script:Definition.Profile='Public'; $script:Rule.CimInstanceProperties['Profiles'].Value=[uint16]4
                $script:Cache.LocalMergePolicy.Domain=[pscustomobject]@{Present=$true;Kind='DWord';Value=0}
            }
            'GPO rule with configured local merge ban' {
                $script:Rule.CimInstanceProperties['PolicyStoreSourceType'].Value=[uint16]2
                $script:Cache.LocalMergePolicy.Public=[pscustomobject]@{Present=$true;Kind='DWord';Value=0}
            }
        }
        $live = Test-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition
        $cached = Test-AdvancedSecurityFirewallRuleDefinition -Definition $script:Definition `
            -RuleSet @($script:Rule) -FilterCache $script:Cache
        $live.Compliant | Should -Be $Expected -Because ($live.Mismatches -join '; ')
        $cached.Compliant | Should -Be $Expected -Because ($cached.Mismatches -join '; ')
        Should -Invoke Get-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $PolicyStore -ceq 'ActiveStore' }
        Should -Invoke Get-NetFirewallPortFilter -Times 1 -Exactly
        if ($Case -like 'mixed GPO status*' -and $Case -ne 'mixed GPO status with restricted package') {
            Should -Invoke Get-AdvancedSecurityFirewallWfpEvidence -Times 2 -Exactly
        }
        else { Should -Invoke Get-AdvancedSecurityFirewallWfpEvidence -Times 0 -Exactly }
    }
}

Describe 'AdvancedSecurity refuses a firewall layer that local-rule policy blocks' {
    BeforeEach {
        $script:MergePolicy = @{}
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $script:MergePolicy[$name] = [pscustomobject]@{ Present=$false; Kind=$null; Value=$null }
        }
        Mock Get-AdvancedSecurityFirewallLocalMergePolicy { $script:MergePolicy }
    }

    It 'reports no blocked profile when local rules may merge' {
        @(Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $false).Count | Should -Be 0
        $script:MergePolicy.Public = [pscustomobject]@{ Present=$true; Kind='DWord'; Value=1 }
        @(Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $false).Count | Should -Be 0
    }

    It 'reports <Case> on an edition without managed firewall policy' -TestCases @(
        @{ Case='the SecurityBaseline Public merge ban'; Kind='DWord'; Value=0 },
        @{ Case='a non-DWORD merge value'; Kind='String'; Value='0' },
        @{ Case='an out-of-range merge value'; Kind='DWord'; Value=2 }
    ) {
        param($Kind, $Value)
        $script:MergePolicy.Public = [pscustomobject]@{ Present=$true; Kind=$Kind; Value=$Value }
        @(Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $false) | Should -Be @('Public')
    }

    It 'never blocks editions that write the owned rules to the local GPO' {
        $script:MergePolicy.Public = [pscustomobject]@{ Present=$true; Kind='DWord'; Value=0 }
        @(Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $true).Count | Should -Be 0
        Should -Invoke Get-AdvancedSecurityFirewallLocalMergePolicy -Times 0 -Exactly
    }

    It 'stops before backup or any change and recommends skipping in the interactive prompt' {
        $invoke = Get-Content (Join-Path $repo 'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1') -Raw
        $probe = $invoke.IndexOf('Get-AdvancedSecurityLocalRuleBlockedProfile -ManagedPolicySupported $managedPolicySupported', [StringComparison]::Ordinal)
        $refusal = $invoke.IndexOf('if (-not $SkipFirewallLayer -and $localRuleBlockedProfiles.Count -gt 0)', [StringComparison]::Ordinal)
        $decision = $invoke.IndexOf('$null = Write-FirewallControllerRuntimeWarning -FirewallLayerSkipped $SkipFirewallLayer -Detection $firewallControllerStatus', [StringComparison]::Ordinal)
        $backup = $invoke.IndexOf('$backupInit = Initialize-BackupSystem', [StringComparison]::Ordinal)
        $probe | Should -BeGreaterThan 0
        $decision | Should -BeGreaterThan $probe
        $refusal | Should -BeGreaterThan $decision
        $backup | Should -BeGreaterThan $refusal
        $invoke | Should -Match "firewallDefault = if \(\`$firewallControllerStatus\.Detected -or \`$localRuleBlockedProfiles\.Count -gt 0\) \{ 'Y' \}"
    }
}
