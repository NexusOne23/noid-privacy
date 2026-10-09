#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/QuickActions.ps1')
}

Describe 'Named firewall queries distinguish absence from unavailable evidence' -Skip:($env:OS -ne 'Windows_NT') {
    It 'accepts only the native missing-name errors as absence: <Identity>' -TestCases @(
        @{Identity='InstanceID'}, @{Identity='Name'}
    ) {
        param($Identity)
        $null=$Identity # Referenced inside Pester's dynamically executed mock.
        Mock Get-NetFirewallRule {
            Write-Error -ErrorRecord ([Management.Automation.ErrorRecord]::new(
                [Exception]::new('No matching rule'),
                ('CmdletizationQuery_NotFound_'+$Identity+',Get-NetFirewallRule'),
                [Management.Automation.ErrorCategory]::ObjectNotFound, $Name))
        }
        @(Get-QuickActionFirewallRuleQuery -Names @('NoID-Block-SSDP-UDP-1900')).Count | Should -Be 0
    }

    It 'rejects <Fault> instead of returning a false empty or partial inventory' -TestCases @(
        @{Fault='access denied';Category='PermissionDenied';Id='WindowsSystemError,Get-NetFirewallRule'},
        @{Fault='an unavailable provider';Category='ObjectNotFound';Id='CimClassNotFound,Get-NetFirewallRule'},
        @{Fault='a partial read';Category='ReadError';Id='WindowsSystemError,Get-NetFirewallRule'}
    ) {
        param($Fault,$Category,$Id)
        $null=$Fault,$Category,$Id # Category/Id are read inside the mock.
        Mock Get-NetFirewallRule {
            [pscustomobject]@{Name='NoID-Block-SSDP-UDP-1900'}
            Write-Error -ErrorRecord ([Management.Automation.ErrorRecord]::new(
                [Exception]::new('Injected native failure'), $Id,
                [Management.Automation.ErrorCategory]$Category, $Name))
        }
        { Get-QuickActionFirewallRuleQuery -Names @('NoID-Block-SSDP-UDP-1900') } | Should -Throw '*state is unknown*'
    }
}

Describe 'Quick Action firewall ownership checks every declared scope' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:ScopeDefinition = @(Get-AdvancedSecurityFirewallDefinitions -Feature RiskyPorts |
                Where-Object Name -eq 'NoID-Block-SSDP-UDP-1900')[0]
        $d=$script:ScopeDefinition
        $script:ScopeRule = [pscustomobject]@{
            Name=$d.Name; InstanceID=$d.Name; Group=''; PolicyStoreSourceType='Local'
            DisplayName=$d.DisplayName; Description=$d.Description
            Enabled='True'; Direction='Inbound'; Action='Block'; Profile='Any'; EdgeTraversalPolicy='Block'
            Owner=$null; PackageFamilyName=$null; Platforms=@(); PolicyAppId=$null; RemoteDynamicKeywordAddresses=@()
        }
        $script:ScopeFilters = @{
            Port=[pscustomobject]@{Protocol='UDP';LocalPort='1900';RemotePort='Any'}
            Address=[pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'}
            Application=[pscustomobject]@{Program='Any';Package=''}
            Service=[pscustomobject]@{Service='Any'}
            Interface=[pscustomobject]@{InterfaceAlias='Any'}
            InterfaceType=[pscustomobject]@{InterfaceType='Any'}
            Security=[pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules='False';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}
        }
        Mock Get-QuickActionNamedFirewallRules {
            if ($Name -ceq $script:ScopeRule.Name) { $script:ScopeRule }
        }
        Mock Get-NetFirewallPortFilter { $script:ScopeFilters.Port } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallAddressFilter { $script:ScopeFilters.Address } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallApplicationFilter { $script:ScopeFilters.Application } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallServiceFilter { $script:ScopeFilters.Service } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallInterfaceFilter { $script:ScopeFilters.Interface } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallInterfaceTypeFilter { $script:ScopeFilters.InterfaceType } -RemoveParameterType AssociatedNetFirewallRule
        Mock Get-NetFirewallSecurityFilter { $script:ScopeFilters.Security } -RemoveParameterType AssociatedNetFirewallRule
        Mock New-NetFirewallRule { throw 'Unexpected mutation' }
        Mock Remove-NetFirewallRule { throw 'Unexpected mutation' }
        Mock Set-AdvancedSecurityFirewallRuleDefinition { throw 'Unexpected mutation' }
    }

    It 'continues to read the exact <Description> rule without changing its serialized state' -TestCases @(
        @{Description='module'}, @{Description='historical Quick Action'}
    ) {
        param($Description)
        if ($Description -eq 'historical Quick Action') { $script:ScopeRule.Description='NoID Privacy Quick Action v1' }
        $state=Get-QuickActionNamedFirewallState UPnP
        $state.rules[0].canonical | Should -BeTrue
        $state.rules[0].store | Should -BeExactly 'Local'
        @($state.rules[0].PSObject.Properties.Name) | Should -Be @('name','exists','canonical','store','displayName','protocol','localPort')
        $state.rules[0].name | Should -BeExactly 'NoID-Block-SSDP-UDP-1900'
        $state.rules[1].exists | Should -BeFalse
    }

    It 'rejects <Fault> and does not partially create or remove another rule' -TestCases @(
        @{Fault='foreign description'}, @{Fault='foreign display name'}, @{Fault='foreign group'},
        @{Fault='address restriction'}, @{Fault='program restriction'}, @{Fault='package restriction'},
        @{Fault='service restriction'}, @{Fault='interface restriction'}, @{Fault='interface type restriction'},
        @{Fault='user restriction'}, @{Fault='authentication requirement'}, @{Fault='edge traversal'},
        @{Fault='policy app identity'}, @{Fault='rule owner'}, @{Fault='package family'},
        @{Fault='platform restriction'}, @{Fault='dynamic address restriction'}, @{Fault='ambiguous filter'}
    ) {
        param($Fault)
        switch ($Fault) {
            'foreign description' { $script:ScopeRule.Description='User rule' }
            'foreign display name' { $script:ScopeRule.DisplayName='User rule' }
            'foreign group' { $script:ScopeRule.Group='User rules' }
            'address restriction' { $script:ScopeFilters.Address.RemoteAddress='LocalSubnet' }
            'program restriction' { $script:ScopeFilters.Application.Program='System' }
            'package restriction' { $script:ScopeFilters.Application.Package='S-1-15-2-1' }
            'service restriction' { $script:ScopeFilters.Service.Service='SSDPSRV' }
            'interface restriction' { $script:ScopeFilters.Interface.InterfaceAlias='TestInterface' }
            'interface type restriction' { $script:ScopeFilters.InterfaceType.InterfaceType='Wireless' }
            'user restriction' { $script:ScopeFilters.Security.LocalUser='D:(A;;CC;;;BA)' }
            'authentication requirement' { $script:ScopeFilters.Security.Authentication='Required' }
            'edge traversal' { $script:ScopeRule.EdgeTraversalPolicy='Allow' }
            'policy app identity' { $script:ScopeRule.PolicyAppId='RestrictedApp' }
            'rule owner' { $script:ScopeRule.Owner='S-1-5-18' }
            'package family' { $script:ScopeRule.PackageFamilyName='Example.Package' }
            'platform restriction' { $script:ScopeRule.Platforms=@('10.0') }
            'dynamic address restriction' { $script:ScopeRule.RemoteDynamicKeywordAddresses=@('{11111111-2222-3333-4444-555555555555}') }
            'ambiguous filter' { $script:ScopeFilters.Address=@($script:ScopeFilters.Address,$script:ScopeFilters.Address) }
        }
        (Get-QuickActionNamedFirewallState UPnP).rules[0].canonical | Should -BeFalse
        { Set-QuickActionNamedFirewallRules UPnP -Present:$true -Confirm:$false } | Should -Throw '*noncanonical*'
        { Set-QuickActionNamedFirewallRules UPnP -Present:$false -Confirm:$false } | Should -Throw '*noncanonical*'
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
        Should -Invoke Set-AdvancedSecurityFirewallRuleDefinition -Times 0 -Exactly
    }

    It 'does not turn a native read failure into a canonical rule' {
        Mock Get-NetFirewallAddressFilter { throw 'Native read unavailable' }
        { Get-QuickActionNamedFirewallState UPnP } | Should -Throw '*unavailable*'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'requires an explicit snapshot for configuration-only inspection' {
        { Test-AdvancedSecurityFirewallRuleDefinition $script:ScopeDefinition -ConfigurationOnly } |
            Should -Throw '*explicit native rule and filter snapshot*'
    }
}
