#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallRules.ps1')
}

Describe 'AdvancedSecurity native firewall rule scope' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $script:ScopeDefinition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        $script:ScopeDefinition.Name = 'NoID-Firewall-Test-' + [Guid]::NewGuid().ToString('N')
        $script:ScopeRuleCreated = $false
    }

    AfterEach {
        if ($script:ScopeRuleCreated) {
            # The setter replaces the CIM object, so resolve the exact unique
            # name whose creation succeeded, including after a repair failure.
            Get-NetFirewallRule -Name $script:ScopeDefinition.Name -ErrorAction Stop |
                Remove-NetFirewallRule -ErrorAction Stop
        }
    }

    It 'checks <Label> in both live and cached verification' -TestCases @(
        @{Label='unrestricted traffic';Extra=@{};Expected=$true},
        # This is Microsoft's public Package example SID, not a host identity.
        @{Label='one application package';Extra=@{Package='S-1-15-2-4292807980-2381230043-3108820062-1451069988-2614848061-670482394-695399705'};Expected=$false},
        @{Label='local administrators only';Extra=@{LocalUser='D:(A;;CC;;;BA)'};Expected=$false},
        @{Label='one policy app identity';Extra=@{PolicyAppId='NoIDTestScope'};Expected=$false},
        @{Label='one remote address';Extra=@{RemoteAddress='127.0.0.1'};Expected=$false}
    ) {
        param($Label, $Extra, $Expected)
        $null = $Label
        $definition = $script:ScopeDefinition
        $parameters = @{
            Name=$definition.Name; DisplayName=$definition.DisplayName; Description=$definition.Description
            Direction='Outbound'; Protocol='TCP'; RemotePort='79'; Action='Block'
            Enabled='True'; Profile='Any'; ErrorAction='Stop'
        }
        foreach ($key in $Extra.Keys) { $parameters[$key] = $Extra[$key] }
        New-NetFirewallRule @parameters | Out-Null
        $script:ScopeRuleCreated = $true
        $rule = Get-NetFirewallRule -Name $definition.Name -PolicyStore ActiveStore -ErrorAction Stop
        $live = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition
        $cached = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @($rule) `
            -FilterCache (Get-AdvancedSecurityFirewallFilterCache)
        (@($live.Compliant, $cached.Compliant) -join ',') | Should -BeExactly "$Expected,$Expected"
    }

    It 'recreates <Label> as the complete owned port block' -TestCases @(
        @{Label='a package-scoped rule';Extra=@{Package='S-1-15-2-4292807980-2381230043-3108820062-1451069988-2614848061-670482394-695399705'}},
        @{Label='a user-scoped rule';Extra=@{LocalUser='D:(A;;CC;;;BA)'}},
        @{Label='an app-identity-scoped rule';Extra=@{PolicyAppId='NoIDTestScope'}},
        @{Label='an address-scoped rule';Extra=@{RemoteAddress='127.0.0.1'}}
    ) {
        param($Label, $Extra)
        $null = $Label
        $definition = $script:ScopeDefinition
        $parameters = @{
            Name=$definition.Name; DisplayName=$definition.DisplayName; Description=$definition.Description
            Direction='Outbound'; Protocol='TCP'; RemotePort='79'; Action='Block'
            Enabled='True'; Profile='Any'; ErrorAction='Stop'
        }
        foreach ($key in $Extra.Keys) { $parameters[$key] = $Extra[$key] }
        New-NetFirewallRule @parameters | Out-Null
        $script:ScopeRuleCreated = $true
        Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition -PolicyStore PersistentStore -Confirm:$false | Should -BeTrue
        $rule = Get-NetFirewallRule -Name $definition.Name -PolicyStore ActiveStore -ErrorAction Stop
        [string]($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop).Package | Should -BeNullOrEmpty
        [string]($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop).LocalUser | Should -BeExactly 'Any'
        (Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @($rule) `
            -FilterCache (Get-AdvancedSecurityFirewallFilterCache)).Compliant | Should -BeTrue
    }
}
