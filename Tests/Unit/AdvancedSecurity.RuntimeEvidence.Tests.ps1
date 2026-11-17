#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    foreach ($helper in @('Set-FirewallShieldsUp', 'Test-FirewallShieldsUp', 'Test-RiskyServices')) {
        . (Join-Path $repo "Modules/AdvancedSecurity/Private/$helper.ps1")
    }
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1'), [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) { throw 'Standalone verifier did not parse' }
    $loops = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
                    $node.Variable.VariablePath.UserPath -eq 'optionalDefinition'
            }, $true))
    if ($loops.Count -ne 1) { throw 'Expected one standalone optional-registry verification loop' }
    # Execute the actual accounting loop without launching the interactive tool.
    $script:OptionalRegistryVerification = [scriptblock]::Create($loops[0].Extent.Text)
}

Describe 'Shields Up requires an enabled effective firewall profile' {
    BeforeEach {
        Set-StrictMode -Off
        $script:ShieldProfile = [pscustomobject]@{
            Enabled = 'True'; DefaultInboundAction = 'Block'; AllowInboundRules = 'False'
        }
        $script:ShieldValue = 1
        $script:ShieldDisableDuringApply = $false
        Mock Write-Log {}
        Mock Write-Host {}
        Mock Test-Path { $true }
        Mock Test-NoIDRegistryKey { $true }
        Mock Get-NetFirewallProfile { $script:ShieldProfile }
        Mock Set-NetFirewallProfile {
            $script:ShieldValue = if ([string]$AllowInboundRules -eq 'False') { 1 } else { 0 }
            $script:ShieldProfile.AllowInboundRules = [string]$AllowInboundRules
            if ($script:ShieldDisableDuringApply) { $script:ShieldProfile.Enabled = 'False' }
        }
        Mock Get-Item {
            $key = [pscustomobject]@{ Data = $script:ShieldValue }
            $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @('DoNotAllowExceptions') }
            $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) $null = $Name; 'DWord' }
            $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($Name) $null = $Name; $this.Data }
            return $key
        }
    }

    It 'does not apply Shields Up to an unproven enabled profile: <State>' -TestCases @(
        @{ State = 'False' }, @{ State = 'NotConfigured' }, @{ State = $null }, @{ State = 'Missing' }
    ) {
        param($State)
        if ($State -eq 'Missing') { $script:ShieldProfile.PSObject.Properties.Remove('Enabled') }
        else { $script:ShieldProfile.Enabled = $State }
        Set-FirewallShieldsUp -Enable -Confirm:$false | Should -BeFalse
        Should -Invoke Set-NetFirewallProfile -Times 0 -Exactly
    }

    It 'does not verify Shields Up on an unproven enabled profile: <State>' -TestCases @(
        @{ State = 'False' }, @{ State = 'NotConfigured' }, @{ State = $null }, @{ State = 'Missing' }
    ) {
        param($State)
        if ($State -eq 'Missing') { $script:ShieldProfile.PSObject.Properties.Remove('Enabled') }
        else { $script:ShieldProfile.Enabled = $State }
        $result = Test-FirewallShieldsUp
        $result.Pass | Should -BeFalse
        $result.IsEnabled | Should -BeFalse
    }

    It 'accepts exact Shields Up state on an enabled effective profile' {
        Set-FirewallShieldsUp -Enable -Confirm:$false | Should -BeTrue
        (Test-FirewallShieldsUp).Pass | Should -BeTrue
        Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly
    }

    It 'uses effective profile evidence in standalone verification: <State>' -TestCases @(
        @{ State = 'False'; Verified = 0; Failed = 1 },
        @{ State = 'NotConfigured'; Verified = 0; Failed = 1 },
        @{ State = $null; Verified = 0; Failed = 1 },
        @{ State = 'Missing'; Verified = 0; Failed = 1 },
        @{ State = 'True'; Verified = 1; Failed = 0 }
    ) {
        param($State, $Verified, $Failed)
        if ($State -eq 'Missing') { $script:ShieldProfile.PSObject.Properties.Remove('Enabled') }
        else { $script:ShieldProfile.Enabled = $State }
        $results = [pscustomobject]@{ Verified = 0; Failed = 0; NotChecked = 0 }
        $advPassed = @()
        $advFailed = @()
        $advancedChoicesAuthoritative = $true
        $shieldsUpCheck = @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
            Name = 'DoNotAllowExceptions'; Expected = 1; Desc = 'Firewall Shields Up (Maximum only)'
        }
        $optionalRegistryChecks = @(@{ Check = $shieldsUpCheck; Selected = $true })
        . $script:OptionalRegistryVerification
        $results.Verified | Should -Be $Verified
        $results.Failed | Should -Be $Failed
        $advPassed.Count | Should -Be $Verified
        $advFailed.Count | Should -Be $Failed
        $results.NotChecked | Should -Be 0
        $null = $advancedChoicesAuthoritative, $optionalRegistryChecks
    }

    It 'detects a profile disabled between preflight and post-apply readback' {
        $script:ShieldDisableDuringApply = $true
        Set-FirewallShieldsUp -Enable -Confirm:$false | Should -BeFalse
        Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly
    }

    It 'can clear Shields Up while preserving an intentionally disabled firewall profile' {
        $script:ShieldProfile.Enabled = 'False'
        Set-FirewallShieldsUp -Disable -Confirm:$false | Should -BeTrue
        $script:ShieldProfile.Enabled | Should -BeExactly 'False'
        $script:ShieldValue | Should -Be 0
    }
}

Describe 'Risky-service verification requires the stopped state' {
    It 'classifies service status <Status> with disabled startup precisely' -TestCases @(
        @{ Status = 'Stopped'; Compliant = $true },
        @{ Status = 'Running'; Compliant = $false },
        @{ Status = 'Paused'; Compliant = $false },
        @{ Status = 'StartPending'; Compliant = $false },
        @{ Status = 'StopPending'; Compliant = $false },
        @{ Status = 'ContinuePending'; Compliant = $false },
        @{ Status = 'PausePending'; Compliant = $false },
        @{ Status = $null; Compliant = $false },
        @{ Status = 'Unrecognized'; Compliant = $false }
    ) {
        param($Status, $Compliant)
        $script:RiskyFixtureStatus = $Status
        Mock Get-Service { [pscustomobject]@{ Name = 'lmhosts'; StartType = 'Disabled'; Status = $script:RiskyFixtureStatus } }
        Mock Write-Log {}
        $result = Test-RiskyServices -SkipUPnP
        $result.Compliant | Should -Be $Compliant
        if ($Status -ne 'Stopped') { @($result.StoppedServices) | Should -Not -Contain 'lmhosts' }
    }
}
