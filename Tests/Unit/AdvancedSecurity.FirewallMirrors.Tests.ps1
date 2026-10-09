#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($helper in @('AdvancedSecurityFirewallMirrors', 'AdvancedSecurityFirewallGpoStore', 'AdvancedSecurityFirewallRules', 'AdvancedSecurityFirewallPolicyState', 'Get-AdvancedSecurityApplicability')) {
        . (Join-Path $repo "Modules/AdvancedSecurity/Private/$helper.ps1")
    }
    . (Join-Path $repo 'Modules/AdvancedSecurity/Public/Restore-AdvancedSecuritySettings.ps1')
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null=$Level,$Message,$Module,$Exception
    }
    function Get-MirrorRuleFixture {
        param([string]$Name, [string]$Group, [string]$Description = 'configuration')
        New-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetFirewallRule -ClientOnly -Property @{
            InstanceID=$Name; RuleGroup=$Group; Description=$Description
            Enabled=[uint16]1; Direction=[uint16]2; Action=[uint16]4; Profiles=[uint16]0
        }
    }
}

Describe 'AdvancedSecurity firewall GPO editor registration' {
    BeforeAll {
        $script:RegistryCse = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
        $script:FirewallEditor = '{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}'
        $script:DeviceGuardEditor = '{8ED67D93-8B70-4C15-BD23-43D585B9FD81}'
        $script:DeviceGuardCse = '{F312195E-3D9D-447A-A3F5-08DFFA24735E}'
    }

    It 'reads only the Registry CSE editors from a native extension list' {
        Initialize-AdvancedSecurityFirewallGpoStore
        $text = "[$script:RegistryCse$script:DeviceGuardEditor$script:FirewallEditor][$script:DeviceGuardCse$script:DeviceGuardEditor]"
        [NoIDPrivacy.FirewallGpoStore]::ParseRegistryEditors($text) -join ',' |
            Should -BeExactly '8ed67d93-8b70-4c15-bd23-43d585b9fd81,b05566ac-fe9c-4368-be01-7a4cbb6cba11'
        @([NoIDPrivacy.FirewallGpoStore]::ParseRegistryEditors('')).Count | Should -Be 0
        # The firewall editor under another processor is not a Registry CSE registration.
        @([NoIDPrivacy.FirewallGpoStore]::ParseRegistryEditors("[$script:DeviceGuardCse$script:FirewallEditor]")).Count | Should -Be 0
    }

    It 'rejects <Fault> instead of guessing the registration state' -TestCases @(
        @{ Fault='an extension without editors'; Text='[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}]' },
        @{ Fault='trailing unparsed text'; Text='[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}]x' },
        @{ Fault='a duplicate extension'; Text='[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{8ED67D93-8B70-4C15-BD23-43D585B9FD81}]' },
        @{ Fault='a duplicate editor'; Text='[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}{b05566ac-fe9c-4368-be01-7a4cbb6cba11}]' }
    ) {
        param($Fault, $Text)
        $null = $Fault
        $extensionList = $Text
        Initialize-AdvancedSecurityFirewallGpoStore
        { [NoIDPrivacy.FirewallGpoStore]::ParseRegistryEditors($extensionList) } | Should -Throw
    }

    It 'does not reach native Group Policy after WhatIf declines the registration restore' {
        Mock Initialize-AdvancedSecurityFirewallGpoStore { throw 'Unexpected native code loading' }
        Set-AdvancedSecurityFirewallGpoEditorRegistration -Registered $false -WhatIf | Should -BeExactly 'Unchanged'
        Should -Invoke Initialize-AdvancedSecurityFirewallGpoStore -Times 0 -Exactly
    }
}

Describe 'AdvancedSecurity compares native copied rule configuration' -Skip:($env:OS -ne 'Windows_NT') {
    It 'distinguishes provider identities from every persisted filter property, including new properties' {
        $rule = New-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetFirewallRule -ClientOnly -Property @{
            InstanceID='source'; CreationClassName='provider-source'; Description='same configuration'
        }
        $script:NativeFilter = New-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NoIDAuditFilter -ClientOnly -Property @{
            InstanceID='source'; CreationClassName='provider-source'; FutureScope='Any'
        }
        Mock Get-NetFirewallPortFilter { $script:NativeFilter }
        Mock Get-NetFirewallAddressFilter { $script:NativeFilter }
        Mock Get-NetFirewallApplicationFilter { $script:NativeFilter }
        Mock Get-NetFirewallServiceFilter { $script:NativeFilter }
        Mock Get-NetFirewallInterfaceFilter { $script:NativeFilter }
        Mock Get-NetFirewallInterfaceTypeFilter { $script:NativeFilter }
        Mock Get-NetFirewallSecurityFilter { $script:NativeFilter }
        $source = Get-AdvancedSecurityFirewallRuleConfiguration -Rule $rule
        $rule.CimInstanceProperties['InstanceID'].Value = 'mirror'
        $rule.CimInstanceProperties['CreationClassName'].Value = 'provider-mirror'
        $script:NativeFilter.CimInstanceProperties['InstanceID'].Value = 'mirror'
        $script:NativeFilter.CimInstanceProperties['CreationClassName'].Value = 'provider-mirror'
        Get-AdvancedSecurityFirewallRuleConfiguration -Rule $rule | Should -BeExactly $source
        $script:NativeFilter.CimInstanceProperties['FutureScope'].Value = 'Restricted'
        Get-AdvancedSecurityFirewallRuleConfiguration -Rule $rule | Should -Not -BeExactly $source
    }
}

Describe 'AdvancedSecurity WFW-backed GPO mirror recovery' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:Contract = Get-AdvancedSecurityFirewallMirrorContract
        $script:RuleName = 'NoID-Block-Finger-TCP-79'
        $script:SourceName = $script:RuleName + $script:Contract.Suffix
        $script:Local = @{}
        $script:Gpo = @{}
        $script:CopyFailure = $false
        $script:Events = [Collections.Generic.List[string]]::new()
        $script:Entries = @()
        $script:Policy = Join-Path $TestDrive 'sealed.wfw'
        Set-Content $script:Policy 'Native hive transport is mocked'
        Mock Get-NetFirewallRule {
            $inventory = if ($PolicyStore -ceq 'PersistentStore') { $script:Local }
                else { throw 'Computer-name GPO access would require ADMIN$' }
            if ($Name) { foreach ($key in $Name) { if ($inventory.ContainsKey($key)) { $inventory[$key] } } }
            else { $inventory.Values }
        }
        Mock Get-AdvancedSecurityFirewallRuleConfiguration { [string]$Rule.Description }
        Mock Get-AdvancedSecurityLocalFirewallGpoState {
            $state = [pscustomobject]@{
                Sources=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
                Mirrors=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
                UnownedGpo=@{}; UnownedLocal=@{}
            }
            foreach ($rule in $script:Local.Values) {
                if ($rule.Group -cne $script:Contract.Group) { $state.UnownedLocal[$rule.Name]=$true; continue }
                $name=$rule.Name.Substring(0,$rule.Name.Length-$script:Contract.Suffix.Length)
                $state.Sources.Add($name,[string]$rule.Description)
            }
            foreach ($rule in $script:Gpo.Values) {
                if ($rule.Group -cne $script:Contract.Group) { $state.UnownedGpo[$rule.Name]=$true; continue }
                $state.Mirrors.Add($rule.Name,[string]$rule.Description)
            }
            return $state
        }
        Mock Sync-AdvancedSecurityLocalFirewallGpo {
            $scope=if($null -ne $NamesToSynchronize){@($NamesToSynchronize)}else{@($script:Contract.Names)}
            $changed=$false
            foreach($name in $scope){
                if($ExpectedSources.ContainsKey($name)){
                    if($script:Gpo.ContainsKey($name) -and $script:Gpo[$name].Description -ceq $ExpectedSources[$name]){continue}
                    $script:Events.Add('copy')
                    if($script:CopyFailure){throw 'Injected native copy failure'}
                    $script:Gpo[$name]=Get-MirrorRuleFixture -Name $name -Group $script:Contract.Group -Description $ExpectedSources[$name]
                    $changed=$true
                }elseif($script:Gpo.ContainsKey($name) -and $script:Gpo[$name].Group -ceq $script:Contract.Group){
                    $script:Events.Add('remove');$script:Gpo.Remove($name);$changed=$true
                }
            }
            return $changed
        }
        Mock Set-AdvancedSecurityFirewallGpoEditorRegistration { $script:Events.Add("registration:$Registered"); 'Unchanged' }
        Mock Get-AdvancedSecurityFirewallPolicyState {
            [pscustomobject]@{ SchemaVersion=1; EntryCount=$script:Entries.Count; Entries=$script:Entries }
        }
        Mock Remove-NetFirewallRule {
            foreach ($rule in $InputObject) {
                $script:Events.Add('remove')
                $name = [string]$rule.Name
                if ($script:Local.ContainsKey($name) -and [object]::ReferenceEquals($script:Local[$name], $rule)) {
                    $script:Local.Remove($name)
                }
                else { $script:Gpo.Remove($name) }
            }
        }
        Mock New-NetFirewallRule {
            if ($PolicyStore -cne 'PersistentStore') { throw 'New rules must keep a local WFW source' }
            $script:Events.Add('create')
            $script:Local[$Name] = Get-MirrorRuleFixture -Name $Name -Group $Group -Description $Description
        }
        Mock Get-AdvancedSecurityApplicability { [pscustomobject]@{ManagedPolicySupported=$true} }
        Mock Test-AdvancedSecurityFirewallRuleDefinition { [pscustomobject]@{Compliant=$true;Mismatches=@()} }
        Mock Copy-NetFirewallRule { throw 'Computer-name GPO copy would require ADMIN$' }
        Mock Invoke-AdvancedSecurityFirewallPolicyRefresh { $script:Events.Add('refresh') }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*\GroupPolicy\Machine\Registry.pol' }
        Mock Start-Process { throw 'Unexpected native process' }
        Mock Start-Sleep {}
    }

    It 'retains all current rule identities in the stable recovery catalog' {
        $names = @(Get-AdvancedSecurityFirewallDefinitions | ForEach-Object { [string]$_.Name } | Sort-Object)
        ($script:Contract.Names | Sort-Object) -join ',' | Should -Be ($names -join ',')
        $script:Contract.Names.Count | Should -Be 16
    }

    It 'reads a legacy WFW without requiring a new artifact or touching foreign GPO rules' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group 'User policy'
        $plan = Get-AdvancedSecurityFirewallMirrorRestorePlan -PolicyFilePath $script:Policy
        $plan.Names.Count | Should -Be 0
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames $plan.Names -Confirm:$false | Should -BeTrue
        $script:Gpo.Count | Should -Be 1
        $script:Events.Count | Should -Be 0
    }

    It 'rejects an unowned GPO collision before the public restore imports anything' {
        $script:Entries = @([pscustomobject]@{
            Kind='Value'; Path='FirewallRules'; Name=$script:SourceName; Type='String'
            Data=('v2.33|Action=Block|EmbedCtxt=' + $script:Contract.Group + '|')
        })
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group 'User policy'
        Restore-FirewallPolicy -BackupFilePath $script:Policy -Confirm:$false | Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Copy-NetFirewallRule -Times 0 -Exactly
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'rejects an unknown marked source in a WFW before import' {
        $script:Entries = @([pscustomobject]@{
            Kind='Value'; Path='FirewallRules'; Name='Unknown-LocalBackup'; Type='String'
            Data=('v2.33|EmbedCtxt=' + $script:Contract.Group + '|')
        })
        { Get-AdvancedSecurityFirewallMirrorRestorePlan -PolicyFilePath $script:Policy } | Should -Throw '*unknown or duplicate*'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'rejects an unowned local recovery-copy name before Apply' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group 'User policy'
        { Assert-AdvancedSecurityFirewallMirrorApplicability -Names @($script:RuleName) } | Should -Throw '*unowned local rule*'
        $script:Events.Count | Should -Be 0
    }

    It 'does not seal <Case> as a recoverable mirrored prestate' -TestCases @(
        @{ Case='an orphaned GPO rule'; Source=$false; Mirror=$true; Different=$false },
        @{ Case='an orphaned local copy'; Source=$true; Mirror=$false; Different=$false },
        @{ Case='a differing GPO rule'; Source=$true; Mirror=$true; Different=$true }
    ) {
        param($Case, $Source, $Mirror, $Different)
        $null = $Case
        if ($Source) { $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group }
        if ($Mirror) {
            $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group `
                -Description $(if ($Different) { 'different' } else { 'configuration' })
        }
        { Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized } | Should -Throw '*prestate is incomplete or differs*'
        { Assert-AdvancedSecurityFirewallMirrorApplicability -Names @($script:RuleName) -SelectedRulesOnly } | Should -Throw '*prestate is incomplete or differs*'
        $script:Events.Count | Should -Be 0
    }

    It 'removes only marked GPO rules when restoring a legacy WFW and preserves old local rules' {
        $script:Local[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group ''
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        $script:Gpo['Foreign'] = Get-MirrorRuleFixture -Name 'Foreign' -Group 'User policy'
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false | Should -BeTrue
        $script:Gpo.Keys | Should -Be @('Foreign')
        $script:Local.Keys | Should -Be @($script:RuleName)
        $script:Events -join ',' | Should -Be 'remove,refresh'
        Should -Invoke Set-AdvancedSecurityFirewallGpoEditorRegistration -Times 0 -Exactly
    }

    It 'returns the firewall editor registration to its sealed prestate before refreshing policy' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        Mock Set-AdvancedSecurityFirewallGpoEditorRegistration { $script:Events.Add("registration:$Registered"); 'Changed' }
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -SealedEditorRegistration $false -Confirm:$false | Should -BeTrue
        $script:Events -join ',' | Should -Be 'remove,registration:False,refresh'
    }

    It 'refreshes policy after a registration-only change even when no rule changed' {
        Mock Set-AdvancedSecurityFirewallGpoEditorRegistration { $script:Events.Add("registration:$Registered"); 'Changed' }
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -SealedEditorRegistration $true -Confirm:$false | Should -BeTrue
        $script:Events -join ',' | Should -Be 'registration:True,refresh'
    }

    It 'keeps a registration that remaining local policy still needs and reports it' {
        Mock Set-AdvancedSecurityFirewallGpoEditorRegistration { $script:Events.Add("registration:$Registered"); 'Retained' }
        Mock Write-Log {}
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -SealedEditorRegistration $false -Confirm:$false | Should -BeTrue
        $script:Events -join ',' | Should -Be 'registration:False'
        Should -Invoke Write-Log -Times 1 -Exactly -ParameterFilter { $Level -eq 'INFO' -and $Message -like '*registration retained*' }
    }

    It 'rejects an unknown registration result' {
        Mock Set-AdvancedSecurityFirewallGpoEditorRegistration { 'Unknown' }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -SealedEditorRegistration $false -Confirm:$false } |
            Should -Throw '*Unexpected firewall editor registration result*'
        $script:Events.Count | Should -Be 0
    }

    It 'rejects a sealed registration for a selected Apply before inspecting policy' {
        Mock Get-AdvancedSecurityLocalFirewallGpoState { throw 'Unexpected policy inspection' }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -NamesToSynchronize @($script:RuleName) `
                -SealedEditorRegistration $false -Confirm:$false } | Should -Throw '*complete restore*'
        Should -Invoke Set-AdvancedSecurityFirewallGpoEditorRegistration -Times 0 -Exactly
    }

    It 'completes the local GPO writer before refreshing policy' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo {
            $script:Events.Add('final-rule-and-metadata')
            $script:Gpo.Remove($script:RuleName)
            $true
        }
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false | Should -BeTrue
        $script:Gpo.Count | Should -Be 0
        $script:Events -join ',' | Should -Be 'final-rule-and-metadata,refresh'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'retains the rule and propagates a failed final GPO save without ordinary-removal fallback' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo { throw 'Injected native Save failure' }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false } | Should -Throw '*Injected native Save failure*'
        $script:Gpo.Count | Should -Be 1
        $script:Events.Count | Should -Be 0
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'submits a complete owned inventory for one local GPO synchronization' {
        foreach ($name in $script:Contract.Names) {
            $script:Gpo[$name] = Get-MirrorRuleFixture -Name $name -Group $script:Contract.Group
        }
        Mock Sync-AdvancedSecurityLocalFirewallGpo {
            if ($script:Gpo.Count -ne 16 -or $ExpectedSources.Count -ne 0) { throw 'Incomplete reconciliation request' }
            $script:Gpo.Clear()
            $true
        }
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false | Should -BeTrue
        $script:Gpo.Count | Should -Be 0
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 1 -Exactly
    }

    It 'rejects a reported final removal when the rule actually remains' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo { $true }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false } | Should -Throw '*prestate is incomplete or differs*'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'reconstructs a missing GPO rule from complete native source data through the local API' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -Confirm:$false | Should -BeTrue
        $script:Gpo.Count | Should -Be 1
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 1 -Exactly -ParameterFilter {
            $ExpectedSources.Count -eq 1 -and $ExpectedSources[$script:RuleName] -ceq 'configuration'
        }
        Should -Invoke Copy-NetFirewallRule -Times 0 -Exactly
    }

    It 'can retry a copy failure using the same restored local recovery data' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        $script:CopyFailure = $true
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -Confirm:$false } | Should -Throw '*Injected native copy failure*'
        $script:Local.Count | Should -Be 1
        $script:CopyFailure = $false
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -Confirm:$false | Should -BeTrue
        $script:Events -join ',' | Should -Be 'copy,copy,refresh'
    }

    It 'rejects a WFW plan versus imported-source mismatch before GPO writes' {
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -Confirm:$false } | Should -Throw '*prevalidated WFW plan*'
        $script:Events.Count | Should -Be 0
    }

    It 'rejects ownership changes immediately before removal' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo { throw 'NoID firewall GPO ownership changed before native Save' }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false } | Should -Throw '*ownership changed*'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'finishes policy processing on a retry after the last GPO rule was already removed' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*\GroupPolicy\Machine\Registry.pol' }
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -Confirm:$false | Should -BeTrue
        $script:Events -join ',' | Should -Be 'refresh'
    }

    It 'does not certify a native copy that returned without creating the mirror' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo { $true }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -Confirm:$false } | Should -Throw '*prestate is incomplete or differs*'
    }

    It 'does not inspect or change policy after WhatIf declines synchronization' {
        Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -WhatIf | Should -BeFalse
        Should -Invoke Get-NetFirewallRule -Times 0 -Exactly
        $script:Events.Count | Should -Be 0
    }

    It 'migrates a legacy local rule only after creating its recoverable GPO rule' {
        $script:Local[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group '' -Description 'old local state'
        $definition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition -Confirm:$false | Should -BeTrue
        $script:Local.Keys | Should -Be @($script:SourceName)
        $script:Gpo.Keys | Should -Be @($script:RuleName)
        $script:Local[$script:SourceName].Group | Should -BeExactly $script:Contract.Group
        $script:Events -join ',' | Should -Be 'create,copy,refresh,remove'
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 1 -Exactly
    }

    It 'keeps the local firewall path for editions without managed policy support' {
        Mock Get-AdvancedSecurityApplicability { [pscustomobject]@{ManagedPolicySupported=$false} }
        Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false | Should -BeTrue
        $script:Local.Keys | Should -Be @($script:RuleName)
        $script:Gpo.Count | Should -Be 0
        $script:Events -join ',' | Should -Be 'create'
        Should -Invoke Copy-NetFirewallRule -Times 0 -Exactly
    }

    It 'rejects an unowned GPO collision before Apply changes the local source' {
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group 'User policy'
        { Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false } | Should -Throw '*unowned local-GPO*'
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        $script:Events.Count | Should -Be 0
    }

    It 'retains the old local rule and recovery source after a native GPO copy failure' {
        $old = Get-MirrorRuleFixture -Name $script:RuleName -Group '' -Description 'old local state'
        $script:Local[$script:RuleName] = $old
        $script:CopyFailure = $true
        { Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false } | Should -Throw '*Injected native copy failure*'
        $script:Local[$script:RuleName] | Should -Be $old
        $script:Local.ContainsKey($script:SourceName) | Should -BeTrue
        $script:Events -join ',' | Should -Be 'create,copy'
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 0 -Exactly
    }

    It 'requires actual enforcement after successful GPO synchronization' {
        Mock Test-AdvancedSecurityFirewallRuleDefinition { [pscustomobject]@{Compliant=$false;Mismatches=@('not enforced')} }
        { Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false } | Should -Throw '*Exact firewall-rule verification failed*'
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 5 -Exactly
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 1 -Exactly
    }

    It 'waits for active GPO enforcement without recreating the rule or refreshing policy again' {
        $script:ActiveReads = 0
        Mock Test-AdvancedSecurityFirewallRuleDefinition {
            $script:ActiveReads++
            [pscustomobject]@{Compliant=($script:ActiveReads -eq 2);Mismatches=@('pending active rule')}
        }
        Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false | Should -BeTrue
        Should -Invoke Test-AdvancedSecurityFirewallRuleDefinition -Times 2 -Exactly
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 1 -Exactly
        Should -Invoke Invoke-AdvancedSecurityFirewallPolicyRefresh -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'preserves foreign policy and other owned pairs across repeated Apply' {
        $otherName = 'NoID-Block-mDNS-UDP-5353'
        $script:Local[$otherName + $script:Contract.Suffix] = Get-MirrorRuleFixture -Name ($otherName + $script:Contract.Suffix) -Group $script:Contract.Group
        $script:Gpo[$otherName] = Get-MirrorRuleFixture -Name $otherName -Group $script:Contract.Group
        $foreign = Get-MirrorRuleFixture -Name 'Foreign' -Group 'User policy'
        $script:Gpo['Foreign'] = $foreign
        $definition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition -Confirm:$false | Should -BeTrue
        Set-AdvancedSecurityFirewallRuleDefinition -Definition $definition -Confirm:$false | Should -BeTrue
        $state = Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized
        $state.Sources.Count | Should -Be 2
        $state.Mirrors.Count | Should -Be 2
        $script:Gpo['Foreign'] | Should -Be $foreign
        $script:Gpo[$otherName].Description | Should -BeExactly 'configuration'
    }

    It 'rejects ambiguous edition evidence before inspecting or modifying policy' {
        Mock Get-AdvancedSecurityApplicability { [pscustomobject]@{ManagedPolicySupported='true'} }
        { Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false } | Should -Throw '*unambiguous native edition*'
        Should -Invoke Get-NetFirewallRule -Times 0 -Exactly
        $script:Events.Count | Should -Be 0
    }

    It 'does not inspect or modify policy after WhatIf declines Apply' {
        Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -WhatIf | Should -BeFalse
        Should -Invoke Get-NetFirewallRule -Times 0 -Exactly
        Should -Invoke Get-AdvancedSecurityApplicability -Times 0 -Exactly
        $script:Events.Count | Should -Be 0
    }

    It 'preserves an unselected GPO configuration instead of repairing it during one-rule Apply' {
        $otherName = 'NoID-Block-mDNS-UDP-5353'
        $script:Local[$otherName + $script:Contract.Suffix] = Get-MirrorRuleFixture -Name ($otherName + $script:Contract.Suffix) -Group $script:Contract.Group
        $other = Get-MirrorRuleFixture -Name $otherName -Group $script:Contract.Group -Description 'changed outside selected Apply'
        $script:Gpo[$otherName] = $other
        Set-AdvancedSecurityFirewallRuleDefinition -Definition (Get-AdvancedSecurityFirewallDefinitions -Feature Finger) -Confirm:$false | Should -BeTrue
        $script:Gpo[$otherName] | Should -Be $other
        $script:Gpo[$otherName].Description | Should -BeExactly 'changed outside selected Apply'
        # Full backup/module verification must still reject the differing pair.
        { Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized } | Should -Throw '*prestate is incomplete or differs*'
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 1 -Exactly -ParameterFilter { $NamesToSynchronize.Count -eq 1 -and $NamesToSynchronize[0] -ceq $script:RuleName }
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }

    It 'rejects a <Case> selected synchronization scope before writes' -TestCases @(
        @{Case='foreign';Names=@('Foreign')},
        @{Case='duplicate';Names=@('NoID-Block-Finger-TCP-79','NoID-Block-Finger-TCP-79')}
    ) {
        param($Case,$Names)
        $null=$Case,$Names # Names is consumed by the deferred Should-Throw block.
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @() -NamesToSynchronize $Names -Confirm:$false } | Should -Throw '*selected firewall synchronization scope*'
        $script:Events.Count | Should -Be 0
    }

    It 'rejects a selected native copy whose complete configuration differs' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        Mock Sync-AdvancedSecurityLocalFirewallGpo {
            $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group -Description 'unexpected native scope'
            $true
        }
        { Sync-AdvancedSecurityFirewallMirrors -ExpectedNames @($script:RuleName) -NamesToSynchronize @($script:RuleName) -Confirm:$false } | Should -Throw '*prestate is incomplete or differs*'
    }

    It 'rejects a recovery string that Windows does not expose as a native rule' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        Mock Get-NetFirewallRule { @() }
        { Get-AdvancedSecurityFirewallMirrorState } | Should -Throw '*native*inventory*incomplete*'
        Should -Invoke Sync-AdvancedSecurityLocalFirewallGpo -Times 0 -Exactly
    }

    It 'rejects a native source whose provider ownership differs from the captured raw marker' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        Mock Get-NetFirewallRule { Get-MirrorRuleFixture -Name $script:SourceName -Group 'User policy' }
        { Get-AdvancedSecurityFirewallMirrorState } | Should -Throw '*native*ownership*missing*'
    }

    It 'rejects raw source drift across native provider verification' {
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group
        $script:Reads=0
        Mock Get-AdvancedSecurityLocalFirewallGpoState {
            $script:Reads++
            $sources=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
            $sources.Add($script:RuleName,$(if($script:Reads -eq 1){'before'}else{'after'}))
            [pscustomobject]@{Sources=$sources;Mirrors=@{};UnownedGpo=@{};UnownedLocal=@{}}
        }
        { Get-AdvancedSecurityFirewallMirrorState } | Should -Throw '*sources changed during native verification*'
    }

    It 'includes unknown future fields in complete native mirror equality' {
        $payload='v2.34|Action=Block|FutureScope=Any|'
        $script:Local[$script:SourceName] = Get-MirrorRuleFixture -Name $script:SourceName -Group $script:Contract.Group -Description $payload
        $script:Gpo[$script:RuleName] = Get-MirrorRuleFixture -Name $script:RuleName -Group $script:Contract.Group -Description $payload
        (Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized).Sources[$script:RuleName] | Should -BeExactly $payload
        $script:Gpo[$script:RuleName].Description='v2.34|Action=Block|FutureScope=Restricted|'
        { Get-AdvancedSecurityFirewallMirrorState -RequireSynchronized } | Should -Throw '*prestate is incomplete or differs*'
    }

    It 'requires a native read before allowing a legacy WFW import when the local GPO is unreadable' {
        Mock Get-AdvancedSecurityLocalFirewallGpoState { throw 'Native GPO read failed' }
        Restore-FirewallPolicy -BackupFilePath $script:Policy -Confirm:$false | Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
    }
}
