#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Tests/Windows11/Windows11DecisionEvidence.ps1')
    $script:EvidenceAsrRules = Get-Content (Join-Path $repo 'Modules/ASR/Config/ASR-Rules.json') -Raw | ConvertFrom-Json
    function Get-DecisionEvidenceCase {
        param([string]$Module)
        $environment = @{}
        $decisions = @{}
        $result = $null
        switch ($Module) {
            'SecurityBaseline' {
                $decisions = @{bitLockerUSBEnforcement=$true;submitAllSamples=$false;smartScreenWarnMode=$true;standardUserElevationMode='SecureDesktop';adminProtectionMode='Classic'}
                $result = [pscustomobject]@{Details=@{BitLockerUSBEnforcement=$true;SubmitAllSamples=$false;SmartScreenWarnMode=$true;StandardUserElevationMode='SecureDesktop';ConsentPromptBehaviorUser=1;AdminProtectionMode='Classic';TypeOfAdminApprovalMode=1}}
            }
            'ASR' {
                $environment = @{CloudProtectionEnabled=$true;ConfigMgrDetected=$false}
                $decisions = @{usesManagementTools=$true;allowNewSoftware=$true;continueWithoutCloud=$false}
                $actions = @(foreach ($rule in $script:EvidenceAsrRules) {
                    if ($rule.PSObject.Properties['WindowsClientApplicable'] -and -not $rule.WindowsClientApplicable) { continue }
                    [pscustomobject]@{Guid=$rule.GUID;Action=$(if ($rule.GUID -in @('d1e49aac-8f56-4280-b9ba-993a6d77406c','01443614-cd74-433a-b99e-2ecdc07bfc25')) {2} else {1})}
                })
                $result = [pscustomobject]@{Status='DryRun';CloudProtectionEnabled=$true;ConfigMgrDetected=$false;RulesPreviewed=18;RulesNotApplicable=1;Details=@{RequestedActions=$actions}}
            }
            'DNS' {
                $decisions = @{provider='Quad9';dohMode='REQUIRE'}
                $result = [pscustomobject]@{Status='DryRun';Provider='Quad9';DoHMode='REQUIRE'}
            }
            'Privacy' {
                $decisions = @{mode='Strict';disableCloudClipboard=$false;applyStorePackagePolicy=$true;removeBloatwareApps='standard';removeWeatherWidget=$true}
                $result = [pscustomobject]@{Status='DryRun';Mode='Strict';PreviewDecisions=[pscustomobject]@{CloudClipboardTargetCount=1;CloudClipboardTargetType='DWord';CloudClipboardTargetValue=0;Tier1PolicyRemovalSelected=$true;Tier2BloatwareRemovalSelected=$true;WeatherWidgetRemovalSelected=$true}}
            }
            'AntiAI' {
                $targets = @(foreach ($index in 0..49) {
                    [pscustomobject]@{Path='fixture';Name=[string]$index;Feature=('group' + [int][math]::Floor($index / 4))}
                })
                $environment = @{AntiAITargets=$targets}
                $result = [pscustomobject]@{DeclaredPolicyTargets=50;TotalFeatures=12;Previewed=8;PreviewedPolicyTargets=27;NotApplicablePolicyTargets=23;ApplicableTargetPlan=@($targets | Select-Object -First 27);NotApplicableTargetPlan=@($targets | Select-Object -Skip 27)}
            }
            'EdgeHardening' {
                $decisions = @{allowExtensions=$true}
                $result = [pscustomobject]@{Status='DryRun';AllowExtensions=$true;PoliciesSelected=30;BaselineSelected=23;PrivacySelected=7;PoliciesPreviewed=25;PoliciesNotApplicable=5}
            }
            'AdvancedSecurity' {
                $environment = @{RdpHostSupported=$true;WirelessDisplaySupported=$true;DomainJoined=$true}
                $decisions = @{securityProfile='Enterprise';skipFirewallLayer=$false;disableRDP=$true;forceAdminShares=$true;disableUPnP=$false;disableWirelessDisplay=$true;disableDiscoveryProtocols=$true;disableIPv6=$true}
                $result = [pscustomobject]@{Status='DryRun';SecurityProfile='Enterprise';SkipFirewallLayer=$false;DisableRDP=$false;AdminSharesDisabled=$false;DisableUPnP=$true;DisableWirelessDisplayCompletely=$true;DisableDiscoveryProtocolsCompletely=$false;DisableIPv6Completely=$false;EnableFirewallShieldsUp=$false;FirewallLayer='WouldApply'}
            }
        }
        return @{Scenario=[pscustomobject]@{Module=$Module;Decisions=$decisions};Result=$result;Environment=$environment;AsrDefinitions=$script:EvidenceAsrRules}
    }
}

Describe 'Windows decision evidence oracle' {
    It 'accepts complete actual decision evidence for <Module>' -TestCases @(
        @{Module='SecurityBaseline'}, @{Module='ASR'}, @{Module='DNS'}, @{Module='Privacy'},
        @{Module='AntiAI'}, @{Module='EdgeHardening'}, @{Module='AdvancedSecurity'}
    ) {
        param($Module)
        $case = Get-DecisionEvidenceCase $Module
        $proof = Assert-Windows11DecisionEvidence @case
        $proof.Verified | Should -BeTrue
        @($proof.CheckedValues.PSObject.Properties).Count | Should -BeGreaterThan 0
    }

    It 'rejects a missing or malformed decision field: <Module>/<Field>' -TestCases @(
        @{Module='SecurityBaseline';Parent='Details';Field='SubmitAllSamples'},
        @{Module='SecurityBaseline';Parent='Details';Field='AdminProtectionMode'},
        @{Module='SecurityBaseline';Parent='Details';Field='TypeOfAdminApprovalMode'},
        @{Module='ASR';Parent='';Field='CloudProtectionEnabled'},
        @{Module='DNS';Parent='';Field='Provider'},
        @{Module='DNS';Parent='';Field='DoHMode'},
        @{Module='Privacy';Parent='PreviewDecisions';Field='Tier1PolicyRemovalSelected'},
        @{Module='Privacy';Parent='PreviewDecisions';Field='Tier2BloatwareRemovalSelected'},
        @{Module='Privacy';Parent='PreviewDecisions';Field='WeatherWidgetRemovalSelected'},
        @{Module='Privacy';Parent='PreviewDecisions';Field='CloudClipboardTargetCount'},
        @{Module='AntiAI';Parent='';Field='DeclaredPolicyTargets'},
        @{Module='EdgeHardening';Parent='';Field='AllowExtensions'},
        @{Module='EdgeHardening';Parent='';Field='BaselineSelected'},
        @{Module='AdvancedSecurity';Parent='';Field='DisableRDP'},
        @{Module='AdvancedSecurity';Parent='';Field='AdminSharesDisabled'},
        @{Module='AdvancedSecurity';Parent='';Field='DisableUPnP'},
        @{Module='AdvancedSecurity';Parent='';Field='DisableWirelessDisplayCompletely'},
        @{Module='AdvancedSecurity';Parent='';Field='DisableDiscoveryProtocolsCompletely'},
        @{Module='AdvancedSecurity';Parent='';Field='DisableIPv6Completely'},
        @{Module='AdvancedSecurity';Parent='';Field='EnableFirewallShieldsUp'}
    ) {
        param($Module, $Parent, $Field)
        foreach ($fault in @('missing','type','value')) {
            $case = Get-DecisionEvidenceCase $Module
            $target = if ($Parent) {$case.Result.$Parent} else {$case.Result}
            $old = $target.$Field
            if ($fault -eq 'missing') {
                if ($target -is [hashtable]) {$target.Remove($Field)} else {$target.PSObject.Properties.Remove($Field)}
            }
            elseif ($fault -eq 'type') {
                $target.$Field = if ($old -is [string]) { $true } else { [string]$old }
            }
            else {
                $target.$Field = if ($old -is [bool]) {-not $old} elseif ($old -is [string]) {'wrong-choice'} else {999}
            }
            { Assert-Windows11DecisionEvidence @case } | Should -Throw
        }
    }

    It 'rejects duplicate, missing, foreign and incorrectly selected ASR rules' {
        foreach ($fault in @('duplicate','missing','foreign','management','software','type')) {
            $case = Get-DecisionEvidenceCase ASR
            $actions = $case.Result.Details.RequestedActions
            switch ($fault) {
                'duplicate' {$actions[1].Guid=$actions[0].Guid}
                'missing' {$case.Result.Details.RequestedActions=@($actions | Select-Object -Skip 1)}
                'foreign' {$actions[0].Guid='00000000-0000-0000-0000-000000000000'}
                'management' {($actions | Where-Object Guid -eq 'd1e49aac-8f56-4280-b9ba-993a6d77406c').Action=1}
                'software' {($actions | Where-Object Guid -eq '01443614-cd74-433a-b99e-2ecdc07bfc25').Action=1}
                'type' {$actions[0].Action='1'}
            }
            { Assert-Windows11DecisionEvidence @case } | Should -Throw
        }
    }

    It 'requires the specific cloud refusal before backup instead of any failure' {
        $case = Get-DecisionEvidenceCase ASR
        $case.Environment.CloudProtectionEnabled=$false
        $case.Result=[pscustomobject]@{Success=$false;Status='Failed';CloudProtectionEnabled=$false;ConfigMgrDetected=$false;RulesPreviewed=0;BackupCreated=$false;Details=@{RequestedActions=@()};Errors=@('ASR application cancelled (cloud protection required, continueWithoutCloud=false)')}
        (Assert-Windows11DecisionEvidence @case).Verified | Should -BeTrue
        $case.Result.Errors=@('unrelated failure')
        { Assert-Windows11DecisionEvidence @case } | Should -Throw
    }

    It 'marks profile-fixed and currently inactive choices explicitly' {
        $case = Get-DecisionEvidenceCase AdvancedSecurity
        $proof = Assert-Windows11DecisionEvidence @case
        @($proof.InactiveChoices).Count | Should -Be 5
        $proof.InactiveChoices | Should -Contain 'forceAdminShares'
        $proof.InactiveChoices | Should -Contain 'disableIPv6'
        $case = Get-DecisionEvidenceCase ASR
        (Assert-Windows11DecisionEvidence @case).InactiveChoices | Should -Contain 'continueWithoutCloud'
        $case = Get-DecisionEvidenceCase Privacy
        (Assert-Windows11DecisionEvidence @case).InactiveChoices | Should -Contain 'disableCloudClipboard'
    }

    It 'requires canonical KEEP even when a stale DoH mode was configured' {
        $case = Get-DecisionEvidenceCase DNS
        $case.Scenario.Decisions.provider='KEEP'
        $case.Result.Provider='KEEP';$case.Result.Status='Success';$case.Result.DoHMode='KEEP'
        (Assert-Windows11DecisionEvidence @case).InactiveChoices | Should -Contain 'dohMode'
        $case.Result.DoHMode='REQUIRE'
        { Assert-Windows11DecisionEvidence @case } | Should -Throw
    }

    It 'checks reconciled Edge and AntiAI target counts' {
        foreach ($module in @('EdgeHardening','AntiAI')) {
            $case = Get-DecisionEvidenceCase $module
            if ($module -eq 'EdgeHardening') {$case.Result.PoliciesPreviewed=24}
            else {$case.Result.PreviewedPolicyTargets=26}
            { Assert-Windows11DecisionEvidence @case } | Should -Throw
        }
    }

    It 'rejects missing, duplicate and foreign AntiAI identities even when counters reconcile' {
        foreach ($fault in @('duplicate','foreign','missing','all-groups')) {
            $case = Get-DecisionEvidenceCase AntiAI
            switch ($fault) {
                'duplicate' {$case.Result.NotApplicableTargetPlan[0]=$case.Result.ApplicableTargetPlan[0]}
                'foreign' {$case.Result.NotApplicableTargetPlan[0]=[pscustomobject]@{Path='foreign';Name='unknown'}}
                'missing' {$case.Result.NotApplicableTargetPlan=@($case.Result.NotApplicableTargetPlan | Select-Object -Skip 1);$case.Result.NotApplicablePolicyTargets=15}
                'all-groups' {$case.Result.Previewed=12}
            }
            { Assert-Windows11DecisionEvidence @case } | Should -Throw
        }
    }
}
