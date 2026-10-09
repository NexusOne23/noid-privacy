#Requires -Version 5.1

BeforeAll {
    $root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach($file in @('Runtime','Logger','Rollback','IntentState','QuickActions')) {. (Join-Path $root "Core\$file.ps1")}
    function Get-FrameworkVersion {'2.2.6'}
    $baselineRegistry=Get-Content (Join-Path $root 'Modules\SecurityBaseline\ParsedSettings\Computer-RegistryPolicies.json') -Raw|ConvertFrom-Json
    $script:BaselineRecordingSetting=@($baselineRegistry|Where-Object ValueName -CEQ AllowGameDVR)
    if($script:BaselineRecordingSetting.Count -ne 1){throw 'Expected one shipped recording-policy target'}
    function Get-XboxIntentSettings {
        $catalog=Get-NoIDXboxComponentCatalog
        [pscustomobject]@{
            SchemaVersion=1
            RegistryValues=@(Get-NoIDXboxSettingsRegistryTargets|ForEach-Object {
                [pscustomobject]@{kind='RegistryValue';path=$_.Path;name=$_.Name;keyExisted=$true;valueExisted=$true;originalName=$_.Name;type=$_.Type;value=$(if($_.Type -ceq 'DWord'){1}else{,@()});absentAncestorKeys=@()}
            })
            Services=@($catalog.Services|ForEach-Object {
                [pscustomobject]@{kind='Service';name=$_;exists=$true;status='Stopped';startType='Manual';delayedAutoStartExists=$false;delayedAutoStart=$null}
            })
            Task=[pscustomobject]@{TaskPath=$catalog.TaskPath;TaskName=$catalog.TaskName;Exists=$true;Enabled=$true}
        }
    }
    function Get-XboxIntentRecord {
        $stamp=[DateTime]::UtcNow.ToString('o')
        $modules=[ordered]@{}
        foreach($name in @('SecurityBaseline','Privacy','EdgeHardening')) {
            $intent=switch($name) {
                SecurityBaseline {[pscustomobject]@{standardUserElevationMode='SecureDesktop';bitLockerUSBEnforcement=$false;submitAllSamples=$false;smartScreenWarnMode=$true;asrActionOverrides=@()}}
                Privacy {[pscustomobject]@{mode='Strict';disableCloudClipboard=$true;applyStorePackagePolicy=$true;removeBloatwareApps=$true;removeWeatherWidget=$false}}
                EdgeHardening {[pscustomobject]@{allowExtensions=$true}}
            }
            $modules[$name]=[pscustomobject]@{moduleName=$name;recordedAt=$stamp;sourceKind='ApplyDecision';sourceId='test';sourceEvidenceSha256=('a'*64);intent=$intent}
        }
        [pscustomobject]@{schemaVersion=3;frameworkVersion='2.2.6';engineContractFingerprint=('b'*64);updatedAt=$stamp;modules=[pscustomobject]$modules}
    }
    $errors=$null;$tokens=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Tools\Verify-Complete-Hardening.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Verifier has syntax errors'}
    $script:XboxVerificationLoops=@{}
    foreach($condition in @('$computerSettings','$section.PSObject.Properties','$privacyChecks')) {
        $loops=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Condition.Extent.Text -ceq $condition},$true))
        if($loops.Count -ne 1){throw "Expected one production loop: $condition"}
        $script:XboxVerificationLoops[$condition]=[scriptblock]::Create($loops[0].Extent.Text)
    }
    function Get-PrivacyTargetApplicability {param($Path,$Name,$Applicability) $null=$Path,$Name,$Applicability; [pscustomobject]@{Applicable=$true}}
    function Test-RegistryValue {param($Path,$Name,$ExpectedValue) $null=$Path,$Name,$ExpectedValue; $false}
    function Get-ActualRegistryValue {param($Path,$Name) $null=$Path,$Name; '0'}
    function Invoke-XboxVerificationFixture {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='The extracted production verification loops are dot-sourced and consume these exact local variables.')]
        [CmdletBinding()]
        param([ValidateSet('Registry','Services','Privacy')][string]$Scope,[switch]$Unrelated,[switch]$Tier1Unselected,[switch]$Applied)
        $results=@{Verified=0;Failed=0;NotApplicable=0;NotChecked=0}
        $securityBaselineIntent=[pscustomobject]@{xboxSettings=(New-NoIDXboxIntentProjection $script:Settings SecurityBaseline)}
        $registryPassed=@();$registryFailed=@();$securityPassed=@();$securityFailed=@();$securityNotApplicable=@();$securityVerified=0
        $privacyPassed=@();$privacyFailed=@();$privacyNotApplicable=@();$privacyNotChecked=@()
        $privacyIntentForRun=[pscustomobject]@{xboxSettings=(New-NoIDXboxIntentProjection $script:Settings Privacy)}
        $appliedScopeRun=[bool]$Applied
        if($Scope -ceq 'Registry') {
            $computerSettings=$script:BaselineRecordingSetting
            . $script:XboxVerificationLoops['$computerSettings']
        }
        elseif($Scope -ceq 'Services') {
            $sectionName='Service General Setting';$gpoName='Baseline'
            $section=[pscustomobject]@{XboxGipSvc='StartupType=Disabled'}
            $allSecurityTemplateServices=$script:Services
            . $script:XboxVerificationLoops['$section.PSObject.Properties']
        }
        else {
            $target=@(Get-NoIDXboxIntentRegistryTargets Privacy)[0]
            if($Unrelated){$target=[pscustomobject]@{Path=(Get-NoIDXboxComponentCatalog).RemovalPolicyRoot+'\Microsoft.Copilot_8wekyb3d8bbwe';Name='RemovePackage'}}
            $check=[pscustomobject]@{Path=$target.Path;Name=$target.Name;Type='DWord';Value=1;Desc='App removal flag'}
            $privacyChecks=@($check);$selectedPrivacyCheckMap=@{(($check.Path+'|'+$check.Name).ToLowerInvariant())=$check}
            $privacyMode='Strict';$tier1PolicySelected=-not $Tier1Unselected;$privacyApplicability=$null
            . $script:XboxVerificationLoops['$privacyChecks']
        }
        [pscustomobject]@{Counts=$results;Passed=@($registryPassed)+@($securityPassed)+@($privacyPassed);Failed=@($registryFailed)+@($securityFailed)+@($privacyFailed)}
    }
}

Describe 'Xbox comparison labels have a closed module scope' {
    BeforeEach {
        $script:Settings=Get-XboxIntentSettings
        $script:Intent=Get-XboxIntentRecord
    }
    It 'accepts existing schema two and three with optional Xbox projections' {
        foreach($version in @(2,3)) {
            $script:Intent.schemaVersion=$version
            foreach($module in @('SecurityBaseline','Privacy')) {
                $script:Intent.modules.$module.intent|Add-Member NoteProperty xboxSettings (New-NoIDXboxIntentProjection $script:Settings $module) -Force
            }
            Assert-NoIDIntentState ($script:Intent|ConvertTo-Json -Depth 20|ConvertFrom-Json) | Should -BeTrue
        }
    }
    It 'does not carry game identities user identities app versions or unrelated dynamic entries' {
        $dynamic=$script:Settings.RegistryValues[-1]
        $dynamic.value=@('Foreign.App_publisher','Microsoft.XboxGamingOverlay_8wekyb3d8bbwe')
        $projection=New-NoIDXboxIntentProjection $script:Settings Privacy
        $projection.registryValues[-1].value | Should -Be @('Microsoft.XboxGamingOverlay_8wekyb3d8bbwe')
        ($projection|ConvertTo-Json -Depth 10) | Should -Not -Match 'Foreign|UserSid|PackageFullName|GamingServices'
        @($projection.registryValues).Count | Should -Be 5
    }
    It 'rejects extra targets flags wrong types unrelated services and duplicate identities' {
        foreach($change in @('Extra','WrongType','ForeignService','Duplicate','Dynamic')) {
            $projection=New-NoIDXboxIntentProjection $script:Settings SecurityBaseline
            switch($change) {
                Extra {$projection|Add-Member NoteProperty command 'bad'}
                WrongType {$projection.registryValues[0].value='1'}
                ForeignService {$projection.services[0].name='GamingServices'}
                Duplicate {$projection.services[0].name=$projection.services[1].name}
                Dynamic {$projection=New-NoIDXboxIntentProjection $script:Settings Privacy;$projection.registryValues[-1].value=@('Foreign.App_publisher')}
            }
            $module=if($change -ceq 'Dynamic'){'Privacy'}else{'SecurityBaseline'}
            {Assert-NoIDXboxIntentProjection $projection $module} | Should -Throw
        }
    }
    It 'represents absence without inventing a default' {
        $record=$script:Settings.RegistryValues[0]
        $record.valueExisted=$false;$record.originalName=$null;$record.type=$null;$record.value=$null
        $projection=New-NoIDXboxIntentProjection $script:Settings SecurityBaseline
        $projection.registryValues[0].present | Should -BeFalse
        $projection.registryValues[0].value | Should -BeNullOrEmpty
    }
}

Describe 'Xbox intent reconciliation follows verified evidence' {
    BeforeEach {
        $script:Settings=Get-XboxIntentSettings
        $script:Intent=Get-XboxIntentRecord
        $script:Published=$null
        $script:SourcePath=Join-Path $TestDrive 'session'
        $null=New-Item $script:SourcePath -ItemType Directory -Force
        Set-Content (Join-Path $script:SourcePath 'manifest.json') 'fixture manifest'
        Set-Content (Join-Path $script:SourcePath 'restore-receipt.json') 'fixture receipt'
        $script:Doc=[pscustomobject]@{SessionPath=$script:SourcePath;Manifest=[pscustomobject]@{sessionId='Session_20261001_000000_000_aaaaaaaa_QuickAction_Xbox';status='Applied'};PreState=[pscustomobject]@{targets=[pscustomobject]@{settings=$script:Settings}};PostState=[pscustomobject]@{targets=[pscustomobject]@{settings=$script:Settings}}}
        Mock Read-NoIDIntentState {if($script:Published){$script:Published}else{$script:Intent}}
        Mock Publish-NoIDIntentState {param($State) $script:Published=$State|ConvertTo-Json -Depth 20|ConvertFrom-Json}
        Mock Get-NoIDXboxSessionDocument {$script:Doc}
        Mock Get-SessionRestoreReceipt {$null}
        Mock Get-NoIDXboxSettingsState {$script:Settings}
        Mock Write-Log {}
    }
    It 'retains all non-Xbox decisions and untouched module provenance on Apply' {
        $edge=Get-QuickActionObjectSha256 $script:Intent.modules.EdgeHardening
        Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath | Should -BeTrue
        $script:Published.modules.Privacy.intent.mode | Should -BeExactly Strict
        $script:Published.modules.Privacy.intent.removeBloatwareApps | Should -BeTrue
        $script:Published.modules.SecurityBaseline.intent.smartScreenWarnMode | Should -BeTrue
        (Get-QuickActionObjectSha256 $script:Published.modules.EdgeHardening) | Should -BeExactly $edge
        $script:Published.engineContractFingerprint | Should -BeExactly ('b'*64)
        $script:Published.modules.SecurityBaseline.sourceKind | Should -BeExactly QuickActionApply
        $script:Published.modules.SecurityBaseline.sourceEvidenceSha256 | Should -BeExactly (Get-FileHash (Join-Path $script:SourcePath 'manifest.json')).Hash.ToLowerInvariant()
    }
    It 'does not invent module Apply records on a fresh machine' {
        Mock Read-NoIDIntentState {$null}
        Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath | Should -BeTrue
        Should -Invoke Publish-NoIDIntentState -Exactly 0
        Should -Invoke Get-NoIDXboxSettingsState -Exactly 0
    }
    It 'does not recreate a previously cleared module intent' {
        $script:Intent.modules.PSObject.Properties.Remove('Privacy')
        Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath | Should -BeTrue
        $script:Published.modules.PSObject.Properties.Name | Should -Not -Contain Privacy
    }
    It 'requires successful sealed Apply evidence and rejects an already restored Apply' {
        $script:Doc.Manifest.status='ApplyFailedSettingsRestored'
        {Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath} | Should -Throw '*sealed successful*'
        $script:Doc.Manifest.status='Applied'
        Mock Get-SessionRestoreReceipt {[pscustomobject]@{restoredScopes=@('action:Xbox')}}
        {Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath} | Should -Throw '*restored session*'
        Should -Invoke Publish-NoIDIntentState -Exactly 0
    }
    It 'requires a valid receipt for a settings-only recovery and binds its hash' {
        {Update-NoIDXboxIntentState -SourceKind QuickActionRestore -SessionPath $script:SourcePath} | Should -Throw '*validated settings receipt*'
        Mock Get-SessionRestoreReceipt {[pscustomobject]@{restoredScopes=@('action:Xbox')}}
        $script:Doc.Manifest.status='ApplyFailedSettingsRestoreFailed'
        Update-NoIDXboxIntentState -SourceKind QuickActionRestore -SessionPath $script:SourcePath | Should -BeTrue
        $script:Published.modules.Privacy.sourceKind | Should -BeExactly QuickActionRestore
        $script:Published.modules.Privacy.sourceEvidenceSha256 | Should -BeExactly (Get-FileHash (Join-Path $script:SourcePath 'restore-receipt.json')).Hash.ToLowerInvariant()
    }
    It 'rejects stale settings evidence before replacing saved intent' {
        $script:Doc.PostState.targets.settings=$script:Settings|ConvertTo-Json -Depth 20|ConvertFrom-Json
        $script:Settings.Services[0].startType='Disabled'
        {Update-NoIDXboxIntentState -SourceKind QuickActionApply -SessionPath $script:SourcePath} | Should -Throw '*no longer matches*'
        Should -Invoke Publish-NoIDIntentState -Exactly 0
    }
    It 'reports label persistence failure without undoing verified Windows changes' {
        Mock Publish-NoIDIntentState {throw 'Test disk error'}
        Update-NoIDXboxIntentAfterChange -SourceKind QuickActionApply -SessionPath $script:SourcePath | Should -Match 'saved report choices could not be updated'
        Should -Invoke Write-Log -Exactly 1 -ParameterFilter {$Level -ceq 'WARNING'}
    }
}

Describe 'Production verification checks the exact Xbox selection' {
    BeforeEach {
        $script:Settings=Get-XboxIntentSettings
        $script:Services=@([pscustomobject]@{Name='XboxGipSvc';StartType='Manual'})
        $script:Key=[pscustomobject]@{Name='AllowGameDVR';Kind='DWord';Value=1;Present=$true}
        $script:Key|Add-Member ScriptMethod GetValueNames {if($this.Present){@($this.Name)}else{@()}}
        $script:Key|Add-Member ScriptMethod GetValueKind {param($Name) $null=$Name; $this.Kind}
        $script:Key|Add-Member ScriptMethod GetValue {param($Name,$Default,$Options) $null=$Name,$Default,$Options; $this.Value}
        Mock Get-Item {$script:Key}
    }
    It 'passes the selected recording value and fails a different value or type' {
        (Invoke-XboxVerificationFixture Registry).Counts.Verified | Should -Be 1
        $script:Key.Value=0
        (Invoke-XboxVerificationFixture Registry).Counts.Failed | Should -Be 1
        $script:Key.Value=1;$script:Key.Kind='String'
        (Invoke-XboxVerificationFixture Registry).Counts.Failed | Should -Be 1
    }
    It 'checks service startup against SCM even when a policy export could be stale' {
        (Invoke-XboxVerificationFixture Services).Counts.Verified | Should -Be 1
        $script:Services[0].StartType='Disabled'
        (Invoke-XboxVerificationFixture Services).Counts.Failed | Should -Be 1
        $script:Services=@()
        (Invoke-XboxVerificationFixture Services).Counts.Failed | Should -Be 1
    }
    It 'accepts a proven absent service only if the recorded selection also had no service' {
        $script:Services=@()
        $service=$script:Settings.Services[0];$service.exists=$false;$service.startType=$null;$service.status=$null
        (Invoke-XboxVerificationFixture Services).Counts.NotApplicable | Should -Be 1
    }
    It 'passes an Xbox removal exception without weakening other app removal checks' {
        $script:Settings.RegistryValues[1].value=0
        $script:Key.Name='RemovePackage';$script:Key.Value=0
        (Invoke-XboxVerificationFixture Privacy).Counts.Verified | Should -Be 1
        (Invoke-XboxVerificationFixture Privacy -Unrelated).Counts.Failed | Should -Be 1
        (Invoke-XboxVerificationFixture Privacy -Applied).Counts.Failed | Should -Be 1
    }
    It 'retains unselected Tier 1 as excluded rather than a green Xbox exception' {
        (Invoke-XboxVerificationFixture Privacy -Tier1Unselected).Counts.NotChecked | Should -Be 1
    }
    It 'compares absence exactly and propagates registry access failures' {
        $expected=(New-NoIDXboxIntentProjection $script:Settings SecurityBaseline).registryValues[0]
        $expected.present=$false;$expected.value=$null;$script:Key.Present=$false
        (Get-NoIDXboxIntentRegistryResult $expected).Passed | Should -BeTrue
        $script:Key.Present=$true
        (Get-NoIDXboxIntentRegistryResult $expected).Passed | Should -BeFalse
        Mock Get-Item {throw 'Access denied'}
        {Get-NoIDXboxIntentRegistryResult $expected} | Should -Throw '*Access denied*'
    }
    It 'does not turn unrelated or duplicate dynamic entries into passing evidence' {
        $expected=(New-NoIDXboxIntentProjection $script:Settings Privacy).registryValues[-1]
        $script:Key.Name='DynamicRemovalList';$script:Key.Kind='MultiString';$script:Key.Value=@()
        (Get-NoIDXboxIntentRegistryResult $expected).Passed | Should -BeTrue
        $script:Key.Value=@('Foreign.App_publisher')
        (Get-NoIDXboxIntentRegistryResult $expected).Passed | Should -BeFalse
        $family='Microsoft.XboxGamingOverlay_8wekyb3d8bbwe';$expected.value=@($family)
        $script:Key.Value=@($family,$family)
        (Get-NoIDXboxIntentRegistryResult $expected).Passed | Should -BeFalse
    }
}
