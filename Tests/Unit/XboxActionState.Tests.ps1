#Requires -Version 5.1

BeforeAll {
    $repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($file in @('Runtime','Rollback','IntentState','QuickActions','XboxComponents','XboxSettings','XboxAppRemoval','XboxAppWorker','XboxActionState','XboxActionApply','XboxActionSessions','XboxActionRestore','XboxActionTransaction')) {
        . (Join-Path $repoRoot "Core\$file.ps1")
    }
    function Get-FrameworkVersion { '2.2.6' }
    function Get-XboxActionTargets {
        param([switch]$Disabled)
        $catalog=Get-NoIDXboxComponentCatalog
        $values=@(Get-NoIDXboxSettingsRegistryTargets|ForEach-Object {
            [pscustomobject][ordered]@{kind='RegistryValue';path=$_.Path;name=$_.Name;keyExisted=$true;valueExisted=$false;originalName=$null;type=$null;value=$null;absentAncestorKeys=@()}
        })
        $values[0].valueExisted=$true;$values[0].originalName=$values[0].name;$values[0].type='DWord';$values[0].value=[int](-not $Disabled)
        $services=@($catalog.Services|ForEach-Object {
            [pscustomobject][ordered]@{kind='Service';name=$_;exists=$true;status='Stopped';startType=$(if($Disabled){'Disabled'}else{'Manual'});delayedAutoStartExists=$false;delayedAutoStart=$null}
        })
        $task=[pscustomobject][ordered]@{TaskPath=$catalog.TaskPath;TaskName=$catalog.TaskName;Exists=$true;Enabled=(-not $Disabled)}
        $sid='S-1-5-21-1-2-3-1001'
        [pscustomobject][ordered]@{
            userSid=$sid;sessionId=1
            settings=[pscustomobject][ordered]@{SchemaVersion=1;RegistryValues=$values;Services=$services;Task=$task}
            components=[pscustomobject][ordered]@{
                UserSid=$sid
                Apps=@($catalog.Apps|ForEach-Object {[pscustomobject]@{Name=$_.Name;Present=(-not $Disabled);Healthy=(-not $Disabled)}})
                RemovablePackages=@(if(-not $Disabled){$catalog.Apps|ForEach-Object {[pscustomobject]@{AppName=$_.Name;PackageFullName=$_.Name+'_1.2.3.4_x64__8wekyb3d8bbwe';PackageFamilyName=$_.PackageFamilyName}}})
                Services=@($services|ForEach-Object {[pscustomobject]@{Name=$_.name;Exists=$_.exists;StartType=$_.startType;Status=$_.status}})
                Task=$task;RecordingAllowed=(-not $Disabled);RecordingPolicySupported=$true;RemovalBlocked=$false
                Applicability=[pscustomobject]@{RecordingPolicySupported=$true;RemovalPolicySupported=$false;ManagementStateKnown=$true;DomainJoined=$false;MdmRegistered=$false}
                RecordingPolicy=$values[0]
                RemovalPolicyEnabled=[pscustomobject]@{path=$catalog.RemovalPolicyRoot;name='Enabled';valueExisted=$false;type=$null;value=$null}
                RemovalPolicyValues=@($values|Where-Object name -CEQ RemovePackage)
                DynamicRemovalList=$values[-1]
            }
        }
    }
    Mock Read-NoIDIntentState { $null }
}

Describe 'Xbox switch observations and identity' {
    It 'accepts complete enabled disabled and JSON observations' {
        foreach($disabled in @($false,$true)) {
            $targets=Get-XboxActionTargets -Disabled:$disabled
            {Assert-NoIDXboxActionTargets $targets} | Should -Not -Throw
            {Assert-NoIDXboxActionTargets (ConvertFrom-Json (ConvertTo-Json $targets -Depth 20))} | Should -Not -Throw
        }
        @(Get-NoIDXboxActionTargetIds).Count | Should -Be 24
        @(Get-NoIDXboxActionTargetIds | Where-Object {$_ -match 'GamingServices|SomeGame'}).Count | Should -Be 0
    }
    It 'rejects different user bindings malformed sessions and extra data' {
        foreach($change in @('User','Session','Extra','Scope')) {
            $targets=Get-XboxActionTargets
            switch($change) {
                'User' {$targets.components.UserSid='S-1-5-21-1-2-3-1002'}
                'Session' {$targets.sessionId='1'}
                'Extra' {$targets|Add-Member NoteProperty Command 'bad'}
                'Scope' {$targets.components|Add-Member NoteProperty Command 'bad'}
            }
            {Assert-NoIDXboxActionTargets $targets} | Should -Throw
        }
    }
    It 'rejects inconsistent app registry service task and recording observations' {
        foreach($change in @('App','Registry','Service','Task','Recording','Edition','RemovalSummary')) {
            $targets=ConvertFrom-Json (ConvertTo-Json (Get-XboxActionTargets) -Depth 20)
            switch($change) {
                'App' {$targets.components.RemovablePackages=@()}
                'Registry' {$targets.settings.RegistryValues[0].value=0}
                'Service' {$targets.settings.Services[0].startType='Disabled'}
                'Task' {$targets.settings.Task.Enabled=$false}
                'Recording' {$targets.components.RecordingAllowed=$false}
                'Edition' {$targets.components.RecordingPolicySupported=$false}
                'RemovalSummary' {$targets.components.RemovalBlocked=$true}
            }
            {Assert-NoIDXboxActionTargets $targets} | Should -Throw
        }
    }
}

Describe 'Xbox switch read behavior' {
    BeforeEach {
        $script:Targets=Get-XboxActionTargets
        $script:User=[pscustomobject]@{Sid=$script:Targets.userSid;SessionId=1}
        Mock Get-PrivacyUserContext {$script:User}
        Mock Get-NoIDXboxComponentSnapshot {$script:Targets.components}
        Mock Get-NoIDXboxSettingsState {$script:Targets.settings}
        Mock Add-AppxPackage {throw 'Query must not install apps'}
        Mock Remove-AppxPackage {throw 'Query must not remove apps'}
        Mock Set-Service {throw 'Query must not write services'}
        Mock New-QuickActionPreparedSession {throw 'Query must not create a backup'}
    }
    It 'returns measured state without app writes service writes or backups' {
        $state=Get-NoIDXboxActionState
        $state.state | Should -BeExactly Enable
        $state.actionable | Should -BeTrue
        $state.fingerprint | Should -Match '^[0-9a-f]{64}$'
        Should -Invoke Add-AppxPackage -Exactly 0
        Should -Invoke Remove-AppxPackage -Exactly 0
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke New-QuickActionPreparedSession -Exactly 0
    }
    It 'keeps mixed state actionable and fingerprints package version changes' {
        $script:Targets.components.Apps[0].Healthy=$false
        $first=Get-NoIDXboxActionState
        $first.state | Should -BeExactly Mixed
        $first.actionable | Should -BeTrue
        $script:Targets.components.RemovablePackages[0].PackageFullName=$script:Targets.components.RemovablePackages[0].PackageFullName.Replace('1.2.3.4','1.2.3.5')
        (Get-NoIDXboxActionState).fingerprint | Should -Not -Be $first.fingerprint
    }
    It 'makes managed or unknown ownership non-actionable with a reason' {
        foreach($field in @('ManagementStateKnown','DomainJoined','MdmRegistered')) {
            $original=$script:Targets.components.Applicability.$field
            $script:Targets.components.Applicability.$field=-not $original
            $state=Get-NoIDXboxActionState
            $state.actionable | Should -BeFalse
            $state.reason | Should -Not -BeNullOrEmpty
            $script:Targets.components.Applicability.$field=$original
        }
    }
    It 'does not hide provider failures as disabled state' {
        Mock Get-NoIDXboxComponentSnapshot {throw 'AppX provider failed'}
        {Get-NoIDXboxActionState} | Should -Throw '*provider failed*'
    }
    It 'rejects a desktop switch during the query' {
        $script:Calls=0
        Mock Get-PrivacyUserContext {
            $script:Calls++
            [pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=$script:Calls}
        }
        {Get-NoIDXboxActionState} | Should -Throw '*identity changed*'
    }
}


Describe 'Xbox action evidence and mutation gate' {
    BeforeEach {
        $script:Targets=Get-XboxActionTargets
        $script:User=[pscustomobject]@{Sid=$script:Targets.userSid;SessionId=1}
        $script:State=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets $script:Targets
        Mock Get-NoIDXboxActionState {$script:State}
        Mock Get-PrivacyUserContext {$script:User}
        Mock Invoke-NoIDXboxSettingsApply {}
        Mock Get-NoIDXboxSettingsState {$script:Targets.settings}
        Mock Invoke-NoIDXboxAppRemoval {[pscustomobject]@{Success=$true}}
        Mock Invoke-NoIDXboxAppRecovery {[pscustomobject]@{Success=$true}}
    }
    It 'accepts a valid action artifact and rejects changed fingerprints and target identities' {
        {Assert-NoIDXboxActionState $script:State} | Should -Not -Throw
        $copy=ConvertFrom-Json (ConvertTo-Json $script:State -Depth 20)
        $copy.targetIds[0]='registry:HKLM:\SOFTWARE\Other::Value'
        {Assert-NoIDXboxActionState $copy} | Should -Throw '*exact target set*'
        $copy=ConvertFrom-Json (ConvertTo-Json $script:State -Depth 20)
        $copy.fingerprint='0'*64
        {Assert-NoIDXboxActionState $copy} | Should -Throw '*fingerprint*'
        $copy=ConvertFrom-Json (ConvertTo-Json $script:State -Depth 20)
        $copy.state='Disable'
        {Assert-NoIDXboxActionState $copy} | Should -Throw '*observations*'
    }
    It 'rejects stale versions before changing any settings or apps' {
        $before=ConvertFrom-Json (ConvertTo-Json $script:State -Depth 20)
        $script:Targets.components.RemovablePackages[0].PackageFullName=$script:Targets.components.RemovablePackages[0].PackageFullName.Replace('1.2.3.4','1.2.3.5')
        $script:State=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets $script:Targets
        {Invoke-NoIDXboxActionScopeApply -PreState $before -DesiredState Disable -Confirm:$false} | Should -Throw '*changed after it was displayed*'
        Should -Invoke Invoke-NoIDXboxSettingsApply -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
    }
    It 'returns a no-op without launching app workers or rewriting settings' {
        $result=Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Enable -Confirm:$false
        $result.Changed | Should -BeFalse
        $result.AppResult | Should -BeNullOrEmpty
        Should -Invoke Invoke-NoIDXboxSettingsApply -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
    }
    It 'keeps the six sealed removal identities and verifies the final off state' {
        $script:Calls=0
        Mock Get-NoIDXboxActionState {
            $script:Calls++
            if($script:Calls -eq 1){return $script:State}
            Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        }
        $result=Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Disable -Confirm:$false
        $result.Changed | Should -BeTrue
        $result.PostState.state | Should -BeExactly Disable
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 1 -ParameterFilter {$Entries.Count -eq 6 -and $User.Sid -ceq $script:User.Sid}
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
    }
    It 'reports partial app failures separately from settings restoration' {
        Mock Invoke-NoIDXboxAppRemoval {[pscustomobject]@{Success=$false}}
        try {
            Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Disable -Confirm:$false
            throw 'Expected partial failure'
        }catch{
            $_.Exception.Message | Should -Match 'did not complete'
            $_.Exception.Data['AppChangesIncomplete'] | Should -BeTrue
            $_.Exception.Data['WorkerQuiesced'] | Should -BeTrue
        }
    }
    It 'propagates an unquiesced worker without declaring rollback safe' {
        Mock Invoke-NoIDXboxAppRemoval {
            $failure=[InvalidOperationException]::new('Worker still active')
            $failure.Data['WorkerQuiesced']=$false
            throw $failure
        }
        try {
            Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Disable -Confirm:$false
            throw 'Expected worker failure'
        }catch{
            $_.Exception.Message | Should -Match 'Worker still active'
            $_.Exception.Data['WorkerQuiesced'] | Should -BeFalse
        }
    }
    It 'rejects false app success if independent readback remains enabled' {
        {Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Disable -Confirm:$false} | Should -Throw '*did not reach*'
    }
    It 'honors WhatIf before settings or apps are changed' {
        {Invoke-NoIDXboxActionScopeApply -PreState $script:State -DesiredState Disable -WhatIf} | Should -Throw '*not confirmed*'
        Should -Invoke Invoke-NoIDXboxSettingsApply -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
    }
}


Describe 'Explicit Xbox settings-only session contract' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
    }
    It 'seals complete observations with explicit settings-only restore and keeps schema 3 unchanged' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $script:QuickActionSchemaVersion | Should -Be 3
        {Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath} | Should -Throw '*non-restorable*'
        $doc=Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false
        $doc.Manifest.schemaVersion | Should -Be 4
        $doc.Manifest.restoreMode | Should -BeExactly SettingsOnly
        $doc.PreState.fingerprint | Should -BeExactly $script:Before.fingerprint
        $doc.PostState.fingerprint | Should -BeExactly $script:After.fingerprint
        @(Get-ChildItem $prepared.SessionPath -File).Count | Should -Be 3
    }
    It 'creates no session for unchanged state or WhatIf' {
        {New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Enable -BackupDirectory $script:SessionRoot -Confirm:$false} | Should -Throw '*unchanged*'
        New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -WhatIf
        Test-Path $script:SessionRoot | Should -BeFalse
    }
    It 'rejects an output path outside the prepared session before writing' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $external=Join-Path $TestDrive 'foreign-output.json'
        $prepared.ManifestPath=$external
        {Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false} | Should -Throw '*external output path*'
        Test-Path $external | Should -BeFalse
        Test-Path (Join-Path $prepared.SessionPath 'poststate.json') | Should -BeFalse
    }
    It 'refuses to seal a different user before publishing any poststate' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $targets=Get-XboxActionTargets -Disabled
        $targets.userSid='S-1-5-21-1-2-3-1002';$targets.components.UserSid=$targets.userSid
        $foreign=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets $targets
        {Complete-NoIDXboxSession -PreparedSession $prepared -PostState $foreign -Confirm:$false} | Should -Throw '*different or incomplete*'
        Test-Path (Join-Path $prepared.SessionPath 'poststate.json') | Should -BeFalse
        (Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath -AllowPrepared).Manifest.status | Should -BeExactly Prepared
    }
    It 'rejects edited artifacts and undeclared files in a sealed session' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $null=Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false
        $foreign=Join-Path $prepared.SessionPath 'extra.txt';Set-Content $foreign 'unexpected'
        {Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath} | Should -Throw '*undeclared*'
        Remove-Item $foreign
        Add-Content $prepared.PrePath ' '
        {Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath} | Should -Throw '*integrity*'
    }
    It 'rejects a substituted restore mode or schema even with valid state hashes' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $null=Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false
        $raw=Get-Content $prepared.ManifestPath -Raw -Encoding UTF8
        foreach($field in @('restoreMode','schemaVersion','actionId')) {
            $manifest=ConvertFrom-Json $raw
            switch($field){'restoreMode'{$manifest.restoreMode='AppsAndSettings'};'schemaVersion'{$manifest.schemaVersion=3};'actionId'{$manifest.actionId='SmartScreen'}}
            $null=Write-AtomicUtf8File -Path $prepared.ManifestPath -Content (ConvertTo-QuickActionCanonicalJson $manifest)
            {Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath} | Should -Throw
        }
    }
    It 'binds supplied manifest metadata to the actual sealed file' {
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $doc=Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false
        $doc.Manifest.frameworkVersion='9.9.9'
        {Get-NoIDXboxSessionDocument -SessionPath $prepared.SessionPath -Manifest $doc.Manifest} | Should -Throw '*on-disk*'
    }
}


Describe 'Xbox settings-only restore transaction' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        $script:Prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $script:Document=Complete-NoIDXboxSession -PreparedSession $script:Prepared -PostState $script:After -Confirm:$false
        $script:LiveSettings=$script:After.targets.settings
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=2}}
        Mock Assert-NoIDXboxUnmanagedDevice {}
        Mock Assert-NoIDXboxWorkersIdle {}
        Mock Get-NoIDXboxSettingsState {$script:LiveSettings}
        Mock Restore-NoIDXboxSettingsState {param($State) $script:LiveSettings=$State}
        Mock Invoke-NoIDXboxAppRemoval {throw 'Settings restore must not remove apps'}
        Mock Invoke-NoIDXboxAppRecovery {throw 'Settings restore must not install apps'}
    }
    It 'restores exact configuration after a new login while leaving apps unchanged' {
        $sealed=@(Get-ChildItem $script:Prepared.SessionPath -File|Sort-Object Name|ForEach-Object {(Get-FileHash $_.FullName).Hash})
        Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:Before.targets.settings)
        (Get-SessionRestoreReceipt -SessionPath $script:Prepared.SessionPath -Manifest $script:Document.Manifest).restoredScopes | Should -Contain 'action:Xbox'
        $after=@(Get-ChildItem $script:Prepared.SessionPath -File|Where-Object Name -NE restore-receipt.json|Sort-Object Name|ForEach-Object {(Get-FileHash $_.FullName).Hash})
        ($after -join ',') | Should -BeExactly ($sealed -join ',')
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
    }
    It 'repairs the receipt after interrupted publication without rewriting live settings' {
        $script:LiveSettings=$script:Before.targets.settings
        Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        Test-Path (Join-Path $script:Prepared.SessionPath 'restore-receipt.json') | Should -BeTrue
    }
    It 'does not restore twice or rewrite newer state after a validated receipt' {
        $null=Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false
        $script:LiveSettings=$script:After.targets.settings
        Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 1
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:After.targets.settings)
    }
    It 'rejects a different desktop user and newer settings before any write' {
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1002';SessionId=1}}
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*different desktop user*'
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=1}}
        $script:LiveSettings=ConvertFrom-Json (ConvertTo-Json $script:After.targets.settings -Depth 20)
        $script:LiveSettings.Services[0].startType='Automatic'
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*newer settings*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'compensates a failed receipt write without falsely recording a completed restore' {
        Mock Write-SessionRestoreReceipt {throw 'Disk full'}
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*receipt publication failed*'
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:After.targets.settings)
        Test-Path (Join-Path $script:Prepared.SessionPath 'restore-receipt.json') | Should -BeFalse
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 2
    }
    It 'accepts a receipt that was atomically published before a transient read failure' {
        $script:ActualReceiptWriter=${function:Write-SessionRestoreReceipt}
        Mock Write-SessionRestoreReceipt {
            param($SessionPath,$Manifest,$Scopes)
            $null=& $script:ActualReceiptWriter -SessionPath $SessionPath -Manifest $Manifest -Scopes $Scopes -Confirm:$false
            throw 'Transient read error after publication'
        }
        Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 1
    }
    It 'retains restored settings when an unresolved receipt prevents safe compensation' {
        Mock Write-SessionRestoreReceipt {
            param($SessionPath)
            $null=New-Item (Join-Path $SessionPath 'restore-receipt.json') -ItemType Directory
            throw 'Publication failed'
        }
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*retained because receipt status is uncertain*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 1
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:Before.targets.settings)
    }
    It 'never overwrites unexplained partial state during compensation' {
        Mock Restore-NoIDXboxSettingsState {
            $script:LiveSettings=ConvertFrom-Json (ConvertTo-Json $script:After.targets.settings -Depth 20)
            $script:LiveSettings.Services[0].startType='Automatic'
            throw 'Interrupted setting write'
        }
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*cannot be safely compensated*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 1
    }
    It 'refuses restore while a previous app worker remains active' {
        Mock Assert-NoIDXboxWorkersIdle {throw 'A previous NoID app operation is still running'}
        {Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*still running*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        Test-Path (Join-Path $script:Prepared.SessionPath 'restore-receipt.json') | Should -BeFalse
    }
    It 'honors WhatIf without settings changes or a receipt' {
        Restore-NoIDXboxSession -SessionPath $script:Prepared.SessionPath -WhatIf | Should -BeFalse
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        Test-Path (Join-Path $script:Prepared.SessionPath 'restore-receipt.json') | Should -BeFalse
    }
}

Describe 'Xbox restore ordering with both owning modules' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        $prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $script:Document=Complete-NoIDXboxSession -PreparedSession $prepared -PostState $script:After -Confirm:$false
        $script:OtherPath=Join-Path $script:SessionRoot 'Session_other'
        $null=New-Item $script:OtherPath -ItemType Directory
        $script:Other=[ordered]@{schemaVersion=2;sessionId='Session_other';timestamp=([datetime]::Parse($script:Document.Manifest.timestamp).AddSeconds(1).ToString('o'));restorable=$true;modules=@()}
    }
    It 'blocks a newer Privacy or SecurityBaseline session until every overlapping scope is receipted' {
        $script:Other.modules=@([pscustomobject]@{name='Privacy'},[pscustomobject]@{name='SecurityBaseline'})
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Throw '*newer overlapping*'
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('module:Privacy') -Confirm:$false
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Throw '*newer overlapping*'
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('module:SecurityBaseline') -Confirm:$false
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Not -Throw
    }
    It 'allows unrelated newer module sessions' {
        $script:Other.modules=@([pscustomobject]@{name='DNS'})
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Not -Throw
    }
    It 'makes newer Xbox changes block both Privacy and SecurityBaseline module restore' {
        $script:Other.schemaVersion=4;$script:Other['recordType']='QuickActionSession';$script:Other['actionId']='Xbox'
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        foreach($name in @('Privacy','SecurityBaseline','privacy','SECURITYBASELINE')) {
            {Assert-NoIDXboxRestoreOrder -SelectedDocument $script:Document -ModuleNames @($name)} | Should -Throw '*newer overlapping*'
        }
        {Assert-NoIDXboxRestoreOrder -SelectedDocument $script:Document -ModuleNames @('DNS')} | Should -Not -Throw
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('action:Xbox') -Confirm:$false
        {Assert-NoIDXboxRestoreOrder -SelectedDocument $script:Document -ModuleNames @('Privacy','SecurityBaseline')} | Should -Not -Throw
    }
    It 'does not accept forged or malformed receipts as proof of restored overlap' {
        $script:Other.modules=@([pscustomobject]@{name='Privacy'})
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('module:Privacy') -Confirm:$false
        $script:Other.restorable=$false
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Throw '*order cannot be verified*'
    }
    It 'respects case-insensitive module identities without relaxing Xbox receipt identity' {
        $script:Other.modules=@([pscustomobject]@{name='privacy'})
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Throw '*newer overlapping*'
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('module:Privacy') -Confirm:$false
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Not -Throw
        $script:Other.schemaVersion=4;$script:Other['recordType']='QuickActionSession';$script:Other['actionId']='Xbox'
        $null=Write-AtomicUtf8File -Path (Join-Path $script:OtherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $script:Other)
        Remove-Item (Join-Path $script:OtherPath 'restore-receipt.json')
        $null=Write-SessionRestoreReceipt -SessionPath $script:OtherPath -Manifest $script:Other -Scopes @('action:xbox') -Confirm:$false
        {Assert-NoIDXboxRestoreOrder $script:Document} | Should -Throw '*newer overlapping*'
    }
}


Describe 'Xbox complete mutation transaction' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        $script:LiveSettings=$script:Before.targets.settings
        Mock Assert-NoIDXboxWorkersIdle {}
        Mock Get-NoIDXboxActionState {$script:Before}
        Mock Get-NoIDXboxSettingsState {$script:LiveSettings}
        Mock Restore-NoIDXboxActionSettings {
            param($Settings,$ExpectedCurrentSettings)
            (Get-QuickActionObjectSha256 $ExpectedCurrentSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:LiveSettings)
            $script:LiveSettings=$Settings
            $true
        }
        Mock Invoke-NoIDXboxActionScopeApply {
            $script:LiveSettings=$script:After.targets.settings
            [pscustomobject]@{Changed=$true;PostState=$script:After}
        }
        function Invoke-XboxTransactionTest {
            param([string]$DesiredState='Disable',[switch]$Simulate)
            Invoke-NoIDXboxAction -DesiredState $DesiredState -ExpectedFingerprint $script:Before.fingerprint -BackupDirectory $script:SessionRoot -Confirm:$false -WhatIf:$Simulate
        }
    }
    It 'seals a real session and returns only a verified successful result' {
        $result=Invoke-XboxTransactionTest
        $result.success | Should -BeTrue
        $result.status | Should -BeExactly Applied
        $result.mutated | Should -BeTrue
        $result.verified | Should -BeTrue
        $doc=Get-NoIDXboxSessionDocument $result.backupPath
        $doc.Manifest.restoreMode | Should -BeExactly SettingsOnly
        $doc.PostState.fingerprint | Should -BeExactly $script:After.fingerprint
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
    }
    It 'creates no record or worker for an unchanged setting' {
        $result=Invoke-XboxTransactionTest -DesiredState Enable
        $result.status | Should -BeExactly NoChange
        $result.backupPath | Should -BeExactly ''
        Test-Path $script:SessionRoot | Should -BeFalse
        Should -Invoke Invoke-NoIDXboxActionScopeApply -Exactly 0
    }
    It 'rejects stale display evidence before creating any record or changing settings' {
        Mock Get-NoIDXboxActionState {$script:After}
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly Failed
        $result.mutated | Should -BeFalse
        Test-Path $script:SessionRoot | Should -BeFalse
        Should -Invoke Invoke-NoIDXboxActionScopeApply -Exactly 0
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
    }
    It 'closes an unchanged prepared record without overwriting intervening settings' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $script:LiveSettings=$script:After.targets.settings
            throw 'State changed between preparation and write'
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly Failed
        $result.mutated | Should -BeFalse
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
        $doc=Get-NoIDXboxSessionDocument $result.backupPath -AllowIncomplete
        $doc.Manifest.status | Should -BeExactly Rejected
        (Get-SessionRestoreReceipt -SessionPath $doc.SessionPath -Manifest $doc.Manifest).restoredScopes | Should -Contain 'action:Xbox'
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:After.targets.settings)
    }
    It 'reports settings-only compensation after partial app changes and closes only that scope' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $script:LiveSettings=$script:After.targets.settings
            $failureException=[InvalidOperationException]::new('App operation failed')
            $failureException.Data['XboxSettingsWriteStarted']=$true
            $failureException.Data['XboxAppsMayHaveChanged']=$true
            $failureException.Data['WorkerQuiesced']=$true
            $failureException.Data['XboxSettingsAfterApply']=$script:After.targets.settings
            throw $failureException
        }
        $result=Invoke-XboxTransactionTest
        $result.success | Should -BeFalse
        $result.status | Should -BeExactly ApplyFailedSettingsRestored
        $result.error | Should -Match 'Apps may have changed'
        $result.error | Should -Match 'were not restored'
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 1
        $doc=Get-NoIDXboxSessionDocument $result.backupPath -AllowIncomplete
        $doc.Manifest.status | Should -BeExactly ApplyFailedSettingsRestored
        (Get-SessionRestoreReceipt -SessionPath $doc.SessionPath -Manifest $doc.Manifest).restoredScopes | Should -Contain 'action:Xbox'
        {Get-NoIDXboxSessionDocument $result.backupPath} | Should -Throw '*non-restorable*'
    }
    It 'does not restore while an app worker might still be changing the machine' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $failureException=[InvalidOperationException]::new('Unstopped worker')
            $failureException.Data['XboxSettingsWriteStarted']=$true
            $failureException.Data['XboxAppsMayHaveChanged']=$true
            $failureException.Data['WorkerQuiesced']=$false
            throw $failureException
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestoreFailed
        $result.error | Should -Match 'not been confirmed stopped'
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
        Test-Path (Join-Path $result.backupPath 'restore-receipt.json') | Should -BeFalse
    }
    It 'does not overwrite unverified partial settings even after a writer started' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $script:LiveSettings=$script:After.targets.settings
            $failureException=[InvalidOperationException]::new('Interrupted settings write')
            $failureException.Data['XboxSettingsWriteStarted']=$true
            $failureException.Data['WorkerQuiesced']=$true
            throw $failureException
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestoreFailed
        $result.error | Should -Match 'cannot be attributed'
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
    }
    It 'does not overwrite a later external edit on the compensation path' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $script:LiveSettings=ConvertFrom-Json (ConvertTo-Json $script:After.targets.settings -Depth 20)
            $script:LiveSettings.Services[0].startType='Automatic'
            $failureException=[InvalidOperationException]::new('App failed after external edit')
            $failureException.Data['XboxSettingsWriteStarted']=$true
            $failureException.Data['WorkerQuiesced']=$true
            $failureException.Data['XboxSettingsAfterApply']=$script:After.targets.settings
            throw $failureException
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestoreFailed
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
    }
    It 'seals a settings write failure that independently still matches the original state' {
        Mock Invoke-NoIDXboxActionScopeApply {
            $failureException=[InvalidOperationException]::new('Native writer refused change')
            $failureException.Data['XboxSettingsWriteStarted']=$true
            $failureException.Data['WorkerQuiesced']=$true
            throw $failureException
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestored
        $result.error | Should -Not -Match 'Apps may have changed'
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 0
    }
    It 'keeps both causes visible if settings recovery also fails' {
        Mock Complete-NoIDXboxSession {throw 'Seal failed'}
        Mock Restore-NoIDXboxActionSettings {throw 'Settings denied'}
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestoreFailed
        $result.error | Should -Match 'Seal failed'
        $result.error | Should -Match 'Settings denied'
    }
    It 'compensates failed sealing without claiming the apps were rolled back' {
        Mock Complete-NoIDXboxSession {throw 'Seal failed'}
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestored
        $result.error | Should -Match 'Apps may have changed'
        Should -Invoke Restore-NoIDXboxActionSettings -Exactly 1
    }
    It 'records a failure after completed publication while keeping its sealed artifacts' {
        $script:ActualComplete=${function:Complete-NoIDXboxSession}
        Mock Complete-NoIDXboxSession {
            param($PreparedSession,$PostState)
            $null=& $script:ActualComplete -PreparedSession $PreparedSession -PostState $PostState -Confirm:$false
            throw 'Read failed after completed publication'
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestored
        $doc=Get-NoIDXboxSessionDocument $result.backupPath -AllowIncomplete
        $doc.Manifest.status | Should -BeExactly ApplyFailedSettingsRestored
        $doc.PostState.fingerprint | Should -BeExactly $script:After.fingerprint
        (Get-SessionRestoreReceipt -SessionPath $doc.SessionPath -Manifest $doc.Manifest).restoredScopes | Should -Contain 'action:Xbox'
    }
    It 'seals interrupted poststate observations as failed and closes settings recovery' {
        Mock Complete-NoIDXboxSession {
            param($PreparedSession,$PostState)
            $null=Write-AtomicUtf8File -Path (Join-Path $PreparedSession.SessionPath 'poststate.json') -Content (ConvertTo-QuickActionCanonicalJson $PostState)
            throw 'Manifest publication failed'
        }
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly ApplyFailedSettingsRestored
        $result.error | Should -Not -Match 'Failure record could not be completed'
        Test-Path (Join-Path $result.backupPath 'poststate.json') | Should -BeTrue
        Test-Path (Join-Path $result.backupPath 'restore-receipt.json') | Should -BeTrue
        $doc=Get-NoIDXboxSessionDocument $result.backupPath -AllowIncomplete
        $doc.Manifest.status | Should -BeExactly ApplyFailedSettingsRestored
        $doc.PostState.fingerprint | Should -BeExactly $script:After.fingerprint
    }
    It 'reports missing failure receipts without inventing closure' {
        Mock Invoke-NoIDXboxActionScopeApply {throw 'Stale second read'}
        Mock Write-SessionRestoreReceipt {throw 'Receipt disk full'}
        $result=Invoke-XboxTransactionTest
        $result.error | Should -Match 'Receipt disk full'
        Test-Path (Join-Path $result.backupPath 'restore-receipt.json') | Should -BeFalse
    }
    It 'refuses an active prior worker before creating a record' {
        Mock Assert-NoIDXboxWorkersIdle {throw 'A previous NoID app operation is still running'}
        $result=Invoke-XboxTransactionTest
        $result.status | Should -BeExactly Failed
        Test-Path $script:SessionRoot | Should -BeFalse
        Should -Invoke Invoke-NoIDXboxActionScopeApply -Exactly 0
    }
    It 'honors WhatIf without creating a session or invoking the mutation scope' {
        $result=Invoke-XboxTransactionTest -Simulate
        $result.status | Should -BeExactly Failed
        Test-Path $script:SessionRoot | Should -BeFalse
        Should -Invoke Invoke-NoIDXboxActionScopeApply -Exactly 0
    }
}

Describe 'Xbox active-worker guard' {
    It 'rejects only active exact NoID app-worker names and fails if enumeration is unavailable' {
        Mock Get-ScheduledTask {
            @([pscustomobject]@{TaskName=('NoID-XboxRecovery-'+('a'*32));State='Ready'},
              [pscustomobject]@{TaskName='UnrelatedTask';State='Running'},
              [pscustomobject]@{TaskName='NoID-XboxRecovery-other';State='Running'})
        }
        {Assert-NoIDXboxWorkersIdle} | Should -Not -Throw
        foreach($prefix in @('XboxRecovery','PrivacyAppx')) {
            foreach($state in @('Running','Queued','Unknown',$null)) {
                Mock Get-ScheduledTask {[pscustomobject]@{TaskName=('NoID-'+$prefix+'-'+('a'*32));State=$state}}
                {Assert-NoIDXboxWorkersIdle} | Should -Throw '*still running*'
            }
        }
        Mock Get-ScheduledTask {throw 'Scheduler unavailable'}
        {Assert-NoIDXboxWorkersIdle} | Should -Throw '*Scheduler unavailable*'
    }
}


Describe 'Xbox canonical Shell integration' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        $script:Prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $script:Document=Complete-NoIDXboxSession -PreparedSession $script:Prepared -PostState $script:After -Confirm:$false
        $script:LiveSettings=$script:After.targets.settings
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=2}}
        Mock Assert-NoIDXboxUnmanagedDevice {}
        Mock Assert-NoIDXboxWorkersIdle {}
        Mock Get-NoIDXboxSettingsState {$script:LiveSettings}
        Mock Restore-NoIDXboxSettingsState {param($State) $script:LiveSettings=$State}
        Mock Get-NoIDXboxComponentSnapshot {throw 'Settings listing/restore must not query apps'}
        Mock Invoke-NoIDXboxAppRecovery {throw 'Settings listing/restore must not install apps'}
        Mock Invoke-NoIDXboxAppRemoval {throw 'Settings listing/restore must not remove apps'}
    }
    It 'defines Xbox with both module restore scopes without changing the legacy schema' {
        @(Get-QuickActionDefinitions).Count | Should -Be 10
        (Get-QuickActionDefinition Xbox).States | Should -Be @('Enable','Disable')
        (Get-QuickActionModuleRestoreScopes Xbox) | Should -Be @('Privacy','SecurityBaseline')
        $script:QuickActionSchemaVersion | Should -Be 3
    }
    It 'queries Xbox independently without unrelated Defender or firewall calls' {
        Mock Get-NoIDXboxActionState {$script:Before}
        Mock Get-MpPreference {throw 'Must not call Defender'}
        Mock Get-QuickActionNamedFirewallRuleSnapshot {throw 'Must not call Firewall'}
        $states=@(Get-AllQuickActionStates -ActionIds @('Xbox'))
        $states.Count | Should -Be 1
        $states[0].fingerprint | Should -BeExactly $script:Before.fingerprint
        Should -Invoke Get-MpPreference -Exactly 0
        Should -Invoke Get-QuickActionNamedFirewallRuleSnapshot -Exactly 0
    }
    It 'keeps failed Xbox reads explicitly unavailable' {
        Mock Get-NoIDXboxActionState {throw 'AppX unavailable'}
        $states=@(Get-AllQuickActionStates -ActionIds @('Xbox'))
        $states.Count | Should -Be 1
        $states[0].state | Should -BeExactly Unknown
        $states[0].actionable | Should -BeFalse
        $states[0].reason | Should -Match 'AppX unavailable'
    }
    It 'routes Xbox apply to its own transaction and rejects unrelated desired states' {
        Mock Invoke-NoIDXboxAction {[pscustomobject]@{Delegated=$true}}
        (Invoke-QuickAction -ActionId Xbox -DesiredState Disable -ExpectedFingerprint ('a'*64) -Confirm:$false).Delegated | Should -BeTrue
        Should -Invoke Invoke-NoIDXboxAction -Exactly 1 -ParameterFilter {$DesiredState -ceq 'Disable' -and $ExpectedFingerprint -ceq ('a'*64)}
        {Invoke-QuickAction -ActionId Xbox -DesiredState Allow -ExpectedFingerprint ('a'*64) -Confirm:$false} | Should -Throw
    }
    It 'validates Xbox artifacts through the generic reader while rejecting schema-3 relabeling' {
        Assert-QuickActionStateArtifact $script:Before | Should -BeTrue
        (Get-QuickActionSessionDocument -SessionPath $script:Prepared.SessionPath).Manifest.restoreMode | Should -BeExactly SettingsOnly
        $manifest=Get-Content $script:Prepared.ManifestPath -Raw -Encoding UTF8|ConvertFrom-Json
        $manifest.schemaVersion=3
        $null=Write-AtomicUtf8File -Path $script:Prepared.ManifestPath -Content (ConvertTo-QuickActionCanonicalJson $manifest)
        {Get-QuickActionSessionDocument -SessionPath $script:Prepared.SessionPath} | Should -Throw
    }
    It 'lists exactly the 18 restorable settings without claiming six app backups or querying apps' {
        $sessions=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)
        $sessions.Count | Should -Be 1
        $sessions[0].RestoreMode | Should -BeExactly SettingsOnly
        $sessions[0].TotalItems | Should -Be 18
        $sessions[0].Modules[0].itemsBackedUp | Should -Be 18
        $sessions[0].Restorable | Should -BeTrue
        Should -Invoke Get-NoIDXboxComponentSnapshot -Exactly 0
    }
    It 'keeps drifted settings visible and unavailable in the common backup listing' {
        $script:LiveSettings=ConvertFrom-Json (ConvertTo-Json $script:After.targets.settings -Depth 20)
        $script:LiveSettings.Services[0].startType='Automatic'
        $session=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $session.Restorable | Should -BeFalse
        $session.ValidationStatus | Should -BeExactly LiveStateDrifted
        $session.SessionId | Should -BeExactly $script:Document.Manifest.sessionId
    }
    It 'restores settings through the common dispatcher and publishes its exact receipt contract' {
        $result=Restore-Session -SessionPath $script:Prepared.SessionPath -PassThruContract -NoReboot
        $result.success | Should -BeTrue
        $result.sessionType | Should -BeExactly quickAction
        $result.restoredScopes | Should -Be @('action:Xbox')
        $result.manifestSha256 | Should -Match '^[0-9a-f]{64}$'
        $result.receiptSha256 | Should -Match '^[0-9a-f]{64}$'
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
        $session=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $session.Restorable | Should -BeFalse
        $session.ValidationStatus | Should -BeExactly RestoredAndValidated
    }
    It 'lists closed failed changes as failed instead of applied or restorable' {
        $doc=Set-NoIDXboxFailedSession -SessionPath $script:Prepared.SessionPath -Status ApplyFailedSettingsRestored -Confirm:$false
        $null=Write-SessionRestoreReceipt -SessionPath $doc.SessionPath -Manifest $doc.Manifest -Scopes @('action:Xbox') -Confirm:$false
        $session=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $session.Restorable | Should -BeFalse
        $session.Modules[0].status | Should -BeExactly ApplyFailedSettingsRestored
        $session.ValidationStatus | Should -BeExactly FailedSettingsClosed
    }
    It 'never interprets a settings-only restore as an exact full app restore' {
        {Restore-QuickActionScopeState -State $script:Before -Confirm:$false} | Should -Throw '*settings-only*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
    }
}


Describe 'Interrupted Xbox settings recovery' {
    BeforeEach {
        $script:SessionRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Before=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Enable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets)
        $script:After=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets (Get-XboxActionTargets -Disabled)
        $script:Prepared=New-NoIDXboxPreparedSession -PreState $script:Before -DesiredState Disable -BackupDirectory $script:SessionRoot -Confirm:$false
        $script:LiveSettings=ConvertFrom-Json (ConvertTo-Json $script:After.targets.settings -Depth 20)
        $script:LiveSettings.Services[0].startType='Automatic'
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=2}}
        Mock Assert-NoIDXboxUnmanagedDevice {}
        Mock Assert-NoIDXboxWorkersIdle {}
        Mock Get-NoIDXboxSettingsState {$script:LiveSettings}
        Mock Restore-NoIDXboxSettingsState {param($State) $script:LiveSettings=$State}
        Mock Invoke-NoIDXboxAppRecovery {throw 'Recovery must not install apps'}
        Mock Invoke-NoIDXboxAppRemoval {throw 'Recovery must not remove apps'}
        Mock Get-NoIDXboxComponentSnapshot {throw 'Settings recovery must not query apps'}
    }
    It 'offers incomplete settings recovery with a fingerprint of the displayed settings' {
        $item=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $item.Restorable | Should -BeTrue
        $item.ValidationStatus | Should -BeExactly InterruptedSettingsRecoveryAvailable
        $item.ExpectedSettingsFingerprint | Should -BeExactly (Get-QuickActionObjectSha256 $script:LiveSettings)
        $item.Modules[0].status | Should -BeExactly Prepared
        $item.TotalItems | Should -Be 18
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        Should -Invoke Get-NoIDXboxComponentSnapshot -Exactly 0
    }
    It 'recovers a reviewed partial state through the common dispatcher without app mutations' {
        $preHash=(Get-FileHash $script:Prepared.PrePath).Hash
        $item=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $result=Restore-Session -SessionPath $item.SessionPath -ExpectedSettingsFingerprint $item.ExpectedSettingsFingerprint -PassThruContract -NoReboot
        $result.success | Should -BeTrue
        $result.restoredScopes | Should -Be @('action:Xbox')
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:Before.targets.settings)
        (Get-FileHash $script:Prepared.PrePath).Hash | Should -BeExactly $preHash
        $doc=Get-NoIDXboxSessionDocument $item.SessionPath -AllowIncomplete
        $doc.Manifest.status | Should -Not -Be Applied
        $doc.Manifest.restorable | Should -BeFalse
        Should -Invoke Invoke-NoIDXboxAppRecovery -Exactly 0
        Should -Invoke Invoke-NoIDXboxAppRemoval -Exactly 0
        @(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0].ValidationStatus | Should -BeExactly FailedSettingsClosed
    }
    It 'does not treat an interrupted poststate as permission to overwrite settings' {
        $null=Write-AtomicUtf8File -Path (Join-Path $script:Prepared.SessionPath 'poststate.json') -Content (ConvertTo-QuickActionCanonicalJson $script:After)
        $script:LiveSettings=$script:After.targets.settings
        {Restore-QuickActionSession $script:Prepared.SessionPath -Confirm:$false} | Should -Throw '*requires the reviewed*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        (Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete).Manifest.status | Should -BeExactly Prepared
    }
    It 'rejects a changed live state after the recovery view was displayed' {
        $fingerprint=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0].ExpectedSettingsFingerprint
        $script:LiveSettings.Services[0].startType='Manual'
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint $fingerprint -Confirm:$false} | Should -Throw '*changed after recovery was displayed*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        (Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete).Manifest.status | Should -BeExactly Prepared
    }
    It 'closes unchanged prepared settings without rewriting them or requiring a new snapshot' {
        $script:LiveSettings=$script:Before.targets.settings
        Restore-QuickActionSession $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
        $item=@(Get-BackupSessions -BackupDirectory $script:SessionRoot)[0]
        $item.ValidationStatus | Should -BeExactly FailedSettingsClosed
        $item.Restorable | Should -BeFalse
    }
    It 'preserves the sealed manifest and state files when recovering a terminal failed record' {
        $doc=Set-NoIDXboxFailedSession $script:Prepared.SessionPath -Status ApplyFailedSettingsRestoreFailed -Confirm:$false
        $before=@(Get-ChildItem $doc.SessionPath -File|Sort-Object Name|ForEach-Object {(Get-FileHash $_.FullName).Hash})
        $fingerprint=Get-QuickActionObjectSha256 $script:LiveSettings
        Restore-QuickActionSession $doc.SessionPath -ExpectedSettingsFingerprint $fingerprint -Confirm:$false | Should -BeTrue
        $after=@(Get-ChildItem $doc.SessionPath -File|Where-Object Name -NE restore-receipt.json|Sort-Object Name|ForEach-Object {(Get-FileHash $_.FullName).Hash})
        ($after -join ',') | Should -BeExactly ($before -join ',')
    }
    It 'honors WhatIf before finalizing the interrupted record or changing Windows' {
        $hash=(Get-FileHash $script:Prepared.ManifestPath).Hash
        Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -WhatIf | Should -BeFalse
        (Get-FileHash $script:Prepared.ManifestPath).Hash | Should -BeExactly $hash
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'still refuses an active worker even with a reviewed settings fingerprint' {
        Mock Assert-NoIDXboxWorkersIdle {throw 'Worker still running'}
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -Confirm:$false} | Should -Throw '*Worker still running*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'still refuses newer overlapping changes even with a reviewed fingerprint' {
        $otherPath=Join-Path $script:SessionRoot 'Session_newer'
        $null=New-Item $otherPath -ItemType Directory
        $other=[pscustomobject]@{schemaVersion=2;sessionId='Session_newer';timestamp=([datetime]::Parse($script:Prepared.Manifest.timestamp).AddSeconds(1).ToString('o'));modules=@([pscustomobject]@{name='Privacy'})}
        $null=Write-AtomicUtf8File -Path (Join-Path $otherPath 'manifest.json') -Content (ConvertTo-QuickActionCanonicalJson $other)
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -Confirm:$false} | Should -Throw '*newer overlapping*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'still refuses another desktop user even with a matching settings fingerprint' {
        Mock Get-PrivacyUserContext {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1002';SessionId=2}}
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -Confirm:$false} | Should -Throw '*different desktop user*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'does not relax completed-session drift checks through the recovery parameter' {
        $null=Complete-NoIDXboxSession $script:Prepared -PostState $script:After -Confirm:$false
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -Confirm:$false} | Should -Throw '*refusing to overwrite newer*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'rejects the Xbox recovery parameter for other session types before dispatch' {
        $manifest=$script:Prepared.Manifest
        $manifest.schemaVersion=3;$manifest.actionId='SmartScreen'
        $null=Write-AtomicUtf8File -Path $script:Prepared.ManifestPath -Content (ConvertTo-QuickActionCanonicalJson $manifest)
        $result=Restore-Session $script:Prepared.SessionPath -ExpectedSettingsFingerprint ('a'*64) -PassThruContract
        $result.success | Should -BeFalse
        $result.error | Should -Match 'only for Xbox'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'rejects tampered prestates even when current settings were reviewed' {
        Add-Content $script:Prepared.PrePath ' '
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint (Get-QuickActionObjectSha256 $script:LiveSettings) -Confirm:$false} | Should -Throw '*integrity*'
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 0
    }
    It 'compensates receipt publication failure back to the reviewed partial state' {
        $partial=Get-QuickActionObjectSha256 $script:LiveSettings
        Mock Write-SessionRestoreReceipt {throw 'Receipt disk full'}
        {Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint $partial -Confirm:$false} | Should -Throw '*receipt publication failed*'
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly $partial
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 2
        Test-Path (Join-Path $script:Prepared.SessionPath 'restore-receipt.json') | Should -BeFalse
    }
    It 'keeps an interrupted poststate as failed evidence without changing its bytes' {
        $path=Join-Path $script:Prepared.SessionPath 'poststate.json'
        $null=Write-AtomicUtf8File -Path $path -Content (ConvertTo-QuickActionCanonicalJson $script:After)
        $hash=(Get-FileHash $path).Hash
        {Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowPrepared} | Should -Throw '*undeclared*'
        $script:LiveSettings=$script:Before.targets.settings
        Restore-QuickActionSession $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        (Get-FileHash $path).Hash | Should -BeExactly $hash
        $doc=Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete
        $doc.PostState.fingerprint | Should -BeExactly $script:After.fingerprint
        $doc.Manifest.status | Should -Not -Be Applied
    }
    It 'rejects interrupted poststates with a different user or invalid fingerprint' {
        $path=Join-Path $script:Prepared.SessionPath 'poststate.json'
        $targets=Get-XboxActionTargets -Disabled
        $targets.userSid='S-1-5-21-1-2-3-1002';$targets.components.UserSid=$targets.userSid
        $foreign=Complete-QuickActionState -ActionId Xbox -OwningModule SecurityBaseline -State Disable -Actionable:$true -TargetIds (Get-NoIDXboxActionTargetIds) -Targets $targets
        $null=Write-AtomicUtf8File -Path $path -Content (ConvertTo-QuickActionCanonicalJson $foreign)
        {Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete} | Should -Throw '*different user*'
        $foreign=$script:After;$foreign.fingerprint='a'*64
        $null=Write-AtomicUtf8File -Path $path -Content (ConvertTo-QuickActionCanonicalJson $foreign)
        {Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete} | Should -Throw '*fingerprint*'
    }
    It 'cannot label interrupted poststate evidence as rejection before mutation' {
        $null=Write-AtomicUtf8File -Path (Join-Path $script:Prepared.SessionPath 'poststate.json') -Content (ConvertTo-QuickActionCanonicalJson $script:After)
        {Set-NoIDXboxFailedSession $script:Prepared.SessionPath -Status Rejected -Confirm:$false} | Should -Throw '*rejected before mutation*'
    }
    It 'keeps bounded atomic writer remnants opaque and leaves their contents unchanged' {
        $remnants=@()
        foreach($name in @('manifest','prestate','poststate')) {
            foreach($suffix in @('tmp','replace-backup')) {
                $path=Join-Path $script:Prepared.SessionPath ($name+'.json.'+('a'*32)+'.'+$suffix)
                Set-Content $path 'not JSON and not authority'
                $remnants+=@{Path=$path;Hash=(Get-FileHash -LiteralPath $path).Hash}
            }
        }
        $doc=Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete
        $doc.Manifest.status | Should -BeExactly Prepared
        $script:LiveSettings=$script:Before.targets.settings
        Restore-QuickActionSession $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        $expectedNames=@('manifest.json','prestate.json','restore-receipt.json')+@($remnants|ForEach-Object {Split-Path $_.Path -Leaf})
        (@(Get-ChildItem -LiteralPath $script:Prepared.SessionPath -Force|ForEach-Object Name|Sort-Object) -join ',') | Should -BeExactly (($expectedNames|Sort-Object) -join ',')
        foreach($file in $remnants) {(Get-FileHash -LiteralPath $file.Path).Hash | Should -BeExactly $file.Hash}
    }
    It 'rejects oversized and unrelated transient names instead of hiding unknown files' {
        $path=Join-Path $script:Prepared.SessionPath ('manifest.json.'+('a'*32)+'.tmp')
        [IO.File]::WriteAllText($path,('x'*65537))
        {Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete} | Should -Throw '*undeclared*'
        [IO.File]::WriteAllText($path,'')
        Move-Item $path (Join-Path $script:Prepared.SessionPath 'manifest.json.unknown.tmp')
        {Get-NoIDXboxSessionDocument $script:Prepared.SessionPath -AllowIncomplete} | Should -Throw '*undeclared*'
    }
    It 'does not repeat completed failed-session recovery after a validated receipt' {
        $fingerprint=Get-QuickActionObjectSha256 $script:LiveSettings
        Restore-QuickActionSession $script:Prepared.SessionPath -ExpectedSettingsFingerprint $fingerprint -Confirm:$false | Should -BeTrue
        $script:LiveSettings=$script:After.targets.settings
        Restore-QuickActionSession $script:Prepared.SessionPath -Confirm:$false | Should -BeTrue
        Should -Invoke Restore-NoIDXboxSettingsState -Exactly 1
        (Get-QuickActionObjectSha256 $script:LiveSettings) | Should -BeExactly (Get-QuickActionObjectSha256 $script:After.targets.settings)
    }
}
