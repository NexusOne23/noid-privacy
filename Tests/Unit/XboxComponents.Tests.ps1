#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Core\XboxComponents.ps1')
    function Get-XboxInventoryFixture {
        param([switch]$Disabled)
        $catalog = Get-NoIDXboxComponentCatalog
        [pscustomobject]@{
            Apps = @($catalog.Apps | ForEach-Object {
                $present = -not $Disabled -or -not $_.RemoveWhenDisabled
                [pscustomobject]@{Name=$_.Name;Present=[bool]$present;Healthy=[bool]$present}
            })
            Services = @($catalog.Services | ForEach-Object {
                [pscustomobject]@{Name=$_;Exists=$true;StartType=$(if ($Disabled) {'Disabled'} else {'Manual'});Status='Stopped'}
            })
            Task = [pscustomobject]@{Exists=$true;Enabled=(-not [bool]$Disabled)}
            RecordingAllowed = -not [bool]$Disabled
            RecordingPolicySupported = $true
            RemovalBlocked = [bool]$Disabled
            Applicability = [pscustomobject]@{
                RecordingPolicySupported=$true;RemovalPolicySupported=$true
                ManagementStateKnown=$true;DomainJoined=$false;MdmRegistered=$false
            }
        }
    }
}

Describe 'Xbox component scope' {
    It 'covers every Xbox app removed by Privacy without targeting games or the shared runtime' {
        $privacy = Get-Content (Join-Path $script:RepoRoot 'Modules\Privacy\Config\Bloatware.json') -Raw | ConvertFrom-Json
        $names = @($privacy.RemoveApps | Where-Object { $_ -match '^Microsoft\.(Xbox|GamingApp)' } | Sort-Object)
        $actual = @((Get-NoIDXboxComponentCatalog).Apps | Where-Object RemoveWhenDisabled | ForEach-Object Name | Sort-Object)
        $names.Count | Should -Be 6
        ($actual -join ',') | Should -BeExactly ($names -join ',')
        $actual | Should -Not -Contain 'Microsoft.GamingServices'
        @((Get-NoIDXboxComponentCatalog).Apps).Count | Should -Be 6
        @((Get-NoIDXboxComponentCatalog).Services) | Should -Not -Contain 'GamingServices'
        @((Get-NoIDXboxComponentCatalog).Services) | Should -Not -Contain 'GamingServicesNet'
        @((Get-NoIDXboxComponentCatalog).Apps | Where-Object { $_.Name -match '[*?]' }).Count | Should -Be 0
    }

    It 'matches the baseline service targets and recording policy' {
        $templates = Get-Content (Join-Path $script:RepoRoot 'Modules\SecurityBaseline\ParsedSettings\SecurityTemplates.json') -Raw | ConvertFrom-Json
        $services = @($templates.PSObject.Properties.Value | ForEach-Object {
            if ($_.PSObject.Properties['Service General Setting']) { $_.'Service General Setting'.PSObject.Properties.Name }
        } | Sort-Object)
        (((Get-NoIDXboxComponentCatalog).Services | Sort-Object) -join ',') | Should -BeExactly ($services -join ',')
        $policies = Get-Content (Join-Path $script:RepoRoot 'Modules\SecurityBaseline\ParsedSettings\Computer-RegistryPolicies.json') -Raw | ConvertFrom-Json
        $recording = @($policies | Where-Object { $_.ValueName -ceq 'AllowGameDVR' })
        $recording.Count | Should -Be 1
        ('HKLM:\' + $recording[0].KeyName.TrimStart('[')) | Should -Be (Get-NoIDXboxComponentCatalog).RecordingPolicyPath
        $recording[0].Data | Should -Be 0
    }

    It 'uses the same verified Store identities as existing recovery' {
        $map = Get-Content (Join-Path $script:RepoRoot 'Modules\Privacy\Config\Bloatware-Map.json') -Raw | ConvertFrom-Json
        foreach ($app in @((Get-NoIDXboxComponentCatalog).Apps | Where-Object { $_.RemoveWhenDisabled -and $_.StoreId })) {
            $app.StoreId | Should -BeExactly $map.Mappings.($app.Name).StoreId
        }
        $legacy = (Get-NoIDXboxComponentCatalog).Apps | Where-Object Name -EQ 'Microsoft.XboxApp'
        $legacy.RequiredWhenEnabled | Should -BeFalse
        $legacy.StoreId | Should -BeNullOrEmpty
    }
}

Describe 'Measured Xbox state' {
    It 'recognizes an enabled installation without requiring demand-start services to run permanently' {
        Resolve-NoIDXboxComponentState (Get-XboxInventoryFixture) | Should -BeExactly 'Enable'
    }

    It 'recognizes module hardening with removed Xbox apps while retaining the shared gaming runtime' {
        Resolve-NoIDXboxComponentState (Get-XboxInventoryFixture -Disabled) | Should -BeExactly 'Disable'
    }

    It 'does not call installed Xbox apps disabled just because all services are disabled' {
        $state = Get-XboxInventoryFixture -Disabled
        $state.Apps[0].Present = $true; $state.Apps[0].Healthy = $true
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
    }

    It 'requires each supported current Xbox app' {
        foreach ($name in @('Microsoft.GamingApp','Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider')) {
            $state = Get-XboxInventoryFixture
            $app = $state.Apps | Where-Object Name -EQ $name
            $app.Present = $false; $app.Healthy = $false
            Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
        }
    }

    It 'does not require discontinued optional packages to recreate an enabled installation' {
        $state = Get-XboxInventoryFixture
        foreach ($app in $state.Apps | Where-Object Name -In @('Microsoft.XboxApp','Microsoft.Xbox.TCUI','Microsoft.XboxSpeechToTextOverlay')) {
            $app.Present = $false; $app.Healthy = $false
        }
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Enable'
    }

    It 'detects unhealthy registrations and every single service or task blocker' {
        $state = Get-XboxInventoryFixture
        $state.Apps[0].Healthy = $false
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
        foreach ($index in 0..3) {
            $state = Get-XboxInventoryFixture
            $state.Services[$index].StartType = 'Disabled'
            Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
        }
        $state = Get-XboxInventoryFixture
        $state.Task.Enabled = $false
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
    }

    It 'does not accept blocked reinstallations or recordings as fully enabled' {
        $state = Get-XboxInventoryFixture
        $state.RemovalBlocked = $true
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
        $state = Get-XboxInventoryFixture
        $state.RecordingAllowed = $false
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
    }

    It 'does not accept a disabled but still running Xbox service as fully off' {
        $state = Get-XboxInventoryFixture -Disabled
        $state.Services[0].Status = 'Running'
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Mixed'
    }

    It 'distinguishes an absent optional OS component from a failed query' {
        $state = Get-XboxInventoryFixture
        $state.Task.Exists = $false
        $state.Services[0].Exists = $false
        Resolve-NoIDXboxComponentState $state | Should -BeExactly 'Enable'
        $state.Services[0].Exists = $null
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*not measured*'
    }

    It 'rejects incomplete and duplicate inventories even when counts would otherwise pass' {
        $state = Get-XboxInventoryFixture
        $state.Apps = @($state.Apps[0..4])
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*incomplete*'
        $state = Get-XboxInventoryFixture
        $state.Apps[1] = $state.Apps[0]
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*duplicate*'
        $state = Get-XboxInventoryFixture
        $state.Services[1] = $state.Services[0]
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*duplicate*'
    }

    It 'rejects unread policies and transient service results instead of treating them as false' {
        $state = Get-XboxInventoryFixture
        $state.RecordingAllowed = $null
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*Boolean*'
        $state = Get-XboxInventoryFixture
        $state.Services[0].Status = 'StartPending'
        { Resolve-NoIDXboxComponentState $state } | Should -Throw '*changing*'
    }
}

Describe 'Xbox inventory reads' {
    BeforeAll {
        # Only the registry abstraction is supplied here. Windows provides the
        # AppX/service commands; none of the query tests changes native state.
        function Get-QuickActionRegistryValueState { param($Path, $Name) $null = $Path, $Name }
    }
    BeforeEach {
        $script:XboxTestPolicies = @{}
        $script:XboxApplicability = (Get-XboxInventoryFixture).Applicability
        Mock Get-NoIDXboxApplicability { $script:XboxApplicability }
        Mock Get-QuickActionRegistryValueState {
            param($Path, $Name)
            $key = "${Path}::$Name"
            if ($script:XboxTestPolicies.ContainsKey($key)) { return $script:XboxTestPolicies[$key] }
            [pscustomobject]@{path=$Path;name=$Name;valueExisted=$false;type=$null;value=$null}
        }
        Mock Get-AppxPackage {
            @((Get-NoIDXboxComponentCatalog).Apps | ForEach-Object {
                [pscustomobject]@{Name=$_.Name;PackageFamilyName=$_.PackageFamilyName;PackageFullName=$_.Name+'_1.2.3.4_x64__8wekyb3d8bbwe';IsBundle=$false;Status='Ok'}
            })
        }
        Mock Get-Service {
            $fixture = Get-XboxInventoryFixture
            @($fixture.Services)
        }
        Mock Get-NoIDXboxTaskState { [pscustomobject]@{Exists=$false;Enabled=$null} }
    }

    It 'reads the explicitly bound user and uses one package/service enumeration' {
        $snapshot = Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001'
        Resolve-NoIDXboxComponentState $snapshot | Should -BeExactly 'Enable'
        Should -Invoke Get-AppxPackage -Exactly 1 -ParameterFilter {
            $User -ceq 'S-1-5-21-1-2-3-1001' -and ((($PackageTypeFilter -join ',') -split '\s*,\s*' | Sort-Object) -join ',') -ceq 'Bundle,Main'
        }
        Should -Invoke Get-Service -Exactly 1
    }

    It 'leaves shared game dependencies outside detection and policy exceptions' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{path=$root;name='Enabled';valueExisted=$true;type='DWord';value=1}
        $script:XboxTestPolicies["${root}::DynamicRemovalList"] = [pscustomobject]@{path=$root;name='DynamicRemovalList';valueExisted=$true;type='MultiString';value=@('Microsoft.GamingServices_8wekyb3d8bbwe')}
        $snapshot = Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001'
        Resolve-NoIDXboxComponentState $snapshot | Should -BeExactly 'Enable'
        $snapshot.Apps.Name | Should -Not -Contain 'Microsoft.GamingServices'
        @(Get-NoIDXboxRemovalPolicyPlan $snapshot).Count | Should -Be 0
        Should -Invoke Get-QuickActionRegistryValueState -Exactly 0 -ParameterFilter {$Path -like '*GamingServices*'}
    }

    It 'propagates a package query failure instead of calling apps absent' {
        Mock Get-AppxPackage { throw 'package provider failed' }
        { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*provider failed*'
    }

    It 'propagates service and task query failures instead of calling components absent' {
        Mock Get-Service { throw 'service provider failed' }
        { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*provider failed*'
        Mock Get-Service { (Get-XboxInventoryFixture).Services }
        Mock Get-NoIDXboxTaskState { throw 'task access denied' }
        { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*access denied*'
    }

    It 'rejects an app with a lookalike name and the wrong publisher' {
        Mock Get-AppxPackage {
            [pscustomobject]@{Name='Microsoft.GamingApp';PackageFamilyName='Microsoft.GamingApp_otherpublisher';Status='Ok'}
        }
        { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*publisher*'
    }

    It 'recognizes native removal policies without mistaking frozen legacy labels for effective policy' {
        $catalog = Get-NoIDXboxComponentCatalog
        $root = $catalog.RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        $key = $root + '\Microsoft.GamingApp_8wekyb3d8bbwe::RemovePackage'
        $script:XboxTestPolicies[$key] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeTrue
        $script:XboxTestPolicies.Remove($key)
        $script:XboxTestPolicies["${root}\XboxGamingOverlay::RemovePackage"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeFalse
        $script:XboxTestPolicies[$key] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        $script:XboxTestPolicies["${root}::Enabled"].value = 0
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeFalse
    }

    It 'detects Xbox in the dynamic removal list without treating unrelated apps as Xbox blockers' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        $script:XboxTestPolicies["${root}::DynamicRemovalList"] = [pscustomobject]@{valueExisted=$true;type='MultiString';value=@('Other.App_example')}
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeFalse
        $script:XboxTestPolicies["${root}::DynamicRemovalList"].value += 'Microsoft.GamingApp_8wekyb3d8bbwe'
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeTrue
    }

    It 'rejects malformed policy values rather than silently treating them as allow' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='String';value='1'}
        { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*unsupported*'
    }

    It 'does not report removal policies as enforced on unsupported editions' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        $script:XboxTestPolicies["${root}\Microsoft.GamingApp_8wekyb3d8bbwe::RemovePackage"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        $script:XboxTestPolicies["${root}::DynamicRemovalList"] = [pscustomobject]@{valueExisted=$true;type='MultiString';value=@('Microsoft.GamingServices_8wekyb3d8bbwe')}
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeTrue
        $script:XboxApplicability.RemovalPolicySupported = $false
        (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeFalse
    }

    It 'accepts only native PFN flags while dynamic selection can block any Xbox family' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
        foreach ($app in (Get-NoIDXboxComponentCatalog).Apps) {
            $key = $root+'\'+$app.PackageFamilyName+'::RemovePackage'
            $script:XboxTestPolicies[$key] = [pscustomobject]@{valueExisted=$true;type='DWord';value=1}
            $expected = $app.Name -cin @('Microsoft.GamingApp','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay','Microsoft.Xbox.TCUI')
            (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -Be $expected
            $script:XboxTestPolicies.Remove($key)
            $script:XboxTestPolicies["${root}::DynamicRemovalList"] = [pscustomobject]@{valueExisted=$true;type='MultiString';value=@($app.PackageFamilyName)}
            (Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001').RemovalBlocked | Should -BeTrue
            $script:XboxTestPolicies.Remove("${root}::DynamicRemovalList")
        }
    }

    It 'rejects untyped flags and scalar or missing dynamic lists' {
        $root = (Get-NoIDXboxComponentCatalog).RemovalPolicyRoot
        foreach ($value in @($true,'1',2)) {
            $script:XboxTestPolicies["${root}::Enabled"] = [pscustomobject]@{valueExisted=$true;type='DWord';value=$value}
            { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*unsupported*'
        }
        $script:XboxTestPolicies.Clear()
        foreach ($value in @($null,'Microsoft.GamingApp_8wekyb3d8bbwe',@('valid',17))) {
            $script:XboxTestPolicies["${root}::DynamicRemovalList"] = [pscustomobject]@{valueExisted=$true;type='MultiString';value=$value}
            { Get-NoIDXboxComponentSnapshot -UserSid 'S-1-5-21-1-2-3-1001' } | Should -Throw '*unsupported*'
        }
    }

    It 'ignores unsupported recording policy in both directions without hiding other blockers' {
        foreach ($disabled in @($false,$true)) {
            $snapshot = Get-XboxInventoryFixture -Disabled:$disabled
            $snapshot.RecordingPolicySupported = $false
            $snapshot.RecordingAllowed = $disabled
            Resolve-NoIDXboxComponentState $snapshot | Should -Be $(if($disabled){'Disable'}else{'Enable'})
            $snapshot.Services[0].StartType = $(if($disabled){'Manual'}else{'Disabled'})
            Resolve-NoIDXboxComponentState $snapshot | Should -Be 'Mixed'
        }
    }
}

Describe 'Xbox scheduled-task lookup' {
    It 'opens one exact COM folder without the cmdlet-only trailing separator' {
        $fakeFolder = [pscustomobject]@{}
        $fakeFolder | Add-Member ScriptMethod GetTask {
            param($Name)
            if ($Name -cne 'XblGameSaveTask') { throw 'Wrong task identity' }
            [pscustomobject]@{Enabled=$false}
        }
        $script:FakeXboxTaskFolder = $fakeFolder
        $script:FakeXboxScheduler = [pscustomobject]@{}
        $script:FakeXboxScheduler | Add-Member ScriptMethod Connect { }
        $script:FakeXboxScheduler | Add-Member ScriptMethod GetFolder {
            param($Path)
            if ($Path -cne '\Microsoft\XblGameSave') { throw 'Wrong COM folder syntax' }
            $script:FakeXboxTaskFolder
        }
        Mock New-Object { $script:FakeXboxScheduler } -ParameterFilter { $ComObject -ceq 'Schedule.Service' }
        $task = Get-NoIDXboxTaskState
        $task.Exists | Should -BeTrue
        $task.Enabled | Should -BeFalse
        Should -Invoke New-Object -Exactly 1 -ParameterFilter { $ComObject -ceq 'Schedule.Service' }
    }
}

Describe 'Xbox-only app-removal policy exceptions' {
    BeforeAll {
        function Get-XboxRemovalPolicyFixture {
            $snapshot = Get-XboxInventoryFixture -Disabled
            $catalog = Get-NoIDXboxComponentCatalog
            $values = @($catalog.Apps | ForEach-Object {
                [pscustomobject]@{path=$catalog.RemovalPolicyRoot+'\'+$_.PackageFamilyName;name='RemovePackage';valueExisted=$true;type='DWord';value=1}
                if ($_.LegacyPolicyName) {
                    [pscustomobject]@{path=$catalog.RemovalPolicyRoot+'\'+$_.LegacyPolicyName;name='RemovePackage';valueExisted=$true;type='DWord';value=1}
                }
            })
            $snapshot | Add-Member NoteProperty RemovalPolicyEnabled ([pscustomobject]@{path=$catalog.RemovalPolicyRoot;name='Enabled';valueExisted=$true;type='DWord';value=1})
            $snapshot | Add-Member NoteProperty RemovalPolicyValues $values
            $snapshot | Add-Member NoteProperty DynamicRemovalList ([pscustomobject]@{path=$catalog.RemovalPolicyRoot;name='DynamicRemovalList';valueExisted=$false;type=$null;value=$null})
            return $snapshot
        }
    }

    It 'clears only named Xbox flags and preserves the enabled global removal policy' {
        $snapshot = Get-XboxRemovalPolicyFixture
        $before = ConvertTo-Json $snapshot -Depth 12 -Compress
        $plan = @(Get-NoIDXboxRemovalPolicyPlan $snapshot)
        $plan.Count | Should -Be 11
        @($plan | Where-Object { $_.Name -eq 'Enabled' -or $_.Value -ne 0 -or $_.Type -cne 'DWord' }).Count | Should -Be 0
        @($plan | Where-Object { $_.Path -match 'Other|WindowsStore|WindowsTerminal' }).Count | Should -Be 0
        (ConvertTo-Json $snapshot -Depth 12 -Compress) | Should -BeExactly $before
        $snapshot.RemovalPolicyEnabled.value | Should -Be 1
    }

    It 'matches the frozen 2.2.5 Xbox policy identities used by sealed restore' {
        . (Join-Path $script:RepoRoot 'Modules\Privacy\Private\Get-PrivacyTier1PolicyDefinition.ps1')
        $legacy = Get-PrivacyTier1LegacyV225PolicyDefinition
        $expected = @($legacy.Targets | Where-Object { $_.PSObject.Properties['PolicyId'] -and $_.PolicyId -in @('GamingApp','XboxGamingOverlay','XboxIdentityProvider','XboxSpeechToTextOverlay','XboxTCUI') })
        $expected.Count | Should -Be 5
        $plan = @(Get-NoIDXboxRemovalPolicyPlan (Get-XboxRemovalPolicyFixture))
        foreach ($target in $expected) {
            @($plan | Where-Object { $_.Path -ceq $target.Path -and $_.Name -ceq $target.Name }).Count | Should -Be 1
        }
    }

    It 'preserves every unrelated dynamic removal entry and its order' {
        $snapshot = Get-XboxRemovalPolicyFixture
        $snapshot.DynamicRemovalList.valueExisted = $true
        $snapshot.DynamicRemovalList.type = 'MultiString'
        $snapshot.DynamicRemovalList.value = @('Other.First_publisher', 'Microsoft.GamingApp_8wekyb3d8bbwe', 'Microsoft.GamingServices_8wekyb3d8bbwe', 'Other.Second_publisher', 'microsoft.xboxgamingoverlay_8wekyb3d8bbwe', 'Other.First_publisher')
        $change = @(Get-NoIDXboxRemovalPolicyPlan $snapshot | Where-Object Name -EQ DynamicRemovalList)
        $change.Count | Should -Be 1
        ($change[0].Value -join ',') | Should -BeExactly 'Other.First_publisher,Microsoft.GamingServices_8wekyb3d8bbwe,Other.Second_publisher,Other.First_publisher'
        $change[0].Type | Should -BeExactly 'MultiString'
    }

    It 'represents an emptied Xbox-only dynamic list as a real empty string array' {
        $snapshot = Get-XboxRemovalPolicyFixture
        $snapshot.DynamicRemovalList.valueExisted = $true
        $snapshot.DynamicRemovalList.type = 'MultiString'
        $snapshot.DynamicRemovalList.value = @('Microsoft.GamingApp_8wekyb3d8bbwe')
        $change = @(Get-NoIDXboxRemovalPolicyPlan $snapshot | Where-Object Name -EQ DynamicRemovalList)
        $change.Count | Should -Be 1
        ($null -eq $change[0].Value) | Should -BeFalse
        @($change[0].Value).Count | Should -Be 0
    }

    It 'does not create absent flags or rewrite an unrelated dynamic list' {
        $snapshot = Get-XboxRemovalPolicyFixture
        foreach ($value in $snapshot.RemovalPolicyValues) { $value.valueExisted=$false; $value.type=$null; $value.value=$null }
        $snapshot.DynamicRemovalList.valueExisted = $true
        $snapshot.DynamicRemovalList.type = 'MultiString'
        $snapshot.DynamicRemovalList.value = @('Other.App_publisher')
        @(Get-NoIDXboxRemovalPolicyPlan $snapshot).Count | Should -Be 0
    }

    It 'leaves inert removal values unchanged on unsupported editions' {
        $snapshot = Get-XboxRemovalPolicyFixture
        $snapshot.Applicability.RemovalPolicySupported = $false
        @(Get-NoIDXboxRemovalPolicyPlan $snapshot).Count | Should -Be 0
    }

    It 'rejects substituted or duplicate targets before returning a writable plan' {
        foreach ($mutation in @('ForeignPath','ForeignName','Duplicate','WrongRoot','WrongDynamic')) {
            $snapshot = Get-XboxRemovalPolicyFixture
            switch ($mutation) {
                'ForeignPath' { $snapshot.RemovalPolicyValues[0].path='HKLM:\SOFTWARE\Unrelated' }
                'ForeignName' { $snapshot.RemovalPolicyValues[0].name='OtherApp' }
                'Duplicate' { $snapshot.RemovalPolicyValues[0]=$snapshot.RemovalPolicyValues[1] }
                'WrongRoot' { $snapshot.RemovalPolicyEnabled.name='OtherEnabled' }
                'WrongDynamic' { $snapshot.DynamicRemovalList.name='OtherList' }
            }
            { Get-NoIDXboxRemovalPolicyPlan $snapshot } | Should -Throw '*identity*'
        }
    }

    It 'rejects incomplete and invalid policy data without returning partial changes' {
        $snapshot = Get-XboxRemovalPolicyFixture
        $snapshot.RemovalPolicyValues = @($snapshot.RemovalPolicyValues[0])
        { Get-NoIDXboxRemovalPolicyPlan $snapshot } | Should -Throw '*incomplete*'
        foreach ($badValue in @($null, @('Other.App_publisher', 17), @(''))) {
            $snapshot = Get-XboxRemovalPolicyFixture
            $snapshot.DynamicRemovalList.valueExisted = $true
            $snapshot.DynamicRemovalList.type = 'MultiString'
            $snapshot.DynamicRemovalList.value = $badValue
            { Get-NoIDXboxRemovalPolicyPlan $snapshot } | Should -Throw
        }
    }
}

Describe 'Exact Xbox package-removal inventory' {
    BeforeAll {
        function Get-XboxPackageFixture {
            param([string]$Name='Microsoft.GamingApp', [switch]$Bundle)
            [pscustomobject]@{
                Name=$Name;PackageFamilyName=$Name+'_8wekyb3d8bbwe'
                PackageFullName=$Name+$(if($Bundle){'_1.2.3.4_neutral_~_8wekyb3d8bbwe'}else{'_1.2.3.4_x64__8wekyb3d8bbwe'})
                IsBundle=[bool]$Bundle;Status='Ok'
            }
        }
    }
    It 'selects the Bundle parent and excludes games, shared runtime and unrelated apps' {
        $packages=@(
            (Get-XboxPackageFixture)
            (Get-XboxPackageFixture -Bundle)
            (Get-XboxPackageFixture -Name Microsoft.XboxIdentityProvider)
            (Get-XboxPackageFixture -Name Microsoft.GamingServices)
            (Get-XboxPackageFixture -Name Microsoft.SomeGame)
            (Get-XboxPackageFixture -Name Microsoft.WindowsStore)
        )
        $inventory=@(Get-NoIDXboxAppRemovalInventory -Packages $packages)
        $inventory.Count | Should -Be 2
        $inventory[0].PackageFullName | Should -BeExactly 'Microsoft.GamingApp_1.2.3.4_neutral_~_8wekyb3d8bbwe'
        $inventory[1].AppName | Should -BeExactly 'Microsoft.XboxIdentityProvider'
    }

    It 'rejects wrong publishers, substituted package names, duplicates and inconsistent Bundle flags' {
        foreach ($mutation in @('Publisher','FullName','Duplicate','Bundle','MissingBundle')) {
            $package=Get-XboxPackageFixture
            $packages=@($package)
            switch($mutation){
                'Publisher' {$package.PackageFamilyName='Microsoft.GamingApp_otherpublisher'}
                'FullName' {$package.PackageFullName='Microsoft.SomeGame_1.2.3.4_x64__8wekyb3d8bbwe'}
                'Duplicate' {$packages=@($package,$package)}
                'Bundle' {$package.IsBundle=$true}
                'MissingBundle' {$package.PSObject.Properties.Remove('IsBundle')}
            }
            {Get-NoIDXboxAppRemovalInventory -Packages $packages} | Should -Throw
        }
    }

    It 'returns an empty inventory when every removable Xbox app is already absent' {
        @(Get-NoIDXboxAppRemovalInventory -Packages @()).Count | Should -Be 0
        @(Get-NoIDXboxAppRemovalInventory -Packages @((Get-XboxPackageFixture -Name Microsoft.GamingServices))).Count | Should -Be 0
    }
}
