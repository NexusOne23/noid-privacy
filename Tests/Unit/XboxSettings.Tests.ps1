#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core\XboxComponents.ps1')
    . (Join-Path $repoRoot 'Core\XboxSettings.ps1')
    . (Join-Path $repoRoot 'Core\QuickActions.ps1')

    function Get-XboxSettingsFixture {
        [pscustomobject][ordered]@{
            SchemaVersion=1
            RegistryValues=@(Get-NoIDXboxSettingsRegistryTargets | ForEach-Object {
                [pscustomobject][ordered]@{
                    kind='RegistryValue';path=$_.Path;name=$_.Name;keyExisted=$true;valueExisted=$false
                    originalName=$null;type=$null;value=$null;absentAncestorKeys=@()
                }
            })
            Services=@((Get-NoIDXboxComponentCatalog).Services | ForEach-Object {
                [pscustomobject][ordered]@{
                    kind='Service';name=$_;exists=$true;status='Stopped';startType='Disabled'
                    delayedAutoStartExists=$false;delayedAutoStart=$null
                }
            })
            Task=[pscustomobject]@{TaskPath='\Microsoft\XblGameSave\';TaskName='XblGameSaveTask';Exists=$true;Enabled=$false}
        }
    }
    function Get-QuickActionRegistryValueState { param($Path,$Name) $null=$Path,$Name }
    function Get-QuickActionServiceState { param($Name) $null=$Name }
    function Set-QuickActionRegistryValue {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param($Path,$Name,$Type,[AllowEmptyCollection()]$Value)
        $null=$Type,$Value
        if ($PSCmdlet.ShouldProcess($Path, "Set $Name")) { throw 'Registry writes must be mocked' }
    }
    function Restore-QuickActionRegistryValue {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param($State)
        if ($PSCmdlet.ShouldProcess([string]$State.path, 'Restore registry value')) { throw 'Registry restore must be mocked' }
    }
}

Describe 'Closed Xbox settings restore evidence' {
    It 'accepts the complete closed scope through a JSON round trip' {
        $state=Get-XboxSettingsFixture
        {Assert-NoIDXboxSettingsState $state} | Should -Not -Throw
        $copy=ConvertFrom-Json (ConvertTo-Json $state -Depth 12)
        {Assert-NoIDXboxSettingsState $copy} | Should -Not -Throw
        @($state.RegistryValues).Count | Should -Be 13
        @($state.Services).Count | Should -Be 4
    }

    It 'rejects foreign, missing, duplicate and enlarged target sets' {
        foreach ($change in @('Registry','Service','Task','Duplicate','Missing','ExtraField')) {
            $state=Get-XboxSettingsFixture
            switch($change){
                'Registry' {$state.RegistryValues[-1].path='HKLM:\SOFTWARE\Unrelated'}
                'Service' {$state.Services[-1].name='GamingServices'}
                'Task' {$state.Task.TaskName='OtherTask'}
                'Duplicate' {$state.RegistryValues[-1]=$state.RegistryValues[0]}
                'Missing' {$state.Services=@($state.Services[0])}
                'ExtraField' {$state | Add-Member NoteProperty ArbitraryCommand 'bad'}
            }
            {Assert-NoIDXboxSettingsState $state} | Should -Throw
        }
    }

    It 'distinguishes an empty native dynamic list from missing or fabricated data' {
        $state=Get-XboxSettingsFixture
        $list=$state.RegistryValues[-1]
        $list.valueExisted=$true;$list.originalName=$list.name;$list.type='MultiString';$list.value=[string[]]@()
        {Assert-NoIDXboxSettingsState $state} | Should -Not -Throw
        foreach($value in @($null, 'single-untyped-string', @('App_family',17))) {
            $list.value=$value
            {Assert-NoIDXboxSettingsState $state} | Should -Throw '*string array*'
        }
    }

    It 'rejects Boolean, string and out-of-range data claimed to be a DWORD' {
        foreach($data in @($true,'1',2,-1)) {
            $state=Get-XboxSettingsFixture
            $value=$state.RegistryValues[0]
            $value.valueExisted=$true;$value.originalName=$value.name;$value.type='DWord';$value.value=$data
            {Assert-NoIDXboxSettingsState $state} | Should -Throw '*DWORD*'
        }
    }

    It 'allows only the exact originally absent ancestor chain for cleanup' {
        $state=Get-XboxSettingsFixture
        $value=$state.RegistryValues[0]
        $value.keyExisted=$false;$value.absentAncestorKeys=@($value.path)
        {Assert-NoIDXboxSettingsState $state} | Should -Not -Throw
        foreach($path in @('HKLM:\SOFTWARE\Unrelated','HKLM:\SOFTWARE',$value.path+'\Child')) {
            $value.absentAncestorKeys=@($value.path,$path)
            {Assert-NoIDXboxSettingsState $state} | Should -Throw '*ancestor chain*'
        }
    }

    It 'rejects transient or invented state on absent services and tasks' {
        $state=Get-XboxSettingsFixture
        $state.Services[0].status='StopPending'
        {Assert-NoIDXboxSettingsState $state} | Should -Throw '*unsupported*'
        $state=Get-XboxSettingsFixture
        $state.Services[0].exists=$false
        {Assert-NoIDXboxSettingsState $state} | Should -Throw '*invented*'
        $state=Get-XboxSettingsFixture
        $state.Task.Exists=$false
        {Assert-NoIDXboxSettingsState $state} | Should -Throw '*task identity*'
    }
}

Describe 'Xbox settings mutation scope' {
    BeforeEach {
        $script:Fixture=Get-XboxSettingsFixture
        $script:Applicability=[pscustomobject]@{
            RecordingPolicySupported=$true;RemovalPolicySupported=$true
            ManagementStateKnown=$true;DomainJoined=$false;MdmRegistered=$false
        }
        $script:ComponentSnapshot=[pscustomobject]@{Applicability=$script:Applicability}
        Mock Get-NoIDXboxApplicability {$script:Applicability}
        $script:FakeControllers=@{}
        foreach($name in (Get-NoIDXboxComponentCatalog).Services) {
            $controller=[pscustomobject]@{Name=$name;Status='Stopped';DependentServices=@()}
            $controller | Add-Member ScriptMethod Refresh {}
            $controller | Add-Member ScriptMethod WaitForStatus {param($Status,$Timeout) $null=$Timeout; $this.Status=[string]$Status}
            $script:FakeControllers[$name]=$controller
        }
        Mock Get-Service {
            param($Name)
            if ($Name) {
                if (@($Name).Count -ne 1) {throw 'Expected one exact service identity'}
                $identity=[string](@($Name)[0])
                if (-not $script:FakeControllers.ContainsKey($identity)) {throw 'Outside Xbox service scope'}
                return $script:FakeControllers[$identity]
            }
            @($script:FakeControllers.Values)
        }
        Mock Get-NoIDXboxSettingsState {$script:Fixture}
        Mock Resolve-NoIDXboxComponentState {'Mixed'}
        Mock Get-NoIDXboxRemovalPolicyPlan {@()}
        Mock Set-Service {}
        Mock Start-Service {}
        Mock Stop-Service {}
        Mock Resume-Service {}
        Mock Suspend-Service {}
        Mock Remove-ItemProperty {}
        Mock Set-NoIDXboxTaskEnabled {}
        Mock Set-QuickActionRegistryValue {}
        Mock Restore-QuickActionRegistryValue {}
    }

    It 'enables only the four baseline services and recording without forcing services to run' {
        Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false
        Should -Invoke Set-Service -Exactly 4 -ParameterFilter {$StartupType -eq 'Manual' -and $Name -in @('XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc')}
        Should -Invoke Start-Service -Exactly 0
        Should -Invoke Stop-Service -Exactly 0
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 1 -ParameterFilter {$Enabled}
        Should -Invoke Set-QuickActionRegistryValue -Exactly 1 -ParameterFilter {$Name -ceq 'AllowGameDVR' -and $Value -eq 1}
    }

    It 'does not rewrite already enabled service startup choices' {
        $script:Fixture.Services[0].startType='Automatic'
        $script:Fixture.Services[1].startType='Manual'
        Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false
        Should -Invoke Set-Service -Exactly 2
        Should -Invoke Set-Service -Exactly 0 -ParameterFilter {$Name -in @('XboxGipSvc','XblAuthManager')}
    }

    It 'stops only named Xbox services without force and applies disabled state' {
        foreach($controller in $script:FakeControllers.Values) {$controller.Status='Running'}
        Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Disable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false
        Should -Invoke Stop-Service -Exactly 4 -ParameterFilter {-not $Force}
        Should -Invoke Set-Service -Exactly 4 -ParameterFilter {$StartupType -eq 'Disabled'}
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 1 -ParameterFilter {-not $Enabled}
        Should -Invoke Set-QuickActionRegistryValue -Exactly 1 -ParameterFilter {$Name -ceq 'AllowGameDVR' -and $Value -eq 0}
    }

    It 'refuses an external active dependent before any mutation' {
        $script:FakeControllers.XblAuthManager.DependentServices=@([pscustomobject]@{Name='UnrelatedGameService';Status='Running'})
        {Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Disable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false} | Should -Throw '*unrelated service*'
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Stop-Service -Exactly 0
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 0
    }

    It 'rejects intervening settings changes before any mutation' {
        $live=ConvertFrom-Json (ConvertTo-Json $script:Fixture -Depth 12)
        $live.Services[0].startType='Automatic'
        Mock Get-NoIDXboxSettingsState {$live}
        {Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false} | Should -Throw '*changed after the prestate*'
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 0
    }

    It 'marks native write failures but never precondition failures as attempted mutation' {
        Mock Set-Service {throw 'Access denied'}
        try { Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false; throw 'Expected failure' }
        catch { $_.Exception.Data['XboxSettingsWriteStarted'] | Should -BeTrue }
        $script:Applicability.DomainJoined=$true
        try { Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false; throw 'Expected failure' }
        catch { $_.Exception.Data.Contains('XboxSettingsWriteStarted') | Should -BeFalse }
    }

    It 'validates the entire saved scope before changing its first target' {
        $script:Fixture.RegistryValues[-1].path='HKLM:\SOFTWARE\Unrelated'
        {Restore-NoIDXboxSettingsState -State $script:Fixture -Confirm:$false} | Should -Throw
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Restore-QuickActionRegistryValue -Exactly 0
    }

    It 'restores exact recorded settings without running any app operation' {
        Restore-NoIDXboxSettingsState -State $script:Fixture -Confirm:$false
        Should -Invoke Set-Service -Exactly 4 -ParameterFilter {$StartupType -eq 'Disabled'}
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 1 -ParameterFilter {-not $Enabled}
        Should -Invoke Restore-QuickActionRegistryValue -Exactly 13
        Should -Invoke Remove-ItemProperty -Exactly 4 -ParameterFilter {$Name -ceq 'DelayedAutoStart'}
    }

    It 'honors WhatIf without changing settings' {
        Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -WhatIf
        Restore-NoIDXboxSettingsState -State $script:Fixture -WhatIf
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Restore-QuickActionRegistryValue -Exactly 0
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
    }

    It 'refuses managed or unknown ownership for both Apply and Restore before any write' {
        foreach($field in @('ManagementStateKnown','DomainJoined','MdmRegistered')) {
            $original=$script:Applicability.$field
            $script:Applicability.$field=-not $original
            {Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false} | Should -Throw '*managed*'
            {Restore-NoIDXboxSettingsState $script:Fixture -Confirm:$false} | Should -Throw '*managed*'
            $script:Applicability.$field=$original
        }
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
        Should -Invoke Restore-QuickActionRegistryValue -Exactly 0
        Should -Invoke Set-NoIDXboxTaskEnabled -Exactly 0
    }

    It 'does not create a recording policy on unsupported editions' {
        $script:Applicability.RecordingPolicySupported=$false
        Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Disable -ComponentSnapshot $script:ComponentSnapshot -Confirm:$false
        Should -Invoke Set-Service -Exactly 4
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
    }

    It 'rejects missing or malformed ownership instead of granting write access' {
        foreach($value in @($null,'false',0)) {
            $script:Applicability.MdmRegistered=$value
            {Restore-NoIDXboxSettingsState $script:Fixture -Confirm:$false} | Should -Throw '*malformed*'
        }
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Restore-QuickActionRegistryValue -Exactly 0
    }

    It 'refreshes ownership and edition support instead of trusting a cached GUI query' {
        $snapshot=[pscustomobject]@{Applicability=ConvertFrom-Json (ConvertTo-Json $script:Applicability)}
        $script:Applicability.RemovalPolicySupported=$false
        {Invoke-NoIDXboxSettingsApply -PreState $script:Fixture -DesiredState Enable -ComponentSnapshot $snapshot -Confirm:$false} | Should -Throw '*changed*'
        Should -Invoke Get-NoIDXboxApplicability -Exactly 1
        Should -Invoke Set-Service -Exactly 0
        Should -Invoke Set-QuickActionRegistryValue -Exactly 0
    }
}
