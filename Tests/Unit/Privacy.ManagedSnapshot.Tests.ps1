#Requires -Version 5.1
BeforeAll {
    $repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($helper in @('Get-PrivacyTier1PolicyDefinition','Get-PrivacyTier1RestorePolicyDefinitions',
            'PrivacyAppxFirewall','Assert-PrivacyRegistrySnapshot','Assert-PrivacyPrestate')) {
        . (Join-Path $repo "Modules/Privacy/Private/$helper.ps1")
    }
    function Get-PrivacyApplicability { throw 'Unmocked applicability' }
    function Test-NoIDRegistryKey { param($LiteralPath) $null=$LiteralPath; throw 'Unmocked registry' }
    function Get-NoIDScheduledTask { throw 'Unmocked tasks' }
}
Describe 'Managed Privacy snapshots preserve ownership and legacy restore' {
    BeforeEach {
        $firewall=[pscustomobject]@{
            SchemaVersion=1;RegistryPath=$script:PrivacyAppxFirewallRegistryPath;KeyExisted=$false
            PackageFamilyNames=@();EntryCount=0;Entries=@();StateSha256=''
        }
        $firewall.StateSha256=Get-PrivacyAppxFirewallStateHash $firewall
        $tier1=@((Get-PrivacyTier1PolicyDefinition).Targets | ForEach-Object {
            [pscustomobject]@{Path=$_.Path;Name=$_.Name;ApplyType=$_.Type;ApplyValue=$_.Value;Reason='Managed PC'}
        })
        $script:snapshot=[pscustomobject]@{
            SchemaVersion=7;Mode='Strict';InteractiveUserSid='S-1-5-21-1-2-3-1001'
            EditionFamily='Professional';BuildNumber=26300
            DomainJoined=$false;MdmRegistered=$true;ManagementStateKnown=$true;MultiSession=$false
            Tier1PolicyRemovalSelected=$false;Tier2BloatwareRemovalSelected=$false;WeatherWidgetRemovalSelected=$false
            AppxFirewallState=$firewall;DeclaredRegistryTargetCount=28;TargetCount=1
            NotApplicableRegistryTargets=$tier1;NotCheckedRegistryTargets=@()
            DeclaredServiceNames=@('dmwappushservice');ApplicableServiceNames=@();PreservedServiceNames=@('dmwappushservice')
            DeclaredScheduledTaskPaths=@('\Microsoft\Windows\NoID\Task');ApplicableScheduledTaskPaths=@()
            PreservedScheduledTaskPaths=@('\Microsoft\Windows\NoID\Task')
            Entries=@([pscustomobject]@{
                Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
                Name='Start_TrackProgs';ApplyType='DWord';ApplyValue=0
                KeyExisted=$false;Exists=$false;Type=$null;Value=$null
            })
        }
        Mock Get-PrivacyApplicability { $script:snapshot }
        Mock Test-NoIDRegistryKey { $false }
        Mock Get-PrivacyAppxFirewallState { $script:snapshot.AppxFirewallState }
        Mock Get-Service { [pscustomobject]@{Name='dmwappushservice';StartType='Automatic';Status='Running'} }
        Mock Get-NoIDScheduledTask { [pscustomobject]@{TaskPath='\Microsoft\Windows\NoID\';TaskName='Task';State='Ready'} }
    }
    It 'accepts preserved resources without claiming they are absent, including after JSON roundtrip' {
        $snapshot=$script:snapshot | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        Assert-PrivacyRegistrySnapshot $snapshot | Should -BeTrue
        Assert-PrivacyRegistrySnapshot $snapshot -RestoreOnly | Should -BeTrue
        $path=Join-Path $TestDrive 'prestate.json'
        $snapshot | ConvertTo-Json -Depth 20 | Set-Content $path -Encoding UTF8
        Assert-PrivacyPrestate -SnapshotPath $path -Artifacts @(
            [pscustomobject]@{Type='Privacy';Name='Privacy_PreState';BackupFile=$path}
        ) -WindowsSearchPreflightAlreadyProven | Should -BeTrue
    }
    It 'accepts the sealed service startup types, also after JSON roundtrip' {
        $script:snapshot | Add-Member -NotePropertyName ServiceStartupTypes -NotePropertyValue ([ordered]@{ dmwappushservice = 'Disabled' })
        Assert-PrivacyRegistrySnapshot $script:snapshot | Should -BeTrue
        Assert-PrivacyRegistrySnapshot ($script:snapshot | ConvertTo-Json -Depth 20 | ConvertFrom-Json) -RestoreOnly | Should -BeTrue
        $script:snapshot.ServiceStartupTypes = [ordered]@{ dmwappushservice = 'Manual' }
        Assert-PrivacyRegistrySnapshot $script:snapshot | Should -BeTrue
    }
    It 'accepts an empty startup-type inventory for a mode without services, also after JSON roundtrip' {
        # MSRecommended declares no service. Its empty inventory reads back as an
        # object without properties; Windows PowerShell 5.1 then enumerates a
        # single $null name, which once failed every MSRecommended backup.
        $script:snapshot.DeclaredServiceNames = @()
        $script:snapshot.ApplicableServiceNames = @()
        $script:snapshot.PreservedServiceNames = @()
        $script:snapshot | Add-Member -NotePropertyName ServiceStartupTypes -NotePropertyValue ([ordered]@{})
        Assert-PrivacyRegistrySnapshot $script:snapshot | Should -BeTrue
        $roundTrip = $script:snapshot | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        @($roundTrip.ServiceStartupTypes.PSObject.Properties).Count | Should -Be 0
        Assert-PrivacyRegistrySnapshot $roundTrip | Should -BeTrue
        Assert-PrivacyRegistrySnapshot $roundTrip -RestoreOnly | Should -BeTrue
    }
    It 'rejects an unknown startup type or a startup type for an undeclared service' {
        $script:snapshot | Add-Member -NotePropertyName ServiceStartupTypes -NotePropertyValue ([ordered]@{ dmwappushservice = 'Automatic' })
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*service startup-type inventory is invalid*'
        $script:snapshot.ServiceStartupTypes = [ordered]@{ dmwappushservice = 'Disabled'; WerSvc = 'Manual' }
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*service startup-type inventory is invalid*'
        $script:snapshot.ServiceStartupTypes = [ordered]@{}
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*service startup-type inventory is invalid*'
    }
    It 'still validates older schema-7 snapshots without the additive inventories' {
        $script:snapshot.PSObject.Properties.Remove('PreservedServiceNames')
        $script:snapshot.PSObject.Properties.Remove('PreservedScheduledTaskPaths')
        Assert-PrivacyRegistrySnapshot $script:snapshot -RestoreOnly | Should -BeTrue
    }
    It 'rejects a preserved resource outside the declared scope' {
        $script:snapshot.PreservedServiceNames=@('WinDefend')
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*preserved-resource inventory is invalid*'
    }
    It 'rejects an applicable resource also claimed as preserved' {
        $script:snapshot.ApplicableServiceNames=@('dmwappushservice')
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*preserved-resource inventory is invalid*'
    }
    It 'rejects duplicate preserved identities without case sensitivity' {
        $script:snapshot.PreservedServiceNames=@('dmwappushservice','DMWAPPUSHSERVICE')
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*preserved-resource inventory is invalid*'
    }
    It 'rejects management preservation falsely claimed on an unmanaged PC' {
        $script:snapshot.MdmRegistered=$false
        { Assert-PrivacyRegistrySnapshot $script:snapshot } | Should -Throw '*unmanaged PC*'
    }
}
