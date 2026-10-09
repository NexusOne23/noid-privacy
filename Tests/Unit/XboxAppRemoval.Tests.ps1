#Requires -Version 5.1

BeforeAll {
    $repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core\XboxComponents.ps1')
    . (Join-Path $repoRoot 'Core\XboxSettings.ps1')
    . (Join-Path $repoRoot 'Core\XboxAppRemoval.ps1')
    function Get-XboxRemovalEntry {
        param([string]$Name='Microsoft.GamingApp')
        [pscustomobject]@{AppName=$Name;PackageFullName=$Name+'_1.2.3.4_x64__8wekyb3d8bbwe';PackageFamilyName=$Name+'_8wekyb3d8bbwe'}
    }
}
Describe 'Closed Xbox removal request' {
    It 'accepts the exact six families and an empty request' {
        {Assert-NoIDXboxRemovalRequest @()} | Should -Not -Throw
        $entries=@((Get-NoIDXboxComponentCatalog).Apps|Where-Object RemoveWhenDisabled|ForEach-Object {Get-XboxRemovalEntry $_.Name})
        $entries.Count | Should -Be 6
        {Assert-NoIDXboxRemovalRequest $entries} | Should -Not -Throw
    }
    It 'rejects shared Gaming Services games wildcards and substituted identities' {
        foreach($name in @('Microsoft.GamingServices','Microsoft.SomeGame','Microsoft.Xbox*','Microsoft.WindowsStore')) {
            {Assert-NoIDXboxRemovalRequest @((Get-XboxRemovalEntry $name))} | Should -Throw '*outside*'
        }
        foreach($field in @('PackageFamilyName','PackageFullName')) {
            $entry=Get-XboxRemovalEntry;$entry.$field=$entry.$field.Replace('8wekyb3d8bbwe','otherpublisher')
            {Assert-NoIDXboxRemovalRequest @($entry)} | Should -Throw
        }
    }
    It 'rejects duplicate entries extra fields and child-plus-Bundle requests' {
        $entry=Get-XboxRemovalEntry
        {Assert-NoIDXboxRemovalRequest @($entry,$entry)} | Should -Throw
        $bundle=Get-XboxRemovalEntry;$bundle.PackageFullName='Microsoft.GamingApp_1.2.3.4_neutral_~_8wekyb3d8bbwe'
        {Assert-NoIDXboxRemovalRequest @($bundle)} | Should -Not -Throw
        {Assert-NoIDXboxRemovalRequest @($entry,$bundle)} | Should -Throw '*child package*'
        $entry|Add-Member NoteProperty Command 'bad'
        {Assert-NoIDXboxRemovalRequest @($entry)} | Should -Throw '*field set*'
    }
}
Describe 'Xbox removal through the existing original-user engine' {
    BeforeEach {
        $script:XboxUser=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=1;Account='test'}
        $script:Entry=Get-XboxRemovalEntry
        $script:ReadCount=0
        Mock Get-PrivacyUserContext {$script:XboxUser}
        Mock Assert-NoIDXboxUnmanagedDevice {}
        Mock Get-NoIDXboxComponentSnapshot {
            $script:ReadCount++
            [pscustomobject]@{
                RemovablePackages=$(if($script:ReadCount -eq 1){@($script:Entry)}else{@()})
                Apps=@((Get-NoIDXboxComponentCatalog).Apps|ForEach-Object {[pscustomobject]@{Name=$_.Name;Present=(-not $_.RemoveWhenDisabled)}})
            }
        }
        Mock Invoke-PrivacyUserAppxRemoval {[pscustomobject]@{Success=$true;Entries=@()}}
    }
    It 'passes only validated parents to Privacy and independently checks removal afterwards' {
        $result=Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -Confirm:$false
        $result.Success | Should -BeTrue
        $result.AlreadyAbsent | Should -BeFalse
        Should -Invoke Invoke-PrivacyUserAppxRemoval -Exactly 1 -ParameterFilter {$Entries.Count -eq 1 -and $Entries[0].AppName -ceq 'Microsoft.GamingApp' -and $User.Sid -ceq 'S-1-5-21-1-2-3-1001'}
        Should -Invoke Get-NoIDXboxComponentSnapshot -Exactly 2
    }
    It 'does not launch a worker when selected apps are already absent' {
        $script:ReadCount=1
        $result=Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -Confirm:$false
        $result.Success | Should -BeTrue
        $result.AlreadyAbsent | Should -BeTrue
        Should -Invoke Invoke-PrivacyUserAppxRemoval -Exactly 0
    }
    It 'rejects a new version or an empty stale request before any removal' {
        {Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @() -Confirm:$false} | Should -Throw '*changed*'
        $script:ReadCount=0
        $old=Get-XboxRemovalEntry;$old.PackageFullName=$old.PackageFullName.Replace('1.2.3.4','1.2.3.3')
        {Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($old) -Confirm:$false} | Should -Throw '*changed*'
        Should -Invoke Invoke-PrivacyUserAppxRemoval -Exactly 0
    }
    It 'does not turn a partial engine failure into success' {
        Mock Invoke-PrivacyUserAppxRemoval {[pscustomobject]@{Success=$false;Entries=@()}}
        (Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -Confirm:$false).Success | Should -BeFalse
    }
    It 'does not assume worker termination after an unclassified engine exception' {
        Mock Invoke-PrivacyUserAppxRemoval {throw 'Dispatcher cleanup failed'}
        try {
            Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -Confirm:$false
            throw 'Expected cleanup failure'
        }catch{
            $_.Exception.Message | Should -Match 'Dispatcher cleanup failed'
            $_.Exception.Data['WorkerQuiesced'] | Should -BeFalse
        }
    }
    It 'preserves a newly reappeared Xbox app and reports the incomplete result' {
        Mock Get-NoIDXboxComponentSnapshot {
            [pscustomobject]@{RemovablePackages=@($script:Entry);Apps=@([pscustomobject]@{Name='Microsoft.GamingApp';Present=$true})}
        }
        $result=Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -Confirm:$false
        $result.Success | Should -BeFalse
        $result.RemainingApps | Should -Contain 'Microsoft.GamingApp'
        Should -Invoke Invoke-PrivacyUserAppxRemoval -Exactly 1
    }
    It 'honors WhatIf without removing an app' {
        Invoke-NoIDXboxAppRemoval -User $script:XboxUser -Entries @($script:Entry) -WhatIf
        Should -Invoke Invoke-PrivacyUserAppxRemoval -Exactly 0
    }
}
