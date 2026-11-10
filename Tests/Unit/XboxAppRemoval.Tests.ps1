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
Describe 'Closed Xbox app inventory' {
    It 'accepts the exact six families and an empty inventory' {
        {Assert-NoIDXboxAppInventory @()} | Should -Not -Throw
        $entries=@((Get-NoIDXboxComponentCatalog).Apps|Where-Object LegacyRemoveWhenDisabled|ForEach-Object {Get-XboxRemovalEntry $_.Name})
        $entries.Count | Should -Be 6
        {Assert-NoIDXboxAppInventory $entries} | Should -Not -Throw
    }
    It 'rejects shared Gaming Services games wildcards and substituted identities' {
        foreach($name in @('Microsoft.GamingServices','Microsoft.SomeGame','Microsoft.Xbox*','Microsoft.WindowsStore')) {
            {Assert-NoIDXboxAppInventory @((Get-XboxRemovalEntry $name))} | Should -Throw '*outside*'
        }
        foreach($field in @('PackageFamilyName','PackageFullName')) {
            $entry=Get-XboxRemovalEntry;$entry.$field=$entry.$field.Replace('8wekyb3d8bbwe','otherpublisher')
            {Assert-NoIDXboxAppInventory @($entry)} | Should -Throw
        }
    }
    It 'rejects duplicate entries extra fields and child-plus-Bundle inventories' {
        $entry=Get-XboxRemovalEntry
        {Assert-NoIDXboxAppInventory @($entry,$entry)} | Should -Throw
        $bundle=Get-XboxRemovalEntry;$bundle.PackageFullName='Microsoft.GamingApp_1.2.3.4_neutral_~_8wekyb3d8bbwe'
        {Assert-NoIDXboxAppInventory @($bundle)} | Should -Not -Throw
        {Assert-NoIDXboxAppInventory @($entry,$bundle)} | Should -Throw '*child package*'
        $entry|Add-Member NoteProperty Command 'bad'
        {Assert-NoIDXboxAppInventory @($entry)} | Should -Throw '*field set*'
    }
}
Describe 'Xbox switch without app removal' {
    It 'offers no app removal: switching off changes the hardened settings only' {
        Get-Command Invoke-NoIDXboxAppRemoval -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
