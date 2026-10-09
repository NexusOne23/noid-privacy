#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ModuleRoot = Join-Path $repo 'Modules/AntiAI'
    . (Join-Path $script:ModuleRoot 'Private/Get-AntiAIRegistryTargets.ps1')
    . (Join-Path $script:ModuleRoot 'Private/Assert-AntiAIRegistrySnapshot.ps1')
    function Get-AntiAIUserContext { [pscustomobject]@{Root='HKU:\S-1-5-21-1-2-3-1001'} }

    function Get-AntiAITypeFixture {
        param([string]$Type,[AllowNull()][object]$Data)
        $entries = @(Get-AntiAIRegistryTargets | ForEach-Object {
            [pscustomobject]@{
                Path=$_.Path; Name=$_.Name; KeyExisted=$true
                Exists=$false; Type=$null; Value=$null
            }
        })
        $entry = @($entries | Where-Object Path -Like 'HKLM:*')[0]
        $entry.Exists=$true; $entry.Type=$Type; $entry.Value=$Data
        return [pscustomobject]@{
            SchemaVersion=5; DeclaredTargetCount=50
            ApplicableTargetCount=$entries.Count; NotApplicableTargetCount=0
            Entries=$entries; NotApplicableTargets=@()
        }
    }
}

Describe 'AntiAI native and serialized registry prestate types' {
    It 'accepts exact <Case> data before and after backup serialization' -TestCases @(
        @{Case='native empty Binary';Type='Binary';Data=[byte[]]@()}
        @{Case='native single-byte Binary';Type='Binary';Data=[byte[]]@(42)}
        @{Case='native multi-byte Binary';Type='Binary';Data=[byte[]]@(0,1,127,128,255)}
        @{Case='serialized Int32 Binary';Type='Binary';Data=[int[]]@(0,255)}
        @{Case='serialized Int64 Binary';Type='Binary';Data=[long[]]@(0,255)}
        @{Case='empty MultiString';Type='MultiString';Data=[string[]]@()}
        @{Case='single MultiString';Type='MultiString';Data=[string[]]@('one')}
        @{Case='multiple MultiString';Type='MultiString';Data=[string[]]@('alpha','beta')}
    ) {
        param($Case,$Type,$Data)
        $null=$Case
        $snapshot=Get-AntiAITypeFixture -Type $Type -Data $Data
        $json=$snapshot|ConvertTo-Json -Depth 20 -Compress
        { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Not -Throw
        { Assert-AntiAIRegistrySnapshot -Snapshot ($json|ConvertFrom-Json) -RestoreOnly } | Should -Not -Throw
        # Validation must not coerce or mutate the captured data to make it pass.
        ($snapshot|ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $json
    }

    It 'rejects <Case> in both live and serialized input' -TestCases @(
        @{Case='negative Binary';Type='Binary';Data=@(-1)}
        @{Case='oversized Binary';Type='Binary';Data=@(256)}
        @{Case='fractional Binary';Type='Binary';Data=@(0.5)}
        @{Case='string Binary';Type='Binary';Data=@('1')}
        @{Case='Boolean Binary';Type='Binary';Data=@($true)}
        @{Case='null Binary element';Type='Binary';Data=@($null)}
        @{Case='integer MultiString element';Type='MultiString';Data=@(1)}
        @{Case='null MultiString element';Type='MultiString';Data=@($null)}
    ) {
        param($Case,$Type,$Data)
        $null=$Case
        $snapshot=Get-AntiAITypeFixture -Type $Type -Data $Data
        $json=$snapshot|ConvertTo-Json -Depth 20 -Compress
        { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Throw
        { Assert-AntiAIRegistrySnapshot -Snapshot ($json|ConvertFrom-Json) -RestoreOnly } | Should -Throw
    }
}
