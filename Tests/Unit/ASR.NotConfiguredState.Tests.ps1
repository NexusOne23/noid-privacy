#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/ASR/Private/ConvertFrom-ASRPreference.ps1')
}

Describe 'Defender ASR rule modes observed on the machine' {
    It 'accepts documented mode <Action> as existing state' -TestCases @(
        @{ Action = 0 }, @{ Action = 1 }, @{ Action = 2 }, @{ Action = 5 }, @{ Action = 6 }
    ) {
        param($Action)
        $preference = [PSCustomObject]@{
            AttackSurfaceReductionRules_Ids = @('A8F5898E-1DC8-49A9-9878-85004B8A61E6')
            AttackSurfaceReductionRules_Actions = @($Action)
        }
        $state = ConvertFrom-ASRPreference -Preference $preference
        $state.Map['a8f5898e-1dc8-49a9-9878-85004b8a61e6'] | Should -Be $Action
    }

    It 'rejects the undocumented mode <Action>' -TestCases @(@{ Action = 3 }, @{ Action = 4 }, @{ Action = 7 }) {
        param($Action)
        $preference = [PSCustomObject]@{
            AttackSurfaceReductionRules_Ids = @('a8f5898e-1dc8-49a9-9878-85004b8a61e6')
            AttackSurfaceReductionRules_Actions = @($Action)
        }
        { ConvertFrom-ASRPreference -Preference $preference } | Should -Throw '*invalid ASR state*'
    }

    It 'keeps the sealed snapshot reader and NoID-requested actions consistent with those modes' {
        $snapshotReader = Get-Content (Join-Path $repo 'Modules/ASR/Private/Assert-ASRSnapshot.ps1') -Raw -Encoding UTF8
        $snapshotReader | Should -Match '\[int\]\$target\.OriginalAction -notin @\(0, 1, 2, 5, 6\)'
        $snapshotReader | Should -Match '\[int\]\$target\.RequestedAction -notin @\(0, 1, 2, 6\)' -Because 'NoID Privacy never requests Not configured'
    }
}
