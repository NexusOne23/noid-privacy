#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Modules/SecurityBaseline/Private/Get-SecurityBaselineSessionAsrDecision.ps1')
    function Get-SessionManifest { param($SessionPath) throw "Unmocked session read: $SessionPath" }
    function Assert-SessionManifest { param($SessionPath, $Manifest) throw "Unmocked validation: $SessionPath / $Manifest" }
    function Resolve-SessionChildPath { param($SessionPath, $RelativePath) Join-Path $SessionPath $RelativePath }
}

Describe 'SecurityBaseline consumes an earlier sealed ASR decision in the current session' {
    BeforeEach {
        $script:session = Join-Path $TestDrive 'session'
        $null = New-Item -Path $script:session -ItemType Directory -Force
        $script:artifactPath = Join-Path $script:session 'asr.json'
        $script:ruleId = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        $script:snapshot = [PSCustomObject]@{
            Targets = @(
                [PSCustomObject]@{ GUID=$script:ruleId; RequestedAction=1; OriginalAction=2 },
                [PSCustomObject]@{ GUID='01443614-cd74-433a-b99e-2ecdc07bfc25'; RequestedAction=2; OriginalAction=1 }
            )
        }
        $script:snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:artifactPath -Encoding UTF8
        $script:asrModule = [PSCustomObject]@{
            name='ASR'
            artifacts=@([PSCustomObject]@{ type='ASR'; name='ASR_ActiveConfiguration'; relativePath='asr.json' })
        }
        $script:baselineModule = [PSCustomObject]@{ name='SecurityBaseline'; artifacts=@() }
        $script:manifest = [PSCustomObject]@{ modules=@($script:asrModule, $script:baselineModule) }
        Mock Get-SessionManifest { $script:manifest }
        # The canonical validator owns artifact/schema/hash validation. These
        # tests isolate decision selection; its rejection must still propagate.
        Mock Assert-SessionManifest { $true }
    }

    It 'uses sealed requested action <Action>, preserving the original backup bytes' -ForEach @(
        @{ Action=1 }, @{ Action=2 }
    ) {
        $script:snapshot.Targets[0].RequestedAction = $Action
        $script:snapshot.Targets[0].OriginalAction = if ($Action -eq 1) { 2 } else { 1 }
        $script:snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:artifactPath -Encoding UTF8
        $before = (Get-FileHash -LiteralPath $script:artifactPath).Hash

        $result = Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session

        $result.Action | Should -Be $Action
        $result.Source | Should -BeExactly 'sealed ASR choice in the current session'
        (Get-FileHash -LiteralPath $script:artifactPath).Hash | Should -BeExactly $before
        Should -Invoke Assert-SessionManifest -Times 1 -Exactly -ParameterFilter {
            $SessionPath -eq $script:session -and $Manifest -eq $script:manifest
        }
    }

    It 'leaves baseline-only sessions to the existing durable/package fallback' {
        $script:manifest.modules = @($script:baselineModule)
        Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session | Should -BeNullOrEmpty
    }

    It 'does not borrow a later ASR decision from the sealed order' {
        $script:manifest.modules = @($script:baselineModule, $script:asrModule)
        Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session | Should -BeNullOrEmpty
    }

    It 'uses the same case-insensitive module identities as the manifest validator' {
        $script:asrModule.name = 'asr'
        $script:baselineModule.name = 'SECURITYBASELINE'
        (Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session).Action | Should -Be 1
    }

    It 'requires the current baseline backup as the ordering anchor' {
        $script:manifest.modules = @($script:asrModule)
        { Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session } |
            Should -Throw '*Current SecurityBaseline backup is missing*'
    }

    It 'propagates a rejected sealed manifest before reading any decision artifact' {
        Mock Assert-SessionManifest { throw 'Sealed artifact hash mismatch' }
        Mock Resolve-SessionChildPath { throw 'Must not read rejected evidence' }
        { Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session } |
            Should -Throw '*Sealed artifact hash mismatch*'
        Should -Invoke Resolve-SessionChildPath -Times 0 -Exactly
    }

    It 'rejects <Count> ASR decision artifacts' -ForEach @(@{ Count=0 }, @{ Count=2 }) {
        $script:asrModule.artifacts = if ($Count -eq 0) { @() } else {
            @($script:asrModule.artifacts[0], $script:asrModule.artifacts[0])
        }
        { Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session } |
            Should -Throw '*one sealed decision artifact*'
    }

    It 'rejects <Mutation> rather than selecting a different rule or unsupported action' -ForEach @(
        @{ Mutation='Disabled' }, @{ Mutation='Warn' }, @{ Mutation='Missing' }, @{ Mutation='Duplicate' }
    ) {
        switch ($Mutation) {
            'Disabled' { $script:snapshot.Targets[0].RequestedAction=0 }
            'Warn' { $script:snapshot.Targets[0].RequestedAction=6 }
            'Missing' { $script:snapshot.Targets=@($script:snapshot.Targets[1]) }
            'Duplicate' { $script:snapshot.Targets+=@($script:snapshot.Targets[0]) }
        }
        $script:snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:artifactPath -Encoding UTF8
        { Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session } |
            Should -Throw '*unique Block/Audit PSExec/WMI action*'
    }

    It 'does not fall back to an older decision when the current artifact cannot be parsed' {
        Set-Content -LiteralPath $script:artifactPath -Value '{ invalid JSON' -Encoding UTF8
        { Get-SecurityBaselineSessionAsrDecision -SessionPath $script:session } | Should -Throw
    }
}
