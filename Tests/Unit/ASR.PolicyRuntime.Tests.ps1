#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/AsrPolicyRuntime.ps1')
    $script:RuleId = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
    function Copy-RuntimeFixture($Value) { return ($Value | ConvertTo-Json -Depth 10 | ConvertFrom-Json) }
    function Get-RuntimeFixtureValue {
        param($Action=$null, [string]$Kind='DWord')
        return [pscustomobject][ordered]@{
            KeyExisted=$true; Exists=($null -ne $Action)
            Name=if ($null -ne $Action) { $script:RuleId } else { $null }
            Kind=if ($null -ne $Action) { $Kind } else { $null }
            Data=if ($null -eq $Action) { $null } elseif ($Kind -eq 'String') { [string]$Action } else { [int]$Action }
        }
    }
    function Get-RuntimeFixtureRecord {
        $record = [pscustomobject][ordered]@{
            SchemaVersion=1; Target='AsrPolicyRuntime'; RuleId=$script:RuleId
            Policy=(Copy-RuntimeFixture $script:Policy); Local=(Copy-RuntimeFixture $script:Local)
            MissingPolicyKeys=@(); GuardAction=2; TemporaryAction=1; ContentSha256=''
        }
        $record.ContentSha256 = Get-NoIDAsrRuntimeRecordHash $record
        return $record
    }
    # Define native cmdlet stubs for hosts without the Defender module. Every
    # invocation in this suite is mocked; tests must never configure Defender.
    foreach ($name in @('Get-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'Get-Service')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item "Function:$name" { throw 'The native Defender command must be mocked' }
        }
    }
}

Describe 'Scoped ASR policy runtime synchronization and interruption recovery' {
    BeforeEach {
        $script:Journal = Join-Path $TestDrive 'asr-runtime-pending.json'
        if (Test-Path $script:Journal) { Remove-Item -LiteralPath $script:Journal -Force }
        $script:Policy = Get-RuntimeFixtureValue 2 String
        $script:Local = Get-RuntimeFixtureValue
        $script:NativeCalls = [Collections.Generic.List[string]]::new()
        $script:FailRemove = $false
        $script:FailAfterAddOnce = $false
        Mock Get-NoIDAsrRuntimePath {
            param($Kind)
            if ($Kind -ne 'Journal') { return 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' }
            return $script:Journal
        }
        Mock Get-NoIDAsrRuntimeValue {
            param($Kind, $RuleId)
            if ([guid]$RuleId -ne [guid]$script:RuleId) { throw 'Unexpected runtime target' }
            if ($Kind -eq 'Local') { return (Copy-RuntimeFixture $script:Local) }
            return (Copy-RuntimeFixture $script:Policy)
        }
        Mock Get-NoIDAsrRuntimeMissingPolicyKeys { @() }
        Mock Initialize-NoIDIntentStateDirectory { return $TestDrive }
        Mock Set-NoIDIntentPathSecurity { }
        Mock Assert-NoIDIntentStateAcl { $true }
        Mock Start-Sleep { }
        Mock Get-MpPreference {
            $mode = if ($script:Policy.Exists) { [int]$script:Policy.Data }
                elseif ($script:Local.Exists) { [int]$script:Local.Data } else { $null }
            return [pscustomobject]@{
                AttackSurfaceReductionRules_Ids=@(if ($null -ne $mode) { $script:RuleId })
                AttackSurfaceReductionRules_Actions=@(if ($null -ne $mode) { $mode })
            }
        }
        Mock Write-NoIDAsrRuntimePolicy {
            param($RuleId, $State)
            if ([guid]$RuleId -ne [guid]$script:RuleId) { throw 'Unexpected policy target' }
            $null = Assert-NoIDAsrRuntimeRecord (Read-NoIDAsrRuntimeRecord)
            $script:Policy = Copy-RuntimeFixture $State
        }
        Mock Add-MpPreference {
            param($AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions)
            $AttackSurfaceReductionRules_Ids | Should -BeExactly $script:RuleId
            $null = Assert-NoIDAsrRuntimeRecord (Read-NoIDAsrRuntimeRecord)
            @($AttackSurfaceReductionRules_Actions).Count | Should -Be 1
            $action = [int]@($AttackSurfaceReductionRules_Actions)[0]
            $script:NativeCalls.Add('Add:' + [string]$action)
            $script:Local = Get-RuntimeFixtureValue $action
            if ($script:FailAfterAddOnce) { $script:FailAfterAddOnce=$false; throw 'Native failure after mutation' }
        }
        Mock Remove-MpPreference {
            param($AttackSurfaceReductionRules_Ids)
            $AttackSurfaceReductionRules_Ids | Should -BeExactly $script:RuleId
            $null = Assert-NoIDAsrRuntimeRecord (Read-NoIDAsrRuntimeRecord)
            $script:NativeCalls.Add('Remove')
            if ($script:FailRemove) { throw 'Native recovery unavailable' }
            $script:Local = Get-RuntimeFixtureValue
        }
    }

    It 'publishes recovery before the native call and leaves no local rule or journal' {
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false
        ($script:NativeCalls -join ',') | Should -BeExactly 'Add:1,Remove'
        $script:Policy.Data | Should -BeExactly '2'
        $script:Local.Exists | Should -BeFalse
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'preserves an existing local mode <Mode> instead of materializing the merged rule list' -TestCases @(
        @{Mode=0;Temporary=1}, @{Mode=1;Temporary=2}, @{Mode=2;Temporary=1},
        @{Mode=5;Temporary=1}, @{Mode=6;Temporary=1}
    ) {
        param($Mode, $Temporary)
        $script:Local = Get-RuntimeFixtureValue $Mode
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false
        ($script:NativeCalls -join ',') | Should -BeExactly "Add:$Temporary,Add:$Mode"
        $script:Local.Data | Should -Be $Mode
        $script:Policy.Data | Should -BeExactly '2'
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'restores an absent policy after consuming an existing local preference' {
        $script:Policy = Get-RuntimeFixtureValue
        $script:Local = Get-RuntimeFixtureValue 2
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false
        $script:Policy.Exists | Should -BeFalse
        $script:Local.Data | Should -Be 2
        Should -Invoke Write-NoIDAsrRuntimePolicy -Times 2 -Exactly
    }

    It 'keeps an originally unconfigured rule unconfigured in both stores' {
        $script:Policy = Get-RuntimeFixtureValue
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false
        $script:Policy.Exists | Should -BeFalse
        $script:Local.Exists | Should -BeFalse
        Should -Invoke Write-NoIDAsrRuntimePolicy -Times 1 -Exactly -ParameterFilter { $State.Exists -and $State.Data -ceq '0' }
    }

    It 'recovers a native partial failure but still reports that failure' {
        $script:FailAfterAddOnce=$true
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw '*Native failure after mutation*'
        $script:Local.Exists | Should -BeFalse
        $script:Policy.Data | Should -BeExactly '2'
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'accepts native null arrays on a PC with no configured ASR rules' {
        $script:Policy = Get-RuntimeFixtureValue
        Mock Get-MpPreference {
            [pscustomobject]@{ AttackSurfaceReductionRules_Ids=$null; AttackSurfaceReductionRules_Actions=$null }
        }
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false
        $script:Local.Exists | Should -BeFalse
        $script:Policy.Exists | Should -BeFalse
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'recovers interruption at <Stage> with the original absent policy intact' -TestCases @(
        @{Stage='published'}, @{Stage='guard'}, @{Stage='native'}, @{Stage='local-restored'}
    ) {
        param($Stage)
        $script:Policy = Get-RuntimeFixtureValue
        $record = Get-RuntimeFixtureRecord
        $record.GuardAction = 0
        $record.ContentSha256 = Get-NoIDAsrRuntimeRecordHash $record
        $record | ConvertTo-Json -Depth 8 | Set-Content $script:Journal
        if ($Stage -ne 'published') { $script:Policy = Get-NoIDAsrRuntimeGuard $record }
        if ($Stage -eq 'native') { $script:Local = Get-RuntimeFixtureValue 1 }
        Restore-NoIDPendingAsrRuntime -Confirm:$false
        $script:Local.Exists | Should -BeFalse
        $script:Policy.Exists | Should -BeFalse
        Test-Path $script:Journal | Should -BeFalse
        $script:NativeCalls.Count | Should -Be $(if ($Stage -eq 'native') { 1 } else { 0 })
    }

    It 'rejects mismatched Defender arrays before publishing recovery' {
        Mock Get-MpPreference {
            [pscustomobject]@{ AttackSurfaceReductionRules_Ids=@($script:RuleId); AttackSurfaceReductionRules_Actions=@() }
        }
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw '*mismatched ASR arrays*'
        $script:NativeCalls.Count | Should -Be 0
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'retains recovery authority on cleanup failure and replays it on retry' {
        $script:FailRemove=$true
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw '*Native recovery unavailable*'
        Test-Path $script:Journal | Should -BeTrue
        $script:Local.Data | Should -Be 1
        $script:FailRemove=$false
        Restore-NoIDPendingAsrRuntime -Confirm:$false
        $script:Local.Exists | Should -BeFalse
        Test-Path $script:Journal | Should -BeFalse
    }

    It 'refuses later local changes without consuming the pending journal' {
        $script:FailRemove=$true
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw
        $script:FailRemove=$false
        $script:Local = Get-RuntimeFixtureValue 6
        $calls=$script:NativeCalls.Count
        { Restore-NoIDPendingAsrRuntime -Confirm:$false } | Should -Throw '*later state has not been overwritten*'
        $script:NativeCalls.Count | Should -Be $calls
        $script:Local.Data | Should -Be 6
        Test-Path $script:Journal | Should -BeTrue
    }

    It 'refuses a later policy change without altering either store' {
        $script:FailRemove=$true
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw
        $script:Policy = Get-RuntimeFixtureValue 6 String
        $calls=$script:NativeCalls.Count
        { Restore-NoIDPendingAsrRuntime -Confirm:$false } | Should -Throw '*later state has not been overwritten*'
        $script:NativeCalls.Count | Should -Be $calls
        $script:Policy.Data | Should -BeExactly '6'
    }

    It 'refuses a second operation while a valid recovery record exists' {
        Get-RuntimeFixtureRecord | ConvertTo-Json -Depth 8 | Set-Content $script:Journal
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -Confirm:$false } | Should -Throw '*Pending ASR runtime recovery*'
        $script:NativeCalls.Count | Should -Be 0
    }

    It 'rejects content corruption before invoking any native mutation' {
        $record=Get-RuntimeFixtureRecord
        $record.GuardAction=1
        $record | ConvertTo-Json -Depth 8 | Set-Content $script:Journal
        { Restore-NoIDPendingAsrRuntime -Confirm:$false } | Should -Throw '*content hash differs*'
        $script:NativeCalls.Count | Should -Be 0
    }

    It 'rejects an invalid target even with a recomputed content hash' {
        $record=Get-RuntimeFixtureRecord
        $record.Policy.Name='OtherRegistryValue'
        $record.ContentSha256=Get-NoIDAsrRuntimeRecordHash $record
        { Assert-NoIDAsrRuntimeRecord $record } | Should -Throw '*outside the recorded target*'
    }

    It 'rejects an ancestor outside the ASR policy scope' {
        $record=Get-RuntimeFixtureRecord
        $record.Policy.KeyExisted=$false;$record.Policy.Exists=$false
        $record.Policy.Name=$null;$record.Policy.Kind=$null;$record.Policy.Data=$null
        $record.MissingPolicyKeys=@('SOFTWARE')
        $record.ContentSha256=Get-NoIDAsrRuntimeRecordHash $record
        { Assert-NoIDAsrRuntimeRecord $record } | Should -Throw '*invalid absent policy ancestor*'
    }

    It 'rejects an untrusted journal ACL without trying to repair it' {
        Get-RuntimeFixtureRecord | ConvertTo-Json -Depth 8 | Set-Content $script:Journal
        Mock Assert-NoIDIntentStateAcl { throw 'Untrusted journal ACL' }
        { Restore-NoIDPendingAsrRuntime -Confirm:$false } | Should -Throw '*Untrusted journal ACL*'
        Should -Invoke Set-NoIDIntentPathSecurity -Times 0 -Exactly
        $script:NativeCalls.Count | Should -Be 0
    }

    It 'does not mutate preferences, policy or recovery files in WhatIf mode' {
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -WhatIf
        $script:NativeCalls.Count | Should -Be 0
        Test-Path $script:Journal | Should -BeFalse
        Should -Invoke Initialize-NoIDIntentStateDirectory -Times 0 -Exactly
        Should -Invoke Write-NoIDAsrRuntimePolicy -Times 0 -Exactly
    }

    It 'preserves policy without starting a stopped Defender for baseline-only changes' {
        Mock Get-Service { [pscustomobject]@{Status='Stopped'} }
        Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -AllowStoppedDefender -Confirm:$false -WarningAction SilentlyContinue
        $script:NativeCalls.Count | Should -Be 0
        Test-Path $script:Journal | Should -BeFalse
        Should -Invoke Write-NoIDAsrRuntimePolicy -Times 0 -Exactly
    }

    It 'fails visibly when optional Defender service state cannot be read' {
        Mock Get-Service { throw 'Defender service query failed' }
        { Sync-NoIDAsrPolicyRuntime -RuleId $script:RuleId -AllowStoppedDefender -Confirm:$false } | Should -Throw '*service query failed*'
        $script:NativeCalls.Count | Should -Be 0
        Test-Path $script:Journal | Should -BeFalse
    }
}
