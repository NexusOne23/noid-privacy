#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:VerifierSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw
    $script:MutexProbeSource = @'
param($MutexName)
$mutex = [Threading.Mutex]::new($false, $MutexName)
try {
    $acquired = $mutex.WaitOne(0, $false)
    if ($acquired) { $mutex.ReleaseMutex() }
    return $acquired
}
finally { $mutex.Dispose() }
'@

    function Test-IndependentMutexAvailable {
        param([string]$Name)
        $probe = [PowerShell]::Create()
        try {
            $null = $probe.AddScript($script:MutexProbeSource).AddArgument($Name)
            $answer = @($probe.Invoke())
            if ($probe.HadErrors -or $answer.Count -ne 1) { throw 'Independent mutex probe failed' }
            return [bool]$answer[0]
        }
        finally { $probe.Dispose() }
    }
}

Describe 'Verifier mutation exclusion before intent reads' {
    BeforeEach {
        $script:FixtureRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:MutexName = 'Global\NoIDVerifierTest_' + [Guid]::NewGuid().ToString('N')
        foreach ($folder in @('Tools/Private', 'Config', 'Core', 'Utils', 'Session')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:FixtureRoot $folder) -Force
        }
        # Only definitions are loaded before the observation point. Empty
        # helpers isolate this concurrency test from Windows and report APIs.
        foreach ($file in @(
                'Tools/Private/Get-PrivacyVerificationPresentation.ps1',
                'Tools/Private/Get-VerificationModulePresentation.ps1',
                'Tools/Private/Get-VerificationNotCheckedAccounting.ps1',
                'Core/IntentState.ps1', 'Core/AsrPolicyRuntime.ps1', 'Utils/SecurityProducts.ps1'
            )) {
            [IO.File]::WriteAllText((Join-Path $script:FixtureRoot $file), '', [Text.UTF8Encoding]::new($false))
        }
        # Runtime rejection has its own native entrypoint regressions. These
        # fixtures model an accepted host and stop before Windows measurements,
        # so the mutex lifecycle remains independently testable on any host.
        [IO.File]::WriteAllText((Join-Path $script:FixtureRoot 'Core/Runtime.ps1'),
            'function Assert-NoIDPowerShellRuntime {}', [Text.UTF8Encoding]::new($false))
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'Config/SettingsCounts.json') `
            -Destination (Join-Path $script:FixtureRoot 'Config/SettingsCounts.json')
        $config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw | ConvertFrom-Json
        foreach ($module in $config.modules.PSObject.Properties) { $module.Value.enabled = ($module.Name -ceq 'ASR') }
        $script:ConfigPath = Join-Path $script:FixtureRoot 'config.json'
        [IO.File]::WriteAllText($script:ConfigPath, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        $script:SessionPath = Join-Path $script:FixtureRoot 'Session'
        [IO.File]::WriteAllText((Join-Path $script:SessionPath 'manifest.json'), '{"sessionId":"test-observation-only"}', [Text.UTF8Encoding]::new($false))

        $readStatement = '$sessionIntentState = Read-NoIDIntentState -AllowMissing'
        ([regex]::Matches($script:VerifierSource, [regex]::Escape($readStatement))).Count | Should -Be 1
        $observation = @'
$probe = [PowerShell]::Create()
try {
    $null = $probe.AddScript('__PROBE_SOURCE__').AddArgument('__MUTEX_NAME__')
    $answers = @($probe.Invoke())
    if ($probe.HadErrors -or $answers.Count -ne 1) { throw 'Observation failed' }
    [PSCustomObject]@{ NoIDMutexProbe = $true; MutationCanStart = [bool]$answers[0] }
}
finally { $probe.Dispose() }
return
'@
        $observation = $observation.Replace('__MUTEX_NAME__', $script:MutexName)
        $observation = $observation.Replace('__PROBE_SOURCE__', $script:MutexProbeSource.Replace("'", "''"))
        # Stop at the real intent-read site: no operating-system measurement
        # or mutation runs. Only this test copy omits the administrator check.
        $candidate = $script:VerifierSource.Replace('#Requires -RunAsAdministrator', '')
        $candidate = $candidate.Replace('Global\NoIDPrivacyMutationV1', $script:MutexName)
        $candidate = $candidate.Replace($readStatement, $observation)
        $script:CandidatePath = Join-Path $script:FixtureRoot 'Tools/Verify.ps1'
        [IO.File]::WriteAllText($script:CandidatePath, $candidate, [Text.UTF8Encoding]::new($false))
    }

    It 'excludes another thread before reading intent and releases after early return' {
        $observations = @(& $script:CandidatePath -ModulesCsv ASR -ConfigPath $script:ConfigPath `
                -AppliedSessionPath $script:SessionPath | Where-Object { $_.PSObject.Properties['NoIDMutexProbe'] })
        $observations.Count | Should -Be 1
        $observations[0].MutationCanStart | Should -BeFalse
        Test-IndependentMutexAvailable -Name $script:MutexName | Should -BeTrue
    }

    It 'refuses an already-running mutation before reaching intent' {
        $ready = [Threading.ManualResetEvent]::new($false)
        $finish = [Threading.ManualResetEvent]::new($false)
        $holder = [PowerShell]::Create()
        $null = $holder.AddScript({
                param($Name, $ReadyEvent, $FinishEvent)
                $mutex = [Threading.Mutex]::new($false, $Name)
                try {
                    $null = $mutex.WaitOne()
                    try { $null = $ReadyEvent.Set(); $null = $FinishEvent.WaitOne(10000) }
                    finally { $mutex.ReleaseMutex() }
                }
                finally { $mutex.Dispose() }
            }).AddArgument($script:MutexName).AddArgument($ready).AddArgument($finish)
        $pending = $holder.BeginInvoke()
        try {
            $ready.WaitOne(5000) | Should -BeTrue
            { & $script:CandidatePath -ModulesCsv ASR -ConfigPath $script:ConfigPath -AppliedSessionPath $script:SessionPath } |
                Should -Throw '*Another NoID Privacy Apply, Restore or Quick Action*'
        }
        finally {
            $null = $finish.Set()
            $null = $holder.EndInvoke($pending)
            $holder.Dispose(); $ready.Dispose(); $finish.Dispose()
        }
        Test-IndependentMutexAvailable -Name $script:MutexName | Should -BeTrue
    }

    It 'releases when an early required-input check throws' {
        # A checkout copied from release media can retain ReadOnly on the
        # copied fixture. Verify the intended missing-input condition before
        # invoking the verifier, rather than continuing after a failed delete.
        $missingInput = Join-Path $script:FixtureRoot 'Config/SettingsCounts.json'
        Remove-Item -LiteralPath $missingInput -Force -ErrorAction Stop
        Test-Path -LiteralPath $missingInput | Should -BeFalse
        { & $script:CandidatePath -ModulesCsv ASR -ConfigPath $script:ConfigPath -AppliedSessionPath $script:SessionPath } |
            Should -Throw '*Canonical settings count file is missing*'
        Test-IndependentMutexAvailable -Name $script:MutexName | Should -BeTrue
    }
}
