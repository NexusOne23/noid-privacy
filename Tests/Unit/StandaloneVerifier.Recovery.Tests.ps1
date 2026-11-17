#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $harness = Join-Path $repo 'Tests/Windows11/Invoke-Windows11StandaloneVerifierValidation.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($harness, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Standalone harness does not parse' }
    foreach ($name in @('Get-StandaloneSessionSignature', 'Copy-StandaloneRecoverySession',
            'Invoke-StandaloneRestore', 'Invoke-StandaloneFailureRecovery', 'Invoke-StateCapture',
            'Compare-IndependentStateFingerprint', 'Get-RegistryEntryIdentity',
            'Invoke-StandaloneVerification', 'Assert-SelectedPrivacyVerifierUx')) {
        $definition = $ast.Find({ param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            }, $false)
        if ($null -eq $definition) { throw "Missing standalone helper: $name" }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $workflow = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [Management.Automation.Language.TryStatementAst] -and
            $_.Extent.Text -match 'Full Strict Apply failed'
        })
    if ($workflow.Count -ne 1) { throw 'Expected one recovery-protected standalone workflow' }
    $script:StandaloneWorkflow = [scriptblock]::Create($workflow[0].Extent.Text)
}

Describe 'Standalone verifier recovery archive' {
    BeforeEach {
        $caseRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:ArchiveSource = Join-Path $caseRoot 'session'
        $script:ArchiveRoot = Join-Path $caseRoot 'archive'
        $null = New-Item -Path (Join-Path $script:ArchiveSource 'module') -ItemType Directory -Force
        $null = New-Item -Path $script:ArchiveRoot -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:ArchiveSource 'manifest.json') -Value '{"sealed":"fixture"}'
        Set-Content -LiteralPath (Join-Path $script:ArchiveSource 'module/prestate.json') -Value '{"saved":"original"}'
        $script:ArchiveOriginal = Get-StandaloneSessionSignature -SessionPath $script:ArchiveSource
    }

    It 'copies and checks every file while preserving the original session' {
        $copy = Copy-StandaloneRecoverySession -SessionPath $script:ArchiveSource -ArchiveRoot $script:ArchiveRoot
        Get-StandaloneSessionSignature -SessionPath $copy | Should -BeExactly $script:ArchiveOriginal
        Get-StandaloneSessionSignature -SessionPath $script:ArchiveSource | Should -BeExactly $script:ArchiveOriginal
    }

    It 'detects <Damage> even when the copied manifest is unchanged' -TestCases @(
        @{Damage='a corrupt payload'}, @{Damage='a missing payload'}
    ) {
        param($Damage)
        $script:ArchiveDamage = $Damage
        Mock Copy-Item {
            param($LiteralPath, $Destination)
            $null = [IO.Directory]::CreateDirectory((Join-Path $Destination 'module'))
            foreach ($relative in @('manifest.json', 'module/prestate.json')) {
                [IO.File]::Copy((Join-Path $LiteralPath $relative), (Join-Path $Destination $relative))
            }
            $payload = Join-Path $Destination 'module/prestate.json'
            if ($script:ArchiveDamage -eq 'a corrupt payload') { Set-Content -LiteralPath $payload -Value 'damaged' }
            else { Remove-Item -LiteralPath $payload -Force }
        }
        { Copy-StandaloneRecoverySession -SessionPath $script:ArchiveSource -ArchiveRoot $script:ArchiveRoot } |
            Should -Throw '*does not match every original session file*'
        Get-StandaloneSessionSignature -SessionPath $script:ArchiveSource | Should -BeExactly $script:ArchiveOriginal
        $sourceManifest = Join-Path $script:ArchiveSource 'manifest.json'
        $copyManifest = Join-Path $script:ArchiveRoot 'session/manifest.json'
        (Get-FileHash -LiteralPath $copyManifest).Hash | Should -BeExactly (Get-FileHash -LiteralPath $sourceManifest).Hash
    }

    It 'refuses to overwrite an existing archive destination' {
        $destination = Join-Path $script:ArchiveRoot 'session'
        $null = New-Item -Path $destination -ItemType Directory
        $sentinel = Join-Path $destination 'owner.txt'
        Set-Content -LiteralPath $sentinel -Value 'preserve'
        { Copy-StandaloneRecoverySession -SessionPath $script:ArchiveSource -ArchiveRoot $script:ArchiveRoot } |
            Should -Throw '*destination already exists*'
        (Get-Content -LiteralPath $sentinel -Raw).Trim() | Should -BeExactly 'preserve'
    }
}

Describe 'Standalone verifier recovery after a failed validation' {
    BeforeEach {
        $script:RecoveryRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $existing = New-Item -Path (Join-Path $script:RecoveryRoot 'old-session') -ItemType Directory -Force
        $script:RecoveryKnown = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $null = $script:RecoveryKnown.Add($existing.FullName)
        $script:RecoveryBefore = [pscustomobject]@{
            StateAfter = [pscustomobject]@{CombinedHash='original';Components=[pscustomobject]@{Registry='original'}}
            RegistrySnapshotBefore = @()
        }
        $script:RecoveryAfter = $script:RecoveryBefore
        Mock Invoke-StandaloneRestore { [pscustomobject]@{ExitCode=0;Output=@()} }
        Mock Invoke-StateCapture { [pscustomobject]@{Document=$script:RecoveryAfter} }
    }

    It 'recovers the one new session even when Apply failed before returning its contract' {
        $created = New-Item -Path (Join-Path $script:RecoveryRoot 'new-session') -ItemType Directory
        $script:ExpectedRecoveryPath = $created.FullName
        $result = Invoke-StandaloneFailureRecovery -BackupRoot $script:RecoveryRoot -KnownSessions $script:RecoveryKnown -BeforeState $script:RecoveryBefore
        $result.Attempted | Should -BeTrue
        $result.Succeeded | Should -BeTrue
        Should -Invoke Invoke-StandaloneRestore -Exactly 1 -ParameterFilter { $SessionPath -ceq $script:ExpectedRecoveryPath }
    }

    It 'uses the verified archive after the original session was deleted' {
        $archive = New-Item -Path (Join-Path $TestDrive 'retained-archive') -ItemType Directory
        $script:ExpectedRecoveryPath = $archive.FullName
        $result = Invoke-StandaloneFailureRecovery -RecoverySession $archive.FullName -BackupRoot $script:RecoveryRoot -KnownSessions $script:RecoveryKnown -BeforeState $script:RecoveryBefore
        $result.Succeeded | Should -BeTrue
        Should -Invoke Invoke-StandaloneRestore -Exactly 1 -ParameterFilter { $SessionPath -ceq $script:ExpectedRecoveryPath }
    }

    It 'does not guess a restore target among <Count> new sessions' -TestCases @(@{Count=0}, @{Count=2}) {
        param($Count)
        for ($i=0; $i -lt $Count; $i++) { $null = New-Item -Path (Join-Path $script:RecoveryRoot "new-$i") -ItemType Directory }
        $result = Invoke-StandaloneFailureRecovery -BackupRoot $script:RecoveryRoot -KnownSessions $script:RecoveryKnown -BeforeState $script:RecoveryBefore
        $result.Attempted | Should -BeFalse
        $result.Succeeded | Should -BeFalse
        $result.Error | Should -Match 'Cannot select one recovery session'
        Should -Invoke Invoke-StandaloneRestore -Exactly 0
    }

    It 'reports a failed restore and does not claim recovery' {
        Mock Invoke-StandaloneRestore { [pscustomobject]@{ExitCode=4;Output=@()} }
        $result = Invoke-StandaloneFailureRecovery -RecoverySession 'fixture-session' -BackupRoot $script:RecoveryRoot -KnownSessions $script:RecoveryKnown -BeforeState $script:RecoveryBefore
        $result.Attempted | Should -BeTrue
        $result.Succeeded | Should -BeFalse
        $result.RestoreExitCode | Should -Be 4
        Should -Invoke Invoke-StateCapture -Exactly 0
    }

    It 'rejects exit zero when the independent state still differs' {
        $script:RecoveryAfter = [pscustomobject]@{
            StateAfter = [pscustomobject]@{CombinedHash='changed';Components=[pscustomobject]@{Registry='changed'}}
            RegistrySnapshotBefore = @()
        }
        $result = Invoke-StandaloneFailureRecovery -RecoverySession 'fixture-session' -BackupRoot $script:RecoveryRoot -KnownSessions $script:RecoveryKnown -BeforeState $script:RecoveryBefore
        $result.Succeeded | Should -BeFalse
        $result.RestoreExitCode | Should -Be 0
        $result.Error | Should -Match 'independent pre-Apply state'
    }

    It 'runs actual workflow cleanup after <FailurePoint> and preserves the validation failure' -TestCases @(
        @{FailurePoint='failed Apply';SuccessfulApply=$false},
        @{FailurePoint='verification after session deletion';SuccessfulApply=$true}
    ) {
        param($FailurePoint, $SuccessfulApply)
        $null = $FailurePoint
        $script:WorkflowApplySucceeds = $SuccessfulApply
        function Invoke-FixtureChild {
            $null = $args
            $session = Join-Path $script:RecoveryRoot 'new-session'
            $null = New-Item -Path $session -ItemType Directory
            Set-Content -LiteralPath (Join-Path $session 'manifest.json') -Value '{"sealed":"fixture"}'
            Set-Content -LiteralPath (Join-Path $session 'prestate.json') -Value '{"saved":"original"}'
            $global:LASTEXITCODE = if ($script:WorkflowApplySucceeds) { 0 } else { 4 }
            'NOID_RESULT_JSON={"schemaVersion":2,"success":true,"modulesExecuted":7,"modulesFailed":0}'
        }
        Mock Invoke-StandaloneVerification {
            param($Name)
            if ($Name -eq 'standalone-after-session-delete') { throw 'Injected verifier failure after deletion' }
            [pscustomobject]@{Document=[pscustomobject]@{
                TotalSettings=119;ProductTargetInventory=119;PrivacyChecks=119;PrivacyMode='Strict'
                Failed=0;NotChecked=0;NotCheckedDeliberate=0
            }}
        }
        Mock Assert-SelectedPrivacyVerifierUx {}
        $windowsPowerShell = 'Invoke-FixtureChild'
        $entryPoint = 'fixture-entry'
        $configurationFullPath = 'fixture-config'
        $backupRoot = $script:RecoveryRoot
        $knownSessions = $script:RecoveryKnown
        $preState = [pscustomobject]@{Document=$script:RecoveryBefore}
        $EvidenceDirectory = Join-Path $backupRoot 'evidence'
        $null = New-Item -Path $EvidenceDirectory -ItemType Directory
        $null = $knownSessions.Add($EvidenceDirectory)
        $recoverySession = $null
        $restoreCompleted = $false
        $expectedTotal = 119
        $expectedProductInventory = 119
        $expectedPrivacyProductCount = 119
        # The extracted production block reads these caller-scope inputs.
        $null = $windowsPowerShell, $entryPoint, $configurationFullPath, $preState,
            $recoverySession, $restoreCompleted, $expectedTotal, $expectedProductInventory,
            $expectedPrivacyProductCount
        $hadExitCode = Test-Path variable:global:LASTEXITCODE
        $savedExitCode = Get-Variable LASTEXITCODE -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        try {
            $message = if ($SuccessfulApply) { '*Injected verifier failure after deletion*' } else { '*Full Strict Apply failed*' }
            { & $script:StandaloneWorkflow } | Should -Throw $message
        }
        finally {
            if ($hadExitCode) { $global:LASTEXITCODE = $savedExitCode }
            else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
        }
        $evidence = Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'failure-recovery.json') -Raw | ConvertFrom-Json
        $evidence.Attempted | Should -BeTrue
        $evidence.Succeeded | Should -BeTrue
        Should -Invoke Invoke-StandaloneRestore -Exactly 1
        if ($SuccessfulApply) {
            Test-Path -LiteralPath (Join-Path $backupRoot 'new-session') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $EvidenceDirectory 'ArchivedSessions/new-session/prestate.json') | Should -BeTrue
        }
    }
}
