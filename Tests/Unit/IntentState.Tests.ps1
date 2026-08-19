#Requires -Version 5.1

BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:RunningOnWindows = $env:OS -eq 'Windows_NT'
    $script:RunningElevated = if ($script:RunningOnWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    else { $false }
}

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    # IntentState is intentionally usable before the rollback helpers are loaded.
    # Provide the persistence seam that Framework supplies in production so Pester
    # can replace it without touching ProgramData.
    function Write-AtomicUtf8File {
        param([string]$Path, [string]$Content)
        $null = $Path, $Content
        throw 'Test persistence seam was not mocked.'
    }

    function Get-QuickActionSessionDocument {
        param([string]$SessionPath)
        throw "Test Quick Action session seam was not mocked: $SessionPath"
    }

    function Get-FrameworkVersion {
        return '2.2.5-test'
    }

    . (Join-Path $script:RepoRoot 'Core\IntentState.ps1')

    function New-TestIntentState {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'Pure test-fixture constructor; it does not mutate system state.'
        )]
        param(
            [string]$EngineFingerprint = ('1' * 64),
            [int]$SchemaVersion = 2
        )

        return [PSCustomObject]@{
            schemaVersion = $SchemaVersion
            frameworkVersion = '2.2.5'
            engineContractFingerprint = $EngineFingerprint
            updatedAt = [DateTime]::UtcNow.ToString('o')
            modules = [PSCustomObject]@{
                EdgeHardening = [PSCustomObject]@{
                    moduleName = 'EdgeHardening'
                    recordedAt = [DateTime]::UtcNow.ToString('o')
                    sourceKind = 'QuickActionLiveConfirmation'
                    sourceId = 'EdgeExtensions'
                    sourceEvidenceSha256 = ('2' * 64)
                    intent = [PSCustomObject]@{ allowExtensions = $false }
                }
            }
        }
    }
}

Describe 'Durable Apply intent schema contract' {
    It 'accepts a schema-valid decision recorded by a different engine fingerprint' {
        $state = New-TestIntentState -EngineFingerprint ('a' * 64)
        { Assert-NoIDIntentState -State $state } | Should -Not -Throw
    }

    It 'rejects unknown schemas instead of guessing compatibility' {
        $state = New-TestIntentState -SchemaVersion 99
        { Assert-NoIDIntentState -State $state } | Should -Throw '*Unsupported Apply-intent schema*'
    }

    It 'rejects unknown module identities' {
        $state = New-TestIntentState
        $state.modules | Add-Member -NotePropertyName ForeignModule -NotePropertyValue ([PSCustomObject]@{})
        { Assert-NoIDIntentState -State $state } | Should -Throw '*unknown modules*'
    }

    It 'rejects malformed source evidence instead of using it as a comparison label' {
        $state = New-TestIntentState
        $state.modules.EdgeHardening.sourceEvidenceSha256 = 'not-a-hash'
        { Assert-NoIDIntentState -State $state } | Should -Throw '*evidence hash is invalid*'
    }

    It 'rejects unknown fields instead of silently widening the intent schema' {
        $state = New-TestIntentState
        $state.modules.EdgeHardening.intent | Add-Member -NotePropertyName guessedDefault -NotePropertyValue $true
        { Assert-NoIDIntentState -State $state } | Should -Throw '*property contract mismatch*unknown: guessedDefault*'
    }

    It 'requires canonical UTC round-trip timestamps' {
        $state = New-TestIntentState
        $state.updatedAt = '2026-08-15 12:00:00'
        { Assert-NoIDIntentState -State $state } | Should -Throw '*canonical UTC round-trip timestamp*'
    }

    It 'represents an explicit DNS KEEP decision without inventing a DoH mode' {
        $state = New-TestIntentState
        $stamp = [DateTime]::UtcNow.ToString('o')
        $state.modules | Add-Member -NotePropertyName DNS -NotePropertyValue ([PSCustomObject]@{
                moduleName='DNS'; recordedAt=$stamp; sourceKind='ApplyDecision'; sourceId='DNS-KEEP'
                sourceEvidenceSha256=('4' * 64)
                intent=[PSCustomObject]@{ provider='KEEP'; dohMode='KEEP' }
            })
        { Assert-NoIDIntentState -State $state } | Should -Not -Throw

        $state.modules.DNS.intent.dohMode = 'REQUIRE'
        { Assert-NoIDIntentState -State $state } | Should -Throw '*DNS decision is invalid*'
    }

    It 'publishes a successful DNS KEEP result as an Apply decision without requiring a session' {
        $script:publishedIntentState = $null
        Mock Read-NoIDIntentState { $script:publishedIntentState }
        Mock Get-NoIDEngineContractFingerprint { '6' * 64 }
        Mock Get-FrameworkVersion { '2.2.5' }
        Mock Publish-NoIDIntentState {
            param($State)
            $script:publishedIntentState = $State
            'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json'
        }

        $result = [PSCustomObject]@{
            ModuleName = 'DNS'
            Success = $true
            Status = 'Success'
            Provider = 'KEEP'
            DoHMode = 'KEEP'
        }
        {
            Write-NoIDApplyIntentState -ModuleResults @($result)
        } | Should -Not -Throw

        [string]$script:publishedIntentState.modules.DNS.sourceKind |
            Should -BeExactly 'ApplyDecision'
        [string]$script:publishedIntentState.modules.DNS.sourceId |
            Should -BeExactly 'DNS-KEEP'
        [string]$script:publishedIntentState.modules.DNS.intent.provider |
            Should -BeExactly 'KEEP'
        [string]$script:publishedIntentState.modules.DNS.intent.dohMode |
            Should -BeExactly 'KEEP'
        Should -Invoke Publish-NoIDIntentState -Times 1 -Exactly
    }

    It 'updates ASR intent for NewSoftware without inventing an undeclared SecurityBaseline override' {
        $stamp = [DateTime]::UtcNow.ToString('o')
        $guid = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        $state = [PSCustomObject]@{
            schemaVersion = 2
            frameworkVersion = '2.2.5'
            engineContractFingerprint = ('1' * 64)
            updatedAt = $stamp
            modules = [PSCustomObject]@{
                SecurityBaseline = [PSCustomObject]@{
                    moduleName='SecurityBaseline'; recordedAt=$stamp
                    sourceKind='ApplySession'; sourceId='Session_20260815_120000_000_1234abcd'
                    sourceEvidenceSha256=('2' * 64)
                    intent=[PSCustomObject]@{
                        standardUserElevationMode='Strict'; bitLockerUSBEnforcement=$false
                        submitAllSamples=$false; smartScreenWarnMode=$false
                        asrActionOverrides=@()
                    }
                }
                ASR = [PSCustomObject]@{
                    moduleName='ASR'; recordedAt=$stamp
                    sourceKind='ApplySession'; sourceId='Session_20260815_120000_000_1234abcd'
                    sourceEvidenceSha256=('2' * 64)
                    intent=[PSCustomObject]@{
                        requestedActions=@([PSCustomObject]@{ Guid=$guid; Action=1 })
                    }
                }
            }
        }
        Mock Read-NoIDIntentState { $state }
        Mock Get-NoIDEngineContractFingerprint { '3' * 64 }
        Mock Get-NoIDIntentStatePath { 'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json' }
        Mock Initialize-NoIDIntentStateDirectory { '/tmp/noid-intent-test/EngineState' }
        Mock Set-NoIDIntentPathSecurity { }
        Mock Assert-NoIDIntentStateAcl { $true }
        Mock Write-AtomicUtf8File { $true }

        Update-NoIDQuickActionIntentState `
            -ActionId NewSoftware `
            -DesiredState Allow `
            -SourceKind QuickActionLiveConfirmation `
            -SourceEvidenceSha256 ('4' * 64) | Should -BeTrue

        [int]$state.modules.ASR.intent.requestedActions[0].Action | Should -Be 2
        [string]$state.modules.ASR.sourceId | Should -BeExactly 'NewSoftware'

        # NewSoftware's rule is NOT in the SecurityBaseline inventory: the sealed
        # Computer-RegistryPolicies.json declares fifteen ASR rules and this GUID is
        # none of them (only ManagementTools' d1e49aac-... is). An override for an
        # undeclared GUID is not merely useless - Verify-Complete-Hardening.ps1
        # requires exactly one declared target per override and otherwise throws
        # 'Durable SecurityBaseline ASR override is invalid', so a single Quick
        # Action permanently broke verification of every declared baseline check.
        # Assert against the shipped inventory, not against a hardcoded belief.
        $baselinePolicies = Get-Content -LiteralPath (Join-Path $script:RepoRoot `
                'Modules/SecurityBaseline/ParsedSettings/Computer-RegistryPolicies.json') `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        $declaredAsrGuids = @($baselinePolicies | Where-Object {
                ([string]$_.KeyName -replace '^\[', '' -replace '\]$', '') -ceq
                    'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            } | ForEach-Object { ([string]$_.ValueName).ToLowerInvariant() })
        $declaredAsrGuids | Should -Not -Contain $guid `
            -Because 'the NewSoftware rule is not part of the SecurityBaseline inventory'

        @($state.modules.SecurityBaseline.intent.asrActionOverrides).Count | Should -Be 0
        Should -Invoke Write-AtomicUtf8File -Times 1 -Exactly
    }

    It 'still records the SecurityBaseline override for the ManagementTools rule it does declare' {
        $stamp = [DateTime]::UtcNow.ToString('o')
        $guid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        $state = [PSCustomObject]@{
            schemaVersion = 2
            frameworkVersion = '2.2.5'
            engineContractFingerprint = ('1' * 64)
            updatedAt = $stamp
            modules = [PSCustomObject]@{
                SecurityBaseline = [PSCustomObject]@{
                    moduleName='SecurityBaseline'; recordedAt=$stamp
                    sourceKind='ApplySession'; sourceId='Session_20260815_120000_000_1234abcd'
                    sourceEvidenceSha256=('2' * 64)
                    intent=[PSCustomObject]@{
                        standardUserElevationMode='Strict'; bitLockerUSBEnforcement=$false
                        submitAllSamples=$false; smartScreenWarnMode=$false
                        asrActionOverrides=@()
                    }
                }
                ASR = [PSCustomObject]@{
                    moduleName='ASR'; recordedAt=$stamp
                    sourceKind='ApplySession'; sourceId='Session_20260815_120000_000_1234abcd'
                    sourceEvidenceSha256=('2' * 64)
                    intent=[PSCustomObject]@{
                        requestedActions=@([PSCustomObject]@{ Guid=$guid; Action=1 })
                    }
                }
            }
        }
        Mock Read-NoIDIntentState { $state }
        Mock Get-NoIDEngineContractFingerprint { '3' * 64 }
        Mock Get-NoIDIntentStatePath { 'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json' }
        Mock Initialize-NoIDIntentStateDirectory { '/tmp/noid-intent-test/EngineState' }
        Mock Set-NoIDIntentPathSecurity { }
        Mock Assert-NoIDIntentStateAcl { $true }
        Mock Write-AtomicUtf8File { $true }

        Update-NoIDQuickActionIntentState `
            -ActionId ManagementTools `
            -DesiredState Allow `
            -SourceKind QuickActionLiveConfirmation `
            -SourceEvidenceSha256 ('4' * 64) | Should -BeTrue

        [int]$state.modules.ASR.intent.requestedActions[0].Action | Should -Be 2
        @($state.modules.SecurityBaseline.intent.asrActionOverrides).Count | Should -Be 1
        [string]$state.modules.SecurityBaseline.intent.asrActionOverrides[0].Guid | Should -BeExactly $guid
        [int]$state.modules.SecurityBaseline.intent.asrActionOverrides[0].Action | Should -Be 2
        [string]$state.modules.SecurityBaseline.sourceId | Should -BeExactly 'ManagementTools'
        [string]$state.modules.ASR.sourceId | Should -BeExactly 'ManagementTools'
        Should -Invoke Write-AtomicUtf8File -Times 1 -Exactly
    }

    It 'the real read path fails closed on a missing, corrupt, or schema-invalid register' {
        # Every other test that touches Read-NoIDIntentState replaces it with a
        # mock, so its three fail-closed steps - missing-file throw, ACL
        # assertion, schema assertion on the parsed document - had never once
        # executed. Only Get-NoIDIntentStatePath is mocked here; the function
        # under test runs for real against a TestDrive file.
        $statePath = Join-Path $TestDrive 'last-apply-intent.json'
        Mock Get-NoIDIntentStatePath { $statePath }
        # The ACL gate is exercised as "was it consulted", not re-proven here -
        # it has its own dedicated tests; a real ProgramData ACL cannot exist on
        # a TestDrive file.
        Mock Assert-NoIDIntentStateAcl { $true }

        # (a) Missing file without -AllowMissing is a hard failure...
        { Read-NoIDIntentState } | Should -Throw '*Apply-intent record is missing*'
        # ...and with -AllowMissing an explicit $null, never a fabricated state.
        Read-NoIDIntentState -AllowMissing | Should -BeNullOrEmpty

        # (b) A file that is not JSON must throw, not return garbage.
        Set-Content -LiteralPath $statePath -Value '{' -Encoding UTF8
        { Read-NoIDIntentState } | Should -Throw

        # (c) Valid JSON with an inconsistent module record must fail the schema
        # assertion - the register is trusted input to the verifier, so a
        # tampered or truncated document can never be returned as intent.
        $broken = New-TestIntentState
        $broken.modules.EdgeHardening.moduleName = 'Privacy'
        $broken | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statePath -Encoding UTF8
        { Read-NoIDIntentState } | Should -Throw

        # (d) A schema-valid document round-trips, with the ACL gate consulted.
        New-TestIntentState | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statePath -Encoding UTF8
        $state = Read-NoIDIntentState
        [string]$state.modules.EdgeHardening.moduleName | Should -BeExactly 'EdgeHardening'
        [bool]$state.modules.EdgeHardening.intent.allowExtensions | Should -BeFalse
        # Once each for (b), (c) and (d); (a) never reaches the ACL gate.
        Should -Invoke Assert-NoIDIntentStateAcl -Times 3 -Exactly
    }

    It 'does not rewrite provenance when a Quick Action has no recorded module to update' {
        $state = New-TestIntentState
        Mock Read-NoIDIntentState { $state }
        Mock Get-NoIDEngineContractFingerprint { '3' * 64 }
        Mock Publish-NoIDIntentState { throw 'must not publish a no-op' }

        Update-NoIDQuickActionIntentState `
            -ActionId RDP `
            -DesiredState Disable `
            -SourceKind QuickActionLiveConfirmation `
            -SourceEvidenceSha256 ('4' * 64) | Should -BeTrue

        [string]$state.engineContractFingerprint | Should -BeExactly ('1' * 64)
        Should -Invoke Publish-NoIDIntentState -Times 0 -Exactly
    }

    It 'removes the durable record when Restore invalidates its final module' {
        $state = New-TestIntentState
        Mock Read-NoIDIntentState { $state }
        Mock Get-NoIDIntentStatePath {
            'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json'
        }
        Mock Assert-NoIDIntentStateAcl { $true }
        Mock Remove-Item { }
        Mock Test-Path { $false }
        Mock Publish-NoIDIntentState { throw 'must not publish an empty intent record' }

        Remove-NoIDApplyIntentModules -ModuleNames EdgeHardening | Should -BeTrue

        Should -Invoke Assert-NoIDIntentStateAcl -Times 1 -Exactly
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -ceq 'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json' -and
            $Force
        }
        Should -Invoke Publish-NoIDIntentState -Times 0 -Exactly
    }

    It 'does not rewrite timestamps or promote Apply provenance for a recorded no-op' {
        $state = New-TestIntentState
        $originalUpdatedAt = [string]$state.updatedAt
        $originalRecordedAt = [string]$state.modules.EdgeHardening.recordedAt
        Mock Read-NoIDIntentState { $state }
        Mock Publish-NoIDIntentState { throw 'must not publish an unchanged label' }

        Update-NoIDQuickActionIntentState `
            -ActionId EdgeExtensions `
            -DesiredState Block `
            -SourceKind QuickActionLiveConfirmation `
            -SourceEvidenceSha256 ('4' * 64) | Should -BeTrue

        [string]$state.engineContractFingerprint | Should -BeExactly ('1' * 64)
        [string]$state.updatedAt | Should -BeExactly $originalUpdatedAt
        [string]$state.modules.EdgeHardening.recordedAt | Should -BeExactly $originalRecordedAt
        [string]$state.modules.EdgeHardening.sourceId | Should -BeExactly 'EdgeExtensions'
        Should -Invoke Publish-NoIDIntentState -Times 0 -Exactly
    }

    It 'replaces DNS KEEP with the exact sealed provider for EncryptedDNS Apply' {
        $state = New-TestIntentState
        $stamp = [DateTime]::UtcNow.ToString('o')
        $state.modules | Add-Member -NotePropertyName DNS -NotePropertyValue ([PSCustomObject]@{
                moduleName='DNS'; recordedAt=$stamp; sourceKind='ApplyDecision'; sourceId='DNS-KEEP'
                sourceEvidenceSha256=('4' * 64)
                intent=[PSCustomObject]@{ provider='KEEP'; dohMode='KEEP' }
            })
        $sessionId = 'Session_20260815_120000_000_1234abcd_QuickAction_EncryptedDNS'
        $sessionPath = Join-Path $TestDrive $sessionId
        Mock Read-NoIDIntentState { $state }
        Mock Get-QuickActionSessionDocument {
            [PSCustomObject]@{
                SessionPath = $sessionPath
                Manifest = [PSCustomObject]@{ sessionId = $sessionId }
                PreState = [PSCustomObject]@{ targets = [PSCustomObject]@{
                        resolverEvidence = [PSCustomObject]@{ providerId='Quad9' }
                    } }
                PostState = [PSCustomObject]@{ targets = [PSCustomObject]@{
                        resolverEvidence = [PSCustomObject]@{ providerId='Quad9' }
                    } }
            }
        }
        Mock Get-FileHash { [PSCustomObject]@{ Hash = ('5' * 64) } }
        Mock Publish-NoIDIntentState { 'C:\ProgramData\NoID Privacy\EngineState\last-apply-intent.json' }

        Update-NoIDQuickActionIntentState `
            -ActionId EncryptedDNS `
            -DesiredState Require `
            -SourceKind QuickActionApply `
            -SourceSessionPath $sessionPath |
            Should -BeTrue

        [string]$state.modules.DNS.intent.provider | Should -BeExactly 'Quad9'
        [string]$state.modules.DNS.intent.dohMode | Should -BeExactly 'REQUIRE'
        [string]$state.modules.DNS.sourceKind | Should -BeExactly 'QuickActionApply'
        [string]$state.modules.DNS.sourceId | Should -BeExactly $sessionId
        [string]$state.engineContractFingerprint | Should -BeExactly ('1' * 64)
        Should -Invoke Publish-NoIDIntentState -Times 1 -Exactly
    }

    It 'stores AntiAI user targets with one canonical HKCU role separator' {
        $moduleResult = [PSCustomObject]@{
            ModuleName = 'AntiAI'
            ApplicableTargetPlan = @(
                [PSCustomObject]@{
                    Path='HKU:\S-1-5-21-1-2-3-1001\Software\Policies\NoID'
                    Name='Example'
                }
            )
            NotApplicableTargetPlan = @(
                1..42 | ForEach-Object {
                    [PSCustomObject]@{ Path="HKLM:\SOFTWARE\Policies\NoID\$_"; Name='Value' }
                }
            )
        }

        $intent = New-NoIDModuleIntent -ModuleResult $moduleResult

        [string]$intent.applicableTargets[0].path |
            Should -BeExactly 'HKCU:\Software\Policies\NoID'
        [string]$intent.applicableTargets[0].path |
            Should -Not -Match '^HKCU:\\\\'
    }

    It 'maps a SecurityBaseline ASR override from the module result into the intent record' {
        $moduleResult = [PSCustomObject]@{
            ModuleName = 'SecurityBaseline'
            Details = @{
                StandardUserElevationMode = 'Strict'
                BitLockerUSBEnforcement = $false
                SubmitAllSamples = $false
                SmartScreenWarnMode = $true
                AsrActionOverrides = @([PSCustomObject]@{
                    Guid = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'
                    Action = 1
                })
            }
        }

        $intent = New-NoIDModuleIntent -ModuleResult $moduleResult

        @($intent.asrActionOverrides).Count | Should -Be 1
        [string]$intent.asrActionOverrides[0].Guid |
            Should -BeExactly 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        [int]$intent.asrActionOverrides[0].Action | Should -Be 1
    }

    It 'keeps the SecurityBaseline override list empty when the result carries none' {
        $moduleResult = [PSCustomObject]@{
            ModuleName = 'SecurityBaseline'
            Details = @{
                StandardUserElevationMode = 'Strict'
                BitLockerUSBEnforcement = $false
                SubmitAllSamples = $false
                SmartScreenWarnMode = $false
                AsrActionOverrides = @()
            }
        }

        $intent = New-NoIDModuleIntent -ModuleResult $moduleResult

        @($intent.asrActionOverrides).Count | Should -Be 0
    }

    It 'rejects a SecurityBaseline override action outside the documented Block/Audit set' {
        $moduleResult = [PSCustomObject]@{
            ModuleName = 'SecurityBaseline'
            Details = @{
                StandardUserElevationMode = 'Strict'
                BitLockerUSBEnforcement = $false
                SubmitAllSamples = $false
                SmartScreenWarnMode = $false
                AsrActionOverrides = @([PSCustomObject]@{
                    Guid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
                    Action = 6
                })
            }
        }

        { New-NoIDModuleIntent -ModuleResult $moduleResult } |
            Should -Throw '*unsupported ASR override action*'
    }
}

Describe 'Durable Apply intent Windows ACL contract' -Skip:(-not $script:RunningOnWindows -or -not $script:RunningElevated) {
    It 'accepts a pure Users read ACE and rejects raw GENERIC_ALL' {
        $productDirectory = Join-Path $TestDrive 'NoID Privacy'
        $stateDirectory = Join-Path $productDirectory 'EngineState'
        $statePath = Join-Path $stateDirectory 'last-apply-intent.json'
        $null = New-Item -ItemType Directory -Path $stateDirectory -Force
        Set-Content -LiteralPath $statePath -Value '{}' -Encoding UTF8
        Set-NoIDIntentPathSecurity -Path $productDirectory -IsDirectory $true
        Set-NoIDIntentPathSecurity -Path $stateDirectory -IsDirectory $true
        Set-NoIDIntentPathSecurity -Path $statePath -IsDirectory $false

        $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl = Get-Acl -LiteralPath $statePath
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $users,
                [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [Security.AccessControl.AccessControlType]::Allow
            ))
        Set-Acl -LiteralPath $statePath -AclObject $acl
        { Assert-NoIDIntentStateAcl -StatePath $statePath } | Should -Not -Throw

        # FileSystemAccessRule rejects raw generic bits as undefined enum
        # members. Add a real Win32 GENERIC_ALL ACE through SDDL instead so
        # the production reader must handle the representation Windows stores.
        $acl = Get-Acl -LiteralPath $statePath
        $sddl = $acl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All)
        $genericAllAce = '(A;;GA;;;S-1-5-32-545)'
        $saclIndex = $sddl.IndexOf('S:', [StringComparison]::Ordinal)
        $sddl = if ($saclIndex -ge 0) {
            $sddl.Insert($saclIndex, $genericAllAce)
        }
        else { $sddl + $genericAllAce }
        $acl.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $statePath -AclObject $acl
        { Assert-NoIDIntentStateAcl -StatePath $statePath } |
            Should -Throw '*grants write access to an untrusted identity*'
    }

    It 'rejects an otherwise protected file owned by an untrusted identity' {
        $productDirectory = Join-Path $TestDrive 'NoID Privacy Owner'
        $stateDirectory = Join-Path $productDirectory 'EngineState'
        $statePath = Join-Path $stateDirectory 'last-apply-intent.json'
        $null = New-Item -ItemType Directory -Path $stateDirectory -Force
        Set-Content -LiteralPath $statePath -Value '{}' -Encoding UTF8
        Set-NoIDIntentPathSecurity -Path $productDirectory -IsDirectory $true
        Set-NoIDIntentPathSecurity -Path $stateDirectory -IsDirectory $true
        Set-NoIDIntentPathSecurity -Path $statePath -IsDirectory $false

        $acl = Get-Acl -LiteralPath $statePath
        $untrustedOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($untrustedOwner.Value -in @('S-1-5-18', 'S-1-5-32-544')) {
            # Elevated local VM runs execute as SYSTEM, which is deliberately a
            # trusted owner. Use BUILTIN\Users so this remains a real negative
            # ACL test instead of asserting that SYSTEM itself is untrusted.
            $untrustedOwner = [Security.Principal.SecurityIdentifier]::new(
                'S-1-5-32-545')
        }
        $acl.SetOwner($untrustedOwner)
        Set-Acl -LiteralPath $statePath -AclObject $acl
        { Assert-NoIDIntentStateAcl -StatePath $statePath } |
            Should -Throw '*untrusted owner*'
    }
}
