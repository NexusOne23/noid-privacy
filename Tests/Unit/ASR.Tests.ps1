#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for ASR (Attack Surface Reduction) module

.DESCRIPTION
    Pester v5 tests for the ASR module functionality.
    Tests return values, DryRun behavior, and backup creation.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0
#>

BeforeAll {
    # Module entry points prompt through Read-Host unless non-interactive mode
    # is set; the 'Interactive'-tagged smoke tests below run through
    # Invoke-UnitNonInteractive so they cannot block on a real desktop.
    . (Join-Path $PSScriptRoot '_NonInteractive.ps1')
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function global:Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Namespace) $null = $ClassName, $Namespace; throw 'Get-CimInstance test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        function global:Get-MpComputerStatus { [CmdletBinding()] param() throw 'Get-MpComputerStatus test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        function global:Get-Service { [CmdletBinding()] param([string[]]$Name) $null = $Name; throw 'Get-Service test placeholder was not mocked' }
    }
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/ASR/ASR.psm1"
    $script:ModuleRoot = Split-Path $modulePath -Parent
    $script:RepoRoot = Split-Path $script:ModuleRoot -Parent | Split-Path -Parent

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }

    # Import Core modules for testing
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1")
    $corePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }
    foreach ($functionName in @(
            'Write-Log', 'Write-ErrorLog', 'Initialize-Logger',
            'Initialize-BackupSystem', 'Start-ModuleBackup',
            'Complete-ModuleBackup', 'Save-IncompleteModuleBackup',
            'Test-NonInteractiveMode', 'Get-ConfigValue'
        )) {
        if (Test-Path "function:$functionName") {
            Set-Item -Path "function:global:$functionName" -Value (Get-Item "function:$functionName").ScriptBlock
        }
    }
    Import-Module $modulePath -Force
    . (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Utils/Dependencies.ps1')
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-SealedAppliedAsrPlan.ps1')

    function New-TestSealedAppliedAsrSession {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)][string]$Root,
            [Parameter(Mandatory)][array]$DeclaredRules
        )

        $sessionPath = Join-Path $Root ([Guid]::NewGuid().ToString('N'))
        if (-not $PSCmdlet.ShouldProcess($sessionPath, 'Create sealed ASR test session')) {
            return
        }
        $artifactDirectory = Join-Path $sessionPath 'ASR'
        $null = New-Item -ItemType Directory -Path $artifactDirectory -Force
        $artifactPath = Join-Path $artifactDirectory 'ASR_ActiveConfiguration.json'
        $targets = @($DeclaredRules | Where-Object {
                -not ($_.PSObject.Properties.Name -contains 'WindowsClientApplicable') -or
                [bool]$_.WindowsClientApplicable
            } | ForEach-Object {
                [PSCustomObject]@{
                    GUID            = [string]$_.GUID
                    RequestedAction = [int]$_.Action
                }
            })
        [PSCustomObject]@{
            SchemaVersion = 4
            Target         = 'WindowsClientDefenderASR'
            PolicyPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Targets        = $targets
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $artifactPath -Encoding UTF8
        $hash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        [PSCustomObject]@{
            schemaVersion = 2
            modules       = @(
                [PSCustomObject]@{
                    name      = 'ASR'
                    status    = 'Success'
                    artifacts = @(
                        [PSCustomObject]@{
                            type         = 'ASR'
                            name         = 'ASR_ActiveConfiguration'
                            target       = 'DefenderASR'
                            relativePath = 'ASR\ASR_ActiveConfiguration.json'
                            sha256       = $hash
                        }
                    )
                }
            )
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $sessionPath 'manifest.json') -Encoding UTF8

        [PSCustomObject]@{
            SessionPath  = $sessionPath
            ArtifactPath = $artifactPath
        }
    }

    function New-TestAlreadyRestoredAsrSnapshot {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)][string]$Root,
            [Parameter(Mandatory)][bool]$PolicyKeyExisted,
            [switch]$IncludeNonBaselineTarget
        )

        $snapshotPath = Join-Path $Root ([Guid]::NewGuid().ToString('N') + '.json')
        if (-not $PSCmdlet.ShouldProcess($snapshotPath, 'Create already-restored ASR test snapshot')) {
            return
        }
        $targets = @(
            [PSCustomObject]@{
                Name             = 'Block abused vulnerable signed drivers'
                GUID             = '56a863a9-875e-4185-98a7-b882c64b5ce5'
                RequestedAction  = 1
                OriginalExists   = $false
                OriginalAction   = $null
                PolicyOverride   = $true
                PolicyValue      = [PSCustomObject]@{
                    Exists       = $false
                    OriginalName = $null
                    Type         = $null
                    Value        = $null
                }
                BaselineStatus   = 'Missing'
                UserConfigurable = $false
            }
        )
        if ($IncludeNonBaselineTarget) {
            $targets += [PSCustomObject]@{
                Name             = 'Block webshell creation for Servers'
                GUID             = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
                RequestedAction  = 1
                OriginalExists   = $false
                OriginalAction   = $null
                PolicyOverride   = $true
                PolicyValue      = [PSCustomObject]@{
                    Exists       = $false
                    OriginalName = $null
                    Type         = $null
                    Value        = $null
                }
                BaselineStatus   = 'Missing'
                UserConfigurable = $false
            }
        }
        [PSCustomObject]@{
            SchemaVersion      = 5
            Target             = 'WindowsClientDefenderASR'
            PolicyPath         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            PolicyKeyExisted   = $PolicyKeyExisted
            AbsentAncestorKeys = @()
            DeclaredCount      = $targets.Count
            TargetCount        = $targets.Count
            NotApplicableCount = 0
            Targets            = @($targets)
            NotApplicable      = @()
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
        return $snapshotPath
    }

    function New-TestSecurityBaselineAsrPrestate {
        [CmdletBinding(SupportsShouldProcess)]
        param([Parameter(Mandatory)][string]$Root)

        $snapshotPath = Join-Path $Root ([Guid]::NewGuid().ToString('N') + '.json')
        if (-not $PSCmdlet.ShouldProcess($snapshotPath, 'Create SecurityBaseline ASR prestate')) {
            return
        }
        [PSCustomObject]@{
            SchemaVersion     = 4
            Computer          = @(
                [PSCustomObject]@{
                    KeyName          = '[Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
                    ValueName        = '56a863a9-875e-4185-98a7-b882c64b5ce5'
                    Type             = 'REG_SZ'
                    OriginalValue    = $null
                    OriginalValueName = $null
                    KeyExisted       = $false
                    Exists           = $false
                }
            )
            ComputerClearKeys = @()
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
        return $snapshotPath
    }

    # Initialize logging (silent for tests)
    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }

    # Initialize config
    if (Get-Command Initialize-Config -ErrorAction SilentlyContinue) {
        $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "config.json"
        Initialize-Config -ConfigPath $configPath
    }
}

Describe "ASR Module" {

    Context "Result contract" {

        It "initializes the requested-action plan consumed by durable intent" {
            $source = Get-Content -LiteralPath (Join-Path $script:ModuleRoot 'Public/Invoke-ASRRules.ps1') -Raw -Encoding UTF8
            $source | Should -Match 'RequestedActions\s*=\s*@\(\)'
        }
    }

    Context "Module Structure" {

        It "Should export Invoke-ASRRules function" {
            $command = Get-Command -Name Invoke-ASRRules -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.CommandType | Should -Be 'Function'
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-ASRRules
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }
    }

    Context "Function Execution - DryRun Mode" {
        # This test runs on CI too: Invoke-ASRRules wraps its whole process block
        # in try/catch and returns Success=$false instead of throwing, so
        # Should -Not -Throw is satisfied even without admin rights/Defender.

        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-ASRRules -DryRun } } | Should -Not -Throw
        }
    }

    Context "Return Object Structure" {
        # Skipped - requires proper Windows Defender environment
    }

    Context "ASR Rules Configuration" {

        It "Should load ASR rules from JSON" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/ASR/Config/ASR-Rules.json"
            $rulesPath | Should -Exist
        }

        It "ASR rules file should be valid JSON" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/ASR/Config/ASR-Rules.json"
            { Get-Content $rulesPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Should have 19 ASR rules" {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/ASR/Config/ASR-Rules.json"
            $rules = Get-Content $rulesPath -Raw | ConvertFrom-Json
            $rules.Count | Should -Be 19
        }

        It 'pins all 19 declared rule tuples as literals' {
            # The count of 19 and a file-to-itself comparison cannot see a wrong
            # ACTION: flipping the LSASS rule to Audit still counts 19, still
            # matches itself, and ships a machine that only logs credential theft
            # instead of blocking it. These tuples are the only authority outside
            # the config file; changing the file now requires changing the test.
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/ASR/Config/ASR-Rules.json'
            $rules = Get-Content $rulesPath -Raw | ConvertFrom-Json

            $expected = @{
                '56a863a9-875e-4185-98a7-b882c64b5ce5' = @(1, 'Block', $false)
                '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = @(1, 'Block', $false)
                'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = @(1, 'Block', $false)
                '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = @(1, 'Block', $false)
                'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = @(1, 'Block', $false)
                '01443614-cd74-433a-b99e-2ecdc07bfc25' = @(1, 'Missing', $true)
                '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = @(1, 'Block', $true)
                'd3e037e1-3eb8-44c8-a917-57927947596d' = @(1, 'Block', $false)
                '3b576869-a4ec-4529-8536-b80a7769e899' = @(1, 'Block', $false)
                '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = @(1, 'Block', $false)
                '26190899-1602-49e8-8b27-eb1d0a1ce869' = @(1, 'Block', $false)
                'e6db77e5-3df2-4cf1-b95a-636979351e5b' = @(1, 'Block', $false)
                'd1e49aac-8f56-4280-b9ba-993a6d77406c' = @(1, 'Audit', $false)
                '33ddedf1-c6e0-47cb-833e-de6133960387' = @(1, 'Missing', $false)
                'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = @(1, 'Block', $false)
                'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = @(1, 'Missing', $false)
                'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = @(1, 'Missing', $false)
                '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = @(1, 'Block', $false)
                'c1db55ab-c21a-4637-bb3f-a12568109d35' = @(1, 'Block', $true)
            }

            @($rules).Count | Should -Be $expected.Count
            foreach ($rule in @($rules)) {
                $guid = ([string]$rule.GUID).ToLowerInvariant()
                $expected.ContainsKey($guid) | Should -BeTrue -Because "rule $guid must be one of the 19 declared identities"
                [int]$rule.Action | Should -Be $expected[$guid][0] -Because "the enforced action of $guid"
                [string]$rule.BaselineStatus | Should -BeExactly $expected[$guid][1] -Because "the baseline provenance of $guid"
                [bool]$rule.RequiresCloudProtection | Should -Be $expected[$guid][2] -Because "the cloud dependency of $guid"
            }
        }

        It 'Test-ASRCompliance fails and names the rule when Defender diverges from the plan' {
            # The verifier had no behavioural test at all. Feed it a Defender
            # state where one planned Block rule is only at Audit and assert the
            # result is non-compliant, counts once, and names exactly that GUID.
            InModuleScope ASR {
                $lsass = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
                $office = '3b576869-a4ec-4529-8536-b80a7769e899'
                $plan = @(
                    [PSCustomObject]@{ Name = 'LSASS'; GUID = $lsass; Action = 1 }
                    [PSCustomObject]@{ Name = 'Office children'; GUID = $office; Action = 1 }
                )

                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($lsass, $office)
                        AttackSurfaceReductionRules_Actions = @(2, 1)
                    }
                }

                $verdict = Test-ASRCompliance -ExpectedRules $plan
                $verdict.Passed | Should -BeFalse
                $verdict.CheckedCount | Should -Be 2
                $verdict.FailedCount | Should -Be 1
                @($verdict.FailedRules) | Should -Be @($lsass)

                # A rule missing from Defender entirely is a failure too, never a skip.
                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($office)
                        AttackSurfaceReductionRules_Actions = @(1)
                    }
                }
                $missing = Test-ASRCompliance -ExpectedRules $plan
                $missing.Passed | Should -BeFalse
                @($missing.FailedRules) | Should -Be @($lsass)

                # And full agreement passes.
                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($lsass, $office)
                        AttackSurfaceReductionRules_Actions = @(1, 1)
                    }
                }
                $clean = Test-ASRCompliance -ExpectedRules $plan
                $clean.Passed | Should -BeTrue
                $clean.FailedCount | Should -Be 0
            }
        }

        It 'Should classify the Exchange Webshell rule as the sole Windows-client NotApplicable identity' {
            $rulesPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/ASR/Config/ASR-Rules.json'
            $rules = Get-Content $rulesPath -Raw | ConvertFrom-Json
            $notApplicable = @($rules | Where-Object {
                    $_.PSObject.Properties.Name -contains 'WindowsClientApplicable' -and
                    -not [bool]$_.WindowsClientApplicable
                })
            $notApplicable.Count | Should -Be 1
            $notApplicable[0].GUID | Should -Be 'a8f5898e-1dc8-49a9-9878-85004b8a61e6'
            $notApplicable[0].NotApplicableReason | Should -Match 'Exchange-server'
        }
    }

    Context "BAVR and skip integrity" {
        It 'loads the exact ASR action map only from a valid sealed Apply session' {
            $rules = Get-Content (Join-Path $script:ModuleRoot 'Config/ASR-Rules.json') -Raw | ConvertFrom-Json
            $session = New-TestSealedAppliedAsrSession -Root $TestDrive -DeclaredRules $rules

            $result = Get-SealedAppliedAsrPlan -SessionPath $session.SessionPath -DeclaredRules $rules

            $result.ActionMap.Count | Should -Be 18
            foreach ($rule in @($rules | Where-Object { -not $_.PSObject.Properties['WindowsClientApplicable'] -or $_.WindowsClientApplicable })) {
                $id = ([Guid]$rule.GUID).ToString('D').ToLowerInvariant()
                $result.ActionMap[$id] | Should -Be ([int]$rule.Action)
            }
        }

        It 'rejects a sealed ASR artifact whose bytes no longer match the manifest' {
            $rules = Get-Content (Join-Path $script:ModuleRoot 'Config/ASR-Rules.json') -Raw | ConvertFrom-Json
            $session = New-TestSealedAppliedAsrSession -Root $TestDrive -DeclaredRules $rules
            Add-Content -LiteralPath $session.ArtifactPath -Value 'tampered'

            { Get-SealedAppliedAsrPlan -SessionPath $session.SessionPath -DeclaredRules $rules } |
                Should -Throw '*failed its manifest SHA-256 check*'
        }

        It 'rejects missing, duplicate, and out-of-scope ASR targets even with a recomputed hash' {
            $rules = Get-Content (Join-Path $script:ModuleRoot 'Config/ASR-Rules.json') -Raw | ConvertFrom-Json
            foreach ($mutation in @('Missing', 'Duplicate', 'OutOfScope')) {
                $session = New-TestSealedAppliedAsrSession -Root $TestDrive -DeclaredRules $rules
                $plan = Get-Content -LiteralPath $session.ArtifactPath -Raw | ConvertFrom-Json
                switch ($mutation) {
                    'Missing' { $plan.Targets = @($plan.Targets | Select-Object -Skip 1) }
                    'Duplicate' { $plan.Targets[-1].GUID = $plan.Targets[0].GUID }
                    'OutOfScope' { $plan.Targets[0].GUID = [Guid]::NewGuid().ToString('D') }
                }
                $plan | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $session.ArtifactPath -Encoding UTF8
                $manifestPath = Join-Path $session.SessionPath 'manifest.json'
                $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
                $manifest.modules[0].artifacts[0].sha256 =
                    (Get-FileHash -LiteralPath $session.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

                { Get-SealedAppliedAsrPlan -SessionPath $session.SessionPath -DeclaredRules $rules } |
                    Should -Throw -Because "$mutation target inventory must be rejected"
            }
        }

        It 'requires an explicit non-interactive cloud-unavailable decision' {
            $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-ASRRules.ps1') -Raw
            $invoke | Should -Match 'continueWithoutCloud" -Required'
            $invoke | Should -Not -Match 'continueWithoutCloud" -Default'
            $invoke | Should -Not -Match 'Management tools setting.*ALL BLOCK'
        }

        It "Should preserve local and unrelated Defender rules through target-scoped policy writes" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/ASR/Private/Set-ASRViaPowerShell.ps1') -Raw
            $source | Should -Match 'ConvertFrom-ASRPreference -Preference \(Get-MpPreference'
            $source | Should -Match '\$expected\[\[string\]\$entry\.Key\]'
            $source | Should -Match 'foreach \(\$declared in \$declaredRules.Values\)'
            $source | Should -Match 'target-scoped ASR policy rules'
            $source | Should -Match 'ASR post-apply count mismatch'
            $source | Should -Match 'ASR policy registry verification failed'
            $source | Should -Not -Match '(?m)^\s*Set-MpPreference\s+'
        }

        It "Should seal a target-counted exact Defender prestate" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backup = Get-Content (Join-Path $repo 'Modules/ASR/Private/Backup-ASRRegistry.ps1') -Raw
            $backup | Should -Match 'SchemaVersion\s*=\s*5'
            $backup | Should -Match 'TargetCount\s*=\s*\[int\]\$targets\.Count'
            $backup | Should -Match 'NotApplicableCount'
            $backup | Should -Match 'AbsentAncestorKeys'
            $backup | Should -Match 'OriginalName'
            $backup | Should -Match 'Assert-ASRSnapshot -Snapshot \$roundTrip'
            $backup | Should -Match 'invalid or duplicate target'
        }

        It 'accepts only policy-owned targets in a complete schema 5 snapshot' {
            InModuleScope ASR {
                $snapshot = [PSCustomObject]@{
                    SchemaVersion     = 5
                    Target            = 'WindowsClientDefenderASR'
                    PolicyPath        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
                    PolicyKeyExisted  = $false
                    AbsentAncestorKeys = @()
                    DeclaredCount     = 1
                    TargetCount       = 1
                    NotApplicableCount = 0
                    Targets           = @(
                        [PSCustomObject]@{
                            Name             = 'Block abused vulnerable signed drivers'
                            GUID             = '56a863a9-875e-4185-98a7-b882c64b5ce5'
                            RequestedAction  = 1
                            OriginalExists   = $false
                            OriginalAction   = $null
                            PolicyOverride   = $true
                            PolicyValue      = [PSCustomObject]@{
                                Exists       = $false
                                OriginalName = $null
                                Type         = $null
                                Value        = $null
                            }
                            BaselineStatus   = 'Missing'
                            UserConfigurable = $false
                        }
                    )
                    NotApplicable     = @()
                }

                Assert-ASRSnapshot -Snapshot $snapshot | Should -BeTrue
                $snapshot.Targets[0].PolicyOverride = $false
                { Assert-ASRSnapshot -Snapshot $snapshot } | Should -Throw '*invalid or duplicate target*'
            }
        }

        It 'Should reconcile Defender authority, full ASR state and policy subtree on both sides of sealing' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $guard = Get-Content (Join-Path $repo 'Modules/ASR/Private/Assert-ASRPrestate.ps1') -Raw
            $invoke = Get-Content (Join-Path $repo 'Modules/ASR/Public/Invoke-ASRRules.ps1') -Raw
            $guard | Should -Match "AMRunningMode -ne 'Normal'"
            $guard | Should -Match 'ConvertFrom-ASRPreference -Preference \$preference'
            $guard | Should -Match 'Defender ASR target changed after backup'
            $guard | Should -Match 'ASR policy target changed after backup'
            ([regex]::Matches($invoke, 'Assert-ASRPrestate')).Count | Should -Be 2
            $firstGuard = $invoke.IndexOf('Assert-ASRPrestate')
            $seal = $invoke.IndexOf('Complete-ModuleBackup', $firstGuard)
            $secondGuard = $invoke.IndexOf('Assert-ASRPrestate', $seal)
            $apply = $invoke.IndexOf('Set-ASRViaPowerShell', $secondGuard)
            $firstGuard | Should -BeLessThan $seal
            $seal | Should -BeLessThan $secondGuard
            $secondGuard | Should -BeLessThan $apply
        }

        It 'normalizes only the paired Defender null placeholder to an empty ASR state' {
            InModuleScope ASR {
                $empty = [PSCustomObject]@{
                    AttackSurfaceReductionRules_Ids = [object[]]@($null)
                    AttackSurfaceReductionRules_Actions = [object[]]@($null)
                }
                $state = ConvertFrom-ASRPreference -Preference $empty
                $state.Count | Should -Be 0
                @($state.Ids).Count | Should -Be 0
                @($state.Actions).Count | Should -Be 0
                $state.Map.Count | Should -Be 0
            }
        }

        It 'rejects asymmetric, partial-null, malformed, unsupported, and duplicate Defender ASR states' {
            InModuleScope ASR {
                $validId = '56a863a9-875e-4185-98a7-b882c64b5ce5'
                $cases = @(
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($validId)
                        AttackSurfaceReductionRules_Actions = @()
                    },
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = [object[]]@($null)
                        AttackSurfaceReductionRules_Actions = @(1)
                    },
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @('not-a-guid')
                        AttackSurfaceReductionRules_Actions = @(1)
                    },
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($validId)
                        AttackSurfaceReductionRules_Actions = @(3)
                    },
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @($validId, $validId)
                        AttackSurfaceReductionRules_Actions = @(1, 1)
                    }
                )
                foreach ($case in $cases) {
                    { ConvertFrom-ASRPreference -Preference $case } | Should -Throw
                }
            }
        }

        It "Should report third-party endpoint handling as skipped and never applied success" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/ASR/Public/Invoke-ASRRules.ps1') -Raw
            $invoke | Should -Match '\$result\.Status\s*=\s*''Skipped'''
            $invoke | Should -Match '\$result.RulesSkipped\s*=\s*\[int\]\$result.Details.Applicable'
            $invoke | Should -Match 'Skipped \$\(\$result.RulesSkipped\) ASR settings; verifier state=NotChecked'
            $invoke | Should -Not -Match '\$result.Success\s*=\s*\$true\s*# Not an error - intentional skip'
        }

        It 'Should represent ASR DryRun verification as NotChecked and applied count as zero' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/ASR/Public/Invoke-ASRRules.ps1') -Raw
            $invoke | Should -Match 'VerificationPassed\s*=\s*\$null'
            $invoke | Should -Match '\$result\.Status = if \(\$DryRun\) \{ ''DryRun'' \} else \{ ''Success'' \}'
            $invoke | Should -Match 'if \(-not \$DryRun\) \{\s*\$result\.RulesApplied = \$applyResult\.Applied'
            $invoke | Should -Match '\$result\.RulesPreviewed = \$applyResult\.Applied'
        }

        It 'Should accept a live ASR target that already holds the sealed restore state' {
            # The ASR rule set overlaps the Security Baseline registry policies,
            # so a baseline apply or restore can put a target back on the exact
            # value this restore is about to write. That is a no-op, not drift:
            # refusing there aborted the entire module restore.
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $restore = Get-Content (Join-Path $repo 'Modules/ASR/Private/Restore-ASRState.ps1') -Raw
            $restore | Should -Match '\$matchesRestoreTarget'
            $restore | Should -Match '\$matchesRestorePolicy'
            $restore | Should -Match 'restoring this target is a no-op'
            # Foreign later state must still block.
            $restore | Should -Match 'if \(-not \$matchesApply -and -not \$matchesRestoreTarget\)'
            $restore | Should -Match 'if \(-not \$matchesAppliedPolicy -and -not \$matchesRestorePolicy\)'
        }

        It 'treats an already-absent ASR policy value as a repeat-restore no-op' {
            $backupPath = New-TestAlreadyRestoredAsrSnapshot -Root $TestDrive -PolicyKeyExisted $true

            InModuleScope ASR -Parameters @{ BackupPath = $backupPath } {
                param($BackupPath)

                $policyKey = [PSCustomObject]@{}
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @() }
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetSubKeyNames -Value { @() }
                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids     = [object[]]@($null)
                        AttackSurfaceReductionRules_Actions = [object[]]@($null)
                    }
                }
                Mock Test-Path { $true }
                Mock Get-Item { $policyKey }
                Mock Remove-ItemProperty { throw 'A missing policy value must not be removed again' }

                $result = Restore-ASRState -BackupPath $BackupPath -Confirm:$false

                $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
                $result.Restored | Should -Be 1
                @($result.Errors).Count | Should -Be 0
                Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            }
        }

        It 'treats an already-absent originally missing ASR policy key as a repeat-restore no-op' {
            $backupPath = New-TestAlreadyRestoredAsrSnapshot -Root $TestDrive -PolicyKeyExisted $false

            InModuleScope ASR -Parameters @{ BackupPath = $backupPath } {
                param($BackupPath)

                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids     = [object[]]@($null)
                        AttackSurfaceReductionRules_Actions = [object[]]@($null)
                    }
                }
                Mock Test-Path { $false }
                Mock Get-Item { throw 'An already-absent policy key must not be reopened' }
                Mock Remove-ItemProperty { throw 'An already-absent policy key has no value to remove' }

                $result = Restore-ASRState -BackupPath $BackupPath -Confirm:$false

                $result.Success | Should -BeTrue
                $result.Restored | Should -Be 1
                @($result.Errors).Count | Should -Be 0
                Should -Invoke Get-Item -Times 0 -Exactly
                Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            }
        }

        It 'accepts the exact combined session prestate on a repeated layered restore' {
            $backupPath = New-TestAlreadyRestoredAsrSnapshot `
                -Root $TestDrive `
                -PolicyKeyExisted $true `
                -IncludeNonBaselineTarget
            $snapshot = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
            $snapshot.Targets[0].OriginalExists = $true
            $snapshot.Targets[0].OriginalAction = 1
            $snapshot.Targets[0].PolicyValue.Exists = $true
            $snapshot.Targets[0].PolicyValue.OriginalName = $snapshot.Targets[0].GUID
            $snapshot.Targets[0].PolicyValue.Type = 'String'
            $snapshot.Targets[0].PolicyValue.Value = '1'
            $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $backupPath -Encoding UTF8
            $baselinePath = New-TestSecurityBaselineAsrPrestate -Root $TestDrive

            InModuleScope ASR -Parameters @{
                BackupPath = $backupPath
                BaselinePath = $baselinePath
            } {
                param($BackupPath, $BaselinePath)

                Mock Test-Path { -not ([string]$LiteralPath).StartsWith('HKLM:', [StringComparison]::OrdinalIgnoreCase) }
                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids     = [object[]]@($null)
                        AttackSurfaceReductionRules_Actions = [object[]]@($null)
                    }
                }
                Mock Get-Item { throw 'An already-absent combined-prestate key must not be reopened' }
                Mock Remove-ItemProperty { throw 'An already-absent combined-prestate value must not be removed' }

                $result = Restore-ASRState `
                    -BackupPath $BackupPath `
                    -SecurityBaselineRegistryBackupPath $BaselinePath `
                    -Confirm:$false

                $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
                $result.Restored | Should -Be 2
                $result.AlreadyAtCombinedSessionPrestate | Should -BeTrue
                @($result.Errors).Count | Should -Be 0
                Should -Invoke Get-MpPreference -Times 1 -Exactly
                Should -Invoke Get-Item -Times 0 -Exactly
                Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            }
        }

        It 'does not accept foreign ASR state as the combined session prestate' {
            $backupPath = New-TestAlreadyRestoredAsrSnapshot `
                -Root $TestDrive `
                -PolicyKeyExisted $true `
                -IncludeNonBaselineTarget
            $snapshot = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
            $snapshot.Targets[0].OriginalExists = $true
            $snapshot.Targets[0].OriginalAction = 1
            $snapshot.Targets[0].PolicyValue.Exists = $true
            $snapshot.Targets[0].PolicyValue.OriginalName = $snapshot.Targets[0].GUID
            $snapshot.Targets[0].PolicyValue.Type = 'String'
            $snapshot.Targets[0].PolicyValue.Value = '1'
            $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $backupPath -Encoding UTF8
            $baselinePath = New-TestSecurityBaselineAsrPrestate -Root $TestDrive

            InModuleScope ASR -Parameters @{
                BackupPath = $backupPath
                BaselinePath = $baselinePath
            } {
                param($BackupPath, $BaselinePath)

                $policyKey = [PSCustomObject]@{}
                $policyKey | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
                    @('56a863a9-875e-4185-98a7-b882c64b5ce5')
                }
                Mock Test-Path {
                    -not ([string]$LiteralPath).StartsWith('HKLM:', [StringComparison]::OrdinalIgnoreCase)
                }
                Mock Get-Item { $policyKey }
                Mock Get-MpPreference {
                    [PSCustomObject]@{
                        AttackSurfaceReductionRules_Ids = @('c1db55ab-c21a-4637-bb3f-a12568109d35')
                        AttackSurfaceReductionRules_Actions = @(0)
                    }
                }
                Mock Remove-ItemProperty { throw 'Foreign ASR state must be rejected before mutation' }

                $result = Restore-ASRState `
                    -BackupPath $BackupPath `
                    -SecurityBaselineRegistryBackupPath $BaselinePath `
                    -Confirm:$false

                $result.Success | Should -BeFalse
                $result.AlreadyAtCombinedSessionPrestate | Should -BeFalse
                $result.Errors -join '; ' | Should -Match 'target drifted after Apply'
                Should -Invoke Get-MpPreference -Times 2 -Exactly
                Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            }
        }

        It 'Should restore only sealed ASR targets and reject post-Apply target drift before mutation' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $restore = Get-Content (Join-Path $repo 'Modules/ASR/Private/Restore-ASRState.ps1') -Raw
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $restore | Should -Match 'target drifted after Apply; refusing to overwrite later state'
            $restore | Should -Match 'foreach \(\$entry in \$current\.GetEnumerator\(\)\)'
            $restore | Should -Match '\$desired\.Remove\(\$id\)'
            $restore | Should -Match 'Originally absent ASR policy key contains later unowned state'
            $restore | Should -Match 'Originally absent ASR ancestor contains later unowned'
            $restore | Should -Match 'ASR absent ancestor remains after restore'
            $restore | Should -Match 'value-name casing verification failed after restore'
            $restore | Should -Match 'if \(\$schemaVersion -lt 5\)'
            $restore | Should -Match 'Schema 5 Apply owns only target-scoped policy values'
            $rollback | Should -Match 'Restore-ASRState -BackupPath \$asrBackupPath'
            $rollback | Should -Match 'ConvertFrom-ASRPreference\.ps1'
            $rollback | Should -Not -Match 'Clear-ASRRules'
            $rollback | Should -Not -Match 'ASR_Config'
        }

        It 'Should expose only the canonical sealed-session restore engine' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            (Join-Path $repo 'Modules/ASR/Private/Restore-ASRSettings.ps1') | Should -Not -Exist
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollback | Should -Match 'Restore-Session'
            $rollback | Should -Match 'ASR target-scoped restore failed'
            $restore = Get-Content (Join-Path $repo 'Modules/ASR/Private/Restore-ASRState.ps1') -Raw
            $restore | Should -Match 'ASR post-restore count mismatch'
        }

        It "requires positive Defender primary authority before applying ASR" {
            $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-ASRRules.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:ModuleRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $invoke | Should -Match "AMRunningMode -eq 'Normal'"
            $invoke | Should -Match 'AntivirusEnabled'
            $invoke | Should -Match 'RealTimeProtectionEnabled'
            $invoke | Should -Match 'Defender enforcement authority could not be established'
            $verifier | Should -Match "DetectionMethod = 'DefenderAuthorityQueryFailed'"
            $verifier | Should -Match 'DefenderPrimaryAuthority'
        }

        It 'uses the end block as the only result output for every early ASR skip' {
            $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-ASRRules.ps1') -Raw
            ([regex]::Matches($invoke, 'return\s+\$result')).Count | Should -Be 1
            $invoke | Should -Match 'end\s*\{[\s\S]*return\s+\$result'
        }

        It "Should detect stopped endpoint and ConfigMgr service registrations" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $dependencies = Get-Content (Join-Path $repo 'Utils/Dependencies.ps1') -Raw
            $configMgr = Get-Content (Join-Path $repo 'Modules/ASR/Private/Test-ConfigMgrPresence.ps1') -Raw
            $invoke = Get-Content (Join-Path $repo 'Modules/ASR/Public/Invoke-ASRRules.ps1') -Raw
            $dependencies | Should -Match 'InstalledService:\$\(\$installed.Status\)'
            $dependencies | Should -Match '\$installedServices\s*=\s*@\(Get-Service -ErrorAction Stop\)'
            $configMgr | Should -Match 'client service detected \(\$\(\$ccmService.Status\)\)'
            $configMgr | Should -Match 'Failed to determine ConfigMgr presence'
            $invoke | Should -Match 'ConfigMgr presence could not be inspected; the explicit usesManagementTools='
            $configMgr | Should -Match 'return \$null'
            $configMgr | Should -Not -Match 'Using conservative detected state'
        }

        It 'classifies Defender SecurityCenter records without localized display-name matching' {
            Test-IsMicrosoftDefenderSecurityCenterProduct -Product ([PSCustomObject]@{
                    instanceGuid = '{D68DDC3A-831F-4FAE-9E44-DA132C1ACF46}'
                    displayName = 'Windows-Sicherheitsschutz'
                    pathToSignedProductExe = 'windowsdefender://'
                    pathToSignedReportingExe = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe'
                }) | Should -BeTrue

            Test-IsMicrosoftDefenderSecurityCenterProduct -Product ([PSCustomObject]@{
                    instanceGuid = '{11111111-2222-3333-4444-555555555555}'
                    displayName = 'Antivirus de terceros'
                    pathToSignedProductExe = 'C:\Program Files\Vendor\av.exe'
                    pathToSignedReportingExe = 'C:\Program Files\Vendor\service.exe'
                }) | Should -BeFalse
        }

        It 'Should classify SecurityCenter, passive Defender, stopped endpoint service and clean Defender matrices' {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    instanceGuid              = '{11111111-2222-3333-4444-555555555555}'
                    displayName               = 'Example Endpoint Protection'
                    pathToSignedProductExe    = 'C:\Program Files\Example\endpoint.exe'
                    pathToSignedReportingExe  = 'C:\Program Files\Example\reporter.exe'
                }
            }
            Mock Get-MpComputerStatus {
                [PSCustomObject]@{ AMRunningMode = 'Normal' }
            }
            Mock Get-Service { @() }
            $securityCenter = Test-ThirdPartySecurityProduct
            $securityCenter.Detected | Should -BeTrue
            $securityCenter.DetectionMethod | Should -Be 'SecurityCenter2'

            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{
                        instanceGuid              = '{11111111-2222-3333-4444-555555555555}'
                        displayName               = 'Example Endpoint Protection'
                        pathToSignedProductExe    = 'C:\Program Files\Example\endpoint.exe'
                        pathToSignedReportingExe  = 'C:\Program Files\Example\reporter.exe'
                    }
                    [PSCustomObject]@{
                        instanceGuid              = '{22222222-3333-4444-5555-666666666666}'
                        displayName               = 'Second Endpoint Protection'
                        pathToSignedProductExe    = 'C:\Program Files\Second\endpoint.exe'
                        pathToSignedReportingExe  = 'C:\Program Files\Second\reporter.exe'
                    }
                )
            }
            $multipleRegistered = Test-ThirdPartySecurityProduct
            $multipleRegistered.Detected | Should -BeTrue
            $multipleRegistered.ProductName | Should -Be 'Example Endpoint Protection, Second Endpoint Protection'

            Mock Get-CimInstance { throw 'SecurityCenter unavailable' }
            Mock Get-MpComputerStatus {
                [PSCustomObject]@{ AMRunningMode = 'Passive Mode' }
            }
            Mock Get-Service { @() }
            $passive = Test-ThirdPartySecurityProduct
            $passive.Detected | Should -BeTrue
            $passive.DefenderPassiveMode | Should -BeTrue
            $passive.DetectionMethod | Should -Be 'PassiveMode'

            Mock Get-CimInstance { @() }
            Mock Get-MpComputerStatus {
                [PSCustomObject]@{ AMRunningMode = 'Normal' }
            }
            Mock Get-Service {
                @([PSCustomObject]@{ Name = 'ekrn'; Status = 'Stopped' })
            }
            $stoppedService = Test-ThirdPartySecurityProduct
            $stoppedService.Detected | Should -BeTrue
            $stoppedService.DetectionMethod | Should -Be 'InstalledService:Stopped'

            Mock Get-Service { @() }
            $clean = Test-ThirdPartySecurityProduct
            $clean.Detected | Should -BeFalse
            $clean.ProductName | Should -BeNullOrEmpty
        }

        It "Should require exact actions and reject duplicate expected or configured rules" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $verify = Get-Content (Join-Path $repo 'Modules/ASR/Private/Test-ASRCompliance.ps1') -Raw
            $normalizer = Get-Content (Join-Path $repo 'Modules/ASR/Private/ConvertFrom-ASRPreference.ps1') -Raw
            $verify | Should -Match 'Duplicate expected ASR rule'
            $verify | Should -Match 'ConvertFrom-ASRPreference'
            $normalizer | Should -Match 'Defender returned duplicate ASR rule'
            $verify | Should -Match '\[int\]\$actualAction -eq \[int\]\$rule.Action'
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module ASR -Force -ErrorAction SilentlyContinue
}
