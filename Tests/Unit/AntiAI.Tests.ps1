#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for AntiAI module

.DESCRIPTION
    Pester v5 tests for the AntiAI module functionality.
    Tests return values, DryRun behavior, and compliance verification.

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
    # Load production core dependencies before importing the module. The module
    # session resolves the same promoted logging/config functions as production.
    # Import through the production manifest. Importing AntiAI.psm1 directly
    # bypasses FunctionsToExport and can hide a verifier-breaking export gap.
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/AntiAI.psd1"
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1")
    $corePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }

    foreach ($fn in 'Write-Log','Write-ErrorLog','Initialize-Logger','Get-LogFilePath','Get-ErrorContext','Test-NonInteractiveMode') {
        if (Test-Path "function:$fn") {
            Set-Item -Path "function:global:$fn" -Value (Get-Item "function:$fn").ScriptBlock
        }
    }

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
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

    # Initialize backup system
    if (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue) {
        Initialize-BackupSystem -BackupDirectory (Join-Path $TestDrive 'Backups')
    }
}

Describe "AntiAI Module" {

    Context "Module Structure" {

        It "Should export Invoke-AntiAI function" {
            $command = Get-Command -Name Invoke-AntiAI -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should not present AntiAI as a separately versioned product' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw -Encoding UTF8
            $source | Should -Match "Write-Host '  ANTI-AI MODULE'"
            $source | Should -Not -Match 'ANTI-AI MODULE v'
            $source | Should -Not -Match '\$displayVersion'
        }

        It "Should export Test-AntiAICompliance function" {
            $command = Get-Command -Name Test-AntiAICompliance -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export the durable intent target-plan resolver used by the standalone verifier" {
            $command = Get-Command -Name Get-AntiAIIntentTargetPlan -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
            $command.ModuleName | Should -BeExactly 'AntiAI'
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It "Should not expose a SkipBackup parameter" {
            $command = Get-Command -Name Invoke-AntiAI
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $false
        }
    }

    Context "AntiAI Configuration" {

        It "Should load AntiAI settings from JSON" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $settingsPath | Should -Exist
        }

        It "Settings file should be valid JSON" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            { Get-Content $settingsPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Settings should be a valid config object" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings | Should -Not -BeNullOrEmpty
        }

        It "Should declare the exact 43-target and 12-group inventory" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.TotalPolicies | Should -Be 43
            $settings.TotalFeatureGroups | Should -Be 12
            @($settings.Features.PSObject.Properties).Count | Should -Be 12
            $edge = $settings.Features.'12_Edge_Copilot_Sidebar'.Registry.'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            $edge.NewTabPageBingChatEnabled.Type | Should -Be 'DWord'
            $edge.NewTabPageBingChatEnabled.Value | Should -Be 0
        }

        It "Should model Recall ADMX enable values separately from text data" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $recall = $settings.Features.'2_Windows_Recall'.EnterpriseProtection.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            $recall.SetDenyAppListForRecall.Type | Should -Be 'DWord'
            $recall.SetDenyAppListForRecall.Value | Should -Be 1
            $recall.DenyAppListForRecall.Type | Should -Be 'String'
            $recall.SetDenyUriListForRecall.Type | Should -Be 'DWord'
            $recall.SetDenyUriListForRecall.Value | Should -Be 1
            $recall.DenyUriListForRecall.Type | Should -Be 'String'
        }

        It "Should not declare the unsupported HideAIActionsMenu value" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            (Get-Content $settingsPath -Raw) | Should -Not -Match '"HideAIActionsMenu"\s*:'
        }
    }

    Context "Function Execution - DryRun Mode" {
        # These tests require admin rights and proper environment - skipped on CI

        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AntiAI -DryRun } } | Should -Not -Throw
        }

        It "Should return a result" -Tag 'Interactive' {
            $result = Invoke-UnitNonInteractive { Invoke-AntiAI -DryRun }
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Return Object Structure" {
        # Skipped - return object properties may vary based on environment
    }

    Context "Compliance Testing" {

        It "Test-AntiAICompliance rejects a live-derived standalone scope" {
            { Test-AntiAICompliance -ErrorAction Stop } |
                Should -Throw '*requires an explicit sealed or durable target plan*'
        }

        # The compliance verdict is Invoke-AntiAI's post-Apply gate: it decides
        # VerificationPassed, the "N/47 exact checks passed" line, and Success.
        # Until now its only behavioural coverage was "throws with no plan".
        BeforeEach {
            # Two applicable targets + 41 declared-not-applicable = the closed
            # 43-target scope the function reconciles against.
            $script:CopilotTarget = [PSCustomObject]@{
                Feature = 'Copilot'; Description = 'Turn off Windows Copilot'
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
                Name = 'TurnOffWindowsCopilot'; Type = 'DWord'; Value = 1
            }
            $script:RecallTarget = [PSCustomObject]@{
                Feature = 'Recall'; Description = 'Disable AI data analysis'
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                Name = 'DisableAIDataAnalysis'; Type = 'DWord'; Value = 1
            }
            $script:NotApplicableFill = @(1..41 | ForEach-Object {
                [PSCustomObject]@{
                    Feature = "Fill$_"; Path = "HKLM:\SOFTWARE\Test\NA$_"; Name = "Value$_"
                    Reason = 'Declared not applicable for this fixture'
                }
            })
            Mock -ModuleName AntiAI Get-AntiAIUserContext {
                [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' }
            }
            # Registry world default: both applicable keys exist with the exact
            # requested value/kind; all four Copilot URI hives are absent.
            $global:AntiAITestRegistryWorld = @{
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' = @{ TurnOffWindowsCopilot = @('DWord', 1) }
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' = @{ DisableAIDataAnalysis = @('DWord', 1) }
            }
            Mock -ModuleName AntiAI Test-Path {
                $global:AntiAITestRegistryWorld.ContainsKey([string]$LiteralPath)
            }
            Mock -ModuleName AntiAI Get-Item {
                $values = $global:AntiAITestRegistryWorld[[string]$LiteralPath]
                $key = [PSCustomObject]@{}
                $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
                    [string[]]@($values.Keys)
                }.GetNewClosure()
                $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
                    param($name) [Microsoft.Win32.RegistryValueKind]($values[$name][0])
                }.GetNewClosure()
                # Production calls GetValue(name, default, options); the shim
                # only consumes the name and the excess arguments bind to $args.
                $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                    param($name) $values[$name][1]
                }.GetNewClosure()
                $key
            }
        }

        It "passes only when every applicable value matches exactly" {
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'PASS'
            $verdict.Passed | Should -Be 6      # 2 registry + 4 absent URI hives
            $verdict.Failed | Should -Be 0
            $verdict.NotApplicable | Should -Be 41
            $verdict.TotalChecks | Should -Be 47
            $verdict.ExitCode | Should -Be 0
        }

        It "fails on a wrong registry VALUE and names the divergence" {
            $global:AntiAITestRegistryWorld['HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'].TurnOffWindowsCopilot = @('DWord', 0)
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
            $verdict.Failed | Should -Be 1
            $verdict.ExitCode | Should -Be 1
            $failedCheck = @($verdict.Details | Where-Object Status -eq 'FAIL')[0]
            [string]$failedCheck.Name | Should -BeExactly 'TurnOffWindowsCopilot'
            [string]$failedCheck.Error | Should -Match 'expected DWord'
        }

        It "fails on a wrong registry KIND even when the data looks right" {
            $global:AntiAITestRegistryWorld['HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'].DisableAIDataAnalysis = @('String', 1)
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
            $verdict.Failed | Should -Be 1
            [string]@($verdict.Details | Where-Object Status -eq 'FAIL')[0].Name |
                Should -BeExactly 'DisableAIDataAnalysis'
        }

        It "fails when a Copilot URI source hive still exists" {
            $global:AntiAITestRegistryWorld['HKLM:\SOFTWARE\Classes\ms-copilot'] = @{}
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
            $failedCheck = @($verdict.Details | Where-Object Status -eq 'FAIL')[0]
            [string]$failedCheck.Category | Should -BeExactly 'URIHandlers'
            [string]$failedCheck.Error | Should -Match 'still exists'
        }

        AfterAll {
            Remove-Variable -Name AntiAITestRegistryWorld -Scope Global -ErrorAction SilentlyContinue
        }

        It "refuses to attest a plan with zero applicable targets" {
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @() `
                -NotApplicableTargets @($script:NotApplicableFill + @(
                    [PSCustomObject]@{ Feature = 'Fill42'; Path = 'HKLM:\SOFTWARE\Test\NA42'; Name = 'Value42'; Reason = 'fixture' }
                    [PSCustomObject]@{ Feature = 'Fill43'; Path = 'HKLM:\SOFTWARE\Test\NA43'; Name = 'Value43'; Reason = 'fixture' }
                ))
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }
    }

    Context "AI Features Coverage" {
        # Config structure tests - skipped as structure may vary
    }

    Context "Exact registry BAVR" {
        It "Should validate key existence and unowned state before mutation" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/AntiAI/Private/Restore-AntiAIRegistryState.ps1') -Raw
            $source | Should -Match 'Validate the complete document before the first registry mutation'
            $source | Should -Match 'Originally absent AntiAI key contains unowned state'
            $source | Should -Match 'AntiAI key-existence verification failed'
            $source | Should -Match 'Mount-UserRegistryHiveForRestore -Sid \$sid'
            $source | Should -Match 'Dismount-UserRegistryHiveAfterRestore -Mount \$mount'
        }

        It "Should use the same strict snapshot validator in backup restore and Core preflight" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw
            $restore = Get-Content (Join-Path $repo 'Modules/AntiAI/Private/Restore-AntiAIRegistryState.ps1') -Raw
            $core = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $invoke | Should -Match 'SchemaVersion\s*=\s*4'
            $invoke | Should -Match 'Assert-AntiAIRegistrySnapshot -Snapshot \$snapshot'
            $invoke | Should -Match 'Assert-AntiAIRegistrySnapshot -Snapshot \$roundTrip'
            $restore | Should -Match 'Assert-AntiAIRegistrySnapshot -Snapshot \$snapshot -RestoreOnly'
            $core | Should -Match 'Assert-AntiAIRegistrySnapshot -Snapshot \$json -RestoreOnly'
            $core | Should -Match 'Mount-UserRegistryHiveForRestore -Sid \$Matches\[1\]'
            $core | Should -Match 'Temporary URI-handler user hive could not be unloaded'
        }

        It "Should reject non-Boolean existence flags before restore" {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                $entries = @(Get-AntiAIRegistryTargets | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4; DeclaredTargetCount = 43
                    ApplicableTargetCount = $entries.Count; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Not -Throw
                $snapshot.Entries[0].Exists = 'false'
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Throw '*must be Boolean*'
            }
        }

        It 'Should reject an incomplete schema-4 inventory during RestoreOnly validation' {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                $entries = @(Get-AntiAIRegistryTargets | Select-Object -First 42 | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4; DeclaredTargetCount = 42
                    ApplicableTargetCount = 42; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } |
                    Should -Throw '*exact target count*'
            }
        }

        It 'resolves a durable AntiAI partition without consulting live applicability' {
            InModuleScope AntiAI {
                $script:TestAntiAIUserRoot = 'HKU:\S-1-5-21-1-2-3-1001'
                Mock Get-AntiAIUserContext {
                    [PSCustomObject]@{ Root = $script:TestAntiAIUserRoot }
                }
                $targets = @(Get-AntiAIRegistryTargets)
                $intent = [PSCustomObject]@{
                    applicableTargets = @($targets | Select-Object -First 17 | ForEach-Object {
                            [PSCustomObject]@{ path=[string]$_.Path; name=[string]$_.Name }
                        })
                    notApplicableTargets = @($targets | Select-Object -Skip 17 | ForEach-Object {
                            [PSCustomObject]@{ path=[string]$_.Path; name=[string]$_.Name }
                        })
                }
                # Intent belongs to the Apply-time desktop user. Verification
                # resolves the HKCU role for a different interactive user.
                $script:TestAntiAIUserRoot = 'HKU:\S-1-5-21-1-2-3-1002'
                Mock Get-AntiAITargetPlan { throw 'live applicability must not be read' }
                $plan = Get-AntiAIIntentTargetPlan -Intent $intent
                $plan.ApplicableCount | Should -Be 17
                $plan.NotApplicableCount | Should -Be 26
                $plan.EvidenceSource | Should -BeExactly 'DurableApplyIntent'
                @(@($plan.ApplicableTargets) + @($plan.NotApplicableTargets) |
                    Where-Object {
                        [string]$_.Path -like 'HKU:\S-1-5-21-1-2-3-1002\*'
                    }).Count | Should -BeGreaterThan 0
                Should -Invoke Get-AntiAITargetPlan -Times 0 -Exactly
            }
        }

        It 'keeps schema-4 RestoreOnly independent of the current inventory and forces a schema bump when that inventory changes' {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext {
                    [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' }
                }
                $entries = @(Get-AntiAIRegistryTargets | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4; DeclaredTargetCount = $entries.Count
                    ApplicableTargetCount = $entries.Count; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                Mock Get-AntiAIRegistryTargets { throw 'current inventory must not be read during restore' }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Not -Throw
                Should -Invoke Get-AntiAIRegistryTargets -Times 0 -Exactly
            }
        }

        It "Should apply only the canonical config-derived target set" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw
            $source | Should -Match 'Set-AntiAIRegistryTargets[\s\S]*-Targets \$applicableTargets'
            $source | Should -Not -Match 'Disable-Recall|Set-RecallProtection|Disable-CopilotAdvanced|Disable-ExplorerAI'
        }

        It "classifies all 43 targets and never mutates the NotApplicable subset" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $plan = Get-Content (Join-Path $repo 'Modules/AntiAI/Private/Get-AntiAITargetPlan.ps1') -Raw
            $invoke = Get-Content (Join-Path $repo 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw
            $restore = Get-Content (Join-Path $repo 'Modules/AntiAI/Private/Restore-AntiAIRegistryState.ps1') -Raw
            $plan | Should -Match 'ApplicableTargets'
            $plan | Should -Match 'NotApplicableTargets'
            $plan | Should -Match 'EEA-only Insider policy'
            $plan | Should -Match 'documented Edge \$minimum\+ policy is staged for a future installation'
            $plan | Should -Match 'DisableSettingsAgent''[\s\S]*\$commercial -and \$settingsAgentFloor'
            $plan | Should -Match 'DisableClickToDo''[\s\S]*\$proOrHigher -and \$recallFloor'
            $plan | Should -Match '\$isApplicable = \$null -ne \$notepadVersion -and \$notepadVersion -ge \$minimumNotepad'
            $invoke | Should -Match 'NotApplicableTargetCount'
            $invoke | Should -Match 'foreach \(\$target in \$applicableTargets\)'
            $invoke | Should -Match 'Assert-AntiAIPrestate -Snapshot \$snapshot -UriSources \$uriSources'
            ([regex]::Matches($invoke, 'Assert-AntiAIPrestate -Snapshot \$snapshot -UriSources \$uriSources')).Count | Should -Be 2
            $restore | Should -Match '\$entries = @\(\$snapshot\.Entries\)'
            $verifier = Get-Content (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $verifier | Should -Match 'Get-AntiAIIntentTargetPlan -Intent \$antiAIIntent'
            $verifier | Should -Match '\$antiAIPlan = if \(\$appliedScopeRun\)[\s\S]{0,100}Get-AntiAITargetPlan'
            $verifier | Should -Match "VerificationReasonCode\s*=\s*'AntiAI\.NoSavedTargetPlan'"
            $verifier | Should -Match 'NotApplicableDetails = \$antiAINotApplicable'
            $core = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $core | Should -Match 'Originally absent AntiAI URI source was created after Apply; refusing to delete later unowned state'
        }

        It "classifies Home, Pro, and Enterprise evaluation by OperatingSystemSKU" {
            InModuleScope AntiAI {
                function Get-WindowsVersion { throw 'Mock was not installed' }
                Set-Item -Path function:Get-CimInstance -Value { throw 'Mock was not installed' }
                Mock Get-CimInstance {
                    [PSCustomObject]@{
                        OperatingSystemSKU = $script:antiAiTestSku
                        ProductType = 1
                        BuildNumber = '26200'
                    }
                }
                Mock Get-WindowsVersion {
                    [PSCustomObject]@{
                        IsSupported = $true; Release = '25H2'; DisplayVersion = '25H2'
                        BuildNumber = 26200; UpdateBuildRevision = 8655
                        FullBuild = '26200.8655'; SupportLevel = 'Stable'
                        Edition = $script:antiAiTestEdition
                    }
                }
                Mock Test-Path { $false }

                foreach ($case in @(
                        @{ Sku = 101; Edition = 'Core'; Family = 'Home'; Commercial = $false; ProOrHigher = $false }
                        @{ Sku = 48; Edition = 'Professional'; Family = 'Professional'; Commercial = $false; ProOrHigher = $true }
                        @{ Sku = 72; Edition = 'EnterpriseEval'; Family = 'Enterprise'; Commercial = $true; ProOrHigher = $true }
                    )) {
                    $script:antiAiTestSku = $case.Sku
                    $script:antiAiTestEdition = $case.Edition
                    $result = Get-AntiAIApplicability
                    $result.EditionFamily | Should -Be $case.Family
                    $result.OperatingSystemSKU | Should -Be $case.Sku
                    $result.CommercialEdition | Should -Be $case.Commercial
                    $result.ProOrHigherEdition | Should -Be $case.ProOrHigher
                    $result.InsiderPreviewProfile | Should -BeFalse
                }
            }
        }

        It "plans stable 25H2 AI controls per edition without requiring Insider enrollment" {
            $declaredTargets = InModuleScope AntiAI {
                Mock Get-AntiAIUserContext {
                    [PSCustomObject]@{ Root = 'Registry::HKEY_USERS\S-1-5-21-1000' }
                }
                @(Get-AntiAIRegistryTargets)
            }
            InModuleScope AntiAI -Parameters @{ DeclaredTargets = $declaredTargets } {
                param($DeclaredTargets)
                Set-Item -Path function:Get-AppxPackage -Value { throw 'Mock was not installed' }
                Mock Test-Path { $false }
                Mock Get-AppxPackage {
                    [PSCustomObject]@{ Version = '11.2605.29.0' }
                }

                foreach ($case in @(
                        @{ Family = 'Home'; Commercial = $false; ProOrHigher = $false; Applicable = 18; SettingsAgent = $false; ClickToDo = $false }
                        @{ Family = 'Professional'; Commercial = $false; ProOrHigher = $true; Applicable = 27; SettingsAgent = $false; ClickToDo = $true }
                        @{ Family = 'Enterprise'; Commercial = $true; ProOrHigher = $true; Applicable = 34; SettingsAgent = $true; ClickToDo = $true }
                    )) {
                    $state = [PSCustomObject]@{
                        SupportedWindowsProfile = $true
                        WindowsBuildNumber = 26200
                        WindowsUBR = 8655
                        CommercialEdition = $case.Commercial
                        ProOrHigherEdition = $case.ProOrHigher
                        InsiderPreviewProfile = $false
                    }
                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $plan.ApplicableCount | Should -Be $case.Applicable
                    $plan.NotApplicableCount | Should -Be (43 - $case.Applicable)
                    (@($plan.ApplicableTargets | Where-Object Name -eq 'DisableSettingsAgent').Count -eq 1) |
                        Should -Be $case.SettingsAgent
                    (@($plan.ApplicableTargets | Where-Object Name -eq 'DisableClickToDo').Count -eq 1) |
                        Should -Be $case.ClickToDo
                    @($plan.ApplicableTargets | Where-Object Name -eq 'DisableAIFeatures').Count | Should -Be 1
                }
            }
        }

        It 'uses the newest parseable Edge copy and ignores a stale unparseable executable' {
            $declaredTargets = InModuleScope AntiAI {
                Mock Get-AntiAIUserContext {
                    [PSCustomObject]@{ Root = 'Registry::HKEY_USERS\S-1-5-21-1000' }
                }
                @(Get-AntiAIRegistryTargets)
            }
            InModuleScope AntiAI -Parameters @{ DeclaredTargets = $declaredTargets } {
                param($DeclaredTargets)
                $oldProgramFiles = $env:ProgramFiles
                $oldProgramFilesX86 = ${env:ProgramFiles(x86)}
                try {
                    Set-Item -Path function:Get-AppxPackage -Value { throw 'Get-AppxPackage test placeholder was not mocked' }
                    $env:ProgramFiles = Join-Path $TestDrive 'PF64'
                    ${env:ProgramFiles(x86)} = Join-Path $TestDrive 'PF32'
                    $newestPath = Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'
                    $stalePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
                    Mock Test-Path {
                        param($LiteralPath)
                        return [string]$LiteralPath -in @($newestPath, $stalePath)
                    }
                    Mock Get-Item {
                        param($LiteralPath)
                        if ([string]$LiteralPath -ceq $newestPath) {
                            return [PSCustomObject]@{
                                VersionInfo = [PSCustomObject]@{ FileVersion = '151.0.10.1 stable' }
                            }
                        }
                        return [PSCustomObject]@{
                            VersionInfo = [PSCustomObject]@{ FileVersion = 'stub' }
                        }
                    }
                    Mock Get-AppxPackage {
                        [PSCustomObject]@{ Version = '11.2605.29.0' }
                    }
                    Mock Get-Process { throw 'Explorer must not be consulted for AntiAI product discovery' }
                    $state = [PSCustomObject]@{
                        SupportedWindowsProfile = $true
                        WindowsBuildNumber = 26200
                        WindowsUBR = 8875
                        CommercialEdition = $true
                        ProOrHigherEdition = $true
                        InsiderPreviewProfile = $false
                    }

                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $plan.EdgeVersion | Should -BeExactly '151.0.10.1'
                    $plan.DeclaredCount | Should -Be 43
                    ($plan.ApplicableCount + $plan.NotApplicableCount) | Should -Be 43
                    Should -Invoke Get-Process -Times 0 -Exactly
                }
                finally {
                    $env:ProgramFiles = $oldProgramFiles
                    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
                }
            }
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module AntiAI -Force -ErrorAction SilentlyContinue
}
