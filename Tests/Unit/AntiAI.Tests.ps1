#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for AntiAI module

.DESCRIPTION
    Pester v5 tests for the AntiAI module functionality.
    Tests return values, DryRun behavior, and compliance verification.

.NOTES
    Author: NexusOne23
    Version: 2.2.6
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
            # The framework frames every module; AntiAI adds no second header.
            $source | Should -Not -Match "Write-Host '  ANTI-AI MODULE'"
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

        It "Should declare the exact 50-target and 12-group inventory" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            $settings.TotalPolicies | Should -Be 50
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

        It "Should declare no retired or undocumented value as a target" {
            # Absent from Microsoft's WindowsAI CSP, every official ADMX and the
            # 26H2 system binaries; ShowCopilotButton was never written.
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $raw = Get-Content $settingsPath -Raw
            foreach ($name in @(
                    'LetAppsAccessGenerativeAI', 'DisableAgentConnectors', 'DisableAgentWorkspaces',
                    'DisableRemoteAgentConnectors', 'AgentConnectorMinimumPolicy', 'ShowCopilotButton'
                )) {
                $raw | Should -Not -Match ('"' + $name + '"\s*:')
            }
            $settings = $raw | ConvertFrom-Json
            $settings.Features.'1_GenerativeAI_Master'.Registry.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'.LetAppsAccessSystemAIModels.Value | Should -Be 2
        }

        It "Should declare the Copilot app startup tasks as Settings-equivalent per-user values" {
            $settingsPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AntiAI/Config/AntiAI-Settings.json"
            $copilot = (Get-Content $settingsPath -Raw | ConvertFrom-Json).Features.'3_Windows_Copilot'.Registry
            $prefix = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\'
            foreach ($task in @('Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId', 'Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId')) {
                # StartupTaskState.DisabledByUser, exactly what Settings > Apps > Startup writes.
                $state = $copilot.PSObject.Properties[$prefix + $task].Value.State
                $state.Type | Should -BeExactly 'DWord'
                $state.Value | Should -Be 1
            }
        }

        It "Should keep the Copilot app and Edge Cowork policies as separate identities" {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                $cowork = @(Get-AntiAIRegistryTargets | Where-Object Name -eq 'CopilotCoworkToolActionsEnabled')
                @($cowork.Path | Sort-Object) | Should -Be @(
                    'HKLM:\SOFTWARE\Policies\Microsoft\Copilot', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge')
                @($cowork | ForEach-Object Value) | Should -Be @(0, 0)
            }
        }
    }

    Context "Function Execution - DryRun Mode" {
        # Runs the real entry point non-interactively against the live machine.

        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AntiAI -DryRun } } | Should -Not -Throw
        }

        It "Should return a result" -Tag 'Interactive' {
            $result = Invoke-UnitNonInteractive { Invoke-AntiAI -DryRun }
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Compliance Testing" {

        It "Test-AntiAICompliance rejects a live-derived standalone scope" {
            { Test-AntiAICompliance -ErrorAction Stop } |
                Should -Throw '*requires an explicit sealed or durable target plan*'
        }

        # The compliance verdict is Invoke-AntiAI's post-Apply gate: it decides
        # VerificationPassed, the passed/failed/not-applicable line, and Success.
        # These cases exercise that verdict against a mocked registry world.
        BeforeEach {
            Mock -ModuleName AntiAI Get-AntiAIUserContext {
                [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' }
            }
            # Use the real closed inventory, including Copilot's user hive.
            $canonical = @(InModuleScope AntiAI { Get-AntiAIRegistryTargets })
            $script:CopilotTarget = $canonical | Where-Object Name -eq 'TurnOffWindowsCopilot'
            $script:RecallTarget = $canonical | Where-Object Name -eq 'DisableAIDataAnalysis'
            $script:NotApplicableFill = @($canonical | Where-Object {
                    $_.Name -notin @('TurnOffWindowsCopilot', 'DisableAIDataAnalysis')
                } | Select-Object Path, Name, Feature, @{Name='Reason';Expression={'Fixture partition'}})
            # Registry world default: both applicable keys exist with the exact
            # requested value/kind; all four Copilot URI hives are absent.
            $global:AntiAITestRegistryWorld = @{
                'HKU:\S-1-5-21-1-2-3-1001\Software\Policies\Microsoft\Windows\WindowsCopilot' = @{ TurnOffWindowsCopilot = @('DWord', 1) }
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' = @{ DisableAIDataAnalysis = @('DWord', 1) }
            }
            Mock -ModuleName AntiAI Test-Path {
                $global:AntiAITestRegistryWorld.ContainsKey([string]$LiteralPath)
            } -ParameterFilter { $LiteralPath -like 'HKLM:\*' -or $LiteralPath -like 'HKU:\*' }
            Mock -ModuleName AntiAI Test-NoIDRegistryKey {
                $global:AntiAITestRegistryWorld.ContainsKey([string]$LiteralPath)
            } -ParameterFilter { $LiteralPath -like 'HKLM:\*' -or $LiteralPath -like 'HKU:\*' }
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
            } -ParameterFilter { $LiteralPath -like 'HKLM:\*' -or $LiteralPath -like 'HKU:\*' }
        }

        It "passes only when every applicable value matches exactly" {
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'PASS'
            $verdict.Passed | Should -Be 6      # 2 registry + 4 absent URI hives
            $verdict.Failed | Should -Be 0
            $verdict.NotApplicable | Should -Be 48
            $verdict.TotalChecks | Should -Be 54
            $verdict.ExitCode | Should -Be 0
        }

        It "fails on a wrong registry VALUE and names the divergence" {
            $global:AntiAITestRegistryWorld[$script:CopilotTarget.Path].TurnOffWindowsCopilot = @('DWord', 0)
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

        It 'rejects a duplicate applicable target even when all supplied reads match' {
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:CopilotTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        It 'rejects duplicate non-applicable identities' {
            $script:NotApplicableFill[1] = $script:NotApplicableFill[0]
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        It 'rejects identities appearing in both applicability buckets' {
            $script:NotApplicableFill[0] = $script:CopilotTarget | Select-Object Path, Name, Feature,
                @{Name='Reason';Expression={'Overlapping fixture'}}
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        It 'rejects a foreign identity in the non-applicable bucket' {
            $script:NotApplicableFill[0].Path = 'HKLM:\SOFTWARE\ForeignFixture'
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        It 'rejects a caller-weakened expected value even when the live value agrees' {
            $script:CopilotTarget.Value = 0
            $global:AntiAITestRegistryWorld[$script:CopilotTarget.Path].TurnOffWindowsCopilot = @('DWord', 0)
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        It 'rejects a caller-changed expected registry kind even when the live kind agrees' {
            $script:CopilotTarget.Type = 'String'
            $script:CopilotTarget.Value = '1'
            $global:AntiAITestRegistryWorld[$script:CopilotTarget.Path].TurnOffWindowsCopilot = @('String', '1')
            $verdict = Test-AntiAICompliance -ApplicableTargets @($script:CopilotTarget, $script:RecallTarget) `
                -NotApplicableTargets $script:NotApplicableFill
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }

        AfterAll {
            Remove-Variable -Name AntiAITestRegistryWorld -Scope Global -ErrorAction SilentlyContinue
        }

        It "refuses to attest a plan with zero applicable targets" {
            $verdict = Test-AntiAICompliance `
                -ApplicableTargets @() `
                -NotApplicableTargets @($script:NotApplicableFill + @(
                    [PSCustomObject]@{ Feature = 'Fill47'; Path = 'HKLM:\SOFTWARE\Test\NA47'; Name = 'Value47'; Reason = 'fixture' }
                    [PSCustomObject]@{ Feature = 'Fill48'; Path = 'HKLM:\SOFTWARE\Test\NA48'; Name = 'Value48'; Reason = 'fixture' }
                ))
            $verdict.OverallStatus | Should -BeExactly 'FAIL'
        }
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
            $invoke | Should -Match 'SchemaVersion\s*=\s*5'
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
                    SchemaVersion = 5; DeclaredTargetCount = 50
                    ApplicableTargetCount = $entries.Count; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Not -Throw
                $snapshot.Entries[0].Exists = 'false'
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Throw '*must be Boolean*'
            }
        }

        It 'Should reject an incomplete schema-5 inventory during RestoreOnly validation' {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                $entries = @(Get-AntiAIRegistryTargets | Select-Object -First 49 | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 5; DeclaredTargetCount = 49
                    ApplicableTargetCount = 49; NotApplicableTargetCount = 0
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
                $plan.NotApplicableCount | Should -Be 33
                $plan.EvidenceSource | Should -BeExactly 'DurableApplyIntent'
                $plan.InventoryChanged | Should -BeFalse
                @(@($plan.ApplicableTargets) + @($plan.NotApplicableTargets) |
                    Where-Object {
                        [string]$_.Path -like 'HKU:\S-1-5-21-1-2-3-1002\*'
                    }).Count | Should -BeGreaterThan 0
                Should -Invoke Get-AntiAITargetPlan -Times 0 -Exactly
            }
        }

        It 'keeps a published schema-4 session restorable without reading the current inventory' {
            InModuleScope AntiAI {
                # The exact 43-identity inventory sealed by 2.2.5/2.2.6.
                $user = 'HKU:\S-1-5-21-1-2-3-1001'
                $schema4 = [ordered]@{
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' = @('LetAppsAccessGenerativeAI')
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' = @(
                        'AgentConnectorMinimumPolicy', 'AgentConsentDuration', 'AllowRecallEnablement',
                        'AllowRecallExport', 'ConfigureAgentConnectors', 'DenyAppListForRecall',
                        'DenyUriListForRecall', 'DisableAgentConnectors', 'DisableAgentWorkspaces',
                        'DisableAIDataAnalysis', 'DisableClickToDo', 'DisableRemoteAgentConnectors',
                        'DisableSettingsAgent', 'SetDenyAppListForRecall', 'SetDenyUriListForRecall',
                        'SetMaximumStorageDurationForRecallSnapshots', 'SetMaximumStorageSpaceForRecallSnapshots')
                    'HKLM:\SOFTWARE\Policies\Microsoft\Edge' = @(
                        'AIGenThemesEnabled', 'AllowBrowsingWithCopilot', 'BuiltInAIAPIsEnabled',
                        'ComposeInlineEnabled', 'CopilotAddressBarSuggestionsEnabled', 'CopilotNewTabPageEnabled',
                        'CopilotPageContext', 'EdgeEntraCopilotPageContext', 'EdgeHistoryAISearchEnabled',
                        'GenAILocalFoundationalModelSettings', 'HubsSidebarEnabled', 'M365LinksAutoOpenCopilotEnabled',
                        'Microsoft365CopilotChatIconEnabled', 'NewTabPageBingChatEnabled',
                        'ShareBrowsingHistoryWithCopilotSearchAllowed', 'StandaloneHubsSidebarEnabled', 'VisualSearchEnabled')
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' = @(
                        'DisableCocreator', 'DisableGenerativeFill', 'DisableImageCreator')
                    'HKLM:\SOFTWARE\Policies\WindowsNotepad' = @('DisableAIFeatures')
                    "$user\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" = @('DisableRecallDataProviders')
                    "$user\Software\Policies\Microsoft\Windows\WindowsCopilot" = @('TurnOffWindowsCopilot')
                    "$user\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @('ShowCopilotButton')
                    "$user\Software\Policies\Microsoft\Windows\CopilotKey" = @('SetCopilotHardwareKey')
                }
                $entries = @(foreach ($path in $schema4.Keys) {
                        foreach ($name in $schema4[$path]) {
                            [PSCustomObject]@{ Path = $path; Name = $name; KeyExisted = $false; Exists = $false; Type = $null; Value = $null }
                        }
                    })
                $entries.Count | Should -Be 43
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4; DeclaredTargetCount = 43
                    ApplicableTargetCount = 43; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                Mock Get-AntiAIRegistryTargets { throw 'current inventory must not be read during restore' }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Not -Throw
                # A schema-4 document is not a valid new backup ...
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot } | Should -Throw '*current snapshot schema 5*'
                # ... and cannot smuggle in a schema-5 identity.
                $entries[0].Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Copilot'
                $entries[0].Name = 'BrowsingEnabled'
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Throw '*outside the exact allowlist*'
                Should -Invoke Get-AntiAIRegistryTargets -Times 0 -Exactly
            }
        }

        It 'keeps a schema-5 session restorable without reading the current inventory' {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                $entries = @(Get-AntiAIRegistryTargets | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 5; DeclaredTargetCount = $entries.Count
                    ApplicableTargetCount = $entries.Count; NotApplicableTargetCount = 0
                    Entries = $entries; NotApplicableTargets = @()
                }
                Mock Get-AntiAIRegistryTargets { throw 'current inventory must not be read during restore' }
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Not -Throw
                # A retired schema-4 identity is not accepted in a schema-5 document.
                $entries[0].Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                $entries[0].Name = 'DisableAgentWorkspaces'
                { Assert-AntiAIRegistrySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Throw '*outside the exact allowlist*'
                Should -Invoke Get-AntiAIRegistryTargets -Times 0 -Exactly
            }
        }

        It 'reports a 2.2.6 durable plan as an earlier inventory instead of guessing or failing' {
            InModuleScope AntiAI {
                Mock Get-AntiAIUserContext { [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' } }
                Mock Get-AntiAITargetPlan { throw 'live applicability must not be read' }
                $legacy = @('LetAppsAccessGenerativeAI', 'DisableAgentConnectors', 'DisableAgentWorkspaces',
                    'DisableRemoteAgentConnectors', 'AgentConnectorMinimumPolicy', 'ShowCopilotButton')
                $current = @(Get-AntiAIRegistryTargets | Where-Object {
                        $_.Name -notin @('LetAppsAccessSystemAIModels', 'BrowsingEnabled', 'Install{C50565E9-CCCF-44B4-BA15-5AC5C6569197}',
                            'AllowTelemetry', 'TextPredictionEnabled', 'TabServicesEnabled', 'EdgeAutofillMlEnabled',
                            'MicrosoftEditorProofingEnabled', 'CopilotCoworkToolActionsEnabled', 'ProactiveAuthWorkflowEnabled',
                            'State')
                    } | ForEach-Object { [PSCustomObject]@{ path = [string]$_.Path; name = [string]$_.Name } })
                $records = @($current) + @($legacy | ForEach-Object {
                        [PSCustomObject]@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; name = $_ }
                    })
                $records.Count | Should -Be 43
                $intent = [PSCustomObject]@{
                    applicableTargets = @($records | Select-Object -First 20)
                    notApplicableTargets = @($records | Select-Object -Skip 20)
                }
                $plan = Get-AntiAIIntentTargetPlan -Intent $intent
                $plan.InventoryChanged | Should -BeTrue
                $plan.EvidenceSource | Should -BeExactly 'EarlierInventoryApplyIntent'
                $plan.ApplicableCount | Should -Be 0
                Should -Invoke Get-AntiAITargetPlan -Times 0 -Exactly
            }
        }

        It "Should apply only the canonical config-derived target set" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw
            $source | Should -Match 'Set-AntiAIRegistryTargets[\s\S]*-Targets \$applicableTargets'
            $source | Should -Not -Match 'Disable-Recall|Set-RecallProtection|Disable-CopilotAdvanced|Disable-ExplorerAI'
        }

        It "classifies all 50 targets and never mutates the NotApplicable subset" {
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
            $verifier | Should -Match 'VerificationReasonCode\s*=\s*\$\(if \(\$antiAIInventoryChanged\) \{ ''AntiAI\.SavedPlanPredatesInventory'' \} else \{ ''AntiAI\.NoSavedTargetPlan'' \}\)'
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
                Mock Test-NoIDRegistryKey { $false }
                Mock Get-AntiAIManagementState {
                    [PSCustomObject]@{ DomainJoined = $false; MdmRegistered = $false; Managed = $false; QueryErrors = @() }
                }

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
                    (@($result.ApplicabilityNotes | Where-Object { $_ -like 'Recall policies delete existing Recall snapshots.*' }).Count -eq 1) |
                        Should -Be $case.ProOrHigher
                    $result.InsiderPreviewProfile | Should -BeFalse
                    $result.AgentPolicyProfile | Should -BeFalse
                }
            }
        }

        It 'enables the documented WindowsAI agent policy profile on explicit 26H2 without inventing Insider enrollment' {
            InModuleScope AntiAI {
                Set-Item -Path function:Get-WindowsVersion -Value { throw 'Mock was not installed' }
                Set-Item -Path function:Get-CimInstance -Value { throw 'Mock was not installed' }
                Mock Get-CimInstance {
                    [PSCustomObject]@{
                        OperatingSystemSKU = 72
                        ProductType = 1
                        BuildNumber = '26300'
                    }
                }
                Mock Get-WindowsVersion {
                    [PSCustomObject]@{
                        IsSupported = $true; Release = '26H2'; DisplayVersion = '26H2'
                        BuildNumber = 26300; UpdateBuildRevision = 9278
                        FullBuild = '26300.9278'; SupportLevel = 'Stable'
                        Edition = 'EnterpriseEval'
                    }
                }
                Mock Test-Path { $false }
                Mock Test-NoIDRegistryKey { $false }
                Mock Get-AntiAIManagementState {
                    [PSCustomObject]@{ DomainJoined = $false; MdmRegistered = $false; Managed = $false; QueryErrors = @() }
                }

                $result = Get-AntiAIApplicability
                $result.InsiderPreviewProfile | Should -BeFalse
                $result.AgentPolicyProfile | Should -BeTrue
                $result.AgentPolicies | Should -Match 'explicit 26H2'
                @($result.Warnings | Where-Object { $_ -match 'WindowsAI agent|Preview|release gate' }).Count | Should -Be 0
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
                Mock Test-NoIDRegistryKey { $false }
                Mock Get-AppxPackage {
                    [PSCustomObject]@{ Version = '11.2605.29.0' }
                }

                foreach ($case in @(
                        @{ Family = 'Home'; Commercial = $false; ProOrHigher = $false; Applicable = 27; SettingsAgent = $false; ClickToDo = $false }
                        @{ Family = 'Professional'; Commercial = $false; ProOrHigher = $true; Applicable = 36; SettingsAgent = $false; ClickToDo = $true }
                        @{ Family = 'Enterprise'; Commercial = $true; ProOrHigher = $true; Applicable = 43; SettingsAgent = $true; ClickToDo = $true }
                    )) {
                    $state = [PSCustomObject]@{
                        SupportedWindowsProfile = $true
                        WindowsBuildNumber = 26200
                        WindowsUBR = 8655
                        CommercialEdition = $case.Commercial
                        ProOrHigherEdition = $case.ProOrHigher
                        InsiderPreviewProfile = $false
                        AgentPolicyProfile = $false
                        ManagedDevice = $false
                    }
                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $plan.ApplicableCount | Should -Be $case.Applicable
                    $plan.NotApplicableCount | Should -Be (50 - $case.Applicable)
                    # Copilot app and MXC machine policies are staged on every edition.
                    @($plan.ApplicableTargets | Where-Object {
                            [string]$_.Path -in @('HKLM:\SOFTWARE\Policies\Microsoft\Copilot', 'HKLM:\SOFTWARE\Policies\Mxc')
                        }).Count | Should -Be 3
                    # Edge Update ignores its policies on this unmanaged device.
                    @($plan.NotApplicableTargets | Where-Object {
                            [string]$_.Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -and
                            [string]$_.Reason -like '*only on domain-joined or MDM-enrolled devices; this device is neither'
                        }).Count | Should -Be 1
                    (@($plan.ApplicableTargets | Where-Object Name -eq 'LetAppsAccessSystemAIModels').Count -eq 1) |
                        Should -Be $case.ProOrHigher
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
                    # No App Paths registration: only the two file candidates exist.
                    Mock Test-NoIDRegistryKey { $false }
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
                        AgentPolicyProfile = $false
                        ManagedDevice = $false
                    }

                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $plan.EdgeVersion | Should -BeExactly '151.0.10.1'
                    $plan.DeclaredCount | Should -Be 50
                    ($plan.ApplicableCount + $plan.NotApplicableCount) | Should -Be 50
                    Should -Invoke Get-Process -Times 0 -Exactly
                }
                finally {
                    $env:ProgramFiles = $oldProgramFiles
                    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
                }
            }
        }

        It 'writes the Edge Update Copilot install block only where Edge Update reads policies' {
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
                Mock Test-NoIDRegistryKey { $false }
                Mock Get-AppxPackage { [PSCustomObject]@{ Version = '11.2605.29.0' } }
                foreach ($case in @(
                        @{ Managed = $true; Applicable = $true; Reason = $null }
                        @{ Managed = $false; Applicable = $false; Reason = '*this device is neither' }
                        @{ Managed = $null; Applicable = $false; Reason = 'Device management could not be checked*' }
                    )) {
                    $state = [PSCustomObject]@{
                        SupportedWindowsProfile = $true; WindowsBuildNumber = 26200; WindowsUBR = 9457
                        CommercialEdition = $false; ProOrHigherEdition = $true
                        InsiderPreviewProfile = $false; AgentPolicyProfile = $false; ManagedDevice = $case.Managed
                    }
                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $edgeUpdate = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                    (@($plan.ApplicableTargets | Where-Object Path -eq $edgeUpdate).Count -eq 1) | Should -Be $case.Applicable
                    if ($case.Reason) {
                        @($plan.NotApplicableTargets | Where-Object { $_.Path -eq $edgeUpdate -and $_.Reason -like $case.Reason }).Count |
                            Should -Be 1
                    }
                }
                $missing = [PSCustomObject]@{
                    SupportedWindowsProfile = $true; WindowsBuildNumber = 26200; WindowsUBR = 9457
                    CommercialEdition = $false; ProOrHigherEdition = $true
                    InsiderPreviewProfile = $false; AgentPolicyProfile = $false
                }
                { Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $missing } |
                    Should -Throw "*missing 'ManagedDevice'*"
            }
        }

        It 'plans a Copilot app startup task only when the app registered it for the user' {
            $declaredTargets = InModuleScope AntiAI {
                Mock Get-AntiAIUserContext {
                    [PSCustomObject]@{ Root = 'HKU:\S-1-5-21-1-2-3-1001' }
                }
                @(Get-AntiAIRegistryTargets)
            }
            InModuleScope AntiAI -Parameters @{ DeclaredTargets = $declaredTargets } {
                param($DeclaredTargets)
                Set-Item -Path function:Get-AppxPackage -Value { throw 'Mock was not installed' }
                $officeHub = 'HKU:\S-1-5-21-1-2-3-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId'
                $copilot = 'HKU:\S-1-5-21-1-2-3-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId'
                Mock Test-Path { $false }
                # Only the Microsoft 365 Copilot app is registered for this user.
                Mock Test-NoIDRegistryKey { [string]$LiteralPath -ceq $officeHub }
                Mock Get-AppxPackage { [PSCustomObject]@{ Version = '11.2605.29.0' } }
                $state = [PSCustomObject]@{
                    SupportedWindowsProfile = $true; WindowsBuildNumber = 26200; WindowsUBR = 9457
                    CommercialEdition = $false; ProOrHigherEdition = $false
                    InsiderPreviewProfile = $false; AgentPolicyProfile = $false; ManagedDevice = $false
                }
                $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                @($plan.ApplicableTargets | Where-Object { $_.Path -ceq $officeHub -and $_.Name -ceq 'State' -and $_.Value -eq 1 }).Count |
                    Should -Be 1
                @($plan.NotApplicableTargets | Where-Object {
                        $_.Path -ceq $copilot -and $_.Reason -ceq 'The Copilot app has no startup task registered for this user'
                    }).Count | Should -Be 1
                # Home: 27 edition-applicable targets plus the registered startup task.
                $plan.ApplicableCount | Should -Be 28
            }
        }

        It 'treats Edge Update management like Edge Update: domain or MDM, unknown is never managed' {
            InModuleScope AntiAI {
                Set-Item -Path function:Get-CimInstance -Value { throw 'Mock was not installed' }
                Mock Get-CimInstance { [PSCustomObject]@{ PartOfDomain = [bool]$script:mgmtCase.Domain } }
                Mock Test-AntiAIMdmRegistration {
                    if ($script:mgmtCase.MdmThrows) { throw 'MDMRegistration.dll unavailable' }
                    [bool]$script:mgmtCase.Mdm
                }
                foreach ($case in @(
                        @{ Domain = $true; Mdm = $false; MdmThrows = $false; Managed = $true }
                        @{ Domain = $false; Mdm = $true; MdmThrows = $false; Managed = $true }
                        @{ Domain = $false; Mdm = $false; MdmThrows = $false; Managed = $false }
                        @{ Domain = $false; Mdm = $false; MdmThrows = $true; Managed = $null }
                        @{ Domain = $true; Mdm = $false; MdmThrows = $true; Managed = $true }
                    )) {
                    $script:mgmtCase = $case
                    $state = Get-AntiAIManagementState
                    $state.Managed | Should -Be $case.Managed
                    (@($state.QueryErrors).Count -gt 0) | Should -Be $case.MdmThrows
                }
            }
        }

        It 'refuses to restore a Copilot app startup value while the user is signed out' {
            InModuleScope AntiAI {
                $sid = 'S-1-5-21-1-2-3-1001'
                $path = "HKU:\$sid\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId"
                $backup = Join-Path $TestDrive 'antiai-prestate.json'
                [PSCustomObject]@{
                    SchemaVersion = 5; DeclaredTargetCount = 50; ApplicableTargetCount = 1; NotApplicableTargetCount = 49
                    Entries = @([PSCustomObject]@{ Path = $path; Name = 'State'; KeyExisted = $true; Exists = $true; Type = 'DWord'; Value = 2 })
                    NotApplicableTargets = @()
                } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $backup -Encoding UTF8
                Mock Assert-AntiAIRegistrySnapshot { $true }
                function Mount-UserRegistryHiveForRestore { param($Sid) [PSCustomObject]@{ Sid = $Sid; Temporary = $true } }
                function Dismount-UserRegistryHiveAfterRestore { param($Mount) $null -ne $Mount }
                # NTUSER.DAT is mounted, the user's Classes hive is not loaded.
                Mock Test-NoIDRegistryKey { [string]$LiteralPath -ceq "HKU:\$sid" }
                Mock New-ItemProperty { throw 'must not write before the Classes hive check' }
                Mock New-NoIDRegistryKey { throw 'must not create keys before the Classes hive check' }
                $result = Restore-AntiAIRegistryState -BackupPath $backup
                $result.Success | Should -BeFalse
                @($result.Errors) -join ' ' | Should -Match 'must be signed in to restore the Copilot app start-up setting'
                Should -Invoke New-ItemProperty -Times 0 -Exactly
                Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
            }
        }

        It 'plans the two documented agent controls on explicit 26H2 Enterprise and the Recall-provider control only on Insider builds' {
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
                Mock Test-NoIDRegistryKey { $false }
                Mock Get-AppxPackage { [PSCustomObject]@{ Version = '11.2605.29.0' } }
                foreach ($case in @(
                        @{ Insider = $false; Applicable = 45; Provider = $false }
                        @{ Insider = $true; Applicable = 46; Provider = $true }
                    )) {
                    $state = [PSCustomObject]@{
                        SupportedWindowsProfile = $true
                        WindowsBuildNumber = 26300
                        WindowsUBR = 9457
                        CommercialEdition = $true
                        ProOrHigherEdition = $true
                        InsiderPreviewProfile = $case.Insider
                        AgentPolicyProfile = $true
                        ManagedDevice = $false
                    }
                    $plan = Get-AntiAITargetPlan -Targets $DeclaredTargets -Applicability $state
                    $plan.ApplicableCount | Should -Be $case.Applicable
                    @($plan.ApplicableTargets | Where-Object Name -in @('ConfigureAgentConnectors', 'AgentConsentDuration')).Count |
                        Should -Be 2
                    (@($plan.ApplicableTargets | Where-Object Name -eq 'DisableRecallDataProviders').Count -eq 1) |
                        Should -Be $case.Provider
                }
            }
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module AntiAI -Force -ErrorAction SilentlyContinue
}
